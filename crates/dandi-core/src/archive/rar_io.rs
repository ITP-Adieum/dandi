use std::cell::RefCell;
use std::fs;
use std::io::{self, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use rars::{
    extract_volumes_with_links, Archive as RarArchive, ArchiveFamily, ArchiveMember,
    ArchiveMemberDetail, ArchiveReadOptions, ArchiveReader, AttrSource, Error as RarError,
    ErrorKind as RarErrorKind, ExtractedEntryMeta, ExtractedLink,
};
use unicode_normalization::UnicodeNormalization;

use crate::archive::extract_sink::{ExtractionSink, StagedFileHandle};
use crate::archive::split::{discover_volumes, SplitFileReader, VolumeKind};
use crate::archive::{
    plan_extract_root, synthesize_parent_dirs, ArchiveEntryInfo, ArchiveFormat, ArchiveSummary,
    EntryKind, InspectOptions, UnpackOptions, UnpackReport,
};
use crate::codec::{decode_entry_name_with_override, detect_archive_encoding, EntryEncodingFlags};
use crate::error::{DandiError, Result};
use crate::platform::{read_zone_identifier, to_fs_path};
use crate::progress::{CancellationToken, ProgressEvent, ProgressObserver, ProgressPhase};
use crate::safety::{is_os_junk, sanitize_entry_path, SafetyBudget};

const MAX_RAR_HEADER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RAR_DICT_BYTES: u64 = 256 * 1024 * 1024;

struct OpenedRar {
    volumes: Vec<RarArchive>,
    volume_paths: Vec<PathBuf>,
    total_archive_bytes: u64,
    used_password: Option<Vec<u8>>,
}

struct LogicalRarEntry {
    index: usize,
    raw_name: Vec<u8>,
    name_is_unicode: bool,
    kind: EntryKind,
    unpacked_size: u64,
    packed_size: u64,
    modified_unix_secs: Option<i64>,
    unix_mode: Option<u32>,
    encrypted: bool,
    compression_method: String,
    symlink_target: Option<String>,
}

fn build_rar_read_options<'a>(
    password: Option<&'a [u8]>,
    budget: &SafetyBudget,
) -> ArchiveReadOptions<'a> {
    let max_headers = (budget.max_entries as u64).saturating_add(64);
    ArchiveReadOptions::with_optional_password(password)
        .with_max_header_count(max_headers)
        .with_max_header_bytes(MAX_RAR_HEADER_BYTES)
        .with_max_total_output_bytes(budget.max_total_bytes)
        .with_rar50_dictionary_size_limit(MAX_RAR_DICT_BYTES)
        .with_rar3_vm_programs(false)
        .with_threads(1)
}

fn run_rars_guarded<T, F>(f: F) -> Result<T>
where
    F: FnOnce() -> rars::Result<T>,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(err)) => Err(map_rar_error(&err, None)),
        Err(_) => Err(DandiError::CorruptArchive(
            "RAR parser encountered an internal error on malformed archive data".to_string(),
        )),
    }
}

/// Resolves the first volume when the user opens a non-first native RAR volume (e.g. `.part2.rar`).
fn resolve_native_rar_first_volume(path: &Path) -> Result<PathBuf> {
    let Some(file_name) = path.file_name().map(|s| s.to_string_lossy().into_owned()) else {
        return Ok(path.to_path_buf());
    };
    let lower = file_name.to_ascii_lowercase();
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    // Old-style volume names: `name.rar`, `name.r00`, `name.r01`, ...
    if let Some((stem, ext)) = file_name.rsplit_once('.') {
        let e = ext.as_bytes();
        let old_style = e.len() == 3
            && e[0].eq_ignore_ascii_case(&b'r')
            && e[1].is_ascii_digit()
            && e[2].is_ascii_digit();
        if old_style && !stem.is_empty() {
            let first = ["rar", "RAR"]
                .iter()
                .map(|x| parent.join(format!("{stem}.{x}")))
                .find(|p| to_fs_path(p).is_file())
                .ok_or_else(|| {
                    DandiError::CorruptArchive(format!(
                        "missing RAR volume '{}'",
                        parent.join(format!("{stem}.rar")).display()
                    ))
                })?;
            return Ok(first);
        }
    }

    if !lower.ends_with(".rar") || file_name.len() <= 4 {
        return Ok(path.to_path_buf());
    }

    let stem_without_rar = &file_name[..file_name.len() - 4];
    let ext_case = &file_name[file_name.len() - 4..];
    let lower_stem = &lower[..lower.len() - 4];

    if let Some(pos) = lower_stem.rfind(".part") {
        let digits = &lower_stem[pos + 5..];
        if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(part_num) = digits.parse::<usize>() {
                if part_num > 1 {
                    let width = digits.len();
                    let part_tag = &stem_without_rar[pos..pos + 5];
                    let base = &stem_without_rar[..pos];
                    // Sets may be zero-padded (`part01`) or not (`part1` ... `part10`).
                    let padded = parent.join(format!("{base}{part_tag}{:0width$}{ext_case}", 1));
                    let unpadded = parent.join(format!("{base}{part_tag}1{ext_case}"));
                    return [&padded, &unpadded]
                        .into_iter()
                        .find(|p| to_fs_path(p).is_file())
                        .cloned()
                        .ok_or_else(|| {
                            DandiError::CorruptArchive(format!(
                                "missing RAR volume '{}'",
                                padded.display()
                            ))
                        });
                }
            }
        }
    }

    Ok(path.to_path_buf())
}

fn open_rar_single_volume(
    path: &Path,
    password: Option<&str>,
    budget: &SafetyBudget,
) -> Result<(RarArchive, Option<Vec<u8>>)> {
    let fs_path = to_fs_path(path);
    match password {
        None => {
            let opts = build_rar_read_options(None, budget);
            let arc = run_rars_guarded(|| ArchiveReader::read_path_with_options(&fs_path, opts))?;
            Ok((arc, None))
        }
        Some(raw_pw) => {
            let pw_nfc: String = raw_pw.nfc().collect();
            let opts_nfc = build_rar_read_options(Some(pw_nfc.as_bytes()), budget);
            match run_rars_guarded(|| ArchiveReader::read_path_with_options(&fs_path, opts_nfc)) {
                Ok(arc) => Ok((arc, Some(pw_nfc.into_bytes()))),
                Err(first_err) => {
                    if pw_nfc != raw_pw {
                        let opts_raw = build_rar_read_options(Some(raw_pw.as_bytes()), budget);
                        if let Ok(arc) = run_rars_guarded(|| {
                            ArchiveReader::read_path_with_options(&fs_path, opts_raw)
                        }) {
                            return Ok((arc, Some(raw_pw.as_bytes().to_vec())));
                        }
                    }
                    Err(first_err)
                }
            }
        }
    }
}

fn open_rar_volumes(
    archive_path: &Path,
    password: Option<&str>,
    budget: &SafetyBudget,
    cancel: &CancellationToken,
) -> Result<OpenedRar> {
    cancel.check()?;
    let vol_set = discover_volumes(archive_path)?;

    // Numeric split `.rar.001`, `.rar.002`, ... -> stream via SplitFileReader.
    if vol_set.kind == VolumeKind::Numeric {
        let split_reader = SplitFileReader::open(&vol_set.volumes)?;
        let total_len = split_reader.total_len().max(1);
        let (arc, used_pw) = match password {
            None => {
                let opts = build_rar_read_options(None, budget);
                let arc = run_rars_guarded(|| {
                    ArchiveReader::read_reader_with_options(split_reader, opts)
                })?;
                (arc, None)
            }
            Some(raw_pw) => {
                let pw_nfc: String = raw_pw.nfc().collect();
                let opts_nfc = build_rar_read_options(Some(pw_nfc.as_bytes()), budget);
                match run_rars_guarded(|| {
                    ArchiveReader::read_reader_with_options(split_reader, opts_nfc)
                }) {
                    Ok(arc) => (arc, Some(pw_nfc.into_bytes())),
                    Err(first_err) => {
                        if pw_nfc != raw_pw {
                            let retry = SplitFileReader::open(&vol_set.volumes)?;
                            let opts_raw = build_rar_read_options(Some(raw_pw.as_bytes()), budget);
                            if let Ok(arc) = run_rars_guarded(|| {
                                ArchiveReader::read_reader_with_options(retry, opts_raw)
                            }) {
                                return Ok(OpenedRar {
                                    volumes: vec![arc],
                                    volume_paths: vol_set.volumes,
                                    total_archive_bytes: total_len,
                                    used_password: Some(raw_pw.as_bytes().to_vec()),
                                });
                            }
                        }
                        return Err(first_err);
                    }
                }
            }
        };
        return Ok(OpenedRar {
            volumes: vec![arc],
            volume_paths: vol_set.volumes,
            total_archive_bytes: total_len,
            used_password: used_pw,
        });
    }

    // Single `.rar` or native RAR multi-volume (`.part1.rar`/`.part2.rar` or `.rar`/`.r00`).
    let first_path = resolve_native_rar_first_volume(archive_path)?;
    let (first_arc, used_pw) = open_rar_single_volume(&first_path, password, budget)?;
    let mut total_bytes = fs::metadata(to_fs_path(&first_path))
        .map(|m| m.len())
        .unwrap_or(1);

    if !first_arc.is_volume() {
        return Ok(OpenedRar {
            volumes: vec![first_arc],
            volume_paths: vec![first_path],
            total_archive_bytes: total_bytes.max(1),
            used_password: used_pw,
        });
    }

    let mut volumes = vec![first_arc];
    let mut volume_paths = vec![first_path.clone()];

    // Discover subsequent volumes sequentially.
    for idx in 1..10_000usize {
        cancel.check()?;
        let Some(next_path) = volumes[0].volume_path(&first_path, idx) else {
            break;
        };
        let last_continues = volumes
            .last()
            .and_then(|v| v.members().last())
            .is_some_and(|m| m.meta.is_split_after);
        if !to_fs_path(&next_path).is_file() {
            if last_continues {
                return Err(DandiError::CorruptArchive(format!(
                    "missing RAR volume '{}'",
                    next_path.display()
                )));
            }
            // Check if a later volume exists beyond a missing middle volume (e.g. part3 without part2).
            if let Some(after_next) = volumes[0].volume_path(&first_path, idx + 1) {
                if to_fs_path(&after_next).is_file() {
                    return Err(DandiError::CorruptArchive(format!(
                        "missing RAR volume '{}'",
                        next_path.display()
                    )));
                }
            }
            break;
        }
        let pw_str = used_pw
            .as_deref()
            .and_then(|b| std::str::from_utf8(b).ok())
            .or(password);
        let (next_arc, _) = open_rar_single_volume(&next_path, pw_str, budget)?;
        total_bytes = total_bytes.saturating_add(
            fs::metadata(to_fs_path(&next_path))
                .map(|m| m.len())
                .unwrap_or(0),
        );
        volumes.push(next_arc);
        volume_paths.push(next_path);
    }

    Ok(OpenedRar {
        volumes,
        volume_paths,
        total_archive_bytes: total_bytes.max(1),
        used_password: used_pw,
    })
}

fn collect_logical_entries(volumes: &[RarArchive]) -> Vec<LogicalRarEntry> {
    let mut entries: Vec<LogicalRarEntry> = Vec::new();
    for vol in volumes {
        for member in vol.members() {
            if member.meta.is_split_before {
                // Accumulate packed bytes onto the logical entry started in the previous volume.
                if let Some(prev) = entries.last_mut() {
                    prev.packed_size = prev.packed_size.saturating_add(member.meta.packed_size);
                }
                continue;
            }
            let idx = entries.len();
            let (kind, symlink_target) = classify_member_kind(&member);
            let mtime = member
                .times()
                .ok()
                .and_then(|t| t.modified)
                .or_else(|| member.meta.modification_time())
                .map(|ts| ts.unix_seconds());
            let unix_mode = extract_unix_mode(member.meta.attr_source(), member.meta.file_attr);
            let compression_method = format_rar_method(&member);

            entries.push(LogicalRarEntry {
                index: idx,
                raw_name: member.meta.name.clone(),
                name_is_unicode: member.name_is_unicode(),
                kind,
                unpacked_size: member.meta.unpacked_size,
                packed_size: member.meta.packed_size,
                modified_unix_secs: mtime,
                unix_mode,
                encrypted: member.meta.is_encrypted,
                compression_method,
                symlink_target,
            });
        }
    }
    entries
}

fn classify_member_kind(member: &ArchiveMember) -> (EntryKind, Option<String>) {
    if member.meta.is_directory {
        return (EntryKind::Directory, None);
    }
    if member.meta.is_redirection {
        if let ArchiveMemberDetail::Rar50Plus {
            redirection: Some(ref redir),
            ..
        } = member.detail
        {
            if matches!(redir.redirection_type, 1 | 2) {
                let target = String::from_utf8_lossy(&redir.target_name).into_owned();
                return (EntryKind::Symlink, Some(target));
            }
        }
        return (EntryKind::Symlink, None);
    }
    if member.meta.family == ArchiveFamily::Rar15To40
        && member.meta.host_os == Some(3)
        && (member.meta.file_attr & !0o7777) == 0o120000
    {
        return (EntryKind::Symlink, None);
    }
    (EntryKind::File, None)
}

fn extract_unix_mode(source: AttrSource, attr: u64) -> Option<u32> {
    if source == AttrSource::Unix {
        let mode = (attr & 0xFFFF) as u32;
        if mode != 0 {
            return Some(mode);
        }
    }
    None
}

fn format_rar_method(member: &ArchiveMember) -> String {
    let family = match member.meta.family {
        ArchiveFamily::Rar13 => "rar1",
        ArchiveFamily::Rar15To40 => "rar4",
        ArchiveFamily::Rar50Plus => "rar5",
        _ => "rar",
    };
    if member.meta.is_stored {
        format!("{family}/store")
    } else {
        family.to_string()
    }
}

pub(crate) fn inspect_rar(archive_path: &Path, opts: &InspectOptions) -> Result<ArchiveSummary> {
    let cancel = CancellationToken::new();
    let opened = open_rar_volumes(
        archive_path,
        opts.password.as_deref(),
        &opts.budget,
        &cancel,
    )?;
    let logical = collect_logical_entries(&opened.volumes);

    if logical.len() > opts.budget.max_entries {
        return Err(DandiError::BudgetExceeded {
            reason: format!(
                "RAR archive declares {} entries, exceeding limit {}",
                logical.len(),
                opts.budget.max_entries
            ),
        });
    }

    let legacy_raw_names: Vec<&[u8]> = logical
        .iter()
        .filter(|e| !e.name_is_unicode)
        .map(|e| e.raw_name.as_slice())
        .collect();
    let detection = detect_archive_encoding(&legacy_raw_names, opts.locale_hint);
    let applied_encoding = opts.encoding_override.unwrap_or(detection.encoding);
    let explicit_override = opts.encoding_override.is_some();

    let mut entries = Vec::with_capacity(logical.len().min(4096));
    let mut total_uncompressed = 0u64;
    let mut total_compressed = 0u64;
    let mut any_encrypted = opened.used_password.is_some();

    for item in &logical {
        let decoded = decode_entry_name_with_override(
            &item.raw_name,
            EntryEncodingFlags {
                utf8_bit11: item.name_is_unicode,
            },
            None,
            applied_encoding,
            explicit_override,
        );
        let junk = is_os_junk(&decoded.path);
        if junk && !opts.include_os_junk {
            continue;
        }
        if item.encrypted {
            any_encrypted = true;
        }
        total_uncompressed = total_uncompressed.saturating_add(item.unpacked_size);
        total_compressed = total_compressed.saturating_add(item.packed_size);

        entries.push(ArchiveEntryInfo {
            index: Some(item.index),
            path: decoded.path,
            kind: item.kind,
            uncompressed_size: item.unpacked_size,
            compressed_size: item.packed_size,
            modified_unix_secs: item.modified_unix_secs,
            unix_mode: item.unix_mode,
            encrypted: item.encrypted,
            compression_method: item.compression_method.clone(),
            is_os_junk: junk,
            is_synthesized: false,
            symlink_target: item.symlink_target.clone(),
        });
    }

    let entries = synthesize_parent_dirs(entries);
    let total_entries = entries.len();

    Ok(ArchiveSummary {
        format: ArchiveFormat::Rar,
        encoding: detection,
        applied_encoding,
        total_entries,
        total_uncompressed_bytes: total_uncompressed,
        total_compressed_bytes: total_compressed.max(opened.total_archive_bytes),
        encrypted: any_encrypted,
        entries,
    })
}

/// Push writer bridging `rars`'s `Box<dyn Write>` into [`ExtractionSink`].
///
/// `rars` may report an integrity failure only after a member's bytes were written and its
/// writer dropped, so a dropped writer parks its file in `pending` instead of finalizing it.
/// The file is finalized when `rars` moves on to the next member or finishes cleanly; on error
/// the parked handle is dropped, which deletes the unverified file.
struct SinkPushWriter {
    sink: Rc<RefCell<ExtractionSink>>,
    handle: Option<StagedFileHandle>,
    err_slot: Rc<RefCell<Option<DandiError>>>,
    pending: Rc<RefCell<Option<StagedFileHandle>>>,
}

impl Write for SinkPushWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let Some(ref mut handle) = self.handle else {
            return Err(io::Error::other("sink file handle already closed"));
        };
        let res = self.sink.borrow_mut().write_file_chunk(handle, buf);
        if let Err(err) = res {
            let msg = err.to_string();
            stash_error(&self.err_slot, err);
            return Err(io::Error::other(msg));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for SinkPushWriter {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            if self.err_slot.borrow().is_none() {
                *self.pending.borrow_mut() = Some(handle);
            }
        }
    }
}

fn stash_error(slot: &Rc<RefCell<Option<DandiError>>>, err: DandiError) {
    let mut slot = slot.borrow_mut();
    if slot.is_none() {
        *slot = Some(err);
    }
}

/// Finalizes the file parked by the previous member's writer (see [`SinkPushWriter`]).
fn finalize_pending(
    sink: &Rc<RefCell<ExtractionSink>>,
    pending: &Rc<RefCell<Option<StagedFileHandle>>>,
) -> Result<()> {
    let parked = pending.borrow_mut().take();
    match parked {
        Some(handle) => sink.borrow_mut().finish_file(handle).map(|_| ()),
        None => Ok(()),
    }
}

/// Maps a `rars` callback back to its logical entry by raw name, so selection and decoded names
/// never depend on callbacks arriving one-per-entry in header order.
struct EntryCursor {
    next: usize,
    visited: Vec<bool>,
}

impl EntryCursor {
    fn new(len: usize) -> Self {
        Self {
            next: 0,
            visited: vec![false; len],
        }
    }

    fn resolve(&mut self, logical: &[LogicalRarEntry], name: &[u8]) -> Result<usize> {
        let in_order = logical
            .get(self.next)
            .filter(|e| e.raw_name == name && !self.visited[self.next])
            .map(|_| self.next);
        let idx = in_order
            .or_else(|| {
                logical
                    .iter()
                    .enumerate()
                    .find(|(i, e)| !self.visited[*i] && e.raw_name == name)
                    .map(|(i, _)| i)
            })
            .ok_or_else(|| {
                DandiError::CorruptArchive(format!(
                    "RAR extraction produced entry '{}' that its headers do not list",
                    String::from_utf8_lossy(name)
                ))
            })?;
        self.visited[idx] = true;
        self.next = idx + 1;
        Ok(idx)
    }
}

/// Discard writer for skipped/unselected RAR entries that STILL enforces `SafetyBudget` and
/// `CancellationToken` (blocking Zip Bombs hidden inside skipped solid entries).
struct BudgetedDiscardWriter {
    sink: Rc<RefCell<ExtractionSink>>,
    err_slot: Rc<RefCell<Option<DandiError>>>,
    compressed_hint: u64,
}

impl Write for BudgetedDiscardWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut sink = self.sink.borrow_mut();
        if let Err(err) = sink.check_cancelled() {
            let msg = err.to_string();
            let mut slot = self.err_slot.borrow_mut();
            if slot.is_none() {
                *slot = Some(err);
            }
            return Err(io::Error::other(msg));
        }
        if let Err(err) = sink.record_skipped_bytes(buf.len() as u64, self.compressed_hint) {
            let msg = err.to_string();
            let mut slot = self.err_slot.borrow_mut();
            if slot.is_none() {
                *slot = Some(err);
            }
            return Err(io::Error::other(msg));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn unpack_rar(
    archive_path: &Path,
    dest_dir: &Path,
    opts: &UnpackOptions,
    observer: &dyn ProgressObserver,
) -> Result<UnpackReport> {
    opts.cancel.check()?;
    let opened = open_rar_volumes(
        archive_path,
        opts.password.as_deref(),
        &opts.budget,
        &opts.cancel,
    )?;
    let logical = collect_logical_entries(&opened.volumes);

    if logical.len() > opts.budget.max_entries {
        return Err(DandiError::BudgetExceeded {
            reason: format!(
                "RAR archive declares {} entries, exceeding limit {}",
                logical.len(),
                opts.budget.max_entries
            ),
        });
    }

    let legacy_raw_names: Vec<&[u8]> = logical
        .iter()
        .filter(|e| !e.name_is_unicode)
        .map(|e| e.raw_name.as_slice())
        .collect();
    let detection = detect_archive_encoding(&legacy_raw_names, opts.locale_hint);
    let applied_encoding = opts.encoding_override.unwrap_or(detection.encoding);
    let explicit_override = opts.encoding_override.is_some();

    let zone_data = if opts.propagate_zone_identifier {
        read_zone_identifier(archive_path)
    } else {
        None
    };

    let mut budget = opts.budget.clone();
    budget.set_archive_compressed_size(opened.total_archive_bytes);

    let mut visible_for_smart: Vec<(String, EntryKind)> = Vec::new();
    let mut junk_skipped = 0usize;
    let mut total_bytes_planned = 0u64;
    let mut decoded_names: Vec<String> = Vec::with_capacity(logical.len());
    let mut selected_mask: Vec<bool> = Vec::with_capacity(logical.len());

    for item in &logical {
        opts.cancel.check()?;
        let decoded = decode_entry_name_with_override(
            &item.raw_name,
            EntryEncodingFlags {
                utf8_bit11: item.name_is_unicode,
            },
            None,
            applied_encoding,
            explicit_override,
        );
        let junk = is_os_junk(&decoded.path);
        let keep = !(opts.exclude_os_junk && junk)
            && opts
                .selected_entries
                .as_ref()
                .is_none_or(|sel| sel.contains(&item.index));

        if opts.exclude_os_junk && junk {
            junk_skipped += 1;
        }
        if keep {
            budget.record_entry(item.unpacked_size, item.packed_size)?;
            let sanitized = sanitize_entry_path(&decoded.path, opts.path_policy)?;
            visible_for_smart.push((sanitized.normalized().to_string(), item.kind));
            total_bytes_planned = total_bytes_planned.saturating_add(item.unpacked_size);
        }

        decoded_names.push(decoded.path);
        selected_mask.push(keep);
    }

    let plan = plan_extract_root(
        archive_path,
        dest_dir,
        opts.mode,
        opts.overwrite,
        &visible_for_smart,
    )?;

    let mut sink_inner = ExtractionSink::new(plan, opts, budget, zone_data)?;

    // Pre-register RAR5 symlinks whose targets are already known in headers before any files write.
    for (idx, item) in logical.iter().enumerate() {
        if selected_mask[idx] && item.kind == EntryKind::Symlink {
            if let Some(ref target) = item.symlink_target {
                sink_inner.register_declared_symlink(&decoded_names[idx], target)?;
            }
        }
    }
    sink_inner.validate_declared_symlink_chains()?;

    let sink = Rc::new(RefCell::new(sink_inner));
    let err_slot: Rc<RefCell<Option<DandiError>>> = Rc::new(RefCell::new(None));
    let pending: Rc<RefCell<Option<StagedFileHandle>>> = Rc::new(RefCell::new(None));
    let cursor = RefCell::new(EntryCursor::new(logical.len()));
    let total_entries = logical.len();

    let pw_bytes = opened.used_password.as_deref();
    let read_opts = build_rar_read_options(pw_bytes, &opts.budget);
    let archive_total_bytes = opened.total_archive_bytes;

    // Shared prologue of both callbacks: finalize the previous member, honour cancellation and
    // resolve which logical entry this callback is for.
    let begin_member = |name: &[u8]| -> Result<usize> {
        finalize_pending(&sink, &pending)?;
        opts.cancel.check()?;
        cursor.borrow_mut().resolve(&logical, name)
    };
    let fail = |err: DandiError| -> RarError {
        let msg = err.to_string();
        stash_error(&err_slot, err);
        RarError::from(io::Error::other(msg))
    };

    let open_fn = |meta: &ExtractedEntryMeta| -> rars::Result<Box<dyn Write>> {
        let idx = begin_member(meta.name_bytes()).map_err(fail)?;
        let item = &logical[idx];
        let decoded_path = decoded_names[idx].clone();
        let packed_hint = if item.packed_size > 0 {
            item.packed_size
        } else {
            archive_total_bytes
        };
        let mtime = item
            .modified_unix_secs
            .or_else(|| meta.modified.map(|ts| ts.unix_seconds()));
        let unix_mode = item
            .unix_mode
            .or_else(|| extract_unix_mode(meta.attr_source, meta.file_attr));

        if !selected_mask[idx] {
            return Ok(Box::new(BudgetedDiscardWriter {
                sink: Rc::clone(&sink),
                err_slot: Rc::clone(&err_slot),
                compressed_hint: packed_hint,
            }));
        }

        let progress = |current_entry: String| {
            observer.on_progress(&ProgressEvent {
                phase: ProgressPhase::Unpacking,
                current_entry,
                entries_done: idx + 1,
                entries_total: total_entries,
                bytes_done: sink.borrow().bytes_written(),
                bytes_total: total_bytes_planned.max(1),
            });
        };

        if meta.is_directory {
            let dir_res = sink
                .borrow_mut()
                .extract_directory(&decoded_path, mtime, unix_mode);
            if let Some(current_entry) = dir_res.map_err(fail)? {
                progress(current_entry);
            }
            return Ok(Box::new(io::sink()));
        }

        let begin_res =
            sink.borrow_mut()
                .begin_file(&decoded_path, packed_hint, true, mtime, unix_mode);
        match begin_res.map_err(fail)? {
            Some(handle) => {
                progress(decoded_path);
                Ok(Box::new(SinkPushWriter {
                    sink: Rc::clone(&sink),
                    handle: Some(handle),
                    err_slot: Rc::clone(&err_slot),
                    pending: Rc::clone(&pending),
                }))
            }
            None => Ok(Box::new(BudgetedDiscardWriter {
                sink: Rc::clone(&sink),
                err_slot: Rc::clone(&err_slot),
                compressed_hint: packed_hint,
            })),
        }
    };

    let link_fn = |meta: &ExtractedEntryMeta, link: ExtractedLink<'_>| -> rars::Result<()> {
        let idx = begin_member(meta.name_bytes()).map_err(fail)?;
        if !selected_mask[idx] {
            return Ok(());
        }
        let decoded_path = decoded_names[idx].clone();
        let mtime = logical[idx]
            .modified_unix_secs
            .or_else(|| meta.modified.map(|ts| ts.unix_seconds()));

        match link {
            ExtractedLink::Symlink { target, .. } => {
                let target_str = std::str::from_utf8(target)
                    .map(|t| t.nfc().collect::<String>())
                    .map_err(|_| {
                        fail(DandiError::UnsafeSymlink {
                            path: decoded_path.clone(),
                            target: "<non-utf8>".to_string(),
                            reason: "symlink target is not valid UTF-8".to_string(),
                        })
                    })?;
                let queued = sink
                    .borrow_mut()
                    .queue_symlink(&decoded_path, target_str, mtime);
                queued.map(|_| ()).map_err(fail)
            }
            other => Err(fail(DandiError::UnsafeSymlink {
                path: decoded_path,
                target: String::from_utf8_lossy(other.target()).into_owned(),
                reason: "hardlinks, junctions, and file copies are not permitted".to_string(),
            })),
        }
    };

    let extract_res = catch_unwind(AssertUnwindSafe(|| {
        if opened.volumes.len() == 1 {
            opened.volumes[0].extract_with_links(read_opts, open_fn, link_fn)
        } else {
            extract_volumes_with_links(&opened.volumes, read_opts, open_fn, link_fn)
        }
    }));

    let stashed_err = err_slot.borrow_mut().take();
    match extract_res {
        Ok(Ok(())) => {
            if let Some(err) = stashed_err {
                return Err(err);
            }
            finalize_pending(&sink, &pending)?;
        }
        Ok(Err(rar_err)) => {
            pending.borrow_mut().take();
            if let Some(err) = stashed_err {
                return Err(err);
            }
            let vol_hint = opened.volume_paths.first().map(|p| p.as_path());
            return Err(map_rar_error(&rar_err, vol_hint));
        }
        Err(_) => {
            pending.borrow_mut().take();
            return Err(DandiError::CorruptArchive(
                "RAR extractor encountered an internal error on malformed archive data".to_string(),
            ));
        }
    }

    let sink_owned = Rc::try_unwrap(sink)
        .map_err(|_| DandiError::ArchiveEngine("RAR extraction sink still borrowed".to_string()))?
        .into_inner();

    let reported_dir_str = sink_owned.reported_output_dir().display().to_string();
    let report = sink_owned.finish(
        ArchiveFormat::Rar,
        detection.encoding,
        applied_encoding,
        junk_skipped,
    )?;

    observer.on_progress(&ProgressEvent {
        phase: ProgressPhase::Finalizing,
        current_entry: reported_dir_str,
        entries_done: total_entries,
        entries_total: total_entries,
        bytes_done: report.bytes_written,
        bytes_total: total_bytes_planned.max(1),
    });

    Ok(report)
}

fn map_rar_error(err: &RarError, first_volume: Option<&Path>) -> DandiError {
    if matches!(err.root_cause(), RarError::MissingVolume) {
        if let RarError::InVolume { index, .. } = err {
            if let Some(first) = first_volume {
                return DandiError::CorruptArchive(format!(
                    "missing RAR volume {} for '{}'",
                    index + 1,
                    first.display()
                ));
            }
        }
        return DandiError::CorruptArchive(err.to_string());
    }

    match err.kind() {
        RarErrorKind::PasswordRequired => DandiError::PasswordRequired,
        RarErrorKind::BadPassword => DandiError::InvalidPassword,
        RarErrorKind::Cancelled => DandiError::Cancelled,
        RarErrorKind::ResourceLimit => DandiError::BudgetExceeded {
            reason: err.to_string(),
        },
        RarErrorKind::UnsupportedFormat | RarErrorKind::UnsupportedFeature => {
            DandiError::UnsupportedFormat(err.to_string())
        }
        RarErrorKind::UnsafePath => DandiError::UnsafePath {
            path: String::new(),
            reason: err.to_string(),
        },
        RarErrorKind::InvalidArgument => DandiError::InvalidInput(err.to_string()),
        RarErrorKind::Io => DandiError::CorruptArchive(err.to_string()),
        _ => DandiError::CorruptArchive(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_part_resolves_to_padded_or_unpadded_first_volume() {
        let tmp = tempfile::TempDir::new().unwrap();
        for name in [
            "plain.part1.rar",
            "plain.part10.rar",
            "pad.part01.rar",
            "pad.part02.rar",
        ] {
            fs::write(tmp.path().join(name), b"").unwrap();
        }
        let first = resolve_native_rar_first_volume(&tmp.path().join("plain.part10.rar")).unwrap();
        assert_eq!(first, tmp.path().join("plain.part1.rar"));
        let first = resolve_native_rar_first_volume(&tmp.path().join("pad.part02.rar")).unwrap();
        assert_eq!(first, tmp.path().join("pad.part01.rar"));
        assert!(matches!(
            resolve_native_rar_first_volume(&tmp.path().join("gone.part3.rar")),
            Err(DandiError::CorruptArchive(_))
        ));
    }
}
