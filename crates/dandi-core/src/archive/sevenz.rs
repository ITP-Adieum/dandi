use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sevenz_rust2::encoder_options::{AesEncoderOptions, Lzma2Options};
use sevenz_rust2::{
    ArchiveEntry, ArchiveReader, ArchiveWriter, EncoderConfiguration, EncoderMethod, EntryDecision,
    NtTime, Password,
};
use unicode_normalization::UnicodeNormalization;

use crate::archive::extract_sink::ExtractionSink;
use crate::archive::split::{
    discover_volumes, ensure_split_destination_free, validate_split_size, SplitFileReader,
    SplitStyle, SplitVolumeWriter,
};
use crate::archive::zip::writer::{
    collect_pack_items, commit_temp_file, create_sibling_temp_path, is_incompressible_extension,
    PackItem, TempFileGuard,
};
use crate::archive::{
    plan_extract_root, synthesize_parent_dirs, ArchiveEntryInfo, ArchiveFormat, ArchiveSummary,
    EntryKind, InspectOptions, PackOptions, PackReport, UnpackOptions, UnpackReport,
};
use crate::codec::{EncodingCandidate, EncodingDetection, EncodingId};
use crate::error::{DandiError, Result};
use crate::platform::{read_zone_identifier, to_fs_path};
use crate::progress::{CancellationToken, ProgressEvent, ProgressObserver, ProgressPhase};
use crate::safety::{is_os_junk, sanitize_entry_path};

const STREAM_BUF_SIZE: usize = 256 * 1024;
/// 7-Zip's own key-derivation work factor (2^19 SHA-256 rounds). `sevenz-rust2` caches the
/// derived key per salt, and every block in one archive shares the salt, so this cost is paid
/// once per archive rather than once per entry.
const AES_CYCLES_POWER: u8 = 19;
const MAX_SYMLINK_TARGET_BYTES: u64 = 4096;

/// 7-Zip/p7zip store `st_mode` in the high 16 bits of the Windows attributes, flagged by
/// `FILE_ATTRIBUTE_UNIX_EXTENSION`.
const ATTR_UNIX_EXTENSION: u32 = 0x8000;
const ATTR_READONLY: u32 = 0x01;
const ATTR_DIRECTORY: u32 = 0x10;
const ATTR_ARCHIVE: u32 = 0x20;
const S_IFMT: u32 = 0o170_000;
const S_IFLNK: u32 = 0o120_000;

struct CancelReadWrapper<R: Read> {
    inner: R,
    cancel: CancellationToken,
    err_slot: Arc<Mutex<Option<DandiError>>>,
}

impl<R: Read> Read for CancelReadWrapper<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancel.is_cancelled() {
            if let Ok(mut slot) = self.err_slot.lock() {
                if slot.is_none() {
                    *slot = Some(DandiError::Cancelled);
                }
            }
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "operation cancelled",
            ));
        }
        self.inner.read(buf)
    }
}

/// Packs files/directories into a `.7z` archive (single file or numeric `.7z.001/.002` split)
/// with Unicode NFC paths, OS junk filtering, optional AES-256 encryption (including headers),
/// cooperative cancellation, and atomic rollback on error.
pub(crate) fn pack_7z(
    inputs: &[PathBuf],
    output_7z: &Path,
    opts: &PackOptions,
    observer: &dyn ProgressObserver,
) -> Result<PackReport> {
    opts.cancel.check()?;
    let split_size = validate_split_size(opts.split_size_bytes)?;

    if !opts.overwrite {
        match split_size {
            None if to_fs_path(output_7z).exists() => {
                return Err(DandiError::AlreadyExists {
                    path: output_7z.to_path_buf(),
                });
            }
            None => {}
            Some(_) => ensure_split_destination_free(output_7z, SplitStyle::Numeric)?,
        }
    }

    if let Some(parent) = output_7z.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(to_fs_path(parent)).map_err(|e| DandiError::io(parent, e))?;
        }
    }

    observer.on_progress(&ProgressEvent {
        phase: ProgressPhase::Scanning,
        current_entry: String::new(),
        entries_done: 0,
        entries_total: 0,
        bytes_done: 0,
        bytes_total: 0,
    });

    let (items, junk_skipped) = collect_pack_items(inputs, opts)?;
    let total_input_bytes: u64 = items.iter().map(|i| i.size).sum();

    let report = match split_size {
        None => {
            let tmp_path = create_sibling_temp_path(output_7z, "7z");
            let mut guard = TempFileGuard::new(tmp_path.clone());
            let tmp_file =
                File::create(to_fs_path(&tmp_path)).map_err(|e| DandiError::io(&tmp_path, e))?;
            let (mut report, mut writer) = pack_7z_into(
                BufWriter::with_capacity(STREAM_BUF_SIZE, tmp_file),
                &items,
                output_7z,
                opts,
                junk_skipped,
                total_input_bytes,
                observer,
            )?;
            writer.flush()?;
            drop(writer);
            let output_bytes = fs::metadata(to_fs_path(&tmp_path))
                .map(|m| m.len())
                .unwrap_or(0);
            commit_temp_file(&tmp_path, output_7z, opts.overwrite)?;
            guard.disarm();
            report.output_path = output_7z.to_path_buf();
            report.output_volumes = vec![output_7z.to_path_buf()];
            report.output_bytes = output_bytes;
            report
        }
        Some(limit) => {
            let split_writer = SplitVolumeWriter::new(output_7z, limit)?;
            let (mut report, finished_writer) = pack_7z_into(
                split_writer,
                &items,
                output_7z,
                opts,
                junk_skipped,
                total_input_bytes,
                observer,
            )?;
            let (primary, volumes, total_bytes) =
                finished_writer.commit(output_7z, opts.overwrite)?;
            report.output_path = primary;
            report.output_volumes = volumes;
            report.output_bytes = total_bytes;
            report
        }
    };

    observer.on_progress(&ProgressEvent {
        phase: ProgressPhase::Finalizing,
        current_entry: report.output_path.display().to_string(),
        entries_done: items.len(),
        entries_total: items.len(),
        bytes_done: total_input_bytes,
        bytes_total: total_input_bytes,
    });

    Ok(report)
}

fn pack_7z_into<W: Write + Seek>(
    sink: W,
    items: &[PackItem],
    output_7z: &Path,
    opts: &PackOptions,
    junk_skipped: usize,
    total_input_bytes: u64,
    observer: &dyn ProgressObserver,
) -> Result<(PackReport, W)> {
    let mut writer = ArchiveWriter::new(sink).map_err(|e| map_7z_error(e, false, false))?;
    let level = opts.compression_level.min(9);

    let base_aes: Option<AesEncoderOptions> = opts
        .password
        .as_deref()
        .map(|pw| {
            let pw_nfc: String = pw.nfc().collect();
            Ok::<_, DandiError>(AesEncoderOptions {
                password: Password::from(pw_nfc.as_str()),
                iv: random_16()?,
                salt: random_16()?,
                num_cycles_power: AES_CYCLES_POWER,
            })
        })
        .transpose()?;
    let encrypted = base_aes.is_some();

    // Ensure header encryption is configured even if the archive has only empty/directory entries.
    if let Some(ref aes) = base_aes {
        writer.set_encrypt_header(true);
        writer.set_content_methods(build_7z_methods(Some(aes), level, false));
    } else {
        writer.set_content_methods(build_7z_methods(None, level, false));
    }

    let err_slot: Arc<Mutex<Option<DandiError>>> = Arc::new(Mutex::new(None));
    let mut files_deflated = 0usize;
    let mut files_stored = 0usize;
    let mut bytes_done = 0u64;

    for (idx, item) in items.iter().enumerate() {
        opts.cancel.check()?;
        let nt_mtime = unix_secs_to_nt_time(item.mtime_secs);

        match item.kind {
            EntryKind::Directory => {
                let clean_dir = item.archive_name.trim_end_matches('/');
                if !clean_dir.is_empty() {
                    let mut entry = ArchiveEntry::new_directory(clean_dir);
                    entry.has_last_modified_date = true;
                    entry.last_modified_date = nt_mtime;
                    entry.has_windows_attributes = true;
                    entry.windows_attributes = unix_attributes(item.kind, item.unix_mode);
                    writer
                        .push_archive_entry::<&[u8]>(entry, None)
                        .map_err(|e| take_or_map_7z(&err_slot, e))?;
                }
            }
            EntryKind::Symlink => {
                let target_bytes = item
                    .symlink_target
                    .as_deref()
                    .unwrap_or_default()
                    .as_bytes();
                let mut entry = ArchiveEntry::new_file(&item.archive_name);
                entry.has_last_modified_date = true;
                entry.last_modified_date = nt_mtime;
                entry.has_windows_attributes = true;
                entry.windows_attributes = unix_attributes(item.kind, item.unix_mode);
                let aes_for_entry = base_aes.as_ref().map(fresh_iv_aes_options).transpose()?;
                writer.set_content_methods(build_7z_methods(aes_for_entry.as_ref(), level, true));
                writer
                    .push_archive_entry(entry, Some(target_bytes))
                    .map_err(|e| take_or_map_7z(&err_slot, e))?;
                files_stored += 1;
                bytes_done = bytes_done.saturating_add(target_bytes.len() as u64);
            }
            EntryKind::File => {
                let use_store =
                    item.size == 0 || level == 0 || is_incompressible_extension(&item.archive_name);
                if use_store {
                    files_stored += 1;
                } else {
                    files_deflated += 1;
                }
                let aes_for_entry = base_aes.as_ref().map(fresh_iv_aes_options).transpose()?;
                writer.set_content_methods(build_7z_methods(
                    aes_for_entry.as_ref(),
                    level,
                    use_store,
                ));

                let mut entry = ArchiveEntry::new_file(&item.archive_name);
                entry.has_last_modified_date = true;
                entry.last_modified_date = nt_mtime;
                entry.has_windows_attributes = true;
                entry.windows_attributes = unix_attributes(item.kind, item.unix_mode);

                if item.size == 0 {
                    writer
                        .push_archive_entry::<&[u8]>(entry, None)
                        .map_err(|e| take_or_map_7z(&err_slot, e))?;
                } else {
                    let src = File::open(to_fs_path(&item.fs_path))
                        .map_err(|e| DandiError::io(&item.fs_path, e))?;
                    let guarded = CancelReadWrapper {
                        inner: src,
                        cancel: opts.cancel.clone(),
                        err_slot: Arc::clone(&err_slot),
                    };
                    writer
                        .push_archive_entry(entry, Some(guarded))
                        .map_err(|e| take_or_map_7z(&err_slot, e))?;
                    bytes_done = bytes_done.saturating_add(item.size);
                }
            }
        }

        observer.on_progress(&ProgressEvent {
            phase: ProgressPhase::Packing,
            current_entry: item.archive_name.clone(),
            entries_done: idx + 1,
            entries_total: items.len(),
            bytes_done,
            bytes_total: total_input_bytes,
        });
    }

    opts.cancel.check()?;
    // Give the encrypted header its own fresh IV while keeping the same KDF salt.
    if let Some(ref aes) = base_aes {
        let header_aes = fresh_iv_aes_options(aes)?;
        writer.set_content_methods(build_7z_methods(Some(&header_aes), level, false));
    }

    let finished = writer.finish().map_err(DandiError::io_plain)?;

    let report = PackReport {
        output_path: output_7z.to_path_buf(),
        output_volumes: vec![output_7z.to_path_buf()],
        entries_written: items.len(),
        files_deflated,
        files_stored,
        junk_skipped,
        total_input_bytes,
        output_bytes: 0,
        used_zip64: false,
        encrypted,
    };
    Ok((report, finished))
}

/// Same password and salt (so the cached key is reused) with a fresh random IV per block.
fn fresh_iv_aes_options(base: &AesEncoderOptions) -> Result<AesEncoderOptions> {
    Ok(AesEncoderOptions {
        password: base.password.clone(),
        iv: random_16()?,
        salt: base.salt,
        num_cycles_power: base.num_cycles_power,
    })
}

fn random_16() -> Result<[u8; 16]> {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).map_err(|e| {
        DandiError::ArchiveEngine(format!("OS random generator unavailable for 7z AES: {e}"))
    })?;
    Ok(buf)
}

fn unix_attributes(kind: EntryKind, unix_mode: u32) -> u32 {
    let dos = match kind {
        EntryKind::Directory => ATTR_DIRECTORY,
        EntryKind::File | EntryKind::Symlink => ATTR_ARCHIVE,
    };
    let readonly = if unix_mode & 0o222 == 0 {
        ATTR_READONLY
    } else {
        0
    };
    dos | readonly | ATTR_UNIX_EXTENSION | ((unix_mode & 0xFFFF) << 16)
}

/// Maps the `&ArchiveEntry` handed to `for_each_entries*` back to its index in
/// `archive.files`. `sevenz-rust2` visits entries block by block and only then the stream-less
/// ones, so a running counter does not match the file index used by `selected_entries`.
struct EntryIndexer {
    base: usize,
    len: usize,
}

impl EntryIndexer {
    fn new(files: &[ArchiveEntry]) -> Self {
        Self {
            base: files.as_ptr() as usize,
            len: files.len(),
        }
    }

    fn index_of(&self, entry: &ArchiveEntry) -> Result<usize> {
        let size = std::mem::size_of::<ArchiveEntry>().max(1);
        let offset = (entry as *const ArchiveEntry as usize).wrapping_sub(self.base);
        let idx = offset / size;
        if offset.is_multiple_of(size) && idx < self.len {
            Ok(idx)
        } else {
            Err(DandiError::ArchiveEngine(format!(
                "7z entry '{}' does not belong to the opened archive",
                entry.name()
            )))
        }
    }
}

fn unix_mode_of(entry: &ArchiveEntry) -> Option<u32> {
    (entry.has_windows_attributes && entry.windows_attributes & ATTR_UNIX_EXTENSION != 0)
        .then_some(entry.windows_attributes >> 16)
        .filter(|mode| *mode != 0)
}

fn entry_kind_of(entry: &ArchiveEntry) -> EntryKind {
    if entry.is_directory() {
        EntryKind::Directory
    } else if unix_mode_of(entry).is_some_and(|m| m & S_IFMT == S_IFLNK) {
        EntryKind::Symlink
    } else {
        EntryKind::File
    }
}

fn build_7z_methods(
    aes: Option<&AesEncoderOptions>,
    level: u32,
    use_store: bool,
) -> Vec<EncoderConfiguration> {
    let mut methods = Vec::with_capacity(2);
    if let Some(aes_opts) = aes {
        methods.push(aes_opts.clone().into());
    }
    if use_store {
        methods.push(EncoderConfiguration::new(EncoderMethod::COPY));
    } else {
        methods.push(Lzma2Options::from_level(level).into());
    }
    methods
}

fn open_7z_reader(
    archive_path: &Path,
    password: Option<&str>,
) -> Result<(ArchiveReader<SplitFileReader>, u64, bool)> {
    let vol_set = discover_volumes(archive_path)?;
    let split_reader = SplitFileReader::open(&vol_set.volumes)?;
    let total_len = split_reader.total_len().max(1);

    let Some(raw_pw) = password else {
        let reader = ArchiveReader::new(split_reader, Password::empty())
            .map_err(|e| map_7z_open_error(e, false))?;
        let encrypted = archive_uses_aes256(reader.archive());
        return Ok((reader, total_len, encrypted));
    };

    let pw_nfc: String = raw_pw.nfc().collect();
    match ArchiveReader::new(split_reader, Password::from(pw_nfc.as_str())) {
        Ok(reader) => {
            let encrypted =
                archive_uses_aes256(reader.archive()) || header_requires_password(&vol_set.volumes);
            Ok((reader, total_len, encrypted))
        }
        Err(first_err) => {
            if pw_nfc != raw_pw {
                let retry_reader = SplitFileReader::open(&vol_set.volumes)?;
                if let Ok(reader) = ArchiveReader::new(retry_reader, Password::from(raw_pw)) {
                    let encrypted = archive_uses_aes256(reader.archive())
                        || header_requires_password(&vol_set.volumes);
                    return Ok((reader, total_len, encrypted));
                }
            }
            let header_enc = header_requires_password(&vol_set.volumes);
            Err(map_7z_error(first_err, true, header_enc))
        }
    }
}

fn header_requires_password(volumes: &[PathBuf]) -> bool {
    let Ok(split) = SplitFileReader::open(volumes) else {
        return false;
    };
    matches!(
        ArchiveReader::new(split, Password::empty()),
        Err(sevenz_rust2::Error::PasswordRequired)
    )
}

fn archive_uses_aes256(archive: &sevenz_rust2::Archive) -> bool {
    let aes_id = EncoderMethod::AES256_SHA256.id();
    archive
        .blocks
        .iter()
        .any(|block| block.coders.iter().any(|c| c.encoder_method_id() == aes_id))
}

pub(crate) fn inspect_7z(archive_path: &Path, opts: &InspectOptions) -> Result<ArchiveSummary> {
    let (reader, total_compressed, archive_encrypted) =
        open_7z_reader(archive_path, opts.password.as_deref())?;
    let archive = reader.archive();

    if archive.files.len() > opts.budget.max_entries {
        return Err(DandiError::BudgetExceeded {
            reason: format!(
                "7z archive declares {} entries, exceeding limit {}",
                archive.files.len(),
                opts.budget.max_entries
            ),
        });
    }

    let mut entries = Vec::with_capacity(archive.files.len().min(4096));
    let mut total_uncompressed = 0u64;

    for (idx, file) in archive.files.iter().enumerate() {
        let path_nfc: String = file.name().nfc().collect();
        let junk = is_os_junk(&path_nfc);
        if junk && !opts.include_os_junk {
            continue;
        }
        let size = file.size();
        total_uncompressed = total_uncompressed.saturating_add(size);
        let mtime = if file.has_last_modified_date {
            nt_time_to_unix_secs(file.last_modified_date())
        } else {
            None
        };
        entries.push(ArchiveEntryInfo {
            index: Some(idx),
            path: path_nfc,
            kind: entry_kind_of(file),
            uncompressed_size: size,
            compressed_size: file.compressed_size,
            modified_unix_secs: mtime,
            unix_mode: unix_mode_of(file),
            encrypted: archive_encrypted,
            compression_method: "7z".to_string(),
            is_os_junk: junk,
            is_synthesized: false,
            symlink_target: None,
        });
    }

    let entries = synthesize_parent_dirs(entries);
    let total_entries = entries.len();

    Ok(ArchiveSummary {
        format: ArchiveFormat::SevenZ,
        encoding: EncodingDetection {
            encoding: EncodingId::Utf8,
            confidence: 1.0,
            candidates: vec![EncodingCandidate {
                encoding: EncodingId::Utf8,
                score: 1.0,
                had_errors: false,
            }],
        },
        applied_encoding: EncodingId::Utf8,
        total_entries,
        total_uncompressed_bytes: total_uncompressed,
        total_compressed_bytes: total_compressed,
        encrypted: archive_encrypted,
        entries,
    })
}

/// Reads the targets of the selected symlink entries (stored as entry data, as 7-Zip does) so
/// they can be registered with the sink before any regular file is written.
fn read_symlink_targets(
    archive_path: &Path,
    password: Option<&str>,
    wanted: &HashSet<usize>,
    cancel: &CancellationToken,
) -> Result<HashMap<usize, String>> {
    let (mut reader, _, archive_encrypted) = open_7z_reader(archive_path, password)?;
    let indexer = EntryIndexer::new(&reader.archive().files);
    let mut targets: HashMap<usize, String> = HashMap::with_capacity(wanted.len());
    let mut callback_err: Option<DandiError> = None;

    let res = reader.for_each_entries_with_decision(|entry, data| {
        if let Err(e) = cancel.check() {
            callback_err = Some(e);
            return Ok(EntryDecision::Stop);
        }
        let current = match indexer.index_of(entry) {
            Ok(i) => i,
            Err(e) => {
                callback_err = Some(e);
                return Ok(EntryDecision::Stop);
            }
        };
        if !wanted.contains(&current) || targets.contains_key(&current) {
            return Ok(EntryDecision::Continue);
        }
        let mut raw = Vec::new();
        if let Err(e) = data
            .take(MAX_SYMLINK_TARGET_BYTES + 1)
            .read_to_end(&mut raw)
        {
            callback_err = Some(map_7z_read_io_error(
                e,
                password.is_some(),
                archive_encrypted,
            ));
            return Ok(EntryDecision::Stop);
        }
        let name: String = entry.name().nfc().collect();
        if raw.len() as u64 > MAX_SYMLINK_TARGET_BYTES {
            callback_err = Some(DandiError::UnsafeSymlink {
                path: name,
                target: String::new(),
                reason: format!("symlink target exceeds {MAX_SYMLINK_TARGET_BYTES} bytes"),
            });
            return Ok(EntryDecision::Stop);
        }
        match String::from_utf8(raw) {
            Ok(target) => {
                targets.insert(current, target.nfc().collect());
            }
            Err(_) => {
                callback_err = Some(DandiError::UnsafeSymlink {
                    path: name,
                    target: "<non-utf8>".to_string(),
                    reason: "symlink target is not valid UTF-8".to_string(),
                });
                return Ok(EntryDecision::Stop);
            }
        }
        Ok(if targets.len() == wanted.len() {
            EntryDecision::Stop
        } else {
            EntryDecision::Continue
        })
    });

    if let Some(err) = callback_err {
        return Err(err);
    }
    res.map_err(|e| map_7z_error(e, password.is_some(), archive_encrypted))?;
    Ok(targets)
}

pub(crate) fn unpack_7z(
    archive_path: &Path,
    dest_dir: &Path,
    opts: &UnpackOptions,
    observer: &dyn ProgressObserver,
) -> Result<UnpackReport> {
    opts.cancel.check()?;
    let password_provided = opts.password.is_some();
    let (mut reader, archive_file_size, archive_encrypted) =
        open_7z_reader(archive_path, opts.password.as_deref())?;

    let zone_data = if opts.propagate_zone_identifier {
        read_zone_identifier(archive_path)
    } else {
        None
    };

    let mut budget = opts.budget.clone();
    budget.set_archive_compressed_size(archive_file_size);
    let mut visible_for_smart: Vec<(String, EntryKind)> = Vec::new();
    let mut junk_skipped = 0usize;
    let mut total_bytes_planned = 0u64;
    let mut wanted_symlinks: HashSet<usize> = HashSet::new();
    let total_count = reader.archive().files.len();

    if total_count > budget.max_entries {
        return Err(DandiError::BudgetExceeded {
            reason: format!(
                "7z archive declares {total_count} entries, exceeding limit {}",
                budget.max_entries
            ),
        });
    }

    for (idx, file) in reader.archive().files.iter().enumerate() {
        opts.cancel.check()?;
        let name_nfc: String = file.name().nfc().collect();
        if opts.exclude_os_junk && is_os_junk(&name_nfc) {
            junk_skipped += 1;
            continue;
        }
        if let Some(ref sel) = opts.selected_entries {
            if !sel.contains(&idx) {
                continue;
            }
        }
        let kind = entry_kind_of(file);
        if kind == EntryKind::Symlink {
            wanted_symlinks.insert(idx);
        }
        budget.record_entry(file.size(), 0)?;
        let sanitized = sanitize_entry_path(&name_nfc, opts.path_policy)?;
        visible_for_smart.push((sanitized.normalized().to_string(), kind));
        total_bytes_planned = total_bytes_planned.saturating_add(file.size());
    }

    let plan = plan_extract_root(
        archive_path,
        dest_dir,
        opts.mode,
        opts.overwrite,
        &visible_for_smart,
    )?;

    let mut sink = ExtractionSink::new(plan, opts, budget, zone_data)?;

    let mut symlink_targets = if wanted_symlinks.is_empty() {
        HashMap::new()
    } else {
        read_symlink_targets(
            archive_path,
            opts.password.as_deref(),
            &wanted_symlinks,
            &opts.cancel,
        )?
    };
    for (idx, target) in &symlink_targets {
        if let Some(file) = reader.archive().files.get(*idx) {
            let name_nfc: String = file.name().nfc().collect();
            sink.register_declared_symlink(&name_nfc, target)?;
        }
    }
    sink.validate_declared_symlink_chains()?;

    let indexer = EntryIndexer::new(&reader.archive().files);
    let mut visited = vec![false; total_count];
    let mut entries_done = 0usize;
    let mut callback_err: Option<DandiError> = None;

    let iter_res = reader.for_each_entries_with_decision(|entry, data_reader| {
        if let Err(e) = opts.cancel.check() {
            callback_err = Some(e);
            return Ok(EntryDecision::Stop);
        }
        let current_idx = match indexer.index_of(entry) {
            Ok(i) => i,
            Err(e) => {
                callback_err = Some(e);
                return Ok(EntryDecision::Stop);
            }
        };
        if std::mem::replace(&mut visited[current_idx], true) {
            return Ok(EntryDecision::Continue);
        }
        entries_done += 1;

        let name_nfc: String = entry.name().nfc().collect();
        let skip_entry = (opts.exclude_os_junk && is_os_junk(&name_nfc))
            || opts
                .selected_entries
                .as_ref()
                .is_some_and(|sel| !sel.contains(&current_idx));
        if skip_entry {
            if !entry.is_directory() {
                if let Err(e) = sink.record_skipped_bytes(entry.size(), archive_file_size) {
                    callback_err = Some(e);
                    return Ok(EntryDecision::Stop);
                }
            }
            return Ok(EntryDecision::Continue);
        }

        let mtime = if entry.has_last_modified_date {
            nt_time_to_unix_secs(entry.last_modified_date())
        } else {
            None
        };
        let unix_mode = unix_mode_of(entry);

        let extract_res = match entry_kind_of(entry) {
            EntryKind::Directory => sink.extract_directory(&name_nfc, mtime, unix_mode),
            EntryKind::Symlink => match symlink_targets.remove(&current_idx) {
                Some(target) => sink.queue_symlink(&name_nfc, target, mtime),
                None => Err(DandiError::CorruptArchive(format!(
                    "7z symlink entry '{name_nfc}' has no readable target"
                ))),
            },
            EntryKind::File => sink.extract_file(
                &name_nfc,
                data_reader,
                archive_file_size,
                false,
                mtime,
                unix_mode,
                |e| map_7z_read_io_error(e, password_provided, archive_encrypted),
            ),
        };

        match extract_res {
            Ok(Some(current_entry)) => {
                observer.on_progress(&ProgressEvent {
                    phase: ProgressPhase::Unpacking,
                    current_entry,
                    entries_done,
                    entries_total: total_count,
                    bytes_done: sink.bytes_written(),
                    bytes_total: total_bytes_planned.max(1),
                });
            }
            Ok(None) => {}
            Err(e) => {
                callback_err = Some(e);
                return Ok(EntryDecision::Stop);
            }
        }

        Ok(EntryDecision::Continue)
    });

    if let Some(err) = callback_err {
        return Err(err);
    }
    iter_res.map_err(|e| map_7z_error(e, password_provided, archive_encrypted))?;

    sink.finish(
        ArchiveFormat::SevenZ,
        EncodingId::Utf8,
        EncodingId::Utf8,
        junk_skipped,
    )
}

fn nt_time_to_unix_secs(nt: NtTime) -> Option<i64> {
    let st: SystemTime = nt.into();
    st.duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as i64)
}

fn unix_secs_to_nt_time(unix_secs: i64) -> NtTime {
    let st = if unix_secs >= 0 {
        UNIX_EPOCH + Duration::from_secs(unix_secs as u64)
    } else {
        UNIX_EPOCH
    };
    NtTime::try_from(st).unwrap_or_default()
}

fn take_or_map_7z(slot: &Arc<Mutex<Option<DandiError>>>, err: sevenz_rust2::Error) -> DandiError {
    if let Ok(mut guard) = slot.lock() {
        if let Some(dandi_err) = guard.take() {
            return dandi_err;
        }
    }
    map_7z_error(err, false, false)
}

fn map_7z_open_error(err: sevenz_rust2::Error, password_provided: bool) -> DandiError {
    map_7z_error(err, password_provided, false)
}

fn map_7z_error(
    err: sevenz_rust2::Error,
    password_provided: bool,
    archive_encrypted: bool,
) -> DandiError {
    match err {
        sevenz_rust2::Error::PasswordRequired => DandiError::PasswordRequired,
        sevenz_rust2::Error::MaybeBadPassword(_) => {
            if password_provided {
                DandiError::InvalidPassword
            } else {
                DandiError::PasswordRequired
            }
        }
        sevenz_rust2::Error::ChecksumVerificationFailed if archive_encrypted => {
            if password_provided {
                DandiError::InvalidPassword
            } else {
                DandiError::PasswordRequired
            }
        }
        sevenz_rust2::Error::Io(ref io_err, _) if archive_encrypted => {
            if !password_provided {
                DandiError::PasswordRequired
            } else if io_err.kind() == io::ErrorKind::InvalidData
                || io_err.kind() == io::ErrorKind::UnexpectedEof
                || io_err.to_string().to_ascii_lowercase().contains("checksum")
                || io_err
                    .to_string()
                    .to_ascii_lowercase()
                    .contains("illegalblocksize")
            {
                DandiError::InvalidPassword
            } else {
                DandiError::CorruptArchive(err.to_string())
            }
        }
        other => {
            if archive_encrypted && password_provided {
                let lower = other.to_string().to_ascii_lowercase();
                if lower.contains("header")
                    || lower.contains("checksum")
                    || lower.contains("password")
                    || lower.contains("lzma")
                    || lower.contains("corrupt")
                {
                    return DandiError::InvalidPassword;
                }
            }
            DandiError::CorruptArchive(other.to_string())
        }
    }
}

fn map_7z_read_io_error(
    err: io::Error,
    password_provided: bool,
    archive_encrypted: bool,
) -> DandiError {
    let msg = err.to_string();
    let lower = msg.to_ascii_lowercase();
    if lower.contains("passwordrequired") {
        return DandiError::PasswordRequired;
    }
    if lower.contains("maybebadpassword") {
        return if password_provided {
            DandiError::InvalidPassword
        } else {
            DandiError::PasswordRequired
        };
    }
    if archive_encrypted {
        if !password_provided {
            return DandiError::PasswordRequired;
        }
        if err.kind() == io::ErrorKind::InvalidData
            || err.kind() == io::ErrorKind::UnexpectedEof
            || lower.contains("checksum")
            || lower.contains("illegalblocksize")
            || lower.contains("corrupt")
            || lower.contains("lzma")
        {
            return DandiError::InvalidPassword;
        }
    }
    DandiError::CorruptArchive(msg)
}
