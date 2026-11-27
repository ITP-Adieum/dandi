use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use unicode_normalization::UnicodeNormalization;
use zip::ZipArchive;

use crate::archive::extract_sink::ExtractionSink;
use crate::archive::zip::header::{compression_method_name, read_zip_raw_entries};
use crate::archive::{
    plan_extract_root, synthesize_parent_dirs, ArchiveEntryInfo, ArchiveFormat, ArchiveSummary,
    EntryKind, InspectOptions, UnpackOptions, UnpackReport,
};
use crate::codec::{decode_entry_name_with_override, detect_archive_encoding, EntryEncodingFlags};
use crate::error::{DandiError, Result};
use crate::platform::{read_zone_identifier, to_fs_path};
use crate::progress::{ProgressEvent, ProgressObserver, ProgressPhase};
use crate::safety::{is_os_junk, sanitize_entry_path};

const STREAM_BUF_SIZE: usize = 256 * 1024;

pub(crate) fn inspect_zip(archive_path: &Path, opts: &InspectOptions) -> Result<ArchiveSummary> {
    let fs_path = to_fs_path(archive_path);
    let mut file = File::open(&fs_path).map_err(|e| DandiError::io(archive_path, e))?;
    let raw_headers = read_zip_raw_entries(&mut file, opts.budget.max_entries)?;

    let non_bit11_names: Vec<&[u8]> = raw_headers
        .iter()
        .filter(|h| !h.utf8_bit11() && !h.has_valid_0x7075())
        .map(|h| h.raw_name.as_slice())
        .collect();
    let detection = detect_archive_encoding(&non_bit11_names, opts.locale_hint);
    let applied_encoding = opts.encoding_override.unwrap_or(detection.encoding);
    let explicit_override = opts.encoding_override.is_some();

    let mut entries = Vec::with_capacity(raw_headers.len());
    let mut total_uncompressed = 0u64;
    let mut total_compressed = 0u64;
    let mut any_encrypted = false;

    for h in &raw_headers {
        let decoded = decode_entry_name_with_override(
            &h.raw_name,
            EntryEncodingFlags {
                utf8_bit11: h.utf8_bit11(),
            },
            h.unicode_extra_0x7075(),
            applied_encoding,
            explicit_override,
        );
        let junk = is_os_junk(&decoded.path);
        if junk && !opts.include_os_junk {
            continue;
        }
        let kind = if h.is_symlink() {
            EntryKind::Symlink
        } else if h.is_dir_with_decoded_name(&decoded.path) {
            EntryKind::Directory
        } else {
            EntryKind::File
        };
        if h.encrypted() {
            any_encrypted = true;
        }
        total_uncompressed = total_uncompressed.saturating_add(h.uncompressed_size);
        total_compressed = total_compressed.saturating_add(h.compressed_size);

        entries.push(ArchiveEntryInfo {
            index: Some(h.index),
            path: decoded.path,
            kind,
            uncompressed_size: h.uncompressed_size,
            compressed_size: h.compressed_size,
            modified_unix_secs: h.mtime_unix_secs,
            unix_mode: h.unix_mode(),
            encrypted: h.encrypted(),
            compression_method: compression_method_name(h.compression_method),
            is_os_junk: junk,
            is_synthesized: false,
            symlink_target: None,
        });
    }

    let entries = synthesize_parent_dirs(entries);
    let total_entries = entries.len();

    Ok(ArchiveSummary {
        format: ArchiveFormat::Zip,
        encoding: detection,
        applied_encoding,
        total_entries,
        total_uncompressed_bytes: total_uncompressed,
        total_compressed_bytes: total_compressed,
        encrypted: any_encrypted,
        entries,
    })
}

pub(crate) fn unpack_zip(
    archive_path: &Path,
    dest_dir: &Path,
    opts: &UnpackOptions,
    observer: &dyn ProgressObserver,
) -> Result<UnpackReport> {
    opts.cancel.check()?;
    let fs_archive = to_fs_path(archive_path);
    let archive_file_size = fs::metadata(&fs_archive)
        .map(|m| m.len())
        .unwrap_or(1)
        .max(1);
    let mut raw_file = File::open(&fs_archive).map_err(|e| DandiError::io(archive_path, e))?;
    let raw_headers = read_zip_raw_entries(&mut raw_file, opts.budget.max_entries)?;

    let non_bit11_names: Vec<&[u8]> = raw_headers
        .iter()
        .filter(|h| !h.utf8_bit11() && !h.has_valid_0x7075())
        .map(|h| h.raw_name.as_slice())
        .collect();
    let detection = detect_archive_encoding(&non_bit11_names, opts.locale_hint);
    let applied_encoding = opts.encoding_override.unwrap_or(detection.encoding);
    let explicit_override = opts.encoding_override.is_some();

    let zone_data = if opts.propagate_zone_identifier {
        read_zone_identifier(archive_path)
    } else {
        None
    };

    struct PlannedZipEntry {
        index: usize,
        decoded_path: String,
        kind: EntryKind,
        compressed_size: u64,
        uncompressed_size: u64,
        mtime_unix_secs: Option<i64>,
        unix_mode: Option<u32>,
        encrypted: bool,
    }

    let mut planned = Vec::with_capacity(raw_headers.len());
    let mut junk_skipped = 0usize;
    let mut visible_for_smart: Vec<(String, EntryKind)> = Vec::new();
    let mut budget = opts.budget.clone();
    budget.set_archive_compressed_size(archive_file_size);

    for h in &raw_headers {
        opts.cancel.check()?;
        let decoded = decode_entry_name_with_override(
            &h.raw_name,
            EntryEncodingFlags {
                utf8_bit11: h.utf8_bit11(),
            },
            h.unicode_extra_0x7075(),
            applied_encoding,
            explicit_override,
        );
        let junk = is_os_junk(&decoded.path);
        if opts.exclude_os_junk && junk {
            junk_skipped += 1;
            continue;
        }
        if let Some(ref sel) = opts.selected_entries {
            if !sel.contains(&h.index) {
                continue;
            }
        }

        let kind = if h.is_symlink() {
            EntryKind::Symlink
        } else if h.is_dir_with_decoded_name(&decoded.path) {
            EntryKind::Directory
        } else {
            EntryKind::File
        };

        // Validate every entry path and budget up front before touching disk.
        budget.record_entry(h.uncompressed_size, h.compressed_size)?;
        let sanitized = sanitize_entry_path(&decoded.path, opts.path_policy)?;
        visible_for_smart.push((sanitized.normalized().to_string(), kind));

        planned.push(PlannedZipEntry {
            index: h.index,
            decoded_path: decoded.path,
            kind,
            compressed_size: h.compressed_size,
            uncompressed_size: h.uncompressed_size,
            mtime_unix_secs: h.mtime_unix_secs,
            unix_mode: h.unix_mode(),
            encrypted: h.encrypted(),
        });
    }

    let plan = plan_extract_root(
        archive_path,
        dest_dir,
        opts.mode,
        opts.overwrite,
        &visible_for_smart,
    )?;

    let mut sink = ExtractionSink::new(plan, opts, budget, zone_data)?;

    raw_file.seek(SeekFrom::Start(0))?;
    let mut archive = ZipArchive::new(BufReader::with_capacity(STREAM_BUF_SIZE, raw_file))
        .map_err(map_zip_error)?;

    let bytes_total_planned: u64 = planned
        .iter()
        .map(|e| e.uncompressed_size)
        .sum::<u64>()
        .max(1);

    // Pre-pass: read & register all symlink entries BEFORE creating any regular files,
    // blocking absolute targets, root escapes, symlink-ancestor writes, and multi-hop chaining.
    let mut symlink_targets: HashMap<usize, String> = HashMap::new();
    for entry in &planned {
        if entry.kind != EntryKind::Symlink {
            continue;
        }
        opts.cancel.check()?;
        let zf = open_zip_entry(
            &mut archive,
            entry.index,
            entry.encrypted,
            opts.password.as_deref(),
        )?;
        let mut target_bytes = Vec::new();
        zf.take(8192)
            .read_to_end(&mut target_bytes)
            .map_err(classify_zip_read_io_error)?;
        let target = String::from_utf8(target_bytes).map_err(|_| DandiError::UnsafeSymlink {
            path: entry.decoded_path.clone(),
            target: "<non-utf8>".to_string(),
            reason: "symlink target is not valid UTF-8".to_string(),
        })?;
        sink.register_declared_symlink(&entry.decoded_path, &target)?;
        symlink_targets.insert(entry.index, target);
    }
    sink.validate_declared_symlink_chains()?;

    for (done_idx, entry) in planned.iter().enumerate() {
        opts.cancel.check()?;
        let extracted_norm = match entry.kind {
            EntryKind::Directory => {
                sink.extract_directory(&entry.decoded_path, entry.mtime_unix_secs, entry.unix_mode)?
            }
            EntryKind::Symlink => {
                let target = symlink_targets.remove(&entry.index).unwrap_or_default();
                sink.queue_symlink(&entry.decoded_path, target, entry.mtime_unix_secs)?
            }
            EntryKind::File => {
                let mut zf = open_zip_entry(
                    &mut archive,
                    entry.index,
                    entry.encrypted,
                    opts.password.as_deref(),
                )?;
                sink.extract_file(
                    &entry.decoded_path,
                    &mut zf,
                    entry.compressed_size,
                    true,
                    entry.mtime_unix_secs,
                    entry.unix_mode,
                    classify_zip_read_io_error,
                )?
            }
        };

        if let Some(current_entry) = extracted_norm {
            observer.on_progress(&ProgressEvent {
                phase: ProgressPhase::Unpacking,
                current_entry,
                entries_done: done_idx + 1,
                entries_total: planned.len(),
                bytes_done: sink.bytes_written(),
                bytes_total: bytes_total_planned,
            });
        }
    }

    let reported_dir_str = sink.reported_output_dir().display().to_string();
    let report = sink.finish(
        ArchiveFormat::Zip,
        detection.encoding,
        applied_encoding,
        junk_skipped,
    )?;

    observer.on_progress(&ProgressEvent {
        phase: ProgressPhase::Finalizing,
        current_entry: reported_dir_str,
        entries_done: planned.len(),
        entries_total: planned.len(),
        bytes_done: report.bytes_written,
        bytes_total: bytes_total_planned,
    });

    Ok(report)
}

pub(crate) fn open_zip_entry<'a, R: Read + Seek>(
    archive: &'a mut ZipArchive<R>,
    index: usize,
    encrypted: bool,
    password: Option<&str>,
) -> Result<zip::read::ZipFile<'a, R>> {
    if !encrypted {
        return archive.by_index(index).map_err(map_zip_error);
    }

    let pw = password.ok_or(DandiError::PasswordRequired)?;
    let pw_nfc: String = pw.nfc().collect();

    // Try UTF-8 NFC password first; if raw password differs (e.g. legacy NFD), probe before opening.
    if pw_nfc != pw {
        let nfc_ok = archive.by_index_decrypt(index, pw_nfc.as_bytes()).is_ok();
        if nfc_ok {
            return archive
                .by_index_decrypt(index, pw_nfc.as_bytes())
                .map_err(map_zip_error);
        }
        return archive
            .by_index_decrypt(index, pw.as_bytes())
            .map_err(map_zip_error);
    }

    archive
        .by_index_decrypt(index, pw_nfc.as_bytes())
        .map_err(map_zip_error)
}

pub(crate) fn map_zip_error(err: zip::result::ZipError) -> DandiError {
    match err {
        zip::result::ZipError::InvalidPassword => DandiError::InvalidPassword,
        zip::result::ZipError::UnsupportedArchive(msg) => {
            if msg.to_ascii_lowercase().contains("password") {
                DandiError::PasswordRequired
            } else {
                DandiError::CorruptArchive(msg.to_string())
            }
        }
        zip::result::ZipError::InvalidArchive(msg) => DandiError::CorruptArchive(msg.to_string()),
        zip::result::ZipError::Io(e) => classify_zip_read_io_error(e),
        other => DandiError::CorruptArchive(other.to_string()),
    }
}

pub(crate) fn classify_zip_read_io_error(err: io::Error) -> DandiError {
    let msg = err.to_string();
    let lower = msg.to_ascii_lowercase();
    if lower.contains("invalid password") || lower.contains("authentication") {
        DandiError::InvalidPassword
    } else if err.kind() == io::ErrorKind::InvalidData
        || err.kind() == io::ErrorKind::UnexpectedEof
        || lower.contains("crc")
        || lower.contains("corrupt")
    {
        DandiError::CorruptArchive(msg)
    } else {
        DandiError::io_plain(err)
    }
}
