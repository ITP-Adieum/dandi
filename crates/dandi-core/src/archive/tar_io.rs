use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::Path;
use std::sync::{Arc, Mutex};

use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use lzma_rust2::XzReader;
use tar::{Archive, EntryType};

use crate::archive::extract_sink::ExtractionSink;
use crate::archive::{
    plan_extract_root, synthesize_parent_dirs, ArchiveEntryInfo, ArchiveFormat, ArchiveSummary,
    EntryKind, InspectOptions, UnpackOptions, UnpackReport,
};
use crate::codec::{decode_entry_name_with_override, detect_archive_encoding, EntryEncodingFlags};
use crate::error::{DandiError, Result};
use crate::platform::{read_zone_identifier, to_fs_path};
use crate::progress::{CancellationToken, ProgressEvent, ProgressObserver, ProgressPhase};
use crate::safety::{is_os_junk, sanitize_entry_path, SafetyBudget};

const STREAM_BUF_SIZE: usize = 256 * 1024;

type StreamErrorSlot = Arc<Mutex<Option<DandiError>>>;

/// Wraps a decompressed TAR byte stream to enforce `SafetyBudget` and `CancellationToken`
/// continuously across ALL entries (including skipped/unselected entries and header scans).
struct BudgetedReader<R: Read> {
    inner: R,
    bytes_read: u64,
    archive_file_size: u64,
    max_total_bytes: u64,
    max_compression_ratio: f64,
    ratio_check_threshold_bytes: u64,
    cancel: CancellationToken,
    error_slot: StreamErrorSlot,
}

impl<R: Read> BudgetedReader<R> {
    fn new(
        inner: R,
        archive_file_size: u64,
        budget: &SafetyBudget,
        cancel: CancellationToken,
        error_slot: StreamErrorSlot,
    ) -> Self {
        Self {
            inner,
            bytes_read: 0,
            archive_file_size: archive_file_size.max(1),
            max_total_bytes: budget.max_total_bytes,
            max_compression_ratio: budget.max_compression_ratio,
            ratio_check_threshold_bytes: budget.ratio_check_threshold_bytes,
            cancel,
            error_slot,
        }
    }

    fn record_stream_error(&self, err: DandiError) -> io::Error {
        let msg = err.to_string();
        if let Ok(mut guard) = self.error_slot.lock() {
            if guard.is_none() {
                *guard = Some(err);
            }
        }
        io::Error::other(msg)
    }
}

impl<R: Read> Read for BudgetedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancel.is_cancelled() {
            return Err(self.record_stream_error(DandiError::Cancelled));
        }

        let n = self.inner.read(buf)?;
        if n == 0 {
            return Ok(0);
        }

        self.bytes_read = match self.bytes_read.checked_add(n as u64) {
            Some(v) => v,
            None => {
                return Err(self.record_stream_error(DandiError::BudgetExceeded {
                    reason: "TAR decompressed stream byte counter overflow".to_string(),
                }));
            }
        };

        // Allow 512-byte TAR header/padding overhead margin while strictly bounding stream bombs.
        let stream_limit = self.max_total_bytes.saturating_add(1024 * 1024);
        if self.bytes_read > stream_limit {
            return Err(self.record_stream_error(DandiError::BudgetExceeded {
                reason: format!(
                    "TAR decompressed stream {} bytes exceeds limit {} bytes",
                    self.bytes_read, self.max_total_bytes
                ),
            }));
        }

        if self.bytes_read >= self.ratio_check_threshold_bytes {
            let ratio = (self.bytes_read as f64) / (self.archive_file_size as f64);
            if ratio > self.max_compression_ratio {
                return Err(self.record_stream_error(DandiError::BudgetExceeded {
                    reason: format!(
                        "TAR stream expansion ratio {ratio:.1}x exceeds limit {:.1}x",
                        self.max_compression_ratio
                    ),
                }));
            }
        }

        Ok(n)
    }
}

fn take_stream_or_corrupt(slot: &StreamErrorSlot, err: io::Error) -> DandiError {
    if let Ok(mut guard) = slot.lock() {
        if let Some(dandi_err) = guard.take() {
            return dandi_err;
        }
    }
    DandiError::CorruptArchive(err.to_string())
}

fn open_tar_reader(
    archive_path: &Path,
    fmt: ArchiveFormat,
    budget: &SafetyBudget,
    cancel: CancellationToken,
) -> Result<(Box<dyn Read>, StreamErrorSlot, u64)> {
    let fs_path = to_fs_path(archive_path);
    let archive_file_size = fs::metadata(&fs_path).map(|m| m.len()).unwrap_or(1).max(1);
    let file = File::open(&fs_path).map_err(|e| DandiError::io(archive_path, e))?;
    let buffered = BufReader::with_capacity(STREAM_BUF_SIZE, file);
    let error_slot: StreamErrorSlot = Arc::new(Mutex::new(None));

    let raw: Box<dyn Read> = match fmt {
        ArchiveFormat::Tar => Box::new(buffered),
        ArchiveFormat::TarGz => Box::new(GzDecoder::new(buffered)),
        ArchiveFormat::TarBz2 => Box::new(BzDecoder::new(buffered)),
        ArchiveFormat::TarZst => {
            let dec = zstd::stream::read::Decoder::new(buffered)
                .map_err(|e| DandiError::CorruptArchive(e.to_string()))?;
            Box::new(dec)
        }
        ArchiveFormat::TarXz => Box::new(XzReader::new(buffered, true)),
        _ => {
            return Err(DandiError::UnsupportedFormat(
                fmt.display_name().to_string(),
            ))
        }
    };

    let wrapped = BudgetedReader::new(
        raw,
        archive_file_size,
        budget,
        cancel,
        Arc::clone(&error_slot),
    );
    Ok((Box::new(wrapped), error_slot, archive_file_size))
}

#[derive(Debug)]
struct TarMetaEntry {
    index: usize,
    raw_name: Vec<u8>,
    kind: EntryKind,
    size: u64,
    mtime: Option<i64>,
    unix_mode: Option<u32>,
    symlink_target: Option<String>,
}

fn scan_tar_metadata(
    archive_path: &Path,
    fmt: ArchiveFormat,
    budget: &SafetyBudget,
    cancel: &CancellationToken,
) -> Result<(Vec<TarMetaEntry>, u64)> {
    let (reader, error_slot, archive_file_size) =
        open_tar_reader(archive_path, fmt, budget, cancel.clone())?;
    let mut tar_archive = Archive::new(reader);
    let mut items = Vec::new();
    let mut scan_budget = budget.clone();
    scan_budget.set_archive_compressed_size(archive_file_size);

    for (idx, entry_res) in tar_archive
        .entries()
        .map_err(|e| take_stream_or_corrupt(&error_slot, e))?
        .enumerate()
    {
        cancel.check()?;
        let entry = entry_res.map_err(|e| take_stream_or_corrupt(&error_slot, e))?;
        let entry_type = entry.header().entry_type();
        let kind = match entry_type {
            EntryType::Directory => EntryKind::Directory,
            EntryType::Symlink => EntryKind::Symlink,
            EntryType::Regular | EntryType::Continuous => EntryKind::File,
            _ => continue,
        };
        let raw_name = entry.path_bytes().into_owned();
        let size = entry.header().size().unwrap_or(0);
        scan_budget.record_entry(size, 0)?;

        let mtime = entry.header().mtime().ok().map(|v| v as i64);
        let unix_mode = entry.header().mode().ok();
        let symlink_target = if kind == EntryKind::Symlink {
            entry
                .link_name_bytes()
                .map(|b| String::from_utf8_lossy(&b).into_owned())
        } else {
            None
        };

        items.push(TarMetaEntry {
            index: idx,
            raw_name,
            kind,
            size,
            mtime,
            unix_mode,
            symlink_target,
        });
    }

    Ok((items, archive_file_size))
}

pub(crate) fn inspect_tar(
    archive_path: &Path,
    fmt: ArchiveFormat,
    opts: &InspectOptions,
) -> Result<ArchiveSummary> {
    let cancel = CancellationToken::new();
    let (meta_items, archive_file_size) =
        scan_tar_metadata(archive_path, fmt, &opts.budget, &cancel)?;
    let raw_refs: Vec<&[u8]> = meta_items.iter().map(|m| m.raw_name.as_slice()).collect();
    let detection = detect_archive_encoding(&raw_refs, opts.locale_hint);
    let applied_encoding = opts.encoding_override.unwrap_or(detection.encoding);
    let explicit_override = opts.encoding_override.is_some();

    let mut entries = Vec::with_capacity(meta_items.len());
    let mut total_uncompressed = 0u64;

    for m in &meta_items {
        let decoded = decode_entry_name_with_override(
            &m.raw_name,
            EntryEncodingFlags::default(),
            None,
            applied_encoding,
            explicit_override,
        );
        let junk = is_os_junk(&decoded.path);
        if junk && !opts.include_os_junk {
            continue;
        }
        total_uncompressed = total_uncompressed.saturating_add(m.size);
        entries.push(ArchiveEntryInfo {
            index: Some(m.index),
            path: decoded.path,
            kind: m.kind,
            uncompressed_size: m.size,
            compressed_size: 0,
            modified_unix_secs: m.mtime,
            unix_mode: m.unix_mode,
            encrypted: false,
            compression_method: fmt.display_name().to_string(),
            is_os_junk: junk,
            is_synthesized: false,
            symlink_target: m.symlink_target.clone(),
        });
    }

    let entries = synthesize_parent_dirs(entries);
    let total_entries = entries.len();

    Ok(ArchiveSummary {
        format: fmt,
        encoding: detection,
        applied_encoding,
        total_entries,
        total_uncompressed_bytes: total_uncompressed,
        total_compressed_bytes: archive_file_size,
        encrypted: false,
        entries,
    })
}

pub(crate) fn unpack_tar(
    archive_path: &Path,
    fmt: ArchiveFormat,
    dest_dir: &Path,
    opts: &UnpackOptions,
    observer: &dyn ProgressObserver,
) -> Result<UnpackReport> {
    opts.cancel.check()?;
    let (meta_items, archive_file_size) =
        scan_tar_metadata(archive_path, fmt, &opts.budget, &opts.cancel)?;
    let raw_refs: Vec<&[u8]> = meta_items.iter().map(|m| m.raw_name.as_slice()).collect();
    let detection = detect_archive_encoding(&raw_refs, opts.locale_hint);
    let applied_encoding = opts.encoding_override.unwrap_or(detection.encoding);
    let explicit_override = opts.encoding_override.is_some();

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
    let mut declared_symlinks: Vec<(String, String)> = Vec::new();

    for m in &meta_items {
        opts.cancel.check()?;
        let decoded = decode_entry_name_with_override(
            &m.raw_name,
            EntryEncodingFlags::default(),
            None,
            applied_encoding,
            explicit_override,
        );
        if opts.exclude_os_junk && is_os_junk(&decoded.path) {
            junk_skipped += 1;
            continue;
        }
        if let Some(ref sel) = opts.selected_entries {
            if !sel.contains(&m.index) {
                continue;
            }
        }
        budget.record_entry(m.size, 0)?;
        let sanitized = sanitize_entry_path(&decoded.path, opts.path_policy)?;
        visible_for_smart.push((sanitized.normalized().to_string(), m.kind));
        if m.kind == EntryKind::Symlink {
            declared_symlinks.push((decoded.path, m.symlink_target.clone().unwrap_or_default()));
        }
        total_bytes_planned = total_bytes_planned.saturating_add(m.size);
    }

    let plan = plan_extract_root(
        archive_path,
        dest_dir,
        opts.mode,
        opts.overwrite,
        &visible_for_smart,
    )?;

    let mut sink = ExtractionSink::new(plan, opts, budget, zone_data)?;
    for (decoded_path, target) in &declared_symlinks {
        sink.register_declared_symlink(decoded_path, target)?;
    }
    sink.validate_declared_symlink_chains()?;

    let (reader, error_slot, _) =
        open_tar_reader(archive_path, fmt, &opts.budget, opts.cancel.clone())?;
    let mut tar_archive = Archive::new(reader);

    for (idx, entry_res) in tar_archive
        .entries()
        .map_err(|e| take_stream_or_corrupt(&error_slot, e))?
        .enumerate()
    {
        opts.cancel.check()?;
        let mut entry = entry_res.map_err(|e| take_stream_or_corrupt(&error_slot, e))?;
        let entry_type = entry.header().entry_type();
        let kind = match entry_type {
            EntryType::Directory => EntryKind::Directory,
            EntryType::Symlink => EntryKind::Symlink,
            EntryType::Regular | EntryType::Continuous => EntryKind::File,
            _ => continue,
        };

        if let Some(ref sel) = opts.selected_entries {
            if !sel.contains(&idx) {
                continue;
            }
        }

        let raw_name = entry.path_bytes().into_owned();
        let decoded = decode_entry_name_with_override(
            &raw_name,
            EntryEncodingFlags::default(),
            None,
            applied_encoding,
            explicit_override,
        );
        if opts.exclude_os_junk && is_os_junk(&decoded.path) {
            continue;
        }

        let mtime = entry.header().mtime().ok().map(|v| v as i64);
        let unix_mode = entry.header().mode().ok();

        let extracted_norm = match kind {
            EntryKind::Directory => sink.extract_directory(&decoded.path, mtime, unix_mode)?,
            EntryKind::Symlink => {
                let target = entry
                    .link_name_bytes()
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default();
                sink.queue_symlink(&decoded.path, target, mtime)?
            }
            EntryKind::File => sink.extract_file(
                &decoded.path,
                &mut entry,
                archive_file_size,
                false,
                mtime,
                unix_mode,
                |e| take_stream_or_corrupt(&error_slot, e),
            )?,
        };

        if let Some(current_entry) = extracted_norm {
            observer.on_progress(&ProgressEvent {
                phase: ProgressPhase::Unpacking,
                current_entry,
                entries_done: idx + 1,
                entries_total: meta_items.len(),
                bytes_done: sink.bytes_written(),
                bytes_total: total_bytes_planned.max(1),
            });
        }
    }

    sink.finish(fmt, detection.encoding, applied_encoding, junk_skipped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tempfile::TempDir;

    #[test]
    fn tar_budgeted_reader_trips_during_body_skip_without_hanging() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("skip_body_bomb.tar.gz");
        {
            let file = File::create(&path).unwrap();
            let gz = GzEncoder::new(file, Compression::fast());
            let mut builder = tar::Builder::new(gz);
            for i in 0..2 {
                let mut hdr = tar::Header::new_gnu();
                hdr.set_entry_type(tar::EntryType::Regular);
                hdr.set_size(4 * 1024 * 1024);
                hdr.set_mode(0o644);
                hdr.set_mtime(1_735_689_600);
                hdr.set_cksum();
                let zero_reader = io::repeat(0u8).take(4 * 1024 * 1024);
                builder
                    .append_data(&mut hdr, format!("z_{i}.bin"), zero_reader)
                    .unwrap();
            }
            let gz = builder.into_inner().unwrap();
            gz.finish().unwrap();
        }

        // 1. Directly iterate tar::Archive over BudgetedReader so tar's internal read_exact / io::copy
        //    must skip entry 0's 4 MiB body and trip BudgetedReader::read() itself (would hang forever on EINTR).
        let budget = SafetyBudget::new(100 * 1024 * 1024, 1000, 50.0, 2 * 1024 * 1024);
        let cancel = CancellationToken::new();
        let (reader, error_slot, _) =
            open_tar_reader(&path, ArchiveFormat::TarGz, &budget, cancel).unwrap();
        let mut tar_archive = Archive::new(reader);
        let mut got_err: Option<DandiError> = None;
        for entry_res in tar_archive.entries().unwrap() {
            if let Err(e) = entry_res {
                got_err = Some(take_stream_or_corrupt(&error_slot, e));
                break;
            }
        }
        assert!(
            matches!(got_err, Some(DandiError::BudgetExceeded { .. })),
            "expected BudgetedReader to return BudgetExceeded without hanging, got {got_err:?}"
        );

        // 2. Verify pre-cancelled token trips BudgetedReader::read() inside tar's read_exact immediately.
        let pre_cancel = CancellationToken::new();
        pre_cancel.cancel();
        let res_cancel = scan_tar_metadata(
            &path,
            ArchiveFormat::TarGz,
            &SafetyBudget::default(),
            &pre_cancel,
        );
        assert!(
            matches!(res_cancel, Err(DandiError::Cancelled)),
            "expected Cancelled without hanging, got {res_cancel:?}"
        );
    }
}
