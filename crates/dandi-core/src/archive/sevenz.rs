use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use sevenz_rust2::{ArchiveReader, Password};
use unicode_normalization::UnicodeNormalization;

use crate::archive::extract_sink::ExtractionSink;
use crate::archive::{
    plan_extract_root, synthesize_parent_dirs, ArchiveEntryInfo, ArchiveFormat, ArchiveSummary,
    EntryKind, InspectOptions, UnpackOptions, UnpackReport,
};
use crate::codec::{EncodingCandidate, EncodingDetection, EncodingId};
use crate::error::{DandiError, Result};
use crate::platform::{read_zone_identifier, to_fs_path};
use crate::progress::{ProgressEvent, ProgressObserver, ProgressPhase};
use crate::safety::{is_os_junk, sanitize_entry_path};

pub(crate) fn inspect_7z(archive_path: &Path, opts: &InspectOptions) -> Result<ArchiveSummary> {
    let pw = build_7z_password(opts.password.as_deref());
    let fs_path = to_fs_path(archive_path);
    let reader = ArchiveReader::open(&fs_path, pw).map_err(map_7z_error)?;
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
    let mut any_encrypted = false;

    for (idx, file) in archive.files.iter().enumerate() {
        let path_nfc: String = file.name().nfc().collect();
        let junk = is_os_junk(&path_nfc);
        if junk && !opts.include_os_junk {
            continue;
        }
        let kind = if file.is_directory() {
            EntryKind::Directory
        } else {
            EntryKind::File
        };
        let size = file.size();
        total_uncompressed = total_uncompressed.saturating_add(size);
        let mtime = if file.has_last_modified_date {
            nt_time_to_unix_secs(file.last_modified_date())
        } else {
            None
        };
        if archive.is_solid && opts.password.is_some() {
            any_encrypted = true;
        }
        entries.push(ArchiveEntryInfo {
            index: Some(idx),
            path: path_nfc,
            kind,
            uncompressed_size: size,
            compressed_size: 0,
            modified_unix_secs: mtime,
            unix_mode: None,
            encrypted: any_encrypted,
            compression_method: "7z".to_string(),
            is_os_junk: junk,
            is_synthesized: false,
            symlink_target: None,
        });
    }

    let entries = synthesize_parent_dirs(entries);
    let total_entries = entries.len();
    let total_compressed = fs::metadata(&fs_path).map(|m| m.len()).unwrap_or(0);

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
        encrypted: any_encrypted,
        entries,
    })
}

pub(crate) fn unpack_7z(
    archive_path: &Path,
    dest_dir: &Path,
    opts: &UnpackOptions,
    observer: &dyn ProgressObserver,
) -> Result<UnpackReport> {
    opts.cancel.check()?;
    let pw = build_7z_password(opts.password.as_deref());
    let fs_path = to_fs_path(archive_path);
    let mut reader = ArchiveReader::open(&fs_path, pw).map_err(map_7z_error)?;
    let archive_file_size = fs::metadata(&fs_path).map(|m| m.len()).unwrap_or(1).max(1);

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
        let kind = if file.is_directory() {
            EntryKind::Directory
        } else {
            EntryKind::File
        };
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
    let mut entry_idx = 0usize;
    let mut callback_err: Option<DandiError> = None;

    let iter_res = reader.for_each_entries(|entry, data_reader| {
        let current_idx = entry_idx;
        entry_idx += 1;

        if opts.cancel.is_cancelled() {
            callback_err = Some(DandiError::Cancelled);
            return Ok(false);
        }

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
                    return Ok(false);
                }
            }
            return Ok(true);
        }

        let mtime = if entry.has_last_modified_date {
            nt_time_to_unix_secs(entry.last_modified_date())
        } else {
            None
        };

        let extract_res = if entry.is_directory() {
            sink.extract_directory(&name_nfc, mtime, None)
        } else {
            sink.extract_file(
                &name_nfc,
                data_reader,
                archive_file_size,
                false,
                mtime,
                None,
                |e| DandiError::CorruptArchive(e.to_string()),
            )
        };

        match extract_res {
            Ok(Some(current_entry)) => {
                observer.on_progress(&ProgressEvent {
                    phase: ProgressPhase::Unpacking,
                    current_entry,
                    entries_done: entry_idx,
                    entries_total: total_count,
                    bytes_done: sink.bytes_written(),
                    bytes_total: total_bytes_planned.max(1),
                });
            }
            Ok(None) => {}
            Err(e) => {
                callback_err = Some(e);
                return Ok(false);
            }
        }

        Ok(true)
    });

    if let Some(err) = callback_err {
        return Err(err);
    }
    iter_res.map_err(map_7z_error)?;

    sink.finish(
        ArchiveFormat::SevenZ,
        EncodingId::Utf8,
        EncodingId::Utf8,
        junk_skipped,
    )
}

fn build_7z_password(password: Option<&str>) -> Password {
    match password {
        Some(pw) => {
            let nfc: String = pw.nfc().collect();
            Password::from(nfc.as_str())
        }
        None => Password::empty(),
    }
}

fn nt_time_to_unix_secs(nt: sevenz_rust2::NtTime) -> Option<i64> {
    let st: SystemTime = nt.into();
    st.duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as i64)
}

fn map_7z_error(err: sevenz_rust2::Error) -> DandiError {
    let msg = err.to_string();
    let lower = msg.to_ascii_lowercase();
    if lower.contains("password") || lower.contains("wrong password") {
        DandiError::InvalidPassword
    } else {
        DandiError::CorruptArchive(msg)
    }
}
