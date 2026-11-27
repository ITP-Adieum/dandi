use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use lzma_rust2::XzReader;
use tar::{Archive, EntryType};

use crate::archive::{
    check_not_through_archive_symlink, ensure_no_symlink_ancestors, plan_extract_root,
    synthesize_parent_dirs, ArchiveEntryInfo, ArchiveFormat, ArchiveSummary, DirCleanupGuard,
    EntryKind, InspectOptions, UnpackOptions, UnpackReport,
};
use crate::codec::{decode_entry_name, detect_archive_encoding, EntryEncodingFlags};
use crate::error::{DandiError, Result};
use crate::platform::{
    apply_unix_mode, create_relative_symlink, read_zone_identifier, set_mtime, to_fs_path,
    write_zone_identifier,
};
use crate::progress::{ProgressEvent, ProgressObserver, ProgressPhase};
use crate::safety::{is_os_junk, sanitize_entry_path, validate_symlink_target, CollisionTracker};

const STREAM_BUF_SIZE: usize = 256 * 1024;

fn open_tar_reader(archive_path: &Path, fmt: ArchiveFormat) -> Result<Box<dyn Read>> {
    let fs_path = to_fs_path(archive_path);
    let file = File::open(&fs_path).map_err(|e| DandiError::io(archive_path, e))?;
    let buffered = BufReader::with_capacity(STREAM_BUF_SIZE, file);
    match fmt {
        ArchiveFormat::Tar => Ok(Box::new(buffered)),
        ArchiveFormat::TarGz => Ok(Box::new(GzDecoder::new(buffered))),
        ArchiveFormat::TarBz2 => Ok(Box::new(BzDecoder::new(buffered))),
        ArchiveFormat::TarZst => {
            let dec = zstd::stream::read::Decoder::new(buffered)
                .map_err(|e| DandiError::CorruptArchive(e.to_string()))?;
            Ok(Box::new(dec))
        }
        ArchiveFormat::TarXz => Ok(Box::new(XzReader::new(buffered, true))),
        _ => Err(DandiError::UnsupportedFormat(
            fmt.display_name().to_string(),
        )),
    }
}

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
    max_entries: usize,
) -> Result<Vec<TarMetaEntry>> {
    let reader = open_tar_reader(archive_path, fmt)?;
    let mut tar_archive = Archive::new(reader);
    let mut items = Vec::new();

    for (idx, entry_res) in tar_archive
        .entries()
        .map_err(|e| DandiError::CorruptArchive(e.to_string()))?
        .enumerate()
    {
        if idx >= max_entries {
            return Err(DandiError::BudgetExceeded {
                reason: format!("TAR entry count exceeds limit {max_entries}"),
            });
        }
        let entry = entry_res.map_err(|e| DandiError::CorruptArchive(e.to_string()))?;
        let entry_type = entry.header().entry_type();
        let kind = match entry_type {
            EntryType::Directory => EntryKind::Directory,
            EntryType::Symlink => EntryKind::Symlink,
            EntryType::Regular | EntryType::Continuous => EntryKind::File,
            _ => continue,
        };
        let raw_name = entry.path_bytes().into_owned();
        let size = entry.header().size().unwrap_or(0);
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

    Ok(items)
}

pub(crate) fn inspect_tar(
    archive_path: &Path,
    fmt: ArchiveFormat,
    opts: &InspectOptions,
) -> Result<ArchiveSummary> {
    let meta_items = scan_tar_metadata(archive_path, fmt, opts.budget.max_entries)?;
    let raw_refs: Vec<&[u8]> = meta_items.iter().map(|m| m.raw_name.as_slice()).collect();
    let detection = detect_archive_encoding(&raw_refs, opts.locale_hint);
    let applied_encoding = opts.encoding_override.unwrap_or(detection.encoding);

    let mut entries = Vec::with_capacity(meta_items.len());
    let mut total_uncompressed = 0u64;

    for m in &meta_items {
        let decoded = decode_entry_name(
            &m.raw_name,
            EntryEncodingFlags::default(),
            None,
            applied_encoding,
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
    let total_compressed = fs::metadata(to_fs_path(archive_path))
        .map(|m| m.len())
        .unwrap_or(0);

    Ok(ArchiveSummary {
        format: fmt,
        encoding: detection,
        applied_encoding,
        total_entries,
        total_uncompressed_bytes: total_uncompressed,
        total_compressed_bytes: total_compressed,
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
    let meta_items = scan_tar_metadata(archive_path, fmt, opts.budget.max_entries)?;
    let raw_refs: Vec<&[u8]> = meta_items.iter().map(|m| m.raw_name.as_slice()).collect();
    let detection = detect_archive_encoding(&raw_refs, opts.locale_hint);
    let applied_encoding = opts.encoding_override.unwrap_or(detection.encoding);

    let archive_file_size = fs::metadata(to_fs_path(archive_path))
        .map(|m| m.len())
        .unwrap_or(1)
        .max(1);
    let zone_data = if opts.propagate_zone_identifier {
        read_zone_identifier(archive_path)
    } else {
        None
    };

    let mut budget = opts.budget.clone();
    let mut visible_for_smart: Vec<(String, EntryKind)> = Vec::new();
    let mut junk_skipped = 0usize;
    let mut total_bytes_planned = 0u64;
    let mut symlink_paths_lower: HashSet<String> = HashSet::new();

    for m in &meta_items {
        opts.cancel.check()?;
        let decoded = decode_entry_name(
            &m.raw_name,
            EntryEncodingFlags::default(),
            None,
            applied_encoding,
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
        budget.record_entry(m.size, archive_file_size)?;
        let sanitized = sanitize_entry_path(&decoded.path, opts.path_policy)?;
        if m.kind == EntryKind::Symlink {
            let target = m.symlink_target.as_deref().unwrap_or_default();
            validate_symlink_target(dest_dir, &sanitized.relative, target)?;
            symlink_paths_lower.insert(sanitized.normalized.to_lowercase());
        }
        visible_for_smart.push((sanitized.normalized, m.kind));
        total_bytes_planned = total_bytes_planned.saturating_add(m.size);
    }

    let plan = plan_extract_root(
        archive_path,
        dest_dir,
        opts.mode,
        opts.overwrite,
        &visible_for_smart,
    )?;

    fs::create_dir_all(to_fs_path(&plan.extract_root))
        .map_err(|e| DandiError::io(&plan.extract_root, e))?;
    let mut dir_guard = DirCleanupGuard::new(plan.cleanup_root.clone());

    let reader = open_tar_reader(archive_path, fmt)?;
    let mut tar_archive = Archive::new(reader);

    let mut collisions = CollisionTracker::new();
    let mut sanitized_paths = 0usize;
    let mut files_extracted = 0usize;
    let mut dirs_created = 0usize;
    let mut symlinks_created = 0usize;

    struct PendingSymlink {
        link_rel: PathBuf,
        target: String,
        mtime: Option<i64>,
    }
    let mut pending_symlinks: Vec<PendingSymlink> = Vec::new();
    let mut deferred_dir_mtimes: Vec<(PathBuf, i64, Option<u32>)> = Vec::new();
    let mut read_buf = vec![0u8; STREAM_BUF_SIZE];

    for (idx, entry_res) in tar_archive
        .entries()
        .map_err(|e| DandiError::CorruptArchive(e.to_string()))?
        .enumerate()
    {
        opts.cancel.check()?;
        let mut entry = entry_res.map_err(|e| DandiError::CorruptArchive(e.to_string()))?;
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
        let decoded = decode_entry_name(
            &raw_name,
            EntryEncodingFlags::default(),
            None,
            applied_encoding,
        );
        if opts.exclude_os_junk && is_os_junk(&decoded.path) {
            continue;
        }

        let sanitized = sanitize_entry_path(&decoded.path, opts.path_policy)?;
        if sanitized.was_sanitized {
            sanitized_paths += 1;
        }
        let eff_str = match plan.strip_prefix.as_deref() {
            Some(p) if sanitized.normalized == p => String::new(),
            Some(p) => sanitized
                .normalized
                .strip_prefix(&format!("{p}/"))
                .unwrap_or(&sanitized.normalized)
                .to_string(),
            None => sanitized.normalized.clone(),
        };
        if eff_str.is_empty() {
            continue;
        }
        let eff = sanitize_entry_path(&eff_str, opts.path_policy)?;
        let mtime = entry.header().mtime().ok().map(|v| v as i64);
        let unix_mode = entry.header().mode().ok();

        match kind {
            EntryKind::Directory => {
                check_not_through_archive_symlink(&eff.normalized, &symlink_paths_lower)?;
                collisions.register_dir(&eff.normalized);
                let out_path = plan.extract_root.join(&eff.relative);
                ensure_no_symlink_ancestors(&plan.extract_root, &eff.relative)?;
                fs::create_dir_all(to_fs_path(&out_path))
                    .map_err(|e| DandiError::io(&out_path, e))?;
                dirs_created += 1;
                if let Some(ts) = mtime {
                    deferred_dir_mtimes.push((out_path, ts, unix_mode));
                } else if let Some(mode) = unix_mode {
                    let _ = apply_unix_mode(&out_path, mode, true);
                }
            }
            EntryKind::Symlink => {
                let target = entry
                    .link_name_bytes()
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default();
                let resolved_rel = collisions.resolve_file(&eff);
                validate_symlink_target(&plan.extract_root, &resolved_rel, &target)?;
                pending_symlinks.push(PendingSymlink {
                    link_rel: resolved_rel,
                    target,
                    mtime,
                });
            }
            EntryKind::File => {
                check_not_through_archive_symlink(&eff.normalized, &symlink_paths_lower)?;
                let resolved_rel = collisions.resolve_file(&eff);
                let out_path = plan.extract_root.join(&resolved_rel);
                if let Some(parent_rel) = resolved_rel.parent() {
                    if !parent_rel.as_os_str().is_empty() {
                        ensure_no_symlink_ancestors(&plan.extract_root, parent_rel)?;
                        let parent_abs = plan.extract_root.join(parent_rel);
                        fs::create_dir_all(to_fs_path(&parent_abs))
                            .map_err(|e| DandiError::io(&parent_abs, e))?;
                    }
                }
                ensure_no_symlink_ancestors(&plan.extract_root, &resolved_rel)?;

                let fs_out = to_fs_path(&out_path);
                let out_file = File::create(&fs_out).map_err(|e| DandiError::io(&out_path, e))?;
                let mut writer = BufWriter::with_capacity(STREAM_BUF_SIZE, out_file);
                let mut entry_written = 0u64;

                loop {
                    opts.cancel.check()?;
                    let n = entry
                        .read(&mut read_buf)
                        .map_err(|e| DandiError::CorruptArchive(e.to_string()))?;
                    if n == 0 {
                        break;
                    }
                    entry_written = entry_written.saturating_add(n as u64);
                    budget.record_written_bytes(n as u64, entry_written, archive_file_size)?;
                    writer.write_all(&read_buf[..n])?;
                }
                writer.flush()?;
                drop(writer);

                if let Some(mode) = unix_mode {
                    let _ = apply_unix_mode(&out_path, mode, false);
                }
                if let Some(ts) = mtime {
                    let _ = set_mtime(&out_path, ts, false);
                }
                if let Some(ref zdata) = zone_data {
                    let _ = write_zone_identifier(&out_path, zdata);
                }
                files_extracted += 1;
            }
        }

        observer.on_progress(&ProgressEvent {
            phase: ProgressPhase::Unpacking,
            current_entry: eff.normalized,
            entries_done: idx + 1,
            entries_total: meta_items.len(),
            bytes_done: budget.bytes_written(),
            bytes_total: total_bytes_planned.max(1),
        });
    }

    for sym in pending_symlinks {
        opts.cancel.check()?;
        let abs_link = plan.extract_root.join(&sym.link_rel);
        if let Some(parent) = abs_link.parent() {
            fs::create_dir_all(to_fs_path(parent)).map_err(|e| DandiError::io(parent, e))?;
        }
        let target_resolved =
            validate_symlink_target(&plan.extract_root, &sym.link_rel, &sym.target)?;
        let target_is_dir = to_fs_path(&target_resolved).is_dir();
        create_relative_symlink(&abs_link, &sym.target, target_is_dir)
            .map_err(|e| DandiError::io(&abs_link, e))?;
        if let Some(ts) = sym.mtime {
            let _ = set_mtime(&abs_link, ts, true);
        }
        symlinks_created += 1;
    }

    for (dir_path, ts, mode) in deferred_dir_mtimes.into_iter().rev() {
        let _ = set_mtime(&dir_path, ts, false);
        if let Some(m) = mode {
            let _ = apply_unix_mode(&dir_path, m, true);
        }
    }

    dir_guard.disarm();

    Ok(UnpackReport {
        format: fmt,
        output_dir: plan.reported_output_dir,
        detected_encoding: detection.encoding,
        applied_encoding,
        files_extracted,
        dirs_created,
        symlinks_created,
        junk_skipped,
        bytes_written: budget.bytes_written(),
        sanitized_paths,
        renamed_collisions: collisions.into_renames(),
    })
}
