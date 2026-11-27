use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::write::DeflateEncoder;
use flate2::Compression;
use rayon::prelude::*;
use time::OffsetDateTime;
use unicode_normalization::UnicodeNormalization;
use walkdir::WalkDir;
use zip::write::SimpleFileOptions;
use zip::{AesMode, CompressionMethod, ZipArchive, ZipWriter};

use crate::archive::split::{
    ensure_split_destination_free, validate_split_size, PkwareSplitWriter, SplitStyle,
    SplitVolumeWriter,
};
use crate::archive::zip::header::{
    build_0x5455_extra, copy_extra_fields_excluding, read_single_disk_directory, read_u16_le,
    read_u32_le, unix_secs_to_dos, BIT11_UTF8, CDH_SIG, EOCD_SIG, LFH_SIG, METHOD_DEFLATE,
    METHOD_STORE, VERSION_MADE_BY_UNIX, ZIP64_EOCD_SIG, ZIP64_LOCATOR_SIG, ZIP64_THRESHOLD_DISK,
    ZIP64_THRESHOLD_ENTRIES, ZIP64_THRESHOLD_U32,
};
use crate::archive::zip::reader::{
    classify_zip_read_io_error, map_zip_error, open_zip_entry, open_zip_source,
};
use crate::archive::{EntryKind, PackOptions, PackReport, RepackOptions, RepackReport};
use crate::codec::{
    decode_entry_name_with_override, detect_archive_encoding, normalize_for_pack,
    EntryEncodingFlags,
};
use crate::error::{DandiError, Result};
use crate::platform::{read_unix_mode_for_pack, to_fs_path};
use crate::progress::{CancellationToken, ProgressEvent, ProgressObserver, ProgressPhase};
use crate::safety::is_os_junk;

const PARALLEL_BATCH_MAX_BYTES: u64 = 32 * 1024 * 1024;
const PARALLEL_BATCH_MAX_FILES: usize = 256;
const LARGE_STREAM_THRESHOLD: u64 = 16 * 1024 * 1024;
const STREAM_BUF_SIZE: usize = 256 * 1024;

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Checks if a filename extension belongs to an already-compressed format suitable for Method 0 Store.
pub(crate) fn is_incompressible_extension(path: &str) -> bool {
    let ext = match path.rsplit_once('.') {
        Some((_, e)) => e.to_ascii_lowercase(),
        None => return false,
    };
    matches!(
        ext.as_str(),
        "jpg"
            | "jpeg"
            | "png"
            | "webp"
            | "avif"
            | "gif"
            | "heic"
            | "heif"
            | "mp4"
            | "m4v"
            | "mov"
            | "mkv"
            | "webm"
            | "avi"
            | "mp3"
            | "aac"
            | "m4a"
            | "ogg"
            | "opus"
            | "flac"
            | "pdf"
            | "docx"
            | "xlsx"
            | "pptx"
            | "zip"
            | "7z"
            | "rar"
            | "gz"
            | "tgz"
            | "bz2"
            | "xz"
            | "zst"
            | "woff"
            | "woff2"
            | "apk"
            | "ipa"
            | "dmg"
    )
}

#[derive(Clone, Debug)]
pub(crate) struct PackItem {
    pub fs_path: PathBuf,
    pub archive_name: String,
    pub kind: EntryKind,
    pub size: u64,
    pub mtime_secs: i64,
    pub unix_mode: u32,
    pub symlink_target: Option<String>,
}

pub(crate) struct TempFileGuard {
    path: Option<PathBuf>,
}

impl TempFileGuard {
    pub fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    pub fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            let _ = fs::remove_file(to_fs_path(&p));
        }
    }
}

pub(crate) fn create_sibling_temp_path(dest: &Path, ext: &str) -> PathBuf {
    let parent = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let pid = std::process::id();
    let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    parent.join(format!(".dandi-tmp-{pid}-{seq}-{nanos}.{ext}"))
}

pub(crate) fn commit_temp_file(tmp: &Path, dst: &Path, overwrite: bool) -> Result<()> {
    let fs_tmp = to_fs_path(tmp);
    let fs_dst = to_fs_path(dst);
    if fs_dst.exists() {
        if !overwrite {
            return Err(DandiError::AlreadyExists {
                path: dst.to_path_buf(),
            });
        }
        #[cfg(windows)]
        {
            fs::remove_file(&fs_dst).map_err(|e| DandiError::io(dst, e))?;
        }
    }
    fs::rename(&fs_tmp, &fs_dst).map_err(|e| DandiError::io(dst, e))
}

pub(crate) fn collect_pack_items(
    inputs: &[PathBuf],
    opts: &PackOptions,
) -> Result<(Vec<PackItem>, usize)> {
    if inputs.is_empty() {
        return Err(DandiError::InvalidInput(
            "at least one input path is required".to_string(),
        ));
    }

    let mut items = Vec::new();
    let mut junk_skipped = 0usize;
    let mut seen_names: HashSet<String> = HashSet::new();

    for input in inputs {
        opts.cancel.check()?;
        let fs_input = to_fs_path(input);
        let root_meta = fs::symlink_metadata(&fs_input).map_err(|e| DandiError::io(input, e))?;
        let base_name = input
            .file_name()
            .ok_or_else(|| {
                DandiError::InvalidInput(format!("input path has no filename: {}", input.display()))
            })?
            .to_string_lossy()
            .into_owned();

        if root_meta.file_type().is_symlink() {
            let norm = normalize_for_pack(&base_name);
            if opts.exclude_os_junk && is_os_junk(&norm) {
                junk_skipped += 1;
                continue;
            }
            let target: String = fs::read_link(&fs_input)
                .map_err(|e| DandiError::io(input, e))?
                .to_string_lossy()
                .replace('\\', "/")
                .nfc()
                .collect();
            if seen_names.insert(norm.clone()) {
                items.push(PackItem {
                    fs_path: input.clone(),
                    archive_name: norm,
                    kind: EntryKind::Symlink,
                    size: target.len() as u64,
                    mtime_secs: metadata_mtime_secs(&root_meta),
                    unix_mode: read_unix_mode_for_pack(&root_meta, true),
                    symlink_target: Some(target),
                });
            }
            continue;
        }

        if root_meta.is_file() {
            let norm = normalize_for_pack(&base_name);
            if opts.exclude_os_junk && is_os_junk(&norm) {
                junk_skipped += 1;
                continue;
            }
            if seen_names.insert(norm.clone()) {
                items.push(PackItem {
                    fs_path: input.clone(),
                    archive_name: norm,
                    kind: EntryKind::File,
                    size: root_meta.len(),
                    mtime_secs: metadata_mtime_secs(&root_meta),
                    unix_mode: read_unix_mode_for_pack(&root_meta, false),
                    symlink_target: None,
                });
            }
            continue;
        }

        // Directory walk (follow_links = false so symlinks are preserved as symlinks).
        let walker = WalkDir::new(&fs_input)
            .follow_links(false)
            .sort_by_file_name();
        for entry_res in walker {
            opts.cancel.check()?;
            let entry = entry_res.map_err(|e| {
                let p = e.path().map(Path::to_path_buf);
                let io_err = e
                    .into_io_error()
                    .unwrap_or_else(|| io::Error::other("walkdir error"));
                DandiError::Io {
                    path: p,
                    source: io_err,
                }
            })?;
            let path = entry.path();
            let rel = path
                .strip_prefix(&fs_input)
                .map_err(|_| DandiError::ArchiveEngine("strip_prefix failed".to_string()))?;

            let raw_archive_path = if rel.as_os_str().is_empty() {
                format!("{base_name}/")
            } else {
                let mut combined = PathBuf::from(&base_name);
                combined.push(rel);
                let s = combined.to_string_lossy().into_owned();
                if entry.file_type().is_dir() {
                    format!("{s}/")
                } else {
                    s
                }
            };

            let norm = normalize_for_pack(&raw_archive_path);
            if norm.is_empty() {
                continue;
            }
            if opts.exclude_os_junk && is_os_junk(&norm) {
                junk_skipped += 1;
                continue;
            }

            let meta = fs::symlink_metadata(path).map_err(|e| DandiError::io(path, e))?;
            if meta.file_type().is_symlink() {
                let target: String = fs::read_link(path)
                    .map_err(|e| DandiError::io(path, e))?
                    .to_string_lossy()
                    .replace('\\', "/")
                    .nfc()
                    .collect();
                let clean_name = norm.trim_end_matches('/').to_string();
                if seen_names.insert(clean_name.clone()) {
                    items.push(PackItem {
                        fs_path: path.to_path_buf(),
                        archive_name: clean_name,
                        kind: EntryKind::Symlink,
                        size: target.len() as u64,
                        mtime_secs: metadata_mtime_secs(&meta),
                        unix_mode: read_unix_mode_for_pack(&meta, true),
                        symlink_target: Some(target),
                    });
                }
            } else if meta.is_dir() {
                let dir_name = if norm.ends_with('/') {
                    norm
                } else {
                    format!("{norm}/")
                };
                if seen_names.insert(dir_name.clone()) {
                    items.push(PackItem {
                        fs_path: path.to_path_buf(),
                        archive_name: dir_name,
                        kind: EntryKind::Directory,
                        size: 0,
                        mtime_secs: metadata_mtime_secs(&meta),
                        unix_mode: read_unix_mode_for_pack(&meta, false),
                        symlink_target: None,
                    });
                }
            } else if meta.is_file() && seen_names.insert(norm.clone()) {
                items.push(PackItem {
                    fs_path: path.to_path_buf(),
                    archive_name: norm,
                    kind: EntryKind::File,
                    size: meta.len(),
                    mtime_secs: metadata_mtime_secs(&meta),
                    unix_mode: read_unix_mode_for_pack(&meta, false),
                    symlink_target: None,
                });
            }
        }
    }

    Ok((items, junk_skipped))
}

fn metadata_mtime_secs(meta: &fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or_else(current_unix_secs)
}

fn current_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn pack_zip(
    inputs: &[PathBuf],
    output_zip: &Path,
    opts: &PackOptions,
    observer: &dyn ProgressObserver,
) -> Result<PackReport> {
    opts.cancel.check()?;
    let split_size = validate_split_size(opts.split_size_bytes)?;

    if !opts.overwrite {
        match split_size {
            None if to_fs_path(output_zip).exists() => {
                return Err(DandiError::AlreadyExists {
                    path: output_zip.to_path_buf(),
                });
            }
            None => {}
            Some(_) => ensure_split_destination_free(output_zip, opts.split_style)?,
        }
    }

    if let Some(parent) = output_zip.parent() {
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

    let report = if let Some(ref password) = opts.password {
        match (split_size, opts.split_style) {
            (None, _) => {
                let tmp_path = create_sibling_temp_path(output_zip, "zip");
                let mut guard = TempFileGuard::new(tmp_path.clone());
                let tmp_file = File::create(to_fs_path(&tmp_path))
                    .map_err(|e| DandiError::io(&tmp_path, e))?;
                let (mut report, finished_writer) = pack_zip_encrypted_into(
                    &items,
                    BufWriter::with_capacity(STREAM_BUF_SIZE, tmp_file),
                    output_zip,
                    password,
                    opts,
                    junk_skipped,
                    total_input_bytes,
                    observer,
                )?;
                drop(finished_writer);
                commit_temp_file(&tmp_path, output_zip, opts.overwrite)?;
                guard.disarm();
                report.output_path = output_zip.to_path_buf();
                report.output_volumes = vec![output_zip.to_path_buf()];
                report
            }
            (Some(limit), SplitStyle::Numeric) => {
                let split_writer = SplitVolumeWriter::new(output_zip, limit)?;
                let (mut report, finished_writer) = pack_zip_encrypted_into(
                    &items,
                    split_writer,
                    output_zip,
                    password,
                    opts,
                    junk_skipped,
                    total_input_bytes,
                    observer,
                )?;
                let (primary, volumes, total_bytes) =
                    finished_writer.commit(output_zip, opts.overwrite)?;
                report.output_path = primary;
                report.output_volumes = volumes;
                report.output_bytes = total_bytes;
                report
            }
            (Some(limit), SplitStyle::PkwareZip) => {
                let tmp_path = create_sibling_temp_path(output_zip, "zip");
                let _guard = TempFileGuard::new(tmp_path.clone());
                let tmp_file = File::create(to_fs_path(&tmp_path))
                    .map_err(|e| DandiError::io(&tmp_path, e))?;
                let (mut report, finished_writer) = pack_zip_encrypted_into(
                    &items,
                    BufWriter::with_capacity(STREAM_BUF_SIZE, tmp_file),
                    output_zip,
                    password,
                    opts,
                    junk_skipped,
                    total_input_bytes,
                    observer,
                )?;
                drop(finished_writer);
                let (primary, volumes, total_bytes, used_z64) = resplit_single_zip_to_pkware(
                    &tmp_path,
                    output_zip,
                    limit,
                    opts.overwrite,
                    &opts.cancel,
                )?;
                report.output_path = primary;
                report.output_volumes = volumes;
                report.output_bytes = total_bytes;
                report.used_zip64 |= used_z64;
                report
            }
        }
    } else {
        match (split_size, opts.split_style) {
            (None, _) => {
                let tmp_path = create_sibling_temp_path(output_zip, "zip");
                let mut guard = TempFileGuard::new(tmp_path.clone());
                let tmp_file = File::create(to_fs_path(&tmp_path))
                    .map_err(|e| DandiError::io(&tmp_path, e))?;
                let writer = GoldenZipWriter::new_single(tmp_file);
                let report = pack_zip_golden_parallel(
                    &items,
                    writer,
                    output_zip,
                    opts,
                    junk_skipped,
                    total_input_bytes,
                    observer,
                )?;
                commit_temp_file(&tmp_path, output_zip, opts.overwrite)?;
                guard.disarm();
                report
            }
            (Some(limit), SplitStyle::Numeric) => {
                let split_writer = SplitVolumeWriter::new(output_zip, limit)?;
                let writer = GoldenZipWriter::new_numeric(split_writer);
                pack_zip_golden_parallel(
                    &items,
                    writer,
                    output_zip,
                    opts,
                    junk_skipped,
                    total_input_bytes,
                    observer,
                )?
            }
            (Some(limit), SplitStyle::PkwareZip) => {
                let pkware = PkwareSplitWriter::new(output_zip, limit)?;
                let writer = GoldenZipWriter::new_pkware(pkware);
                pack_zip_golden_parallel(
                    &items,
                    writer,
                    output_zip,
                    opts,
                    junk_skipped,
                    total_input_bytes,
                    observer,
                )?
            }
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

struct PreparedEntry {
    archive_name: String,
    method: u16,
    crc32: u32,
    uncompressed_size: u64,
    mtime_secs: i64,
    unix_mode: u32,
    dos_attr: u32,
    payload: Vec<u8>,
}

struct WrittenCdRecord {
    name_bytes: Vec<u8>,
    version_needed: u16,
    flags: u16,
    method: u16,
    dos_time: u16,
    dos_date: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    mtime_secs: i64,
    external_attrs: u32,
    disk_number_start: u32,
    local_header_offset: u64,
}

enum ZipOutputBackend {
    Single {
        writer: BufWriter<File>,
        offset: u64,
    },
    Numeric {
        writer: BufWriter<SplitVolumeWriter>,
        offset: u64,
    },
    Pkware {
        writer: PkwareSplitWriter,
    },
}

impl ZipOutputBackend {
    fn current_location(&self) -> (u32, u64) {
        match self {
            Self::Single { offset, .. } | Self::Numeric { offset, .. } => (0, *offset),
            Self::Pkware { writer } => writer.current_location(),
        }
    }

    fn write_atomic_header(&mut self, data: &[u8]) -> Result<(u32, u64)> {
        match self {
            Self::Single { writer, offset } => {
                let start = *offset;
                writer.write_all(data)?;
                *offset = offset
                    .checked_add(data.len() as u64)
                    .ok_or_else(|| DandiError::ArchiveEngine("ZIP offset overflow".to_string()))?;
                Ok((0, start))
            }
            Self::Numeric { writer, offset } => {
                let start = *offset;
                writer.write_all(data)?;
                *offset = offset
                    .checked_add(data.len() as u64)
                    .ok_or_else(|| DandiError::ArchiveEngine("ZIP offset overflow".to_string()))?;
                Ok((0, start))
            }
            Self::Pkware { writer } => writer.write_atomic_record(data),
        }
    }

    fn write_payload(&mut self, data: &[u8]) -> Result<()> {
        match self {
            Self::Single { writer, offset } => {
                writer.write_all(data)?;
                *offset = offset
                    .checked_add(data.len() as u64)
                    .ok_or_else(|| DandiError::ArchiveEngine("ZIP offset overflow".to_string()))?;
                Ok(())
            }
            Self::Numeric { writer, offset } => {
                writer.write_all(data)?;
                *offset = offset
                    .checked_add(data.len() as u64)
                    .ok_or_else(|| DandiError::ArchiveEngine("ZIP offset overflow".to_string()))?;
                Ok(())
            }
            Self::Pkware { writer } => writer.write_splittable(data),
        }
    }

    fn deflate_stream_from(
        &mut self,
        src: &mut File,
        src_path: &Path,
        compression_level: u32,
        cancel: &CancellationToken,
    ) -> Result<(u64, u64, u32)> {
        let mut buf = vec![0u8; STREAM_BUF_SIZE];
        let mut crc_hasher = crc32fast::Hasher::new();
        let mut uncompressed_size = 0u64;

        let compressed_size = match self {
            Self::Single { writer, offset } => {
                let start_pos = *offset;
                let mut enc = DeflateEncoder::new(writer, Compression::new(compression_level));
                loop {
                    cancel.check()?;
                    let n = src
                        .read(&mut buf)
                        .map_err(|e| DandiError::io(src_path, e))?;
                    if n == 0 {
                        break;
                    }
                    crc_hasher.update(&buf[..n]);
                    uncompressed_size += n as u64;
                    enc.write_all(&buf[..n])?;
                }
                let inner = enc.finish()?;
                inner.flush()?;
                let end_pos = inner.stream_position()?;
                *offset = end_pos;
                end_pos - start_pos
            }
            Self::Numeric { writer, offset } => {
                let start_pos = *offset;
                let mut enc = DeflateEncoder::new(writer, Compression::new(compression_level));
                loop {
                    cancel.check()?;
                    let n = src
                        .read(&mut buf)
                        .map_err(|e| DandiError::io(src_path, e))?;
                    if n == 0 {
                        break;
                    }
                    crc_hasher.update(&buf[..n]);
                    uncompressed_size += n as u64;
                    enc.write_all(&buf[..n])?;
                }
                let inner = enc.finish()?;
                inner.flush()?;
                let end_pos = inner.stream_position()?;
                *offset = end_pos;
                end_pos - start_pos
            }
            Self::Pkware { writer } => {
                let start_total = writer.total_bytes();
                let mut enc = DeflateEncoder::new(writer, Compression::new(compression_level));
                loop {
                    cancel.check()?;
                    let n = src
                        .read(&mut buf)
                        .map_err(|e| DandiError::io(src_path, e))?;
                    if n == 0 {
                        break;
                    }
                    crc_hasher.update(&buf[..n]);
                    uncompressed_size += n as u64;
                    enc.write_all(&buf[..n])?;
                }
                let inner = enc.finish()?;
                inner.flush()?;
                inner.total_bytes() - start_total
            }
        };

        Ok((uncompressed_size, compressed_size, crc_hasher.finalize()))
    }

    fn patch_at(&mut self, disk: u32, offset_in_disk: u64, bytes: &[u8]) -> Result<()> {
        match self {
            Self::Single { writer, offset } => {
                writer.flush()?;
                let inner = writer.get_mut();
                inner.seek(SeekFrom::Start(offset_in_disk))?;
                inner.write_all(bytes)?;
                inner.seek(SeekFrom::Start(*offset))?;
                Ok(())
            }
            Self::Numeric { writer, offset } => {
                writer.flush()?;
                let inner = writer.get_mut();
                inner.seek(SeekFrom::Start(offset_in_disk))?;
                inner.write_all(bytes)?;
                inner.seek(SeekFrom::Start(*offset))?;
                Ok(())
            }
            Self::Pkware { writer } => writer.patch_at(disk, offset_in_disk, bytes),
        }
    }
}

struct GoldenZipWriter {
    backend: ZipOutputBackend,
    cd_records: Vec<WrittenCdRecord>,
    used_zip64: bool,
}

impl GoldenZipWriter {
    fn new_single(file: File) -> Self {
        Self {
            backend: ZipOutputBackend::Single {
                writer: BufWriter::with_capacity(STREAM_BUF_SIZE, file),
                offset: 0,
            },
            cd_records: Vec::new(),
            used_zip64: false,
        }
    }

    fn new_numeric(split_writer: SplitVolumeWriter) -> Self {
        Self {
            backend: ZipOutputBackend::Numeric {
                writer: BufWriter::with_capacity(STREAM_BUF_SIZE, split_writer),
                offset: 0,
            },
            cd_records: Vec::new(),
            used_zip64: false,
        }
    }

    fn new_pkware(pkware: PkwareSplitWriter) -> Self {
        Self {
            backend: ZipOutputBackend::Pkware { writer: pkware },
            cd_records: Vec::new(),
            used_zip64: false,
        }
    }

    fn write_prepared(&mut self, entry: PreparedEntry) -> Result<()> {
        let name_bytes = entry.archive_name.into_bytes();
        let name_len = u16::try_from(name_bytes.len()).map_err(|_| {
            DandiError::InvalidInput("ZIP entry filename exceeds 65535 bytes".to_string())
        })?;
        let compressed_size = entry.payload.len() as u64;
        let uncompressed_size = entry.uncompressed_size;

        let (dos_date, dos_time) = unix_secs_to_dos(entry.mtime_secs);
        let extra_5455 = build_0x5455_extra(entry.mtime_secs);

        let need_zip64_sizes =
            compressed_size >= ZIP64_THRESHOLD_U32 || uncompressed_size >= ZIP64_THRESHOLD_U32;
        let mut lfh_extra = Vec::with_capacity(9 + if need_zip64_sizes { 20 } else { 0 });
        if need_zip64_sizes {
            lfh_extra.extend_from_slice(&0x0001u16.to_le_bytes());
            lfh_extra.extend_from_slice(&16u16.to_le_bytes());
            lfh_extra.extend_from_slice(&uncompressed_size.to_le_bytes());
            lfh_extra.extend_from_slice(&compressed_size.to_le_bytes());
        }
        lfh_extra.extend_from_slice(&extra_5455);

        let lfh_total_len = 30 + name_bytes.len() + lfh_extra.len();
        // Ensure we know the exact disk and offset BEFORE deciding ZIP64 offset version_needed.
        if let ZipOutputBackend::Pkware { ref mut writer } = self.backend {
            writer.ensure_contiguous_space(lfh_total_len as u64)?;
        }
        let (disk_number_start, local_header_offset) = self.backend.current_location();

        let need_zip64_offset = local_header_offset >= ZIP64_THRESHOLD_U32;
        let need_zip64_disk = disk_number_start >= ZIP64_THRESHOLD_DISK;
        let version_needed = if need_zip64_sizes || need_zip64_offset || need_zip64_disk {
            self.used_zip64 = true;
            45u16
        } else {
            20u16
        };

        let lfh_comp = if need_zip64_sizes {
            0xFFFF_FFFFu32
        } else {
            compressed_size as u32
        };
        let lfh_uncomp = if need_zip64_sizes {
            0xFFFF_FFFFu32
        } else {
            uncompressed_size as u32
        };

        let mut lfh_block = Vec::with_capacity(lfh_total_len);
        lfh_block.extend_from_slice(&LFH_SIG.to_le_bytes());
        lfh_block.extend_from_slice(&version_needed.to_le_bytes());
        lfh_block.extend_from_slice(&BIT11_UTF8.to_le_bytes());
        lfh_block.extend_from_slice(&entry.method.to_le_bytes());
        lfh_block.extend_from_slice(&dos_time.to_le_bytes());
        lfh_block.extend_from_slice(&dos_date.to_le_bytes());
        lfh_block.extend_from_slice(&entry.crc32.to_le_bytes());
        lfh_block.extend_from_slice(&lfh_comp.to_le_bytes());
        lfh_block.extend_from_slice(&lfh_uncomp.to_le_bytes());
        lfh_block.extend_from_slice(&name_len.to_le_bytes());
        lfh_block.extend_from_slice(&(lfh_extra.len() as u16).to_le_bytes());
        lfh_block.extend_from_slice(&name_bytes);
        lfh_block.extend_from_slice(&lfh_extra);

        let (actual_disk, actual_offset) = self.backend.write_atomic_header(&lfh_block)?;
        self.backend.write_payload(&entry.payload)?;

        let external_attrs = (entry.unix_mode << 16) | (entry.dos_attr & 0xFFFF);
        self.cd_records.push(WrittenCdRecord {
            name_bytes,
            version_needed,
            flags: BIT11_UTF8,
            method: entry.method,
            dos_time,
            dos_date,
            crc32: entry.crc32,
            compressed_size,
            uncompressed_size,
            mtime_secs: entry.mtime_secs,
            external_attrs,
            disk_number_start: actual_disk,
            local_header_offset: actual_offset,
        });

        Ok(())
    }

    /// Streams a large file (> 16 MiB) directly into the ZIP without buffering it in RAM.
    fn write_large_streamed(
        &mut self,
        item: &PackItem,
        compression_level: u32,
        cancel: &CancellationToken,
    ) -> Result<u16> {
        let store_only = compression_level == 0 || is_incompressible_extension(&item.archive_name);
        let method = if store_only {
            METHOD_STORE
        } else {
            METHOD_DEFLATE
        };
        let name_bytes = item.archive_name.as_bytes().to_vec();
        let name_len = u16::try_from(name_bytes.len()).map_err(|_| {
            DandiError::InvalidInput("ZIP entry filename exceeds 65535 bytes".to_string())
        })?;
        let need_zip64_sizes = item.size >= ZIP64_THRESHOLD_U32;
        let (dos_date, dos_time) = unix_secs_to_dos(item.mtime_secs);
        let extra_5455 = build_0x5455_extra(item.mtime_secs);

        let mut lfh_extra = Vec::with_capacity(9 + if need_zip64_sizes { 20 } else { 0 });
        if need_zip64_sizes {
            lfh_extra.extend_from_slice(&0x0001u16.to_le_bytes());
            lfh_extra.extend_from_slice(&16u16.to_le_bytes());
            lfh_extra.extend_from_slice(&0u64.to_le_bytes());
            lfh_extra.extend_from_slice(&0u64.to_le_bytes());
        }
        lfh_extra.extend_from_slice(&extra_5455);

        let lfh_total_len = 30 + name_bytes.len() + lfh_extra.len();
        if let ZipOutputBackend::Pkware { ref mut writer } = self.backend {
            writer.ensure_contiguous_space(lfh_total_len as u64)?;
        }
        let (disk_number_start, local_header_offset) = self.backend.current_location();

        let need_zip64_offset = local_header_offset >= ZIP64_THRESHOLD_U32;
        let need_zip64_disk = disk_number_start >= ZIP64_THRESHOLD_DISK;
        let version_needed = if need_zip64_sizes || need_zip64_offset || need_zip64_disk {
            self.used_zip64 = true;
            45u16
        } else {
            20u16
        };

        let mut lfh_block = Vec::with_capacity(lfh_total_len);
        lfh_block.extend_from_slice(&LFH_SIG.to_le_bytes());
        lfh_block.extend_from_slice(&version_needed.to_le_bytes());
        lfh_block.extend_from_slice(&BIT11_UTF8.to_le_bytes());
        lfh_block.extend_from_slice(&method.to_le_bytes());
        lfh_block.extend_from_slice(&dos_time.to_le_bytes());
        lfh_block.extend_from_slice(&dos_date.to_le_bytes());
        lfh_block.extend_from_slice(&0u32.to_le_bytes()); // crc placeholder
        lfh_block.extend_from_slice(&0u32.to_le_bytes()); // comp placeholder
        lfh_block.extend_from_slice(&0u32.to_le_bytes()); // uncomp placeholder
        lfh_block.extend_from_slice(&name_len.to_le_bytes());
        lfh_block.extend_from_slice(&(lfh_extra.len() as u16).to_le_bytes());
        lfh_block.extend_from_slice(&name_bytes);
        lfh_block.extend_from_slice(&lfh_extra);

        let (lfh_disk, lfh_offset) = self.backend.write_atomic_header(&lfh_block)?;
        let z64_field_offset = lfh_offset + 30 + (name_bytes.len() as u64);

        let mut src =
            File::open(to_fs_path(&item.fs_path)).map_err(|e| DandiError::io(&item.fs_path, e))?;

        let (uncompressed_size, compressed_size, crc32) = if method == METHOD_STORE {
            let mut buf = vec![0u8; STREAM_BUF_SIZE];
            let mut crc_hasher = crc32fast::Hasher::new();
            let mut uncomp = 0u64;
            loop {
                cancel.check()?;
                let n = src
                    .read(&mut buf)
                    .map_err(|e| DandiError::io(&item.fs_path, e))?;
                if n == 0 {
                    break;
                }
                crc_hasher.update(&buf[..n]);
                uncomp += n as u64;
                self.backend.write_payload(&buf[..n])?;
            }
            (uncomp, uncomp, crc_hasher.finalize())
        } else {
            self.backend
                .deflate_stream_from(&mut src, &item.fs_path, compression_level, cancel)?
        };

        // Patch CRC32 and sizes directly into the Local File Header on `lfh_disk`.
        let lfh_comp = if need_zip64_sizes || compressed_size >= ZIP64_THRESHOLD_U32 {
            0xFFFF_FFFFu32
        } else {
            compressed_size as u32
        };
        let lfh_uncomp = if need_zip64_sizes || uncompressed_size >= ZIP64_THRESHOLD_U32 {
            0xFFFF_FFFFu32
        } else {
            uncompressed_size as u32
        };
        let mut patch = [0u8; 12];
        patch[0..4].copy_from_slice(&crc32.to_le_bytes());
        patch[4..8].copy_from_slice(&lfh_comp.to_le_bytes());
        patch[8..12].copy_from_slice(&lfh_uncomp.to_le_bytes());
        self.backend.patch_at(lfh_disk, lfh_offset + 14, &patch)?;

        if need_zip64_sizes {
            let mut z64_patch = [0u8; 16];
            z64_patch[0..8].copy_from_slice(&uncompressed_size.to_le_bytes());
            z64_patch[8..16].copy_from_slice(&compressed_size.to_le_bytes());
            self.backend
                .patch_at(lfh_disk, z64_field_offset + 4, &z64_patch)?;
        }

        self.cd_records.push(WrittenCdRecord {
            name_bytes,
            version_needed,
            flags: BIT11_UTF8,
            method,
            dos_time,
            dos_date,
            crc32,
            compressed_size,
            uncompressed_size,
            mtime_secs: item.mtime_secs,
            external_attrs: item.unix_mode << 16,
            disk_number_start: lfh_disk,
            local_header_offset: lfh_offset,
        });

        Ok(method)
    }

    fn build_cdh_bytes(rec: &WrittenCdRecord, used_zip64: &mut bool) -> Vec<u8> {
        let need_z64_uncomp = rec.uncompressed_size >= ZIP64_THRESHOLD_U32;
        let need_z64_comp = rec.compressed_size >= ZIP64_THRESHOLD_U32;
        let need_z64_off = rec.local_header_offset >= ZIP64_THRESHOLD_U32;
        let need_z64_disk = rec.disk_number_start >= ZIP64_THRESHOLD_DISK;
        let need_z64 = need_z64_uncomp || need_z64_comp || need_z64_off || need_z64_disk;
        if need_z64 {
            *used_zip64 = true;
        }

        let mut cd_extra = Vec::with_capacity(41);
        if need_z64 {
            let mut z64_payload = Vec::with_capacity(28);
            if need_z64_uncomp {
                z64_payload.extend_from_slice(&rec.uncompressed_size.to_le_bytes());
            }
            if need_z64_comp {
                z64_payload.extend_from_slice(&rec.compressed_size.to_le_bytes());
            }
            if need_z64_off {
                z64_payload.extend_from_slice(&rec.local_header_offset.to_le_bytes());
            }
            if need_z64_disk {
                z64_payload.extend_from_slice(&rec.disk_number_start.to_le_bytes());
            }
            cd_extra.extend_from_slice(&0x0001u16.to_le_bytes());
            cd_extra.extend_from_slice(&(z64_payload.len() as u16).to_le_bytes());
            cd_extra.extend_from_slice(&z64_payload);
        }
        cd_extra.extend_from_slice(&build_0x5455_extra(rec.mtime_secs));

        let version_needed = if need_z64 {
            rec.version_needed.max(45)
        } else {
            rec.version_needed
        };
        let version_made_by = VERSION_MADE_BY_UNIX | version_needed;
        let cd_comp = if need_z64_comp {
            0xFFFF_FFFFu32
        } else {
            rec.compressed_size as u32
        };
        let cd_uncomp = if need_z64_uncomp {
            0xFFFF_FFFFu32
        } else {
            rec.uncompressed_size as u32
        };
        let cd_disk = if need_z64_disk {
            0xFFFFu16
        } else {
            rec.disk_number_start as u16
        };
        let cd_off = if need_z64_off {
            0xFFFF_FFFFu32
        } else {
            rec.local_header_offset as u32
        };

        let mut out = Vec::with_capacity(46 + rec.name_bytes.len() + cd_extra.len());
        out.extend_from_slice(&CDH_SIG.to_le_bytes());
        out.extend_from_slice(&version_made_by.to_le_bytes());
        out.extend_from_slice(&version_needed.to_le_bytes());
        out.extend_from_slice(&rec.flags.to_le_bytes());
        out.extend_from_slice(&rec.method.to_le_bytes());
        out.extend_from_slice(&rec.dos_time.to_le_bytes());
        out.extend_from_slice(&rec.dos_date.to_le_bytes());
        out.extend_from_slice(&rec.crc32.to_le_bytes());
        out.extend_from_slice(&cd_comp.to_le_bytes());
        out.extend_from_slice(&cd_uncomp.to_le_bytes());
        out.extend_from_slice(&(rec.name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&(cd_extra.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment len
        out.extend_from_slice(&cd_disk.to_le_bytes()); // disk number start
        out.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        out.extend_from_slice(&rec.external_attrs.to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&rec.name_bytes);
        out.extend_from_slice(&cd_extra);
        out
    }

    fn finish_and_commit(
        mut self,
        output_zip: &Path,
        overwrite: bool,
    ) -> Result<(PathBuf, Vec<PathBuf>, u64, bool)> {
        let entry_count = self.cd_records.len();

        match self.backend {
            ZipOutputBackend::Single {
                mut writer,
                mut offset,
            } => {
                let cd_start = offset;
                let records = std::mem::take(&mut self.cd_records);
                for rec in &records {
                    let cdh = Self::build_cdh_bytes(rec, &mut self.used_zip64);
                    writer.write_all(&cdh)?;
                    offset += cdh.len() as u64;
                }
                let cd_size = offset - cd_start;
                let trailer = build_eocd_trailer(
                    0,
                    0,
                    entry_count as u64,
                    entry_count as u64,
                    cd_size,
                    cd_start,
                    offset,
                    &mut self.used_zip64,
                );
                writer.write_all(&trailer)?;
                offset += trailer.len() as u64;
                writer.flush()?;
                Ok((
                    output_zip.to_path_buf(),
                    vec![output_zip.to_path_buf()],
                    offset,
                    self.used_zip64,
                ))
            }
            ZipOutputBackend::Numeric {
                mut writer,
                mut offset,
            } => {
                let cd_start = offset;
                let records = std::mem::take(&mut self.cd_records);
                for rec in &records {
                    let cdh = Self::build_cdh_bytes(rec, &mut self.used_zip64);
                    writer.write_all(&cdh)?;
                    offset += cdh.len() as u64;
                }
                let cd_size = offset - cd_start;
                let trailer = build_eocd_trailer(
                    0,
                    0,
                    entry_count as u64,
                    entry_count as u64,
                    cd_size,
                    cd_start,
                    offset,
                    &mut self.used_zip64,
                );
                writer.write_all(&trailer)?;
                writer.flush()?;
                let split_writer = writer
                    .into_inner()
                    .map_err(|e| DandiError::io_plain(e.into_error()))?;
                let (primary, volumes, total_bytes) = split_writer.commit(output_zip, overwrite)?;
                Ok((primary, volumes, total_bytes, self.used_zip64))
            }
            ZipOutputBackend::Pkware { mut writer } => {
                let mut records = std::mem::take(&mut self.cd_records);

                // If everything (entries + CD + EOCD) fits inside Disk 0, strip the 4-byte split
                // signature so single-volume archives are 100% standard single-file ZIPs.
                let estimated_cd_len: u64 = records
                    .iter()
                    .map(|r| 46 + (r.name_bytes.len() as u64) + 41)
                    .sum();
                let fits_single_disk = writer.disk_count() == 1
                    && writer
                        .current_location()
                        .1
                        .saturating_sub(4)
                        .saturating_add(estimated_cd_len)
                        .saturating_add(98)
                        <= writer.split_size();

                if fits_single_disk {
                    writer.strip_single_disk_split_sig()?;
                    for rec in &mut records {
                        rec.local_header_offset = rec.local_header_offset.saturating_sub(4);
                    }
                }

                let mut cd_start_loc: Option<(u32, u64)> = None;
                let mut cd_total_bytes = 0u64;
                let mut cd_entries_per_disk: HashMap<u32, u64> = HashMap::new();

                for rec in &records {
                    let cdh = Self::build_cdh_bytes(rec, &mut self.used_zip64);
                    let (disk, off) = writer.write_atomic_record(&cdh)?;
                    if cd_start_loc.is_none() {
                        cd_start_loc = Some((disk, off));
                    }
                    *cd_entries_per_disk.entry(disk).or_insert(0) += 1;
                    cd_total_bytes += cdh.len() as u64;
                }

                let (cd_start_disk, cd_start_offset) =
                    cd_start_loc.unwrap_or_else(|| writer.current_location());

                // Reserve space for the full trailer (ZIP64 EOCD + Locator + EOCD = max 98 bytes)
                // so the trailer is never split across volumes.
                writer.ensure_contiguous_space(98)?;
                let (final_disk, trailer_start_offset) = writer.current_location();
                let entries_on_final_disk =
                    cd_entries_per_disk.get(&final_disk).copied().unwrap_or(0);

                let trailer = build_eocd_trailer(
                    final_disk,
                    cd_start_disk,
                    entries_on_final_disk,
                    entry_count as u64,
                    cd_total_bytes,
                    cd_start_offset,
                    trailer_start_offset,
                    &mut self.used_zip64,
                );
                writer.write_atomic_record(&trailer)?;

                let (primary, volumes, total_bytes) = writer.commit(output_zip, overwrite)?;
                Ok((primary, volumes, total_bytes, self.used_zip64))
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_eocd_trailer(
    final_disk: u32,
    cd_start_disk: u32,
    entries_on_final_disk: u64,
    total_entries: u64,
    cd_size: u64,
    cd_start_offset: u64,
    z64_eocd_offset_in_final_disk: u64,
    used_zip64: &mut bool,
) -> Vec<u8> {
    let need_zip64_eocd = total_entries >= ZIP64_THRESHOLD_ENTRIES as u64
        || entries_on_final_disk >= ZIP64_THRESHOLD_ENTRIES as u64
        || cd_size >= ZIP64_THRESHOLD_U32
        || cd_start_offset >= ZIP64_THRESHOLD_U32
        || final_disk >= ZIP64_THRESHOLD_DISK
        || cd_start_disk >= ZIP64_THRESHOLD_DISK;

    let mut out = Vec::with_capacity(if need_zip64_eocd { 98 } else { 22 });

    if need_zip64_eocd {
        *used_zip64 = true;
        let mut z64_eocd = [0u8; 56];
        z64_eocd[0..4].copy_from_slice(&ZIP64_EOCD_SIG.to_le_bytes());
        z64_eocd[4..12].copy_from_slice(&44u64.to_le_bytes());
        z64_eocd[12..14].copy_from_slice(&(VERSION_MADE_BY_UNIX | 45).to_le_bytes());
        z64_eocd[14..16].copy_from_slice(&45u16.to_le_bytes());
        z64_eocd[16..20].copy_from_slice(&final_disk.to_le_bytes());
        z64_eocd[20..24].copy_from_slice(&cd_start_disk.to_le_bytes());
        z64_eocd[24..32].copy_from_slice(&entries_on_final_disk.to_le_bytes());
        z64_eocd[32..40].copy_from_slice(&total_entries.to_le_bytes());
        z64_eocd[40..48].copy_from_slice(&cd_size.to_le_bytes());
        z64_eocd[48..56].copy_from_slice(&cd_start_offset.to_le_bytes());
        out.extend_from_slice(&z64_eocd);

        let mut z64_loc = [0u8; 20];
        z64_loc[0..4].copy_from_slice(&ZIP64_LOCATOR_SIG.to_le_bytes());
        z64_loc[4..8].copy_from_slice(&final_disk.to_le_bytes());
        z64_loc[8..16].copy_from_slice(&z64_eocd_offset_in_final_disk.to_le_bytes());
        z64_loc[16..20].copy_from_slice(&(final_disk.saturating_add(1)).to_le_bytes());
        out.extend_from_slice(&z64_loc);
    }

    let eocd_this_disk = if final_disk >= ZIP64_THRESHOLD_DISK {
        0xFFFFu16
    } else {
        final_disk as u16
    };
    let eocd_cd_disk = if cd_start_disk >= ZIP64_THRESHOLD_DISK {
        0xFFFFu16
    } else {
        cd_start_disk as u16
    };
    let eocd_disk_entries = if entries_on_final_disk >= ZIP64_THRESHOLD_ENTRIES as u64 {
        0xFFFFu16
    } else {
        entries_on_final_disk as u16
    };
    let eocd_total_entries = if total_entries >= ZIP64_THRESHOLD_ENTRIES as u64 {
        0xFFFFu16
    } else {
        total_entries as u16
    };
    let eocd_cd_size = if cd_size >= ZIP64_THRESHOLD_U32 {
        0xFFFF_FFFFu32
    } else {
        cd_size as u32
    };
    let eocd_cd_offset = if cd_start_offset >= ZIP64_THRESHOLD_U32 {
        0xFFFF_FFFFu32
    } else {
        cd_start_offset as u32
    };

    let mut eocd = [0u8; 22];
    eocd[0..4].copy_from_slice(&EOCD_SIG.to_le_bytes());
    eocd[4..6].copy_from_slice(&eocd_this_disk.to_le_bytes());
    eocd[6..8].copy_from_slice(&eocd_cd_disk.to_le_bytes());
    eocd[8..10].copy_from_slice(&eocd_disk_entries.to_le_bytes());
    eocd[10..12].copy_from_slice(&eocd_total_entries.to_le_bytes());
    eocd[12..16].copy_from_slice(&eocd_cd_size.to_le_bytes());
    eocd[16..20].copy_from_slice(&eocd_cd_offset.to_le_bytes());
    out.extend_from_slice(&eocd);

    out
}

/// Streams a single encrypted ZIP into PKWARE multi-disk split volumes without decrypting payloads.
fn resplit_single_zip_to_pkware(
    src_single_zip: &Path,
    output_zip: &Path,
    split_size: u64,
    overwrite: bool,
    cancel: &CancellationToken,
) -> Result<(PathBuf, Vec<PathBuf>, u64, bool)> {
    let mut src =
        File::open(to_fs_path(src_single_zip)).map_err(|e| DandiError::io(src_single_zip, e))?;
    let parsed = read_single_disk_directory(&mut src, usize::MAX)?;

    let mut pkware = PkwareSplitWriter::new(output_zip, split_size)?;
    let mut new_locs: Vec<(u32, u64)> = Vec::with_capacity(parsed.headers.len());
    let mut copy_buf = vec![0u8; STREAM_BUF_SIZE];

    for (idx, h) in parsed.headers.iter().enumerate() {
        cancel.check()?;
        let start = h.local_header_offset;
        let end = parsed
            .headers
            .get(idx + 1)
            .map(|next| next.local_header_offset)
            .unwrap_or(parsed.cd_global_offset);
        if end < start {
            return Err(DandiError::ArchiveEngine(
                "invalid local header offsets during split".to_string(),
            ));
        }

        // Read LFH header (30 + name_len + extra_len) atomically so LFH is never split across disks.
        src.seek(SeekFrom::Start(start))?;
        let mut lfh_fixed = [0u8; 30];
        src.read_exact(&mut lfh_fixed)?;
        let lfh_name_len = read_u16_le(&lfh_fixed, 26)? as usize;
        let lfh_extra_len = read_u16_le(&lfh_fixed, 28)? as usize;
        let mut lfh_full = Vec::with_capacity(30 + lfh_name_len + lfh_extra_len);
        lfh_full.extend_from_slice(&lfh_fixed);
        let var_len = lfh_name_len + lfh_extra_len;
        let mut var_buf = vec![0u8; var_len];
        src.read_exact(&mut var_buf)?;
        lfh_full.extend_from_slice(&var_buf);

        let loc = pkware.write_atomic_record(&lfh_full)?;
        new_locs.push(loc);

        // Stream remaining encrypted payload (+ any data descriptor) across disk boundaries.
        let mut rem = (end - start).saturating_sub(lfh_full.len() as u64);
        while rem > 0 {
            cancel.check()?;
            let to_read = (rem as usize).min(copy_buf.len());
            src.read_exact(&mut copy_buf[..to_read])?;
            pkware.write_splittable(&copy_buf[..to_read])?;
            rem -= to_read as u64;
        }
    }

    let mut used_zip64 = false;
    let cd_buf = &parsed.raw_cd_bytes;
    let fits_single_disk = pkware.disk_count() == 1
        && pkware
            .current_location()
            .1
            .saturating_sub(4)
            .saturating_add(cd_buf.len() as u64)
            .saturating_add(parsed.headers.len() as u64 * 16)
            .saturating_add(98)
            <= pkware.split_size();

    if fits_single_disk {
        pkware.strip_single_disk_split_sig()?;
        for (_, off) in &mut new_locs {
            *off = off.saturating_sub(4);
        }
    }

    let mut cd_start_loc: Option<(u32, u64)> = None;
    let mut cd_total_bytes = 0u64;
    let mut cd_entries_per_disk: HashMap<u32, u64> = HashMap::new();
    let mut pos = 0usize;
    let mut idx = 0usize;

    while pos < cd_buf.len() {
        let header_end = pos + 46;
        let name_len = read_u16_le(cd_buf, pos + 28)? as usize;
        let extra_len = read_u16_le(cd_buf, pos + 30)? as usize;
        let comment_len = read_u16_le(cd_buf, pos + 32)? as usize;
        let name_start = header_end;
        let extra_start = name_start + name_len;
        let comment_start = extra_start + extra_len;
        let next_pos = comment_start + comment_len;

        let hdr = &parsed.headers[idx];
        let (new_disk, new_off) = new_locs[idx];

        let need_z64_uncomp = hdr.uncompressed_size >= ZIP64_THRESHOLD_U32
            || read_u32_le(cd_buf, pos + 24)? as u64 == ZIP64_THRESHOLD_U32;
        let need_z64_comp = hdr.compressed_size >= ZIP64_THRESHOLD_U32
            || read_u32_le(cd_buf, pos + 20)? as u64 == ZIP64_THRESHOLD_U32;
        let need_z64_off = new_off >= ZIP64_THRESHOLD_U32;
        let need_z64_disk = new_disk >= ZIP64_THRESHOLD_DISK;
        let need_z64 = need_z64_uncomp || need_z64_comp || need_z64_off || need_z64_disk;
        if need_z64 {
            used_zip64 = true;
        }

        let orig_extra = &cd_buf[extra_start..comment_start];
        let mut new_extra = Vec::with_capacity(orig_extra.len() + 32);
        if need_z64 {
            let mut z64_payload = Vec::with_capacity(28);
            if need_z64_uncomp {
                z64_payload.extend_from_slice(&hdr.uncompressed_size.to_le_bytes());
            }
            if need_z64_comp {
                z64_payload.extend_from_slice(&hdr.compressed_size.to_le_bytes());
            }
            if need_z64_off {
                z64_payload.extend_from_slice(&new_off.to_le_bytes());
            }
            if need_z64_disk {
                z64_payload.extend_from_slice(&new_disk.to_le_bytes());
            }
            new_extra.extend_from_slice(&0x0001u16.to_le_bytes());
            new_extra.extend_from_slice(&(z64_payload.len() as u16).to_le_bytes());
            new_extra.extend_from_slice(&z64_payload);
        }
        copy_extra_fields_excluding(orig_extra, 0x0001, &mut new_extra);

        let mut cdh = [0u8; 46];
        cdh.copy_from_slice(&cd_buf[pos..header_end]);
        if need_z64 {
            let ver = u16::from_le_bytes([cdh[6], cdh[7]]).max(45);
            cdh[6..8].copy_from_slice(&ver.to_le_bytes());
        }
        cdh[30..32].copy_from_slice(&(new_extra.len() as u16).to_le_bytes());
        cdh[34..36].copy_from_slice(
            &(if need_z64_disk {
                0xFFFFu16
            } else {
                new_disk as u16
            })
            .to_le_bytes(),
        );
        cdh[42..46].copy_from_slice(
            &(if need_z64_off {
                0xFFFF_FFFFu32
            } else {
                new_off as u32
            })
            .to_le_bytes(),
        );

        let mut full_cdh = Vec::with_capacity(46 + name_len + new_extra.len() + comment_len);
        full_cdh.extend_from_slice(&cdh);
        full_cdh.extend_from_slice(&cd_buf[name_start..extra_start]);
        full_cdh.extend_from_slice(&new_extra);
        full_cdh.extend_from_slice(&cd_buf[comment_start..next_pos]);

        let (cd_disk, cd_off) = pkware.write_atomic_record(&full_cdh)?;
        if cd_start_loc.is_none() {
            cd_start_loc = Some((cd_disk, cd_off));
        }
        *cd_entries_per_disk.entry(cd_disk).or_insert(0) += 1;
        cd_total_bytes += full_cdh.len() as u64;

        pos = next_pos;
        idx += 1;
    }

    let (cd_start_disk, cd_start_offset) =
        cd_start_loc.unwrap_or_else(|| pkware.current_location());
    pkware.ensure_contiguous_space(98)?;
    let (final_disk, trailer_offset) = pkware.current_location();
    let entries_on_final_disk = cd_entries_per_disk.get(&final_disk).copied().unwrap_or(0);

    let trailer = build_eocd_trailer(
        final_disk,
        cd_start_disk,
        entries_on_final_disk,
        parsed.headers.len() as u64,
        cd_total_bytes,
        cd_start_offset,
        trailer_offset,
        &mut used_zip64,
    );
    pkware.write_atomic_record(&trailer)?;

    let (primary, volumes, total_bytes) = pkware.commit(output_zip, overwrite)?;
    Ok((primary, volumes, total_bytes, used_zip64))
}

fn pack_zip_golden_parallel(
    items: &[PackItem],
    mut writer: GoldenZipWriter,
    output_zip: &Path,
    opts: &PackOptions,
    junk_skipped: usize,
    total_input_bytes: u64,
    observer: &dyn ProgressObserver,
) -> Result<PackReport> {
    let mut entries_done = 0usize;
    let mut bytes_done = 0u64;
    let mut files_deflated = 0usize;
    let mut files_stored = 0usize;

    let mut batch: Vec<&PackItem> = Vec::new();
    let mut batch_bytes = 0u64;

    let flush_batch = |batch: &mut Vec<&PackItem>,
                       writer: &mut GoldenZipWriter,
                       entries_done: &mut usize,
                       bytes_done: &mut u64,
                       files_deflated: &mut usize,
                       files_stored: &mut usize|
     -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        opts.cancel.check()?;
        let level = opts.compression_level.min(9);
        let cancel = &opts.cancel;

        let prepared: Vec<Result<PreparedEntry>> = batch
            .par_iter()
            .map(|item| {
                cancel.check()?;
                let raw = fs::read(to_fs_path(&item.fs_path))
                    .map_err(|e| DandiError::io(&item.fs_path, e))?;
                let crc32 = crc32fast::hash(&raw);
                let uncompressed_size = raw.len() as u64;

                let should_store =
                    raw.is_empty() || level == 0 || is_incompressible_extension(&item.archive_name);

                let (method, payload) = if should_store {
                    (METHOD_STORE, raw)
                } else {
                    let mut encoder = DeflateEncoder::new(
                        Vec::with_capacity(raw.len() / 2),
                        Compression::new(level),
                    );
                    encoder.write_all(&raw)?;
                    let compressed = encoder.finish()?;
                    if compressed.len() < raw.len() {
                        (METHOD_DEFLATE, compressed)
                    } else {
                        (METHOD_STORE, raw)
                    }
                };

                Ok(PreparedEntry {
                    archive_name: item.archive_name.clone(),
                    method,
                    crc32,
                    uncompressed_size,
                    mtime_secs: item.mtime_secs,
                    unix_mode: item.unix_mode,
                    dos_attr: 0,
                    payload,
                })
            })
            .collect();

        for res in prepared {
            opts.cancel.check()?;
            let entry = res?;
            let entry_name = entry.archive_name.clone();
            let entry_size = entry.uncompressed_size;
            if entry.method == METHOD_DEFLATE {
                *files_deflated += 1;
            } else {
                *files_stored += 1;
            }
            writer.write_prepared(entry)?;
            *entries_done += 1;
            *bytes_done += entry_size;
            observer.on_progress(&ProgressEvent {
                phase: ProgressPhase::Packing,
                current_entry: entry_name,
                entries_done: *entries_done,
                entries_total: items.len(),
                bytes_done: *bytes_done,
                bytes_total: total_input_bytes,
            });
        }
        batch.clear();
        Ok(())
    };

    for item in items {
        opts.cancel.check()?;
        match item.kind {
            EntryKind::Directory => {
                flush_batch(
                    &mut batch,
                    &mut writer,
                    &mut entries_done,
                    &mut bytes_done,
                    &mut files_deflated,
                    &mut files_stored,
                )?;
                batch_bytes = 0;
                writer.write_prepared(PreparedEntry {
                    archive_name: item.archive_name.clone(),
                    method: METHOD_STORE,
                    crc32: 0,
                    uncompressed_size: 0,
                    mtime_secs: item.mtime_secs,
                    unix_mode: item.unix_mode,
                    dos_attr: 0x10,
                    payload: Vec::new(),
                })?;
                entries_done += 1;
            }
            EntryKind::Symlink => {
                flush_batch(
                    &mut batch,
                    &mut writer,
                    &mut entries_done,
                    &mut bytes_done,
                    &mut files_deflated,
                    &mut files_stored,
                )?;
                batch_bytes = 0;
                let target_bytes = item
                    .symlink_target
                    .as_deref()
                    .unwrap_or_default()
                    .as_bytes()
                    .to_vec();
                let crc32 = crc32fast::hash(&target_bytes);
                let len = target_bytes.len() as u64;
                writer.write_prepared(PreparedEntry {
                    archive_name: item.archive_name.clone(),
                    method: METHOD_STORE,
                    crc32,
                    uncompressed_size: len,
                    mtime_secs: item.mtime_secs,
                    unix_mode: item.unix_mode,
                    dos_attr: 0,
                    payload: target_bytes,
                })?;
                files_stored += 1;
                entries_done += 1;
                bytes_done += len;
            }
            EntryKind::File => {
                if item.size > LARGE_STREAM_THRESHOLD {
                    flush_batch(
                        &mut batch,
                        &mut writer,
                        &mut entries_done,
                        &mut bytes_done,
                        &mut files_deflated,
                        &mut files_stored,
                    )?;
                    batch_bytes = 0;
                    let method = writer.write_large_streamed(
                        item,
                        opts.compression_level.min(9),
                        &opts.cancel,
                    )?;
                    if method == METHOD_DEFLATE {
                        files_deflated += 1;
                    } else {
                        files_stored += 1;
                    }
                    entries_done += 1;
                    bytes_done += item.size;
                    observer.on_progress(&ProgressEvent {
                        phase: ProgressPhase::Packing,
                        current_entry: item.archive_name.clone(),
                        entries_done,
                        entries_total: items.len(),
                        bytes_done,
                        bytes_total: total_input_bytes,
                    });
                } else {
                    if !batch.is_empty()
                        && (batch.len() >= PARALLEL_BATCH_MAX_FILES
                            || batch_bytes + item.size > PARALLEL_BATCH_MAX_BYTES)
                    {
                        flush_batch(
                            &mut batch,
                            &mut writer,
                            &mut entries_done,
                            &mut bytes_done,
                            &mut files_deflated,
                            &mut files_stored,
                        )?;
                        batch_bytes = 0;
                    }
                    batch_bytes += item.size;
                    batch.push(item);
                }
            }
        }
    }

    flush_batch(
        &mut batch,
        &mut writer,
        &mut entries_done,
        &mut bytes_done,
        &mut files_deflated,
        &mut files_stored,
    )?;

    let (output_path, output_volumes, output_bytes, used_zip64) =
        writer.finish_and_commit(output_zip, opts.overwrite)?;

    Ok(PackReport {
        output_path,
        output_volumes,
        entries_written: items.len(),
        files_deflated,
        files_stored,
        junk_skipped,
        total_input_bytes,
        output_bytes,
        used_zip64,
        encrypted: false,
    })
}

#[allow(clippy::too_many_arguments)]
fn pack_zip_encrypted_into<W: Write + Seek>(
    items: &[PackItem],
    sink: W,
    output_zip: &Path,
    password: &str,
    opts: &PackOptions,
    junk_skipped: usize,
    total_input_bytes: u64,
    observer: &dyn ProgressObserver,
) -> Result<(PackReport, W)> {
    let pw_nfc: String = password.nfc().collect();
    let mut zw = ZipWriter::new(sink);

    let mut files_deflated = 0usize;
    let mut files_stored = 0usize;
    let mut bytes_done = 0u64;
    let mut buf = vec![0u8; STREAM_BUF_SIZE];

    for (idx, item) in items.iter().enumerate() {
        opts.cancel.check()?;
        let dt = unix_secs_to_zip_datetime(item.mtime_secs);
        let ts_u32 = item.mtime_secs.clamp(0, u32::MAX as i64) as u32;

        match item.kind {
            EntryKind::Directory => {
                let fopts = SimpleFileOptions::default()
                    .compression_method(CompressionMethod::Stored)
                    .unix_permissions(item.unix_mode)
                    .last_modified_time(dt)
                    .large_file(false)
                    .with_extended_timestamp(Some(ts_u32), None, None)
                    .map_err(|e| DandiError::ArchiveEngine(e.to_string()))?;
                zw.add_directory(&item.archive_name, fopts)
                    .map_err(|e| DandiError::ArchiveEngine(e.to_string()))?;
            }
            EntryKind::Symlink => {
                let target = item.symlink_target.as_deref().unwrap_or_default();
                let fopts = SimpleFileOptions::default()
                    .compression_method(CompressionMethod::Stored)
                    .unix_permissions(item.unix_mode)
                    .last_modified_time(dt)
                    .with_aes_encryption(AesMode::Aes256, &pw_nfc);
                zw.add_symlink(&item.archive_name, target, fopts)
                    .map_err(|e| DandiError::ArchiveEngine(e.to_string()))?;
                files_stored += 1;
            }
            EntryKind::File => {
                let use_store =
                    opts.compression_level == 0 || is_incompressible_extension(&item.archive_name);
                let method = if use_store {
                    files_stored += 1;
                    CompressionMethod::Stored
                } else {
                    files_deflated += 1;
                    CompressionMethod::Deflated
                };
                // The `zip` crate rejects any explicit level for `Stored` entries.
                let level = (!use_store).then(|| i64::from(opts.compression_level.min(9)));
                let fopts = SimpleFileOptions::default()
                    .compression_method(method)
                    .compression_level(level)
                    .unix_permissions(item.unix_mode)
                    .last_modified_time(dt)
                    .large_file(item.size >= ZIP64_THRESHOLD_U32)
                    .with_aes_encryption(AesMode::Aes256, &pw_nfc)
                    .with_extended_timestamp(Some(ts_u32), None, None)
                    .map_err(|e| DandiError::ArchiveEngine(e.to_string()))?;

                zw.start_file(&item.archive_name, fopts)
                    .map_err(|e| DandiError::ArchiveEngine(e.to_string()))?;

                let mut src = File::open(to_fs_path(&item.fs_path))
                    .map_err(|e| DandiError::io(&item.fs_path, e))?;
                loop {
                    opts.cancel.check()?;
                    let n = src
                        .read(&mut buf)
                        .map_err(|e| DandiError::io(&item.fs_path, e))?;
                    if n == 0 {
                        break;
                    }
                    zw.write_all(&buf[..n])?;
                    bytes_done += n as u64;
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

    let mut finished = zw
        .finish()
        .map_err(|e| DandiError::ArchiveEngine(e.to_string()))?;
    finished.flush()?;
    let output_bytes = finished.stream_position()?;

    let report = PackReport {
        output_path: output_zip.to_path_buf(),
        output_volumes: vec![output_zip.to_path_buf()],
        entries_written: items.len(),
        files_deflated,
        files_stored,
        junk_skipped,
        total_input_bytes,
        output_bytes,
        used_zip64: output_bytes >= ZIP64_THRESHOLD_U32 || items.len() >= ZIP64_THRESHOLD_ENTRIES,
        encrypted: true,
    };
    Ok((report, finished))
}

fn unix_secs_to_zip_datetime(unix_secs: i64) -> zip::DateTime {
    let dt = OffsetDateTime::from_unix_timestamp(unix_secs).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let year = dt.year().clamp(1980, 2107) as u16;
    let month = u8::from(dt.month());
    let day = dt.day();
    let hour = dt.hour();
    let minute = dt.minute();
    let second = dt.second();
    zip::DateTime::from_date_and_time(year, month, day, hour, minute, second).unwrap_or_default()
}

pub(crate) fn repack_zip_nfc(
    src_zip: &Path,
    dst_zip: &Path,
    opts: &RepackOptions,
    observer: &dyn ProgressObserver,
) -> Result<RepackReport> {
    opts.cancel.check()?;
    if to_fs_path(dst_zip).exists() && !opts.overwrite {
        return Err(DandiError::AlreadyExists {
            path: dst_zip.to_path_buf(),
        });
    }
    if let Some(parent) = dst_zip.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(to_fs_path(parent)).map_err(|e| DandiError::io(parent, e))?;
        }
    }

    let opened = open_zip_source(src_zip, opts.budget.max_entries)?;
    let raw_headers = opened.raw_headers;
    let src_file_size = opened.archive_total_size;

    let non_bit11: Vec<&[u8]> = raw_headers
        .iter()
        .filter(|h| !h.utf8_bit11() && !h.has_valid_0x7075())
        .map(|h| h.raw_name.as_slice())
        .collect();
    let detection = detect_archive_encoding(&non_bit11, opts.locale_hint);
    let source_encoding = opts.encoding_override.unwrap_or(detection.encoding);
    let explicit_override = opts.encoding_override.is_some();

    let mut archive = ZipArchive::new(opened.stream).map_err(map_zip_error)?;

    let tmp_path = create_sibling_temp_path(dst_zip, "zip");
    let mut guard = TempFileGuard::new(tmp_path.clone());
    let tmp_file = File::create(to_fs_path(&tmp_path)).map_err(|e| DandiError::io(&tmp_path, e))?;
    let mut writer = GoldenZipWriter::new_single(tmp_file);

    let mut budget = opts.budget.clone();
    budget.set_archive_compressed_size(src_file_size);
    let mut entries_repacked = 0usize;
    let mut junk_skipped = 0usize;
    let total_bytes: u64 = raw_headers.iter().map(|h| h.uncompressed_size).sum();

    for h in &raw_headers {
        opts.cancel.check()?;
        let decoded = decode_entry_name_with_override(
            &h.raw_name,
            EntryEncodingFlags {
                utf8_bit11: h.utf8_bit11(),
            },
            h.unicode_extra_0x7075(),
            source_encoding,
            explicit_override,
        );
        if opts.exclude_os_junk && is_os_junk(&decoded.path) {
            junk_skipped += 1;
            continue;
        }
        budget.record_entry(h.uncompressed_size, h.compressed_size)?;

        let mut clean_name = normalize_for_pack(&decoded.path);
        if clean_name.is_empty() {
            continue;
        }

        let mtime_secs = h.mtime_unix_secs.unwrap_or_else(current_unix_secs);
        if h.is_dir_with_decoded_name(&decoded.path) {
            if !clean_name.ends_with('/') {
                clean_name.push('/');
            }
            let mode = h.unix_mode().unwrap_or(0o040755);
            writer.write_prepared(PreparedEntry {
                archive_name: clean_name,
                method: METHOD_STORE,
                crc32: 0,
                uncompressed_size: 0,
                mtime_secs,
                unix_mode: if mode & 0o777 == 0 { 0o040755 } else { mode },
                dos_attr: 0x10,
                payload: Vec::new(),
            })?;
        } else {
            let mut zf = open_zip_entry(
                &mut archive,
                h.index,
                h.encrypted(),
                opts.password.as_deref(),
            )?;
            budget.note_live_entry_compressed(h.compressed_size);
            let mut raw = Vec::new();
            let mut chunk = [0u8; 64 * 1024];
            let mut entry_read = 0u64;
            loop {
                opts.cancel.check()?;
                let n = zf.read(&mut chunk).map_err(classify_zip_read_io_error)?;
                if n == 0 {
                    break;
                }
                entry_read += n as u64;
                budget.record_written_bytes(n as u64, entry_read, h.compressed_size)?;
                raw.extend_from_slice(&chunk[..n]);
            }
            let crc32 = crc32fast::hash(&raw);
            let uncompressed_size = raw.len() as u64;
            let is_sym = h.is_symlink();
            let mode = if is_sym {
                0o120777
            } else {
                match h.unix_mode() {
                    Some(m) if (m & 0o777) != 0 => m,
                    _ => 0o100644,
                }
            };

            let (method, payload) = if is_sym
                || raw.is_empty()
                || opts.compression_level == 0
                || is_incompressible_extension(&clean_name)
            {
                (METHOD_STORE, raw)
            } else {
                let mut enc = DeflateEncoder::new(
                    Vec::with_capacity(raw.len() / 2),
                    Compression::new(opts.compression_level.min(9)),
                );
                enc.write_all(&raw)?;
                let comp = enc.finish()?;
                if comp.len() < raw.len() {
                    (METHOD_DEFLATE, comp)
                } else {
                    (METHOD_STORE, raw)
                }
            };

            writer.write_prepared(PreparedEntry {
                archive_name: clean_name.clone(),
                method,
                crc32,
                uncompressed_size,
                mtime_secs,
                unix_mode: mode,
                dos_attr: 0,
                payload,
            })?;
        }

        entries_repacked += 1;
        observer.on_progress(&ProgressEvent {
            phase: ProgressPhase::Repacking,
            current_entry: decoded.path,
            entries_done: entries_repacked,
            entries_total: raw_headers.len(),
            bytes_done: budget.bytes_written(),
            bytes_total: total_bytes,
        });
    }

    let (_, _, output_bytes, _) = writer.finish_and_commit(dst_zip, opts.overwrite)?;
    drop(archive);
    commit_temp_file(&tmp_path, dst_zip, opts.overwrite)?;
    guard.disarm();

    Ok(RepackReport {
        output_path: dst_zip.to_path_buf(),
        source_encoding,
        entries_repacked,
        junk_skipped,
        output_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::zip::header::inspect_zip_raw_headers;
    use crate::archive::{unpack, ExtractMode, UnpackOptions};
    use crate::progress::NoopProgressObserver;
    use tempfile::TempDir;

    #[test]
    fn repack_nfc_in_place_succeeds_when_src_equals_dst() {
        let tmp = TempDir::new().unwrap();
        let src_dir = tmp.path().join("in_place_src");
        fs::create_dir_all(&src_dir).unwrap();
        let file_name = "가나다_테스트.txt";
        let payload = b"in-place repack payload";
        fs::write(src_dir.join(file_name), payload).unwrap();

        let zip_path = tmp.path().join("same.zip");
        pack_zip(
            &[src_dir],
            &zip_path,
            &PackOptions::default(),
            &NoopProgressObserver,
        )
        .unwrap();

        // Repack directly in-place (src_zip == dst_zip); must not fail with Windows sharing violation.
        let report = repack_zip_nfc(
            &zip_path,
            &zip_path,
            &RepackOptions::default(),
            &NoopProgressObserver,
        )
        .unwrap();
        assert_eq!(report.output_path, zip_path);
        assert!(report.entries_repacked >= 1);

        let headers = inspect_zip_raw_headers(&zip_path).unwrap();
        assert!(!headers.is_empty());
        assert!(headers.iter().all(|h| h.utf8_bit11()));

        let out_dir = tmp.path().join("out");
        unpack(
            &zip_path,
            &out_dir,
            &UnpackOptions {
                mode: ExtractMode::Direct,
                ..UnpackOptions::default()
            },
            &NoopProgressObserver,
        )
        .unwrap();
        assert_eq!(
            fs::read(out_dir.join("in_place_src").join(file_name)).unwrap(),
            payload
        );
    }
}
