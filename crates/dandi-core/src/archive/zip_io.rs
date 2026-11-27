use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::write::DeflateEncoder;
use flate2::Compression;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};
use unicode_normalization::UnicodeNormalization;
use walkdir::WalkDir;
use zip::write::SimpleFileOptions;
use zip::{AesMode, CompressionMethod, ZipArchive, ZipWriter};

use crate::archive::{
    check_not_through_archive_symlink, check_symlink_chain_safe, ensure_no_symlink_ancestors,
    plan_extract_root, synthesize_parent_dirs, ArchiveEntryInfo, ArchiveFormat, ArchiveSummary,
    DirCleanupGuard, EntryKind, InspectOptions, PackOptions, PackReport, RepackOptions,
    RepackReport, UnpackOptions, UnpackReport,
};
use crate::codec::{
    decode_entry_name_with_override, detect_archive_encoding, normalize_for_pack, verify_0x7075,
    EntryEncodingFlags,
};
use crate::error::{DandiError, Result};
use crate::platform::{
    apply_unix_mode, create_relative_symlink, read_unix_mode_for_pack, read_zone_identifier,
    set_mtime, to_fs_path, write_zone_identifier,
};
use crate::progress::{ProgressEvent, ProgressObserver, ProgressPhase};
use crate::safety::{
    is_os_junk, sanitize_entry_path, validate_symlink_target, CollisionTracker, SafetyBudget,
};

const LFH_SIG: u32 = 0x0403_4b50;
const CDH_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;
const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;
const ZIP64_LOCATOR_SIG: u32 = 0x0706_4b50;

const BIT11_UTF8: u16 = 0x0800;
const BIT0_ENCRYPTED: u16 = 0x0001;
const VERSION_MADE_BY_UNIX: u16 = 3 << 8;

const METHOD_STORE: u16 = 0;
const METHOD_DEFLATE: u16 = 8;

const ZIP64_THRESHOLD_U32: u64 = 0xFFFF_FFFF;
const ZIP64_THRESHOLD_ENTRIES: usize = 0xFFFF;

const PARALLEL_BATCH_MAX_BYTES: u64 = 32 * 1024 * 1024;
const PARALLEL_BATCH_MAX_FILES: usize = 256;
const LARGE_STREAM_THRESHOLD: u64 = 16 * 1024 * 1024;
const STREAM_BUF_SIZE: usize = 256 * 1024;

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Raw parsed Central Directory entry header for low-level inspection and accurate encoding detection.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RawZipEntryHeader {
    pub index: usize,
    pub version_made_by: u16,
    pub version_needed: u16,
    pub flags: u16,
    pub compression_method: u16,
    pub dos_time: u16,
    pub dos_date: u16,
    pub crc32: u32,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub raw_name: Vec<u8>,
    pub extra_data: Vec<u8>,
    pub external_attrs: u32,
    pub local_header_offset: u64,
    pub has_0x7075: bool,
    pub has_0x5455: bool,
    pub has_zip64_extra: bool,
    pub mtime_unix_secs: Option<i64>,
}

impl RawZipEntryHeader {
    pub fn utf8_bit11(&self) -> bool {
        (self.flags & BIT11_UTF8) != 0
    }

    pub fn encrypted(&self) -> bool {
        (self.flags & BIT0_ENCRYPTED) != 0
    }

    pub fn unix_mode(&self) -> Option<u32> {
        let os_made_by = self.version_made_by >> 8;
        if os_made_by == 3 || os_made_by == 19 {
            let mode = (self.external_attrs >> 16) & 0xFFFF;
            if mode != 0 {
                return Some(mode);
            }
        }
        None
    }

    pub fn is_symlink(&self) -> bool {
        self.unix_mode()
            .map(|m| (m & 0o170000) == 0o120000)
            .unwrap_or(false)
    }

    /// Determines whether this ZIP entry represents a directory using the *decoded* filename.
    ///
    /// Never checks `raw_name.ends_with(b"\\")` on undecoded bytes because Shift_JIS characters
    /// such as `表`, `能`, and `ソ` legitimately end with trail byte `0x5C`.
    pub fn is_dir_with_decoded_name(&self, decoded_path: &str) -> bool {
        if self.is_symlink() {
            return false;
        }
        if decoded_path.ends_with('/') || decoded_path.ends_with('\\') {
            return true;
        }
        if let Some(m) = self.unix_mode() {
            if (m & 0o170000) == 0o040000 {
                return true;
            }
        }
        (self.external_attrs & 0x10) != 0 && self.uncompressed_size == 0
    }

    pub fn unicode_extra_0x7075(&self) -> Option<&[u8]> {
        find_extra_field(&self.extra_data, 0x7075)
    }

    /// Returns true only when an Info-ZIP `0x7075` extra field is present AND its CRC32 matches `raw_name`.
    pub fn has_valid_0x7075(&self) -> bool {
        self.unicode_extra_0x7075()
            .and_then(|e| verify_0x7075(&self.raw_name, e))
            .is_some()
    }
}

/// Inspects raw Central Directory headers of a ZIP file without modifying or decoding entry names.
pub fn inspect_zip_raw_headers(path: &Path) -> Result<Vec<RawZipEntryHeader>> {
    let fs_path = to_fs_path(path);
    let mut file = File::open(&fs_path).map_err(|e| DandiError::io(path, e))?;
    read_zip_raw_entries(&mut file, SafetyBudget::default().max_entries)
}

pub(crate) fn read_zip_raw_entries<R: Read + Seek>(
    reader: &mut R,
    max_entries: usize,
) -> Result<Vec<RawZipEntryHeader>> {
    let file_len = reader.seek(SeekFrom::End(0))?;
    if file_len < 22 {
        return Err(DandiError::CorruptArchive(
            "file is too small to be a valid ZIP archive".to_string(),
        ));
    }

    let search_len = file_len.min(65_535 + 22) as usize;
    let search_start = file_len - (search_len as u64);
    reader.seek(SeekFrom::Start(search_start))?;
    let mut tail = vec![0u8; search_len];
    reader.read_exact(&mut tail)?;

    let eocd_rel = find_eocd(&tail).ok_or_else(|| {
        DandiError::CorruptArchive("End of Central Directory record not found".to_string())
    })?;
    let eocd_offset = search_start + (eocd_rel as u64);
    let eocd = &tail[eocd_rel..];

    let mut total_entries = read_u16_le(eocd, 10)? as u64;
    let mut cd_size = read_u32_le(eocd, 12)? as u64;
    let mut cd_offset = read_u32_le(eocd, 16)? as u64;

    // Check for ZIP64 EOCD Locator immediately preceding EOCD.
    if eocd_offset >= 20 {
        let mut loc = [0u8; 20];
        reader.seek(SeekFrom::Start(eocd_offset - 20))?;
        reader.read_exact(&mut loc)?;
        if read_u32_le(&loc, 0)? == ZIP64_LOCATOR_SIG {
            let z64_offset = read_u64_le(&loc, 8)?;
            if z64_offset
                .checked_add(56)
                .is_some_and(|end| end <= file_len)
            {
                let mut z64 = [0u8; 56];
                reader.seek(SeekFrom::Start(z64_offset))?;
                reader.read_exact(&mut z64)?;
                if read_u32_le(&z64, 0)? == ZIP64_EOCD_SIG {
                    total_entries = read_u64_le(&z64, 32)?;
                    cd_size = read_u64_le(&z64, 40)?;
                    cd_offset = read_u64_le(&z64, 48)?;
                }
            }
        }
    }

    if total_entries > max_entries as u64 {
        return Err(DandiError::BudgetExceeded {
            reason: format!("ZIP declares {total_entries} entries, exceeding limit {max_entries}"),
        });
    }

    const MAX_CD_BYTES: u64 = 256 * 1024 * 1024;
    if cd_size > MAX_CD_BYTES {
        return Err(DandiError::CorruptArchive(format!(
            "Central Directory size {cd_size} exceeds safety cap"
        )));
    }

    let cd_end = cd_offset.checked_add(cd_size).ok_or_else(|| {
        DandiError::CorruptArchive("Central Directory offset overflow".to_string())
    })?;
    if cd_end > file_len {
        return Err(DandiError::CorruptArchive(
            "Central Directory extends past end of file (truncated ZIP)".to_string(),
        ));
    }

    reader.seek(SeekFrom::Start(cd_offset))?;
    let mut cd_buf = vec![0u8; cd_size as usize];
    reader.read_exact(&mut cd_buf)?;

    let mut headers = Vec::with_capacity((total_entries as usize).min(4096));
    let mut pos = 0usize;
    let mut index = 0usize;

    while pos < cd_buf.len() {
        if pos + 46 > cd_buf.len() {
            return Err(DandiError::CorruptArchive(
                "truncated Central Directory entry header".to_string(),
            ));
        }
        if read_u32_le(&cd_buf, pos)? != CDH_SIG {
            return Err(DandiError::CorruptArchive(
                "invalid Central Directory header signature".to_string(),
            ));
        }

        let version_made_by = read_u16_le(&cd_buf, pos + 4)?;
        let version_needed = read_u16_le(&cd_buf, pos + 6)?;
        let flags = read_u16_le(&cd_buf, pos + 8)?;
        let compression_method = read_u16_le(&cd_buf, pos + 10)?;
        let dos_time = read_u16_le(&cd_buf, pos + 12)?;
        let dos_date = read_u16_le(&cd_buf, pos + 14)?;
        let crc32 = read_u32_le(&cd_buf, pos + 16)?;
        let mut compressed_size = read_u32_le(&cd_buf, pos + 20)? as u64;
        let mut uncompressed_size = read_u32_le(&cd_buf, pos + 24)? as u64;
        let name_len = read_u16_le(&cd_buf, pos + 28)? as usize;
        let extra_len = read_u16_le(&cd_buf, pos + 30)? as usize;
        let comment_len = read_u16_le(&cd_buf, pos + 32)? as usize;
        let external_attrs = read_u32_le(&cd_buf, pos + 38)?;
        let mut local_header_offset = read_u32_le(&cd_buf, pos + 42)? as u64;

        let name_start = pos + 46;
        let extra_start = name_start + name_len;
        let comment_start = extra_start + extra_len;
        let next_pos = comment_start + comment_len;
        if next_pos > cd_buf.len() {
            return Err(DandiError::CorruptArchive(
                "Central Directory variable field out of bounds".to_string(),
            ));
        }

        let raw_name = cd_buf[name_start..extra_start].to_vec();
        let extra_data = cd_buf[extra_start..comment_start].to_vec();

        let has_zip64_extra = if let Some(z64_field) = find_extra_field(&extra_data, 0x0001) {
            let mut zpos = 0usize;
            if uncompressed_size == ZIP64_THRESHOLD_U32 && zpos + 8 <= z64_field.len() {
                uncompressed_size = read_u64_le(z64_field, zpos)?;
                zpos += 8;
            }
            if compressed_size == ZIP64_THRESHOLD_U32 && zpos + 8 <= z64_field.len() {
                compressed_size = read_u64_le(z64_field, zpos)?;
                zpos += 8;
            }
            if local_header_offset == ZIP64_THRESHOLD_U32 && zpos + 8 <= z64_field.len() {
                local_header_offset = read_u64_le(z64_field, zpos)?;
            }
            true
        } else {
            false
        };

        let has_0x7075 = find_extra_field(&extra_data, 0x7075).is_some();
        let mtime_5455 = parse_0x5455_mtime(&extra_data);
        let has_0x5455 = mtime_5455.is_some();
        let mtime_unix_secs = mtime_5455
            .or_else(|| parse_0x000a_mtime(&extra_data))
            .or_else(|| dos_to_unix_secs(dos_date, dos_time));

        headers.push(RawZipEntryHeader {
            index,
            version_made_by,
            version_needed,
            flags,
            compression_method,
            dos_time,
            dos_date,
            crc32,
            compressed_size,
            uncompressed_size,
            raw_name,
            extra_data,
            external_attrs,
            local_header_offset,
            has_0x7075,
            has_0x5455,
            has_zip64_extra,
            mtime_unix_secs,
        });

        pos = next_pos;
        index += 1;
        if index > max_entries {
            return Err(DandiError::BudgetExceeded {
                reason: format!("ZIP entry count exceeds limit {max_entries}"),
            });
        }
    }

    Ok(headers)
}

fn find_eocd(tail: &[u8]) -> Option<usize> {
    if tail.len() < 22 {
        return None;
    }
    let max_start = tail.len() - 22;
    for pos in (0..=max_start).rev() {
        if tail[pos..pos + 4] == EOCD_SIG.to_le_bytes() {
            let comment_len = u16::from_le_bytes([tail[pos + 20], tail[pos + 21]]) as usize;
            if pos + 22 + comment_len == tail.len() {
                return Some(pos);
            }
        }
    }
    None
}

fn find_extra_field(extra: &[u8], target_id: u16) -> Option<&[u8]> {
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[pos], extra[pos + 1]]);
        let len = u16::from_le_bytes([extra[pos + 2], extra[pos + 3]]) as usize;
        let data_start = pos + 4;
        let data_end = data_start + len;
        if data_end > extra.len() {
            break;
        }
        if id == target_id {
            return Some(&extra[data_start..data_end]);
        }
        pos = data_end;
    }
    None
}

fn parse_0x5455_mtime(extra: &[u8]) -> Option<i64> {
    let data = find_extra_field(extra, 0x5455)?;
    if data.len() >= 5 && (data[0] & 0x01) != 0 {
        let ts = i32::from_le_bytes([data[1], data[2], data[3], data[4]]) as i64;
        return Some(ts);
    }
    None
}

fn parse_0x000a_mtime(extra: &[u8]) -> Option<i64> {
    let data = find_extra_field(extra, 0x000a)?;
    if data.len() < 4 {
        return None;
    }
    let mut pos = 4; // skip 4-byte reserved field
    while pos + 4 <= data.len() {
        let tag = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let size = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
        let start = pos + 4;
        let end = start + size;
        if end > data.len() {
            break;
        }
        if tag == 0x0001 && size >= 8 {
            let ntfs_ticks = u64::from_le_bytes([
                data[start],
                data[start + 1],
                data[start + 2],
                data[start + 3],
                data[start + 4],
                data[start + 5],
                data[start + 6],
                data[start + 7],
            ]);
            // NTFS epoch is 1601-01-01; Unix epoch is 1970-01-01 = 11_644_473_600 seconds later.
            const NTFS_TO_UNIX_SECS: i64 = 11_644_473_600;
            let secs = (ntfs_ticks / 10_000_000) as i64 - NTFS_TO_UNIX_SECS;
            return Some(secs);
        }
        pos = end;
    }
    None
}

fn dos_to_unix_secs(dos_date: u16, dos_time: u16) -> Option<i64> {
    if dos_date == 0 && dos_time == 0 {
        return None;
    }
    let year = ((dos_date >> 9) & 0x7F) as i32 + 1980;
    let month_num = ((dos_date >> 5) & 0x0F) as u8;
    let day = (dos_date & 0x1F) as u8;
    let hour = ((dos_time >> 11) & 0x1F) as u8;
    let minute = ((dos_time >> 5) & 0x3F) as u8;
    let second = ((dos_time & 0x1F) * 2).min(59) as u8;

    let month = Month::try_from(month_num).ok()?;
    let date = Date::from_calendar_date(year, month, day).ok()?;
    let time = Time::from_hms(hour, minute, second).ok()?;
    let dt = PrimitiveDateTime::new(date, time).assume_utc();
    Some(dt.unix_timestamp())
}

fn unix_secs_to_dos(unix_secs: i64) -> (u16, u16) {
    let dt = OffsetDateTime::from_unix_timestamp(unix_secs).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let year = dt.year().clamp(1980, 2107);
    let month = u8::from(dt.month()) as u16;
    let day = dt.day() as u16;
    let hour = dt.hour() as u16;
    let minute = dt.minute() as u16;
    let second = dt.second() as u16;

    let dos_date = (((year - 1980) as u16) << 9) | (month << 5) | day;
    let dos_time = (hour << 11) | (minute << 5) | (second / 2);
    (dos_date, dos_time)
}

fn build_0x5455_extra(unix_secs: i64) -> [u8; 9] {
    let mut buf = [0u8; 9];
    buf[0..2].copy_from_slice(&0x5455u16.to_le_bytes());
    buf[2..4].copy_from_slice(&5u16.to_le_bytes());
    buf[4] = 0x01; // mtime present
    let ts = unix_secs.clamp(i32::MIN as i64, i32::MAX as i64) as i32;
    buf[5..9].copy_from_slice(&ts.to_le_bytes());
    buf
}

fn compression_method_name(method: u16) -> String {
    match method {
        0 => "store".to_string(),
        8 => "deflate".to_string(),
        9 => "deflate64".to_string(),
        12 => "bzip2".to_string(),
        14 => "lzma".to_string(),
        93 => "zstd".to_string(),
        98 => "ppmd".to_string(),
        99 => "aes".to_string(),
        other => format!("method_{other}"),
    }
}

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
struct PackItem {
    fs_path: PathBuf,
    archive_name: String,
    kind: EntryKind,
    size: u64,
    mtime_secs: i64,
    unix_mode: u32,
    symlink_target: Option<String>,
}

struct TempFileGuard {
    path: Option<PathBuf>,
}

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
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

fn create_sibling_temp_path(dest: &Path) -> PathBuf {
    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
    let pid = std::process::id();
    let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    parent.join(format!(".dandi-tmp-{pid}-{seq}-{nanos}.zip"))
}

fn commit_temp_file(tmp: &Path, dst: &Path, overwrite: bool) -> Result<()> {
    let fs_tmp = to_fs_path(tmp);
    let fs_dst = to_fs_path(dst);
    if fs_dst.exists() {
        if !overwrite {
            return Err(DandiError::InvalidInput(format!(
                "destination already exists: {}",
                dst.display()
            )));
        }
        #[cfg(windows)]
        {
            fs::remove_file(&fs_dst).map_err(|e| DandiError::io(dst, e))?;
        }
    }
    fs::rename(&fs_tmp, &fs_dst).map_err(|e| DandiError::io(dst, e))
}

fn collect_pack_items(inputs: &[PathBuf], opts: &PackOptions) -> Result<(Vec<PackItem>, usize)> {
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
    if to_fs_path(output_zip).exists() && !opts.overwrite {
        return Err(DandiError::InvalidInput(format!(
            "output archive already exists: {}",
            output_zip.display()
        )));
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

    let tmp_path = create_sibling_temp_path(output_zip);
    let mut guard = TempFileGuard::new(tmp_path.clone());

    let report = if let Some(ref password) = opts.password {
        pack_zip_encrypted(
            &items,
            &tmp_path,
            output_zip,
            password,
            opts,
            junk_skipped,
            total_input_bytes,
            observer,
        )?
    } else {
        pack_zip_golden_parallel(
            &items,
            &tmp_path,
            output_zip,
            opts,
            junk_skipped,
            total_input_bytes,
            observer,
        )?
    };

    commit_temp_file(&tmp_path, output_zip, opts.overwrite)?;
    guard.disarm();

    observer.on_progress(&ProgressEvent {
        phase: ProgressPhase::Finalizing,
        current_entry: output_zip.display().to_string(),
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
    local_header_offset: u64,
}

struct GoldenZipWriter {
    writer: BufWriter<File>,
    offset: u64,
    cd_records: Vec<WrittenCdRecord>,
    used_zip64: bool,
}

impl GoldenZipWriter {
    fn new(file: File) -> Self {
        Self {
            writer: BufWriter::with_capacity(STREAM_BUF_SIZE, file),
            offset: 0,
            cd_records: Vec::new(),
            used_zip64: false,
        }
    }

    fn write_all_tracked(&mut self, data: &[u8]) -> Result<()> {
        self.writer.write_all(data)?;
        self.offset = self
            .offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| DandiError::ArchiveEngine("ZIP offset overflow".to_string()))?;
        Ok(())
    }

    fn write_prepared(&mut self, entry: PreparedEntry) -> Result<()> {
        let name_bytes = entry.archive_name.into_bytes();
        let compressed_size = entry.payload.len() as u64;
        let uncompressed_size = entry.uncompressed_size;
        let local_header_offset = self.offset;

        let need_zip64_sizes =
            compressed_size >= ZIP64_THRESHOLD_U32 || uncompressed_size >= ZIP64_THRESHOLD_U32;
        let need_zip64_offset = local_header_offset >= ZIP64_THRESHOLD_U32;
        let version_needed = if need_zip64_sizes || need_zip64_offset {
            self.used_zip64 = true;
            45u16
        } else {
            20u16
        };

        let (dos_date, dos_time) = unix_secs_to_dos(entry.mtime_secs);
        let extra_5455 = build_0x5455_extra(entry.mtime_secs);

        let mut lfh_extra = Vec::with_capacity(9 + if need_zip64_sizes { 20 } else { 0 });
        if need_zip64_sizes {
            lfh_extra.extend_from_slice(&0x0001u16.to_le_bytes());
            lfh_extra.extend_from_slice(&16u16.to_le_bytes());
            lfh_extra.extend_from_slice(&uncompressed_size.to_le_bytes());
            lfh_extra.extend_from_slice(&compressed_size.to_le_bytes());
        }
        lfh_extra.extend_from_slice(&extra_5455);

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

        let mut lfh = [0u8; 30];
        lfh[0..4].copy_from_slice(&LFH_SIG.to_le_bytes());
        lfh[4..6].copy_from_slice(&version_needed.to_le_bytes());
        lfh[6..8].copy_from_slice(&BIT11_UTF8.to_le_bytes());
        lfh[8..10].copy_from_slice(&entry.method.to_le_bytes());
        lfh[10..12].copy_from_slice(&dos_time.to_le_bytes());
        lfh[12..14].copy_from_slice(&dos_date.to_le_bytes());
        lfh[14..18].copy_from_slice(&entry.crc32.to_le_bytes());
        lfh[18..22].copy_from_slice(&lfh_comp.to_le_bytes());
        lfh[22..26].copy_from_slice(&lfh_uncomp.to_le_bytes());
        lfh[26..28].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        lfh[28..30].copy_from_slice(&(lfh_extra.len() as u16).to_le_bytes());

        self.write_all_tracked(&lfh)?;
        self.write_all_tracked(&name_bytes)?;
        self.write_all_tracked(&lfh_extra)?;
        self.write_all_tracked(&entry.payload)?;

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
            local_header_offset,
        });

        Ok(())
    }

    /// Streams a large file (> 16 MiB) directly into the ZIP without buffering it in RAM.
    fn write_large_streamed(
        &mut self,
        item: &PackItem,
        compression_level: u32,
        cancel: &crate::progress::CancellationToken,
    ) -> Result<u16> {
        let store_only = compression_level == 0 || is_incompressible_extension(&item.archive_name);
        let method = if store_only {
            METHOD_STORE
        } else {
            METHOD_DEFLATE
        };
        let name_bytes = item.archive_name.as_bytes().to_vec();
        let local_header_offset = self.offset;
        let need_zip64_sizes = item.size >= ZIP64_THRESHOLD_U32;
        let need_zip64_offset = local_header_offset >= ZIP64_THRESHOLD_U32;
        let version_needed = if need_zip64_sizes || need_zip64_offset {
            self.used_zip64 = true;
            45u16
        } else {
            20u16
        };

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

        let mut lfh = [0u8; 30];
        lfh[0..4].copy_from_slice(&LFH_SIG.to_le_bytes());
        lfh[4..6].copy_from_slice(&version_needed.to_le_bytes());
        lfh[6..8].copy_from_slice(&BIT11_UTF8.to_le_bytes());
        lfh[8..10].copy_from_slice(&method.to_le_bytes());
        lfh[10..12].copy_from_slice(&dos_time.to_le_bytes());
        lfh[12..14].copy_from_slice(&dos_date.to_le_bytes());
        lfh[26..28].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        lfh[28..30].copy_from_slice(&(lfh_extra.len() as u16).to_le_bytes());

        self.write_all_tracked(&lfh)?;
        self.write_all_tracked(&name_bytes)?;
        let z64_field_offset = self.offset;
        self.write_all_tracked(&lfh_extra)?;
        let data_start_offset = self.offset;

        let mut src =
            File::open(to_fs_path(&item.fs_path)).map_err(|e| DandiError::io(&item.fs_path, e))?;
        let mut buf = vec![0u8; STREAM_BUF_SIZE];
        let mut crc_hasher = crc32fast::Hasher::new();
        let mut uncompressed_size = 0u64;

        let compressed_size = if method == METHOD_STORE {
            loop {
                cancel.check()?;
                let n = src
                    .read(&mut buf)
                    .map_err(|e| DandiError::io(&item.fs_path, e))?;
                if n == 0 {
                    break;
                }
                crc_hasher.update(&buf[..n]);
                uncompressed_size += n as u64;
                self.write_all_tracked(&buf[..n])?;
            }
            uncompressed_size
        } else {
            let mut enc =
                DeflateEncoder::new(&mut self.writer, Compression::new(compression_level));
            loop {
                cancel.check()?;
                let n = src
                    .read(&mut buf)
                    .map_err(|e| DandiError::io(&item.fs_path, e))?;
                if n == 0 {
                    break;
                }
                crc_hasher.update(&buf[..n]);
                uncompressed_size += n as u64;
                enc.write_all(&buf[..n])?;
            }
            enc.finish()?;
            self.writer.flush()?;
            let end_pos = self.writer.stream_position()?;
            self.offset = end_pos;
            end_pos - data_start_offset
        };

        let crc32 = crc_hasher.finalize();
        let end_offset = self.offset;

        // Patch CRC32 and sizes directly into the Local File Header.
        self.writer.flush()?;
        let inner = self.writer.get_mut();
        inner.seek(SeekFrom::Start(local_header_offset + 14))?;
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
        inner.write_all(&crc32.to_le_bytes())?;
        inner.write_all(&lfh_comp.to_le_bytes())?;
        inner.write_all(&lfh_uncomp.to_le_bytes())?;
        if need_zip64_sizes {
            inner.seek(SeekFrom::Start(z64_field_offset + 4))?;
            inner.write_all(&uncompressed_size.to_le_bytes())?;
            inner.write_all(&compressed_size.to_le_bytes())?;
        }
        inner.seek(SeekFrom::Start(end_offset))?;

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
            local_header_offset,
        });

        Ok(method)
    }

    fn finish(mut self) -> Result<(u64, bool)> {
        let cd_start = self.offset;
        let entry_count = self.cd_records.len();

        let records = std::mem::take(&mut self.cd_records);
        for rec in records {
            let need_z64_uncomp = rec.uncompressed_size >= ZIP64_THRESHOLD_U32;
            let need_z64_comp = rec.compressed_size >= ZIP64_THRESHOLD_U32;
            let need_z64_off = rec.local_header_offset >= ZIP64_THRESHOLD_U32;
            let need_z64 = need_z64_uncomp || need_z64_comp || need_z64_off;
            if need_z64 {
                self.used_zip64 = true;
            }

            let mut cd_extra = Vec::with_capacity(37);
            if need_z64 {
                let mut z64_payload = Vec::with_capacity(24);
                if need_z64_uncomp {
                    z64_payload.extend_from_slice(&rec.uncompressed_size.to_le_bytes());
                }
                if need_z64_comp {
                    z64_payload.extend_from_slice(&rec.compressed_size.to_le_bytes());
                }
                if need_z64_off {
                    z64_payload.extend_from_slice(&rec.local_header_offset.to_le_bytes());
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
            let cd_off = if need_z64_off {
                0xFFFF_FFFFu32
            } else {
                rec.local_header_offset as u32
            };

            let mut cdh = [0u8; 46];
            cdh[0..4].copy_from_slice(&CDH_SIG.to_le_bytes());
            cdh[4..6].copy_from_slice(&version_made_by.to_le_bytes());
            cdh[6..8].copy_from_slice(&version_needed.to_le_bytes());
            cdh[8..10].copy_from_slice(&rec.flags.to_le_bytes());
            cdh[10..12].copy_from_slice(&rec.method.to_le_bytes());
            cdh[12..14].copy_from_slice(&rec.dos_time.to_le_bytes());
            cdh[14..16].copy_from_slice(&rec.dos_date.to_le_bytes());
            cdh[16..20].copy_from_slice(&rec.crc32.to_le_bytes());
            cdh[20..24].copy_from_slice(&cd_comp.to_le_bytes());
            cdh[24..28].copy_from_slice(&cd_uncomp.to_le_bytes());
            cdh[28..30].copy_from_slice(&(rec.name_bytes.len() as u16).to_le_bytes());
            cdh[30..32].copy_from_slice(&(cd_extra.len() as u16).to_le_bytes());
            cdh[38..42].copy_from_slice(&rec.external_attrs.to_le_bytes());
            cdh[42..46].copy_from_slice(&cd_off.to_le_bytes());

            self.write_all_tracked(&cdh)?;
            self.write_all_tracked(&rec.name_bytes)?;
            self.write_all_tracked(&cd_extra)?;
        }

        let cd_size = self.offset - cd_start;
        let need_zip64_eocd = entry_count >= ZIP64_THRESHOLD_ENTRIES
            || cd_size >= ZIP64_THRESHOLD_U32
            || cd_start >= ZIP64_THRESHOLD_U32;

        if need_zip64_eocd {
            self.used_zip64 = true;
            let z64_eocd_offset = self.offset;
            let mut z64_eocd = [0u8; 56];
            z64_eocd[0..4].copy_from_slice(&ZIP64_EOCD_SIG.to_le_bytes());
            z64_eocd[4..12].copy_from_slice(&44u64.to_le_bytes());
            z64_eocd[12..14].copy_from_slice(&(VERSION_MADE_BY_UNIX | 45).to_le_bytes());
            z64_eocd[14..16].copy_from_slice(&45u16.to_le_bytes());
            z64_eocd[24..32].copy_from_slice(&(entry_count as u64).to_le_bytes());
            z64_eocd[32..40].copy_from_slice(&(entry_count as u64).to_le_bytes());
            z64_eocd[40..48].copy_from_slice(&cd_size.to_le_bytes());
            z64_eocd[48..56].copy_from_slice(&cd_start.to_le_bytes());
            self.write_all_tracked(&z64_eocd)?;

            let mut z64_loc = [0u8; 20];
            z64_loc[0..4].copy_from_slice(&ZIP64_LOCATOR_SIG.to_le_bytes());
            z64_loc[8..16].copy_from_slice(&z64_eocd_offset.to_le_bytes());
            z64_loc[16..20].copy_from_slice(&1u32.to_le_bytes());
            self.write_all_tracked(&z64_loc)?;
        }

        let eocd_entries = if entry_count >= ZIP64_THRESHOLD_ENTRIES {
            0xFFFFu16
        } else {
            entry_count as u16
        };
        let eocd_cd_size = if cd_size >= ZIP64_THRESHOLD_U32 {
            0xFFFF_FFFFu32
        } else {
            cd_size as u32
        };
        let eocd_cd_offset = if cd_start >= ZIP64_THRESHOLD_U32 {
            0xFFFF_FFFFu32
        } else {
            cd_start as u32
        };

        let mut eocd = [0u8; 22];
        eocd[0..4].copy_from_slice(&EOCD_SIG.to_le_bytes());
        eocd[8..10].copy_from_slice(&eocd_entries.to_le_bytes());
        eocd[10..12].copy_from_slice(&eocd_entries.to_le_bytes());
        eocd[12..16].copy_from_slice(&eocd_cd_size.to_le_bytes());
        eocd[16..20].copy_from_slice(&eocd_cd_offset.to_le_bytes());
        self.write_all_tracked(&eocd)?;

        self.writer.flush()?;
        Ok((self.offset, self.used_zip64))
    }
}

fn pack_zip_golden_parallel(
    items: &[PackItem],
    tmp_path: &Path,
    output_zip: &Path,
    opts: &PackOptions,
    junk_skipped: usize,
    total_input_bytes: u64,
    observer: &dyn ProgressObserver,
) -> Result<PackReport> {
    let tmp_file = File::create(to_fs_path(tmp_path)).map_err(|e| DandiError::io(tmp_path, e))?;
    let mut writer = GoldenZipWriter::new(tmp_file);

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

    let (output_bytes, used_zip64) = writer.finish()?;

    Ok(PackReport {
        output_path: output_zip.to_path_buf(),
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
fn pack_zip_encrypted(
    items: &[PackItem],
    tmp_path: &Path,
    output_zip: &Path,
    password: &str,
    opts: &PackOptions,
    junk_skipped: usize,
    total_input_bytes: u64,
    observer: &dyn ProgressObserver,
) -> Result<PackReport> {
    let pw_nfc: String = password.nfc().collect();
    let tmp_file = File::create(to_fs_path(tmp_path)).map_err(|e| DandiError::io(tmp_path, e))?;
    let mut zw = ZipWriter::new(BufWriter::with_capacity(STREAM_BUF_SIZE, tmp_file));

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
                let fopts = SimpleFileOptions::default()
                    .compression_method(method)
                    .compression_level(Some(opts.compression_level.min(9) as i64))
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

    Ok(PackReport {
        output_path: output_zip.to_path_buf(),
        entries_written: items.len(),
        files_deflated,
        files_stored,
        junk_skipped,
        total_input_bytes,
        output_bytes,
        used_zip64: output_bytes >= ZIP64_THRESHOLD_U32 || items.len() >= ZIP64_THRESHOLD_ENTRIES,
        encrypted: true,
    })
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

    // Decode all entry names & build plan before touching disk.
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

        // Validate every entry path and budget up front before writing anything to disk.
        budget.record_entry(h.uncompressed_size, h.compressed_size)?;
        let sanitized = sanitize_entry_path(&decoded.path, opts.path_policy)?;
        visible_for_smart.push((sanitized.normalized, kind));

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

    fs::create_dir_all(to_fs_path(&plan.extract_root))
        .map_err(|e| DandiError::io(&plan.extract_root, e))?;
    let mut dir_guard = DirCleanupGuard::new(plan.cleanup_root.clone());

    raw_file.seek(SeekFrom::Start(0))?;
    let mut archive = ZipArchive::new(BufReader::with_capacity(STREAM_BUF_SIZE, raw_file))
        .map_err(map_zip_error)?;

    let mut collisions = CollisionTracker::new();
    let mut sanitized_paths = 0usize;
    let mut files_extracted = 0usize;
    let mut dirs_created = 0usize;
    let mut symlinks_created = 0usize;
    let mut bytes_total_planned: u64 = planned.iter().map(|e| e.uncompressed_size).sum();
    if bytes_total_planned == 0 {
        bytes_total_planned = 1;
    }

    // Track archive-declared symlinks and defer creation until phase 2.
    struct PendingSymlink {
        link_rel: PathBuf,
        target: String,
        mtime: Option<i64>,
    }
    let mut pending_symlinks: Vec<PendingSymlink> = Vec::new();
    let mut symlink_paths_lower: HashSet<String> = HashSet::new();

    // Pre-pass: read & validate all symlink entries BEFORE creating any regular files,
    // blocking absolute targets, root escapes, symlink-ancestor writes, and multi-hop chaining.
    let mut prevalidated_symlinks: Vec<(PathBuf, String)> = Vec::new();
    for entry in &planned {
        if entry.kind != EntryKind::Symlink {
            continue;
        }
        opts.cancel.check()?;
        let sanitized = sanitize_entry_path(&entry.decoded_path, opts.path_policy)?;
        let stripped = strip_root_prefix(&sanitized.normalized, plan.strip_prefix.as_deref());
        let final_sanitized = sanitize_entry_path(&stripped, opts.path_policy)?;
        let zf = open_zip_entry(
            &mut archive,
            entry.index,
            entry.encrypted,
            opts.password.as_deref(),
        )?;
        let mut target_bytes = Vec::new();
        zf.take(8192).read_to_end(&mut target_bytes)?;
        let target = String::from_utf8(target_bytes).map_err(|_| DandiError::UnsafeSymlink {
            path: final_sanitized.normalized.clone(),
            target: "<non-utf8>".to_string(),
            reason: "symlink target is not valid UTF-8".to_string(),
        })?;
        validate_symlink_target(&plan.extract_root, &final_sanitized.relative, &target)?;
        symlink_paths_lower.insert(final_sanitized.normalized.to_lowercase());
        prevalidated_symlinks.push((final_sanitized.relative, target));
    }
    for (link_rel, target) in &prevalidated_symlinks {
        check_symlink_chain_safe(link_rel, target, &symlink_paths_lower)?;
    }

    let mut read_buf = vec![0u8; STREAM_BUF_SIZE];
    let mut deferred_dir_mtimes: Vec<(PathBuf, i64, Option<u32>)> = Vec::new();

    for (done_idx, entry) in planned.iter().enumerate() {
        opts.cancel.check()?;
        let sanitized = sanitize_entry_path(&entry.decoded_path, opts.path_policy)?;
        if sanitized.was_sanitized {
            sanitized_paths += 1;
        }
        let effective_str = strip_root_prefix(&sanitized.normalized, plan.strip_prefix.as_deref());
        if effective_str.is_empty() {
            continue;
        }
        let eff_sanitized = sanitize_entry_path(&effective_str, opts.path_policy)?;

        match entry.kind {
            EntryKind::Directory => {
                check_not_through_archive_symlink(&eff_sanitized.normalized, &symlink_paths_lower)?;
                collisions.register_dir(&eff_sanitized.normalized);
                let out_path = plan.extract_root.join(&eff_sanitized.relative);
                ensure_no_symlink_ancestors(&plan.extract_root, &eff_sanitized.relative)?;
                fs::create_dir_all(to_fs_path(&out_path))
                    .map_err(|e| DandiError::io(&out_path, e))?;
                dirs_created += 1;
                if let Some(ts) = entry.mtime_unix_secs {
                    deferred_dir_mtimes.push((out_path, ts, entry.unix_mode));
                } else if let Some(mode) = entry.unix_mode {
                    let _ = apply_unix_mode(&out_path, mode, true);
                }
            }
            EntryKind::Symlink => {
                let zf = open_zip_entry(
                    &mut archive,
                    entry.index,
                    entry.encrypted,
                    opts.password.as_deref(),
                )?;
                let mut target_bytes = Vec::new();
                zf.take(8192).read_to_end(&mut target_bytes)?;
                let target =
                    String::from_utf8(target_bytes).map_err(|_| DandiError::UnsafeSymlink {
                        path: eff_sanitized.normalized.clone(),
                        target: "<non-utf8>".to_string(),
                        reason: "symlink target is not valid UTF-8".to_string(),
                    })?;
                let resolved_rel = collisions.resolve_file(&eff_sanitized);
                validate_symlink_target(&plan.extract_root, &resolved_rel, &target)?;
                pending_symlinks.push(PendingSymlink {
                    link_rel: resolved_rel,
                    target,
                    mtime: entry.mtime_unix_secs,
                });
            }
            EntryKind::File => {
                check_not_through_archive_symlink(&eff_sanitized.normalized, &symlink_paths_lower)?;
                let resolved_rel = collisions.resolve_file(&eff_sanitized);
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

                let mut zf = open_zip_entry(
                    &mut archive,
                    entry.index,
                    entry.encrypted,
                    opts.password.as_deref(),
                )?;
                budget.note_live_entry_compressed(entry.compressed_size);

                let fs_out = to_fs_path(&out_path);
                let out_file = File::create(&fs_out).map_err(|e| DandiError::io(&out_path, e))?;
                let mut writer = BufWriter::with_capacity(STREAM_BUF_SIZE, out_file);
                let mut entry_written = 0u64;

                loop {
                    opts.cancel.check()?;
                    let n = match zf.read(&mut read_buf) {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(e) => {
                            let _ = fs::remove_file(&fs_out);
                            return Err(classify_zip_read_io_error(e));
                        }
                    };
                    entry_written = entry_written.saturating_add(n as u64);
                    budget.record_written_bytes(n as u64, entry_written, entry.compressed_size)?;
                    writer.write_all(&read_buf[..n])?;
                }
                writer.flush()?;
                drop(writer);

                if let Some(mode) = entry.unix_mode {
                    let _ = apply_unix_mode(&out_path, mode, false);
                }
                if let Some(ts) = entry.mtime_unix_secs {
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
            current_entry: eff_sanitized.normalized,
            entries_done: done_idx + 1,
            entries_total: planned.len(),
            bytes_done: budget.bytes_written(),
            bytes_total: bytes_total_planned,
        });
    }

    // Phase 2: materialize validated safe relative symlinks.
    for sym in pending_symlinks {
        opts.cancel.check()?;
        check_symlink_chain_safe(&sym.link_rel, &sym.target, &symlink_paths_lower)?;
        ensure_no_symlink_ancestors(&plan.extract_root, &sym.link_rel)?;
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

    // Apply directory permissions and mtimes bottom-up so child writes don't clobber parent mtimes.
    for (dir_path, ts, mode) in deferred_dir_mtimes.into_iter().rev() {
        let _ = set_mtime(&dir_path, ts, false);
        if let Some(m) = mode {
            let _ = apply_unix_mode(&dir_path, m, true);
        }
    }

    dir_guard.disarm();

    observer.on_progress(&ProgressEvent {
        phase: ProgressPhase::Finalizing,
        current_entry: plan.reported_output_dir.display().to_string(),
        entries_done: planned.len(),
        entries_total: planned.len(),
        bytes_done: budget.bytes_written(),
        bytes_total: bytes_total_planned,
    });

    Ok(UnpackReport {
        format: ArchiveFormat::Zip,
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

fn strip_root_prefix(normalized: &str, prefix: Option<&str>) -> String {
    match prefix {
        Some(p) => {
            if normalized == p {
                String::new()
            } else if let Some(rest) = normalized.strip_prefix(&format!("{p}/")) {
                rest.to_string()
            } else {
                normalized.to_string()
            }
        }
        None => normalized.to_string(),
    }
}

fn open_zip_entry<'a, R: Read + Seek>(
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

fn map_zip_error(err: zip::result::ZipError) -> DandiError {
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

fn classify_zip_read_io_error(err: io::Error) -> DandiError {
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

pub(crate) fn repack_zip_nfc(
    src_zip: &Path,
    dst_zip: &Path,
    opts: &RepackOptions,
    observer: &dyn ProgressObserver,
) -> Result<RepackReport> {
    opts.cancel.check()?;
    if to_fs_path(dst_zip).exists() && !opts.overwrite {
        return Err(DandiError::InvalidInput(format!(
            "destination already exists: {}",
            dst_zip.display()
        )));
    }
    if let Some(parent) = dst_zip.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(to_fs_path(parent)).map_err(|e| DandiError::io(parent, e))?;
        }
    }

    let fs_src = to_fs_path(src_zip);
    let src_file_size = fs::metadata(&fs_src).map(|m| m.len()).unwrap_or(1).max(1);
    let mut raw_file = File::open(&fs_src).map_err(|e| DandiError::io(src_zip, e))?;
    let raw_headers = read_zip_raw_entries(&mut raw_file, opts.budget.max_entries)?;

    let non_bit11: Vec<&[u8]> = raw_headers
        .iter()
        .filter(|h| !h.utf8_bit11() && !h.has_valid_0x7075())
        .map(|h| h.raw_name.as_slice())
        .collect();
    let detection = detect_archive_encoding(&non_bit11, opts.locale_hint);
    let source_encoding = opts.encoding_override.unwrap_or(detection.encoding);
    let explicit_override = opts.encoding_override.is_some();

    raw_file.seek(SeekFrom::Start(0))?;
    let mut archive = ZipArchive::new(BufReader::with_capacity(STREAM_BUF_SIZE, raw_file))
        .map_err(map_zip_error)?;

    let tmp_path = create_sibling_temp_path(dst_zip);
    let mut guard = TempFileGuard::new(tmp_path.clone());
    let tmp_file = File::create(to_fs_path(&tmp_path)).map_err(|e| DandiError::io(&tmp_path, e))?;
    let mut writer = GoldenZipWriter::new(tmp_file);

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

    let (output_bytes, _) = writer.finish()?;
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

fn read_u16_le(buf: &[u8], offset: usize) -> Result<u16> {
    let slice = buf
        .get(offset..offset + 2)
        .ok_or_else(|| DandiError::CorruptArchive("unexpected EOF reading u16".to_string()))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(buf: &[u8], offset: usize) -> Result<u32> {
    let slice = buf
        .get(offset..offset + 4)
        .ok_or_else(|| DandiError::CorruptArchive("unexpected EOF reading u32".to_string()))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64_le(buf: &[u8], offset: usize) -> Result<u64> {
    let slice = buf
        .get(offset..offset + 8)
        .ok_or_else(|| DandiError::CorruptArchive("unexpected EOF reading u64".to_string()))?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}
