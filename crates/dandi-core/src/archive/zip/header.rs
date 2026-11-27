use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;

use serde::{Deserialize, Serialize};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

use crate::codec::verify_0x7075;
use crate::error::{DandiError, Result};
use crate::platform::to_fs_path;
use crate::safety::SafetyBudget;

pub(crate) const LFH_SIG: u32 = 0x0403_4b50;
pub(crate) const CDH_SIG: u32 = 0x0201_4b50;
pub(crate) const EOCD_SIG: u32 = 0x0605_4b50;
pub(crate) const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;
pub(crate) const ZIP64_LOCATOR_SIG: u32 = 0x0706_4b50;

pub(crate) const BIT11_UTF8: u16 = 0x0800;
pub(crate) const BIT0_ENCRYPTED: u16 = 0x0001;
pub(crate) const VERSION_MADE_BY_UNIX: u16 = 3 << 8;

pub(crate) const METHOD_STORE: u16 = 0;
pub(crate) const METHOD_DEFLATE: u16 = 8;

pub(crate) const ZIP64_THRESHOLD_U32: u64 = 0xFFFF_FFFF;
pub(crate) const ZIP64_THRESHOLD_ENTRIES: usize = 0xFFFF;

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

/// Parses raw Central Directory headers directly from an in-memory byte slice with strict bounds
/// checking and entry-count caps.
pub fn parse_zip_raw_headers_from_bytes(
    bytes: &[u8],
    max_entries: usize,
) -> Result<Vec<RawZipEntryHeader>> {
    let mut cursor = Cursor::new(bytes);
    read_zip_raw_entries(&mut cursor, max_entries)
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
    let eocd_offset = search_start
        .checked_add(eocd_rel as u64)
        .ok_or_else(|| DandiError::CorruptArchive("EOCD offset overflow".to_string()))?;
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

    let cd_size_usize = usize::try_from(cd_size)
        .map_err(|_| DandiError::CorruptArchive("Central Directory size overflow".to_string()))?;
    reader.seek(SeekFrom::Start(cd_offset))?;
    let mut cd_buf = vec![0u8; cd_size_usize];
    reader.read_exact(&mut cd_buf)?;

    let cap_hint = usize::try_from(total_entries).unwrap_or(4096).min(4096);
    let mut headers = Vec::with_capacity(cap_hint);
    let mut pos = 0usize;
    let mut index = 0usize;

    while pos < cd_buf.len() {
        let header_end = pos.checked_add(46).ok_or_else(|| {
            DandiError::CorruptArchive("Central Directory offset overflow".to_string())
        })?;
        if header_end > cd_buf.len() {
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

        let name_start = header_end;
        let extra_start = name_start.checked_add(name_len).ok_or_else(|| {
            DandiError::CorruptArchive("Central Directory name length overflow".to_string())
        })?;
        let comment_start = extra_start.checked_add(extra_len).ok_or_else(|| {
            DandiError::CorruptArchive("Central Directory extra length overflow".to_string())
        })?;
        let next_pos = comment_start.checked_add(comment_len).ok_or_else(|| {
            DandiError::CorruptArchive("Central Directory comment length overflow".to_string())
        })?;
        if next_pos > cd_buf.len() {
            return Err(DandiError::CorruptArchive(
                "Central Directory variable field out of bounds".to_string(),
            ));
        }

        let raw_name = cd_buf[name_start..extra_start].to_vec();
        let extra_data = cd_buf[extra_start..comment_start].to_vec();

        let has_zip64_extra = if let Some(z64_field) = find_extra_field(&extra_data, 0x0001) {
            let mut zpos = 0usize;
            if uncompressed_size == ZIP64_THRESHOLD_U32
                && zpos.checked_add(8).is_some_and(|e| e <= z64_field.len())
            {
                uncompressed_size = read_u64_le(z64_field, zpos)?;
                zpos += 8;
            }
            if compressed_size == ZIP64_THRESHOLD_U32
                && zpos.checked_add(8).is_some_and(|e| e <= z64_field.len())
            {
                compressed_size = read_u64_le(z64_field, zpos)?;
                zpos += 8;
            }
            if local_header_offset == ZIP64_THRESHOLD_U32
                && zpos.checked_add(8).is_some_and(|e| e <= z64_field.len())
            {
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
        index = index
            .checked_add(1)
            .ok_or_else(|| DandiError::BudgetExceeded {
                reason: "ZIP entry index overflow".to_string(),
            })?;
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
            if pos.checked_add(22).and_then(|v| v.checked_add(comment_len)) == Some(tail.len()) {
                return Some(pos);
            }
        }
    }
    None
}

pub(crate) fn find_extra_field(extra: &[u8], target_id: u16) -> Option<&[u8]> {
    let mut pos = 0usize;
    while let Some(data_start) = pos.checked_add(4) {
        if data_start > extra.len() {
            break;
        }
        let id = u16::from_le_bytes([extra[pos], extra[pos + 1]]);
        let len = u16::from_le_bytes([extra[pos + 2], extra[pos + 3]]) as usize;
        let Some(data_end) = data_start.checked_add(len) else {
            break;
        };
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
    let mut pos = 4usize; // skip 4-byte reserved field
    while let Some(start) = pos.checked_add(4) {
        if start > data.len() {
            break;
        }
        let tag = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let size = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
        let Some(end) = start.checked_add(size) else {
            break;
        };
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
            let secs = i64::try_from(ntfs_ticks / 10_000_000)
                .ok()?
                .checked_sub(NTFS_TO_UNIX_SECS)?;
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

pub(crate) fn unix_secs_to_dos(unix_secs: i64) -> (u16, u16) {
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

pub(crate) fn build_0x5455_extra(unix_secs: i64) -> [u8; 9] {
    let mut buf = [0u8; 9];
    buf[0..2].copy_from_slice(&0x5455u16.to_le_bytes());
    buf[2..4].copy_from_slice(&5u16.to_le_bytes());
    buf[4] = 0x01; // mtime present
    let ts = unix_secs.clamp(i32::MIN as i64, i32::MAX as i64) as i32;
    buf[5..9].copy_from_slice(&ts.to_le_bytes());
    buf
}

pub(crate) fn compression_method_name(method: u16) -> String {
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

fn read_u16_le(buf: &[u8], offset: usize) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| DandiError::CorruptArchive("offset overflow reading u16".to_string()))?;
    let slice = buf
        .get(offset..end)
        .ok_or_else(|| DandiError::CorruptArchive("unexpected EOF reading u16".to_string()))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(buf: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| DandiError::CorruptArchive("offset overflow reading u32".to_string()))?;
    let slice = buf
        .get(offset..end)
        .ok_or_else(|| DandiError::CorruptArchive("unexpected EOF reading u32".to_string()))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64_le(buf: &[u8], offset: usize) -> Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| DandiError::CorruptArchive("offset overflow reading u64".to_string()))?;
    let slice = buf
        .get(offset..end)
        .ok_or_else(|| DandiError::CorruptArchive("unexpected EOF reading u64".to_string()))?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}
