use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;

use serde::{Deserialize, Serialize};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

use crate::archive::split::{discover_volumes, SplitFileReader, VolumeKind};
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
pub(crate) const ZIP64_THRESHOLD_DISK: u32 = 0xFFFF;

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
    pub disk_number_start: u32,
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

/// Parsed Central Directory plus raw CD bytes and disk geometry for split-archive normalization.
pub(crate) struct ParsedZipDirectory {
    pub headers: Vec<RawZipEntryHeader>,
    pub raw_cd_bytes: Vec<u8>,
    pub cd_global_offset: u64,
    pub number_of_this_disk: u32,
    pub disk_with_central_dir: u32,
}

/// Inspects raw Central Directory headers of a ZIP file (single or split) without decoding names.
pub fn inspect_zip_raw_headers(path: &Path) -> Result<Vec<RawZipEntryHeader>> {
    let vol_set = discover_volumes(path)?;
    match vol_set.kind {
        VolumeKind::Single => {
            let fs_path = to_fs_path(path);
            let mut file = File::open(&fs_path).map_err(|e| DandiError::io(path, e))?;
            read_zip_raw_entries(&mut file, SafetyBudget::default().max_entries)
        }
        VolumeKind::Numeric => {
            let mut split = SplitFileReader::open(&vol_set.volumes)?;
            read_zip_raw_entries(&mut split, SafetyBudget::default().max_entries)
        }
        VolumeKind::PkwareZip => {
            let mut split = SplitFileReader::open(&vol_set.volumes)?;
            let parsed =
                read_pkware_split_directory(&mut split, SafetyBudget::default().max_entries)?;
            Ok(parsed.headers)
        }
    }
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
    let parsed = read_single_disk_directory(reader, max_entries)?;
    Ok(parsed.headers)
}

pub(crate) fn read_single_disk_directory<R: Read + Seek>(
    reader: &mut R,
    max_entries: usize,
) -> Result<ParsedZipDirectory> {
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

    let mut number_of_this_disk = read_u16_le(eocd, 4)? as u32;
    let mut disk_with_central_dir = read_u16_le(eocd, 6)? as u32;
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
                    number_of_this_disk = read_u32_le(&z64, 16)?;
                    disk_with_central_dir = read_u32_le(&z64, 20)?;
                    total_entries = read_u64_le(&z64, 32)?;
                    cd_size = read_u64_le(&z64, 40)?;
                    cd_offset = read_u64_le(&z64, 48)?;
                }
            }
        }
    }

    let cd_buf = read_cd_buffer(
        reader,
        cd_offset,
        cd_size,
        file_len,
        total_entries,
        max_entries,
    )?;
    let headers = parse_cd_records(&cd_buf, total_entries, max_entries)?;
    Ok(ParsedZipDirectory {
        headers,
        raw_cd_bytes: cd_buf,
        cd_global_offset: cd_offset,
        number_of_this_disk,
        disk_with_central_dir,
    })
}

/// Parses Central Directory records from a PKWARE multi-disk split ZIP opened in `SplitFileReader`.
pub(crate) fn read_pkware_split_directory(
    reader: &mut SplitFileReader,
    max_entries: usize,
) -> Result<ParsedZipDirectory> {
    let vol_count = reader.volume_count();
    if vol_count == 0 {
        return Err(DandiError::CorruptArchive(
            "split ZIP has no volumes".to_string(),
        ));
    }
    let last_disk_idx = vol_count - 1;
    let last_disk_start = reader
        .volume_start_offset(last_disk_idx)
        .ok_or_else(|| DandiError::CorruptArchive("missing final split disk".to_string()))?;
    let last_disk_len = reader
        .volume_len(last_disk_idx)
        .ok_or_else(|| DandiError::CorruptArchive("missing final split disk length".to_string()))?;
    if last_disk_len < 22 {
        return Err(DandiError::CorruptArchive(
            "final split ZIP volume is too small to contain EOCD".to_string(),
        ));
    }

    let search_len = last_disk_len.min(65_535 + 22) as usize;
    let search_start_in_disk = last_disk_len - (search_len as u64);
    let search_global = last_disk_start
        .checked_add(search_start_in_disk)
        .ok_or_else(|| DandiError::CorruptArchive("split EOCD offset overflow".to_string()))?;
    reader.seek(SeekFrom::Start(search_global))?;
    let mut tail = vec![0u8; search_len];
    reader.read_exact(&mut tail)?;

    let eocd_rel = find_eocd(&tail).ok_or_else(|| {
        DandiError::CorruptArchive(
            "End of Central Directory record not found in final split volume".to_string(),
        )
    })?;
    let eocd_offset_in_disk = search_start_in_disk
        .checked_add(eocd_rel as u64)
        .ok_or_else(|| DandiError::CorruptArchive("EOCD offset overflow".to_string()))?;
    let eocd = &tail[eocd_rel..];

    let mut number_of_this_disk = read_u16_le(eocd, 4)? as u32;
    let mut disk_with_central_dir = read_u16_le(eocd, 6)? as u32;
    let mut total_entries = read_u16_le(eocd, 10)? as u64;
    let mut cd_size = read_u32_le(eocd, 12)? as u64;
    let mut cd_offset_in_disk = read_u32_le(eocd, 16)? as u64;

    // Check ZIP64 EOCD Locator immediately before EOCD.
    let eocd_global = last_disk_start
        .checked_add(eocd_offset_in_disk)
        .ok_or_else(|| DandiError::CorruptArchive("EOCD global offset overflow".to_string()))?;
    if eocd_global >= 20 {
        let mut loc = [0u8; 20];
        reader.seek(SeekFrom::Start(eocd_global - 20))?;
        reader.read_exact(&mut loc)?;
        if read_u32_le(&loc, 0)? == ZIP64_LOCATOR_SIG {
            let z64_disk = read_u32_le(&loc, 4)?;
            let z64_offset_in_disk = read_u64_le(&loc, 8)?;
            if let Some(z64_disk_start) = reader.volume_start_offset(z64_disk as usize) {
                if let Some(z64_global) = z64_disk_start.checked_add(z64_offset_in_disk) {
                    if z64_global
                        .checked_add(56)
                        .is_some_and(|end| end <= reader.total_len())
                    {
                        let mut z64 = [0u8; 56];
                        reader.seek(SeekFrom::Start(z64_global))?;
                        reader.read_exact(&mut z64)?;
                        if read_u32_le(&z64, 0)? == ZIP64_EOCD_SIG {
                            number_of_this_disk = read_u32_le(&z64, 16)?;
                            disk_with_central_dir = read_u32_le(&z64, 20)?;
                            total_entries = read_u64_le(&z64, 32)?;
                            cd_size = read_u64_le(&z64, 40)?;
                            cd_offset_in_disk = read_u64_le(&z64, 48)?;
                        }
                    }
                }
            }
        }
    }

    if number_of_this_disk as usize != last_disk_idx {
        return Err(DandiError::CorruptArchive(format!(
            "split ZIP EOCD declares disk {} but {} volume(s) were opened",
            number_of_this_disk + 1,
            vol_count
        )));
    }
    let cd_disk_start = reader
        .volume_start_offset(disk_with_central_dir as usize)
        .ok_or_else(|| {
            DandiError::CorruptArchive(format!(
                "Central Directory disk index {} is out of range ({} volumes)",
                disk_with_central_dir, vol_count
            ))
        })?;
    let cd_global_offset = cd_disk_start
        .checked_add(cd_offset_in_disk)
        .ok_or_else(|| {
            DandiError::CorruptArchive("Central Directory offset overflow".to_string())
        })?;

    let total_len = reader.total_len();
    let cd_buf = read_cd_buffer(
        reader,
        cd_global_offset,
        cd_size,
        total_len,
        total_entries,
        max_entries,
    )?;
    let headers = parse_cd_records(&cd_buf, total_entries, max_entries)?;

    for h in &headers {
        if (h.disk_number_start as usize) >= vol_count {
            return Err(DandiError::CorruptArchive(format!(
                "split ZIP entry {} references missing disk {}",
                h.index, h.disk_number_start
            )));
        }
    }

    Ok(ParsedZipDirectory {
        headers,
        raw_cd_bytes: cd_buf,
        cd_global_offset,
        number_of_this_disk,
        disk_with_central_dir,
    })
}

fn read_cd_buffer<R: Read + Seek>(
    reader: &mut R,
    cd_offset: u64,
    cd_size: u64,
    total_len: u64,
    total_entries: u64,
    max_entries: usize,
) -> Result<Vec<u8>> {
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
    if cd_end > total_len {
        return Err(DandiError::CorruptArchive(
            "Central Directory extends past end of file (truncated ZIP)".to_string(),
        ));
    }

    let cd_size_usize = usize::try_from(cd_size)
        .map_err(|_| DandiError::CorruptArchive("Central Directory size overflow".to_string()))?;
    reader.seek(SeekFrom::Start(cd_offset))?;
    let mut cd_buf = vec![0u8; cd_size_usize];
    reader.read_exact(&mut cd_buf)?;
    Ok(cd_buf)
}

fn parse_cd_records(
    cd_buf: &[u8],
    total_entries: u64,
    max_entries: usize,
) -> Result<Vec<RawZipEntryHeader>> {
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
        if read_u32_le(cd_buf, pos)? != CDH_SIG {
            return Err(DandiError::CorruptArchive(
                "invalid Central Directory header signature".to_string(),
            ));
        }

        let version_made_by = read_u16_le(cd_buf, pos + 4)?;
        let version_needed = read_u16_le(cd_buf, pos + 6)?;
        let flags = read_u16_le(cd_buf, pos + 8)?;
        let compression_method = read_u16_le(cd_buf, pos + 10)?;
        let dos_time = read_u16_le(cd_buf, pos + 12)?;
        let dos_date = read_u16_le(cd_buf, pos + 14)?;
        let crc32 = read_u32_le(cd_buf, pos + 16)?;
        let mut compressed_size = read_u32_le(cd_buf, pos + 20)? as u64;
        let mut uncompressed_size = read_u32_le(cd_buf, pos + 24)? as u64;
        let name_len = read_u16_le(cd_buf, pos + 28)? as usize;
        let extra_len = read_u16_le(cd_buf, pos + 30)? as usize;
        let comment_len = read_u16_le(cd_buf, pos + 32)? as usize;
        let mut disk_number_start = read_u16_le(cd_buf, pos + 34)? as u32;
        let external_attrs = read_u32_le(cd_buf, pos + 38)?;
        let mut local_header_offset = read_u32_le(cd_buf, pos + 42)? as u64;

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
                zpos += 8;
            }
            if disk_number_start == ZIP64_THRESHOLD_DISK
                && zpos.checked_add(4).is_some_and(|e| e <= z64_field.len())
            {
                disk_number_start = read_u32_le(z64_field, zpos)?;
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
            disk_number_start,
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

/// Rewrites a PKWARE multi-disk Central Directory into a single-disk Central Directory, ZIP64
/// EOCD/locator and EOCD overlay placed at `cd_global_offset` of the concatenated volumes, so the
/// `zip` crate can read the set as one archive. Non-ZIP64 extra fields (WinZip AES `0x9901`,
/// `0x5455`, `0x7075`, ...) and comments are kept verbatim.
pub(crate) fn build_normalized_single_disk_tail(
    parsed: &ParsedZipDirectory,
    reader: &SplitFileReader,
) -> Result<Vec<u8>> {
    let cd_buf = &parsed.raw_cd_bytes;
    let mut patched_cd = Vec::with_capacity(cd_buf.len() + parsed.headers.len() * 12);
    let mut pos = 0usize;
    let mut idx = 0usize;

    while pos < cd_buf.len() {
        let header_end = pos
            .checked_add(46)
            .ok_or_else(|| DandiError::CorruptArchive("CD rewrite offset overflow".to_string()))?;
        let name_len = read_u16_le(cd_buf, pos + 28)? as usize;
        let extra_len = read_u16_le(cd_buf, pos + 30)? as usize;
        let comment_len = read_u16_le(cd_buf, pos + 32)? as usize;
        let name_start = header_end;
        let extra_start = name_start + name_len;
        let comment_start = extra_start + extra_len;
        let next_pos = comment_start + comment_len;

        let hdr = parsed.headers.get(idx).ok_or_else(|| {
            DandiError::CorruptArchive("CD record count mismatch during split rewrite".to_string())
        })?;
        let disk_start = reader
            .volume_start_offset(hdr.disk_number_start as usize)
            .ok_or_else(|| {
                DandiError::CorruptArchive(format!(
                    "split ZIP entry {} references invalid disk {}",
                    idx, hdr.disk_number_start
                ))
            })?;
        let global_lfh_offset = disk_start
            .checked_add(hdr.local_header_offset)
            .ok_or_else(|| DandiError::CorruptArchive("global LFH offset overflow".to_string()))?;

        let need_z64_uncomp = hdr.uncompressed_size >= ZIP64_THRESHOLD_U32
            || read_u32_le(cd_buf, pos + 24)? as u64 == ZIP64_THRESHOLD_U32;
        let need_z64_comp = hdr.compressed_size >= ZIP64_THRESHOLD_U32
            || read_u32_le(cd_buf, pos + 20)? as u64 == ZIP64_THRESHOLD_U32;
        let need_z64_off = global_lfh_offset >= ZIP64_THRESHOLD_U32;
        let need_z64 = need_z64_uncomp || need_z64_comp || need_z64_off;

        // Rebuild extra_data preserving all non-ZIP64 extra blocks verbatim, plus a normalized 0x0001 if needed.
        let orig_extra = &cd_buf[extra_start..comment_start];
        let mut new_extra = Vec::with_capacity(orig_extra.len() + 28);
        if need_z64 {
            let mut z64_payload = Vec::with_capacity(24);
            if need_z64_uncomp {
                z64_payload.extend_from_slice(&hdr.uncompressed_size.to_le_bytes());
            }
            if need_z64_comp {
                z64_payload.extend_from_slice(&hdr.compressed_size.to_le_bytes());
            }
            if need_z64_off {
                z64_payload.extend_from_slice(&global_lfh_offset.to_le_bytes());
            }
            new_extra.extend_from_slice(&0x0001u16.to_le_bytes());
            new_extra.extend_from_slice(&(z64_payload.len() as u16).to_le_bytes());
            new_extra.extend_from_slice(&z64_payload);
        }
        copy_extra_fields_excluding(orig_extra, 0x0001, &mut new_extra);

        let new_extra_len = u16::try_from(new_extra.len()).map_err(|_| {
            DandiError::CorruptArchive("rewritten CD extra field exceeds 65535 bytes".to_string())
        })?;

        let mut cdh = [0u8; 46];
        cdh.copy_from_slice(&cd_buf[pos..header_end]);
        if need_z64 {
            let ver_needed = u16::from_le_bytes([cdh[6], cdh[7]]).max(45);
            cdh[6..8].copy_from_slice(&ver_needed.to_le_bytes());
        }
        cdh[20..24].copy_from_slice(
            &(if need_z64_comp {
                0xFFFF_FFFFu32
            } else {
                hdr.compressed_size as u32
            })
            .to_le_bytes(),
        );
        cdh[24..28].copy_from_slice(
            &(if need_z64_uncomp {
                0xFFFF_FFFFu32
            } else {
                hdr.uncompressed_size as u32
            })
            .to_le_bytes(),
        );
        cdh[30..32].copy_from_slice(&new_extra_len.to_le_bytes());
        // Single-disk normalized disk_number_start = 0.
        cdh[34..36].copy_from_slice(&0u16.to_le_bytes());
        cdh[42..46].copy_from_slice(
            &(if need_z64_off {
                0xFFFF_FFFFu32
            } else {
                global_lfh_offset as u32
            })
            .to_le_bytes(),
        );

        patched_cd.extend_from_slice(&cdh);
        patched_cd.extend_from_slice(&cd_buf[name_start..extra_start]);
        patched_cd.extend_from_slice(&new_extra);
        patched_cd.extend_from_slice(&cd_buf[comment_start..next_pos]);

        pos = next_pos;
        idx += 1;
    }

    let entry_count = parsed.headers.len();
    let cd_size = patched_cd.len() as u64;
    let cd_start = parsed.cd_global_offset;
    let need_zip64_eocd = entry_count >= ZIP64_THRESHOLD_ENTRIES
        || cd_size >= ZIP64_THRESHOLD_U32
        || cd_start >= ZIP64_THRESHOLD_U32;

    if need_zip64_eocd {
        let z64_eocd_offset = cd_start
            .checked_add(cd_size)
            .ok_or_else(|| DandiError::CorruptArchive("ZIP64 EOCD offset overflow".to_string()))?;
        let mut z64_eocd = [0u8; 56];
        z64_eocd[0..4].copy_from_slice(&ZIP64_EOCD_SIG.to_le_bytes());
        z64_eocd[4..12].copy_from_slice(&44u64.to_le_bytes());
        z64_eocd[12..14].copy_from_slice(&(VERSION_MADE_BY_UNIX | 45).to_le_bytes());
        z64_eocd[14..16].copy_from_slice(&45u16.to_le_bytes());
        z64_eocd[24..32].copy_from_slice(&(entry_count as u64).to_le_bytes());
        z64_eocd[32..40].copy_from_slice(&(entry_count as u64).to_le_bytes());
        z64_eocd[40..48].copy_from_slice(&cd_size.to_le_bytes());
        z64_eocd[48..56].copy_from_slice(&cd_start.to_le_bytes());
        patched_cd.extend_from_slice(&z64_eocd);

        let mut z64_loc = [0u8; 20];
        z64_loc[0..4].copy_from_slice(&ZIP64_LOCATOR_SIG.to_le_bytes());
        z64_loc[8..16].copy_from_slice(&z64_eocd_offset.to_le_bytes());
        z64_loc[16..20].copy_from_slice(&1u32.to_le_bytes());
        patched_cd.extend_from_slice(&z64_loc);
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
    patched_cd.extend_from_slice(&eocd);

    Ok(patched_cd)
}

pub(crate) fn copy_extra_fields_excluding(extra: &[u8], exclude_id: u16, dst: &mut Vec<u8>) {
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
        if id != exclude_id {
            dst.extend_from_slice(&extra[pos..data_end]);
        }
        pos = data_end;
    }
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

pub(crate) fn read_u16_le(buf: &[u8], offset: usize) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| DandiError::CorruptArchive("offset overflow reading u16".to_string()))?;
    let slice = buf
        .get(offset..end)
        .ok_or_else(|| DandiError::CorruptArchive("unexpected EOF reading u16".to_string()))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

pub(crate) fn read_u32_le(buf: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| DandiError::CorruptArchive("offset overflow reading u32".to_string()))?;
    let slice = buf
        .get(offset..end)
        .ok_or_else(|| DandiError::CorruptArchive("unexpected EOF reading u32".to_string()))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

pub(crate) fn read_u64_le(buf: &[u8], offset: usize) -> Result<u64> {
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
