use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{DandiError, Result};
use crate::platform::to_fs_path;

/// Minimum allowed split volume size (64 KiB).
pub const MIN_SPLIT_SIZE_BYTES: u64 = 64 * 1024;

const MAX_SPLIT_VOLUMES: u32 = 100_000;

/// PKWARE APPNOTE split ZIP leading signature on Disk 0 (`.z01`).
pub(crate) const PKWARE_SPLIT_SIG: u32 = 0x0807_4b50;

const EOCD_SIG: u32 = 0x0605_4b50;
const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;
const ZIP64_LOCATOR_SIG: u32 = 0x0706_4b50;
const WRITE_BUF_SIZE: usize = 256 * 1024;

static SPLIT_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Volume naming style for multi-volume split archive creation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitStyle {
    /// Standard PKWARE split ZIP (`.z01`, `.z02`, ..., `.zip`) for ZIP; falls back to `Numeric` for `.7z`.
    #[default]
    PkwareZip,
    /// Numeric split parts (`.zip.001`, `.zip.002`, ... / `.7z.001`, `.7z.002`, ...).
    Numeric,
}

/// Validates an optional split volume size, enforcing `>= 64 KiB`.
pub fn validate_split_size(split_size_bytes: Option<u64>) -> Result<Option<u64>> {
    match split_size_bytes {
        None => Ok(None),
        Some(size) if size < MIN_SPLIT_SIZE_BYTES => Err(DandiError::InvalidInput(format!(
            "split volume size must be at least {MIN_SPLIT_SIZE_BYTES} bytes (64 KiB), got {size} bytes"
        ))),
        Some(size) => Ok(Some(size)),
    }
}

/// Classification of a discovered single-file or multi-volume archive set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VolumeKind {
    Single,
    PkwareZip,
    Numeric,
}

/// Discovered volume sequence for an archive on disk.
#[derive(Clone, Debug)]
pub(crate) struct VolumeSet {
    pub kind: VolumeKind,
    /// Ordered volume paths from disk 0 / `.001` through the final volume.
    pub volumes: Vec<PathBuf>,
}

impl VolumeSet {
    pub fn single(path: &Path) -> Self {
        Self {
            kind: VolumeKind::Single,
            volumes: vec![path.to_path_buf()],
        }
    }

    pub fn is_split(&self) -> bool {
        self.kind != VolumeKind::Single
    }
}

/// Discovers sibling split volumes for `.z01`/split `.zip` and `.001` numeric split sets.
///
/// Returns a clear `DandiError::CorruptArchive` naming the missing volume if any part is absent.
pub(crate) fn discover_volumes(path: &Path) -> Result<VolumeSet> {
    let fs_path = to_fs_path(path);
    fs::metadata(&fs_path).map_err(|e| DandiError::io(path, e))?;

    let file_name = match path.file_name() {
        Some(n) => n.to_string_lossy().into_owned(),
        None => return Ok(VolumeSet::single(path)),
    };
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    // 1. Check numeric split suffix (`.001`, `.002`, ..., `.0001`).
    if let Some((base_name, suffix_len, clicked_part)) = parse_numeric_split_name(&file_name) {
        let width = numeric_set_width(parent, &base_name, suffix_len, clicked_part);
        let part1 = parent.join(format!("{base_name}.{:0width$}", 1));
        // A complete archive merely named like a later part (`report.zip.2024`) opens on its own.
        let standalone =
            clicked_part != 1 && !to_fs_path(&part1).exists() && has_archive_magic(path);
        if !standalone && (looks_like_archive_base(&base_name) || has_archive_magic(&part1)) {
            return discover_numeric_volumes(parent, &base_name, width);
        }
    }

    // 2. Check PKWARE split ZIP part (`.z01`, `.z02`, ..., `.z100`).
    if let Some((stem, part_idx, is_upper)) = parse_pkware_z_part(&file_name) {
        let final_zip = find_pkware_final_zip(parent, &stem, is_upper).ok_or_else(|| {
            let expected = parent.join(format!("{stem}{}", if is_upper { ".ZIP" } else { ".zip" }));
            DandiError::CorruptArchive(format!(
                "missing final split ZIP volume '{}'",
                expected.display()
            ))
        })?;
        return discover_pkware_from_final_zip(&final_zip, &stem, is_upper, Some(part_idx));
    }

    // 3. Check if a `.zip` file is the final volume of a PKWARE multi-disk split ZIP.
    if file_name.to_ascii_lowercase().ends_with(".zip") && file_name.len() > 4 {
        if let Ok(Some(info)) = peek_zip_eocd_disk_info(path) {
            if info.number_of_this_disk > 0 {
                let stem = &file_name[..file_name.len() - 4];
                let is_upper = &file_name[file_name.len() - 4..] == ".ZIP";
                return discover_pkware_from_final_zip(path, stem, is_upper, None);
            }
        }
    }

    Ok(VolumeSet::single(path))
}

fn parse_numeric_split_name(file_name: &str) -> Option<(String, usize, usize)> {
    let (base, ext) = file_name.rsplit_once('.')?;
    if base.is_empty() || ext.len() < 3 || !ext.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let part_num = ext.parse::<usize>().ok()?;
    if part_num == 0 {
        return None;
    }
    Some((base.to_string(), ext.len(), part_num))
}

fn looks_like_archive_base(base_name: &str) -> bool {
    let lower = base_name.to_ascii_lowercase();
    [
        ".zip", ".7z", ".tar", ".tgz", ".tar.gz", ".gz", ".tar.zst", ".tzst", ".zst", ".tar.bz2",
        ".tbz2", ".bz2", ".tar.xz", ".txz", ".xz", ".rar",
    ]
    .iter()
    .any(|ext| lower.ends_with(ext))
}

fn has_archive_magic(path: &Path) -> bool {
    let Ok(mut f) = File::open(to_fs_path(path)) else {
        return false;
    };
    let mut header = [0u8; 512];
    let Ok(n) = f.read(&mut header) else {
        return false;
    };
    crate::archive::format::detect_by_magic(&header[..n]).is_some()
}

/// Width of the set a numeric part belongs to. A name that grew past its set's width (`.1000`
/// after `.999`, as 7-Zip numbers parts) belongs to the narrower set whose run reaches it;
/// otherwise the suffix length is the width.
fn numeric_set_width(parent: &Path, base_name: &str, suffix_len: usize, part: usize) -> usize {
    let exists =
        |n: usize, w: usize| to_fs_path(&parent.join(format!("{base_name}.{n:0w$}"))).exists();
    let grown = part.to_string().len() == suffix_len;
    if grown && !exists(1, suffix_len) {
        for w in (3..suffix_len).rev() {
            let Some(first_grown) = first_grown_part(w) else {
                continue;
            };
            if exists(1, w) && (first_grown - 1..=part).all(|n| exists(n, w)) {
                return w;
            }
        }
    }
    suffix_len
}

/// First part number whose name outgrows `width` digits (`1000` for `.001`).
fn first_grown_part(width: usize) -> Option<usize> {
    10usize.checked_pow(u32::try_from(width).ok()?)
}

/// Sorted siblings `<base_name>.<n>` named exactly as part `n` of a set whose first volume is
/// `<base_name>.{1:0width$}`: zero-padded to `width` digits, or longer once `n` outgrows it.
fn numeric_siblings(parent: &Path, base_name: &str, width: usize) -> Result<Vec<(usize, PathBuf)>> {
    let prefix = format!("{base_name}.");
    let mut found: Vec<(usize, PathBuf)> = Vec::new();

    let entries = fs::read_dir(to_fs_path(parent)).map_err(|e| DandiError::io(parent, e))?;
    for entry_res in entries {
        let entry = entry_res.map_err(|e| DandiError::io(parent, e))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(suffix) = name.strip_prefix(&prefix) {
            if !suffix.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            if let Ok(num) = suffix.parse::<usize>() {
                if num >= 1 && suffix == format!("{num:0width$}") {
                    found.push((num, parent.join(name)));
                }
            }
        }
    }

    found.sort_by_key(|(num, _)| *num);
    found.dedup_by_key(|(num, _)| *num);
    Ok(found)
}

/// Every fixed-width part up to the highest one found must exist, so a missing middle volume
/// is named in the error. Grown names (`.1000`…) count only as the run continuing a full
/// fixed-width range, so a look-alike such as `report.zip.2024` never joins a small set.
fn discover_numeric_volumes(parent: &Path, base_name: &str, width: usize) -> Result<VolumeSet> {
    let found = numeric_siblings(parent, base_name, width)?;
    let first_grown = first_grown_part(width).unwrap_or(usize::MAX);
    let fixed_len = found.partition_point(|(num, _)| *num < first_grown);
    let (fixed, grown) = found.split_at(fixed_len);

    let missing_volume = |num: usize| {
        let missing = parent.join(format!("{base_name}.{num:0width$}"));
        DandiError::CorruptArchive(format!("missing split volume '{}'", missing.display()))
    };
    let max_part = fixed.last().map_or(0, |(num, _)| *num);
    if max_part == 0 {
        return Err(missing_volume(1));
    }
    for (idx, (num, _)) in fixed.iter().enumerate() {
        if *num != idx + 1 {
            return Err(missing_volume(idx + 1));
        }
    }

    let mut volumes: Vec<PathBuf> = fixed.iter().map(|(_, p)| p.clone()).collect();
    for (offset, (num, path)) in grown.iter().enumerate() {
        if *num != max_part + 1 + offset {
            break;
        }
        volumes.push(path.clone());
    }

    Ok(VolumeSet {
        kind: VolumeKind::Numeric,
        volumes,
    })
}

fn parse_pkware_z_part(file_name: &str) -> Option<(String, u32, bool)> {
    let (stem, ext) = file_name.rsplit_once('.')?;
    if stem.is_empty() || ext.len() < 3 {
        return None;
    }
    let bytes = ext.as_bytes();
    let is_upper = match bytes[0] {
        b'z' => false,
        b'Z' => true,
        _ => return None,
    };
    if !bytes[1..].iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let num = ext[1..].parse::<u32>().ok()?;
    if num == 0 {
        return None;
    }
    Some((stem.to_string(), num, is_upper))
}

fn find_pkware_final_zip(parent: &Path, stem: &str, prefer_upper: bool) -> Option<PathBuf> {
    let candidates = if prefer_upper {
        [format!("{stem}.ZIP"), format!("{stem}.zip")]
    } else {
        [format!("{stem}.zip"), format!("{stem}.ZIP")]
    };
    for name in candidates {
        let candidate = parent.join(name);
        if to_fs_path(&candidate).is_file() {
            return Some(candidate);
        }
    }
    None
}

fn pkware_part_filename(stem: &str, one_based_idx: u32, upper: bool) -> String {
    let z = if upper { 'Z' } else { 'z' };
    if one_based_idx < 100 {
        format!("{stem}.{z}{one_based_idx:02}")
    } else {
        format!("{stem}.{z}{one_based_idx}")
    }
}

fn find_pkware_part(
    parent: &Path,
    stem: &str,
    one_based_idx: u32,
    prefer_upper: bool,
) -> Option<PathBuf> {
    let primary = parent.join(pkware_part_filename(stem, one_based_idx, prefer_upper));
    if to_fs_path(&primary).is_file() {
        return Some(primary);
    }
    let alt = parent.join(pkware_part_filename(stem, one_based_idx, !prefer_upper));
    if to_fs_path(&alt).is_file() {
        return Some(alt);
    }
    None
}

fn discover_pkware_from_final_zip(
    final_zip: &Path,
    stem: &str,
    prefer_upper: bool,
    clicked_part: Option<u32>,
) -> Result<VolumeSet> {
    let parent = final_zip
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let info = peek_zip_eocd_disk_info(final_zip)?.ok_or_else(|| {
        DandiError::CorruptArchive(format!(
            "final split ZIP volume '{}' is missing a valid End of Central Directory record",
            final_zip.display()
        ))
    })?;

    if info.number_of_this_disk == 0 {
        return Err(DandiError::CorruptArchive(format!(
            "'{}' is not a multi-volume split ZIP archive",
            final_zip.display()
        )));
    }

    if let Some(part) = clicked_part {
        if part > info.number_of_this_disk {
            return Err(DandiError::CorruptArchive(format!(
                "split ZIP volume index {part} exceeds archive disk count {}",
                info.number_of_this_disk + 1
            )));
        }
    }

    if info.number_of_this_disk > MAX_SPLIT_VOLUMES {
        return Err(DandiError::CorruptArchive(format!(
            "split ZIP declares {} disks, exceeding safety cap {MAX_SPLIT_VOLUMES}",
            info.number_of_this_disk + 1
        )));
    }

    let mut volumes = Vec::with_capacity((info.number_of_this_disk as usize) + 1);
    for part_idx in 1..=info.number_of_this_disk {
        let part_path =
            find_pkware_part(parent, stem, part_idx, prefer_upper).ok_or_else(|| {
                let expected = parent.join(pkware_part_filename(stem, part_idx, prefer_upper));
                DandiError::CorruptArchive(format!(
                    "missing split ZIP volume '{}'",
                    expected.display()
                ))
            })?;
        volumes.push(part_path);
    }
    volumes.push(final_zip.to_path_buf());

    Ok(VolumeSet {
        kind: VolumeKind::PkwareZip,
        volumes,
    })
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ZipEocdDiskInfo {
    pub number_of_this_disk: u32,
}

fn peek_zip_eocd_disk_info(path: &Path) -> Result<Option<ZipEocdDiskInfo>> {
    let mut file = File::open(to_fs_path(path)).map_err(|e| DandiError::io(path, e))?;
    let file_len = file
        .seek(SeekFrom::End(0))
        .map_err(|e| DandiError::io(path, e))?;
    if file_len < 22 {
        return Ok(None);
    }

    let search_len = file_len.min(65_535 + 22) as usize;
    let search_start = file_len - (search_len as u64);
    file.seek(SeekFrom::Start(search_start))
        .map_err(|e| DandiError::io(path, e))?;
    let mut tail = vec![0u8; search_len];
    file.read_exact(&mut tail)
        .map_err(|e| DandiError::io(path, e))?;

    let Some(eocd_rel) = find_eocd_in_tail(&tail) else {
        return Ok(None);
    };
    let eocd_offset = search_start + (eocd_rel as u64);
    let eocd = &tail[eocd_rel..];
    let mut disk_num = u16::from_le_bytes([eocd[4], eocd[5]]) as u32;

    // Check ZIP64 EOCD Locator immediately preceding EOCD.
    if eocd_offset >= 20 {
        let mut loc = [0u8; 20];
        file.seek(SeekFrom::Start(eocd_offset - 20))
            .map_err(|e| DandiError::io(path, e))?;
        file.read_exact(&mut loc)
            .map_err(|e| DandiError::io(path, e))?;
        if u32::from_le_bytes([loc[0], loc[1], loc[2], loc[3]]) == ZIP64_LOCATOR_SIG {
            let z64_disk = u32::from_le_bytes([loc[4], loc[5], loc[6], loc[7]]);
            let z64_offset = u64::from_le_bytes([
                loc[8], loc[9], loc[10], loc[11], loc[12], loc[13], loc[14], loc[15],
            ]);
            let total_disks = u32::from_le_bytes([loc[16], loc[17], loc[18], loc[19]]);
            if disk_num == 0xFFFF && total_disks > 0 {
                disk_num = total_disks - 1;
            }
            if z64_disk == disk_num && z64_offset.checked_add(56).is_some_and(|e| e <= file_len) {
                let mut z64 = [0u8; 56];
                file.seek(SeekFrom::Start(z64_offset))
                    .map_err(|e| DandiError::io(path, e))?;
                file.read_exact(&mut z64)
                    .map_err(|e| DandiError::io(path, e))?;
                if u32::from_le_bytes([z64[0], z64[1], z64[2], z64[3]]) == ZIP64_EOCD_SIG {
                    disk_num = u32::from_le_bytes([z64[16], z64[17], z64[18], z64[19]]);
                }
            }
        }
    }

    Ok(Some(ZipEocdDiskInfo {
        number_of_this_disk: disk_num,
    }))
}

fn find_eocd_in_tail(tail: &[u8]) -> Option<usize> {
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

#[derive(Clone, Debug)]
struct VolumeSpan {
    path: PathBuf,
    start_offset: u64,
    len: u64,
}

/// Streaming `Read + Seek` reader across ordered split archive volumes with zero full-archive copy.
///
/// Keeps at most one underlying OS file handle open at a time so archives with hundreds or
/// thousands of volumes never exhaust OS file descriptor limits.
pub struct SplitFileReader {
    spans: Vec<VolumeSpan>,
    total_len: u64,
    pos: u64,
    active: Option<(usize, File)>,
    needs_seek: bool,
}

impl SplitFileReader {
    /// Opens an ordered list of split archive volume paths for streaming `Read + Seek`.
    pub fn open(volumes: &[PathBuf]) -> Result<Self> {
        if volumes.is_empty() {
            return Err(DandiError::InvalidInput(
                "at least one volume path is required".to_string(),
            ));
        }

        let mut spans = Vec::with_capacity(volumes.len());
        let mut offset = 0u64;
        for vol in volumes {
            let meta = fs::metadata(to_fs_path(vol)).map_err(|e| DandiError::io(vol, e))?;
            let len = meta.len();
            spans.push(VolumeSpan {
                path: vol.clone(),
                start_offset: offset,
                len,
            });
            offset = offset.checked_add(len).ok_or_else(|| {
                DandiError::CorruptArchive("combined split archive length overflow".to_string())
            })?;
        }

        Ok(Self {
            spans,
            total_len: offset,
            pos: 0,
            active: None,
            needs_seek: false,
        })
    }

    pub fn total_len(&self) -> u64 {
        self.total_len
    }

    pub fn volume_count(&self) -> usize {
        self.spans.len()
    }

    pub fn volume_start_offset(&self, index: usize) -> Option<u64> {
        self.spans.get(index).map(|s| s.start_offset)
    }

    pub fn volume_len(&self, index: usize) -> Option<u64> {
        self.spans.get(index).map(|s| s.len)
    }

    fn locate_volume(&self, pos: u64) -> Option<usize> {
        if pos >= self.total_len {
            return None;
        }
        // Find the last volume whose `start_offset <= pos` and `len > 0`.
        let idx = self.spans.partition_point(|s| s.start_offset <= pos);
        let mut candidate = idx.checked_sub(1)?;
        while candidate < self.spans.len() {
            let span = &self.spans[candidate];
            if pos >= span.start_offset && pos < span.start_offset + span.len {
                return Some(candidate);
            }
            candidate += 1;
        }
        None
    }

    fn ensure_active_volume(
        &mut self,
        vol_idx: usize,
        offset_in_vol: u64,
    ) -> io::Result<&mut File> {
        let same_vol = self.active.as_ref().is_some_and(|(idx, _)| *idx == vol_idx);
        if !same_vol {
            let path = &self.spans[vol_idx].path;
            let mut file = File::open(to_fs_path(path))?;
            if offset_in_vol > 0 {
                file.seek(SeekFrom::Start(offset_in_vol))?;
            }
            self.active = Some((vol_idx, file));
            self.needs_seek = false;
        } else if self.needs_seek {
            if let Some((_, ref mut file)) = self.active {
                file.seek(SeekFrom::Start(offset_in_vol))?;
            }
            self.needs_seek = false;
        }

        match self.active {
            Some((_, ref mut file)) => Ok(file),
            None => Err(io::Error::other("failed to activate split volume handle")),
        }
    }
}

impl Read for SplitFileReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.total_len {
            return Ok(0);
        }

        let Some(vol_idx) = self.locate_volume(self.pos) else {
            return Ok(0);
        };
        let span_start = self.spans[vol_idx].start_offset;
        let span_len = self.spans[vol_idx].len;
        let offset_in_vol = self.pos - span_start;
        let remain_in_vol = span_len - offset_in_vol;
        let to_read = (buf.len() as u64).min(remain_in_vol) as usize;

        let file = self.ensure_active_volume(vol_idx, offset_in_vol)?;
        let n = file.read(&mut buf[..to_read])?;
        if n == 0 && to_read > 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "split volume '{}' ended unexpectedly early",
                    self.spans[vol_idx].path.display()
                ),
            ));
        }
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SplitFileReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target: i128 = match pos {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::End(delta) => (self.total_len as i128) + (delta as i128),
            SeekFrom::Current(delta) => (self.pos as i128) + (delta as i128),
        };
        if target < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot seek before start of split archive",
            ));
        }
        let next_pos = u64::try_from(target)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "seek offset overflow"))?;
        if next_pos != self.pos {
            self.pos = next_pos;
            self.needs_seek = true;
        }
        Ok(self.pos)
    }
}

fn next_temp_prefix(parent: &Path) -> PathBuf {
    let pid = std::process::id();
    let seq = SPLIT_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    parent.join(format!(".dandi-split-{pid}-{seq}-{nanos}"))
}

fn rename_volume(src: &Path, dst: &Path) -> Result<()> {
    let fs_src = to_fs_path(src);
    let fs_dst = to_fs_path(dst);
    #[cfg(windows)]
    {
        if fs_dst.exists() {
            fs::remove_file(&fs_dst).map_err(|e| DandiError::io(dst, e))?;
        }
    }
    fs::rename(&fs_src, &fs_dst).map_err(|e| DandiError::io(dst, e))
}

/// Leftover disks of an older PKWARE set at the same name: the part of the run counting up
/// from `.z01` that lies at or past `first_stale` (`.z03`, `.z04` after re-packing into three
/// disks). Without `.z01` there is no older set, and names past a gap (`backup.z99`) are
/// never touched.
fn stale_pkware_volumes(output_zip: &Path, first_stale: u32) -> Vec<PathBuf> {
    let mut stale = Vec::new();
    for idx in 1..MAX_SPLIT_VOLUMES {
        let existing: Vec<PathBuf> = pkware_volume_names(output_zip, idx)
            .into_iter()
            .filter(|p| to_fs_path(p).is_file())
            .collect();
        if existing.is_empty() {
            break;
        }
        if idx >= first_stale {
            stale.extend(existing);
        }
    }
    stale
}

/// Leftover volumes of an older numeric set at the same name: the members past `count` of the
/// run counting up from `.001` (`.004`, `.005` after re-packing into three). Without `.001`
/// there is no older set to clean up.
///
/// Any other sibling the reader would take for a volume of the new set (a stray `.099`, or a
/// `.1000` next to a full `.001`…`.999` set) is a conflict: deleting it could lose user data and
/// keeping it would leave a set that cannot be opened, so the pack is refused before commit.
fn stale_numeric_volumes(output_base: &Path, count: usize, width: usize) -> Result<Vec<PathBuf>> {
    let parent = output_base
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let base_name = output_base
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let siblings = numeric_siblings(parent, &base_name, width)?;

    let old_len = siblings
        .iter()
        .enumerate()
        .take_while(|(idx, (num, _))| *num == idx + 1)
        .count();
    let (old_set, others) = siblings.split_at(old_len);
    let first_grown = first_grown_part(width).unwrap_or(usize::MAX);
    if let Some((_, stray)) = others
        .iter()
        .find(|(num, _)| *num > count && (*num < first_grown || *num == count + 1))
    {
        return Err(DandiError::InvalidInput(format!(
            "'{}' would be read as a volume of the new split set but is not part of an older set \
             at that name; move or rename it, then pack again",
            stray.display()
        )));
    }

    Ok(old_set
        .iter()
        .filter(|(num, _)| *num > count)
        .map(|(_, p)| p.clone())
        .collect())
}

fn numeric_volume_name(output_base: &Path, idx: u32, width: usize) -> PathBuf {
    PathBuf::from(format!("{}.{idx:0width$}", output_base.to_string_lossy()))
}

fn pkware_volume_names(output_zip: &Path, idx: u32) -> Vec<PathBuf> {
    let parent = output_zip
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let (stem, _) = pkware_stem(output_zip);
    let lower = parent.join(pkware_part_filename(&stem, idx, false));
    let upper = parent.join(pkware_part_filename(&stem, idx, true));
    vec![lower, upper]
}

/// Fails fast with `AlreadyExists` when `overwrite` is off and the output name or the first
/// volume it would create already exists, before any compression work starts.
pub(crate) fn ensure_split_destination_free(output: &Path, style: SplitStyle) -> Result<()> {
    let mut taken = vec![output.to_path_buf()];
    match style {
        SplitStyle::Numeric => taken.push(numeric_volume_name(output, 1, 3)),
        SplitStyle::PkwareZip => taken.extend(pkware_volume_names(output, 1)),
    }
    match taken.into_iter().find(|p| to_fs_path(p).exists()) {
        Some(path) => Err(DandiError::AlreadyExists { path }),
        None => Ok(()),
    }
}

/// Renames staged temp volumes onto their final names. On any failure, every staged temp and
/// every volume already renamed is removed so no half-written set is left behind.
fn commit_staged_volumes(
    staged: &mut Vec<PathBuf>,
    final_paths: &[PathBuf],
    stale: &[PathBuf],
    overwrite: bool,
) -> Result<()> {
    if staged.len() != final_paths.len() {
        return Err(DandiError::ArchiveEngine(
            "staged volume count mismatch".to_string(),
        ));
    }

    if !overwrite {
        if let Some(existing) = final_paths
            .iter()
            .chain(stale.iter())
            .find(|p| to_fs_path(p).exists())
        {
            return Err(DandiError::AlreadyExists {
                path: existing.clone(),
            });
        }
    }
    for old in stale {
        match fs::remove_file(to_fs_path(old)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(DandiError::io(old, e)),
        }
    }

    let mut committed: Vec<PathBuf> = Vec::with_capacity(final_paths.len());
    for (src, dst) in staged.iter().zip(final_paths.iter()) {
        if let Err(err) = rename_volume(src, dst) {
            for done in &committed {
                let _ = fs::remove_file(to_fs_path(done));
            }
            return Err(err);
        }
        committed.push(dst.clone());
    }

    staged.clear();
    Ok(())
}

/// Streaming `Write + Seek` numeric split writer producing `.001`, `.002`, ... volumes.
///
/// Volumes are staged as hidden sibling temp files; only the volume currently being written
/// keeps an OS handle open, so thousands of small volumes never exhaust file descriptors.
/// All staged volumes are deleted on `Drop` unless `commit()` succeeds.
pub(crate) struct SplitVolumeWriter {
    parent: PathBuf,
    tmp_prefix: String,
    split_size: u64,
    temp_paths: Vec<PathBuf>,
    active: Option<ActiveVolume>,
    total_len: u64,
    pos: u64,
    committed: bool,
}

struct ActiveVolume {
    index: usize,
    file: File,
    /// Position of the OS file cursor inside this volume.
    cursor: u64,
}

impl SplitVolumeWriter {
    pub fn new(output_base: &Path, split_size: u64) -> Result<Self> {
        let split_size = validate_split_size(Some(split_size))?
            .ok_or_else(|| DandiError::InvalidInput("missing split size".to_string()))?;
        let parent = output_base
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        fs::create_dir_all(to_fs_path(&parent)).map_err(|e| DandiError::io(&parent, e))?;

        let tmp_prefix = next_temp_prefix(&parent)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".dandi-split".to_string());
        let mut writer = Self {
            parent,
            tmp_prefix,
            split_size,
            temp_paths: Vec::new(),
            active: None,
            total_len: 0,
            pos: 0,
            committed: false,
        };
        writer.activate(0)?;
        Ok(writer)
    }

    /// Makes `vol_idx` the active volume, creating it (and any skipped volume) on first use.
    fn activate(&mut self, vol_idx: usize) -> io::Result<()> {
        if self.active.as_ref().is_some_and(|a| a.index == vol_idx) {
            return Ok(());
        }
        if let Some(mut prev) = self.active.take() {
            prev.file.flush()?;
        }
        while self.temp_paths.len() <= vol_idx {
            let tmp_path = self.parent.join(format!(
                "{}.part{:04}",
                self.tmp_prefix,
                self.temp_paths.len() + 1
            ));
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(to_fs_path(&tmp_path))?;
            self.temp_paths.push(tmp_path);
        }
        let file = OpenOptions::new()
            .write(true)
            .open(to_fs_path(&self.temp_paths[vol_idx]))?;
        self.active = Some(ActiveVolume {
            index: vol_idx,
            file,
            cursor: 0,
        });
        Ok(())
    }

    /// Flushes and atomically renames staged volumes to `<output_base>.001`, `.002`, ...
    /// (removing any higher-numbered volume left from an older set when `overwrite` is set).
    pub fn commit(
        mut self,
        output_base: &Path,
        overwrite: bool,
    ) -> Result<(PathBuf, Vec<PathBuf>, u64)> {
        if let Some(mut active) = self.active.take() {
            active
                .file
                .flush()
                .map_err(|e| DandiError::io(&self.temp_paths[active.index], e))?;
        }
        let last = self.temp_paths.len().saturating_sub(1);
        for (idx, path) in self.temp_paths.iter().enumerate() {
            let len = fs::metadata(to_fs_path(path))
                .map_err(|e| DandiError::io(path, e))?
                .len();
            let expected = if idx == last {
                self.total_len - (last as u64) * self.split_size
            } else {
                self.split_size
            };
            if len != expected {
                return Err(DandiError::ArchiveEngine(format!(
                    "split volume {} has {len} bytes, expected {expected}",
                    idx + 1
                )));
            }
        }

        let count = self.temp_paths.len().max(1);
        let width = count.to_string().len().max(3);
        let final_paths: Vec<PathBuf> = (1..=count as u32)
            .map(|i| numeric_volume_name(output_base, i, width))
            .collect();
        let stale = stale_numeric_volumes(output_base, count, width)?;

        let mut staged = std::mem::take(&mut self.temp_paths);
        if let Err(err) = commit_staged_volumes(&mut staged, &final_paths, &stale, overwrite) {
            self.temp_paths = staged;
            return Err(err);
        }

        self.committed = true;
        let primary = final_paths
            .first()
            .cloned()
            .unwrap_or_else(|| output_base.to_path_buf());
        Ok((primary, final_paths, self.total_len))
    }
}

impl Write for SplitVolumeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut remaining = buf;
        while !remaining.is_empty() {
            let vol_idx = usize::try_from(self.pos / self.split_size)
                .map_err(|_| io::Error::other("split volume index overflow"))?;
            let vol_off = self.pos % self.split_size;
            self.activate(vol_idx)?;
            let active = self
                .active
                .as_mut()
                .ok_or_else(|| io::Error::other("split volume not active"))?;
            if active.cursor != vol_off {
                active.file.seek(SeekFrom::Start(vol_off))?;
                active.cursor = vol_off;
            }

            let avail = usize::try_from(self.split_size - vol_off).unwrap_or(usize::MAX);
            let chunk_len = remaining.len().min(avail);
            active.file.write_all(&remaining[..chunk_len])?;
            active.cursor += chunk_len as u64;

            self.pos = self
                .pos
                .checked_add(chunk_len as u64)
                .ok_or_else(|| io::Error::other("split output offset overflow"))?;
            self.total_len = self.total_len.max(self.pos);
            remaining = &remaining[chunk_len..];
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.active.as_mut() {
            Some(active) => active.file.flush(),
            None => Ok(()),
        }
    }
}

impl Seek for SplitVolumeWriter {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target: i128 = match pos {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::End(delta) => (self.total_len as i128) + (delta as i128),
            SeekFrom::Current(delta) => (self.pos as i128) + (delta as i128),
        };
        if target < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot seek before start of split writer",
            ));
        }
        self.pos = u64::try_from(target)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "seek offset overflow"))?;
        Ok(self.pos)
    }
}

impl Drop for SplitVolumeWriter {
    fn drop(&mut self) {
        if !self.committed {
            self.active = None;
            for path in self.temp_paths.drain(..) {
                let _ = fs::remove_file(to_fs_path(&path));
            }
        }
    }
}

/// PKWARE APPNOTE split ZIP volume writer managing `.z01`, `.z02`, ..., `.zip` rotation,
/// atomic temp staging, non-splitting of headers, and in-place LFH patching across disks.
pub(crate) struct PkwareSplitWriter {
    parent: PathBuf,
    tmp_prefix: PathBuf,
    split_size: u64,
    temp_paths: Vec<PathBuf>,
    disk_lengths: Vec<u64>,
    current_disk: u32,
    disk_offset: u64,
    total_bytes: u64,
    current_writer: Option<BufWriter<File>>,
    committed: bool,
}

impl PkwareSplitWriter {
    pub fn new(output_zip: &Path, split_size: u64) -> Result<Self> {
        let split_size = validate_split_size(Some(split_size))?
            .ok_or_else(|| DandiError::InvalidInput("missing split size".to_string()))?;
        let has_zip_ext = output_zip
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("zip"));
        if !has_zip_ext {
            return Err(DandiError::InvalidInput(format!(
                "PKWARE split output '{}' must end with .zip (volumes are named .z01, .z02, ..., .zip)",
                output_zip.display()
            )));
        }
        let parent = output_zip
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        fs::create_dir_all(to_fs_path(&parent)).map_err(|e| DandiError::io(&parent, e))?;

        let tmp_prefix = next_temp_prefix(&parent);
        let mut writer = Self {
            parent,
            tmp_prefix,
            split_size,
            temp_paths: Vec::new(),
            disk_lengths: Vec::new(),
            current_disk: 0,
            disk_offset: 0,
            total_bytes: 0,
            current_writer: None,
            committed: false,
        };
        writer.open_new_disk()?;
        // PKWARE APPNOTE §8.5.3: disk 0 begins with 0x08074b50 split signature.
        writer.write_raw_on_current_disk(&PKWARE_SPLIT_SIG.to_le_bytes())?;
        Ok(writer)
    }

    fn open_new_disk(&mut self) -> Result<()> {
        if let Some(mut prev) = self.current_writer.take() {
            prev.flush()?;
            drop(prev);
        }
        let disk_idx = self.temp_paths.len();
        let tmp_name = format!(
            "{}.z{:04}",
            self.tmp_prefix
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| ".dandi-pkware".to_string()),
            disk_idx + 1
        );
        let tmp_path = self.parent.join(tmp_name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(to_fs_path(&tmp_path))
            .map_err(|e| DandiError::io(&tmp_path, e))?;
        self.temp_paths.push(tmp_path);
        self.disk_lengths.push(0);
        self.current_disk = u32::try_from(disk_idx)
            .map_err(|_| DandiError::ArchiveEngine("split disk count overflow".to_string()))?;
        self.disk_offset = 0;
        self.current_writer = Some(BufWriter::with_capacity(WRITE_BUF_SIZE, file));
        Ok(())
    }

    fn write_raw_on_current_disk(&mut self, data: &[u8]) -> Result<()> {
        let Some(ref mut w) = self.current_writer else {
            return Err(DandiError::ArchiveEngine(
                "PKWARE split writer not open".to_string(),
            ));
        };
        w.write_all(data)?;
        let n = data.len() as u64;
        self.disk_offset = self
            .disk_offset
            .checked_add(n)
            .ok_or_else(|| DandiError::ArchiveEngine("split disk offset overflow".to_string()))?;
        self.total_bytes = self
            .total_bytes
            .checked_add(n)
            .ok_or_else(|| DandiError::ArchiveEngine("split total bytes overflow".to_string()))?;
        if let Some(len) = self.disk_lengths.last_mut() {
            *len = self.disk_offset;
        }
        Ok(())
    }

    pub fn current_location(&self) -> (u32, u64) {
        (self.current_disk, self.disk_offset)
    }

    pub fn disk_count(&self) -> u32 {
        self.temp_paths.len() as u32
    }

    pub fn split_size(&self) -> u64 {
        self.split_size
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Ensures `len` bytes can be written contiguously on the current disk without splitting.
    /// Rotates to a fresh disk first if the current disk lacks sufficient space.
    pub fn ensure_contiguous_space(&mut self, len: u64) -> Result<(u32, u64)> {
        if self.disk_offset > 0 && self.disk_offset.saturating_add(len) > self.split_size {
            self.open_new_disk()?;
        }
        Ok((self.current_disk, self.disk_offset))
    }

    /// Writes a header or record atomically without splitting it across disks, returning
    /// `(disk_number, offset_within_disk)` where it was placed.
    pub fn write_atomic_record(&mut self, data: &[u8]) -> Result<(u32, u64)> {
        let loc = self.ensure_contiguous_space(data.len() as u64)?;
        self.write_raw_on_current_disk(data)?;
        Ok(loc)
    }

    /// Streams payload bytes that may freely cross disk boundaries.
    pub fn write_splittable(&mut self, mut data: &[u8]) -> Result<()> {
        while !data.is_empty() {
            if self.disk_offset >= self.split_size {
                self.open_new_disk()?;
            }
            let avail = (self.split_size - self.disk_offset) as usize;
            let take = data.len().min(avail);
            self.write_raw_on_current_disk(&data[..take])?;
            data = &data[take..];
        }
        Ok(())
    }

    /// Patches previously written bytes inside a specific disk (used for streamed >16 MiB LFHs).
    pub fn patch_at(&mut self, disk: u32, offset_in_disk: u64, bytes: &[u8]) -> Result<()> {
        if disk == self.current_disk {
            let Some(ref mut w) = self.current_writer else {
                return Err(DandiError::ArchiveEngine(
                    "PKWARE split writer not open".to_string(),
                ));
            };
            w.flush()?;
            let inner = w.get_mut();
            inner.seek(SeekFrom::Start(offset_in_disk))?;
            inner.write_all(bytes)?;
            inner.seek(SeekFrom::Start(self.disk_offset))?;
            Ok(())
        } else {
            let path = self.temp_paths.get(disk as usize).ok_or_else(|| {
                DandiError::ArchiveEngine(format!("invalid split disk index {disk}"))
            })?;
            let mut file = OpenOptions::new()
                .write(true)
                .open(to_fs_path(path))
                .map_err(|e| DandiError::io(path, e))?;
            file.seek(SeekFrom::Start(offset_in_disk))?;
            file.write_all(bytes)?;
            file.flush()?;
            Ok(())
        }
    }

    /// Rewrites Disk 0 without the leading 4-byte `0x08074b50` split signature when the entire
    /// archive fits inside a single volume, so callers get a 100% standard single-file `.zip`.
    pub fn strip_single_disk_split_sig(&mut self) -> Result<()> {
        if self.current_disk != 0 || self.temp_paths.len() != 1 {
            return Err(DandiError::ArchiveEngine(
                "cannot strip split signature on multi-disk archive".to_string(),
            ));
        }
        if let Some(mut w) = self.current_writer.take() {
            w.flush()?;
            drop(w);
        }

        let old_path = self.temp_paths[0].clone();
        let new_name = format!(
            "{}.single.zip",
            self.tmp_prefix
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| ".dandi-pkware".to_string())
        );
        let new_path = self.parent.join(new_name);
        // Tracked before it exists so `Drop` also removes it if the copy fails.
        self.temp_paths.push(new_path.clone());

        let mut src =
            File::open(to_fs_path(&old_path)).map_err(|e| DandiError::io(&old_path, e))?;
        src.seek(SeekFrom::Start(4))?;
        let mut dst = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(to_fs_path(&new_path))
            .map_err(|e| DandiError::io(&new_path, e))?;

        let copied = io::copy(&mut src, &mut dst).map_err(|e| DandiError::io(&new_path, e))?;
        drop(src);
        let _ = fs::remove_file(to_fs_path(&old_path));

        self.temp_paths.remove(0);
        self.disk_lengths[0] = copied;
        self.disk_offset = copied;
        self.total_bytes = copied;
        self.current_writer = Some(BufWriter::with_capacity(WRITE_BUF_SIZE, dst));
        Ok(())
    }

    /// Flushes and atomically renames staged files to `[<stem>.z01, ..., <stem>.zip]`.
    pub fn commit(
        mut self,
        output_zip: &Path,
        overwrite: bool,
    ) -> Result<(PathBuf, Vec<PathBuf>, u64)> {
        if let Some(mut w) = self.current_writer.take() {
            w.flush()?;
            drop(w);
        }

        let num_disks = self.temp_paths.len();
        let final_paths = pkware_final_volume_paths(output_zip, num_disks);
        let first_stale = u32::try_from(num_disks).unwrap_or(MAX_SPLIT_VOLUMES);
        let stale = stale_pkware_volumes(output_zip, first_stale);

        let mut staged = std::mem::take(&mut self.temp_paths);
        if let Err(err) = commit_staged_volumes(&mut staged, &final_paths, &stale, overwrite) {
            self.temp_paths = staged;
            return Err(err);
        }

        self.committed = true;
        Ok((output_zip.to_path_buf(), final_paths, self.total_bytes))
    }
}

impl Write for PkwareSplitWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_splittable(buf)
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(ref mut w) = self.current_writer {
            w.flush()?;
        }
        Ok(())
    }
}

impl Drop for PkwareSplitWriter {
    fn drop(&mut self) {
        if !self.committed {
            self.current_writer = None;
            for p in self.temp_paths.drain(..) {
                let _ = fs::remove_file(to_fs_path(&p));
            }
        }
    }
}

/// Splits `<stem>.zip` into (`<stem>`, upper-case extension?).
fn pkware_stem(output_zip: &Path) -> (String, bool) {
    let file_name = output_zip
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "archive.zip".to_string());
    if file_name.len() > 4 && file_name.to_ascii_lowercase().ends_with(".zip") {
        let upper = &file_name[file_name.len() - 4..] == ".ZIP";
        (file_name[..file_name.len() - 4].to_string(), upper)
    } else {
        (file_name, false)
    }
}

fn pkware_final_volume_paths(output_zip: &Path, num_disks: usize) -> Vec<PathBuf> {
    if num_disks <= 1 {
        return vec![output_zip.to_path_buf()];
    }
    let parent = output_zip
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let (stem, upper) = pkware_stem(output_zip);

    let mut paths = Vec::with_capacity(num_disks);
    for idx in 1..num_disks {
        paths.push(parent.join(pkware_part_filename(&stem, idx as u32, upper)));
    }
    paths.push(output_zip.to_path_buf());
    paths
}

/// Parses a human size such as `10M`, `25MB`, `512K`, `1.5G`, `100MiB` or `65536` into bytes.
///
/// Units are binary (`K` = 1024), matching 7-Zip's `-v10m` volume switch.
pub fn parse_size_spec(spec: &str) -> Result<u64> {
    let invalid = || {
        DandiError::InvalidInput(format!(
            "invalid size '{spec}' (expected e.g. 512K, 10M, 1.5G or a byte count)"
        ))
    };
    let trimmed = spec.trim();
    let split_at = trimmed
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(trimmed.len());
    let (number, unit) = trimmed.split_at(split_at);
    let multiplier: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1 << 10,
        "m" | "mb" | "mib" => 1 << 20,
        "g" | "gb" | "gib" => 1 << 30,
        "t" | "tb" | "tib" => 1 << 40,
        _ => return Err(invalid()),
    };
    let (whole, frac) = number.split_once('.').unwrap_or((number, ""));
    if whole.is_empty() && frac.is_empty() {
        return Err(invalid());
    }
    if frac.len() > 6 || frac.contains('.') {
        return Err(invalid());
    }
    let whole_val: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().map_err(|_| invalid())?
    };
    let mut bytes = whole_val.checked_mul(multiplier).ok_or_else(invalid)?;
    if !frac.is_empty() {
        let frac_val: u64 = frac.parse().map_err(|_| invalid())?;
        let scale = 10u64.pow(frac.len() as u32);
        let frac_bytes = u128::from(frac_val) * u128::from(multiplier) / u128::from(scale);
        bytes = bytes
            .checked_add(u64::try_from(frac_bytes).map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_spec_accepts_binary_units() {
        assert_eq!(parse_size_spec("512K").ok(), Some(512 * 1024));
        assert_eq!(parse_size_spec("10M").ok(), Some(10 * 1024 * 1024));
        assert_eq!(parse_size_spec("25mb").ok(), Some(25 * 1024 * 1024));
        assert_eq!(parse_size_spec("100MiB").ok(), Some(100 * 1024 * 1024));
        assert_eq!(parse_size_spec("1G").ok(), Some(1024 * 1024 * 1024));
        assert_eq!(parse_size_spec("1.5G").ok(), Some(1536 * 1024 * 1024));
        assert_eq!(parse_size_spec(" 65536 ").ok(), Some(65536));
    }

    #[test]
    fn parse_size_spec_rejects_garbage() {
        for bad in [
            "",
            "M",
            "ten",
            "10X",
            "1.2.3M",
            "-5M",
            "99999999999999999999T",
        ] {
            assert!(
                matches!(parse_size_spec(bad), Err(DandiError::InvalidInput(_))),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn validate_split_size_enforces_minimum() {
        assert!(validate_split_size(None).is_ok());
        assert!(validate_split_size(Some(MIN_SPLIT_SIZE_BYTES)).is_ok());
        assert!(matches!(
            validate_split_size(Some(MIN_SPLIT_SIZE_BYTES - 1)),
            Err(DandiError::InvalidInput(_))
        ));
    }
}
