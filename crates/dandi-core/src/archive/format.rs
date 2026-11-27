use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::archive::split::discover_volumes;
use crate::error::{DandiError, Result};
use crate::platform::to_fs_path;

/// Archive container formats supported by Dandi.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveFormat {
    Zip,
    SevenZ,
    Rar,
    Tar,
    TarGz,
    TarZst,
    TarBz2,
    TarXz,
}

impl ArchiveFormat {
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::SevenZ => "7z",
            Self::Rar => "rar",
            Self::Tar => "tar",
            Self::TarGz => "tar.gz",
            Self::TarZst => "tar.zst",
            Self::TarBz2 => "tar.bz2",
            Self::TarXz => "tar.xz",
        }
    }
}

/// Detects an archive's format by magic bytes first, falling back to file extension.
///
/// Automatically resolves split volume sets (`.z01`/split `.zip`, `.001`/`.002`, etc.)
/// so opening any volume part detects the underlying archive format accurately.
pub fn detect_format(path: &Path) -> Result<ArchiveFormat> {
    let probe_path = match discover_volumes(path) {
        Ok(vol_set) if vol_set.is_split() => vol_set.volumes[0].clone(),
        Ok(_) => path.to_path_buf(),
        Err(DandiError::CorruptArchive(_)) => {
            // Even if a sibling part is missing, allow format detection from the path name
            // so `inspect`/`unpack` can proceed and surface the exact missing-volume error.
            if let Some(fmt) = detect_by_extension(path) {
                return Ok(fmt);
            }
            path.to_path_buf()
        }
        Err(err) => return Err(err),
    };

    let fs_path = to_fs_path(&probe_path);
    let mut file = File::open(&fs_path).map_err(|e| DandiError::io(&probe_path, e))?;
    let mut header = [0u8; 512];
    let n = file
        .read(&mut header)
        .map_err(|e| DandiError::io(&probe_path, e))?;
    let buf = &header[..n];

    if let Some(fmt) = detect_by_magic(buf) {
        return Ok(fmt);
    }

    if let Some(fmt) = detect_by_extension(&probe_path).or_else(|| detect_by_extension(path)) {
        return Ok(fmt);
    }

    Err(DandiError::UnsupportedFormat(path.display().to_string()))
}

pub(crate) fn detect_by_magic(buf: &[u8]) -> Option<ArchiveFormat> {
    if buf.len() >= 4
        && (buf.starts_with(b"PK\x03\x04")
            || buf.starts_with(b"PK\x05\x06")
            || buf.starts_with(b"PK\x07\x08"))
    {
        return Some(ArchiveFormat::Zip);
    }
    if buf.len() >= 6 && buf.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return Some(ArchiveFormat::SevenZ);
    }
    // RAR5 (`Rar!\x1a\x07\x01\x00`) and RAR4 (`Rar!\x1a\x07\x00`)
    if (buf.len() >= 8 && buf.starts_with(b"Rar!\x1a\x07\x01\x00"))
        || (buf.len() >= 7 && buf.starts_with(b"Rar!\x1a\x07\x00"))
    {
        return Some(ArchiveFormat::Rar);
    }
    if buf.len() >= 2 && buf[0] == 0x1F && buf[1] == 0x8B {
        return Some(ArchiveFormat::TarGz);
    }
    if buf.len() >= 4 && buf.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        return Some(ArchiveFormat::TarZst);
    }
    if buf.len() >= 3 && buf.starts_with(b"BZh") {
        return Some(ArchiveFormat::TarBz2);
    }
    if buf.len() >= 6 && buf.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) {
        return Some(ArchiveFormat::TarXz);
    }
    if buf.len() >= 262 && &buf[257..262] == b"ustar" {
        return Some(ArchiveFormat::Tar);
    }
    None
}

fn detect_by_extension(path: &Path) -> Option<ArchiveFormat> {
    let raw_name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    // Strip numeric split suffix (`.001`, `.002`, ...) before checking container extension.
    let name = strip_numeric_split_ext(&raw_name);

    if name.ends_with(".zip") || is_pkware_z_ext(name) {
        Some(ArchiveFormat::Zip)
    } else if name.ends_with(".7z") {
        Some(ArchiveFormat::SevenZ)
    } else if name.ends_with(".rar") || is_old_rar_vol_ext(name) {
        Some(ArchiveFormat::Rar)
    } else if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        Some(ArchiveFormat::TarGz)
    } else if name.ends_with(".tar.zst") || name.ends_with(".tzst") {
        Some(ArchiveFormat::TarZst)
    } else if name.ends_with(".tar.bz2") || name.ends_with(".tbz2") {
        Some(ArchiveFormat::TarBz2)
    } else if name.ends_with(".tar.xz") || name.ends_with(".txz") {
        Some(ArchiveFormat::TarXz)
    } else if name.ends_with(".tar") {
        Some(ArchiveFormat::Tar)
    } else {
        None
    }
}

fn strip_numeric_split_ext(lower_name: &str) -> &str {
    if let Some((base, ext)) = lower_name.rsplit_once('.') {
        if !base.is_empty() && ext.len() >= 3 && ext.bytes().all(|b| b.is_ascii_digit()) {
            return base;
        }
    }
    lower_name
}

fn is_pkware_z_ext(lower_name: &str) -> bool {
    let Some((_, ext)) = lower_name.rsplit_once('.') else {
        return false;
    };
    let bytes = ext.as_bytes();
    bytes.len() >= 3 && bytes[0] == b'z' && bytes[1..].iter().all(|b| b.is_ascii_digit())
}

fn is_old_rar_vol_ext(lower_name: &str) -> bool {
    let Some((_, ext)) = lower_name.rsplit_once('.') else {
        return false;
    };
    let bytes = ext.as_bytes();
    bytes.len() == 3
        && (b'r'..=b'z').contains(&bytes[0])
        && bytes[1].is_ascii_digit()
        && bytes[2].is_ascii_digit()
}
