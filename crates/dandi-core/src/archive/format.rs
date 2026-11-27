use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{DandiError, Result};
use crate::platform::to_fs_path;

/// Archive container formats supported by Dandi.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveFormat {
    Zip,
    SevenZ,
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
            Self::Tar => "tar",
            Self::TarGz => "tar.gz",
            Self::TarZst => "tar.zst",
            Self::TarBz2 => "tar.bz2",
            Self::TarXz => "tar.xz",
        }
    }
}

/// Detects an archive's format by magic bytes first, falling back to file extension.
pub fn detect_format(path: &Path) -> Result<ArchiveFormat> {
    let fs_path = to_fs_path(path);
    let mut file = File::open(&fs_path).map_err(|e| DandiError::io(path, e))?;
    let mut header = [0u8; 512];
    let n = file
        .read(&mut header)
        .map_err(|e| DandiError::io(path, e))?;
    let buf = &header[..n];

    if let Some(fmt) = detect_by_magic(buf) {
        return Ok(fmt);
    }

    if let Some(fmt) = detect_by_extension(path) {
        return Ok(fmt);
    }

    Err(DandiError::UnsupportedFormat(path.display().to_string()))
}

fn detect_by_magic(buf: &[u8]) -> Option<ArchiveFormat> {
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
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    if name.ends_with(".zip") {
        Some(ArchiveFormat::Zip)
    } else if name.ends_with(".7z") {
        Some(ArchiveFormat::SevenZ)
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
