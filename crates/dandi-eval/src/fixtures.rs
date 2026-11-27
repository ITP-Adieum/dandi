use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use bzip2::write::BzEncoder;
use bzip2::Compression as BzCompression;
use flate2::write::{DeflateEncoder, GzEncoder};
use flate2::Compression;
use lzma_rust2::{XzOptions, XzWriter};
use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

const LFH_SIG: u32 = 0x0403_4b50;
const CDH_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;
const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;
const ZIP64_LOCATOR_SIG: u32 = 0x0706_4b50;

/// Raw ZIP entry specification for building adversarial, legacy-encoding, or spec-edge fixtures.
#[derive(Clone, Debug)]
pub struct RawZipSpec {
    pub raw_name: Vec<u8>,
    pub payload: Vec<u8>,
    pub flags: u16,
    pub compress: bool,
    pub extra: Vec<u8>,
    pub version_made_by: u16,
    pub external_attrs: u32,
    pub override_crc: Option<u32>,
    pub force_zip64: bool,
}

impl RawZipSpec {
    pub fn file(raw_name: Vec<u8>, payload: Vec<u8>) -> Self {
        Self {
            raw_name,
            payload,
            flags: 0,
            compress: true,
            extra: Vec::new(),
            version_made_by: (3 << 8) | 20,
            external_attrs: 0o100644 << 16,
            override_crc: None,
            force_zip64: false,
        }
    }

    pub fn symlink(raw_name: Vec<u8>, target: &str) -> Self {
        Self {
            raw_name,
            payload: target.as_bytes().to_vec(),
            flags: 0x0800,
            compress: false,
            extra: Vec::new(),
            version_made_by: (3 << 8) | 20,
            external_attrs: 0o120777 << 16,
            override_crc: None,
            force_zip64: false,
        }
    }
}

/// Writes a custom ZIP file with exact byte-level control over headers, flags, and extra fields.
pub fn write_raw_zip(path: &Path, entries: &[RawZipSpec]) -> Result<(), String> {
    let mut out = Vec::new();
    let mut cd = Vec::new();
    let mut any_zip64 = false;

    for e in entries {
        let local_offset = out.len() as u64;
        let crc = e
            .override_crc
            .unwrap_or_else(|| crc32fast::hash(&e.payload));
        let uncomp_len = e.payload.len() as u64;

        let (method, data) = if e.compress && !e.payload.is_empty() {
            let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
            enc.write_all(&e.payload).map_err(|err| err.to_string())?;
            let comp = enc.finish().map_err(|err| err.to_string())?;
            (8u16, comp)
        } else {
            (0u16, e.payload.clone())
        };
        let comp_len = data.len() as u64;

        let use_z64 = e.force_zip64;
        if use_z64 {
            any_zip64 = true;
        }
        let version_needed: u16 = if use_z64 { 45 } else { 20 };

        let mut extra = e.extra.clone();
        if use_z64 {
            extra.extend_from_slice(&0x0001u16.to_le_bytes());
            extra.extend_from_slice(&16u16.to_le_bytes());
            extra.extend_from_slice(&uncomp_len.to_le_bytes());
            extra.extend_from_slice(&comp_len.to_le_bytes());
        }

        let lfh_comp = if use_z64 {
            0xFFFF_FFFFu32
        } else {
            comp_len as u32
        };
        let lfh_uncomp = if use_z64 {
            0xFFFF_FFFFu32
        } else {
            uncomp_len as u32
        };

        out.extend_from_slice(&LFH_SIG.to_le_bytes());
        out.extend_from_slice(&version_needed.to_le_bytes());
        out.extend_from_slice(&e.flags.to_le_bytes());
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // dos time
        out.extend_from_slice(&((2026 - 1980) << 9 | (1 << 5) | 1u16).to_le_bytes()); // dos date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&lfh_comp.to_le_bytes());
        out.extend_from_slice(&lfh_uncomp.to_le_bytes());
        out.extend_from_slice(&(e.raw_name.len() as u16).to_le_bytes());
        out.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        out.extend_from_slice(&e.raw_name);
        out.extend_from_slice(&extra);
        out.extend_from_slice(&data);

        let mut cd_extra = e.extra.clone();
        if use_z64 {
            cd_extra.extend_from_slice(&0x0001u16.to_le_bytes());
            cd_extra.extend_from_slice(&24u16.to_le_bytes());
            cd_extra.extend_from_slice(&uncomp_len.to_le_bytes());
            cd_extra.extend_from_slice(&comp_len.to_le_bytes());
            cd_extra.extend_from_slice(&local_offset.to_le_bytes());
        }
        let cd_offset_u32 = if use_z64 {
            0xFFFF_FFFFu32
        } else {
            local_offset as u32
        };

        cd.extend_from_slice(&CDH_SIG.to_le_bytes());
        cd.extend_from_slice(&e.version_made_by.to_le_bytes());
        cd.extend_from_slice(&version_needed.to_le_bytes());
        cd.extend_from_slice(&e.flags.to_le_bytes());
        cd.extend_from_slice(&method.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&((2026 - 1980) << 9 | (1 << 5) | 1u16).to_le_bytes());
        cd.extend_from_slice(&crc.to_le_bytes());
        cd.extend_from_slice(&lfh_comp.to_le_bytes());
        cd.extend_from_slice(&lfh_uncomp.to_le_bytes());
        cd.extend_from_slice(&(e.raw_name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&(cd_extra.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes()); // comment len
        cd.extend_from_slice(&0u16.to_le_bytes()); // disk start
        cd.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        cd.extend_from_slice(&e.external_attrs.to_le_bytes());
        cd.extend_from_slice(&cd_offset_u32.to_le_bytes());
        cd.extend_from_slice(&e.raw_name);
        cd.extend_from_slice(&cd_extra);
    }

    let cd_offset = out.len() as u64;
    let cd_size = cd.len() as u64;
    out.extend_from_slice(&cd);

    if any_zip64 {
        let z64_eocd_offset = out.len() as u64;
        out.extend_from_slice(&ZIP64_EOCD_SIG.to_le_bytes());
        out.extend_from_slice(&44u64.to_le_bytes());
        out.extend_from_slice(&((3u16 << 8) | 45).to_le_bytes());
        out.extend_from_slice(&45u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());

        out.extend_from_slice(&ZIP64_LOCATOR_SIG.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&z64_eocd_offset.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
    }

    out.extend_from_slice(&EOCD_SIG.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(cd_size as u32).to_le_bytes());
    out.extend_from_slice(&(cd_offset as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());

    fs::write(path, out).map_err(|err| err.to_string())
}

/// Builds an Info-ZIP `0x7075` Unicode Path Extra Field block.
pub fn build_0x7075_block(raw_name: &[u8], unicode_path: &str, tamper_crc: bool) -> Vec<u8> {
    let mut crc = crc32fast::hash(raw_name);
    if tamper_crc {
        crc ^= 0xDEAD_BEEF;
    }
    let uni_bytes = unicode_path.as_bytes();
    let payload_len = (1 + 4 + uni_bytes.len()) as u16;
    let mut block = Vec::with_capacity(4 + payload_len as usize);
    block.extend_from_slice(&0x7075u16.to_le_bytes());
    block.extend_from_slice(&payload_len.to_le_bytes());
    block.push(1u8);
    block.extend_from_slice(&crc.to_le_bytes());
    block.extend_from_slice(uni_bytes);
    block
}

/// Builds a real `.7z` archive from `(relative_path, content)` pairs.
pub fn write_7z_fixture(path: &Path, files: &[(&str, &[u8])]) -> Result<(), String> {
    let mut writer = ArchiveWriter::create(path).map_err(|e| e.to_string())?;
    for (name, bytes) in files {
        let entry = ArchiveEntry::new_file(name);
        writer
            .push_archive_entry(entry, Some(*bytes))
            .map_err(|e| e.to_string())?;
    }
    writer.finish().map_err(|e| e.to_string())?;
    Ok(())
}

/// Builds `.tar.gz`, `.tar.zst`, `.tar.bz2`, or `.tar.xz` fixtures.
pub fn write_tar_fixture(path: &Path, kind: &str, files: &[(&str, &[u8])]) -> Result<(), String> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for (name, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(1_735_689_600);
            header.set_cksum();
            builder
                .append_data(&mut header, name, *data)
                .map_err(|e| e.to_string())?;
        }
        builder.finish().map_err(|e| e.to_string())?;
    }

    let file = File::create(path).map_err(|e| e.to_string())?;
    match kind {
        "tar.gz" => {
            let mut enc = GzEncoder::new(file, Compression::default());
            enc.write_all(&tar_bytes).map_err(|e| e.to_string())?;
            enc.finish().map_err(|e| e.to_string())?;
        }
        "tar.zst" => {
            let mut enc = zstd::stream::write::Encoder::new(file, 3).map_err(|e| e.to_string())?;
            enc.write_all(&tar_bytes).map_err(|e| e.to_string())?;
            enc.finish().map_err(|e| e.to_string())?;
        }
        "tar.bz2" => {
            let mut enc = BzEncoder::new(file, BzCompression::default());
            enc.write_all(&tar_bytes).map_err(|e| e.to_string())?;
            enc.finish().map_err(|e| e.to_string())?;
        }
        "tar.xz" => {
            let mut enc = XzWriter::new(file, XzOptions::default()).map_err(|e| e.to_string())?;
            enc.write_all(&tar_bytes).map_err(|e| e.to_string())?;
            enc.finish().map_err(|e| e.to_string())?;
        }
        other => return Err(format!("unknown tar kind: {other}")),
    }
    Ok(())
}

/// Computes lowercase hex SHA-256 of bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in digest {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

/// Computes SHA-256 of a file on disk.
pub fn sha256_file(path: &Path) -> Result<String, String> {
    let mut f = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in digest {
        hex.push_str(&format!("{b:02x}"));
    }
    Ok(hex)
}

/// Walks a directory and returns a deterministic map of `posix_rel_path -> sha256_hex`.
pub fn hash_directory(root: &Path) -> Result<BTreeMap<String, String>, String> {
    let mut map = BTreeMap::new();
    for entry_res in WalkDir::new(root).follow_links(false) {
        let entry = entry_res.map_err(|e| e.to_string())?;
        if entry.file_type().is_file() {
            let rel = entry
                .path()
                .strip_prefix(root)
                .map_err(|e| e.to_string())?
                .to_string_lossy()
                .replace('\\', "/");
            map.insert(rel, sha256_file(entry.path())?);
        }
    }
    Ok(map)
}

/// Deterministic fast PRNG for generating incompressible random-entropy media fixtures.
pub fn fill_pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut state = seed ^ 0x9E37_79B9_7F4A_7C15;
    for chunk in out.chunks_mut(8) {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        let bytes = z.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    out
}
