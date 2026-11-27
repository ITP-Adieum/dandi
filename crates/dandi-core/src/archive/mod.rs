pub(crate) mod extract_sink;
pub mod format;
pub mod rar_io;
pub mod sevenz;
pub mod split;
pub mod tar_io;
pub mod zip;

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::codec::{EncodingDetection, EncodingId};
use crate::error::Result;
use crate::platform::to_fs_path;
use crate::progress::{CancellationToken, ProgressObserver};
use crate::safety::{is_os_junk, CollisionRename, PathPolicy, SafetyBudget};

pub use format::{detect_format, ArchiveFormat};
pub use split::{
    parse_size_spec, validate_split_size, SplitFileReader, SplitStyle, MIN_SPLIT_SIZE_BYTES,
};
pub use zip::{inspect_zip_raw_headers, parse_zip_raw_headers_from_bytes, RawZipEntryHeader};

/// Output container format for archive creation (`pack`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackFormat {
    #[default]
    Zip,
    SevenZ,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArchiveEntryInfo {
    /// Original index inside the archive (`None` for synthesized implicit directories).
    pub index: Option<usize>,
    /// Decoded, Unicode NFC normalized relative path with POSIX `/` separators.
    pub path: String,
    pub kind: EntryKind,
    pub uncompressed_size: u64,
    pub compressed_size: u64,
    pub modified_unix_secs: Option<i64>,
    pub unix_mode: Option<u32>,
    pub encrypted: bool,
    pub compression_method: String,
    pub is_os_junk: bool,
    pub is_synthesized: bool,
    pub symlink_target: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArchiveSummary {
    pub format: ArchiveFormat,
    pub encoding: EncodingDetection,
    pub applied_encoding: EncodingId,
    pub total_entries: usize,
    pub total_uncompressed_bytes: u64,
    pub total_compressed_bytes: u64,
    pub encrypted: bool,
    pub entries: Vec<ArchiveEntryInfo>,
}

#[derive(Clone, Debug, Default)]
pub struct InspectOptions {
    pub encoding_override: Option<EncodingId>,
    pub locale_hint: Option<EncodingId>,
    pub password: Option<String>,
    pub include_os_junk: bool,
    pub budget: SafetyBudget,
}

#[derive(Clone, Debug)]
pub struct PackOptions {
    /// Target archive container format (`Zip` default, or `SevenZ`).
    pub format: PackFormat,
    /// Compression level (`0..=9`, default `6`).
    pub compression_level: u32,
    /// Skip OS metadata junk (`.DS_Store`, `._*`, `__MACOSX`, `Icon\r`, `Thumbs.db`, `desktop.ini`).
    pub exclude_os_junk: bool,
    /// Optional password for AES-256 encryption (UTF-8 NFC normalized).
    pub password: Option<String>,
    /// Optional maximum split volume size in bytes (minimum 64 KiB when set).
    pub split_size_bytes: Option<u64>,
    /// Volume naming style (`PkwareZip` default for ZIP -> `.z01/.zip`; `Numeric` -> `.001/.002`).
    pub split_style: SplitStyle,
    /// Overwrite destination archive if it already exists.
    pub overwrite: bool,
    /// Cooperative cancellation token.
    pub cancel: CancellationToken,
}

impl Default for PackOptions {
    fn default() -> Self {
        Self {
            format: PackFormat::Zip,
            compression_level: 6,
            exclude_os_junk: true,
            password: None,
            split_size_bytes: None,
            split_style: SplitStyle::PkwareZip,
            overwrite: true,
            cancel: CancellationToken::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackReport {
    pub output_path: PathBuf,
    pub output_volumes: Vec<PathBuf>,
    pub entries_written: usize,
    pub files_deflated: usize,
    pub files_stored: usize,
    pub junk_skipped: usize,
    pub total_input_bytes: u64,
    pub output_bytes: u64,
    pub used_zip64: bool,
    pub encrypted: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractMode {
    /// Single top-level folder → extract directly; multiple top-level items / single file → wrap in `<stem>/`.
    #[default]
    Smart,
    /// Always extract directly into `dest_dir`.
    Direct,
    /// Always wrap extracted contents inside `<dest_dir>/<archive_stem>/`.
    Wrap,
}

#[derive(Clone, Debug)]
pub struct UnpackOptions {
    pub mode: ExtractMode,
    pub encoding_override: Option<EncodingId>,
    pub locale_hint: Option<EncodingId>,
    pub password: Option<String>,
    pub selected_entries: Option<HashSet<usize>>,
    pub exclude_os_junk: bool,
    pub path_policy: PathPolicy,
    pub overwrite: bool,
    pub propagate_zone_identifier: bool,
    pub budget: SafetyBudget,
    pub cancel: CancellationToken,
}

impl Default for UnpackOptions {
    fn default() -> Self {
        Self {
            mode: ExtractMode::Smart,
            encoding_override: None,
            locale_hint: None,
            password: None,
            selected_entries: None,
            exclude_os_junk: true,
            path_policy: PathPolicy::WindowsCompat,
            overwrite: false,
            propagate_zone_identifier: true,
            budget: SafetyBudget::default(),
            cancel: CancellationToken::new(),
        }
    }
}

/// Non-fatal warning recorded during extraction instead of silently discarding OS errors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UnpackWarning {
    SymlinkSkipped {
        path: String,
        target: String,
        reason: String,
    },
    PermissionApplyFailed {
        path: String,
        reason: String,
    },
    MtimeApplyFailed {
        path: String,
        reason: String,
    },
    ZoneIdPropagateFailed {
        path: String,
        reason: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnpackReport {
    pub format: ArchiveFormat,
    pub output_dir: PathBuf,
    pub detected_encoding: EncodingId,
    pub applied_encoding: EncodingId,
    pub files_extracted: usize,
    pub dirs_created: usize,
    pub symlinks_created: usize,
    pub symlinks_skipped: usize,
    pub junk_skipped: usize,
    pub bytes_written: u64,
    pub sanitized_paths: usize,
    pub renamed_collisions: Vec<CollisionRename>,
    pub warnings: Vec<UnpackWarning>,
}

#[derive(Clone, Debug)]
pub struct RepackOptions {
    pub encoding_override: Option<EncodingId>,
    pub locale_hint: Option<EncodingId>,
    pub password: Option<String>,
    pub exclude_os_junk: bool,
    pub compression_level: u32,
    pub overwrite: bool,
    pub budget: SafetyBudget,
    pub cancel: CancellationToken,
}

impl Default for RepackOptions {
    fn default() -> Self {
        Self {
            encoding_override: None,
            locale_hint: None,
            password: None,
            exclude_os_junk: true,
            compression_level: 6,
            overwrite: true,
            budget: SafetyBudget::default(),
            cancel: CancellationToken::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepackReport {
    pub output_path: PathBuf,
    pub source_encoding: EncodingId,
    pub entries_repacked: usize,
    pub junk_skipped: usize,
    pub output_bytes: u64,
}

/// Inspects an archive's contents, format, and corpus-detected encoding without extracting.
pub fn inspect(archive_path: &Path, opts: &InspectOptions) -> Result<ArchiveSummary> {
    let fmt = detect_format(archive_path)?;
    match fmt {
        ArchiveFormat::Zip => zip::inspect_zip(archive_path, opts),
        ArchiveFormat::SevenZ => sevenz::inspect_7z(archive_path, opts),
        ArchiveFormat::Rar => rar_io::inspect_rar(archive_path, opts),
        ArchiveFormat::Tar
        | ArchiveFormat::TarGz
        | ArchiveFormat::TarZst
        | ArchiveFormat::TarBz2
        | ArchiveFormat::TarXz => tar_io::inspect_tar(archive_path, fmt, opts),
    }
}

/// Packs input files/directories into a cross-OS Golden ZIP or `.7z` archive (single or split).
pub fn pack(
    inputs: &[PathBuf],
    output_archive: &Path,
    opts: &PackOptions,
    observer: &dyn ProgressObserver,
) -> Result<PackReport> {
    match opts.format {
        PackFormat::Zip => zip::pack_zip(inputs, output_archive, opts, observer),
        PackFormat::SevenZ => sevenz::pack_7z(inputs, output_archive, opts, observer),
    }
}

/// Unpacks any supported archive (ZIP, 7z, RAR, TAR.*, including split volumes) safely.
pub fn unpack(
    archive_path: &Path,
    dest_dir: &Path,
    opts: &UnpackOptions,
    observer: &dyn ProgressObserver,
) -> Result<UnpackReport> {
    let fmt = detect_format(archive_path)?;
    match fmt {
        ArchiveFormat::Zip => zip::unpack_zip(archive_path, dest_dir, opts, observer),
        ArchiveFormat::SevenZ => sevenz::unpack_7z(archive_path, dest_dir, opts, observer),
        ArchiveFormat::Rar => rar_io::unpack_rar(archive_path, dest_dir, opts, observer),
        ArchiveFormat::Tar
        | ArchiveFormat::TarGz
        | ArchiveFormat::TarZst
        | ArchiveFormat::TarBz2
        | ArchiveFormat::TarXz => tar_io::unpack_tar(archive_path, fmt, dest_dir, opts, observer),
    }
}

/// Rewrites a legacy CP949/Shift_JIS/GBK or macOS NFD ZIP into a clean NFC UTF-8 Golden ZIP.
pub fn repack_nfc(
    src_zip: &Path,
    dst_zip: &Path,
    opts: &RepackOptions,
    observer: &dyn ProgressObserver,
) -> Result<RepackReport> {
    zip::repack_zip_nfc(src_zip, dst_zip, opts, observer)
}

/// Synthesizes missing parent directory entries (`MacPacker#47`) for tree inspection.
pub(crate) fn synthesize_parent_dirs(entries: Vec<ArchiveEntryInfo>) -> Vec<ArchiveEntryInfo> {
    let mut existing_dirs: HashSet<String> = HashSet::new();
    for entry in &entries {
        if entry.kind == EntryKind::Directory {
            existing_dirs.insert(entry.path.trim_end_matches('/').to_string());
        }
    }

    let mut missing_dirs: BTreeSet<String> = BTreeSet::new();
    for entry in &entries {
        let clean = entry.path.trim_end_matches('/');
        let mut cur = clean;
        while let Some((parent, _)) = cur.rsplit_once('/') {
            if parent.is_empty() {
                break;
            }
            if !existing_dirs.contains(parent) {
                missing_dirs.insert(parent.to_string());
            }
            cur = parent;
        }
    }

    if missing_dirs.is_empty() {
        return entries;
    }

    let mut result = Vec::with_capacity(entries.len() + missing_dirs.len());
    for dir in missing_dirs {
        result.push(ArchiveEntryInfo {
            index: None,
            path: format!("{dir}/"),
            kind: EntryKind::Directory,
            uncompressed_size: 0,
            compressed_size: 0,
            modified_unix_secs: None,
            unix_mode: Some(0o040755),
            encrypted: false,
            compression_method: "synthesized".to_string(),
            is_os_junk: is_os_junk(&dir),
            is_synthesized: true,
            symlink_target: None,
        });
    }
    result.extend(entries);
    result
}

/// Extraction target plan produced by Smart Extraction analysis.
#[derive(Clone, Debug)]
pub(crate) struct ExtractPlan {
    /// Physical directory root where entries will be written.
    pub extract_root: PathBuf,
    /// Optional single-root prefix to strip when rewriting a colliding single-root folder.
    pub strip_prefix: Option<String>,
    /// Highest directory created fresh by Dandi (cleaned up completely on error or cancellation).
    pub cleanup_root: Option<PathBuf>,
    /// Reported user-facing output path (the created folder or `dest_dir`).
    pub reported_output_dir: PathBuf,
}

/// Computes the target directory plan for `ExtractMode::Smart`, `Direct`, or `Wrap`.
pub(crate) fn plan_extract_root(
    archive_path: &Path,
    dest_dir: &Path,
    mode: ExtractMode,
    overwrite: bool,
    visible_paths: &[(String, EntryKind)],
) -> Result<ExtractPlan> {
    let dest_exists = to_fs_path(dest_dir).exists();

    let cleanup_for = |target: &Path| -> Option<PathBuf> {
        if !dest_exists {
            Some(dest_dir.to_path_buf())
        } else if !to_fs_path(target).exists() {
            Some(target.to_path_buf())
        } else {
            None
        }
    };

    match mode {
        ExtractMode::Direct => Ok(ExtractPlan {
            extract_root: dest_dir.to_path_buf(),
            strip_prefix: None,
            cleanup_root: cleanup_for(dest_dir),
            reported_output_dir: dest_dir.to_path_buf(),
        }),
        ExtractMode::Wrap => {
            let stem = archive_stem(archive_path);
            let target = resolve_unique_dir(dest_dir, &stem, overwrite);
            Ok(ExtractPlan {
                cleanup_root: cleanup_for(&target),
                extract_root: target.clone(),
                strip_prefix: None,
                reported_output_dir: target,
            })
        }
        ExtractMode::Smart => {
            let mut top_roots: HashSet<String> = HashSet::new();
            let mut single_root_is_dir = false;

            for (norm_path, kind) in visible_paths {
                let trimmed = norm_path.trim_end_matches('/');
                if trimmed.is_empty() {
                    continue;
                }
                match trimmed.split_once('/') {
                    Some((first, _rest)) => {
                        top_roots.insert(first.to_string());
                        single_root_is_dir = true;
                    }
                    None => {
                        top_roots.insert(trimmed.to_string());
                        if *kind == EntryKind::Directory {
                            single_root_is_dir = true;
                        }
                    }
                }
            }

            if top_roots.len() == 1 && single_root_is_dir {
                if let Some(root_name) = top_roots.into_iter().next() {
                    let candidate = dest_dir.join(&root_name);
                    if to_fs_path(&candidate).exists() && !overwrite {
                        // Avoid clobbering existing folder while avoiding double-wrap (`foo/foo/`).
                        let unique = resolve_unique_dir(dest_dir, &root_name, false);
                        return Ok(ExtractPlan {
                            cleanup_root: cleanup_for(&unique),
                            extract_root: unique.clone(),
                            strip_prefix: Some(root_name),
                            reported_output_dir: unique,
                        });
                    }
                    return Ok(ExtractPlan {
                        cleanup_root: cleanup_for(&candidate),
                        extract_root: dest_dir.to_path_buf(),
                        strip_prefix: None,
                        reported_output_dir: candidate,
                    });
                }
            }

            let stem = archive_stem(archive_path);
            let target = resolve_unique_dir(dest_dir, &stem, overwrite);
            Ok(ExtractPlan {
                cleanup_root: cleanup_for(&target),
                extract_root: target.clone(),
                strip_prefix: None,
                reported_output_dir: target,
            })
        }
    }
}

/// Folder name used by `Wrap`/`Smart` extraction; never empty or dots-only (`...part1.rar`
/// would otherwise yield `..` and escape `dest_dir`).
pub(crate) fn archive_stem(archive_path: &Path) -> String {
    let stem = raw_archive_stem(archive_path);
    if stem.trim_matches('.').trim().is_empty() {
        "extracted".to_string()
    } else {
        stem
    }
}

fn raw_archive_stem(archive_path: &Path) -> String {
    let mut file_name = archive_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "extracted".to_string());

    // Strip numeric split suffix (`.001`, `.002`, ...) first.
    if let Some((base, ext)) = file_name.rsplit_once('.') {
        if !base.is_empty() && ext.len() >= 3 && ext.bytes().all(|b| b.is_ascii_digit()) {
            file_name = base.to_string();
        }
    }

    let lower = file_name.to_ascii_lowercase();
    for suffix in [".tar.gz", ".tar.zst", ".tar.bz2", ".tar.xz"] {
        if lower.ends_with(suffix) && file_name.len() > suffix.len() {
            return file_name[..file_name.len() - suffix.len()].to_string();
        }
    }

    // Strip `.partN.rar` multi-volume RAR suffix cleanly (e.g. `bundle.part01.rar` -> `bundle`).
    if lower.ends_with(".rar") && file_name.len() > 4 {
        let without_rar = &file_name[..file_name.len() - 4];
        let lower_wo = &lower[..lower.len() - 4];
        if let Some(pos) = lower_wo.rfind(".part") {
            let digits = &lower_wo[pos + 5..];
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) && pos > 0 {
                return without_rar[..pos].to_string();
            }
        }
        return without_rar.to_string();
    }

    match Path::new(&file_name).file_stem() {
        Some(s) if !s.is_empty() => s.to_string_lossy().into_owned(),
        _ => "extracted".to_string(),
    }
}

fn resolve_unique_dir(parent: &Path, base_name: &str, overwrite: bool) -> PathBuf {
    let initial = parent.join(base_name);
    if overwrite || !to_fs_path(&initial).exists() {
        return initial;
    }
    let mut counter = 2usize;
    loop {
        let candidate = parent.join(format!("{base_name} ({counter})"));
        if !to_fs_path(&candidate).exists() {
            return candidate;
        }
        counter += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_stem_strips_split_and_multi_suffixes() {
        assert_eq!(archive_stem(Path::new("/x/photos.part01.rar")), "photos");
        assert_eq!(archive_stem(Path::new("/x/backup.zip.001")), "backup");
        assert_eq!(archive_stem(Path::new("/x/logs.tar.gz.002")), "logs");
        assert_eq!(archive_stem(Path::new("/x/set.z01")), "set");
    }

    #[test]
    fn archive_stem_never_yields_a_parent_reference() {
        for name in ["...part1.rar", "...tar.gz", "..rar", "...zip.001"] {
            assert_eq!(archive_stem(Path::new(name)), "extracted", "{name}");
        }
    }
}
