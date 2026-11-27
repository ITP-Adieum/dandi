use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use crate::error::{DandiError, Result};

/// Controls filesystem sanitization rules applied during archive extraction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathPolicy {
    /// Applies Windows-compatible sanitization across all OSes (safe for cloud sync & SMB).
    #[default]
    WindowsCompat,
    /// Applies Windows rules on Windows and POSIX-safe rules on Unix.
    Native,
}

impl PathPolicy {
    fn enforce_windows_rules(self) -> bool {
        match self {
            Self::WindowsCompat => true,
            Self::Native => cfg!(windows),
        }
    }
}

/// Sanitized relative path ready for safe extraction inside a target directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SanitizedPath {
    /// Clean relative path using POSIX `/` separators.
    pub normalized: String,
    /// Native relative `PathBuf` built from sanitized path components.
    pub relative: PathBuf,
    /// True if any segment was modified by Windows-compatibility sanitization.
    pub was_sanitized: bool,
}

/// Records a case-insensitive filename collision that was deterministically disambiguated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollisionRename {
    pub original: String,
    pub resolved: String,
}

/// Validates and sanitizes an archive entry path against Zip Slip and OS filesystem hazards.
///
/// Always rejects traversal (`..`), root prefixes (`/`), drive letters (`C:`), UNC paths (`\\`),
/// and NUL bytes *before* applying character sanitization.
pub fn sanitize_entry_path(raw_relative: &str, policy: PathPolicy) -> Result<SanitizedPath> {
    if raw_relative.contains('\0') {
        return Err(DandiError::UnsafePath {
            path: raw_relative.to_string(),
            reason: "contains NUL byte".to_string(),
        });
    }

    if raw_relative.starts_with('/') || raw_relative.starts_with('\\') {
        return Err(DandiError::UnsafePath {
            path: raw_relative.to_string(),
            reason: "absolute or UNC path is not permitted".to_string(),
        });
    }

    // Detect Windows drive prefixes like `C:\...`, `C:/...`, or `C:` BEFORE any character sanitization.
    // Note: filenames like `a:b*c?.txt` (colon not followed by `/` or `\`) are sanitized under WindowsCompat.
    let bytes = raw_relative.as_bytes();
    if bytes.len() >= 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes.len() == 2 || bytes[2] == b'/' || bytes[2] == b'\\')
    {
        return Err(DandiError::UnsafePath {
            path: raw_relative.to_string(),
            reason: "Windows drive prefix is not permitted".to_string(),
        });
    }

    let nfc: String = raw_relative.nfc().collect();
    let mut clean_segments: Vec<String> = Vec::new();
    let mut was_sanitized = false;
    let win_rules = policy.enforce_windows_rules();

    for raw_seg in nfc.split(['/', '\\']) {
        if raw_seg.is_empty() || raw_seg == "." {
            continue;
        }
        if raw_seg == ".." {
            return Err(DandiError::UnsafePath {
                path: raw_relative.to_string(),
                reason: "parent directory traversal ('..') is not permitted".to_string(),
            });
        }

        // Also reject drive-letter-like segments embedded in a path (e.g., `a/C:/b`).
        let sb = raw_seg.as_bytes();
        if sb.len() >= 2 && sb[0].is_ascii_alphabetic() && sb[1] == b':' && !win_rules {
            return Err(DandiError::UnsafePath {
                path: raw_relative.to_string(),
                reason: "drive-letter segment is not permitted".to_string(),
            });
        }

        let seg = if win_rules {
            let (s, changed) = sanitize_windows_segment(raw_seg);
            if changed {
                was_sanitized = true;
            }
            s
        } else {
            raw_seg.to_string()
        };

        if seg == "." || seg == ".." || seg.is_empty() {
            return Err(DandiError::UnsafePath {
                path: raw_relative.to_string(),
                reason: "segment resolved to unsafe component".to_string(),
            });
        }

        clean_segments.push(seg);
    }

    if clean_segments.is_empty() {
        return Err(DandiError::UnsafePath {
            path: raw_relative.to_string(),
            reason: "entry path contains no valid path segments".to_string(),
        });
    }

    let normalized = clean_segments.join("/");
    let mut relative = PathBuf::new();
    for seg in &clean_segments {
        relative.push(seg);
    }

    Ok(SanitizedPath {
        normalized,
        relative,
        was_sanitized,
    })
}

fn sanitize_windows_segment(segment: &str) -> (String, bool) {
    let mut out = String::with_capacity(segment.len());
    let mut changed = false;

    for ch in segment.chars() {
        let is_illegal =
            matches!(ch, ':' | '*' | '?' | '"' | '<' | '>' | '|') || ((ch as u32) <= 0x1F);
        if is_illegal {
            out.push('_');
            changed = true;
        } else {
            out.push(ch);
        }
    }

    // Strip trailing dots and spaces (forbidden on Windows NTFS/FAT).
    let trimmed = out.trim_end_matches(['.', ' ']);
    if trimmed.len() != out.len() {
        changed = true;
        out = trimmed.to_string();
    }

    if out.is_empty() {
        return ("_".to_string(), true);
    }

    if is_windows_reserved_name(&out) {
        out.insert(0, '_');
        changed = true;
    }

    (out, changed)
}

fn is_windows_reserved_name(segment: &str) -> bool {
    let stem = segment.split('.').next().unwrap_or(segment);
    let upper = stem.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

/// Validates that a symlink at `link_rel` pointing to `target` resolves strictly inside `dest_root`.
pub fn validate_symlink_target(dest_root: &Path, link_rel: &Path, target: &str) -> Result<PathBuf> {
    let link_display = link_rel.to_string_lossy().into_owned();
    if target.is_empty() {
        return Err(DandiError::UnsafeSymlink {
            path: link_display,
            target: target.to_string(),
            reason: "symlink target is empty".to_string(),
        });
    }
    if target.contains('\0') {
        return Err(DandiError::UnsafeSymlink {
            path: link_display,
            target: target.to_string(),
            reason: "symlink target contains NUL byte".to_string(),
        });
    }
    if target.starts_with('/') || target.starts_with('\\') {
        return Err(DandiError::UnsafeSymlink {
            path: link_display,
            target: target.to_string(),
            reason: "absolute symlink targets are not permitted".to_string(),
        });
    }
    let tb = target.as_bytes();
    if tb.len() >= 2 && tb[0].is_ascii_alphabetic() && tb[1] == b':' {
        return Err(DandiError::UnsafeSymlink {
            path: link_display,
            target: target.to_string(),
            reason: "drive-letter symlink targets are not permitted".to_string(),
        });
    }

    let mut stack: Vec<String> = Vec::new();
    if let Some(parent) = link_rel.parent() {
        for comp in parent.components() {
            match comp {
                Component::Normal(s) => stack.push(s.to_string_lossy().into_owned()),
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(DandiError::UnsafeSymlink {
                        path: link_display,
                        target: target.to_string(),
                        reason: "symlink path itself is not strictly relative".to_string(),
                    });
                }
            }
        }
    }

    for seg in target.split(['/', '\\']) {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            if stack.pop().is_none() {
                return Err(DandiError::UnsafeSymlink {
                    path: link_display,
                    target: target.to_string(),
                    reason: "symlink target escapes extraction root".to_string(),
                });
            }
        } else {
            stack.push(seg.to_string());
        }
    }

    let mut resolved = dest_root.to_path_buf();
    for seg in stack {
        resolved.push(seg);
    }
    Ok(resolved)
}

/// Detects macOS and Windows OS metadata junk paths (`__MACOSX/`, `.DS_Store`, `._*`, `Icon\r`, `Thumbs.db`, `desktop.ini`).
pub fn is_os_junk(rel_path: &str) -> bool {
    let trimmed = rel_path.trim_end_matches(['/', '\\']);
    if trimmed.is_empty() {
        return false;
    }

    let mut last_seg = "";
    for seg in trimmed.split(['/', '\\']) {
        if seg.is_empty() {
            continue;
        }
        if seg == "__MACOSX" {
            return true;
        }
        last_seg = seg;
    }

    if last_seg == ".DS_Store" || last_seg == "Icon\r" {
        return true;
    }
    if last_seg.starts_with("._") && last_seg.len() > 2 {
        return true;
    }
    let lower = last_seg.to_ascii_lowercase();
    lower == "thumbs.db" || lower == "desktop.ini"
}

/// Tracks extracted relative paths case-insensitively to prevent silent overwrites on APFS/NTFS.
#[derive(Clone, Debug, Default)]
pub struct CollisionTracker {
    seen_files: HashSet<String>,
    seen_dirs: HashSet<String>,
    renames: Vec<CollisionRename>,
}

impl CollisionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a directory path (directories merge cleanly by lowercase path).
    pub fn register_dir(&mut self, normalized: &str) {
        self.seen_dirs.insert(normalized.to_lowercase());
    }

    /// Resolves a file or symlink path, deterministically suffixing colliding names (`name (2).ext`).
    pub fn resolve_file(&mut self, sanitized: &SanitizedPath) -> PathBuf {
        let lower = sanitized.normalized.to_lowercase();
        if !self.seen_files.contains(&lower) {
            self.seen_files.insert(lower);
            return sanitized.relative.clone();
        }

        let (dir_prefix, file_name) = match sanitized.normalized.rsplit_once('/') {
            Some((d, f)) => (Some(d), f),
            None => (None, sanitized.normalized.as_str()),
        };
        let (stem, ext) = split_stem_ext(file_name);

        let mut counter = 2usize;
        loop {
            let candidate_name = match ext {
                Some(e) => format!("{stem} ({counter}).{e}"),
                None => format!("{stem} ({counter})"),
            };
            let candidate_norm = match dir_prefix {
                Some(d) => format!("{d}/{candidate_name}"),
                None => candidate_name.clone(),
            };
            let candidate_lower = candidate_norm.to_lowercase();
            if !self.seen_files.contains(&candidate_lower) {
                self.seen_files.insert(candidate_lower);
                self.renames.push(CollisionRename {
                    original: sanitized.normalized.clone(),
                    resolved: candidate_norm.clone(),
                });
                let mut rel = PathBuf::new();
                for seg in candidate_norm.split('/') {
                    rel.push(seg);
                }
                return rel;
            }
            counter += 1;
        }
    }

    pub fn into_renames(self) -> Vec<CollisionRename> {
        self.renames
    }
}

fn split_stem_ext(file_name: &str) -> (&str, Option<&str>) {
    match file_name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() => (stem, Some(ext)),
        _ => (file_name, None),
    }
}

/// Checked-arithmetic guard against Zip Bombs and unbounded archive expansion.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SafetyBudget {
    pub max_total_bytes: u64,
    pub max_entries: usize,
    pub max_compression_ratio: f64,
    pub ratio_check_threshold_bytes: u64,
    #[serde(skip)]
    entries_seen: usize,
    #[serde(skip)]
    bytes_written: u64,
}

impl Default for SafetyBudget {
    fn default() -> Self {
        Self {
            max_total_bytes: 64 * 1024 * 1024 * 1024, // 64 GiB
            max_entries: 500_000,
            max_compression_ratio: 200.0,
            ratio_check_threshold_bytes: 10 * 1024 * 1024, // 10 MiB
            entries_seen: 0,
            bytes_written: 0,
        }
    }
}

impl SafetyBudget {
    pub fn new(
        max_total_bytes: u64,
        max_entries: usize,
        max_compression_ratio: f64,
        ratio_check_threshold_bytes: u64,
    ) -> Self {
        Self {
            max_total_bytes,
            max_entries,
            max_compression_ratio,
            ratio_check_threshold_bytes,
            entries_seen: 0,
            bytes_written: 0,
        }
    }

    pub fn record_entry(
        &mut self,
        declared_uncompressed: u64,
        declared_compressed: u64,
    ) -> Result<()> {
        self.entries_seen =
            self.entries_seen
                .checked_add(1)
                .ok_or_else(|| DandiError::BudgetExceeded {
                    reason: "entry count overflow".to_string(),
                })?;
        if self.entries_seen > self.max_entries {
            return Err(DandiError::BudgetExceeded {
                reason: format!(
                    "entry count {} exceeds limit {}",
                    self.entries_seen, self.max_entries
                ),
            });
        }
        if declared_uncompressed > self.max_total_bytes {
            return Err(DandiError::BudgetExceeded {
                reason: format!(
                    "declared entry size {declared_uncompressed} bytes exceeds limit {} bytes",
                    self.max_total_bytes
                ),
            });
        }
        if declared_uncompressed >= self.ratio_check_threshold_bytes {
            let denom = declared_compressed.max(1) as f64;
            let ratio = (declared_uncompressed as f64) / denom;
            if ratio > self.max_compression_ratio {
                return Err(DandiError::BudgetExceeded {
                    reason: format!(
                        "declared compression ratio {ratio:.1}x exceeds limit {:.1}x",
                        self.max_compression_ratio
                    ),
                });
            }
        }
        Ok(())
    }

    pub fn record_written_bytes(
        &mut self,
        delta: u64,
        entry_written: u64,
        entry_compressed_hint: u64,
    ) -> Result<()> {
        self.bytes_written =
            self.bytes_written
                .checked_add(delta)
                .ok_or_else(|| DandiError::BudgetExceeded {
                    reason: "total extracted bytes overflow".to_string(),
                })?;
        if self.bytes_written > self.max_total_bytes {
            return Err(DandiError::BudgetExceeded {
                reason: format!(
                    "extracted bytes {} exceed limit {}",
                    self.bytes_written, self.max_total_bytes
                ),
            });
        }
        if entry_written >= self.ratio_check_threshold_bytes && entry_compressed_hint > 0 {
            let ratio = (entry_written as f64) / (entry_compressed_hint as f64);
            if ratio > self.max_compression_ratio {
                return Err(DandiError::BudgetExceeded {
                    reason: format!(
                        "live compression ratio {ratio:.1}x exceeds limit {:.1}x",
                        self.max_compression_ratio
                    ),
                });
            }
        }
        Ok(())
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zip_slip_vectors() {
        for bad in [
            "../evil.txt",
            "a/../../evil.txt",
            "/etc/evil",
            r"C:\Windows\evil.dll",
            r"..\evil.txt",
            r"\\server\share\evil.txt",
            "ok/bad\0name.txt",
        ] {
            let res = sanitize_entry_path(bad, PathPolicy::WindowsCompat);
            assert!(
                matches!(res, Err(DandiError::UnsafePath { .. })),
                "expected UnsafePath for {bad:?}, got {res:?}"
            );
        }
    }

    #[test]
    fn sanitizes_windows_hazards() {
        let s1 = sanitize_entry_path("a:b*c?.txt", PathPolicy::WindowsCompat).unwrap();
        assert_eq!(s1.normalized, "a_b_c_.txt");
        assert!(s1.was_sanitized);

        let s2 = sanitize_entry_path("CON.txt", PathPolicy::WindowsCompat).unwrap();
        assert_eq!(s2.normalized, "_CON.txt");

        let s3 = sanitize_entry_path("dir/NUL", PathPolicy::WindowsCompat).unwrap();
        assert_eq!(s3.normalized, "dir/_NUL");

        let s4 = sanitize_entry_path("trailing. ", PathPolicy::WindowsCompat).unwrap();
        assert_eq!(s4.normalized, "trailing");
    }

    #[test]
    fn validates_symlinks_strictly() {
        let root = Path::new("/tmp/extract");
        assert!(
            validate_symlink_target(root, Path::new("app/Contents/link"), "../Resources/a").is_ok()
        );
        assert!(matches!(
            validate_symlink_target(root, Path::new("out"), "/tmp"),
            Err(DandiError::UnsafeSymlink { .. })
        ));
        assert!(matches!(
            validate_symlink_target(root, Path::new("a/link"), "../../outside"),
            Err(DandiError::UnsafeSymlink { .. })
        ));
    }

    #[test]
    fn detects_os_junk() {
        assert!(is_os_junk("__MACOSX/foo/._bar.txt"));
        assert!(is_os_junk("project/.DS_Store"));
        assert!(is_os_junk("project/._report.pdf"));
        assert!(is_os_junk("project/Icon\r"));
        assert!(is_os_junk("folder/Thumbs.db"));
        assert!(is_os_junk("folder/desktop.ini"));
        assert!(!is_os_junk("project/README.md"));
        assert!(!is_os_junk("project/.gitignore"));
    }

    #[test]
    fn disambiguates_case_collisions() {
        let mut tracker = CollisionTracker::new();
        let a = sanitize_entry_path("docs/Readme.md", PathPolicy::WindowsCompat).unwrap();
        let b = sanitize_entry_path("docs/README.md", PathPolicy::WindowsCompat).unwrap();
        assert_eq!(tracker.resolve_file(&a), PathBuf::from("docs/Readme.md"));
        assert_eq!(
            tracker.resolve_file(&b),
            PathBuf::from("docs/README (2).md")
        );
        assert_eq!(tracker.into_renames().len(), 1);
    }

    #[test]
    fn enforces_zip_bomb_budget() {
        let mut budget = SafetyBudget {
            max_total_bytes: 5 * 1024 * 1024,
            max_entries: 100,
            max_compression_ratio: 100.0,
            ratio_check_threshold_bytes: 1024 * 1024,
            ..SafetyBudget::default()
        };
        let res = budget.record_entry(100 * 1024 * 1024, 100 * 1024);
        assert!(matches!(res, Err(DandiError::BudgetExceeded { .. })));
    }
}
