use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use crate::archive::{ArchiveFormat, ExtractPlan, UnpackOptions, UnpackReport, UnpackWarning};
use crate::codec::EncodingId;
use crate::error::{DandiError, Result};
use crate::platform::{
    apply_unix_mode, create_relative_symlink, set_mtime, to_fs_path, write_zone_identifier,
    SymlinkOutcome,
};
use crate::progress::CancellationToken;
use crate::safety::{
    resolve_symlink_steps, sanitize_entry_path, validate_symlink_target, CollisionTracker,
    PathPolicy, SafetyBudget, SanitizedPath,
};

const STREAM_BUF_SIZE: usize = 256 * 1024;

struct PendingSymlink {
    link_rel: PathBuf,
    link_norm: String,
    target: String,
    mtime: Option<i64>,
}

struct DeferredDirMeta {
    dir_path: PathBuf,
    dir_norm: String,
    mtime: i64,
    unix_mode: Option<u32>,
}

/// RAII cleanup guard for an extraction directory created fresh by Dandi.
struct DirCleanupGuard {
    path: Option<PathBuf>,
}

impl DirCleanupGuard {
    fn new(path: Option<PathBuf>) -> Self {
        Self { path }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for DirCleanupGuard {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            let _ = fs::remove_dir_all(to_fs_path(&p));
        }
    }
}

/// Unified deep module responsible for all filesystem writes during archive extraction across
/// ZIP, TAR, and 7z.
///
/// Centralizes path sanitization, case-insensitive collision disambiguation, symlink ancestor
/// & chaining checks, atomic `overwrite: false` enforcement, budgeted streaming writes,
/// cooperative cancellation, metadata/ADS application with structured warnings, deferred Phase-2
/// symlink materialization, and automatic directory rollback on failure.
pub(crate) struct ExtractionSink {
    extract_root: PathBuf,
    strip_prefix: Option<String>,
    reported_output_dir: PathBuf,
    path_policy: PathPolicy,
    overwrite: bool,
    zone_data: Option<Vec<u8>>,
    budget: SafetyBudget,
    cancel: CancellationToken,
    dir_guard: DirCleanupGuard,
    collisions: CollisionTracker,
    symlink_paths_lower: HashSet<String>,
    prevalidated_symlinks: Vec<(PathBuf, String)>,
    pending_symlinks: Vec<PendingSymlink>,
    deferred_dir_meta: Vec<DeferredDirMeta>,
    read_buf: Vec<u8>,
    files_extracted: usize,
    dirs_created: usize,
    symlinks_created: usize,
    symlinks_skipped: usize,
    sanitized_paths: usize,
    warnings: Vec<UnpackWarning>,
}

impl ExtractionSink {
    pub fn new(
        plan: ExtractPlan,
        opts: &UnpackOptions,
        budget: SafetyBudget,
        zone_data: Option<Vec<u8>>,
    ) -> Result<Self> {
        fs::create_dir_all(to_fs_path(&plan.extract_root))
            .map_err(|e| DandiError::io(&plan.extract_root, e))?;
        let dir_guard = DirCleanupGuard::new(plan.cleanup_root);

        Ok(Self {
            extract_root: plan.extract_root,
            strip_prefix: plan.strip_prefix,
            reported_output_dir: plan.reported_output_dir,
            path_policy: opts.path_policy,
            overwrite: opts.overwrite,
            zone_data,
            budget,
            cancel: opts.cancel.clone(),
            dir_guard,
            collisions: CollisionTracker::new(),
            symlink_paths_lower: HashSet::new(),
            prevalidated_symlinks: Vec::new(),
            pending_symlinks: Vec::new(),
            deferred_dir_meta: Vec::new(),
            read_buf: vec![0u8; STREAM_BUF_SIZE],
            files_extracted: 0,
            dirs_created: 0,
            symlinks_created: 0,
            symlinks_skipped: 0,
            sanitized_paths: 0,
            warnings: Vec::new(),
        })
    }

    pub fn reported_output_dir(&self) -> &Path {
        &self.reported_output_dir
    }

    pub fn bytes_written(&self) -> u64 {
        self.budget.bytes_written()
    }

    /// Pre-registers a symlink declared in the archive before any files are extracted,
    /// validating that its target does not escape `extract_root`.
    pub fn register_declared_symlink(&mut self, decoded_path: &str, target: &str) -> Result<()> {
        self.cancel.check()?;
        let Some(eff) = self.prepare_effective_path(decoded_path, false)? else {
            return Ok(());
        };
        validate_symlink_target(&self.extract_root, eff.relative(), target)?;
        self.symlink_paths_lower
            .insert(eff.normalized().to_lowercase());
        self.prevalidated_symlinks
            .push((eff.relative().to_path_buf(), target.to_string()));
        Ok(())
    }

    /// Verifies that no pre-registered archive symlink traverses or chains through another
    /// archive-declared symlink.
    pub fn validate_declared_symlink_chains(&self) -> Result<()> {
        for (link_rel, target) in &self.prevalidated_symlinks {
            check_symlink_chain_safe(link_rel, target, &self.symlink_paths_lower)?;
        }
        Ok(())
    }

    /// Accounts for uncompressed bytes of skipped entries (e.g. solid 7z blocks) in the budget.
    pub fn record_skipped_bytes(&mut self, bytes: u64, compressed_hint: u64) -> Result<()> {
        if bytes > 0 {
            self.budget
                .record_written_bytes(bytes, bytes, compressed_hint)?;
        }
        Ok(())
    }

    /// Creates a sanitized directory entry and schedules bottom-up metadata application.
    pub fn extract_directory(
        &mut self,
        decoded_path: &str,
        mtime: Option<i64>,
        unix_mode: Option<u32>,
    ) -> Result<Option<String>> {
        self.cancel.check()?;
        let Some(eff) = self.prepare_effective_path(decoded_path, true)? else {
            return Ok(None);
        };
        check_not_through_archive_symlink(eff.normalized(), &self.symlink_paths_lower)?;
        self.collisions.register_dir(eff.normalized());

        let out_path = self.extract_root.join(eff.relative());
        ensure_no_symlink_ancestors(&self.extract_root, eff.relative())?;
        fs::create_dir_all(to_fs_path(&out_path)).map_err(|e| DandiError::io(&out_path, e))?;
        self.dirs_created += 1;

        let norm = eff.normalized().to_string();
        if let Some(ts) = mtime {
            self.deferred_dir_meta.push(DeferredDirMeta {
                dir_path: out_path,
                dir_norm: norm.clone(),
                mtime: ts,
                unix_mode,
            });
        } else if let Some(mode) = unix_mode {
            if let Err(e) = apply_unix_mode(&out_path, mode, true) {
                self.warnings.push(UnpackWarning::PermissionApplyFailed {
                    path: norm.clone(),
                    reason: e.to_string(),
                });
            }
        }

        Ok(Some(norm))
    }

    /// Validates and queues a symlink entry for deferred Phase-2 materialization.
    pub fn queue_symlink(
        &mut self,
        decoded_path: &str,
        target: String,
        mtime: Option<i64>,
    ) -> Result<Option<String>> {
        self.cancel.check()?;
        let Some(eff) = self.prepare_effective_path(decoded_path, true)? else {
            return Ok(None);
        };
        let resolved = self.collisions.resolve_file(&eff);
        validate_symlink_target(&self.extract_root, resolved.relative(), &target)?;
        check_symlink_chain_safe(resolved.relative(), &target, &self.symlink_paths_lower)?;

        self.pending_symlinks.push(PendingSymlink {
            link_rel: resolved.relative().to_path_buf(),
            link_norm: resolved.normalized().to_string(),
            target,
            mtime,
        });
        Ok(Some(eff.normalized().to_string()))
    }

    /// Extracts a single regular file entry from `reader` with full safety, budget, atomic
    /// `overwrite: false`, cancellation, and metadata/warning handling.
    #[allow(clippy::too_many_arguments)]
    pub fn extract_file<R, F>(
        &mut self,
        decoded_path: &str,
        reader: &mut R,
        entry_compressed_hint: u64,
        note_live_compressed: bool,
        mtime: Option<i64>,
        unix_mode: Option<u32>,
        map_read_err: F,
    ) -> Result<Option<String>>
    where
        R: Read + ?Sized,
        F: Fn(io::Error) -> DandiError,
    {
        self.cancel.check()?;
        let Some(eff) = self.prepare_effective_path(decoded_path, true)? else {
            return Ok(None);
        };
        check_not_through_archive_symlink(eff.normalized(), &self.symlink_paths_lower)?;

        let resolved = self.collisions.resolve_file(&eff);
        let out_path = self.extract_root.join(resolved.relative());
        if let Some(parent_rel) = resolved.relative().parent() {
            if !parent_rel.as_os_str().is_empty() {
                ensure_no_symlink_ancestors(&self.extract_root, parent_rel)?;
                let parent_abs = self.extract_root.join(parent_rel);
                fs::create_dir_all(to_fs_path(&parent_abs))
                    .map_err(|e| DandiError::io(&parent_abs, e))?;
            }
        }
        ensure_no_symlink_ancestors(&self.extract_root, resolved.relative())?;

        if note_live_compressed {
            self.budget
                .note_live_entry_compressed(entry_compressed_hint);
        }

        let fs_out = to_fs_path(&out_path);
        let out_file = if self.overwrite {
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&fs_out)
                .map_err(|e| DandiError::io(&out_path, e))?
        } else {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&fs_out)
                .map_err(|e| {
                    if e.kind() == io::ErrorKind::AlreadyExists {
                        DandiError::AlreadyExists {
                            path: out_path.clone(),
                        }
                    } else {
                        DandiError::io(&out_path, e)
                    }
                })?
        };

        let mut writer = BufWriter::with_capacity(STREAM_BUF_SIZE, out_file);
        let mut entry_written = 0u64;

        let stream_res: Result<()> = (|| {
            loop {
                self.cancel.check()?;
                let n = match reader.read(&mut self.read_buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => return Err(map_read_err(e)),
                };
                entry_written = entry_written.saturating_add(n as u64);
                self.budget
                    .record_written_bytes(n as u64, entry_written, entry_compressed_hint)?;
                writer
                    .write_all(&self.read_buf[..n])
                    .map_err(|e| DandiError::io(&out_path, e))?;
            }
            writer.flush().map_err(|e| DandiError::io(&out_path, e))?;
            Ok(())
        })();

        drop(writer);
        if let Err(err) = stream_res {
            let _ = fs::remove_file(&fs_out);
            return Err(err);
        }

        let resolved_norm = resolved.normalized().to_string();
        if let Some(mode) = unix_mode {
            if let Err(e) = apply_unix_mode(&out_path, mode, false) {
                self.warnings.push(UnpackWarning::PermissionApplyFailed {
                    path: resolved_norm.clone(),
                    reason: e.to_string(),
                });
            }
        }
        if let Some(ts) = mtime {
            if let Err(e) = set_mtime(&out_path, ts, false) {
                self.warnings.push(UnpackWarning::MtimeApplyFailed {
                    path: resolved_norm.clone(),
                    reason: e.to_string(),
                });
            }
        }
        if let Some(ref zdata) = self.zone_data {
            if let Err(e) = write_zone_identifier(&out_path, zdata) {
                self.warnings.push(UnpackWarning::ZoneIdPropagateFailed {
                    path: resolved_norm,
                    reason: e.to_string(),
                });
            }
        }

        self.files_extracted += 1;
        Ok(Some(eff.normalized().to_string()))
    }

    /// Finalizes extraction: materializes Phase-2 symlinks, applies deferred bottom-up directory
    /// metadata, disarms rollback cleanup, and returns the completed `UnpackReport`.
    pub fn finish(
        mut self,
        format: ArchiveFormat,
        detected_encoding: EncodingId,
        applied_encoding: EncodingId,
        junk_skipped: usize,
    ) -> Result<UnpackReport> {
        // Phase 2: materialize validated safe relative symlinks.
        for sym in std::mem::take(&mut self.pending_symlinks) {
            self.cancel.check()?;
            check_symlink_chain_safe(&sym.link_rel, &sym.target, &self.symlink_paths_lower)?;
            ensure_no_symlink_ancestors(&self.extract_root, &sym.link_rel)?;

            let abs_link = self.extract_root.join(&sym.link_rel);
            let fs_link = to_fs_path(&abs_link);
            if let Some(parent) = abs_link.parent() {
                fs::create_dir_all(to_fs_path(parent)).map_err(|e| DandiError::io(parent, e))?;
            }

            if let Ok(meta) = fs::symlink_metadata(&fs_link) {
                if !self.overwrite {
                    return Err(DandiError::AlreadyExists { path: abs_link });
                }
                if meta.is_dir() && !meta.file_type().is_symlink() {
                    fs::remove_dir_all(&fs_link).map_err(|e| DandiError::io(&abs_link, e))?;
                } else if let Err(e) = fs::remove_file(&fs_link) {
                    // On Windows, a directory symlink must be removed via `remove_dir`.
                    if fs::remove_dir(&fs_link).is_err() {
                        return Err(DandiError::io(&abs_link, e));
                    }
                }
            }

            let target_resolved =
                validate_symlink_target(&self.extract_root, &sym.link_rel, &sym.target)?;
            let target_is_dir = to_fs_path(&target_resolved).is_dir();

            match create_relative_symlink(&abs_link, &sym.target, target_is_dir) {
                Ok(SymlinkOutcome::Created) => {
                    if let Some(ts) = sym.mtime {
                        if let Err(e) = set_mtime(&abs_link, ts, true) {
                            self.warnings.push(UnpackWarning::MtimeApplyFailed {
                                path: sym.link_norm.clone(),
                                reason: e.to_string(),
                            });
                        }
                    }
                    self.symlinks_created += 1;
                }
                Ok(SymlinkOutcome::SkippedPrivilegeNotHeld) => {
                    self.symlinks_skipped += 1;
                    self.warnings.push(UnpackWarning::SymlinkSkipped {
                        path: sym.link_norm,
                        target: sym.target,
                        reason: "symlink privilege not held (ERROR_PRIVILEGE_NOT_HELD 1314)"
                            .to_string(),
                    });
                }
                Err(e) if !self.overwrite && e.kind() == io::ErrorKind::AlreadyExists => {
                    return Err(DandiError::AlreadyExists { path: abs_link });
                }
                Err(e) => return Err(DandiError::io(&abs_link, e)),
            }
        }

        // Apply directory permissions and mtimes bottom-up so child writes don't clobber parent mtimes.
        for meta in std::mem::take(&mut self.deferred_dir_meta)
            .into_iter()
            .rev()
        {
            if let Err(e) = set_mtime(&meta.dir_path, meta.mtime, false) {
                self.warnings.push(UnpackWarning::MtimeApplyFailed {
                    path: meta.dir_norm.clone(),
                    reason: e.to_string(),
                });
            }
            if let Some(mode) = meta.unix_mode {
                if let Err(e) = apply_unix_mode(&meta.dir_path, mode, true) {
                    self.warnings.push(UnpackWarning::PermissionApplyFailed {
                        path: meta.dir_norm,
                        reason: e.to_string(),
                    });
                }
            }
        }

        self.dir_guard.disarm();

        Ok(UnpackReport {
            format,
            output_dir: self.reported_output_dir,
            detected_encoding,
            applied_encoding,
            files_extracted: self.files_extracted,
            dirs_created: self.dirs_created,
            symlinks_created: self.symlinks_created,
            symlinks_skipped: self.symlinks_skipped,
            junk_skipped,
            bytes_written: self.budget.bytes_written(),
            sanitized_paths: self.sanitized_paths,
            renamed_collisions: self.collisions.into_renames(),
            warnings: self.warnings,
        })
    }

    fn prepare_effective_path(
        &mut self,
        decoded_path: &str,
        count_sanitized: bool,
    ) -> Result<Option<SanitizedPath>> {
        let sanitized = sanitize_entry_path(decoded_path, self.path_policy)?;
        if count_sanitized && sanitized.was_sanitized() {
            self.sanitized_paths += 1;
        }
        let eff_str = strip_root_prefix(sanitized.normalized(), self.strip_prefix.as_deref());
        if eff_str.is_empty() {
            return Ok(None);
        }
        let eff = sanitize_entry_path(&eff_str, self.path_policy)?;
        Ok(Some(eff))
    }
}

fn strip_root_prefix(normalized: &str, prefix: Option<&str>) -> String {
    match prefix {
        Some(p) if normalized == p => String::new(),
        Some(p) => normalized
            .strip_prefix(&format!("{p}/"))
            .unwrap_or(normalized)
            .to_string(),
        None => normalized.to_string(),
    }
}

/// Ensures no existing ancestor between `root` and `rel` is a symlink on disk.
fn ensure_no_symlink_ancestors(root: &Path, rel: &Path) -> Result<()> {
    let mut current = root.to_path_buf();
    for comp in rel.components() {
        current.push(comp);
        let fs_cur = to_fs_path(&current);
        if let Ok(meta) = fs::symlink_metadata(&fs_cur) {
            if meta.file_type().is_symlink() {
                return Err(DandiError::UnsafeSymlink {
                    path: rel.to_string_lossy().into_owned(),
                    target: current.display().to_string(),
                    reason: "refusing to traverse or overwrite existing symlink during extraction"
                        .to_string(),
                });
            }
        }
    }
    Ok(())
}

/// Checks if any prefix of `normalized` matches a symlink declared in the archive.
fn check_not_through_archive_symlink(
    normalized: &str,
    symlink_paths_lower: &HashSet<String>,
) -> Result<()> {
    let mut prefix = String::new();
    for (idx, part) in normalized.split('/').enumerate() {
        if idx > 0 {
            prefix.push('/');
        }
        prefix.push_str(&part.to_lowercase());
        if symlink_paths_lower.contains(&prefix) {
            return Err(DandiError::UnsafeSymlink {
                path: normalized.to_string(),
                target: prefix,
                reason: "entry attempts to write through a symlink path in the archive".to_string(),
            });
        }
    }
    Ok(())
}

/// Checks that a symlink's own strict ancestor paths AND its lexically traversed target path
/// do not pass through any archive-declared symlink (blocks multi-hop symlink chaining).
fn check_symlink_chain_safe(
    link_rel: &Path,
    target: &str,
    symlink_paths_lower: &HashSet<String>,
) -> Result<()> {
    let link_norm = link_rel.to_string_lossy().replace('\\', "/");
    let parts: Vec<&str> = link_norm.split('/').collect();
    if parts.len() > 1 {
        let mut prefix = String::new();
        for (idx, part) in parts[..parts.len() - 1].iter().enumerate() {
            if idx > 0 {
                prefix.push('/');
            }
            prefix.push_str(&part.to_lowercase());
            if symlink_paths_lower.contains(&prefix) {
                return Err(DandiError::UnsafeSymlink {
                    path: link_norm,
                    target: target.to_string(),
                    reason: format!(
                        "symlink ancestor '{prefix}' is itself a symlink in the archive"
                    ),
                });
            }
        }
    }

    let (_resolved, traversed_lower) = resolve_symlink_steps(link_rel, target)?;
    for step in traversed_lower {
        if symlink_paths_lower.contains(&step) {
            return Err(DandiError::UnsafeSymlink {
                path: link_norm,
                target: target.to_string(),
                reason: format!("symlink target traverses another symlink '{step}' in the archive"),
            });
        }
    }
    Ok(())
}
