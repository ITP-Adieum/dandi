use std::io;
use std::path::{Path, PathBuf};

/// Converts a filesystem path into an OS-safe path for I/O.
///
/// On Windows, applies the extended-length `\\?\` prefix for paths approaching or exceeding
/// `MAX_PATH` (260 chars) so deep directory trees never fail with `ERROR_PATH_NOT_FOUND`.
pub fn to_fs_path(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        to_windows_extended_path(path)
    }
    #[cfg(not(windows))]
    {
        path.to_path_buf()
    }
}

#[cfg(windows)]
fn to_windows_extended_path(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if raw.starts_with(r"\\?\") {
        return path.to_path_buf();
    }
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path),
            Err(_) => return path.to_path_buf(),
        }
    };
    let normalized = normalize_windows_lexical(&abs);
    let s = normalized.to_string_lossy();
    if s.len() < 240 {
        return normalized;
    }
    if let Some(unc) = s.strip_prefix(r"\\") {
        PathBuf::from(format!(r"\\?\UNC\{unc}"))
    } else {
        PathBuf::from(format!(r"\\?\{s}"))
    }
}

#[cfg(windows)]
fn normalize_windows_lexical(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Applies sanitized Unix file permissions on Unix targets.
///
/// Never applies mode `000`, ensuring extracted files remain readable and directories traversable.
pub fn apply_unix_mode(path: &Path, raw_mode: u32, is_dir: bool) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms_bits = raw_mode & 0o777;
        let safe_mode = if perms_bits == 0 {
            if is_dir {
                0o755
            } else {
                0o644
            }
        } else if is_dir {
            perms_bits | 0o700
        } else {
            perms_bits | 0o600
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(safe_mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, raw_mode, is_dir);
        Ok(())
    }
}

/// Reads Unix permission mode bits for packing, defaulting to `0o100644`/`0o100755`/`0o040755`.
pub fn read_unix_mode_for_pack(metadata: &std::fs::Metadata, is_symlink: bool) -> u32 {
    if is_symlink {
        return 0o120777;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let bits = metadata.permissions().mode() & 0o777;
        if metadata.is_dir() {
            let dir_bits = if bits == 0 { 0o755 } else { bits | 0o700 };
            0o040000 | dir_bits
        } else {
            let file_bits = if bits == 0 {
                0o644
            } else if bits & 0o111 != 0 {
                bits | 0o644
            } else {
                bits | 0o600
            };
            0o100000 | file_bits
        }
    }
    #[cfg(not(unix))]
    {
        if metadata.is_dir() {
            0o040755
        } else {
            0o100644
        }
    }
}

/// Result of attempting to materialize a relative symlink on disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymlinkOutcome {
    /// Symlink was created on disk.
    Created,
    /// Skipped on Windows because the process lacks `SeCreateSymbolicLinkPrivilege`
    /// (`ERROR_PRIVILEGE_NOT_HELD`, error code 1314).
    SkippedPrivilegeNotHeld,
}

/// Creates a relative symlink at `link_path` pointing to `target`.
///
/// Fails with `io::ErrorKind::AlreadyExists` if `link_path` already exists; callers enforcing
/// overwrite policy must explicitly remove existing entries only when `overwrite` is enabled.
pub fn create_relative_symlink(
    link_path: &Path,
    target: &str,
    target_is_dir: bool,
) -> io::Result<SymlinkOutcome> {
    let fs_link = to_fs_path(link_path);
    #[cfg(unix)]
    {
        let _ = target_is_dir;
        std::os::unix::fs::symlink(target, &fs_link)?;
        Ok(SymlinkOutcome::Created)
    }
    #[cfg(windows)]
    {
        let win_target = target.replace('/', "\\");
        let res = if target_is_dir {
            std::os::windows::fs::symlink_dir(&win_target, &fs_link)
        } else {
            std::os::windows::fs::symlink_file(&win_target, &fs_link)
        };
        match res {
            Ok(()) => Ok(SymlinkOutcome::Created),
            // ERROR_PRIVILEGE_NOT_HELD (1314) when Developer Mode is disabled on Windows
            Err(err) if err.raw_os_error() == Some(1314) => {
                Ok(SymlinkOutcome::SkippedPrivilegeNotHeld)
            }
            Err(err) => Err(err),
        }
    }
}

/// Sets file modification time in UTC Unix seconds.
#[allow(deprecated)]
pub fn set_mtime(path: &Path, unix_secs: i64, is_symlink: bool) -> io::Result<()> {
    let fs_path = to_fs_path(path);
    let ft = filetime::FileTime::from_unix_time(unix_secs, 0);
    if is_symlink {
        filetime::set_symlink_file_times(&fs_path, ft, ft)
    } else {
        filetime::set_file_mtime(&fs_path, ft)
    }
}

/// Reads the Windows Mark-of-the-Web (`Zone.Identifier`) Alternate Data Stream, if present.
pub fn read_zone_identifier(archive_path: &Path) -> Option<Vec<u8>> {
    #[cfg(windows)]
    {
        let fs_path = to_fs_path(archive_path);
        let mut ads = fs_path.into_os_string();
        ads.push(":Zone.Identifier");
        std::fs::read(PathBuf::from(ads)).ok()
    }
    #[cfg(not(windows))]
    {
        let _ = archive_path;
        None
    }
}

/// Propagates a `Zone.Identifier` ADS onto an extracted file on Windows.
pub fn write_zone_identifier(target_path: &Path, zone_data: &[u8]) -> io::Result<()> {
    #[cfg(windows)]
    {
        let fs_path = to_fs_path(target_path);
        let mut ads = fs_path.into_os_string();
        ads.push(":Zone.Identifier");
        std::fs::write(PathBuf::from(ads), zone_data)
    }
    #[cfg(not(windows))]
    {
        let _ = (target_path, zone_data);
        Ok(())
    }
}
