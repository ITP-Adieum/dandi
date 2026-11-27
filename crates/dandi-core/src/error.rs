use std::path::PathBuf;

use thiserror::Error;

/// Convenience result alias for all `dandi-core` operations.
pub type Result<T> = std::result::Result<T, DandiError>;

/// Structured error type for `dandi-core`.
#[derive(Debug, Error)]
pub enum DandiError {
    #[error("I/O error{}: {source}", path.as_ref().map(|p| format!(" at '{}'", p.display())).unwrap_or_default())]
    Io {
        path: Option<PathBuf>,
        #[source]
        source: std::io::Error,
    },

    #[error("unsupported archive format: {0}")]
    UnsupportedFormat(String),

    #[error("corrupt or invalid archive: {0}")]
    CorruptArchive(String),

    #[error("invalid archive password")]
    InvalidPassword,

    #[error("archive is encrypted and requires a password")]
    PasswordRequired,

    #[error("unsafe archive entry path '{path}': {reason}")]
    UnsafePath { path: String, reason: String },

    #[error("unsafe symlink '{path}' -> '{target}': {reason}")]
    UnsafeSymlink {
        path: String,
        target: String,
        reason: String,
    },

    #[error("safety budget exceeded: {reason}")]
    BudgetExceeded { reason: String },

    #[error("operation cancelled")]
    Cancelled,

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("unsupported encoding '{0}'")]
    UnsupportedEncoding(String),

    #[error("archive engine error: {0}")]
    ArchiveEngine(String),
}

impl DandiError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: Some(path.into()),
            source,
        }
    }

    pub fn io_plain(source: std::io::Error) -> Self {
        Self::Io { path: None, source }
    }
}

impl From<std::io::Error> for DandiError {
    fn from(source: std::io::Error) -> Self {
        Self::Io { path: None, source }
    }
}
