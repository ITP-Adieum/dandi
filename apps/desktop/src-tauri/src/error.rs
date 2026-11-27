use dandi_core::DandiError;
use serde::{Deserialize, Serialize};

/// Structured error category serialized across the Tauri IPC boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Io,
    UnsupportedFormat,
    CorruptArchive,
    InvalidPassword,
    PasswordRequired,
    UnsafePath,
    UnsafeSymlink,
    BudgetExceeded,
    Cancelled,
    AlreadyExists,
    InvalidInput,
    UnsupportedEncoding,
    ArchiveEngine,
    Internal,
}

/// Serializable error returned by every Tauri command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandError {
    pub kind: ErrorKind,
    pub message: String,
}

impl CommandError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidInput, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Internal, message)
    }
}

impl From<DandiError> for CommandError {
    fn from(err: DandiError) -> Self {
        let kind = match &err {
            DandiError::Io { .. } => ErrorKind::Io,
            DandiError::UnsupportedFormat(_) => ErrorKind::UnsupportedFormat,
            DandiError::CorruptArchive(_) => ErrorKind::CorruptArchive,
            DandiError::InvalidPassword => ErrorKind::InvalidPassword,
            DandiError::PasswordRequired => ErrorKind::PasswordRequired,
            DandiError::UnsafePath { .. } => ErrorKind::UnsafePath,
            DandiError::UnsafeSymlink { .. } => ErrorKind::UnsafeSymlink,
            DandiError::BudgetExceeded { .. } => ErrorKind::BudgetExceeded,
            DandiError::Cancelled => ErrorKind::Cancelled,
            DandiError::AlreadyExists { .. } => ErrorKind::AlreadyExists,
            DandiError::InvalidInput(_) => ErrorKind::InvalidInput,
            DandiError::UnsupportedEncoding(_) => ErrorKind::UnsupportedEncoding,
            DandiError::ArchiveEngine(_) => ErrorKind::ArchiveEngine,
        };
        Self {
            kind,
            message: err.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_all_dandi_error_variants_cleanly() {
        let cases: Vec<(DandiError, ErrorKind)> = vec![
            (
                DandiError::io_plain(std::io::Error::new(std::io::ErrorKind::NotFound, "missing")),
                ErrorKind::Io,
            ),
            (
                DandiError::UnsupportedFormat("foo.bin".into()),
                ErrorKind::UnsupportedFormat,
            ),
            (
                DandiError::CorruptArchive("bad crc".into()),
                ErrorKind::CorruptArchive,
            ),
            (DandiError::InvalidPassword, ErrorKind::InvalidPassword),
            (DandiError::PasswordRequired, ErrorKind::PasswordRequired),
            (
                DandiError::UnsafePath {
                    path: "../evil".into(),
                    reason: "traversal".into(),
                },
                ErrorKind::UnsafePath,
            ),
            (
                DandiError::UnsafeSymlink {
                    path: "link".into(),
                    target: "/etc".into(),
                    reason: "escape".into(),
                },
                ErrorKind::UnsafeSymlink,
            ),
            (
                DandiError::BudgetExceeded {
                    reason: "ratio".into(),
                },
                ErrorKind::BudgetExceeded,
            ),
            (DandiError::Cancelled, ErrorKind::Cancelled),
            (
                DandiError::AlreadyExists {
                    path: std::path::PathBuf::from("existing.txt"),
                },
                ErrorKind::AlreadyExists,
            ),
            (
                DandiError::InvalidInput("empty".into()),
                ErrorKind::InvalidInput,
            ),
            (
                DandiError::UnsupportedEncoding("xyz".into()),
                ErrorKind::UnsupportedEncoding,
            ),
            (
                DandiError::ArchiveEngine("boom".into()),
                ErrorKind::ArchiveEngine,
            ),
        ];

        for (src, expected_kind) in cases {
            let mapped = CommandError::from(src);
            assert_eq!(mapped.kind, expected_kind);
            assert!(!mapped.message.is_empty());
        }
    }
}
