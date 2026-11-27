//! Dandi core archive engine.
//!
//! Deep-module public surface re-exporting encoding/normalization (`codec`),
//! filesystem safety (`safety`), unified archive I/O (`archive`),
//! cooperative progress/cancellation (`progress`), and structured errors (`error`).

pub mod archive;
pub mod codec;
pub mod error;
pub mod platform;
pub mod progress;
pub mod safety;

pub use archive::{
    detect_format, inspect, pack, parse_size_spec, repack_nfc, unpack, validate_split_size,
    ArchiveEntryInfo, ArchiveFormat, ArchiveSummary, EntryKind, ExtractMode, InspectOptions,
    PackFormat, PackOptions, PackReport, RepackOptions, RepackReport, SplitFileReader, SplitStyle,
    UnpackOptions, UnpackReport, UnpackWarning, MIN_SPLIT_SIZE_BYTES,
};
pub use codec::{
    decode_entry_name, detect_archive_encoding, normalize_for_pack, supported_encodings,
    DecodeSource, DecodedName, EncodingCandidate, EncodingDetection, EncodingId,
    EntryEncodingFlags,
};
pub use error::{DandiError, Result};
pub use platform::SymlinkOutcome;
pub use progress::{
    CancellationToken, NoopProgressObserver, ProgressEvent, ProgressObserver, ProgressPhase,
    ThrottledProgressObserver,
};
pub use safety::{
    is_os_junk, sanitize_entry_path, validate_symlink_target, CollisionRename, CollisionTracker,
    PathPolicy, SafetyBudget, SanitizedPath,
};
