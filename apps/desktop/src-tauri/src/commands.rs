use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dandi_core::{
    detect_format, inspect, pack, repack_nfc, supported_encodings, unpack, ArchiveSummary,
    CancellationToken, EncodingId, ExtractMode, InspectOptions, PackOptions, PackReport,
    ProgressEvent, ProgressObserver, ProgressPhase, RepackOptions, RepackReport,
    ThrottledProgressObserver, UnpackOptions, UnpackReport,
};
use serde::{Deserialize, Serialize};
use tauri::ipc::Channel;
use tauri::{AppHandle, State};
use tauri_plugin_opener::OpenerExt;

use crate::error::CommandError;
use crate::state::AppState;

static OP_SEQ: AtomicU64 = AtomicU64::new(1);

fn resolve_op_id(requested: Option<String>) -> String {
    match requested {
        Some(id) if !id.trim().is_empty() => id,
        _ => format!("op-{}", OP_SEQ.fetch_add(1, Ordering::Relaxed)),
    }
}

fn parse_encoding_override(raw: Option<String>) -> Result<Option<EncodingId>, CommandError> {
    match raw {
        None => Ok(None),
        Some(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("auto") {
                Ok(None)
            } else {
                EncodingId::from_name(trimmed)
                    .map(Some)
                    .map_err(CommandError::from)
            }
        }
    }
}

fn normalize_password(password: Option<String>) -> Option<String> {
    password.filter(|p| !p.is_empty())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProgressPayload {
    pub op_id: String,
    pub phase: ProgressPhase,
    pub current_entry: String,
    pub entries_done: usize,
    pub entries_total: usize,
    pub bytes_done: u64,
    pub bytes_total: u64,
}

impl ProgressPayload {
    pub fn from_event(op_id: &str, event: &ProgressEvent) -> Self {
        Self {
            op_id: op_id.to_string(),
            phase: event.phase,
            current_entry: event.current_entry.clone(),
            entries_done: event.entries_done,
            entries_total: event.entries_total,
            bytes_done: event.bytes_done,
            bytes_total: event.bytes_total,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncodingOption {
    pub id: EncodingId,
    pub canonical_name: String,
    pub label: String,
    pub region: String,
}

fn describe_encoding(id: EncodingId) -> EncodingOption {
    let (label, region) = match id {
        EncodingId::Utf8 => ("UTF-8", "Unicode"),
        EncodingId::Cp949 => ("CP949 / EUC-KR", "Korean"),
        EncodingId::ShiftJis => ("Shift_JIS (CP932)", "Japanese"),
        EncodingId::Gb18030 => ("GB18030 / GBK", "Simplified Chinese"),
        EncodingId::Big5 => ("Big5 (CP950)", "Traditional Chinese"),
        EncodingId::Windows1251 => ("Windows-1251", "Cyrillic"),
        EncodingId::Ibm866 => ("IBM866 (CP866)", "Cyrillic DOS"),
        EncodingId::Windows1252 => ("Windows-1252", "Western European"),
        EncodingId::Cp437 => ("CP437", "DOS / OEM"),
        EncodingId::Windows1258 => ("Windows-1258", "Vietnamese"),
        EncodingId::Windows874 => ("Windows-874", "Thai"),
    };
    EncodingOption {
        id,
        canonical_name: id.canonical_name().to_string(),
        label: label.to_string(),
        region: region.to_string(),
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PackRequestOptions {
    pub op_id: Option<String>,
    pub compression_level: Option<u32>,
    pub exclude_os_junk: Option<bool>,
    pub password: Option<String>,
    pub overwrite: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct UnpackRequestOptions {
    pub op_id: Option<String>,
    pub mode: Option<ExtractMode>,
    pub encoding_override: Option<String>,
    pub password: Option<String>,
    pub selected_entries: Option<Vec<usize>>,
    pub exclude_os_junk: Option<bool>,
    pub overwrite: Option<bool>,
    pub reveal_after: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct FixRequestOptions {
    pub op_id: Option<String>,
    pub encoding_override: Option<String>,
    pub password: Option<String>,
    pub exclude_os_junk: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum DroppedPathsClassification {
    OpenArchive { path: String },
    PackInputs { paths: Vec<String> },
    Empty,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutputPathKind {
    PackZip,
    FixNfcZip,
    ExtractDir,
}

pub(crate) fn inspect_archive_impl(
    path: &Path,
    encoding_override: Option<String>,
    password: Option<String>,
    include_os_junk: bool,
) -> Result<ArchiveSummary, CommandError> {
    let opts = InspectOptions {
        encoding_override: parse_encoding_override(encoding_override)?,
        password: normalize_password(password),
        include_os_junk,
        ..InspectOptions::default()
    };
    inspect(path, &opts).map_err(CommandError::from)
}

pub(crate) fn pack_archive_impl(
    inputs: &[PathBuf],
    output_zip: &Path,
    options: PackRequestOptions,
    cancel: CancellationToken,
    observer: &dyn ProgressObserver,
) -> Result<PackReport, CommandError> {
    if inputs.is_empty() {
        return Err(CommandError::invalid_input(
            "at least one file or folder is required to create an archive",
        ));
    }
    let opts = PackOptions {
        compression_level: options.compression_level.unwrap_or(6).min(9),
        exclude_os_junk: options.exclude_os_junk.unwrap_or(true),
        password: normalize_password(options.password),
        overwrite: options.overwrite.unwrap_or(true),
        cancel,
    };
    pack(inputs, output_zip, &opts, observer).map_err(CommandError::from)
}

pub(crate) fn unpack_archive_impl(
    archive_path: &Path,
    dest_dir: &Path,
    options: UnpackRequestOptions,
    cancel: CancellationToken,
    observer: &dyn ProgressObserver,
) -> Result<UnpackReport, CommandError> {
    let selected_entries = options
        .selected_entries
        .map(|indices| indices.into_iter().collect::<HashSet<usize>>())
        .filter(|set| !set.is_empty());

    let opts = UnpackOptions {
        mode: options.mode.unwrap_or(ExtractMode::Smart),
        encoding_override: parse_encoding_override(options.encoding_override)?,
        password: normalize_password(options.password),
        selected_entries,
        exclude_os_junk: options.exclude_os_junk.unwrap_or(true),
        overwrite: options.overwrite.unwrap_or(false),
        cancel,
        ..UnpackOptions::default()
    };
    unpack(archive_path, dest_dir, &opts, observer).map_err(CommandError::from)
}

fn resolve_comparable_path(path: &Path) -> PathBuf {
    if let Ok(canon) = std::fs::canonicalize(path) {
        return canon;
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if let (Ok(canon_parent), Some(name)) = (std::fs::canonicalize(parent), path.file_name()) {
        return canon_parent.join(name);
    }
    path.to_path_buf()
}

fn paths_refer_to_same_file(a: &Path, b: &Path) -> bool {
    let ra = resolve_comparable_path(a);
    let rb = resolve_comparable_path(b);
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        ra.to_string_lossy().to_lowercase() == rb.to_string_lossy().to_lowercase()
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        ra == rb
    }
}

pub(crate) fn fix_archive_encoding_impl(
    src_zip: &Path,
    dst_zip: &Path,
    options: FixRequestOptions,
    cancel: CancellationToken,
    observer: &dyn ProgressObserver,
) -> Result<RepackReport, CommandError> {
    if paths_refer_to_same_file(src_zip, dst_zip) {
        return Err(CommandError::invalid_input(
            "Destination ZIP must be a different file from the source archive",
        ));
    }
    let opts = RepackOptions {
        encoding_override: parse_encoding_override(options.encoding_override)?,
        password: normalize_password(options.password),
        exclude_os_junk: options.exclude_os_junk.unwrap_or(true),
        overwrite: true,
        cancel,
        ..RepackOptions::default()
    };
    repack_nfc(src_zip, dst_zip, &opts, observer).map_err(CommandError::from)
}

pub(crate) fn classify_dropped_paths_impl(paths: Vec<String>) -> DroppedPathsClassification {
    let cleaned: Vec<String> = paths
        .into_iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();

    if cleaned.is_empty() {
        return DroppedPathsClassification::Empty;
    }

    if cleaned.len() == 1 {
        let single = &cleaned[0];
        let p = Path::new(single);
        if p.is_file() && detect_format(p).is_ok() {
            return DroppedPathsClassification::OpenArchive {
                path: single.clone(),
            };
        }
    }

    DroppedPathsClassification::PackInputs { paths: cleaned }
}

pub(crate) fn default_output_path_impl(
    inputs: &[String],
    kind: OutputPathKind,
) -> Result<String, CommandError> {
    let first = inputs
        .first()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CommandError::invalid_input("missing input path"))?;

    let path = Path::new(first);
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let out = match kind {
        OutputPathKind::ExtractDir => parent.to_path_buf(),
        OutputPathKind::FixNfcZip => {
            let stem = path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "archive".to_string());
            parent.join(format!("{stem}_nfc.zip"))
        }
        OutputPathKind::PackZip => {
            if inputs.len() == 1 {
                let stem = if path.is_dir() {
                    path.file_name()
                } else {
                    path.file_stem()
                }
                .map(|s| s.to_string_lossy().into_owned())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "archive".to_string());
                parent.join(format!("{stem}.zip"))
            } else {
                parent.join("Archive.zip")
            }
        }
    };

    Ok(out.to_string_lossy().into_owned())
}

#[tauri::command]
pub async fn inspect_archive(
    path: String,
    encoding_override: Option<String>,
    password: Option<String>,
    include_os_junk: Option<bool>,
) -> Result<ArchiveSummary, CommandError> {
    let archive_path = PathBuf::from(path);
    let include_junk = include_os_junk.unwrap_or(false);
    tauri::async_runtime::spawn_blocking(move || {
        inspect_archive_impl(&archive_path, encoding_override, password, include_junk)
    })
    .await
    .map_err(|e| CommandError::internal(format!("background inspect task failed: {e}")))?
}

#[tauri::command]
pub async fn pack_archive(
    inputs: Vec<String>,
    output_zip: String,
    options: Option<PackRequestOptions>,
    on_progress: Channel<ProgressPayload>,
    state: State<'_, AppState>,
) -> Result<PackReport, CommandError> {
    let opts = options.unwrap_or_default();
    let op_id = resolve_op_id(opts.op_id.clone());
    let (cancel, guard) = state.register_operation(op_id.clone());
    let input_paths: Vec<PathBuf> = inputs.into_iter().map(PathBuf::from).collect();
    let output_path = PathBuf::from(output_zip);

    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        let op_id_for_cb = op_id.clone();
        let observer = ThrottledProgressObserver::new(Duration::from_millis(50), move |event| {
            let _ = on_progress.send(ProgressPayload::from_event(&op_id_for_cb, event));
        });
        pack_archive_impl(&input_paths, &output_path, opts, cancel, &observer)
    })
    .await
    .map_err(|e| CommandError::internal(format!("background pack task failed: {e}")))?
}

#[tauri::command]
pub async fn unpack_archive(
    archive_path: String,
    dest_dir: String,
    options: Option<UnpackRequestOptions>,
    on_progress: Channel<ProgressPayload>,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<UnpackReport, CommandError> {
    let opts = options.unwrap_or_default();
    let reveal_after = opts.reveal_after.unwrap_or(false);
    let op_id = resolve_op_id(opts.op_id.clone());
    let (cancel, guard) = state.register_operation(op_id.clone());
    let archive = PathBuf::from(archive_path);
    let dest = PathBuf::from(dest_dir);

    let report = tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        let op_id_for_cb = op_id.clone();
        let observer = ThrottledProgressObserver::new(Duration::from_millis(50), move |event| {
            let _ = on_progress.send(ProgressPayload::from_event(&op_id_for_cb, event));
        });
        unpack_archive_impl(&archive, &dest, opts, cancel, &observer)
    })
    .await
    .map_err(|e| CommandError::internal(format!("background unpack task failed: {e}")))??;

    if reveal_after {
        let _ = app.opener().reveal_item_in_dir(&report.output_dir);
    }

    Ok(report)
}

#[tauri::command]
pub async fn fix_archive_encoding(
    src_zip: String,
    dst_zip: String,
    options: Option<FixRequestOptions>,
    on_progress: Channel<ProgressPayload>,
    state: State<'_, AppState>,
) -> Result<RepackReport, CommandError> {
    let opts = options.unwrap_or_default();
    let resolved_op_id = resolve_op_id(opts.op_id.clone());
    let (cancel, guard) = state.register_operation(resolved_op_id.clone());
    let src = PathBuf::from(src_zip);
    let dst = PathBuf::from(dst_zip);

    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        let op_id_for_cb = resolved_op_id.clone();
        let observer = ThrottledProgressObserver::new(Duration::from_millis(50), move |event| {
            let _ = on_progress.send(ProgressPayload::from_event(&op_id_for_cb, event));
        });
        fix_archive_encoding_impl(&src, &dst, opts, cancel, &observer)
    })
    .await
    .map_err(|e| CommandError::internal(format!("background repack task failed: {e}")))?
}

#[tauri::command]
pub fn cancel_operation(op_id: String, state: State<'_, AppState>) -> bool {
    state.cancel_operation(&op_id)
}

#[tauri::command]
pub fn list_encodings() -> Vec<EncodingOption> {
    supported_encodings()
        .iter()
        .copied()
        .map(describe_encoding)
        .collect()
}

#[tauri::command]
pub async fn classify_dropped_paths(paths: Vec<String>) -> DroppedPathsClassification {
    tauri::async_runtime::spawn_blocking(move || classify_dropped_paths_impl(paths))
        .await
        .unwrap_or(DroppedPathsClassification::Empty)
}

#[tauri::command]
pub fn take_pending_open_paths(state: State<'_, AppState>) -> Vec<String> {
    state.take_pending_open_paths()
}

#[tauri::command]
pub fn default_output_path(
    inputs: Vec<String>,
    kind: OutputPathKind,
) -> Result<String, CommandError> {
    default_output_path_impl(&inputs, kind)
}

#[tauri::command]
pub fn reveal_in_file_manager(path: String, app: AppHandle) -> Result<(), CommandError> {
    app.opener()
        .reveal_item_in_dir(Path::new(&path))
        .map_err(|e| CommandError::internal(format!("failed to reveal path: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;
    use dandi_core::NoopProgressObserver;
    use tempfile::TempDir;

    #[test]
    fn list_encodings_matches_dandi_core_supported_encodings() {
        let listed = list_encodings();
        let core = supported_encodings();
        assert_eq!(listed.len(), core.len());
        for (opt, expected) in listed.iter().zip(core.iter()) {
            assert_eq!(opt.id, *expected);
            assert_eq!(opt.canonical_name, expected.canonical_name());
            assert!(!opt.label.is_empty());
            assert!(!opt.region.is_empty());
        }
    }

    #[test]
    fn parse_encoding_override_handles_auto_and_errors() {
        assert_eq!(parse_encoding_override(None).unwrap(), None);
        assert_eq!(parse_encoding_override(Some("".into())).unwrap(), None);
        assert_eq!(parse_encoding_override(Some("auto".into())).unwrap(), None);
        assert_eq!(
            parse_encoding_override(Some("cp949".into())).unwrap(),
            Some(EncodingId::Cp949)
        );
        let err = parse_encoding_override(Some("definitely-invalid".into())).unwrap_err();
        assert_eq!(err.kind, ErrorKind::UnsupportedEncoding);
    }

    #[test]
    fn pack_inspect_unpack_fix_and_classify_roundtrip() {
        let dir = TempDir::new().unwrap();
        let src_dir = dir.path().join("프로젝트");
        std::fs::create_dir_all(&src_dir).unwrap();
        let file_a = src_dir.join("보고서_최종.txt");
        let file_b = src_dir.join("notes.md");
        std::fs::write(&file_a, "단디 테스트 내용").unwrap();
        std::fs::write(&file_b, "# Hello Dandi\n").unwrap();

        // Classify directory -> PackInputs
        let cls_dir = classify_dropped_paths_impl(vec![src_dir.to_string_lossy().into_owned()]);
        assert!(matches!(
            cls_dir,
            DroppedPathsClassification::PackInputs { .. }
        ));

        // Pack via IPC impl
        let zip_path = dir.path().join("out.zip");
        let pack_report = pack_archive_impl(
            std::slice::from_ref(&src_dir),
            &zip_path,
            PackRequestOptions::default(),
            CancellationToken::new(),
            &NoopProgressObserver,
        )
        .unwrap();
        assert!(pack_report.entries_written >= 2);

        // Classify created ZIP -> OpenArchive
        let cls_zip = classify_dropped_paths_impl(vec![zip_path.to_string_lossy().into_owned()]);
        assert_eq!(
            cls_zip,
            DroppedPathsClassification::OpenArchive {
                path: zip_path.to_string_lossy().into_owned()
            }
        );

        // Inspect via IPC impl
        let summary = inspect_archive_impl(&zip_path, None, None, false).unwrap();
        assert_eq!(summary.applied_encoding, EncodingId::Utf8);
        assert!(summary
            .entries
            .iter()
            .any(|e| e.path.ends_with("보고서_최종.txt")));

        // Fix encoding (repack_nfc) via IPC impl
        let fixed_zip = dir.path().join("out_nfc.zip");
        let fix_report = fix_archive_encoding_impl(
            &zip_path,
            &fixed_zip,
            FixRequestOptions::default(),
            CancellationToken::new(),
            &NoopProgressObserver,
        )
        .unwrap();
        assert!(fix_report.entries_repacked >= 2);

        // Unpack via IPC impl
        let out_dir = dir.path().join("extracted");
        let unpack_report = unpack_archive_impl(
            &fixed_zip,
            &out_dir,
            UnpackRequestOptions {
                mode: Some(ExtractMode::Smart),
                ..UnpackRequestOptions::default()
            },
            CancellationToken::new(),
            &NoopProgressObserver,
        )
        .unwrap();
        assert_eq!(unpack_report.files_extracted, 2);
        assert_eq!(
            std::fs::read_to_string(unpack_report.output_dir.join("보고서_최종.txt")).unwrap(),
            "단디 테스트 내용"
        );
    }

    #[test]
    fn cancelled_token_aborts_pack_cleanly() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("a.txt");
        std::fs::write(&f, "hello").unwrap();
        let out = dir.path().join("cancelled.zip");

        let token = CancellationToken::new();
        token.cancel();

        let err = pack_archive_impl(
            &[f],
            &out,
            PackRequestOptions::default(),
            token,
            &NoopProgressObserver,
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Cancelled);
        assert!(!out.exists());
    }

    #[test]
    fn default_output_paths_are_well_formed() {
        let dir = TempDir::new().unwrap();
        let sample_file = dir.path().join("report.zip");
        std::fs::write(&sample_file, b"").unwrap();
        let s = sample_file.to_string_lossy().into_owned();

        let fix_out =
            default_output_path_impl(std::slice::from_ref(&s), OutputPathKind::FixNfcZip).unwrap();
        assert!(fix_out.ends_with("report_nfc.zip"));

        let ext_out =
            default_output_path_impl(std::slice::from_ref(&s), OutputPathKind::ExtractDir).unwrap();
        assert_eq!(PathBuf::from(ext_out), dir.path());

        let multi_pack = default_output_path_impl(
            &[s, dir.path().join("b.txt").to_string_lossy().into_owned()],
            OutputPathKind::PackZip,
        )
        .unwrap();
        assert!(multi_pack.ends_with("Archive.zip"));

        // Bare relative filename must fall back to "." instead of empty parent.
        let bare = "bare.zip".to_string();
        let bare_ext =
            default_output_path_impl(std::slice::from_ref(&bare), OutputPathKind::ExtractDir)
                .unwrap();
        assert_eq!(bare_ext, ".");
    }

    #[test]
    fn fix_archive_encoding_rejects_in_place_overwrite() {
        let dir = TempDir::new().unwrap();
        let src_file = dir.path().join("hello.txt");
        std::fs::write(&src_file, "hello").unwrap();
        let zip_path = dir.path().join("original.zip");
        pack_archive_impl(
            &[src_file],
            &zip_path,
            PackRequestOptions::default(),
            CancellationToken::new(),
            &NoopProgressObserver,
        )
        .unwrap();

        let err = fix_archive_encoding_impl(
            &zip_path,
            &zip_path,
            FixRequestOptions::default(),
            CancellationToken::new(),
            &NoopProgressObserver,
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidInput);
        assert!(err.message.contains("different file"));
    }
}
