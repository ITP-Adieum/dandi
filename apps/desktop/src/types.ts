export type ArchiveFormat =
  | "zip"
  | "seven_z"
  | "rar"
  | "tar"
  | "tar_gz"
  | "tar_zst"
  | "tar_bz2"
  | "tar_xz";

export type EntryKind = "file" | "directory" | "symlink";

export type ExtractMode = "smart" | "direct" | "wrap";

export type EncodingId =
  | "utf8"
  | "cp949"
  | "shift_jis"
  | "gb18030"
  | "big5"
  | "windows1251"
  | "ibm866"
  | "windows1252"
  | "cp437"
  | "windows1258"
  | "windows874";

export interface EncodingCandidate {
  encoding: EncodingId;
  score: number;
  had_errors: boolean;
}

export interface EncodingDetection {
  encoding: EncodingId;
  confidence: number;
  candidates: EncodingCandidate[];
}

export interface EncodingOption {
  id: EncodingId;
  canonical_name: string;
  label: string;
  region: string;
}

export interface ArchiveEntryInfo {
  index: number | null;
  path: string;
  kind: EntryKind;
  uncompressed_size: number;
  compressed_size: number;
  modified_unix_secs: number | null;
  unix_mode: number | null;
  encrypted: boolean;
  compression_method: string;
  is_os_junk: boolean;
  is_synthesized: boolean;
  symlink_target: string | null;
}

export interface ArchiveSummary {
  format: ArchiveFormat;
  encoding: EncodingDetection;
  applied_encoding: EncodingId;
  total_entries: number;
  total_uncompressed_bytes: number;
  total_compressed_bytes: number;
  encrypted: boolean;
  entries: ArchiveEntryInfo[];
}

export type ProgressPhase =
  | "scanning"
  | "packing"
  | "unpacking"
  | "repacking"
  | "finalizing";

export interface ProgressPayload {
  op_id: string;
  phase: ProgressPhase;
  current_entry: string;
  entries_done: number;
  entries_total: number;
  bytes_done: number;
  bytes_total: number;
}

export type PackFormat = "zip" | "seven_z";

export type SplitStyle = "pkware_zip" | "numeric";

export interface PackReport {
  output_path: string;
  output_volumes: string[];
  entries_written: number;
  files_deflated: number;
  files_stored: number;
  junk_skipped: number;
  total_input_bytes: number;
  output_bytes: number;
  used_zip64: boolean;
  encrypted: boolean;
}

export interface CollisionRename {
  original: string;
  resolved: string;
}

export type UnpackWarning =
  | { kind: "symlink_skipped"; path: string; target: string; reason: string }
  | { kind: "permission_apply_failed"; path: string; reason: string }
  | { kind: "mtime_apply_failed"; path: string; reason: string }
  | { kind: "zone_id_propagate_failed"; path: string; reason: string };

export interface UnpackReport {
  format: ArchiveFormat;
  output_dir: string;
  detected_encoding: EncodingId;
  applied_encoding: EncodingId;
  files_extracted: number;
  dirs_created: number;
  symlinks_created: number;
  symlinks_skipped?: number;
  junk_skipped: number;
  bytes_written: number;
  sanitized_paths: number;
  renamed_collisions: CollisionRename[];
  warnings?: UnpackWarning[];
}

export interface RepackReport {
  output_path: string;
  source_encoding: EncodingId;
  entries_repacked: number;
  junk_skipped: number;
  output_bytes: number;
}

export type ErrorKind =
  | "io"
  | "unsupported_format"
  | "corrupt_archive"
  | "invalid_password"
  | "password_required"
  | "unsafe_path"
  | "unsafe_symlink"
  | "budget_exceeded"
  | "cancelled"
  | "already_exists"
  | "invalid_input"
  | "unsupported_encoding"
  | "archive_engine"
  | "internal";

export interface CommandError {
  kind: ErrorKind;
  message: string;
}

export type DroppedPathsClassification =
  | { action: "open_archive"; path: string }
  | { action: "pack_inputs"; paths: string[] }
  | { action: "empty" };

export type OutputPathKind = "pack_zip" | "fix_nfc_zip" | "extract_dir";

export interface PackRequestOptions {
  op_id?: string;
  format?: PackFormat;
  compression_level?: number;
  exclude_os_junk?: boolean;
  password?: string;
  /** Volume size such as "25M"; parsed and validated by dandi-core. */
  split_size?: string;
  split_style?: SplitStyle;
  overwrite?: boolean;
}

export interface UnpackRequestOptions {
  op_id?: string;
  mode?: ExtractMode;
  encoding_override?: string;
  password?: string;
  selected_entries?: number[];
  exclude_os_junk?: boolean;
  overwrite?: boolean;
  reveal_after?: boolean;
}

export type ThemePreference = "system" | "light" | "dark";
export type Locale = "ko" | "en" | "ja";
