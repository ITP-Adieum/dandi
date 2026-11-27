import { Channel, invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import type {
  ArchiveSummary,
  CommandError,
  DroppedPathsClassification,
  EncodingOption,
  OutputPathKind,
  PackReport,
  PackRequestOptions,
  ProgressPayload,
  RepackReport,
  UnpackReport,
  UnpackRequestOptions,
} from "./types";

export const ARCHIVE_EXTENSIONS = [
  "zip",
  "7z",
  "tar",
  "tgz",
  "gz",
  "zst",
  "tzst",
  "bz2",
  "tbz2",
  "xz",
  "txz",
];

export function isCommandError(err: unknown): err is CommandError {
  return (
    typeof err === "object" &&
    err !== null &&
    "kind" in err &&
    "message" in err &&
    typeof (err as CommandError).kind === "string" &&
    typeof (err as CommandError).message === "string"
  );
}

export function toCommandError(err: unknown): CommandError {
  if (isCommandError(err)) {
    return err;
  }
  if (err instanceof Error) {
    return { kind: "internal", message: err.message };
  }
  return { kind: "internal", message: String(err) };
}

export async function listEncodings(): Promise<EncodingOption[]> {
  return invoke<EncodingOption[]>("list_encodings");
}

export async function inspectArchive(
  path: string,
  encodingOverride?: string | null,
  password?: string | null,
  includeOsJunk = false
): Promise<ArchiveSummary> {
  return invoke<ArchiveSummary>("inspect_archive", {
    path,
    encodingOverride: encodingOverride ?? null,
    password: password ?? null,
    includeOsJunk,
  });
}

export async function packArchive(
  inputs: string[],
  outputZip: string,
  options: PackRequestOptions,
  onProgress: (payload: ProgressPayload) => void
): Promise<PackReport> {
  const channel = new Channel<ProgressPayload>();
  channel.onmessage = onProgress;
  return invoke<PackReport>("pack_archive", {
    inputs,
    outputZip,
    options,
    onProgress: channel,
  });
}

export async function unpackArchive(
  archivePath: string,
  destDir: string,
  options: UnpackRequestOptions,
  onProgress: (payload: ProgressPayload) => void
): Promise<UnpackReport> {
  const channel = new Channel<ProgressPayload>();
  channel.onmessage = onProgress;
  return invoke<UnpackReport>("unpack_archive", {
    archivePath,
    destDir,
    options,
    onProgress: channel,
  });
}

export async function fixArchiveEncoding(
  srcZip: string,
  dstZip: string,
  encodingOverride: string | null | undefined,
  password: string | null | undefined,
  excludeOsJunk: boolean,
  opId: string,
  onProgress: (payload: ProgressPayload) => void
): Promise<RepackReport> {
  const channel = new Channel<ProgressPayload>();
  channel.onmessage = onProgress;
  return invoke<RepackReport>("fix_archive_encoding", {
    srcZip,
    dstZip,
    options: {
      op_id: opId,
      encoding_override: encodingOverride ?? undefined,
      password: password ?? undefined,
      exclude_os_junk: excludeOsJunk,
    },
    onProgress: channel,
  });
}

export async function cancelOperation(opId: string): Promise<boolean> {
  return invoke<boolean>("cancel_operation", { opId });
}

export async function classifyDroppedPaths(
  paths: string[]
): Promise<DroppedPathsClassification> {
  return invoke<DroppedPathsClassification>("classify_dropped_paths", { paths });
}

export async function takePendingOpenPaths(): Promise<string[]> {
  return invoke<string[]>("take_pending_open_paths");
}

export async function defaultOutputPath(
  inputs: string[],
  kind: OutputPathKind
): Promise<string> {
  return invoke<string>("default_output_path", { inputs, kind });
}

export async function revealInFileManager(path: string): Promise<void> {
  return invoke<void>("reveal_in_file_manager", { path });
}

export async function pickArchiveFile(): Promise<string | null> {
  const selected = await open({
    multiple: false,
    directory: false,
    filters: [
      {
        name: "Archives",
        extensions: ARCHIVE_EXTENSIONS,
      },
    ],
  });
  return typeof selected === "string" ? selected : null;
}

export async function pickPackFiles(): Promise<string[]> {
  const selected = await open({
    multiple: true,
    directory: false,
  });
  if (Array.isArray(selected)) return selected;
  if (typeof selected === "string") return [selected];
  return [];
}

export async function pickPackFolders(): Promise<string[]> {
  const selected = await open({
    multiple: true,
    directory: true,
  });
  if (Array.isArray(selected)) return selected;
  if (typeof selected === "string") return [selected];
  return [];
}

export async function pickDestinationDirectory(
  defaultPath?: string
): Promise<string | null> {
  const selected = await open({
    multiple: false,
    directory: true,
    defaultPath,
  });
  return typeof selected === "string" ? selected : null;
}

export async function pickSaveZipPath(
  defaultPath?: string,
  title?: string
): Promise<string | null> {
  const selected = await save({
    defaultPath,
    title,
    filters: [{ name: "ZIP Archive", extensions: ["zip"] }],
  });
  return typeof selected === "string" ? selected : null;
}
