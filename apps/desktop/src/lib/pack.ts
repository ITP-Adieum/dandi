import type { PackFormat, PackRequestOptions } from "../types";
import type { PackDraftState } from "./state";

export type SplitPreset = "none" | "10" | "25" | "100" | "custom";

export const SPLIT_PRESETS: readonly SplitPreset[] = ["none", "10", "25", "100", "custom"];

export const PACK_FORMATS: readonly PackFormat[] = ["zip", "seven_z"];

export const PACK_EXTENSION: Record<PackFormat, string> = {
  zip: "zip",
  seven_z: "7z",
};

export type SplitChoice = { ok: true; sizeSpec: string | null } | { ok: false };

/**
 * Turns the split picker into the size string the backend parses ("25M").
 * Only the number format is checked here; dandi-core enforces the 64 KiB minimum.
 */
export function splitSizeSpec(preset: SplitPreset, customMb: string): SplitChoice {
  if (preset === "none") return { ok: true, sizeSpec: null };
  if (preset !== "custom") return { ok: true, sizeSpec: `${preset}M` };
  const value = customMb.trim();
  if (!/^\d+(\.\d+)?$/.test(value) || Number(value) <= 0) return { ok: false };
  return { ok: true, sizeSpec: `${value}M` };
}

/** Swaps a trailing `.zip` / `.7z` for the chosen format's extension, or appends it. */
export function withArchiveExtension(path: string, format: PackFormat): string {
  const trimmed = path.trim();
  if (!trimmed) return trimmed;
  const ext = PACK_EXTENSION[format];
  const known = /\.(zip|7z)$/i.exec(trimmed);
  return known ? `${trimmed.slice(0, known.index)}.${ext}` : `${trimmed}.${ext}`;
}

export function defaultPackDraft(inputs: string[], suggestedZip: string): PackDraftState {
  return {
    inputs,
    outputZip: suggestedZip,
    format: "zip",
    compressionLevel: 6,
    excludeOsJunk: true,
    password: "",
    splitPreset: "none",
    splitCustomMb: "",
  };
}

/** Maps the modal state to the `pack_archive` IPC options, or `null` while the split size is invalid. */
export function buildPackRequest(draft: PackDraftState, opId: string): PackRequestOptions | null {
  const split = splitSizeSpec(draft.splitPreset, draft.splitCustomMb);
  if (!split.ok) return null;
  return {
    op_id: opId,
    format: draft.format,
    compression_level: draft.compressionLevel,
    exclude_os_junk: draft.excludeOsJunk,
    password: draft.password || undefined,
    split_size: split.sizeSpec ?? undefined,
    split_style: draft.format === "zip" ? "pkware_zip" : "numeric",
    overwrite: true,
  };
}
