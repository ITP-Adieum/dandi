import type { ArchiveFormat, EncodingId } from "../types";

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "0 B";
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unitIdx = 0;
  while (value >= 1024 && unitIdx < units.length - 1) {
    value /= 1024;
    unitIdx += 1;
  }
  const decimals = value >= 100 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toFixed(decimals)} ${units[unitIdx]}`;
}

export function formatSavingsRatio(
  uncompressedBytes: number,
  compressedBytes: number
): string {
  if (uncompressedBytes <= 0) return "—";
  const savedPct = ((uncompressedBytes - compressedBytes) / uncompressedBytes) * 100;
  if (savedPct <= 0.5) return "0%";
  return `${Math.round(savedPct)}%`;
}

export function formatSpeed(bytesDone: number, elapsedMs: number): string {
  if (bytesDone <= 0 || elapsedMs <= 20) return "—";
  const mbPerSec = bytesDone / (1024 * 1024) / (elapsedMs / 1000);
  if (!Number.isFinite(mbPerSec) || mbPerSec < 0.05) return "< 0.1 MB/s";
  if (mbPerSec >= 100) return `${Math.round(mbPerSec)} MB/s`;
  return `${mbPerSec.toFixed(1)} MB/s`;
}

export function formatTimestamp(unixSecs: number | null): string {
  if (unixSecs === null || !Number.isFinite(unixSecs)) return "—";
  const d = new Date(unixSecs * 1000);
  if (Number.isNaN(d.getTime())) return "—";
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const min = String(d.getMinutes()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd} ${hh}:${min}`;
}

export function formatFormatLabel(fmt: ArchiveFormat): string {
  switch (fmt) {
    case "zip":
      return "ZIP";
    case "seven_z":
      return "7Z";
    case "tar":
      return "TAR";
    case "tar_gz":
      return "TAR.GZ";
    case "tar_zst":
      return "TAR.ZST";
    case "tar_bz2":
      return "TAR.BZ2";
    case "tar_xz":
      return "TAR.XZ";
  }
}

export function shortEncodingLabel(enc: EncodingId): string {
  switch (enc) {
    case "utf8":
      return "UTF-8";
    case "cp949":
      return "CP949";
    case "shift_jis":
      return "Shift_JIS";
    case "gb18030":
      return "GB18030";
    case "big5":
      return "Big5";
    case "windows1251":
      return "Win-1251";
    case "ibm866":
      return "IBM866";
    case "windows1252":
      return "Win-1252";
    case "cp437":
      return "CP437";
    case "windows1258":
      return "Win-1258";
    case "windows874":
      return "Win-874";
  }
}

export function pathBasename(filePath: string): string {
  const normalized = filePath.replace(/[\\/]+$/, "");
  const lastSlash = Math.max(normalized.lastIndexOf("/"), normalized.lastIndexOf("\\"));
  return lastSlash >= 0 ? normalized.slice(lastSlash + 1) : normalized;
}

export function formatProgressPercent(
  bytesDone: number,
  bytesTotal: number,
  entriesDone: number,
  entriesTotal: number
): number {
  if (bytesTotal > 0) {
    return Math.max(0, Math.min(100, Math.round((bytesDone / bytesTotal) * 100)));
  }
  if (entriesTotal > 0) {
    return Math.max(0, Math.min(100, Math.round((entriesDone / entriesTotal) * 100)));
  }
  return 0;
}
