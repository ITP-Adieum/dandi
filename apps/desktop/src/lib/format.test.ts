import { describe, expect, it } from "vitest";
import {
  formatBytes,
  formatFormatLabel,
  formatProgressPercent,
  formatSavingsRatio,
  formatSpeed,
  formatTimestamp,
  pathBasename,
  shortEncodingLabel,
} from "./format";

describe("format utilities", () => {
  it("formats byte sizes across units", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1024)).toBe("1.00 KB");
    expect(formatBytes(15 * 1024 * 1024)).toBe("15.0 MB");
    expect(formatBytes(2.5 * 1024 * 1024 * 1024)).toBe("2.50 GB");
  });

  it("formats compression savings ratios", () => {
    expect(formatSavingsRatio(0, 0)).toBe("—");
    expect(formatSavingsRatio(1000, 1000)).toBe("0%");
    expect(formatSavingsRatio(1000, 250)).toBe("75%");
  });

  it("formats throughput speeds safely", () => {
    expect(formatSpeed(0, 1000)).toBe("—");
    expect(formatSpeed(1024 * 1024 * 50, 500)).toBe("100 MB/s");
    expect(formatSpeed(1024 * 1024 * 12, 1000)).toBe("12.0 MB/s");
  });

  it("formats archive labels, encodings, basenames, and progress percentages", () => {
    expect(formatFormatLabel("tar_zst")).toBe("TAR.ZST");
    expect(formatFormatLabel("rar")).toBe("RAR");
    expect(shortEncodingLabel("cp949")).toBe("CP949");
    expect(shortEncodingLabel("shift_jis")).toBe("Shift_JIS");
    expect(pathBasename("/tmp/work/보고서.zip")).toBe("보고서.zip");
    expect(pathBasename("C:\\Users\\demo\\archive.7z")).toBe("archive.7z");
    expect(formatProgressPercent(50, 200, 1, 4)).toBe(25);
    expect(formatProgressPercent(0, 0, 3, 6)).toBe(50);
    expect(formatTimestamp(null)).toBe("—");
  });
});
