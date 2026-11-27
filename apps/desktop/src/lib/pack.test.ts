import { describe, expect, it } from "vitest";
import {
  buildPackRequest,
  defaultPackDraft,
  splitSizeSpec,
  withArchiveExtension,
} from "./pack";

describe("splitSizeSpec", () => {
  it("maps presets to MiB size strings", () => {
    expect(splitSizeSpec("none", "")).toEqual({ ok: true, sizeSpec: null });
    expect(splitSizeSpec("10", "")).toEqual({ ok: true, sizeSpec: "10M" });
    expect(splitSizeSpec("25", "999")).toEqual({ ok: true, sizeSpec: "25M" });
    expect(splitSizeSpec("100", "")).toEqual({ ok: true, sizeSpec: "100M" });
  });

  it("accepts positive custom MB values, including decimals", () => {
    expect(splitSizeSpec("custom", " 50 ")).toEqual({ ok: true, sizeSpec: "50M" });
    expect(splitSizeSpec("custom", "1.5")).toEqual({ ok: true, sizeSpec: "1.5M" });
  });

  it("rejects empty, zero, negative and non-numeric custom values", () => {
    for (const bad of ["", "0", "0.0", "-5", "abc", "10MB", "1e3", "1.2.3"]) {
      expect(splitSizeSpec("custom", bad)).toEqual({ ok: false });
    }
  });
});

describe("withArchiveExtension", () => {
  it("swaps .zip and .7z both ways, case-insensitively", () => {
    expect(withArchiveExtension("/tmp/보고서.zip", "seven_z")).toBe("/tmp/보고서.7z");
    expect(withArchiveExtension("C:\\Users\\me\\a.7z", "zip")).toBe("C:\\Users\\me\\a.zip");
    expect(withArchiveExtension("/tmp/A.ZIP", "seven_z")).toBe("/tmp/A.7z");
  });

  it("appends an extension when the path has none and leaves empty paths alone", () => {
    expect(withArchiveExtension("/tmp/archive", "seven_z")).toBe("/tmp/archive.7z");
    expect(withArchiveExtension("/tmp/v1.2", "zip")).toBe("/tmp/v1.2.zip");
    expect(withArchiveExtension("   ", "zip")).toBe("");
  });
});

describe("buildPackRequest", () => {
  it("sends ZIP without split by default", () => {
    const req = buildPackRequest(defaultPackDraft(["/tmp/a"], "/tmp/a.zip"), "op-1");
    expect(req).toEqual({
      op_id: "op-1",
      format: "zip",
      compression_level: 6,
      exclude_os_junk: true,
      password: undefined,
      split_size: undefined,
      split_style: "pkware_zip",
      overwrite: true,
    });
  });

  it("uses numeric volumes for 7z and forwards the password", () => {
    const draft = {
      ...defaultPackDraft(["/tmp/a"], "/tmp/a.7z"),
      format: "seven_z" as const,
      password: "단디-7z!2026",
      splitPreset: "25" as const,
    };
    const req = buildPackRequest(draft, "op-2");
    expect(req?.format).toBe("seven_z");
    expect(req?.split_size).toBe("25M");
    expect(req?.split_style).toBe("numeric");
    expect(req?.password).toBe("단디-7z!2026");
  });

  it("returns null while the custom split size is invalid", () => {
    const draft = {
      ...defaultPackDraft(["/tmp/a"], "/tmp/a.zip"),
      splitPreset: "custom" as const,
      splitCustomMb: "0",
    };
    expect(buildPackRequest(draft, "op-3")).toBeNull();
  });
});
