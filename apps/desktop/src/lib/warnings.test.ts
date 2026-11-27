import { describe, expect, it } from "vitest";
import { DICTIONARIES } from "../i18n";
import type { UnpackReport, UnpackWarning } from "../types";
import { buildErrorNotice, buildUnpackNotice, formatUnpackWarning } from "./warnings";

const BASE_REPORT: UnpackReport = {
  format: "zip",
  output_dir: "/tmp/out/project",
  detected_encoding: "utf8",
  applied_encoding: "utf8",
  files_extracted: 4,
  dirs_created: 1,
  symlinks_created: 0,
  symlinks_skipped: 0,
  junk_skipped: 0,
  bytes_written: 4096,
  sanitized_paths: 0,
  renamed_collisions: [],
  warnings: [],
};

describe("unpack warning formatting", () => {
  it("formats all UnpackWarning variants with localized labels across en, ko, ja", () => {
    const warnings: UnpackWarning[] = [
      {
        kind: "symlink_skipped",
        path: "app/current",
        target: "releases/v1",
        reason: "symlinks require Developer Mode on Windows",
      },
      {
        kind: "permission_apply_failed",
        path: "scripts/run.sh",
        reason: "operation not permitted",
      },
      {
        kind: "mtime_apply_failed",
        path: "docs/report.pdf",
        reason: "read-only filesystem",
      },
      {
        kind: "zone_id_propagate_failed",
        path: "bin/app.exe",
        reason: "filesystem does not support NTFS ADS",
      },
    ];

    for (const locale of ["en", "ko", "ja"] as const) {
      const t = DICTIONARIES[locale];
      const formatted = warnings.map((w) => formatUnpackWarning(w, t));

      expect(formatted).toHaveLength(4);
      expect(formatted[0]).toEqual({
        kind: "symlink_skipped",
        label: t.warningKinds.symlink_skipped,
        path: "app/current",
        target: "releases/v1",
        reason: "symlinks require Developer Mode on Windows",
      });
      expect(formatted[1]?.label).toBe(t.warningKinds.permission_apply_failed);
      expect(formatted[1]?.target).toBeUndefined();
      expect(formatted[2]?.label).toBe(t.warningKinds.mtime_apply_failed);
      expect(formatted[3]?.label).toBe(t.warningKinds.zone_id_propagate_failed);
    }
  });

  it("builds a clean success notice when no warnings or skipped symlinks occurred", () => {
    const notice = buildUnpackNotice(BASE_REPORT, DICTIONARIES.en);
    expect(notice.tone).toBe("success");
    expect(notice.title).toContain("4 files");
    expect(notice.revealPath).toBe("/tmp/out/project");
    expect(notice.warnings).toBeUndefined();
    expect(notice.detail).toBeUndefined();
  });

  it("builds a calm warning notice with expandable items when warnings and skipped symlinks exist", () => {
    const report: UnpackReport = {
      ...BASE_REPORT,
      symlinks_skipped: 1,
      renamed_collisions: [{ original: "readme.md", resolved: "readme (2).md" }],
      warnings: [
        {
          kind: "symlink_skipped",
          path: "bin/dandi",
          target: "../target/dandi",
          reason: "privilege not held",
        },
        {
          kind: "mtime_apply_failed",
          path: "README.md",
          reason: "timestamp unsupported",
        },
      ],
    };

    const notice = buildUnpackNotice(report, DICTIONARIES.en);
    expect(notice.tone).toBe("warning");
    expect(notice.title).toContain("2 warning(s)");
    expect(notice.detail).toContain("1 case-insensitive filename collision(s)");
    expect(notice.detail).toContain("1 symlink(s) skipped");
    expect(notice.warnings).toHaveLength(2);
    expect(notice.warnings?.[0]?.target).toBe("../target/dandi");
    expect(notice.warnings?.[1]?.label).toBe(DICTIONARIES.en.warningKinds.mtime_apply_failed);
  });

  it("surfaces warning tone even if only symlinks_skipped count is non-zero", () => {
    const report: UnpackReport = {
      ...BASE_REPORT,
      symlinks_skipped: 2,
      warnings: [],
    };
    const notice = buildUnpackNotice(report, DICTIONARIES.ko);
    expect(notice.tone).toBe("warning");
    expect(notice.title).toContain("경고 2건");
    expect(notice.detail).toContain("심볼릭 링크 2건");
  });

  it("attaches localized guidance for already_exists errors", () => {
    const enNotice = buildErrorNotice(
      "already_exists",
      "destination already exists: /tmp/out/a.txt",
      DICTIONARIES.en
    );
    expect(enNotice.tone).toBe("error");
    expect(enNotice.title).toBe(DICTIONARIES.en.errors.already_exists);
    expect(enNotice.guidance).toBe(DICTIONARIES.en.alreadyExistsGuidance);
    expect(enNotice.detail).toContain("/tmp/out/a.txt");

    const koNotice = buildErrorNotice("already_exists", "exists", DICTIONARIES.ko);
    expect(koNotice.guidance).toContain("기존 파일 덮어쓰기");

    const cancelNotice = buildErrorNotice("cancelled", "cancelled", DICTIONARIES.en);
    expect(cancelNotice.tone).toBe("info");
    expect(cancelNotice.guidance).toBeUndefined();
    expect(cancelNotice.detail).toBeUndefined();
  });
});
