import { describe, expect, it } from "vitest";
import type { ArchiveSummary } from "../types";
import { desktopReducer, INITIAL_DESKTOP_STATE } from "./state";

const SAMPLE_SUMMARY: ArchiveSummary = {
  format: "zip",
  encoding: {
    encoding: "cp949",
    confidence: 0.96,
    candidates: [{ encoding: "cp949", score: 0.96, had_errors: false }],
  },
  applied_encoding: "cp949",
  total_entries: 2,
  total_uncompressed_bytes: 2048,
  total_compressed_bytes: 1024,
  encrypted: false,
  entries: [],
};

const OTHER_SUMMARY: ArchiveSummary = {
  ...SAMPLE_SUMMARY,
  applied_encoding: "utf8",
  total_entries: 5,
};

describe("desktopReducer state transitions", () => {
  it("commits archivePath only on inspect_success and preserves selection on re-inspect", () => {
    let s = desktopReducer(INITIAL_DESKTOP_STATE, {
      type: "inspect_start",
      archivePath: "/tmp/sample.zip",
      encodingOverride: null,
    });
    expect(s.loadingArchive).toBe(true);
    expect(s.pendingArchivePath).toBe("/tmp/sample.zip");
    expect(s.archivePath).toBeNull();

    s = desktopReducer(s, {
      type: "inspect_success",
      archivePath: "/tmp/sample.zip",
      summary: SAMPLE_SUMMARY,
      encodingOverride: null,
      password: null,
    });
    expect(s.loadingArchive).toBe(false);
    expect(s.archivePath).toBe("/tmp/sample.zip");
    expect(s.pendingArchivePath).toBeNull();
    expect(s.summary?.applied_encoding).toBe("cp949");

    s = desktopReducer(s, { type: "set_selected_indices", indices: [0, 1] });
    // Re-inspect same archive under manual encoding preserves selection
    s = desktopReducer(s, {
      type: "inspect_start",
      archivePath: "/tmp/sample.zip",
      encodingOverride: "shift_jis",
    });
    s = desktopReducer(s, {
      type: "inspect_success",
      archivePath: "/tmp/sample.zip",
      summary: SAMPLE_SUMMARY,
      encodingOverride: "shift_jis",
      password: null,
    });
    expect(s.encodingOverride).toBe("shift_jis");
    expect(s.selectedIndices).toEqual([0, 1]);

    // Switching to a different archive resets selection on success
    s = desktopReducer(s, {
      type: "inspect_start",
      archivePath: "/tmp/other.zip",
      encodingOverride: null,
    });
    s = desktopReducer(s, {
      type: "inspect_success",
      archivePath: "/tmp/other.zip",
      summary: OTHER_SUMMARY,
      encodingOverride: null,
      password: null,
    });
    expect(s.archivePath).toBe("/tmp/other.zip");
    expect(s.selectedIndices).toEqual([]);
  });

  it("preserves prior archive state when opening a second archive fails or password modal is cancelled", () => {
    let s = desktopReducer(INITIAL_DESKTOP_STATE, {
      type: "inspect_success",
      archivePath: "/tmp/archive-a.zip",
      summary: SAMPLE_SUMMARY,
      encodingOverride: "cp949",
      password: "secret",
    });
    s = desktopReducer(s, { type: "set_selected_indices", indices: [0] });

    // Attempt to open corrupt archive B
    s = desktopReducer(s, {
      type: "inspect_start",
      archivePath: "/tmp/corrupt-b.zip",
      encodingOverride: null,
    });
    expect(s.archivePath).toBe("/tmp/archive-a.zip");
    expect(s.pendingArchivePath).toBe("/tmp/corrupt-b.zip");

    s = desktopReducer(s, {
      type: "inspect_error",
      archivePath: "/tmp/corrupt-b.zip",
      errorKind: "corrupt_archive",
      notice: {
        tone: "error",
        title: "Archive appears corrupt or truncated",
        detail: "bad central directory",
      },
    });
    expect(s.archivePath).toBe("/tmp/archive-a.zip");
    expect(s.summary).toBe(SAMPLE_SUMMARY);
    expect(s.encodingOverride).toBe("cp949");
    expect(s.selectedIndices).toEqual([0]);
    expect(s.pendingArchivePath).toBeNull();
    expect(s.notice?.title).toBe("Archive appears corrupt or truncated");

    // Attempt to open encrypted archive C, then cancel password modal
    s = desktopReducer(s, {
      type: "inspect_start",
      archivePath: "/tmp/encrypted-c.zip",
      encodingOverride: null,
    });
    s = desktopReducer(s, {
      type: "inspect_error",
      archivePath: "/tmp/encrypted-c.zip",
      errorKind: "password_required",
      notice: { tone: "error", title: "Password required" },
    });
    expect(s.passwordPrompt?.archivePath).toBe("/tmp/encrypted-c.zip");
    expect(s.archivePath).toBe("/tmp/archive-a.zip");

    s = desktopReducer(s, { type: "close_password_prompt" });
    expect(s.passwordPrompt).toBeNull();
    expect(s.pendingArchivePath).toBeNull();
    expect(s.archivePath).toBe("/tmp/archive-a.zip");
    expect(s.summary).toBe(SAMPLE_SUMMARY);
  });

  it("opens password prompt on password_required, flags retry on invalid_password, and preserves selectedOnly", () => {
    let s = desktopReducer(INITIAL_DESKTOP_STATE, {
      type: "inspect_start",
      archivePath: "/tmp/secret.zip",
      encodingOverride: null,
    });
    s = desktopReducer(s, {
      type: "inspect_error",
      archivePath: "/tmp/secret.zip",
      errorKind: "password_required",
      notice: { tone: "error", title: "Password required" },
    });
    expect(s.passwordPrompt?.purpose).toBe("inspect");
    expect(s.passwordPrompt?.invalidAttempt).toBe(false);

    s = desktopReducer(s, {
      type: "inspect_error",
      archivePath: "/tmp/secret.zip",
      errorKind: "invalid_password",
      notice: { tone: "error", title: "Incorrect password" },
    });
    expect(s.passwordPrompt?.invalidAttempt).toBe(true);

    // User has selected entries, but clicked "Extract All" (selectedOnly: false)
    s = desktopReducer(s, { type: "set_selected_indices", indices: [0, 1] });
    s = desktopReducer(s, {
      type: "open_password_prompt",
      prompt: {
        purpose: "unpack",
        archivePath: "/tmp/secret.zip",
        destPath: "/tmp/out",
        selectedOnly: false,
        invalidAttempt: false,
      },
    });
    expect(s.passwordPrompt?.selectedOnly).toBe(false);

    // Caching verified password updates archivePassword
    s = desktopReducer(s, { type: "set_archive_password", password: "correct-horse" });
    expect(s.archivePassword).toBe("correct-horse");
  });

  it("tracks active operation progress, cancellation, and completion notice", () => {
    let s = desktopReducer(INITIAL_DESKTOP_STATE, {
      type: "operation_start",
      opId: "pack-1",
      kind: "pack",
      startedAtMs: 1000,
    });
    expect(s.activeOp?.opId).toBe("pack-1");

    // Ignores stale events from other opIds
    s = desktopReducer(s, {
      type: "operation_progress",
      payload: {
        op_id: "stale-op",
        phase: "packing",
        current_entry: "ignored.txt",
        entries_done: 1,
        entries_total: 2,
        bytes_done: 10,
        bytes_total: 20,
      },
    });
    expect(s.activeOp?.progress).toBeNull();

    s = desktopReducer(s, {
      type: "operation_progress",
      payload: {
        op_id: "pack-1",
        phase: "packing",
        current_entry: "doc.txt",
        entries_done: 1,
        entries_total: 2,
        bytes_done: 500,
        bytes_total: 1000,
      },
    });
    expect(s.activeOp?.progress?.current_entry).toBe("doc.txt");

    s = desktopReducer(s, { type: "operation_cancelling" });
    expect(s.activeOp?.cancelling).toBe(true);

    s = desktopReducer(s, {
      type: "operation_finish",
      notice: { tone: "info", title: "Cancelled" },
    });
    expect(s.activeOp).toBeNull();
    expect(s.notice?.title).toBe("Cancelled");
  });

  it("defaults overwriteExisting to false (including in direct mode) and toggles cleanly", () => {
    expect(INITIAL_DESKTOP_STATE.overwriteExisting).toBe(false);

    let s = desktopReducer(INITIAL_DESKTOP_STATE, {
      type: "set_extract_mode",
      mode: "direct",
    });
    expect(s.extractMode).toBe("direct");
    expect(s.overwriteExisting).toBe(false);

    s = desktopReducer(s, { type: "set_overwrite_existing", value: true });
    expect(s.overwriteExisting).toBe(true);

    s = desktopReducer(s, { type: "set_overwrite_existing", value: false });
    expect(s.overwriteExisting).toBe(false);
  });

  it("retains structured warnings on completion notice until dismissed", () => {
    const s = desktopReducer(INITIAL_DESKTOP_STATE, {
      type: "operation_finish",
      notice: {
        tone: "warning",
        title: "Extracted 3 files to /tmp/out with 1 warning(s).",
        detail: "1 symlink(s) skipped.",
        revealPath: "/tmp/out",
        warnings: [
          {
            kind: "symlink_skipped",
            label: "Symlink skipped",
            path: "bin/tool",
            target: "../lib/tool",
            reason: "Windows symlink privilege not available",
          },
        ],
      },
    });
    expect(s.notice?.tone).toBe("warning");
    expect(s.notice?.warnings).toHaveLength(1);
    expect(s.notice?.warnings?.[0]?.path).toBe("bin/tool");
  });
});
