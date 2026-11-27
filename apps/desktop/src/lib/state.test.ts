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

describe("desktopReducer state transitions", () => {
  it("handles inspect start, success, and encoding re-inspect preserving selection", () => {
    let s = desktopReducer(INITIAL_DESKTOP_STATE, {
      type: "inspect_start",
      archivePath: "/tmp/sample.zip",
      encodingOverride: null,
    });
    expect(s.loadingArchive).toBe(true);

    s = desktopReducer(s, {
      type: "inspect_success",
      archivePath: "/tmp/sample.zip",
      summary: SAMPLE_SUMMARY,
      password: null,
    });
    expect(s.loadingArchive).toBe(false);
    expect(s.summary?.applied_encoding).toBe("cp949");

    s = desktopReducer(s, { type: "set_selected_indices", indices: [0, 1] });
    // Re-inspect same archive under manual encoding preserves selection
    s = desktopReducer(s, {
      type: "inspect_start",
      archivePath: "/tmp/sample.zip",
      encodingOverride: "shift_jis",
    });
    expect(s.encodingOverride).toBe("shift_jis");
    expect(s.selectedIndices).toEqual([0, 1]);

    // Switching to a different archive resets selection
    s = desktopReducer(s, {
      type: "inspect_start",
      archivePath: "/tmp/other.zip",
      encodingOverride: null,
    });
    expect(s.selectedIndices).toEqual([]);
  });

  it("opens password prompt on password_required and flags retry on invalid_password", () => {
    let s = desktopReducer(INITIAL_DESKTOP_STATE, {
      type: "inspect_start",
      archivePath: "/tmp/secret.zip",
      encodingOverride: null,
    });
    s = desktopReducer(s, {
      type: "inspect_error",
      error: { kind: "password_required", message: "encrypted" },
    });
    expect(s.passwordPrompt?.purpose).toBe("inspect");
    expect(s.passwordPrompt?.invalidAttempt).toBe(false);

    s = desktopReducer(s, {
      type: "inspect_error",
      error: { kind: "invalid_password", message: "wrong password" },
    });
    expect(s.passwordPrompt?.invalidAttempt).toBe(true);
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
});
