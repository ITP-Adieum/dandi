import { describe, expect, it } from "vitest";
import type { ArchiveEntryInfo } from "../types";
import {
  buildArchiveTree,
  filterAndSortRows,
  getRowSelectionState,
  toggleRowSelection,
} from "./tree";

function makeEntry(
  overrides: Partial<ArchiveEntryInfo> & { path: string }
): ArchiveEntryInfo {
  return {
    index: null,
    kind: "file",
    uncompressed_size: 100,
    compressed_size: 50,
    modified_unix_secs: 1_700_000_000,
    unix_mode: 0o644,
    encrypted: false,
    compression_method: "Deflated",
    is_os_junk: false,
    is_synthesized: false,
    symlink_target: null,
    ...overrides,
  };
}

describe("buildArchiveTree", () => {
  it("synthesizes missing parent folders and collects descendant indices", () => {
    const entries: ArchiveEntryInfo[] = [
      makeEntry({
        index: 0,
        path: "프로젝트/문서/보고서.pdf",
        uncompressed_size: 4096,
      }),
      makeEntry({
        index: 1,
        path: "프로젝트/문서/메모.txt",
        uncompressed_size: 128,
      }),
      makeEntry({
        index: 2,
        path: "README.md",
        uncompressed_size: 512,
      }),
    ];

    const model = buildArchiveTree(entries, false);
    expect(model.allExtractableIndices).toEqual([0, 1, 2]);
    expect(model.root.children.map((c) => c.path)).toEqual(["프로젝트"]);
    expect(model.root.children[0]?.children.map((c) => c.path)).toEqual([
      "프로젝트/문서",
    ]);

    const rootRows = filterAndSortRows(model, "", "", "name", "asc");
    // Folders sort before files
    expect(rootRows.map((r) => [r.name, r.isDirectory])).toEqual([
      ["프로젝트", true],
      ["README.md", false],
    ]);
    expect(rootRows[0]?.extractableIndices).toEqual([0, 1]);
  });

  it("filters OS junk when showOsJunk is false and reveals them when true", () => {
    const entries: ArchiveEntryInfo[] = [
      makeEntry({ index: 0, path: ".DS_Store", is_os_junk: true }),
      makeEntry({ index: 1, path: "__MACOSX/._a.txt", is_os_junk: true }),
      makeEntry({ index: 2, path: "a.txt", is_os_junk: false }),
    ];

    const hidden = buildArchiveTree(entries, false);
    expect(hidden.allExtractableIndices).toEqual([2]);
    expect(hidden.allRows.map((r) => r.path)).toEqual(["a.txt"]);

    const shown = buildArchiveTree(entries, true);
    expect(shown.allExtractableIndices).toEqual([0, 1, 2]);
    expect(shown.allRows.some((r) => r.path === ".DS_Store")).toBe(true);
  });

  it("supports search filtering and sorting by size descending", () => {
    const entries: ArchiveEntryInfo[] = [
      makeEntry({ index: 0, path: "dir/small.txt", uncompressed_size: 10 }),
      makeEntry({ index: 1, path: "dir/large.txt", uncompressed_size: 9000 }),
      makeEntry({ index: 2, path: "other/notes.md", uncompressed_size: 500 }),
    ];
    const model = buildArchiveTree(entries, false);

    const searchRes = filterAndSortRows(model, "", ".txt", "size", "desc");
    expect(searchRes.map((r) => r.name)).toEqual(["large.txt", "small.txt"]);

    const scopedSearch = filterAndSortRows(model, "other", "notes", "name", "asc");
    expect(scopedSearch.map((r) => r.path)).toEqual(["other/notes.md"]);
  });

  it("computes checked, indeterminate, and unchecked folder states cleanly", () => {
    const entries: ArchiveEntryInfo[] = [
      makeEntry({ index: 0, path: "docs/a.txt" }),
      makeEntry({ index: 1, path: "docs/b.txt" }),
    ];
    const model = buildArchiveTree(entries, false);
    const docsRow = filterAndSortRows(model, "", "", "name", "asc")[0];
    expect(docsRow).toBeDefined();
    if (!docsRow) return;

    expect(getRowSelectionState(docsRow, new Set())).toBe("unchecked");
    expect(getRowSelectionState(docsRow, new Set([0]))).toBe("indeterminate");
    expect(getRowSelectionState(docsRow, new Set([0, 1]))).toBe("checked");

    const afterSelect = toggleRowSelection(docsRow, new Set([0]));
    expect(Array.from(afterSelect).sort()).toEqual([0, 1]);

    const afterUnselect = toggleRowSelection(docsRow, afterSelect);
    expect(Array.from(afterUnselect)).toEqual([]);
  });
});
