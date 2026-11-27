import type { ArchiveEntryInfo } from "../types";

export interface FolderNode {
  /** Normalized folder path without trailing slash (`""` for archive root). */
  path: string;
  name: string;
  depth: number;
  children: FolderNode[];
  /** Direct file/folder child count inside this folder. */
  directCount: number;
  /** Total recursive real extractable entry indices beneath this folder. */
  extractableIndices: number[];
  /** True when the folder had no explicit entry in the archive and was synthesized. */
  isSynthesized: boolean;
}

export interface TableRow {
  /** Normalized path without trailing slash. */
  path: string;
  name: string;
  parentPath: string;
  isDirectory: boolean;
  isSymlink: boolean;
  isSynthesized: boolean;
  isOsJunk: boolean;
  encrypted: boolean;
  uncompressedSize: number;
  compressedSize: number;
  modifiedUnixSecs: number | null;
  compressionMethod: string;
  symlinkTarget: string | null;
  /** Real archive indices represented by this row (1 for a file/symlink; all descendants for a folder). */
  extractableIndices: number[];
}

export interface ArchiveTreeModel {
  root: FolderNode;
  rowsByFolder: Map<string, TableRow[]>;
  allRows: TableRow[];
  allExtractableIndices: number[];
}

export type SortField = "name" | "size" | "compressed" | "modified";
export type SortDirection = "asc" | "desc";

function stripTrailingSlashes(p: string): string {
  return p.replace(/\/+$/, "");
}

function splitParentAndName(cleanPath: string): { parent: string; name: string } {
  const idx = cleanPath.lastIndexOf("/");
  if (idx === -1) {
    return { parent: "", name: cleanPath };
  }
  return {
    parent: cleanPath.slice(0, idx),
    name: cleanPath.slice(idx + 1),
  };
}

/**
 * Builds a clean hierarchical folder tree and per-folder table rows from `dandi-core` entries.
 * Preserves synthesized parent folders (`MacPacker#47`) and computes extractable entry index sets
 * for folder-level selective extraction.
 */
export function buildArchiveTree(
  entries: ArchiveEntryInfo[],
  showOsJunk: boolean
): ArchiveTreeModel {
  const folderMap = new Map<string, FolderNode>();
  const rowMap = new Map<string, TableRow>();

  const ensureFolder = (folderPath: string, isSynthesized: boolean): FolderNode => {
    const existing = folderMap.get(folderPath);
    if (existing) {
      if (!isSynthesized) {
        existing.isSynthesized = false;
      }
      return existing;
    }

    if (folderPath === "") {
      const rootNode: FolderNode = {
        path: "",
        name: "",
        depth: 0,
        children: [],
        directCount: 0,
        extractableIndices: [],
        isSynthesized: false,
      };
      folderMap.set("", rootNode);
      return rootNode;
    }

    const { parent, name } = splitParentAndName(folderPath);
    const parentNode = ensureFolder(parent, true);
    const node: FolderNode = {
      path: folderPath,
      name,
      depth: parentNode.depth + 1,
      children: [],
      directCount: 0,
      extractableIndices: [],
      isSynthesized,
    };
    folderMap.set(folderPath, node);
    parentNode.children.push(node);
    return node;
  };

  const root = ensureFolder("", false);
  const allExtractableSet = new Set<number>();

  for (const entry of entries) {
    if (!showOsJunk && entry.is_os_junk) {
      continue;
    }

    const clean = stripTrailingSlashes(entry.path);
    if (!clean) continue;

    const { parent, name } = splitParentAndName(clean);
    ensureFolder(parent, true);

    if (entry.kind === "directory") {
      const folder = ensureFolder(clean, entry.is_synthesized);
      if (entry.index !== null) {
        allExtractableSet.add(entry.index);
        folder.extractableIndices.push(entry.index);
      }
      const existingRow = rowMap.get(clean);
      if (!existingRow || existingRow.isSynthesized) {
        rowMap.set(clean, {
          path: clean,
          name,
          parentPath: parent,
          isDirectory: true,
          isSymlink: false,
          isSynthesized: entry.is_synthesized,
          isOsJunk: entry.is_os_junk,
          encrypted: entry.encrypted,
          uncompressedSize: 0,
          compressedSize: 0,
          modifiedUnixSecs: entry.modified_unix_secs,
          compressionMethod: entry.compression_method,
          symlinkTarget: null,
          extractableIndices: entry.index !== null ? [entry.index] : [],
        });
      }
    } else {
      const indices = entry.index !== null ? [entry.index] : [];
      if (entry.index !== null) {
        allExtractableSet.add(entry.index);
      }
      rowMap.set(clean, {
        path: clean,
        name,
        parentPath: parent,
        isDirectory: false,
        isSymlink: entry.kind === "symlink",
        isSynthesized: entry.is_synthesized,
        isOsJunk: entry.is_os_junk,
        encrypted: entry.encrypted,
        uncompressedSize: entry.uncompressed_size,
        compressedSize: entry.compressed_size,
        modifiedUnixSecs: entry.modified_unix_secs,
        compressionMethod: entry.compression_method,
        symlinkTarget: entry.symlink_target,
        extractableIndices: indices,
      });

      // Propagate real entry index up every ancestor folder for folder-level selective extraction.
      if (entry.index !== null) {
        let cur: string | null = parent;
        while (cur !== null) {
          const folder = folderMap.get(cur);
          if (folder) {
            folder.extractableIndices.push(entry.index);
          }
          if (cur === "") break;
          cur = splitParentAndName(cur).parent;
        }
      }
    }
  }

  // Ensure every synthesized intermediate folder also appears as a directory row in its parent.
  for (const [folderPath, node] of folderMap.entries()) {
    if (folderPath === "") continue;
    const { parent, name } = splitParentAndName(folderPath);
    const existing = rowMap.get(folderPath);
    if (!existing) {
      rowMap.set(folderPath, {
        path: folderPath,
        name,
        parentPath: parent,
        isDirectory: true,
        isSymlink: false,
        isSynthesized: node.isSynthesized,
        isOsJunk: false,
        encrypted: false,
        uncompressedSize: 0,
        compressedSize: 0,
        modifiedUnixSecs: null,
        compressionMethod: "synthesized",
        symlinkTarget: null,
        extractableIndices: [...node.extractableIndices],
      });
    } else {
      // Merge deduplicated subtree extractable indices into the folder row.
      const merged = new Set<number>([
        ...existing.extractableIndices,
        ...node.extractableIndices,
      ]);
      existing.extractableIndices = Array.from(merged).sort((a, b) => a - b);
    }
  }

  // Propagate subfolder explicit directory indices up to ancestor folders too and deduplicate.
  const deduplicateFolderIndices = (node: FolderNode): number[] => {
    const set = new Set<number>(node.extractableIndices);
    for (const child of node.children) {
      for (const idx of deduplicateFolderIndices(child)) {
        set.add(idx);
      }
    }
    node.children.sort((a, b) =>
      a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" })
    );
    const sorted = Array.from(set).sort((a, b) => a - b);
    node.extractableIndices = sorted;
    const folderRow = rowMap.get(node.path);
    if (folderRow) {
      folderRow.extractableIndices = sorted;
    }
    return sorted;
  };
  deduplicateFolderIndices(root);

  // Group direct rows by parentPath.
  const rowsByFolder = new Map<string, TableRow[]>();
  const allRows: TableRow[] = [];
  for (const row of rowMap.values()) {
    allRows.push(row);
    const list = rowsByFolder.get(row.parentPath) ?? [];
    list.push(row);
    rowsByFolder.set(row.parentPath, list);
  }

  for (const [folderPath, rows] of rowsByFolder.entries()) {
    const folder = folderMap.get(folderPath);
    if (folder) {
      folder.directCount = rows.length;
    }
  }

  return {
    root,
    rowsByFolder,
    allRows,
    allExtractableIndices: Array.from(allExtractableSet).sort((a, b) => a - b),
  };
}

export function filterAndSortRows(
  model: ArchiveTreeModel,
  activeFolder: string,
  searchQuery: string,
  sortField: SortField,
  sortDirection: SortDirection
): TableRow[] {
  const query = searchQuery.trim().toLowerCase();
  let rows: TableRow[];

  if (query.length > 0) {
    rows = model.allRows.filter((row) => {
      if (activeFolder && row.path !== activeFolder && !row.path.startsWith(`${activeFolder}/`)) {
        return false;
      }
      return row.path.toLowerCase().includes(query);
    });
  } else {
    rows = [...(model.rowsByFolder.get(activeFolder) ?? [])];
  }

  const dirMultiplier = sortDirection === "asc" ? 1 : -1;
  rows.sort((a, b) => {
    // Keep folders grouped ahead of files like native Finder / Explorer.
    if (a.isDirectory !== b.isDirectory) {
      return a.isDirectory ? -1 : 1;
    }
    let cmp = 0;
    switch (sortField) {
      case "name":
        cmp = a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" });
        break;
      case "size":
        cmp = a.uncompressedSize - b.uncompressedSize;
        break;
      case "compressed":
        cmp = a.compressedSize - b.compressedSize;
        break;
      case "modified":
        cmp = (a.modifiedUnixSecs ?? 0) - (b.modifiedUnixSecs ?? 0);
        break;
    }
    if (cmp !== 0) return cmp * dirMultiplier;
    return a.path.localeCompare(b.path, undefined, { numeric: true, sensitivity: "base" });
  });

  return rows;
}

export function getRowSelectionState(
  row: TableRow,
  selectedIndices: ReadonlySet<number>
): "checked" | "indeterminate" | "unchecked" {
  if (row.extractableIndices.length === 0) return "unchecked";
  let hits = 0;
  for (const idx of row.extractableIndices) {
    if (selectedIndices.has(idx)) hits += 1;
  }
  if (hits === 0) return "unchecked";
  if (hits === row.extractableIndices.length) return "checked";
  return "indeterminate";
}

export function toggleRowSelection(
  row: TableRow,
  selectedIndices: ReadonlySet<number>
): Set<number> {
  const next = new Set(selectedIndices);
  const state = getRowSelectionState(row, selectedIndices);
  if (state === "checked") {
    for (const idx of row.extractableIndices) {
      next.delete(idx);
    }
  } else {
    for (const idx of row.extractableIndices) {
      next.add(idx);
    }
  }
  return next;
}
