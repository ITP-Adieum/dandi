import { useMemo, useState } from "react";
import {
  ArrowDown,
  ArrowUp,
  ChevronDown,
  ChevronRight,
  Download,
  File,
  Folder,
  FolderOpen,
  Link2,
  Lock,
  Search,
  Sparkles,
  X,
} from "lucide-react";
import type { Dictionary } from "../i18n";
import {
  formatBytes,
  formatFormatLabel,
  formatSavingsRatio,
  formatTimestamp,
} from "../lib/format";
import {
  buildArchiveTree,
  filterAndSortRows,
  getRowSelectionState,
  toggleRowSelection,
  type FolderNode,
  type SortDirection,
  type SortField,
  type TableRow,
} from "../lib/tree";
import type {
  ArchiveSummary,
  EncodingOption,
  ExtractMode,
} from "../types";
import { EncodingPicker } from "./EncodingPicker";

interface ArchiveExplorerProps {
  t: Dictionary;
  summary: ArchiveSummary;
  encodings: EncodingOption[];
  encodingOverride: string | null;
  showOsJunk: boolean;
  extractMode: ExtractMode;
  revealAfterExtract: boolean;
  activeFolder: string;
  searchQuery: string;
  selectedIndices: number[];
  busy: boolean;
  onSelectEncoding: (canonicalName: string | null) => void;
  onFixEncoding: () => void;
  onToggleShowOsJunk: (value: boolean) => void;
  onSelectFolder: (folderPath: string) => void;
  onSearchChange: (query: string) => void;
  onSelectedIndicesChange: (indices: number[]) => void;
  onExtractModeChange: (mode: ExtractMode) => void;
  onRevealAfterChange: (value: boolean) => void;
  onExtractAll: () => void;
  onExtractSelected: () => void;
}

export function ArchiveExplorer({
  t,
  summary,
  encodings,
  encodingOverride,
  showOsJunk,
  extractMode,
  revealAfterExtract,
  activeFolder,
  searchQuery,
  selectedIndices,
  busy,
  onSelectEncoding,
  onFixEncoding,
  onToggleShowOsJunk,
  onSelectFolder,
  onSearchChange,
  onSelectedIndicesChange,
  onExtractModeChange,
  onRevealAfterChange,
  onExtractAll,
  onExtractSelected,
}: ArchiveExplorerProps) {
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(() => new Set([""]));
  const [sortField, setSortField] = useState<SortField>("name");
  const [sortDirection, setSortDirection] = useState<SortDirection>("asc");

  const treeModel = useMemo(
    () => buildArchiveTree(summary.entries, showOsJunk),
    [summary.entries, showOsJunk]
  );

  const visibleRows = useMemo(
    () =>
      filterAndSortRows(treeModel, activeFolder, searchQuery, sortField, sortDirection),
    [treeModel, activeFolder, searchQuery, sortField, sortDirection]
  );

  const selectedSet = useMemo(() => new Set(selectedIndices), [selectedIndices]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortField(field);
      setSortDirection("asc");
    }
  };

  const toggleExpand = (folderPath: string) => {
    setExpandedFolders((prev) => {
      const next = new Set(prev);
      if (next.has(folderPath)) {
        next.delete(folderPath);
      } else {
        next.add(folderPath);
      }
      return next;
    });
  };

  const handleRowToggle = (row: TableRow) => {
    const next = toggleRowSelection(row, selectedSet);
    onSelectedIndicesChange(Array.from(next).sort((a, b) => a - b));
  };

  const handleSelectAllVisible = () => {
    const next = new Set(selectedSet);
    for (const row of visibleRows) {
      for (const idx of row.extractableIndices) {
        next.add(idx);
      }
    }
    onSelectedIndicesChange(Array.from(next).sort((a, b) => a - b));
  };

  const isZip = summary.format === "zip";
  const isLegacyEncoding = summary.applied_encoding !== "utf8";
  const savings = formatSavingsRatio(
    summary.total_uncompressed_bytes,
    summary.total_compressed_bytes
  );

  const breadcrumbs = activeFolder ? activeFolder.split("/") : [];

  const renderFolderBranch = (node: FolderNode) => {
    const hasChildren = node.children.length > 0;
    const isExpanded = node.path === "" || expandedFolders.has(node.path);
    const isActive = activeFolder === node.path;

    return (
      <div key={node.path || "__root__"}>
        <div
          className="group flex items-center gap-1 rounded-md px-1.5 py-1 text-xs transition-colors hover:bg-[var(--bg-hover)]"
          style={{
            paddingLeft: `${node.depth * 14 + 6}px`,
            backgroundColor: isActive ? "var(--bg-active)" : undefined,
            color: isActive ? "var(--text-primary)" : "var(--text-secondary)",
          }}
        >
          {hasChildren && node.path !== "" ? (
            <button
              type="button"
              onClick={() => toggleExpand(node.path)}
              className="flex h-4 w-4 shrink-0 items-center justify-center rounded hover:bg-[var(--bg-hover)]"
              aria-label="Toggle folder"
            >
              {isExpanded ? (
                <ChevronDown className="h-3 w-3" />
              ) : (
                <ChevronRight className="h-3 w-3" />
              )}
            </button>
          ) : (
            <span className="h-4 w-4 shrink-0" />
          )}

          <button
            type="button"
            onClick={() => {
              onSelectFolder(node.path);
              if (hasChildren && !isExpanded) {
                toggleExpand(node.path);
              }
            }}
            className="flex min-w-0 flex-1 items-center gap-1.5 text-left"
          >
            {isActive ? (
              <FolderOpen
                className="h-3.5 w-3.5 shrink-0"
                style={{ color: "var(--accent)" }}
              />
            ) : (
              <Folder
                className="h-3.5 w-3.5 shrink-0"
                style={{ color: "var(--text-muted)" }}
              />
            )}
            <span className="truncate font-medium">
              {node.path === "" ? t.allFiles : node.name}
            </span>
            <span
              className="font-mono-tabular ml-auto shrink-0 text-[10px]"
              style={{ color: "var(--text-muted)" }}
            >
              {node.directCount}
            </span>
          </button>
        </div>

        {isExpanded && node.children.map((child) => renderFolderBranch(child))}
      </div>
    );
  };

  const renderSortIcon = (field: SortField) => {
    if (sortField !== field) return null;
    return sortDirection === "asc" ? (
      <ArrowUp className="h-3 w-3" />
    ) : (
      <ArrowDown className="h-3 w-3" />
    );
  };

  const modeHint =
    extractMode === "smart"
      ? t.modeSmartHint
      : extractMode === "direct"
        ? t.modeDirectHint
        : t.modeWrapHint;

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {/* Archive summary & encoding strip */}
      <section
        className="flex flex-wrap items-center justify-between gap-2 border-b px-3.5 py-2"
        style={{
          backgroundColor: "var(--bg-app)",
          borderColor: "var(--border-subtle)",
        }}
      >
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span
            className="font-mono-tabular rounded border px-1.5 py-0.5 text-[11px] font-semibold"
            style={{
              backgroundColor: "var(--bg-surface)",
              borderColor: "var(--border-strong)",
              color: "var(--text-primary)",
            }}
          >
            {formatFormatLabel(summary.format)}
          </span>

          <span className="tabular-nums" style={{ color: "var(--text-secondary)" }}>
            {t.entriesLabel(summary.total_entries)}
          </span>
          <span style={{ color: "var(--border-strong)" }}>·</span>
          <span className="font-mono-tabular" style={{ color: "var(--text-secondary)" }}>
            {formatBytes(summary.total_uncompressed_bytes)}
          </span>
          {summary.total_compressed_bytes > 0 && (
            <span className="font-mono-tabular text-[11px]" style={{ color: "var(--text-muted)" }}>
              ({formatBytes(summary.total_compressed_bytes)}, {savings})
            </span>
          )}

          {summary.encrypted && (
            <span
              className="inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-medium"
              style={{
                backgroundColor: "var(--warn-bg)",
                borderColor: "var(--warn-border)",
                color: "var(--warn-text)",
              }}
            >
              <Lock className="h-3 w-3" />
              <span>{t.encryptedBadge}</span>
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <EncodingPicker
            t={t}
            appliedEncoding={summary.applied_encoding}
            detection={summary.encoding}
            encodingOverride={encodingOverride}
            encodings={encodings}
            disabled={busy}
            onSelectEncoding={onSelectEncoding}
          />

          {isZip && (
            <button
              type="button"
              disabled={busy}
              onClick={onFixEncoding}
              className="inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors hover:bg-[var(--bg-hover)] disabled:opacity-50"
              style={{
                borderColor: isLegacyEncoding ? "var(--accent-border)" : "var(--border-strong)",
                backgroundColor: isLegacyEncoding ? "var(--accent)" : "var(--bg-surface)",
                color: isLegacyEncoding ? "#ffffff" : "var(--text-primary)",
              }}
            >
              <Sparkles className="h-3.5 w-3.5" />
              <span>{t.fixEncoding}</span>
            </button>
          )}
        </div>
      </section>

      {/* Main split workspace: Folder Tree + File Table */}
      <div className="flex min-h-0 flex-1 overflow-hidden">
        {/* Left folder tree sidebar */}
        <aside
          className="flex w-56 shrink-0 flex-col border-r"
          style={{
            backgroundColor: "var(--bg-sidebar)",
            borderColor: "var(--border-subtle)",
          }}
        >
          <div
            className="flex items-center justify-between border-b px-3 py-2 text-[11px] font-semibold uppercase tracking-wider"
            style={{
              borderColor: "var(--border-subtle)",
              color: "var(--text-muted)",
            }}
          >
            <span>{t.folders}</span>
          </div>
          <div className="flex-1 overflow-y-auto p-1.5">
            {renderFolderBranch(treeModel.root)}
          </div>
        </aside>

        {/* Right entry table */}
        <div
          className="flex min-w-0 flex-1 flex-col"
          style={{ backgroundColor: "var(--bg-surface)" }}
        >
          {/* Search + breadcrumb + selection toolbar */}
          <div
            className="flex flex-wrap items-center justify-between gap-2 border-b px-3 py-2"
            style={{ borderColor: "var(--border-subtle)" }}
          >
            <div className="flex min-w-0 items-center gap-1 text-xs">
              <button
                type="button"
                onClick={() => onSelectFolder("")}
                className="rounded px-1.5 py-0.5 font-medium transition-colors hover:bg-[var(--bg-hover)]"
                style={{
                  color: activeFolder === "" ? "var(--text-primary)" : "var(--text-muted)",
                }}
              >
                /
              </button>
              {breadcrumbs.map((segment, idx) => {
                const target = breadcrumbs.slice(0, idx + 1).join("/");
                const isLast = idx === breadcrumbs.length - 1;
                return (
                  <span key={target} className="flex min-w-0 items-center gap-1">
                    <span style={{ color: "var(--text-muted)" }}>/</span>
                    <button
                      type="button"
                      onClick={() => onSelectFolder(target)}
                      className="max-w-36 truncate rounded px-1.5 py-0.5 font-medium transition-colors hover:bg-[var(--bg-hover)]"
                      style={{
                        color: isLast ? "var(--text-primary)" : "var(--text-secondary)",
                      }}
                    >
                      {segment}
                    </button>
                  </span>
                );
              })}
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <div className="relative">
                <Search
                  className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2"
                  style={{ color: "var(--text-muted)" }}
                />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => onSearchChange(e.target.value)}
                  placeholder={t.searchPlaceholder}
                  className="w-48 rounded-md border py-1 pl-7 pr-6 text-xs outline-none focus:border-[var(--accent)]"
                  style={{
                    backgroundColor: "var(--bg-app)",
                    borderColor: "var(--border-subtle)",
                    color: "var(--text-primary)",
                  }}
                />
                {searchQuery && (
                  <button
                    type="button"
                    onClick={() => onSearchChange("")}
                    className="absolute right-1.5 top-1/2 -translate-y-1/2 rounded p-0.5 hover:bg-[var(--bg-hover)]"
                    style={{ color: "var(--text-muted)" }}
                    aria-label="Clear filter"
                  >
                    <X className="h-3 w-3" />
                  </button>
                )}
              </div>

              <button
                type="button"
                onClick={handleSelectAllVisible}
                className="rounded-md border px-2 py-1 text-[11px] font-medium transition-colors hover:bg-[var(--bg-hover)]"
                style={{
                  borderColor: "var(--border-subtle)",
                  color: "var(--text-secondary)",
                }}
              >
                {t.selectAll}
              </button>

              {selectedIndices.length > 0 && (
                <button
                  type="button"
                  onClick={() => onSelectedIndicesChange([])}
                  className="rounded-md border px-2 py-1 text-[11px] font-medium transition-colors hover:bg-[var(--bg-hover)]"
                  style={{
                    borderColor: "var(--border-subtle)",
                    color: "var(--accent)",
                  }}
                >
                  {t.clearSelection} ({selectedIndices.length})
                </button>
              )}

              <label
                className="inline-flex cursor-pointer items-center gap-1.5 text-[11px]"
                style={{ color: "var(--text-muted)" }}
              >
                <input
                  type="checkbox"
                  checked={showOsJunk}
                  onChange={(e) => onToggleShowOsJunk(e.target.checked)}
                  className="accent-[var(--accent)]"
                />
                <span>{t.showOsJunk}</span>
              </label>
            </div>
          </div>

          {/* Entry rows table */}
          <div className="min-h-0 flex-1 overflow-auto">
            <table className="w-full border-collapse text-left text-xs">
              <thead
                className="sticky top-0 z-10 border-b text-[11px] font-medium"
                style={{
                  backgroundColor: "var(--bg-sidebar)",
                  borderColor: "var(--border-subtle)",
                  color: "var(--text-muted)",
                }}
              >
                <tr>
                  <th className="w-9 px-3 py-2" />
                  <th className="px-2 py-2">
                    <button
                      type="button"
                      onClick={() => handleSort("name")}
                      className="inline-flex items-center gap-1 hover:text-[var(--text-primary)]"
                    >
                      <span>{t.colName}</span>
                      {renderSortIcon("name")}
                    </button>
                  </th>
                  <th className="w-24 px-2 py-2 text-right">
                    <button
                      type="button"
                      onClick={() => handleSort("size")}
                      className="inline-flex items-center justify-end gap-1 hover:text-[var(--text-primary)]"
                    >
                      <span>{t.colSize}</span>
                      {renderSortIcon("size")}
                    </button>
                  </th>
                  <th className="w-24 px-2 py-2 text-right">
                    <button
                      type="button"
                      onClick={() => handleSort("compressed")}
                      className="inline-flex items-center justify-end gap-1 hover:text-[var(--text-primary)]"
                    >
                      <span>{t.colCompressed}</span>
                      {renderSortIcon("compressed")}
                    </button>
                  </th>
                  <th className="w-16 px-2 py-2 text-right">{t.colRatio}</th>
                  <th className="w-36 px-3 py-2 text-right">
                    <button
                      type="button"
                      onClick={() => handleSort("modified")}
                      className="inline-flex items-center justify-end gap-1 hover:text-[var(--text-primary)]"
                    >
                      <span>{t.colModified}</span>
                      {renderSortIcon("modified")}
                    </button>
                  </th>
                </tr>
              </thead>
              <tbody>
                {visibleRows.length === 0 ? (
                  <tr>
                    <td
                      colSpan={6}
                      className="px-4 py-14 text-center text-xs"
                      style={{ color: "var(--text-muted)" }}
                    >
                      {searchQuery.trim() ? t.noSearchResults : t.emptyFolder}
                    </td>
                  </tr>
                ) : (
                  visibleRows.map((row) => {
                    const selState = getRowSelectionState(row, selectedSet);
                    const checked = selState === "checked";
                    const indeterminate = selState === "indeterminate";
                    return (
                      <tr
                        key={row.path}
                        onDoubleClick={() => {
                          if (row.isDirectory) {
                            onSelectFolder(row.path);
                            setExpandedFolders((prev) => new Set(prev).add(row.path));
                          }
                        }}
                        className="border-b transition-colors hover:bg-[var(--bg-hover)]"
                        style={{
                          borderColor: "var(--border-subtle)",
                          backgroundColor: checked ? "var(--accent-soft)" : undefined,
                        }}
                      >
                        <td className="px-3 py-1.5">
                          <input
                            type="checkbox"
                            checked={checked}
                            ref={(el) => {
                              if (el) el.indeterminate = indeterminate;
                            }}
                            disabled={row.extractableIndices.length === 0}
                            onChange={() => handleRowToggle(row)}
                            className="cursor-pointer accent-[var(--accent)]"
                            aria-label={row.name}
                          />
                        </td>
                        <td className="max-w-0 px-2 py-1.5">
                          <div className="flex items-center gap-2">
                            {row.isDirectory ? (
                              <Folder
                                className="h-3.5 w-3.5 shrink-0"
                                style={{ color: "var(--accent)" }}
                              />
                            ) : row.isSymlink ? (
                              <Link2
                                className="h-3.5 w-3.5 shrink-0"
                                style={{ color: "var(--text-muted)" }}
                              />
                            ) : (
                              <File
                                className="h-3.5 w-3.5 shrink-0"
                                style={{ color: "var(--text-muted)" }}
                              />
                            )}
                            <button
                              type="button"
                              onClick={() => {
                                if (row.isDirectory) {
                                  onSelectFolder(row.path);
                                  setExpandedFolders((prev) => new Set(prev).add(row.path));
                                } else {
                                  handleRowToggle(row);
                                }
                              }}
                              className="truncate text-left font-medium hover:underline"
                              title={row.path}
                            >
                              {searchQuery.trim() ? row.path : row.name}
                            </button>
                            {row.isSymlink && row.symlinkTarget && (
                              <span
                                className="font-mono-tabular truncate text-[11px]"
                                style={{ color: "var(--text-muted)" }}
                              >
                                → {row.symlinkTarget}
                              </span>
                            )}
                            {row.encrypted && (
                              <Lock
                                className="h-3 w-3 shrink-0"
                                style={{ color: "var(--warn-text)" }}
                              />
                            )}
                            {row.isOsJunk && (
                              <span
                                className="rounded px-1 py-0.5 text-[10px]"
                                style={{
                                  backgroundColor: "var(--bg-active)",
                                  color: "var(--text-muted)",
                                }}
                              >
                                OS
                              </span>
                            )}
                          </div>
                        </td>
                        <td
                          className="font-mono-tabular px-2 py-1.5 text-right"
                          style={{ color: "var(--text-secondary)" }}
                        >
                          {row.isDirectory ? "—" : formatBytes(row.uncompressedSize)}
                        </td>
                        <td
                          className="font-mono-tabular px-2 py-1.5 text-right"
                          style={{ color: "var(--text-muted)" }}
                        >
                          {row.isDirectory ? "—" : formatBytes(row.compressedSize)}
                        </td>
                        <td
                          className="font-mono-tabular px-2 py-1.5 text-right"
                          style={{ color: "var(--text-muted)" }}
                        >
                          {row.isDirectory
                            ? "—"
                            : formatSavingsRatio(row.uncompressedSize, row.compressedSize)}
                        </td>
                        <td
                          className="font-mono-tabular px-3 py-1.5 text-right"
                          style={{ color: "var(--text-muted)" }}
                        >
                          {formatTimestamp(row.modifiedUnixSecs)}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Bottom Extract Action Bar */}
      <footer
        className="flex flex-wrap items-center justify-between gap-3 border-t px-3.5 py-2.5"
        style={{
          backgroundColor: "var(--bg-surface)",
          borderColor: "var(--border-subtle)",
        }}
      >
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="text-xs font-medium" style={{ color: "var(--text-secondary)" }}>
              {t.extractMode}
            </span>
            <div
              className="inline-flex rounded-md border p-0.5"
              style={{
                borderColor: "var(--border-subtle)",
                backgroundColor: "var(--bg-app)",
              }}
              role="radiogroup"
              aria-label={t.extractMode}
            >
              {(
                [
                  { id: "smart", label: t.modeSmart },
                  { id: "direct", label: t.modeDirect },
                  { id: "wrap", label: t.modeWrap },
                ] as { id: ExtractMode; label: string }[]
              ).map((item) => {
                const active = extractMode === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => onExtractModeChange(item.id)}
                    className="rounded px-2.5 py-1 text-xs font-medium transition-colors"
                    style={{
                      backgroundColor: active ? "var(--bg-surface)" : "transparent",
                      color: active ? "var(--text-primary)" : "var(--text-muted)",
                      boxShadow: active ? "0 1px 2px rgba(0,0,0,0.08)" : "none",
                    }}
                  >
                    {item.label}
                  </button>
                );
              })}
            </div>
          </div>

          <span
            className="hidden text-[11px] lg:inline"
            style={{ color: "var(--text-muted)" }}
          >
            {modeHint}
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <label
            className="inline-flex cursor-pointer items-center gap-1.5 text-xs"
            style={{ color: "var(--text-secondary)" }}
          >
            <input
              type="checkbox"
              checked={revealAfterExtract}
              onChange={(e) => onRevealAfterChange(e.target.checked)}
              className="accent-[var(--accent)]"
            />
            <span>{t.openAfterExtract}</span>
          </label>

          {selectedIndices.length > 0 ? (
            <>
              <button
                type="button"
                disabled={busy}
                onClick={onExtractAll}
                className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--bg-hover)] disabled:opacity-50"
                style={{
                  borderColor: "var(--border-strong)",
                  color: "var(--text-primary)",
                }}
              >
                <span>{t.extractAll}</span>
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={onExtractSelected}
                className="inline-flex items-center gap-1.5 rounded-md px-3.5 py-1.5 text-xs font-medium text-white transition-colors hover:brightness-105 disabled:opacity-50"
                style={{ backgroundColor: "var(--accent)" }}
              >
                <Download className="h-3.5 w-3.5" />
                <span>{t.extractSelected(selectedIndices.length)}</span>
              </button>
            </>
          ) : (
            <button
              type="button"
              disabled={busy}
              onClick={onExtractAll}
              className="inline-flex items-center gap-1.5 rounded-md px-3.5 py-1.5 text-xs font-medium text-white transition-colors hover:brightness-105 disabled:opacity-50"
              style={{ backgroundColor: "var(--accent)" }}
            >
              <Download className="h-3.5 w-3.5" />
              <span>{t.extractAll}</span>
            </button>
          )}
        </div>
      </footer>
    </div>
  );
}
