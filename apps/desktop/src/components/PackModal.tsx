import { useState } from "react";
import {
  AlertTriangle,
  Eye,
  EyeOff,
  FilePlus,
  FolderPlus,
  PackagePlus,
  Trash2,
  X,
} from "lucide-react";
import type { Dictionary } from "../i18n";
import { pathBasename } from "../lib/format";
import type { PackDraftState } from "../lib/state";

interface PackModalProps {
  t: Dictionary;
  draft: PackDraftState;
  onUpdate: (patch: Partial<PackDraftState>) => void;
  onAddFiles: () => void;
  onAddFolders: () => void;
  onPickOutput: () => void;
  onSubmit: () => void;
  onClose: () => void;
}

export function PackModal({
  t,
  draft,
  onUpdate,
  onAddFiles,
  onAddFolders,
  onPickOutput,
  onSubmit,
  onClose,
}: PackModalProps) {
  const [showPassword, setShowPassword] = useState(false);

  const canSubmit = draft.inputs.length > 0 && draft.outputZip.trim().length > 0;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/45 p-4 backdrop-blur-[1px]"
      role="dialog"
      aria-modal="true"
      aria-label={t.packTitle}
    >
      <div
        className="flex max-h-[86vh] w-full max-w-lg flex-col overflow-hidden rounded-xl border shadow-2xl"
        style={{
          backgroundColor: "var(--bg-elevated)",
          borderColor: "var(--border-strong)",
        }}
      >
        {/* Header */}
        <div
          className="flex items-center justify-between border-b px-4 py-3"
          style={{ borderColor: "var(--border-subtle)" }}
        >
          <div className="flex items-center gap-2">
            <PackagePlus className="h-4 w-4" style={{ color: "var(--accent)" }} />
            <h2 className="text-sm font-semibold">{t.packTitle}</h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1 transition-colors hover:bg-[var(--bg-hover)]"
            style={{ color: "var(--text-muted)" }}
            aria-label={t.close}
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 space-y-4 overflow-y-auto p-4 text-xs">
          {/* Input list */}
          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <span className="font-medium" style={{ color: "var(--text-secondary)" }}>
                {t.packInputs} ({draft.inputs.length})
              </span>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={onAddFiles}
                  className="inline-flex items-center gap-1 rounded border px-2 py-1 text-[11px] font-medium transition-colors hover:bg-[var(--bg-hover)]"
                  style={{ borderColor: "var(--border-subtle)" }}
                >
                  <FilePlus className="h-3 w-3" />
                  <span>{t.addFiles}</span>
                </button>
                <button
                  type="button"
                  onClick={onAddFolders}
                  className="inline-flex items-center gap-1 rounded border px-2 py-1 text-[11px] font-medium transition-colors hover:bg-[var(--bg-hover)]"
                  style={{ borderColor: "var(--border-subtle)" }}
                >
                  <FolderPlus className="h-3 w-3" />
                  <span>{t.addFolder}</span>
                </button>
              </div>
            </div>

            <div
              className="max-h-36 overflow-y-auto rounded-lg border"
              style={{
                backgroundColor: "var(--bg-app)",
                borderColor: "var(--border-subtle)",
              }}
            >
              {draft.inputs.length === 0 ? (
                <div className="px-3 py-6 text-center" style={{ color: "var(--text-muted)" }}>
                  {t.addFiles} / {t.addFolder}
                </div>
              ) : (
                draft.inputs.map((item) => (
                  <div
                    key={item}
                    className="flex items-center justify-between gap-2 border-b px-2.5 py-1.5 last:border-b-0"
                    style={{ borderColor: "var(--border-subtle)" }}
                  >
                    <div className="min-w-0">
                      <div className="truncate font-medium">{pathBasename(item)}</div>
                      <div
                        className="font-mono-tabular truncate text-[10px]"
                        style={{ color: "var(--text-muted)" }}
                      >
                        {item}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        onUpdate({
                          inputs: draft.inputs.filter((p) => p !== item),
                        })
                      }
                      className="rounded p-1 transition-colors hover:bg-[var(--bg-hover)]"
                      style={{ color: "var(--text-muted)" }}
                      title={t.remove}
                      aria-label={t.remove}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Output path */}
          <div>
            <label
              className="mb-1.5 block font-medium"
              style={{ color: "var(--text-secondary)" }}
            >
              {t.outputPath}
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={draft.outputZip}
                onChange={(e) => onUpdate({ outputZip: e.target.value })}
                className="font-mono-tabular min-w-0 flex-1 rounded-md border px-2.5 py-1.5 text-xs outline-none focus:border-[var(--accent)]"
                style={{
                  backgroundColor: "var(--bg-app)",
                  borderColor: "var(--border-subtle)",
                  color: "var(--text-primary)",
                }}
              />
              <button
                type="button"
                onClick={onPickOutput}
                className="shrink-0 rounded-md border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--bg-hover)]"
                style={{ borderColor: "var(--border-strong)" }}
              >
                {t.browse}
              </button>
            </div>
          </div>

          {/* Compression level */}
          <div>
            <span
              className="mb-1.5 block font-medium"
              style={{ color: "var(--text-secondary)" }}
            >
              {t.compressionLevel}
            </span>
            <div className="grid grid-cols-3 gap-1.5">
              {[
                { level: 1, label: t.levelFast },
                { level: 6, label: t.levelBalanced },
                { level: 9, label: t.levelMax },
              ].map((opt) => {
                const active = draft.compressionLevel === opt.level;
                return (
                  <button
                    key={opt.level}
                    type="button"
                    onClick={() => onUpdate({ compressionLevel: opt.level })}
                    className="rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors"
                    style={{
                      borderColor: active ? "var(--accent-border)" : "var(--border-subtle)",
                      backgroundColor: active ? "var(--accent-soft)" : "var(--bg-app)",
                      color: active ? "var(--text-primary)" : "var(--text-secondary)",
                    }}
                  >
                    {opt.label}
                  </button>
                );
              })}
            </div>
          </div>

          {/* OS Junk Toggle */}
          <label
            className="flex cursor-pointer items-start gap-2.5 rounded-lg border p-2.5"
            style={{
              backgroundColor: "var(--bg-app)",
              borderColor: "var(--border-subtle)",
            }}
          >
            <input
              type="checkbox"
              checked={draft.excludeOsJunk}
              onChange={(e) => onUpdate({ excludeOsJunk: e.target.checked })}
              className="mt-0.5 accent-[var(--accent)]"
            />
            <div>
              <div className="font-medium">{t.excludeOsJunk}</div>
              <div className="mt-0.5 text-[11px]" style={{ color: "var(--text-muted)" }}>
                {t.excludeOsJunkHint}
              </div>
            </div>
          </label>

          {/* Optional AES-256 Password */}
          <div>
            <label
              className="mb-1.5 block font-medium"
              style={{ color: "var(--text-secondary)" }}
            >
              {t.passwordOptional}
            </label>
            <div className="relative">
              <input
                type={showPassword ? "text" : "password"}
                value={draft.password}
                onChange={(e) => onUpdate({ password: e.target.value })}
                placeholder={t.passwordPlaceholder}
                autoComplete="new-password"
                className="w-full rounded-md border py-1.5 pl-2.5 pr-9 text-xs outline-none focus:border-[var(--accent)]"
                style={{
                  backgroundColor: "var(--bg-app)",
                  borderColor: "var(--border-subtle)",
                  color: "var(--text-primary)",
                }}
              />
              <button
                type="button"
                onClick={() => setShowPassword((v) => !v)}
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 hover:bg-[var(--bg-hover)]"
                style={{ color: "var(--text-muted)" }}
                aria-label="Toggle password visibility"
              >
                {showPassword ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
              </button>
            </div>

            <div
              className="mt-2 flex items-start gap-2 rounded-md border px-2.5 py-2 text-[11px] leading-relaxed"
              style={{
                backgroundColor: "var(--warn-bg)",
                borderColor: "var(--warn-border)",
                color: "var(--warn-text)",
              }}
            >
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>{t.aesWindowsWarning}</span>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div
          className="flex items-center justify-end gap-2 border-t px-4 py-3"
          style={{ borderColor: "var(--border-subtle)" }}
        >
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--bg-hover)]"
            style={{ borderColor: "var(--border-subtle)" }}
          >
            {t.cancel}
          </button>
          <button
            type="button"
            disabled={!canSubmit}
            onClick={onSubmit}
            className="rounded-md px-3.5 py-1.5 text-xs font-medium text-white transition-colors hover:brightness-105 disabled:opacity-45"
            style={{ backgroundColor: "var(--accent)" }}
          >
            {t.startPack}
          </button>
        </div>
      </div>
    </div>
  );
}
