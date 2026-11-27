import { useEffect, useState } from "react";
import { Loader2 } from "lucide-react";
import type { Dictionary } from "../i18n";
import { formatBytes, formatProgressPercent, formatSpeed } from "../lib/format";
import type { ActiveOperation } from "../lib/state";

interface ProgressModalProps {
  t: Dictionary;
  op: ActiveOperation;
  onCancel: () => void;
}

export function ProgressModal({ t, op, onCancel }: ProgressModalProps) {
  const [nowMs, setNowMs] = useState(() => Date.now());

  useEffect(() => {
    const timer = window.setInterval(() => setNowMs(Date.now()), 250);
    return () => window.clearInterval(timer);
  }, []);

  const title =
    op.kind === "pack"
      ? t.progressTitlePack
      : op.kind === "unpack"
        ? t.progressTitleUnpack
        : t.progressTitleFix;

  const p = op.progress;
  const percent = p
    ? formatProgressPercent(p.bytes_done, p.bytes_total, p.entries_done, p.entries_total)
    : 0;
  const elapsedMs = Math.max(1, nowMs - op.startedAtMs);
  const speed = p ? formatSpeed(p.bytes_done, elapsedMs) : "—";
  const phaseLabel = p ? t.phases[p.phase] : t.phases.scanning;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/45 p-4 backdrop-blur-[1px]"
      role="dialog"
      aria-modal="true"
      aria-label={title}
    >
      <div
        className="w-full max-w-md rounded-xl border p-5 shadow-2xl"
        style={{
          backgroundColor: "var(--bg-elevated)",
          borderColor: "var(--border-strong)",
        }}
      >
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Loader2
              className="h-4 w-4 animate-spin"
              style={{ color: "var(--accent)" }}
            />
            <h2 className="text-sm font-semibold">{title}</h2>
          </div>
          <span className="font-mono-tabular text-xs font-semibold">{percent}%</span>
        </div>

        {/* Progress track */}
        <div
          className="mt-3 h-2 w-full overflow-hidden rounded-full"
          style={{ backgroundColor: "var(--bg-active)" }}
        >
          <div
            className="h-full rounded-full transition-[width] duration-100"
            style={{
              width: `${percent}%`,
              backgroundColor: "var(--accent)",
            }}
          />
        </div>

        <div className="mt-3 flex items-center justify-between text-[11px]">
          <span className="font-medium" style={{ color: "var(--text-secondary)" }}>
            {phaseLabel}
          </span>
          <span className="font-mono-tabular" style={{ color: "var(--text-muted)" }}>
            {p ? t.progressEntries(p.entries_done, p.entries_total) : "—"}
          </span>
        </div>

        <div
          className="font-mono-tabular mt-1.5 truncate rounded border px-2.5 py-1.5 text-[11px]"
          style={{
            backgroundColor: "var(--bg-app)",
            borderColor: "var(--border-subtle)",
            color: "var(--text-secondary)",
          }}
          title={p?.current_entry ?? ""}
        >
          {p?.current_entry || "…"}
        </div>

        <div className="mt-3 flex items-center justify-between">
          <div
            className="font-mono-tabular flex items-center gap-2 text-[11px]"
            style={{ color: "var(--text-muted)" }}
          >
            <span>
              {p
                ? `${formatBytes(p.bytes_done)}${p.bytes_total > 0 ? ` / ${formatBytes(p.bytes_total)}` : ""}`
                : "0 B"}
            </span>
            <span>·</span>
            <span>{speed}</span>
          </div>

          <button
            type="button"
            disabled={op.cancelling}
            onClick={onCancel}
            className="rounded-md border px-3 py-1 text-xs font-medium transition-colors hover:bg-[var(--bg-hover)] disabled:opacity-50"
            style={{
              borderColor: "var(--border-strong)",
              color: "var(--danger-text)",
            }}
          >
            {op.cancelling ? t.cancelling : t.cancel}
          </button>
        </div>
      </div>
    </div>
  );
}
