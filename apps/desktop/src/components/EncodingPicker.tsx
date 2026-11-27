import { useEffect, useRef, useState } from "react";
import { Check, ChevronDown, Languages, RotateCcw } from "lucide-react";
import type { Dictionary } from "../i18n";
import { shortEncodingLabel } from "../lib/format";
import type { EncodingDetection, EncodingId, EncodingOption } from "../types";

interface EncodingPickerProps {
  t: Dictionary;
  appliedEncoding: EncodingId;
  detection: EncodingDetection;
  encodingOverride: string | null;
  encodings: EncodingOption[];
  disabled?: boolean;
  onSelectEncoding: (canonicalName: string | null) => void;
}

export function EncodingPicker({
  t,
  appliedEncoding,
  detection,
  encodingOverride,
  encodings,
  disabled,
  onSelectEncoding,
}: EncodingPickerProps) {
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const handleOutside = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("mousedown", handleOutside);
    window.addEventListener("keydown", handleEsc);
    return () => {
      window.removeEventListener("mousedown", handleOutside);
      window.removeEventListener("keydown", handleEsc);
    };
  }, [open]);

  const isManual = encodingOverride !== null;
  const isLegacy = appliedEncoding !== "utf8";
  const confidencePct = Math.round(detection.confidence * 100);
  const modeText = isManual
    ? t.encodingManual
    : confidencePct > 0
      ? `${t.encodingAuto} ${confidencePct}%`
      : t.encodingAuto;

  const topCandidateIds = new Set(
    detection.candidates.slice(0, 3).map((c) => c.encoding)
  );
  const candidateEncodings = encodings.filter((e) => topCandidateIds.has(e.id));

  return (
    <div ref={containerRef} className="relative">
      <button
        type="button"
        disabled={disabled}
        onClick={() => setOpen((v) => !v)}
        title={t.encodingTooltip}
        className="inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors hover:bg-[var(--bg-hover)] disabled:opacity-50"
        style={{
          borderColor: isLegacy ? "var(--accent-border)" : "var(--border-strong)",
          backgroundColor: isLegacy ? "var(--accent-soft)" : "var(--bg-surface)",
          color: "var(--text-primary)",
        }}
      >
        <Languages
          className="h-3.5 w-3.5"
          style={{ color: isLegacy ? "var(--accent)" : "var(--text-secondary)" }}
        />
        <span className="font-mono-tabular font-semibold">
          {shortEncodingLabel(appliedEncoding)}
        </span>
        <span style={{ color: "var(--text-muted)" }}>·</span>
        <span className="tabular-nums" style={{ color: "var(--text-secondary)" }}>
          {modeText}
        </span>
        <ChevronDown className="h-3.5 w-3.5" style={{ color: "var(--text-muted)" }} />
      </button>

      {open && (
        <div
          className="absolute right-0 z-40 mt-1.5 w-72 overflow-hidden rounded-lg border shadow-lg"
          style={{
            backgroundColor: "var(--bg-elevated)",
            borderColor: "var(--border-strong)",
          }}
        >
          <div
            className="border-b px-3 py-2 text-[11px]"
            style={{
              borderColor: "var(--border-subtle)",
              color: "var(--text-muted)",
            }}
          >
            {t.encodingTooltip}
          </div>

          <div className="max-h-80 overflow-y-auto p-1">
            {isManual && (
              <button
                type="button"
                onClick={() => {
                  setOpen(false);
                  onSelectEncoding(null);
                }}
                className="mb-1 flex w-full items-center gap-2 rounded-md px-2.5 py-1.5 text-left text-xs font-medium transition-colors hover:bg-[var(--bg-hover)]"
                style={{ color: "var(--accent)" }}
              >
                <RotateCcw className="h-3.5 w-3.5" />
                <span>{t.encodingResetAuto}</span>
              </button>
            )}

            {candidateEncodings.length > 0 && (
              <>
                <div
                  className="px-2.5 pb-1 pt-1.5 text-[10px] font-semibold uppercase tracking-wider"
                  style={{ color: "var(--text-muted)" }}
                >
                  {t.encodingDetectedTop}
                </div>
                {candidateEncodings.map((opt) => {
                  const active = opt.id === appliedEncoding;
                  const cand = detection.candidates.find((c) => c.encoding === opt.id);
                  return (
                    <button
                      key={`cand-${opt.id}`}
                      type="button"
                      onClick={() => {
                        setOpen(false);
                        onSelectEncoding(opt.canonical_name);
                      }}
                      className="flex w-full items-center justify-between rounded-md px-2.5 py-1.5 text-left text-xs transition-colors hover:bg-[var(--bg-hover)]"
                    >
                      <div className="min-w-0">
                        <div className="font-medium">{opt.label}</div>
                        <div className="text-[11px]" style={{ color: "var(--text-muted)" }}>
                          {opt.region}
                          {cand ? ` · ${Math.round(cand.score * 100)}%` : ""}
                        </div>
                      </div>
                      {active && (
                        <Check className="h-3.5 w-3.5 shrink-0" style={{ color: "var(--accent)" }} />
                      )}
                    </button>
                  );
                })}
                <div
                  className="my-1 h-px"
                  style={{ backgroundColor: "var(--border-subtle)" }}
                />
              </>
            )}

            <div
              className="px-2.5 pb-1 pt-1 text-[10px] font-semibold uppercase tracking-wider"
              style={{ color: "var(--text-muted)" }}
            >
              {t.encodingAll}
            </div>
            {encodings.map((opt) => {
              const active = opt.id === appliedEncoding;
              return (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => {
                    setOpen(false);
                    onSelectEncoding(opt.canonical_name);
                  }}
                  className="flex w-full items-center justify-between rounded-md px-2.5 py-1.5 text-left text-xs transition-colors hover:bg-[var(--bg-hover)]"
                >
                  <div className="min-w-0">
                    <div className="font-medium">{opt.label}</div>
                    <div className="text-[11px]" style={{ color: "var(--text-muted)" }}>
                      {opt.region}
                    </div>
                  </div>
                  {active && (
                    <Check className="h-3.5 w-3.5 shrink-0" style={{ color: "var(--accent)" }} />
                  )}
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
