import { Archive, FolderOpen, PackagePlus, ShieldCheck } from "lucide-react";
import type { Dictionary } from "../i18n";
import { BrandMark } from "./BrandMark";

interface DropZoneProps {
  t: Dictionary;
  loading: boolean;
  onOpenArchive: () => void;
  onCreateZip: () => void;
}

export function DropZone({
  t,
  loading,
  onOpenArchive,
  onCreateZip,
}: DropZoneProps) {
  return (
    <main className="flex flex-1 flex-col items-center justify-center p-8">
      <div
        className="flex w-full max-w-xl flex-col items-center rounded-xl border border-dashed px-8 py-12 text-center transition-colors"
        style={{
          backgroundColor: "var(--bg-surface)",
          borderColor: "var(--border-strong)",
        }}
      >
        <BrandMark size={56} className="mb-5" />

        <h1 className="text-base font-semibold tracking-tight">{t.dropTitle}</h1>
        <p
          className="mt-2 max-w-md text-xs leading-relaxed"
          style={{ color: "var(--text-secondary)" }}
        >
          {t.dropSubtitle}
        </p>

        <div className="mt-6 flex flex-wrap items-center justify-center gap-2.5">
          <button
            type="button"
            onClick={onOpenArchive}
            disabled={loading}
            className="inline-flex items-center gap-2 rounded-lg border px-4 py-2 text-xs font-medium transition-colors hover:bg-[var(--bg-hover)] disabled:opacity-50"
            style={{
              borderColor: "var(--border-strong)",
              backgroundColor: "var(--bg-surface)",
              color: "var(--text-primary)",
            }}
          >
            <FolderOpen className="h-4 w-4" style={{ color: "var(--text-secondary)" }} />
            <span>{t.openArchive}</span>
          </button>

          <button
            type="button"
            onClick={onCreateZip}
            disabled={loading}
            className="inline-flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-medium text-white transition-colors hover:brightness-105 disabled:opacity-50"
            style={{ backgroundColor: "var(--accent)" }}
          >
            <PackagePlus className="h-4 w-4" />
            <span>{t.createZip}</span>
          </button>
        </div>

        <div
          className="mt-8 grid w-full grid-cols-1 gap-2 border-t pt-5 text-left text-[11px] sm:grid-cols-2"
          style={{
            borderColor: "var(--border-subtle)",
            color: "var(--text-muted)",
          }}
        >
          <div className="flex items-start gap-2">
            <Archive className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span>{t.supportedFormats}</span>
          </div>
          <div className="flex items-start gap-2">
            <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span>{t.nfcGuarantee}</span>
          </div>
        </div>
      </div>
    </main>
  );
}
