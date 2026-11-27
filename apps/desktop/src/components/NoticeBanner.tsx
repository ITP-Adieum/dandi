import { useEffect, useState } from "react";
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  FolderOpen,
  Info,
  X,
} from "lucide-react";
import type { Dictionary } from "../i18n";
import type { BannerNotice } from "../lib/state";

interface NoticeBannerProps {
  t: Dictionary;
  notice: BannerNotice;
  onRevealPath: (path: string) => void;
  onClose: () => void;
}

function toneStyles(tone: BannerNotice["tone"]) {
  switch (tone) {
    case "success":
      return {
        backgroundColor: "var(--success-bg)",
        borderColor: "var(--success-border)",
        color: "var(--success-text)",
      };
    case "error":
      return {
        backgroundColor: "var(--danger-bg)",
        borderColor: "var(--danger-border)",
        color: "var(--danger-text)",
      };
    case "warning":
    case "info":
      return {
        backgroundColor: "var(--warn-bg)",
        borderColor: "var(--warn-border)",
        color: "var(--warn-text)",
      };
  }
}

export function NoticeBanner({ t, notice, onRevealPath, onClose }: NoticeBannerProps) {
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    setExpanded(false);
  }, [notice]);

  const warningList = notice.warnings ?? [];
  const hasExpandableWarnings = warningList.length > 0;
  const styles = toneStyles(notice.tone);

  const Icon =
    notice.tone === "success"
      ? CheckCircle2
      : notice.tone === "warning"
        ? AlertTriangle
        : notice.tone === "info"
          ? Info
          : AlertCircle;

  return (
    <div className="border-b px-3.5 py-2 text-xs" style={styles} role="status">
      <div className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-start gap-2">
          <Icon className="mt-0.5 h-4 w-4 shrink-0" />
          <div className="min-w-0 space-y-0.5">
            <div className="truncate font-medium" title={notice.title}>
              {notice.title}
            </div>
            {notice.detail && (
              <div
                className="font-mono-tabular truncate text-[11px] opacity-85"
                title={notice.detail}
              >
                {notice.detail}
              </div>
            )}
            {notice.guidance && (
              <div className="text-[11px] opacity-90">{notice.guidance}</div>
            )}
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-2">
          {hasExpandableWarnings && (
            <button
              type="button"
              onClick={() => setExpanded((prev) => !prev)}
              aria-expanded={expanded}
              className="inline-flex items-center gap-1 rounded border border-current/30 px-2 py-0.5 text-[11px] font-medium hover:bg-black/5"
            >
              {expanded ? (
                <ChevronDown className="h-3 w-3" />
              ) : (
                <ChevronRight className="h-3 w-3" />
              )}
              <span>{expanded ? t.warningsHide : t.warningsShow(warningList.length)}</span>
            </button>
          )}
          {notice.revealPath && (
            <button
              type="button"
              onClick={() => {
                if (notice.revealPath) {
                  onRevealPath(notice.revealPath);
                }
              }}
              className="inline-flex items-center gap-1 rounded border border-current/30 px-2 py-0.5 text-[11px] font-medium hover:bg-black/5"
            >
              <FolderOpen className="h-3 w-3" />
              <span>{t.revealInFileManager}</span>
            </button>
          )}
          <button
            type="button"
            onClick={onClose}
            className="rounded p-0.5 hover:bg-black/10"
            aria-label={t.close}
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {hasExpandableWarnings && expanded && (
        <ul
          className="mt-2 max-h-44 space-y-1.5 overflow-y-auto rounded-md border border-current/20 bg-black/[0.03] p-2 text-[11px]"
          aria-label={t.warningsShow(warningList.length)}
        >
          {warningList.map((item, idx) => (
            <li
              key={`${item.kind}-${item.path}-${idx}`}
              className="flex flex-col gap-0.5 border-b border-current/10 pb-1.5 last:border-b-0 last:pb-0"
            >
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="rounded border border-current/30 px-1.5 py-0.5 text-[10px] font-semibold">
                  {item.label}
                </span>
                <span className="font-mono-tabular break-all font-medium">
                  {item.path}
                  {item.target ? ` → ${item.target}` : ""}
                </span>
              </div>
              <div className="pl-0.5 opacity-85">{item.reason}</div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
