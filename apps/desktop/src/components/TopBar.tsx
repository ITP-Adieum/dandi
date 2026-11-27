import { ArrowLeft, FolderOpen, Monitor, Moon, PackagePlus, Sun } from "lucide-react";
import type { Dictionary } from "../i18n";
import { pathBasename } from "../lib/format";
import type { Locale, ThemePreference } from "../types";
import { BrandMark } from "./BrandMark";

interface TopBarProps {
  t: Dictionary;
  archivePath: string | null;
  locale: Locale;
  theme: ThemePreference;
  busy: boolean;
  onBackHome: () => void;
  onOpenArchive: () => void;
  onCreateZip: () => void;
  onLocaleChange: (locale: Locale) => void;
  onCycleTheme: () => void;
}

const LOCALE_LABELS: { id: Locale; short: string }[] = [
  { id: "ko", short: "한" },
  { id: "en", short: "EN" },
  { id: "ja", short: "日" },
];

export function TopBar({
  t,
  archivePath,
  locale,
  theme,
  busy,
  onBackHome,
  onOpenArchive,
  onCreateZip,
  onLocaleChange,
  onCycleTheme,
}: TopBarProps) {
  const themeLabel =
    theme === "system" ? t.themeSystem : theme === "light" ? t.themeLight : t.themeDark;

  return (
    <header
      className="flex h-12 shrink-0 items-center justify-between border-b px-3.5"
      style={{
        backgroundColor: "var(--bg-surface)",
        borderColor: "var(--border-subtle)",
      }}
    >
      <div className="flex min-w-0 items-center gap-2.5">
        {archivePath ? (
          <button
            type="button"
            onClick={onBackHome}
            disabled={busy}
            className="inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs font-medium transition-colors hover:bg-[var(--bg-hover)] disabled:opacity-50"
            style={{
              borderColor: "var(--border-subtle)",
              color: "var(--text-secondary)",
            }}
            title={t.backHome}
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            <span>{t.backHome}</span>
          </button>
        ) : (
          <div className="flex items-center gap-2">
            <BrandMark size={24} />
            <span className="text-sm font-semibold tracking-tight">{t.appName}</span>
          </div>
        )}

        {archivePath && (
          <div className="flex min-w-0 items-center gap-2 pl-1">
            <BrandMark size={18} className="shrink-0" />
            <span
              className="truncate text-sm font-semibold tracking-tight"
              title={archivePath}
            >
              {pathBasename(archivePath)}
            </span>
          </div>
        )}
      </div>

      <div className="flex shrink-0 items-center gap-2">
        <button
          type="button"
          onClick={onOpenArchive}
          disabled={busy}
          className="inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--bg-hover)] disabled:opacity-50"
          style={{
            borderColor: "var(--border-subtle)",
            color: "var(--text-primary)",
          }}
        >
          <FolderOpen className="h-3.5 w-3.5" style={{ color: "var(--text-secondary)" }} />
          <span>{t.openArchive}</span>
        </button>

        <button
          type="button"
          onClick={onCreateZip}
          disabled={busy}
          className="inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium text-white transition-colors hover:brightness-105 disabled:opacity-50"
          style={{ backgroundColor: "var(--accent)" }}
        >
          <PackagePlus className="h-3.5 w-3.5" />
          <span>{t.createZip}</span>
        </button>

        <div
          className="mx-1 h-4 w-px"
          style={{ backgroundColor: "var(--border-subtle)" }}
        />

        <div
          className="inline-flex rounded-md border p-0.5"
          style={{
            borderColor: "var(--border-subtle)",
            backgroundColor: "var(--bg-app)",
          }}
          role="group"
          aria-label="Language"
        >
          {LOCALE_LABELS.map((item) => {
            const active = locale === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => onLocaleChange(item.id)}
                className="rounded px-1.5 py-0.5 text-[11px] font-medium transition-colors"
                style={{
                  backgroundColor: active ? "var(--bg-surface)" : "transparent",
                  color: active ? "var(--text-primary)" : "var(--text-muted)",
                  boxShadow: active ? "0 1px 2px rgba(0,0,0,0.08)" : "none",
                }}
              >
                {item.short}
              </button>
            );
          })}
        </div>

        <button
          type="button"
          onClick={onCycleTheme}
          className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs transition-colors hover:bg-[var(--bg-hover)]"
          style={{
            borderColor: "var(--border-subtle)",
            color: "var(--text-secondary)",
          }}
          title={themeLabel}
          aria-label={themeLabel}
        >
          {theme === "system" && <Monitor className="h-3.5 w-3.5" />}
          {theme === "light" && <Sun className="h-3.5 w-3.5" />}
          {theme === "dark" && <Moon className="h-3.5 w-3.5" />}
        </button>
      </div>
    </header>
  );
}
