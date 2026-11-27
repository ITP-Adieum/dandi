import { useEffect, useRef, useState } from "react";
import { AlertCircle, Eye, EyeOff, Lock, X } from "lucide-react";
import type { Dictionary } from "../i18n";
import { pathBasename } from "../lib/format";
import type { PasswordPromptState } from "../lib/state";

interface PasswordModalProps {
  t: Dictionary;
  prompt: PasswordPromptState;
  busy?: boolean;
  onSubmit: (password: string) => void;
  onClose: () => void;
}

export function PasswordModal({
  t,
  prompt,
  busy = false,
  onSubmit,
  onClose,
}: PasswordModalProps) {
  const [password, setPassword] = useState("");
  const [visible, setVisible] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
    inputRef.current?.select();
  }, [prompt]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!password || busy) return;
    onSubmit(password);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/45 p-4 backdrop-blur-[1px]"
      role="dialog"
      aria-modal="true"
      aria-label={t.passwordModalTitle}
    >
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm rounded-xl border p-5 shadow-2xl"
        style={{
          backgroundColor: "var(--bg-elevated)",
          borderColor: "var(--border-strong)",
        }}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Lock className="h-4 w-4" style={{ color: "var(--accent)" }} />
            <h2 className="text-sm font-semibold">{t.passwordModalTitle}</h2>
          </div>
          <button
            type="button"
            disabled={busy}
            onClick={onClose}
            className="rounded p-1 hover:bg-[var(--bg-hover)] disabled:opacity-45"
            style={{ color: "var(--text-muted)" }}
            aria-label={t.close}
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <p className="mt-2 text-xs" style={{ color: "var(--text-secondary)" }}>
          {t.passwordModalDesc}
        </p>
        <div
          className="font-mono-tabular mt-1 truncate text-[11px]"
          style={{ color: "var(--text-muted)" }}
        >
          {pathBasename(prompt.archivePath)}
        </div>

        {prompt.invalidAttempt && (
          <div
            className="mt-3 flex items-center gap-2 rounded-md border px-2.5 py-2 text-xs"
            style={{
              backgroundColor: "var(--danger-bg)",
              borderColor: "var(--danger-border)",
              color: "var(--danger-text)",
            }}
          >
            <AlertCircle className="h-3.5 w-3.5 shrink-0" />
            <span>{t.passwordInvalidError}</span>
          </div>
        )}

        <div className="relative mt-3">
          <input
            ref={inputRef}
            type={visible ? "text" : "password"}
            value={password}
            disabled={busy}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••"
            className="w-full rounded-md border py-2 pl-3 pr-9 text-xs outline-none focus:border-[var(--accent)] disabled:opacity-60"
            style={{
              backgroundColor: "var(--bg-app)",
              borderColor: prompt.invalidAttempt ? "var(--danger-border)" : "var(--border-strong)",
              color: "var(--text-primary)",
            }}
          />
          <button
            type="button"
            disabled={busy}
            onClick={() => setVisible((v) => !v)}
            className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 hover:bg-[var(--bg-hover)]"
            style={{ color: "var(--text-muted)" }}
            aria-label="Toggle password visibility"
          >
            {visible ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
          </button>
        </div>

        <div className="mt-4 flex justify-end gap-2">
          <button
            type="button"
            disabled={busy}
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-xs font-medium hover:bg-[var(--bg-hover)] disabled:opacity-45"
            style={{ borderColor: "var(--border-subtle)" }}
          >
            {t.cancel}
          </button>
          <button
            type="submit"
            disabled={!password || busy}
            className="rounded-md px-3.5 py-1.5 text-xs font-medium text-white hover:brightness-105 disabled:opacity-45"
            style={{ backgroundColor: "var(--accent)" }}
          >
            {t.passwordSubmit}
          </button>
        </div>
      </form>
    </div>
  );
}
