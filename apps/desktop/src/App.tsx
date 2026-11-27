import { useCallback, useEffect, useReducer, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { Loader2, Upload } from "lucide-react";
import {
  cancelOperation,
  classifyDroppedPaths,
  defaultOutputPath,
  fixArchiveEncoding,
  inspectArchive,
  listEncodings,
  packArchive,
  pickArchiveFile,
  pickDestinationDirectory,
  pickPackFiles,
  pickPackFolders,
  pickSaveArchivePath,
  revealInFileManager,
  takePendingOpenPaths,
  toCommandError,
  unpackArchive,
} from "./api";
import { ArchiveExplorer } from "./components/ArchiveExplorer";
import { DropZone } from "./components/DropZone";
import { NoticeBanner } from "./components/NoticeBanner";
import { PackModal } from "./components/PackModal";
import { buildPackRequest, defaultPackDraft, withArchiveExtension } from "./lib/pack";
import { PasswordModal } from "./components/PasswordModal";
import { ProgressModal } from "./components/ProgressModal";
import { TopBar } from "./components/TopBar";
import { DICTIONARIES, detectSystemLocale } from "./i18n";
import { formatBytes } from "./lib/format";
import {
  desktopReducer,
  INITIAL_DESKTOP_STATE,
  type BannerNotice,
} from "./lib/state";
import { buildErrorNotice, buildUnpackNotice } from "./lib/warnings";
import type { EncodingOption, ErrorKind, Locale, ThemePreference } from "./types";

const STORAGE_LOCALE = "dandi.locale";
const STORAGE_THEME = "dandi.theme";

function loadStoredLocale(): Locale {
  try {
    const saved = window.localStorage.getItem(STORAGE_LOCALE);
    if (saved === "ko" || saved === "en" || saved === "ja") return saved;
  } catch {
    // ignore storage errors
  }
  return detectSystemLocale();
}

function loadStoredTheme(): ThemePreference {
  try {
    const saved = window.localStorage.getItem(STORAGE_THEME);
    if (saved === "system" || saved === "light" || saved === "dark") return saved;
  } catch {
    // ignore storage errors
  }
  return "system";
}

function nextOpId(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

export default function App() {
  const [state, dispatch] = useReducer(desktopReducer, INITIAL_DESKTOP_STATE);
  const [locale, setLocale] = useState<Locale>(loadStoredLocale);
  const [theme, setTheme] = useState<ThemePreference>(loadStoredTheme);
  const [encodings, setEncodings] = useState<EncodingOption[]>([]);
  const [dragActive, setDragActive] = useState(false);

  const stateRef = useRef(state);
  stateRef.current = state;

  const t = DICTIONARIES[locale];

  // Apply system or manual light/dark theme to :root[data-theme].
  useEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const apply = () => {
      const effective = theme === "system" ? (mq.matches ? "dark" : "light") : theme;
      document.documentElement.setAttribute("data-theme", effective);
    };
    apply();
    mq.addEventListener("change", apply);
    try {
      window.localStorage.setItem(STORAGE_THEME, theme);
    } catch {
      // ignore
    }
    return () => mq.removeEventListener("change", apply);
  }, [theme]);

  useEffect(() => {
    try {
      window.localStorage.setItem(STORAGE_LOCALE, locale);
    } catch {
      // ignore
    }
  }, [locale]);

  // Load supported encodings from dandi-core once at startup.
  useEffect(() => {
    listEncodings()
      .then(setEncodings)
      .catch(() => {
        // fallback handled gracefully
      });
  }, []);

  const formatErrorNotice = useCallback(
    (kind: ErrorKind, detail: string): BannerNotice => buildErrorNotice(kind, detail, t),
    [t]
  );

  const formatErrorNoticeRef = useRef(formatErrorNotice);
  formatErrorNoticeRef.current = formatErrorNotice;

  const runInspect = useCallback(
    async (
      archivePath: string,
      encodingOverride: string | null = null,
      password: string | null = null,
      includeOsJunk?: boolean
    ) => {
      const junk = includeOsJunk ?? stateRef.current.showOsJunk;
      dispatch({ type: "inspect_start", archivePath, encodingOverride });
      try {
        const summary = await inspectArchive(archivePath, encodingOverride, password, junk);
        dispatch({
          type: "inspect_success",
          archivePath,
          summary,
          encodingOverride,
          password,
        });
      } catch (err) {
        const cmdErr = toCommandError(err);
        dispatch({
          type: "inspect_error",
          archivePath,
          errorKind: cmdErr.kind,
          notice: formatErrorNoticeRef.current(cmdErr.kind, cmdErr.message),
        });
      }
    },
    []
  );

  const openPackWithInputs = useCallback(async (inputs: string[]) => {
    let suggestedOutput = "";
    if (inputs.length > 0) {
      try {
        suggestedOutput = await defaultOutputPath(inputs, "pack_zip");
      } catch {
        suggestedOutput = "";
      }
    }
    dispatch({ type: "open_pack_modal", draft: defaultPackDraft(inputs, suggestedOutput) });
  }, []);

  const handleIncomingPaths = useCallback(
    async (paths: string[]) => {
      if (paths.length === 0 || stateRef.current.activeOp) return;
      try {
        const classified = await classifyDroppedPaths(paths);
        if (classified.action === "open_archive") {
          await runInspect(classified.path, null, null);
        } else if (classified.action === "pack_inputs") {
          await openPackWithInputs(classified.paths);
        }
      } catch (err) {
        const cmdErr = toCommandError(err);
        dispatch({
          type: "set_notice",
          notice: formatErrorNoticeRef.current(cmdErr.kind, cmdErr.message),
        });
      }
    },
    [openPackWithInputs, runInspect]
  );

  const handleIncomingPathsRef = useRef(handleIncomingPaths);
  handleIncomingPathsRef.current = handleIncomingPaths;

  // Wire native Tauri v2 drag-and-drop & OS file association open events exactly once.
  useEffect(() => {
    let disposed = false;
    let unlistenDrop: (() => void) | undefined;
    let unlistenOpen: (() => void) | undefined;

    const setup = async () => {
      try {
        const dropUnlisten = await getCurrentWebview().onDragDropEvent((event) => {
          if (event.payload.type === "enter" || event.payload.type === "over") {
            setDragActive(true);
          } else if (event.payload.type === "leave") {
            setDragActive(false);
          } else if (event.payload.type === "drop") {
            setDragActive(false);
            void handleIncomingPathsRef.current(event.payload.paths);
          }
        });
        if (disposed) {
          dropUnlisten();
          return;
        }
        unlistenDrop = dropUnlisten;
      } catch {
        // non-Tauri browser preview fallback
      }

      try {
        const openUnlisten = await listen<string[]>("dandi://open-paths", (event) => {
          void handleIncomingPathsRef.current(event.payload);
        });
        if (disposed) {
          openUnlisten();
          return;
        }
        unlistenOpen = openUnlisten;
      } catch {
        // ignore outside Tauri
      }

      if (disposed) return;

      try {
        const paths = await takePendingOpenPaths();
        if (!disposed && paths.length > 0) {
          void handleIncomingPathsRef.current(paths);
        }
      } catch {
        // ignore outside Tauri
      }
    };

    void setup();

    return () => {
      disposed = true;
      unlistenDrop?.();
      unlistenOpen?.();
    };
  }, []);

  const handleOpenArchiveDialog = async () => {
    const picked = await pickArchiveFile();
    if (picked) {
      await runInspect(picked, null, null);
    }
  };

  const handleCreateZipDialog = async () => {
    const files = await pickPackFiles();
    if (files.length > 0) {
      await openPackWithInputs(files);
    } else {
      await openPackWithInputs([]);
    }
  };

  const handleSelectEncoding = async (canonicalName: string | null) => {
    if (!state.archivePath) return;
    await runInspect(state.archivePath, canonicalName, state.archivePassword, state.showOsJunk);
  };

  const handleToggleShowOsJunk = async (value: boolean) => {
    dispatch({ type: "set_show_os_junk", value });
    if (state.archivePath) {
      await runInspect(state.archivePath, state.encodingOverride, state.archivePassword, value);
    }
  };

  const runUnpack = async (
    archivePath: string,
    destDir: string,
    selectedOnly: boolean,
    passwordOverride?: string | null
  ) => {
    const opId = nextOpId("unpack");
    dispatch({
      type: "operation_start",
      opId,
      kind: "unpack",
      startedAtMs: Date.now(),
    });
    const pwd = passwordOverride ?? stateRef.current.archivePassword ?? undefined;
    try {
      const report = await unpackArchive(
        archivePath,
        destDir,
        {
          op_id: opId,
          mode: stateRef.current.extractMode,
          encoding_override: stateRef.current.encodingOverride ?? undefined,
          password: pwd,
          selected_entries: selectedOnly ? stateRef.current.selectedIndices : undefined,
          exclude_os_junk: !stateRef.current.showOsJunk,
          overwrite: stateRef.current.overwriteExisting,
          reveal_after: stateRef.current.revealAfterExtract,
        },
        (payload) => dispatch({ type: "operation_progress", payload })
      );
      if (passwordOverride && archivePath === stateRef.current.archivePath) {
        dispatch({ type: "set_archive_password", password: passwordOverride });
      }
      dispatch({
        type: "operation_finish",
        notice: buildUnpackNotice(report, t),
      });
    } catch (err) {
      const cmdErr = toCommandError(err);
      if (cmdErr.kind === "password_required" || cmdErr.kind === "invalid_password") {
        dispatch({ type: "operation_finish", notice: null });
        dispatch({
          type: "open_password_prompt",
          prompt: {
            purpose: "unpack",
            archivePath,
            destPath: destDir,
            selectedOnly,
            invalidAttempt: cmdErr.kind === "invalid_password",
          },
        });
        return;
      }
      dispatch({
        type: "operation_finish",
        notice: formatErrorNotice(cmdErr.kind, cmdErr.message),
      });
    }
  };

  const handleExtractClick = async (selectedOnly: boolean) => {
    if (!state.archivePath) return;
    let defaultDir: string | undefined;
    try {
      defaultDir = await defaultOutputPath([state.archivePath], "extract_dir");
    } catch {
      defaultDir = undefined;
    }
    const destDir = await pickDestinationDirectory(defaultDir);
    if (!destDir) return;
    await runUnpack(state.archivePath, destDir, selectedOnly);
  };

  const runFixEncoding = async (
    srcZip: string,
    dstZip: string,
    passwordOverride?: string | null
  ) => {
    const opId = nextOpId("fix");
    dispatch({
      type: "operation_start",
      opId,
      kind: "fix",
      startedAtMs: Date.now(),
    });
    const pwd = passwordOverride ?? stateRef.current.archivePassword ?? undefined;
    try {
      const report = await fixArchiveEncoding(
        srcZip,
        dstZip,
        stateRef.current.encodingOverride,
        pwd,
        !stateRef.current.showOsJunk,
        opId,
        (payload) => dispatch({ type: "operation_progress", payload })
      );
      if (passwordOverride && srcZip === stateRef.current.archivePath) {
        dispatch({ type: "set_archive_password", password: passwordOverride });
      }
      dispatch({
        type: "operation_finish",
        notice: {
          tone: "success",
          title: t.fixSuccess(report.entries_repacked, report.output_path),
          revealPath: report.output_path,
        },
      });
    } catch (err) {
      const cmdErr = toCommandError(err);
      if (cmdErr.kind === "password_required" || cmdErr.kind === "invalid_password") {
        dispatch({ type: "operation_finish", notice: null });
        dispatch({
          type: "open_password_prompt",
          prompt: {
            purpose: "fix",
            archivePath: srcZip,
            destPath: dstZip,
            invalidAttempt: cmdErr.kind === "invalid_password",
          },
        });
        return;
      }
      dispatch({
        type: "operation_finish",
        notice: formatErrorNotice(cmdErr.kind, cmdErr.message),
      });
    }
  };

  const handleFixEncodingClick = async () => {
    if (!state.archivePath) return;
    let suggested: string | undefined;
    try {
      suggested = await defaultOutputPath([state.archivePath], "fix_nfc_zip");
    } catch {
      suggested = undefined;
    }
    const dstZip = await pickSaveArchivePath(suggested, t.fixEncodingTitle);
    if (!dstZip) return;
    await runFixEncoding(state.archivePath, dstZip);
  };

  const handleStartPack = async () => {
    const draft = state.packDraft;
    if (!draft || draft.inputs.length === 0 || !draft.outputZip.trim()) return;
    const opId = nextOpId("pack");
    const request = buildPackRequest(draft, opId);
    if (!request) return;

    dispatch({
      type: "operation_start",
      opId,
      kind: "pack",
      startedAtMs: Date.now(),
    });

    try {
      const report = await packArchive(
        draft.inputs,
        draft.outputZip.trim(),
        request,
        (payload) => dispatch({ type: "operation_progress", payload })
      );
      const volumes = report.output_volumes?.length ?? 1;
      const size = formatBytes(report.output_bytes);
      dispatch({
        type: "operation_finish",
        notice: {
          tone: "success",
          title:
            volumes > 1
              ? t.packSuccessVolumes(report.entries_written, size, volumes)
              : t.packSuccess(report.entries_written, size),
          detail: report.output_path,
          revealPath: report.output_path,
        },
      });
    } catch (err) {
      const cmdErr = toCommandError(err);
      dispatch({
        type: "operation_finish",
        notice: formatErrorNotice(cmdErr.kind, cmdErr.message),
      });
    }
  };

  const handleCancelOperation = async () => {
    if (!state.activeOp) return;
    dispatch({ type: "operation_cancelling" });
    try {
      await cancelOperation(state.activeOp.opId);
    } catch {
      // ignore if already finished
    }
  };

  const handlePasswordSubmit = async (password: string) => {
    const prompt = state.passwordPrompt;
    if (!prompt) return;
    if (prompt.purpose === "inspect") {
      await runInspect(
        prompt.archivePath,
        prompt.encodingOverride ?? null,
        password,
        state.showOsJunk
      );
    } else if (prompt.purpose === "unpack" && prompt.destPath) {
      await runUnpack(prompt.archivePath, prompt.destPath, prompt.selectedOnly ?? false, password);
    } else if (prompt.purpose === "fix" && prompt.destPath) {
      await runFixEncoding(prompt.archivePath, prompt.destPath, password);
    }
  };

  const handlePackAddFiles = async () => {
    const added = await pickPackFiles();
    if (!state.packDraft || added.length === 0) return;
    const merged = Array.from(new Set([...state.packDraft.inputs, ...added]));
    let nextOutput = state.packDraft.outputZip;
    if (!nextOutput) {
      try {
        nextOutput = withArchiveExtension(
          await defaultOutputPath(merged, "pack_zip"),
          state.packDraft.format
        );
      } catch {
        // ignore
      }
    }
    dispatch({
      type: "update_pack_draft",
      patch: { inputs: merged, outputZip: nextOutput },
    });
  };

  const handlePackAddFolders = async () => {
    const added = await pickPackFolders();
    if (!state.packDraft || added.length === 0) return;
    const merged = Array.from(new Set([...state.packDraft.inputs, ...added]));
    let nextOutput = state.packDraft.outputZip;
    if (!nextOutput) {
      try {
        nextOutput = withArchiveExtension(
          await defaultOutputPath(merged, "pack_zip"),
          state.packDraft.format
        );
      } catch {
        // ignore
      }
    }
    dispatch({
      type: "update_pack_draft",
      patch: { inputs: merged, outputZip: nextOutput },
    });
  };

  const handlePickPackOutput = async () => {
    if (!state.packDraft) return;
    const picked = await pickSaveArchivePath(
      state.packDraft.outputZip || undefined,
      t.packTitle,
      state.packDraft.format
    );
    if (picked) {
      dispatch({ type: "update_pack_draft", patch: { outputZip: picked } });
    }
  };

  const handleRevealPath = (path: string) => {
    void revealInFileManager(path).catch((err) => {
      const cmdErr = toCommandError(err);
      dispatch({
        type: "set_notice",
        notice: formatErrorNotice(cmdErr.kind, cmdErr.message),
      });
    });
  };

  const cycleTheme = () => {
    setTheme((prev) =>
      prev === "system" ? "light" : prev === "light" ? "dark" : "system"
    );
  };

  const busy = state.loadingArchive || state.activeOp !== null;

  return (
    <div className="relative flex h-full w-full flex-col overflow-hidden">
      <TopBar
        t={t}
        archivePath={state.archivePath}
        locale={locale}
        theme={theme}
        busy={busy}
        onBackHome={() => dispatch({ type: "close_archive" })}
        onOpenArchive={handleOpenArchiveDialog}
        onCreateZip={handleCreateZipDialog}
        onLocaleChange={setLocale}
        onCycleTheme={cycleTheme}
      />

      {/* Structured notification / warning / error banner */}
      {state.notice && (
        <NoticeBanner
          t={t}
          notice={state.notice}
          onRevealPath={handleRevealPath}
          onClose={() => dispatch({ type: "set_notice", notice: null })}
        />
      )}

      {/* Main Content */}
      {state.loadingArchive && !state.summary ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-3 text-xs">
          <Loader2 className="h-5 w-5 animate-spin" style={{ color: "var(--accent)" }} />
          <span style={{ color: "var(--text-secondary)" }}>{t.inspectingArchive}</span>
        </div>
      ) : state.summary ? (
        <ArchiveExplorer
          t={t}
          summary={state.summary}
          encodings={encodings}
          encodingOverride={state.encodingOverride}
          showOsJunk={state.showOsJunk}
          extractMode={state.extractMode}
          revealAfterExtract={state.revealAfterExtract}
          overwriteExisting={state.overwriteExisting}
          activeFolder={state.activeFolder}
          searchQuery={state.searchQuery}
          selectedIndices={state.selectedIndices}
          busy={busy}
          onSelectEncoding={handleSelectEncoding}
          onFixEncoding={handleFixEncodingClick}
          onToggleShowOsJunk={handleToggleShowOsJunk}
          onSelectFolder={(folder) => dispatch({ type: "set_active_folder", folder })}
          onSearchChange={(query) => dispatch({ type: "set_search_query", query })}
          onSelectedIndicesChange={(indices) =>
            dispatch({ type: "set_selected_indices", indices })
          }
          onExtractModeChange={(mode) => dispatch({ type: "set_extract_mode", mode })}
          onRevealAfterChange={(value) => dispatch({ type: "set_reveal_after", value })}
          onOverwriteExistingChange={(value) =>
            dispatch({ type: "set_overwrite_existing", value })
          }
          onExtractAll={() => void handleExtractClick(false)}
          onExtractSelected={() => void handleExtractClick(true)}
        />
      ) : (
        <DropZone
          t={t}
          loading={busy}
          onOpenArchive={handleOpenArchiveDialog}
          onCreateZip={handleCreateZipDialog}
        />
      )}

      {/* Modals */}
      {state.packDraft && (
        <PackModal
          t={t}
          draft={state.packDraft}
          onUpdate={(patch) => dispatch({ type: "update_pack_draft", patch })}
          onAddFiles={() => void handlePackAddFiles()}
          onAddFolders={() => void handlePackAddFolders()}
          onPickOutput={() => void handlePickPackOutput()}
          onSubmit={() => void handleStartPack()}
          onClose={() => dispatch({ type: "close_pack_modal" })}
        />
      )}

      {state.passwordPrompt && (
        <PasswordModal
          t={t}
          prompt={state.passwordPrompt}
          busy={busy}
          onSubmit={(pwd) => void handlePasswordSubmit(pwd)}
          onClose={() => dispatch({ type: "close_password_prompt" })}
        />
      )}

      {state.activeOp && (
        <ProgressModal
          t={t}
          op={state.activeOp}
          onCancel={() => void handleCancelOperation()}
        />
      )}

      {/* Full-window Native Drag & Drop Overlay */}
      {dragActive && (
        <div
          className="pointer-events-none fixed inset-0 z-50 flex items-center justify-center p-6 backdrop-blur-[2px]"
          style={{ backgroundColor: "rgba(20, 22, 26, 0.56)" }}
        >
          <div
            className="flex flex-col items-center rounded-xl border-2 border-dashed px-10 py-8 text-center shadow-2xl"
            style={{
              backgroundColor: "var(--bg-elevated)",
              borderColor: "var(--accent)",
            }}
          >
            <Upload className="mb-3 h-7 w-7" style={{ color: "var(--accent)" }} />
            <div className="text-sm font-semibold">{t.dropActiveTitle}</div>
            <div className="mt-1 text-xs" style={{ color: "var(--text-secondary)" }}>
              {t.dropActiveSubtitle}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
