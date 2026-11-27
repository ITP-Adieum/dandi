import type {
  ArchiveSummary,
  CommandError,
  ExtractMode,
  ProgressPayload,
} from "../types";

export type ActiveOperationKind = "pack" | "unpack" | "fix";

export interface ActiveOperation {
  opId: string;
  kind: ActiveOperationKind;
  startedAtMs: number;
  cancelling: boolean;
  progress: ProgressPayload | null;
}

export interface PasswordPromptState {
  purpose: "inspect" | "unpack" | "fix";
  archivePath: string;
  invalidAttempt: boolean;
  destPath?: string;
}

export interface BannerNotice {
  tone: "success" | "error" | "info";
  title: string;
  detail?: string;
  revealPath?: string;
}

export interface PackDraftState {
  inputs: string[];
  outputZip: string;
  compressionLevel: number;
  excludeOsJunk: boolean;
  password: string;
}

export interface DesktopState {
  archivePath: string | null;
  summary: ArchiveSummary | null;
  loadingArchive: boolean;
  encodingOverride: string | null;
  archivePassword: string | null;
  showOsJunk: boolean;
  extractMode: ExtractMode;
  revealAfterExtract: boolean;
  activeFolder: string;
  searchQuery: string;
  selectedIndices: number[];
  packDraft: PackDraftState | null;
  passwordPrompt: PasswordPromptState | null;
  activeOp: ActiveOperation | null;
  notice: BannerNotice | null;
}

export const INITIAL_DESKTOP_STATE: DesktopState = {
  archivePath: null,
  summary: null,
  loadingArchive: false,
  encodingOverride: null,
  archivePassword: null,
  showOsJunk: false,
  extractMode: "smart",
  revealAfterExtract: true,
  activeFolder: "",
  searchQuery: "",
  selectedIndices: [],
  packDraft: null,
  passwordPrompt: null,
  activeOp: null,
  notice: null,
};

export type DesktopAction =
  | { type: "inspect_start"; archivePath: string; encodingOverride: string | null }
  | { type: "inspect_success"; archivePath: string; summary: ArchiveSummary; password: string | null }
  | { type: "inspect_error"; error: CommandError }
  | { type: "close_archive" }
  | { type: "set_show_os_junk"; value: boolean }
  | { type: "set_extract_mode"; mode: ExtractMode }
  | { type: "set_reveal_after"; value: boolean }
  | { type: "set_active_folder"; folder: string }
  | { type: "set_search_query"; query: string }
  | { type: "set_selected_indices"; indices: number[] }
  | { type: "open_pack_modal"; draft: PackDraftState }
  | { type: "update_pack_draft"; patch: Partial<PackDraftState> }
  | { type: "close_pack_modal" }
  | { type: "open_password_prompt"; prompt: PasswordPromptState }
  | { type: "close_password_prompt" }
  | { type: "operation_start"; opId: string; kind: ActiveOperationKind; startedAtMs: number }
  | { type: "operation_progress"; payload: ProgressPayload }
  | { type: "operation_cancelling" }
  | { type: "operation_finish"; notice: BannerNotice | null }
  | { type: "set_notice"; notice: BannerNotice | null };

export function desktopReducer(state: DesktopState, action: DesktopAction): DesktopState {
  switch (action.type) {
    case "inspect_start": {
      const sameArchive = state.archivePath === action.archivePath;
      return {
        ...state,
        archivePath: action.archivePath,
        loadingArchive: true,
        encodingOverride: action.encodingOverride,
        archivePassword: sameArchive ? state.archivePassword : null,
        activeFolder: sameArchive ? state.activeFolder : "",
        searchQuery: sameArchive ? state.searchQuery : "",
        selectedIndices: sameArchive ? state.selectedIndices : [],
        notice: null,
      };
    }
    case "inspect_success":
      return {
        ...state,
        archivePath: action.archivePath,
        summary: action.summary,
        loadingArchive: false,
        archivePassword: action.password,
        passwordPrompt: null,
      };
    case "inspect_error": {
      const needsPassword =
        action.error.kind === "password_required" || action.error.kind === "invalid_password";
      if (needsPassword && state.archivePath) {
        return {
          ...state,
          loadingArchive: false,
          passwordPrompt: {
            purpose: "inspect",
            archivePath: state.archivePath,
            invalidAttempt: action.error.kind === "invalid_password",
          },
        };
      }
      return {
        ...state,
        loadingArchive: false,
        notice: {
          tone: "error",
          title: action.error.kind,
          detail: action.error.message,
        },
      };
    }
    case "close_archive":
      return {
        ...state,
        archivePath: null,
        summary: null,
        loadingArchive: false,
        encodingOverride: null,
        archivePassword: null,
        activeFolder: "",
        searchQuery: "",
        selectedIndices: [],
      };
    case "set_show_os_junk":
      return { ...state, showOsJunk: action.value };
    case "set_extract_mode":
      return { ...state, extractMode: action.mode };
    case "set_reveal_after":
      return { ...state, revealAfterExtract: action.value };
    case "set_active_folder":
      return { ...state, activeFolder: action.folder };
    case "set_search_query":
      return { ...state, searchQuery: action.query };
    case "set_selected_indices":
      return { ...state, selectedIndices: action.indices };
    case "open_pack_modal":
      return { ...state, packDraft: action.draft, notice: null };
    case "update_pack_draft":
      if (!state.packDraft) return state;
      return { ...state, packDraft: { ...state.packDraft, ...action.patch } };
    case "close_pack_modal":
      return { ...state, packDraft: null };
    case "open_password_prompt":
      return { ...state, passwordPrompt: action.prompt };
    case "close_password_prompt":
      return { ...state, passwordPrompt: null };
    case "operation_start":
      return {
        ...state,
        packDraft: action.kind === "pack" ? null : state.packDraft,
        passwordPrompt: null,
        notice: null,
        activeOp: {
          opId: action.opId,
          kind: action.kind,
          startedAtMs: action.startedAtMs,
          cancelling: false,
          progress: null,
        },
      };
    case "operation_progress":
      if (!state.activeOp || state.activeOp.opId !== action.payload.op_id) {
        return state;
      }
      return {
        ...state,
        activeOp: {
          ...state.activeOp,
          progress: action.payload,
        },
      };
    case "operation_cancelling":
      if (!state.activeOp) return state;
      return {
        ...state,
        activeOp: {
          ...state.activeOp,
          cancelling: true,
        },
      };
    case "operation_finish":
      return {
        ...state,
        activeOp: null,
        notice: action.notice,
      };
    case "set_notice":
      return { ...state, notice: action.notice };
  }
}
