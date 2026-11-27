import type { Locale, ProgressPhase, ErrorKind, UnpackWarning } from "./types";

export interface Dictionary {
  appName: string;
  appTagline: string;
  openArchive: string;
  createZip: string;
  backHome: string;
  dropTitle: string;
  dropSubtitle: string;
  dropActiveTitle: string;
  dropActiveSubtitle: string;
  supportedFormats: string;
  nfcGuarantee: string;
  encodingAuto: string;
  encodingManual: string;
  encodingResetAuto: string;
  encodingDetectedTop: string;
  encodingAll: string;
  encodingTooltip: string;
  fixEncoding: string;
  fixEncodingTitle: string;
  folders: string;
  allFiles: string;
  searchPlaceholder: string;
  selectAll: string;
  clearSelection: string;
  selectedCount: (count: number) => string;
  showOsJunk: string;
  colName: string;
  colSize: string;
  colCompressed: string;
  colRatio: string;
  colModified: string;
  emptyFolder: string;
  noSearchResults: string;
  extractMode: string;
  modeSmart: string;
  modeDirect: string;
  modeWrap: string;
  modeSmartHint: string;
  modeDirectHint: string;
  modeWrapHint: string;
  openAfterExtract: string;
  overwriteExisting: string;
  overwriteExistingHint: string;
  extractAll: string;
  extractSelected: (count: number) => string;
  entriesLabel: (count: number) => string;
  encryptedBadge: string;
  packTitle: string;
  packInputs: string;
  addFiles: string;
  addFolder: string;
  remove: string;
  outputPath: string;
  browse: string;
  compressionLevel: string;
  levelFast: string;
  levelBalanced: string;
  levelMax: string;
  excludeOsJunk: string;
  excludeOsJunkHint: string;
  passwordOptional: string;
  passwordPlaceholder: string;
  aesWindowsWarning: string;
  startPack: string;
  cancel: string;
  cancelling: string;
  close: string;
  retry: string;
  passwordModalTitle: string;
  passwordModalDesc: string;
  passwordInvalidError: string;
  passwordSubmit: string;
  progressEntries: (done: number, total: number) => string;
  progressTitlePack: string;
  progressTitleUnpack: string;
  progressTitleFix: string;
  revealInFileManager: string;
  packSuccess: (entries: number, size: string) => string;
  unpackSuccess: (files: number, dir: string) => string;
  unpackSuccessWithWarnings: (files: number, dir: string, warningCount: number) => string;
  fixSuccess: (entries: number, path: string) => string;
  collisionsRenamed: (count: number) => string;
  symlinksSkippedSummary: (count: number) => string;
  warningsShow: (count: number) => string;
  warningsHide: string;
  alreadyExistsGuidance: string;
  inspectingArchive: string;
  themeSystem: string;
  themeLight: string;
  themeDark: string;
  phases: Record<ProgressPhase, string>;
  warningKinds: Record<UnpackWarning["kind"], string>;
  errors: Record<ErrorKind, string>;
}

export const DICTIONARIES: Record<Locale, Dictionary> = {
  en: {
    appName: "Dandi",
    appTagline: "Cross-OS archiver that never breaks filenames",
    openArchive: "Open Archive",
    createZip: "Create ZIP",
    backHome: "Home",
    dropTitle: "Drop an archive to inspect, or files to create a ZIP",
    dropSubtitle:
      "Automatic NFC normalization and CP949 / Shift_JIS / GB18030 detection across macOS and Windows.",
    dropActiveTitle: "Release to open or pack",
    dropActiveSubtitle: "Single archives open immediately; files & folders prepare a clean NFC ZIP",
    supportedFormats: "Reads .zip, .7z, .tar, .tgz, .tar.gz, .tar.zst, .tar.bz2, .tar.xz",
    nfcGuarantee: "Packs UTF-8 NFC ZIPs with zero __MACOSX / .DS_Store junk",
    encodingAuto: "Auto",
    encodingManual: "Manual",
    encodingResetAuto: "Reset to Auto-detect",
    encodingDetectedTop: "Detected candidates",
    encodingAll: "All encodings",
    encodingTooltip: "Switch filename encoding preview without extracting",
    fixEncoding: "Fix Encoding (Save NFC ZIP)",
    fixEncodingTitle: "Save Clean NFC UTF-8 ZIP",
    folders: "Folders",
    allFiles: "All files",
    searchPlaceholder: "Filter files…",
    selectAll: "Select all",
    clearSelection: "Clear",
    selectedCount: (n) => `${n} selected`,
    showOsJunk: "Show OS junk",
    colName: "Name",
    colSize: "Size",
    colCompressed: "Packed",
    colRatio: "Saved",
    colModified: "Modified",
    emptyFolder: "This folder has no visible entries.",
    noSearchResults: "No entries match your filter.",
    extractMode: "Layout",
    modeSmart: "Smart",
    modeDirect: "Direct",
    modeWrap: "Wrap",
    modeSmartHint: "Single root folder extracts directly; multiple loose items auto-wrap in a folder.",
    modeDirectHint: "Extract everything directly into the chosen destination folder.",
    modeWrapHint: "Always create a subfolder named after the archive.",
    openAfterExtract: "Open folder after extraction",
    overwriteExisting: "Overwrite existing files",
    overwriteExistingHint:
      "Replace existing files at the destination instead of stopping on conflict.",
    extractAll: "Extract All",
    extractSelected: (n) => `Extract Selected (${n})`,
    entriesLabel: (n) => `${n.toLocaleString()} entries`,
    encryptedBadge: "Encrypted",
    packTitle: "Create Cross-OS ZIP",
    packInputs: "Files & Folders",
    addFiles: "Add Files",
    addFolder: "Add Folder",
    remove: "Remove",
    outputPath: "Output ZIP",
    browse: "Browse…",
    compressionLevel: "Compression",
    levelFast: "Fast (1)",
    levelBalanced: "Balanced (6)",
    levelMax: "Max (9)",
    excludeOsJunk: "Exclude OS junk (.DS_Store, __MACOSX, ._*, Thumbs.db)",
    excludeOsJunkHint: "Recommended for clean macOS ↔ Windows sharing.",
    passwordOptional: "AES-256 Password (Optional)",
    passwordPlaceholder: "Leave empty for unencrypted ZIP",
    aesWindowsWarning:
      "Windows Explorer cannot open AES-256 encrypted ZIPs natively. Recipients on Windows should open it with Dandi or 7-Zip.",
    startPack: "Create ZIP",
    cancel: "Cancel",
    cancelling: "Cancelling…",
    close: "Close",
    retry: "Try Again",
    passwordModalTitle: "Password Required",
    passwordModalDesc: "Enter the archive password to continue.",
    passwordInvalidError: "Incorrect password. Please check and try again.",
    passwordSubmit: "Unlock",
    progressEntries: (done, total) =>
      total > 0 ? `${done.toLocaleString()} / ${total.toLocaleString()} entries` : `${done.toLocaleString()} entries`,
    progressTitlePack: "Creating ZIP…",
    progressTitleUnpack: "Extracting Archive…",
    progressTitleFix: "Repairing to Clean NFC ZIP…",
    revealInFileManager: "Reveal",
    packSuccess: (entries, size) => `Created ZIP with ${entries.toLocaleString()} entries (${size}).`,
    unpackSuccess: (files, dir) => `Extracted ${files.toLocaleString()} files to ${dir}.`,
    unpackSuccessWithWarnings: (files, dir, warningCount) =>
      `Extracted ${files.toLocaleString()} files to ${dir} with ${warningCount} warning(s).`,
    fixSuccess: (entries, path) => `Saved clean NFC ZIP (${entries.toLocaleString()} entries) to ${path}.`,
    collisionsRenamed: (n) => `${n} case-insensitive filename collision(s) safely disambiguated.`,
    symlinksSkippedSummary: (n) => `${n} symlink(s) skipped.`,
    warningsShow: (n) => `Show warnings (${n})`,
    warningsHide: "Hide warnings",
    alreadyExistsGuidance:
      "Enable \"Overwrite existing files\" below or pick Smart/Wrap layout to avoid overwriting existing files.",
    inspectingArchive: "Inspecting archive…",
    themeSystem: "System",
    themeLight: "Light",
    themeDark: "Dark",
    phases: {
      scanning: "Scanning",
      packing: "Compressing",
      unpacking: "Extracting",
      repacking: "Repacking NFC",
      finalizing: "Finalizing",
    },
    warningKinds: {
      symlink_skipped: "Symlink skipped",
      permission_apply_failed: "Permissions not applied",
      mtime_apply_failed: "Timestamp not applied",
      zone_id_propagate_failed: "Zone.Identifier not applied",
    },
    errors: {
      io: "File I/O error",
      unsupported_format: "Unsupported archive format",
      corrupt_archive: "Archive appears corrupt or truncated",
      invalid_password: "Incorrect password",
      password_required: "Password required",
      unsafe_path: "Blocked unsafe path (Zip Slip protection)",
      unsafe_symlink: "Blocked unsafe symlink escape",
      budget_exceeded: "Safety budget exceeded (Zip Bomb protection)",
      cancelled: "Operation cancelled and partial files cleaned up",
      already_exists: "Destination file or folder already exists",
      invalid_input: "Invalid input",
      unsupported_encoding: "Unsupported character encoding",
      archive_engine: "Archive engine error",
      internal: "Unexpected internal error",
    },
  },
  ko: {
    appName: "단디",
    appTagline: "파일명이 절대 깨지지 않는 macOS · Windows 압축 도구",
    openArchive: "압축 열기",
    createZip: "ZIP 만들기",
    backHome: "홈",
    dropTitle: "압축 파일을 놓아 미리보거나, 파일·폴더를 놓아 ZIP으로 묶으세요",
    dropSubtitle:
      "macOS 한글 자소 분리(NFD) 자동 방지 및 윈도우 CP949 / Shift_JIS / GB18030 자동 복원을 지원합니다.",
    dropActiveTitle: "여기에 놓으세요",
    dropActiveSubtitle: "압축 파일은 바로 열리고, 일반 파일·폴더는 깨끗한 NFC ZIP으로 준비됩니다",
    supportedFormats: "지원 형식: .zip, .7z, .tar, .tgz, .tar.gz, .tar.zst, .tar.bz2, .tar.xz",
    nfcGuarantee: "UTF-8 NFC 표준 ZIP 생성 · __MACOSX / .DS_Store 자동 제외",
    encodingAuto: "자동",
    encodingManual: "수동",
    encodingResetAuto: "자동 감지로 되돌리기",
    encodingDetectedTop: "감지된 후보",
    encodingAll: "전체 인코딩",
    encodingTooltip: "압축을 풀지 않고 파일명 인코딩을 즉시 바꿔 미리봅니다",
    fixEncoding: "인코딩 복구 (NFC ZIP 저장)",
    fixEncodingTitle: "깨끗한 NFC UTF-8 ZIP으로 저장",
    folders: "폴더",
    allFiles: "전체 파일",
    searchPlaceholder: "파일명 검색…",
    selectAll: "전체 선택",
    clearSelection: "선택 해제",
    selectedCount: (n) => `${n}개 선택됨`,
    showOsJunk: "OS 숨김 파일 표시",
    colName: "이름",
    colSize: "원본 크기",
    colCompressed: "압축 크기",
    colRatio: "절감률",
    colModified: "수정일",
    emptyFolder: "이 폴더에 표시할 항목이 없습니다.",
    noSearchResults: "검색어와 일치하는 항목이 없습니다.",
    extractMode: "풀기 방식",
    modeSmart: "스마트",
    modeDirect: "바로 풀기",
    modeWrap: "폴더 생성",
    modeSmartHint: "최상위 폴더가 하나면 바로 풀고, 파일이 여러 개면 자동으로 폴더를 만들어 정리합니다.",
    modeDirectHint: "선택한 위치에 폴더를 만들지 않고 바로 풉니다.",
    modeWrapHint: "항상 압축 파일 이름의 새 폴더 안에 풉니다.",
    openAfterExtract: "완료 후 폴더 열기",
    overwriteExisting: "기존 파일 덮어쓰기",
    overwriteExistingHint:
      "대상 위치에 같은 이름의 파일이 있으면 중단하지 않고 덮어씁니다.",
    extractAll: "전체 풀기",
    extractSelected: (n) => `선택 항목 풀기 (${n})`,
    entriesLabel: (n) => `${n.toLocaleString()}개 항목`,
    encryptedBadge: "암호화됨",
    packTitle: "크로스 OS ZIP 만들기",
    packInputs: "포함할 파일 및 폴더",
    addFiles: "파일 추가",
    addFolder: "폴더 추가",
    remove: "제거",
    outputPath: "저장 경로",
    browse: "찾아보기…",
    compressionLevel: "압축 수준",
    levelFast: "빠름 (1)",
    levelBalanced: "균형 (6)",
    levelMax: "최대 (9)",
    excludeOsJunk: "OS 정크 파일 제외 (.DS_Store, __MACOSX, ._*, Thumbs.db)",
    excludeOsJunkHint: "macOS ↔ Windows 공유 시 불필요한 시스템 파일을 자동으로 제외합니다.",
    passwordOptional: "AES-256 암호 (선택)",
    passwordPlaceholder: "비워두면 암호 없이 압축합니다",
    aesWindowsWarning:
      "Windows 기본 탐색기는 AES-256 암호화 ZIP을 열 수 없습니다. Windows에서는 단디(Dandi) 또는 7-Zip으로 열어주세요.",
    startPack: "ZIP 생성",
    cancel: "취소",
    cancelling: "취소 중…",
    close: "닫기",
    retry: "다시 시도",
    passwordModalTitle: "암호 필요",
    passwordModalDesc: "계속하려면 압축 파일의 암호를 입력하세요.",
    passwordInvalidError: "암호가 올바르지 않습니다. 다시 확인해 주세요.",
    passwordSubmit: "확인",
    progressEntries: (done, total) =>
      total > 0 ? `${done.toLocaleString()} / ${total.toLocaleString()} 항목` : `${done.toLocaleString()} 항목`,
    progressTitlePack: "ZIP 압축 중…",
    progressTitleUnpack: "압축 푸는 중…",
    progressTitleFix: "깨끗한 NFC ZIP으로 변환 중…",
    revealInFileManager: "폴더에서 보기",
    packSuccess: (entries, size) => `${entries.toLocaleString()}개 항목을 ZIP(${size})으로 압축했습니다.`,
    unpackSuccess: (files, dir) => `${files.toLocaleString()}개 파일을 ${dir}에 풀었습니다.`,
    unpackSuccessWithWarnings: (files, dir, warningCount) =>
      `${files.toLocaleString()}개 파일을 ${dir}에 풀었습니다 (경고 ${warningCount}건).`,
    fixSuccess: (entries, path) => `깨끗한 NFC ZIP(${entries.toLocaleString()}개 항목)을 ${path}에 저장했습니다.`,
    collisionsRenamed: (n) => `대소문자 충돌 파일 ${n}건을 안전하게 이름 변경했습니다.`,
    symlinksSkippedSummary: (n) => `심볼릭 링크 ${n}건을 건너뛰었습니다.`,
    warningsShow: (n) => `경고 보기 (${n})`,
    warningsHide: "경고 접기",
    alreadyExistsGuidance:
      "기존 파일을 덮어쓰려면 하단의 '기존 파일 덮어쓰기'를 켜거나 스마트/폴더 생성 방식을 선택하세요.",
    inspectingArchive: "압축 파일 분석 중…",
    themeSystem: "시스템",
    themeLight: "라이트",
    themeDark: "다크",
    phases: {
      scanning: "스캔 중",
      packing: "압축 중",
      unpacking: "해제 중",
      repacking: "NFC 재압축 중",
      finalizing: "마무리 중",
    },
    warningKinds: {
      symlink_skipped: "심볼릭 링크 건너뜀",
      permission_apply_failed: "권한 적용 실패",
      mtime_apply_failed: "수정 시간 적용 실패",
      zone_id_propagate_failed: "Zone.Identifier 전파 실패",
    },
    errors: {
      io: "파일 입출력 오류",
      unsupported_format: "지원하지 않는 압축 형식입니다",
      corrupt_archive: "압축 파일이 손상되었거나 불완전합니다",
      invalid_password: "암호가 일치하지 않습니다",
      password_required: "암호가 필요한 파일입니다",
      unsafe_path: "위험한 경로를 차단했습니다 (Zip Slip 방어)",
      unsafe_symlink: "안전하지 않은 심볼릭 링크를 차단했습니다",
      budget_exceeded: "안전 용량 한도를 초과했습니다 (Zip Bomb 방어)",
      cancelled: "작업이 취소되었으며 임시 파일을 정리했습니다",
      already_exists: "대상 위치에 같은 파일 또는 폴더가 이미 있습니다",
      invalid_input: "잘못된 입력입니다",
      unsupported_encoding: "지원하지 않는 문자 인코딩입니다",
      archive_engine: "압축 엔진 오류",
      internal: "예기치 않은 내부 오류",
    },
  },
  ja: {
    appName: "Dandi",
    appTagline: "文字化けしない macOS・Windows 対応アーカイバ",
    openArchive: "書庫を開く",
    createZip: "ZIPを作成",
    backHome: "ホーム",
    dropTitle: "書庫をドロップして中身を確認、またはファイルからZIPを作成",
    dropSubtitle:
      "macOS の濁点分離(NFD)防止と Shift_JIS / CP949 / GB18030 の自動判定に対応しています。",
    dropActiveTitle: "ここにドロップ",
    dropActiveSubtitle: "書庫は即座に開き、通常のファイル・フォルダはNFC ZIP作成へ進みます",
    supportedFormats: "対応形式: .zip, .7z, .tar, .tgz, .tar.gz, .tar.zst, .tar.bz2, .tar.xz",
    nfcGuarantee: "UTF-8 NFC 準拠ZIPを生成 · __MACOSX / .DS_Store を自動除外",
    encodingAuto: "自動",
    encodingManual: "手動",
    encodingResetAuto: "自動判定に戻す",
    encodingDetectedTop: "検出された候補",
    encodingAll: "すべての文字コード",
    encodingTooltip: "展開せずにファイル名の文字コードを即座に切り替えてプレビューします",
    fixEncoding: "文字コードを修復 (NFC ZIP保存)",
    fixEncodingTitle: "クリーンな NFC UTF-8 ZIP として保存",
    folders: "フォルダ",
    allFiles: "すべてのファイル",
    searchPlaceholder: "ファイル名を検索…",
    selectAll: "すべて選択",
    clearSelection: "選択解除",
    selectedCount: (n) => `${n}件選択中`,
    showOsJunk: "OS不要ファイルを表示",
    colName: "名前",
    colSize: "サイズ",
    colCompressed: "圧縮後",
    colRatio: "圧縮率",
    colModified: "更新日時",
    emptyFolder: "このフォルダに表示する項目はありません。",
    noSearchResults: "条件に一致する項目がありません。",
    extractMode: "展開方法",
    modeSmart: "スマート",
    modeDirect: "そのまま",
    modeWrap: "フォルダ作成",
    modeSmartHint: "ルートフォルダが1つなら直接展開し、複数ファイルなら自動でフォルダにまとめます。",
    modeDirectHint: "選択先フォルダへ直接展開します。",
    modeWrapHint: "常に書庫名のサブフォルダを作成して展開します。",
    openAfterExtract: "展開後にフォルダを開く",
    overwriteExisting: "既存ファイルを上書き",
    overwriteExistingHint:
      "展開先に同名ファイルが存在する場合、停止せずに上書きします。",
    extractAll: "すべて展開",
    extractSelected: (n) => `選択項目を展開 (${n})`,
    entriesLabel: (n) => `${n.toLocaleString()}件`,
    encryptedBadge: "暗号化",
    packTitle: "クロスOS ZIPを作成",
    packInputs: "対象ファイル・フォルダ",
    addFiles: "ファイル追加",
    addFolder: "フォルダ追加",
    remove: "削除",
    outputPath: "保存先ZIP",
    browse: "参照…",
    compressionLevel: "圧縮レベル",
    levelFast: "高速 (1)",
    levelBalanced: "標準 (6)",
    levelMax: "最大 (9)",
    excludeOsJunk: "OS不要ファイルを除外 (.DS_Store, __MACOSX, ._*, Thumbs.db)",
    excludeOsJunkHint: "macOS ↔ Windows 間の共有時に不要なメタデータを自動除外します。",
    passwordOptional: "AES-256 パスワード（任意）",
    passwordPlaceholder: "空欄の場合は暗号化しません",
    aesWindowsWarning:
      "Windows標準エクスプローラーではAES-256暗号化ZIPを開けません。Windows側ではDandiまたは7-Zipをご利用ください。",
    startPack: "ZIPを作成",
    cancel: "キャンセル",
    cancelling: "キャンセル中…",
    close: "閉じる",
    retry: "再試行",
    passwordModalTitle: "パスワードが必要です",
    passwordModalDesc: "続行するには書庫のパスワードを入力してください。",
    passwordInvalidError: "パスワードが正しくありません。もう一度お試しください。",
    passwordSubmit: "解除",
    progressEntries: (done, total) =>
      total > 0 ? `${done.toLocaleString()} / ${total.toLocaleString()}件` : `${done.toLocaleString()}件`,
    progressTitlePack: "ZIPを作成中…",
    progressTitleUnpack: "書庫を展開中…",
    progressTitleFix: "NFC ZIPへ変換中…",
    revealInFileManager: "場所を開く",
    packSuccess: (entries, size) => `${entries.toLocaleString()}件をZIP(${size})に圧縮しました。`,
    unpackSuccess: (files, dir) => `${files.toLocaleString()}件のファイルを ${dir} に展開しました。`,
    unpackSuccessWithWarnings: (files, dir, warningCount) =>
      `${files.toLocaleString()}件のファイルを ${dir} に展開しました（警告 ${warningCount}件）。`,
    fixSuccess: (entries, path) => `クリーンなNFC ZIP(${entries.toLocaleString()}件)を ${path} に保存しました。`,
    collisionsRenamed: (n) => `大文字・小文字の衝突ファイル ${n}件を安全にリネームしました。`,
    symlinksSkippedSummary: (n) => `シンボリックリンク ${n}件をスキップしました。`,
    warningsShow: (n) => `警告を表示 (${n})`,
    warningsHide: "警告を閉じる",
    alreadyExistsGuidance:
      "上書きするには下部の「既存ファイルを上書き」を有効にするか、スマート／フォルダ作成モードを選択してください。",
    inspectingArchive: "書庫を解析中…",
    themeSystem: "システム",
    themeLight: "ライト",
    themeDark: "ダーク",
    phases: {
      scanning: "スキャン中",
      packing: "圧縮中",
      unpacking: "展開中",
      repacking: "NFC変換中",
      finalizing: "仕上げ中",
    },
    warningKinds: {
      symlink_skipped: "シンボリックリンクをスキップ",
      permission_apply_failed: "権限の適用に失敗",
      mtime_apply_failed: "更新日時の適用に失敗",
      zone_id_propagate_failed: "Zone.Identifier の引き継ぎに失敗",
    },
    errors: {
      io: "ファイルI/Oエラー",
      unsupported_format: "未対応の書庫形式です",
      corrupt_archive: "書庫が破損しているか不完全です",
      invalid_password: "パスワードが違います",
      password_required: "パスワードが必要です",
      unsafe_path: "危険なパスをブロックしました (Zip Slip 対策)",
      unsafe_symlink: "安全でないシンボリックリンクをブロックしました",
      budget_exceeded: "安全上限を超過しました (Zip Bomb 対策)",
      cancelled: "操作をキャンセルし、一時ファイルを削除しました",
      already_exists: "展開先に同名のファイルまたはフォルダが既に存在します",
      invalid_input: "入力が正しくありません",
      unsupported_encoding: "未対応の文字コードです",
      archive_engine: "アーカイブエンジンエラー",
      internal: "予期しない内部エラー",
    },
  },
};

export function detectSystemLocale(lang?: string): Locale {
  const raw = (lang ?? (typeof navigator !== "undefined" ? navigator.language : "en")).toLowerCase();
  if (raw.startsWith("ko")) return "ko";
  if (raw.startsWith("ja")) return "ja";
  return "en";
}
