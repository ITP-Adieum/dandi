#!/usr/bin/env bash
# Install headless macOS Finder Quick Actions (.workflow) for Dandi.
# Runs `dandi` silently in the background without popping the desktop window
# (prevents MacPacker#279) and works across local, iCloud Drive, and external
# volumes (prevents MacPacker#275 / #305).

set -euo pipefail
shopt -u patsub_replacement 2>/dev/null || true

DRY_RUN=0
DANDI_BIN_ARG=""
SERVICES_DIR="${HOME}/Library/Services"

usage() {
  cat <<'EOF'
Usage: install-quick-actions.sh [OPTIONS]

Install macOS Finder Quick Actions ("Compress with Dandi" and "Extract with Dandi")
into ~/Library/Services/.

Options:
  --dandi-bin <path>     Explicit path to the `dandi` CLI binary
  --services-dir <dir>   Target Services directory (default: ~/Library/Services)
  --dry-run              Print planned actions without writing files
  -h, --help             Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dandi-bin)
      if [[ $# -lt 2 ]]; then
        echo "error: --dandi-bin requires a path argument" >&2
        exit 1
      fi
      DANDI_BIN_ARG="$2"
      shift 2
      ;;
    --services-dir)
      if [[ $# -lt 2 ]]; then
        echo "error: --services-dir requires a directory argument" >&2
        exit 1
      fi
      SERVICES_DIR="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option '$1'" >&2
      usage >&2
      exit 1
      ;;
  esac
done

resolve_dandi_bin() {
  if [[ -n "$DANDI_BIN_ARG" ]]; then
    printf '%s\n' "$DANDI_BIN_ARG"
    return 0
  fi

  if command -v dandi >/dev/null 2>&1; then
    command -v dandi
    return 0
  fi

  local candidate
  for candidate in \
    "/opt/homebrew/bin/dandi" \
    "/usr/local/bin/dandi" \
    "${HOME}/.cargo/bin/dandi" \
    "/Applications/Dandi.app/Contents/MacOS/dandi"; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  printf '%s\n' "/usr/local/bin/dandi"
}

xml_escape() {
  local s="$1"
  s="${s//&/&amp;}"
  s="${s//</&lt;}"
  s="${s//>/&gt;}"
  printf '%s' "$s"
}

bash_single_quote() {
  local s="$1"
  local sq="'"
  local rep="'\\''"
  printf "'%s'" "${s//$sq/$rep}"
}

DANDI_BIN="$(resolve_dandi_bin)"
if [[ ! -x "$DANDI_BIN" ]]; then
  echo "note: '$DANDI_BIN' is not currently executable; the workflow will also search standard PATH locations at runtime." >&2
fi

DANDI_BIN_QUOTED="$(bash_single_quote "$DANDI_BIN")"

COMPRESS_NAME="Compress with Dandi"
EXTRACT_NAME="Extract with Dandi"
COMPRESS_WORKFLOW="${SERVICES_DIR}/${COMPRESS_NAME}.workflow"
EXTRACT_WORKFLOW="${SERVICES_DIR}/${EXTRACT_NAME}.workflow"

COMMON_HELPER=$(cat <<EOF
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:\${HOME}/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin"

notify() {
  /usr/bin/osascript - "\$1" "\$2" <<'APPLESCRIPT' || true
on run argv
  display notification (item 2 of argv) with title (item 1 of argv)
end run
APPLESCRIPT
}

find_dandi() {
  local configured=${DANDI_BIN_QUOTED}
  if [[ -x "\$configured" ]]; then
    printf '%s\n' "\$configured"
    return 0
  fi
  if command -v dandi >/dev/null 2>&1; then
    command -v dandi
    return 0
  fi
  local c
  for c in "/opt/homebrew/bin/dandi" "/usr/local/bin/dandi" "\${HOME}/.cargo/bin/dandi" "/Applications/Dandi.app/Contents/MacOS/dandi"; do
    if [[ -x "\$c" ]]; then
      printf '%s\n' "\$c"
      return 0
    fi
  done
  return 1
}

DANDI_BIN="\$(find_dandi || true)"
if [[ -z "\$DANDI_BIN" ]]; then
  notify "Dandi" "Could not find the 'dandi' CLI binary. Install Dandi CLI or re-run install-quick-actions.sh --dandi-bin <path>."
  exit 1
fi
EOF
)

COMPRESS_SCRIPT=$(cat <<EOF
${COMMON_HELPER}

if [[ \$# -eq 0 ]]; then
  exit 0
fi

first_item="\$1"
parent_dir="\$(dirname -- "\$first_item")"

if [[ \$# -eq 1 ]]; then
  item_name="\$(basename -- "\$first_item")"
  if [[ -d "\$first_item" ]]; then
    stem="\$item_name"
  else
    stem="\${item_name%.*}"
    if [[ -z "\$stem" || "\$stem" == "\$item_name" && "\$item_name" == .* ]]; then
      stem="\$item_name"
    fi
  fi
else
  stem="Archive"
fi

out_zip="\${parent_dir}/\${stem}.zip"
idx=2
while [[ -e "\$out_zip" ]]; do
  out_zip="\${parent_dir}/\${stem} (\${idx}).zip"
  idx=\$((idx + 1))
done

if err_out=\$("\$DANDI_BIN" pack -o "\$out_zip" -- "\$@" 2>&1); then
  notify "Dandi" "Created \$(basename -- "\$out_zip")"
else
  first_line="\${err_out%%\$'\n'*}"
  notify "Dandi" "Compression failed: \${first_line:-unknown error}"
  exit 1
fi
EOF
)

EXTRACT_SCRIPT=$(cat <<EOF
${COMMON_HELPER}

if [[ \$# -eq 0 ]]; then
  exit 0
fi

ok_count=0
fail_count=0
last_ok_name=""
last_err=""

for archive in "\$@"; do
  dest_dir="\$(dirname -- "\$archive")"
  if out=\$("\$DANDI_BIN" unpack --dest "\$dest_dir" --mode smart -- "\$archive" 2>&1); then
    ok_count=\$((ok_count + 1))
    last_ok_name="\$(basename -- "\$archive")"
  else
    fail_count=\$((fail_count + 1))
    last_err="\${out%%\$'\n'*}"
  fi
done

if [[ \$fail_count -eq 0 ]]; then
  if [[ \$ok_count -eq 1 ]]; then
    notify "Dandi" "Extracted \${last_ok_name}"
  else
    notify "Dandi" "Extracted \${ok_count} archives"
  fi
else
  notify "Dandi" "Extraction failed (\${fail_count} error(s)): \${last_err:-unknown error}"
  exit 1
fi
EOF
)

write_info_plist() {
  local target_file="$1"
  local menu_title="$2"
  shift 2
  local uti_xml=""
  local uti
  for uti in "$@"; do
    uti_xml="${uti_xml}        <string>$(xml_escape "$uti")</string>
"
  done

  cat >"$target_file" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>NSServices</key>
  <array>
    <dict>
      <key>NSBackgroundColorName</key>
      <string>background</string>
      <key>NSIconName</key>
      <string>NSActionTemplate</string>
      <key>NSMenuItem</key>
      <dict>
        <key>default</key>
        <string>$(xml_escape "$menu_title")</string>
      </dict>
      <key>NSMessage</key>
      <string>runWorkflowAsService</string>
      <key>NSRequiredContext</key>
      <dict>
        <key>NSApplicationIdentifier</key>
        <string>com.apple.finder</string>
      </dict>
      <key>NSSendFileTypes</key>
      <array>
${uti_xml}      </array>
    </dict>
  </array>
</dict>
</plist>
EOF
}

write_document_wflow() {
  local target_file="$1"
  local action_uuid="$2"
  local input_uuid="$3"
  local output_uuid="$4"
  local script_body="$5"
  local escaped_script
  escaped_script="$(xml_escape "$script_body")"

  cat >"$target_file" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>AMApplicationBuild</key>
  <string>523</string>
  <key>AMApplicationVersion</key>
  <string>2.10</string>
  <key>AMDocumentVersion</key>
  <string>2</string>
  <key>actions</key>
  <array>
    <dict>
      <key>action</key>
      <dict>
        <key>AMAccepts</key>
        <dict>
          <key>Container</key>
          <string>List</string>
          <key>Optional</key>
          <true/>
          <key>Types</key>
          <array>
            <string>com.apple.cocoa.string</string>
          </array>
        </dict>
        <key>AMActionVersion</key>
        <string>2.0.3</string>
        <key>AMApplication</key>
        <array>
          <string>Automator</string>
        </array>
        <key>AMParameterProperties</key>
        <dict>
          <key>COMMAND_STRING</key>
          <dict/>
          <key>CheckedForUserDefaultShell</key>
          <dict/>
          <key>inputMethod</key>
          <dict/>
          <key>shell</key>
          <dict/>
          <key>source</key>
          <dict/>
        </dict>
        <key>AMProvides</key>
        <dict>
          <key>Container</key>
          <string>List</string>
          <key>Types</key>
          <array>
            <string>com.apple.cocoa.string</string>
          </array>
        </dict>
        <key>ActionBundlePath</key>
        <string>/System/Library/Automator/Run Shell Script.action</string>
        <key>ActionName</key>
        <string>Run Shell Script</string>
        <key>ActionParameters</key>
        <dict>
          <key>COMMAND_STRING</key>
          <string>${escaped_script}</string>
          <key>CheckedForUserDefaultShell</key>
          <true/>
          <key>inputMethod</key>
          <integer>1</integer>
          <key>shell</key>
          <string>/bin/bash</string>
          <key>source</key>
          <string></string>
        </dict>
        <key>BundleIdentifier</key>
        <string>com.apple.RunShellScript</string>
        <key>CFBundleVersion</key>
        <string>2.0.3</string>
        <key>CanShowSelectedItemsWhenRun</key>
        <false/>
        <key>CanShowWhenRun</key>
        <false/>
        <key>Category</key>
        <array>
          <string>AMCategoryUtilities</string>
        </array>
        <key>Class Name</key>
        <string>RunShellScriptAction</string>
        <key>InputUUID</key>
        <string>${input_uuid}</string>
        <key>Keywords</key>
        <array>
          <string>Shell</string>
          <string>Script</string>
          <string>Command</string>
          <string>Run</string>
          <string>Unix</string>
        </array>
        <key>OutputUUID</key>
        <string>${output_uuid}</string>
        <key>UUID</key>
        <string>${action_uuid}</string>
        <key>UnlocalizedApplications</key>
        <array>
          <string>Automator</string>
        </array>
        <key>arguments</key>
        <dict>
          <key>0</key>
          <dict>
            <key>default value</key>
            <integer>0</integer>
            <key>name</key>
            <string>inputMethod</string>
            <key>required</key>
            <string>0</string>
            <key>type</key>
            <string>0</string>
            <key>uuid</key>
            <string>0</string>
          </dict>
          <key>1</key>
          <dict>
            <key>default value</key>
            <false/>
            <key>name</key>
            <string>CheckedForUserDefaultShell</string>
            <key>required</key>
            <string>0</string>
            <key>type</key>
            <string>0</string>
            <key>uuid</key>
            <string>1</string>
          </dict>
          <key>2</key>
          <dict>
            <key>default value</key>
            <string></string>
            <key>name</key>
            <string>source</string>
            <key>required</key>
            <string>0</string>
            <key>type</key>
            <string>0</string>
            <key>uuid</key>
            <string>2</string>
          </dict>
          <key>3</key>
          <dict>
            <key>default value</key>
            <string></string>
            <key>name</key>
            <string>COMMAND_STRING</string>
            <key>required</key>
            <string>0</string>
            <key>type</key>
            <string>0</string>
            <key>uuid</key>
            <string>3</string>
          </dict>
          <key>4</key>
          <dict>
            <key>default value</key>
            <string>/bin/sh</string>
            <key>name</key>
            <string>shell</string>
            <key>required</key>
            <string>0</string>
            <key>type</key>
            <string>0</string>
            <key>uuid</key>
            <string>4</string>
          </dict>
        </dict>
        <key>isViewVisible</key>
        <integer>1</integer>
      </dict>
      <key>isViewVisible</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>connectors</key>
  <dict/>
  <key>workflowMetaData</key>
  <dict>
    <key>applicationBundleID</key>
    <string>com.apple.finder</string>
    <key>applicationBundleIDsByPath</key>
    <dict>
      <key>/System/Library/CoreServices/Finder.app</key>
      <string>com.apple.finder</string>
    </dict>
    <key>applicationPath</key>
    <string>/System/Library/CoreServices/Finder.app</string>
    <key>applicationPaths</key>
    <array>
      <string>/System/Library/CoreServices/Finder.app</string>
    </array>
    <key>inputTypeIdentifier</key>
    <string>com.apple.Automator.fileSystemObject</string>
    <key>outputTypeIdentifier</key>
    <string>com.apple.Automator.nothing</string>
    <key>presentationMode</key>
    <integer>15</integer>
    <key>processesInput</key>
    <false/>
    <key>serviceApplicationBundleID</key>
    <string>com.apple.finder</string>
    <key>serviceApplicationPath</key>
    <string>/System/Library/CoreServices/Finder.app</string>
    <key>serviceInputTypeIdentifier</key>
    <string>com.apple.Automator.fileSystemObject</string>
    <key>serviceOutputTypeIdentifier</key>
    <string>com.apple.Automator.nothing</string>
    <key>serviceProcessesInput</key>
    <false/>
    <key>systemImageName</key>
    <string>NSActionTemplate</string>
    <key>useAutomaticInputType</key>
    <false/>
    <key>workflowTypeIdentifier</key>
    <string>com.apple.Automator.servicesMenu</string>
  </dict>
</dict>
</plist>
EOF
}

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "[dry-run] Would use dandi binary: ${DANDI_BIN}"
  echo "[dry-run] Would install: ${COMPRESS_WORKFLOW}"
  echo "[dry-run] Would install: ${EXTRACT_WORKFLOW}"
  exit 0
fi

mkdir -p "${COMPRESS_WORKFLOW}/Contents" "${EXTRACT_WORKFLOW}/Contents"

write_info_plist \
  "${COMPRESS_WORKFLOW}/Contents/Info.plist" \
  "${COMPRESS_NAME}" \
  "public.item"

write_document_wflow \
  "${COMPRESS_WORKFLOW}/Contents/document.wflow" \
  "A1D4D101-7F3E-4C2B-9A11-000000000001" \
  "A1D4D101-7F3E-4C2B-9A11-000000000002" \
  "A1D4D101-7F3E-4C2B-9A11-000000000003" \
  "${COMPRESS_SCRIPT}"

write_info_plist \
  "${EXTRACT_WORKFLOW}/Contents/Info.plist" \
  "${EXTRACT_NAME}" \
  "public.archive" \
  "public.zip-archive" \
  "org.gnu.gnu-zip-archive" \
  "public.tar-archive" \
  "org.gnu.gnu-tar-archive" \
  "public.bzip2-archive" \
  "org.tukaani.xz-archive" \
  "org.7-zip.7-zip-archive" \
  "com.rarlab.rar-archive" \
  "com.facebook.zstd-archive" \
  "public.zstd-archive"

write_document_wflow \
  "${EXTRACT_WORKFLOW}/Contents/document.wflow" \
  "A1D4D102-7F3E-4C2B-9A11-000000000001" \
  "A1D4D102-7F3E-4C2B-9A11-000000000002" \
  "A1D4D102-7F3E-4C2B-9A11-000000000003" \
  "${EXTRACT_SCRIPT}"

if [[ -x "/System/Library/CoreServices/pbs" ]]; then
  /System/Library/CoreServices/pbs -update >/dev/null 2>&1 || true
fi

echo "Installed Dandi Finder Quick Actions:"
echo "  - ${COMPRESS_WORKFLOW}"
echo "  - ${EXTRACT_WORKFLOW}"
echo "CLI binary: ${DANDI_BIN}"
echo "Tip: Right-click files in Finder -> Quick Actions -> Compress/Extract with Dandi."
