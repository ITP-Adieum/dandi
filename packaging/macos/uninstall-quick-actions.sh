#!/usr/bin/env bash
# Remove Dandi macOS Finder Quick Actions from ~/Library/Services/.

set -euo pipefail

DRY_RUN=0
SERVICES_DIR="${HOME}/Library/Services"

usage() {
  cat <<'EOF'
Usage: uninstall-quick-actions.sh [OPTIONS]

Remove Dandi Finder Quick Actions ("Compress with Dandi" and "Extract with Dandi")
from ~/Library/Services/.

Options:
  --services-dir <dir>   Target Services directory (default: ~/Library/Services)
  --dry-run              Print planned removals without deleting files
  -h, --help             Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
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

WORKFLOWS=(
  "${SERVICES_DIR}/Compress with Dandi.workflow"
  "${SERVICES_DIR}/Extract with Dandi.workflow"
)

removed=0
for wf in "${WORKFLOWS[@]}"; do
  if [[ -e "$wf" ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      echo "[dry-run] Would remove: ${wf}"
    else
      rm -rf "$wf"
      echo "Removed: ${wf}"
    fi
    removed=$((removed + 1))
  else
    echo "Not present (skipped): ${wf}"
  fi
done

if [[ "$DRY_RUN" -eq 0 && "$removed" -gt 0 && -x "/System/Library/CoreServices/pbs" ]]; then
  /System/Library/CoreServices/pbs -update >/dev/null 2>&1 || true
fi
