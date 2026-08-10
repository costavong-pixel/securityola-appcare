#!/usr/bin/env bash
set -euo pipefail

PINNED_OPENCODE_VERSION="${OPENCODE_PIN:-1.18.16}"
MODEL="${OPENCODE_WORKER_MODEL:-deepseek/deepseek-v4-flash}"
AGENT="deepseek-worker"

if ! command -v opencode >/dev/null 2>&1; then
  echo "ERROR: opencode is not installed." >&2
  exit 127
fi

actual_version="$(opencode --version 2>/dev/null | tr -d '[:space:]' || true)"
if [[ -z "$actual_version" ]]; then
  echo "ERROR: unable to determine OpenCode version." >&2
  exit 3
fi

if [[ "$actual_version" != "$PINNED_OPENCODE_VERSION" && "$actual_version" != "v$PINNED_OPENCODE_VERSION" ]]; then
  echo "ERROR: OpenCode version $actual_version does not match audited pin $PINNED_OPENCODE_VERSION." >&2
  echo "Update the pin only after Codex re-audits the new version." >&2
  exit 3
fi

if [[ $# -lt 1 ]]; then
  echo "Usage: scripts/deepseek-worker.sh <task-file | task text>" >&2
  exit 2
fi

if [[ $# -eq 1 && -f "$1" ]]; then
  prompt="$(cat "$1")"
else
  prompt="$*"
fi

if [[ -z "${prompt//[[:space:]]/}" ]]; then
  echo "ERROR: empty task." >&2
  exit 2
fi

exec opencode run \
  --agent "$AGENT" \
  --model "$MODEL" \
  --format default \
  "$prompt"
