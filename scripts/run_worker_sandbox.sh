#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 4 ]]; then
  echo "Usage: scripts/run_worker_sandbox.sh <worker-root> <opencode-state-dir> <timeout-seconds> <command> [args...]" >&2
  exit 2
fi

worker_root="$1"
state_root="$2"
timeout_seconds="$3"
shift 3

if [[ "${1:-}" != "opencode" ]]; then
  echo "ERROR: sandbox only launches the approved opencode command." >&2
  exit 4
fi
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  echo "ERROR: DeepSeek worker must not run as root." >&2
  exit 4
fi
if ! command -v bwrap >/dev/null 2>&1; then
  echo "ERROR: bubblewrap is required for the AppCare worker sandbox." >&2
  exit 127
fi
if ! command -v timeout >/dev/null 2>&1; then
  echo "ERROR: coreutils timeout is required for the AppCare worker sandbox." >&2
  exit 127
fi
if ! [[ "$timeout_seconds" =~ ^[0-9]+$ ]] || (( timeout_seconds < 30 || timeout_seconds > 1800 )); then
  echo "ERROR: worker timeout must be between 30 and 1800 seconds." >&2
  exit 4
fi

worker_root_real="$(realpath -e -- "$worker_root" 2>/dev/null || true)"
state_root_real="$(realpath -e -- "$state_root" 2>/dev/null || true)"
if [[ -z "$worker_root_real" || -z "$state_root_real" || ! -d "$worker_root_real" || ! -d "$state_root_real" ]]; then
  echo "ERROR: worker and provider-state roots must be existing directories." >&2
  exit 4
fi
if [[ -L "$worker_root" || -L "$state_root" ]]; then
  echo "ERROR: worker and provider-state roots must not be symlinks." >&2
  exit 4
fi
case "${worker_root_real,,}" in
  *wordpress*|*barnd*|*shield*|*production*|*deploy*)
    echo "ERROR: worker worktree path is outside the AppCare boundary." >&2
    exit 4
    ;;
esac
case "$worker_root_real" in
  */securityola-appcare-worker.*/worktree) ;;
  *)
    echo "ERROR: worker root is not a launcher-created disposable AppCare worktree." >&2
    exit 4
    ;;
esac
case "${state_root_real,,}" in
  *wordpress*|*barnd*|*shield*|*production*|*deploy*|*.env*|*.ssh*)
    echo "ERROR: provider state path is outside the AppCare worker boundary." >&2
    exit 4
    ;;
esac
case "$state_root_real" in
  "$worker_root_real"|"$worker_root_real"/*)
    echo "ERROR: provider state must not be inside the worker worktree." >&2
    exit 4
    ;;
esac

opencode_path="$(command -v opencode)"
opencode_real="$(realpath -e -- "$opencode_path" 2>/dev/null || true)"
if [[ -z "$opencode_real" ]]; then
  echo "ERROR: approved OpenCode executable could not be resolved." >&2
  exit 4
fi
opencode_tool_bind=()
sandbox_opencode="$opencode_real"
sandbox_path="/usr/local/bin:/usr/bin:/bin"
case "$opencode_real" in
  /usr/*|/bin/*|/opt/*|/lib/*|/lib64/*) ;;
  *)
    opencode_tool_root="${APPCARE_OPENCODE_TOOL_ROOT:-}"
    if [[ -z "$opencode_tool_root" ]]; then
      echo "ERROR: non-system OpenCode requires APPCARE_OPENCODE_TOOL_ROOT." >&2
      exit 4
    fi
    opencode_tool_root_real="$(realpath -e -- "$opencode_tool_root" 2>/dev/null || true)"
    if [[ -z "$opencode_tool_root_real" || ! -d "$opencode_tool_root_real" || -L "$opencode_tool_root" ]]; then
      echo "ERROR: AppCare OpenCode tool root must be an existing non-symlink directory." >&2
      exit 4
    fi
    case "${opencode_tool_root_real,,}" in
      *wordpress*|*barnd*|*shield*|*production*|*deploy*|*.env*|*.ssh*)
        echo "ERROR: OpenCode tool root is outside the AppCare boundary." >&2
        exit 4
        ;;
    esac
    case "$opencode_tool_root_real" in
      /home/*/appcare-tools) ;;
      *)
        echo "ERROR: non-system OpenCode tool root must be /home/<user>/appcare-tools." >&2
        exit 4
        ;;
    esac
    case "$opencode_real" in
      "$opencode_tool_root_real"/*) ;;
      *)
        echo "ERROR: OpenCode executable is outside the declared AppCare tool root." >&2
        exit 4
        ;;
    esac
    opencode_relative="${opencode_real#"$opencode_tool_root_real"/}"
    sandbox_opencode="/opt/appcare-opencode-tools/$opencode_relative"
    sandbox_path="/opt/appcare-opencode-tools/bin:$sandbox_path"
    opencode_tool_bind=(--ro-bind "$opencode_tool_root_real" /opt/appcare-opencode-tools)
    ;;
esac

state_mode="$(stat -c '%a' "$state_root_real" 2>/dev/null || stat -f '%Lp' "$state_root_real" 2>/dev/null || true)"
if [[ "$state_mode" =~ ^[0-7]{3}$ && "${state_mode:1:2}" != "00" ]]; then
  echo "ERROR: provider state directory is too broadly accessible." >&2
  exit 4
fi

worker_command=("$@")
worker_command[0]="$sandbox_opencode"

sandbox=(
  bwrap
  --die-with-parent
  --new-session
  --unshare-user
  --unshare-pid
  --unshare-uts
  --unshare-ipc
  --unshare-cgroup-try
  --cap-drop ALL
  --clearenv
)
for system_path in /usr /bin /lib /lib64 /opt /etc; do
  if [[ -e "$system_path" ]]; then
    sandbox+=(--ro-bind "$system_path" "$system_path")
  fi
done
sandbox+=(
  "${opencode_tool_bind[@]}"
  --proc /proc
  --dev /dev
  --tmpfs /tmp
  --tmpfs /home
  --tmpfs /var
  --tmpfs /run
  --dir /home/appcare-worker
  --dir /tmp/appcare-opencode-cache
  --ro-bind "$state_root_real" /run/appcare-opencode-state
  --bind "$worker_root_real" /workspace
  --chdir /workspace
  --setenv HOME /home/appcare-worker
  --setenv PATH "$sandbox_path"
  --setenv XDG_CONFIG_HOME /run/appcare-opencode-state/config
  --setenv XDG_DATA_HOME /run/appcare-opencode-state/data
  --setenv XDG_CACHE_HOME /tmp/appcare-opencode-cache
  --setenv LANG C.UTF-8
  --setenv LC_ALL C.UTF-8
  --setenv TARGET AppCare
  --setenv APPCARE_WORKER_SANDBOX 1
)
if [[ "${APPCARE_WORKER_OFFLINE:-0}" == "1" ]]; then
  sandbox+=(--unshare-net)
fi

exec timeout --signal=TERM --kill-after=10s "$timeout_seconds" "${sandbox[@]}" "${worker_command[@]}"
