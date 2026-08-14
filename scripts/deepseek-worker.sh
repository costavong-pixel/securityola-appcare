#!/usr/bin/env bash
set -euo pipefail

PINNED_OPENCODE_VERSION="1.18.16"
MODEL="opencode/deepseek-v4-flash-free"
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

if [[ $# -ne 1 || ! -f "$1" ]]; then
  echo "Usage: scripts/deepseek-worker.sh <task-file under .codex/tasks>" >&2
  exit 2
fi

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
if ! git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "ERROR: launcher must resolve an AppCare Git checkout." >&2
  exit 4
fi
cd -- "$repo_root"
coordinator_branch="$(git -C "$repo_root" branch --show-current)"
coordinator_head="$(git -C "$repo_root" rev-parse HEAD)"
if [[ -z "$coordinator_branch" ]]; then
  echo "ERROR: worker launcher requires a real non-detached AppCare branch." >&2
  exit 7
fi

repo_root_real="$(realpath -e -- "$repo_root" 2>/dev/null || true)"
task_root="$repo_root/.codex/tasks"
if [[ -L "$task_root" ]]; then
  echo "ERROR: task directory must not be a symlink." >&2
  exit 4
fi
task_root="$(realpath -e -- "$task_root" 2>/dev/null || true)"
task_file="$(realpath -e -- "$1" 2>/dev/null || true)"
if [[ -z "$repo_root_real" || -z "$task_root" || -z "$task_file" ]]; then
  echo "ERROR: task file or task directory does not resolve." >&2
  exit 4
fi
case "$task_root" in
  "$repo_root_real/.codex/tasks"|"$repo_root_real/.codex/tasks/"*) ;;
  *)
    echo "ERROR: task directory must resolve beneath the repository .codex/tasks directory." >&2
    exit 4
    ;;
esac
case "$task_file" in
  "$task_root"/*) ;;
  *)
    echo "ERROR: task file must resolve beneath the repository .codex/tasks directory." >&2
    exit 4
    ;;
esac
task_file_recheck="$(realpath -e -- "$1" 2>/dev/null || true)"
if [[ "$task_file_recheck" != "$task_file" || ! -f "$task_file" || -L "$task_file" ]]; then
  echo "ERROR: task file changed or is not a regular non-symlink file." >&2
  exit 4
fi

python_cmd="$(command -v python3 || command -v python || true)"
if [[ -z "$python_cmd" ]]; then
  echo "ERROR: Python is required to validate the task packet." >&2
  exit 127
fi

if [[ -n "$(git -C "$repo_root" status --porcelain --untracked-files=all)" ]]; then
  echo "ERROR: worker launcher requires a clean AppCare checkout before isolation." >&2
  echo "Commit or otherwise checkpoint the reviewed coordinator changes first." >&2
  exit 7
fi
if ! "$python_cmd" scripts/verify_worker_policy.py >/dev/null; then
  echo "ERROR: worker policy verification failed before isolation." >&2
  exit 5
fi

run_root="$(mktemp -d "${TMPDIR:-/tmp}/securityola-appcare-worker.XXXXXX")"
worker_root="$run_root/worktree"
scope_dir="$run_root/scope"
mkdir -p "$scope_dir"

cleanup() {
  exit_code=$?
  worktree_cleanup_status=0
  if [[ -n "${worker_root:-}" && -d "$worker_root" ]]; then
    git -C "$repo_root" worktree remove --force "$worker_root" >/dev/null 2>&1 || {
      git -C "$repo_root" worktree remove --force "$worker_root" >/dev/null 2>&1 || true
      if [[ -d "$worker_root" ]]; then
        worktree_cleanup_status=1
        echo "ERROR: isolated worker worktree cleanup did not complete." >&2
      fi
    }
  fi
  if [[ "$worktree_cleanup_status" -eq 0 && -n "${run_root:-}" && -d "$run_root" ]]; then
    run_parent="$(realpath -e -- "$(dirname -- "$run_root")" 2>/dev/null || true)"
    run_root_real="$(realpath -e -- "$run_root" 2>/dev/null || true)"
    case "$run_root_real" in
      "$run_parent"/securityola-appcare-worker.*)
        if [[ "$run_root_real" != "/" && "$run_root_real" != "$repo_root_real" ]]; then
          if ! rm -rf -- "$run_root_real" || [[ -e "$run_root_real" ]]; then
            worktree_cleanup_status=1
            echo "ERROR: temporary worker data cleanup did not complete." >&2
          fi
        fi
        ;;
      *)
        worktree_cleanup_status=1
        echo "ERROR: refusing to remove an unverified temporary worker path." >&2
        ;;
    esac
  fi
  if [[ "$worktree_cleanup_status" -ne 0 && "$exit_code" -eq 0 ]]; then
    exit_code=9
  fi
  trap - EXIT
  exit "$exit_code"
}
trap cleanup EXIT

sealed_task="$run_root/task.md"
if ! "$python_cmd" scripts/validate_task_packet.py "$task_file" \
  --seal-output "$sealed_task" \
  --repo-root "$repo_root" \
  --task-root "$task_root" \
  --expected-head "$coordinator_head" \
  --expected-branch "$coordinator_branch" >/dev/null; then
  echo "ERROR: task packet failed the stable secret, scope, and private-data safety check." >&2
  exit 5
fi
prompt="$(<"$sealed_task")"
if [[ -z "${prompt//[[:space:]]/}" ]]; then
  echo "ERROR: empty task." >&2
  exit 2
fi

current_branch="$(git -C "$repo_root" branch --show-current)"
current_head="$(git -C "$repo_root" rev-parse HEAD)"
if [[ "$current_branch" != "$coordinator_branch" || "$current_head" != "$coordinator_head" || -n "$(git -C "$repo_root" status --porcelain --untracked-files=all)" ]]; then
  echo "ERROR: AppCare branch, HEAD, or clean state changed before worker execution." >&2
  exit 7
fi

git -C "$repo_root" worktree add --detach "$worker_root" HEAD >/dev/null
mkdir -p "$worker_root/.codex/tasks"
worker_task="$worker_root/.codex/tasks/$(basename -- "$task_file")"
cp -- "$sealed_task" "$worker_task"
cp -- "$sealed_task" "$scope_dir/task-before.md"

worker_policy="$worker_root/.opencode/agents/deepseek-worker-task.md"
if ! "$python_cmd" -m scripts.generate_worker_policy \
  --task "$worker_task" \
  --output "$worker_policy" >/dev/null; then
  echo "ERROR: task-scoped worker policy could not be generated." >&2
  exit 5
fi

scope_snapshot="$scope_dir/before.json"
"$python_cmd" "$repo_root/scripts/verify_task_scope.py" snapshot \
  --root "$worker_root" \
  --out "$scope_snapshot" >/dev/null

worker_status=0
cd -- "$worker_root"
worker_timeout="${APPCARE_WORKER_TIMEOUT_SECONDS:-900}"
worker_state_dir="${APPCARE_OPENCODE_STATE_DIR:-}"
"$repo_root/scripts/run_worker_sandbox.sh" \
  "$worker_root" \
  "$worker_state_dir" \
  "$worker_timeout" \
  opencode run \
  --agent deepseek-worker-task \
  --model "$MODEL" \
  --format default \
  "$prompt" || worker_status=$?
cd -- "$repo_root"

scope_status=0
"$python_cmd" "$repo_root/scripts/verify_task_scope.py" verify \
  --root "$worker_root" \
  --before "$scope_snapshot" \
  --task "$worker_task" \
  --baseline-task "$scope_dir/task-before.md" || scope_status=$?
if [[ "$scope_status" -ne 0 ]]; then
  echo "ERROR: worker scope verification failed; isolated worktree was discarded." >&2
  exit 6
fi
if [[ "$worker_status" -ne 0 ]]; then
  exit "$worker_status"
fi

secret_status=0
"$python_cmd" -m scripts.scan_worker_changes \
  --root "$worker_root" \
  --before "$scope_snapshot" || secret_status=$?
if [[ "$secret_status" -ne 0 ]]; then
  echo "ERROR: worker-produced changes failed the deterministic secret scan." >&2
  exit 8
fi

"$python_cmd" "$repo_root/scripts/verify_task_scope.py" promote \
  --source-root "$worker_root" \
  --target-root "$repo_root" \
  --before "$scope_snapshot" \
  --task "$worker_task" \
  --baseline-task "$scope_dir/task-before.md" \
  --expected-head "$coordinator_head" \
  --expected-branch "$coordinator_branch"
