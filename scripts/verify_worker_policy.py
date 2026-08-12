"""Verify the bounded OpenCode worker policy and launcher contract."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

EXPECTED_FRONTMATTER_SHA256 = "661a83e0a8f250cf870273dcf8d3d253159d36a6ff636de0c7ca139a562d5d27"
REQUIRED_DENIALS = (
    "external_directory: deny",
    "webfetch: deny",
    "websearch: deny",
    "task: deny",
    "skill: deny",
    "glob: deny",
    "grep: deny",
    "lsp: deny",
    'bash:\n    "*": deny',
)
REQUIRED_READ_ONLY_ALLOWS = (
    '"git status*": allow',
    '"git diff --no-ext-diff*": allow',
    '"git log --oneline*": allow',
    '"git show --stat*": allow',
    '"git branch --show-current*": allow',
)
REQUIRED_PATH_BOUNDARIES = (
    'read:\n    "*": deny',
    'edit:\n    "*": deny',
    '"appcare/*": allow',
    '"tests/*": allow',
    '"docs/security/*": deny',
)
FORBIDDEN_POLICY_MARKERS = (
    "read: allow",
    "edit: allow",
    "glob: allow",
    "grep: allow",
    "lsp: allow",
    '"rg *": allow',
    '"grep *": allow',
    '"find *": allow',
    '"npm run *": allow',
    '"pnpm run *": allow',
    '"bun run *": allow',
    '"uv run *": allow',
    '"pytest -q*": allow',
    '"python -m pytest -q*": allow',
)
FORBIDDEN_LAUNCHER_OPERATIONS = (
    "ssh ",
    "scp ",
    "rsync ",
    "git commit",
    "git push",
    "git merge",
    "docker ",
    "kubectl ",
    "OPENCODE_PIN",
    "OPENCODE_WORKER_MODEL",
)
REQUIRED_LAUNCHER_GUARDS = (
    'repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"',
    'git -C "$repo_root" rev-parse --is-inside-work-tree',
    'cd -- "$repo_root"',
    'git -C "$repo_root" status --porcelain --untracked-files=all',
    'coordinator_head="$(git -C "$repo_root" rev-parse HEAD)"',
    '"$(git -C "$repo_root" rev-parse HEAD)" != "$coordinator_head"',
    'task_root="$repo_root/.codex/tasks"',
    'task_file="$(realpath -e -- "$1"',
    'case "$task_file" in',
    '"$task_root"/*)',
    "scripts/validate_task_packet.py",
    "scripts/verify_task_scope.py",
    "mktemp -d",
    'git -C "$repo_root" worktree add --detach "$worker_root" HEAD',
    "--baseline-task",
    "promote",
    "worktree remove --force",
    'rm -rf -- "$run_root_real"',
)


def frontmatter(text: str) -> str:
    if not text.startswith("---\n"):
        return ""
    end = text.find("\n---", 3)
    if end < 0:
        return ""
    return text[:end].strip() + "\n"


def verify(root: Path) -> list[str]:
    agent_path = root / ".opencode" / "agents" / "deepseek-worker.md"
    launcher_path = root / "scripts" / "deepseek-worker.sh"
    agent = agent_path.read_text(encoding="utf-8")
    launcher = launcher_path.read_text(encoding="utf-8")
    findings: list[str] = []
    actual_hash = hashlib.sha256(frontmatter(agent).encode("utf-8")).hexdigest()
    if actual_hash != EXPECTED_FRONTMATTER_SHA256:
        findings.append("worker frontmatter does not match the reviewed immutable policy")
    for marker in REQUIRED_DENIALS:
        if marker not in agent:
            findings.append(f"missing worker denial: {marker}")
    for marker in REQUIRED_READ_ONLY_ALLOWS:
        if marker not in agent:
            findings.append(f"missing bounded read-only allowance: {marker}")
    for marker in REQUIRED_PATH_BOUNDARIES:
        if marker not in agent:
            findings.append(f"missing worker path boundary: {marker}")
    for marker in FORBIDDEN_POLICY_MARKERS:
        if marker in agent:
            findings.append(f"overbroad worker permission: {marker}")
    for marker in FORBIDDEN_LAUNCHER_OPERATIONS:
        if marker in launcher:
            findings.append(f"forbidden launcher operation: {marker.strip()}")
    for marker in REQUIRED_LAUNCHER_GUARDS:
        if marker not in launcher:
            findings.append(f"missing task-path guard: {marker}")
    if 'PINNED_OPENCODE_VERSION="1.18.16"' not in launcher:
        findings.append("launcher pin is not 1.18.16")
    if 'MODEL="opencode/deepseek-v4-flash-free"' not in launcher:
        findings.append(
            "launcher model is not the reviewed OpenCode DeepSeek V4 Flash catalog entry"
        )
    if 'AGENT="deepseek-worker"' not in launcher:
        findings.append("launcher does not select the bounded deepseek-worker agent")
    return findings


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    findings = verify(root)
    if findings:
        print("Worker-policy verification failed:")
        print("\n".join(findings))
        return 1
    print("Worker-policy verification passed: bounded deny-by-default contract is present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
