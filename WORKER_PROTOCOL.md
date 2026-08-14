# Codex + OpenCode/DeepSeek Worker Protocol

## Roles

### Codex
Owns:
- architecture and product decisions
- security boundaries and threat-model decisions
- task decomposition
- acceptance criteria
- dependency approval
- third-party skill acceptance/rejection
- production/deployment authorization logic
- review of every DeepSeek diff
- merge/release decisions

### OpenCode + DeepSeek V4 Flash
Used for cheap, bounded work such as:
- scaffolding already specified by Codex
- repetitive implementation
- unit/integration test writing
- documentation updates
- mechanical refactors with existing tests
- first-pass bug fixes after Codex identifies the root cause
- local pressure-test harnesses that do not require production access

DeepSeek does not make architecture, security, product, deployment, or release decisions.

### Codex CLI final gate
Before an issue is closed or a change is merged/released, Codex CLI independently reviews the complete diff and test evidence against:
- the GitHub issue acceptance criteria
- `AGENTS.md`
- `SECURITY.md`
- `ARCHITECTURE.md`
- `BETA_LOOP.md`

Security-sensitive changes also receive the applicable Codex Security scan/validation workflow.

## Delegation loop

1. Codex chooses the current BETA issue.
2. Codex performs Saveruflo preflight and Graphify impact review.
3. Codex creates a small task packet under `.codex/tasks/`.
4. `scripts/deepseek-worker.sh` validates the packet for secrets/private data,
   exact `TARGET=AppCare`, repository root, branch, HEAD, allowed paths,
   forbidden capabilities, and WordPress exclusion. It requires the packet to
   resolve to a regular file inside the checkout's own `.codex/tasks/` directory.
5. The launcher requires a clean coordinator checkout, creates a disposable
   Git worktree, generates a task-specific deny-by-default policy, and snapshots
   the worktree before the worker runs. It never gives the worker the
   coordinator's ignored files or credentials and discards the disposable
   worktree after the run.
6. Run `scripts/deepseek-worker.sh .codex/tasks/<task>.md`.
7. On Linux, the worker runs non-root through the AppCare OS sandbox with
   dropped capabilities, hidden home/runtime/deployment trees, provider state
   mounted read-only, and a bounded timeout. Worker-produced files must pass
   the approved redacted secret scan before promotion.
8. The launcher verifies the post-run isolated worktree against the packet's
   pre-run allowed paths and expected branch/HEAD before promoting permitted changes.
9. DeepSeek may edit test files inside the AppCare worktree, but Codex owns
   test execution and evaluates the resulting evidence independently.
10. Codex inspects the diff. Never accept the worker summary as proof.
11. If wrong: Codex narrows/corrects the task and sends another bounded worker pass.
12. Maximum three DeepSeek repair passes on the same defect. After that Codex takes over the fix/root-cause analysis.
13. Codex runs the full deterministic gate and security/failure tests.
14. Codex CLI performs the final independent review.
15. Only after all gates pass may Codex commit/push/close the issue according to the repository workflow.

## Worker task packet

Every task packet must contain:

```text
Issue:
Goal:
TARGET=AppCare
Repository root: .
Branch: <current non-detached branch>
HEAD: <current full Git SHA>
Allowed files/paths:
Read-only files/paths:        # optional
Do not touch:
Acceptance criteria:
Required tests:
Known context/evidence:
Forbidden commands/capabilities:
Stop conditions:
```

Do not send the worker the full project history when a small task packet is sufficient. This is the main token-saving mechanism.

## Hard boundaries

DeepSeek/OpenCode must not:
- access the WordPress SecurityOla environment
- access customer production
- read `.env`/secret files
- use SSH/SCP/rsync
- run deployment or infrastructure commands
- commit/push/merge
- install or upgrade dependencies without explicit Codex approval
- override failed tests
- approve its own work

## OpenCode pin

Audited bootstrap pin: **OpenCode 1.18.16**.

The launcher refuses another OpenCode version until Codex intentionally reviews and updates the pin.

## Model

Low-cost worker: **DeepSeek V4 Flash** (`opencode/deepseek-v4-flash-free`), the exact model ID exposed by the audited OpenCode catalog.

Credentials are configured on the machine through OpenCode `/connect`; never commit API keys to this repository.
