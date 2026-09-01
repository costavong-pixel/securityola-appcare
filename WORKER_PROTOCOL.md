# AppCare Multi-Model Worker Protocol

## Binding documents

This protocol is subordinate to:

- `APPCARE_PRODUCT_IMPLEMENTATION_BLUEPRINT.md`
- `docs/governance/APPCARE_CURRENT_SCOPE.json`
- `docs/governance/APPCARE_MODEL_EXECUTION_ROUTING.md`
- `docs/governance/APPCARE_MODEL_EXECUTION_ROUTING.json`
- `AGENTS.md`
- `.specify/memory/constitution.md`
- `docs/security/PRE_BETA_SECURITY_GATE.md`

## Roles

### GPT-5.6 Luna Max

Owns:

- dependency and architecture plan;
- task decomposition;
- coder-lane routing;
- acceptance criteria;
- scope and path allowlists;
- integration decisions;
- actual diff review;
- trust-boundary function approval;
- readiness and maturity decisions;
- merge recommendation;
- owner-facing report.

### GPT-5.3 Spark

Preferred coder for Luna-approved packets while included Spark quota is available:

- implementation;
- tests;
- bounded debugging;
- documentation attached to implementation;
- review-finding fixes.

Spark does not approve itself, merge, authorize production, alter architecture independently, or promote readiness.

### Direct DeepSeek worker

The mandatory Spark-quota fallback, once runtime-qualified, is:

```text
GPT-5.6 Luna Max coordinator
→ Prompt Ola VPS
→ direct DeepSeek worker
→ owner's DeepSeek API
```

For this route:

```text
CODEX_SPARK_QUOTA_INVOLVED=NO
OPENAI_API_INVOLVED=NO
DEEPSEEK_API_INVOLVED=YES
```

The DeepSeek API credential remains in protected server-side custody. It must not enter chat, Git, GitHub, task packets, normal logs, CI artifacts, evidence, or reports.

Use direct DeepSeek when:

- Spark quota is limited, exhausted, or unavailable;
- Luna intentionally preserves Spark quota for harder integration/debugging;
- the packet is bulk, repetitive, or well-bounded;
- DeepSeek is the cheapest capable coder.

DeepSeek does not approve itself, merge, authorize production, alter architecture independently, or promote readiness.

The existing `scripts/deepseek-worker.sh` currently routes through `opencode/deepseek-v4-flash-free`. It is bounded, but it is not the owner-approved direct DeepSeek API path. The separate `scripts/direct_deepseek_worker.py` component is now `COMPONENT_IMPLEMENTED` with a fixed endpoint, isolated service policy, and deterministic local gates; it is not runtime-qualified or live-verified until the owner completes the server-side credential/model setup and the required host/API evidence is collected.

### GPT-5.6 Terra

Independent architecture/security reviewer:

- privilege and credential design;
- cross-tenant isolation;
- command/path/SQL/scanner injection;
- backup/restore correctness;
- deployment and rollback data-loss risk;
- scheduler and collector threats;
- adversarial test requirements.

Terra does not merge or self-approve fixes it authors.

### Codex Security

Independent scan/verification lane. Security-relevant PRs require the applicable scan; repaired vulnerabilities require verify-fix where appropriate.

### OpenCode/Qwen auxiliary workers

Auxiliary workers remain cheap bounded implementation/test lanes. They never own architecture, credential handling, production access, deployment authority, readiness, or final review.

## Prompt Ola VPS worker boundary

The Prompt Ola VPS is a worker host only for the direct DeepSeek route.

Required:

- dedicated AppCare checkout/worktree;
- dedicated AppCare worker state directory;
- exact base SHA and branch binding;
- sealed sanitized task packet;
- allowlisted writable paths;
- deny-by-default commands/network;
- bounded time/output/resources;
- deterministic scope verification;
- secret scan before promotion;
- temporary-state cleanup.

Forbidden:

- reading or modifying Prompt Ola production files;
- reading or modifying Prompt Ola DBs, services, credentials, logs, deployment paths, or production directories;
- using Prompt Ola secrets for AppCare;
- placing the DeepSeek API key in a task packet or model-visible context.

## One-writer rule

Only one writer may edit a given branch/worktree/file set at a time.

Recommended flow:

```text
Luna freezes task packet
→ Luna selects Spark or direct DeepSeek
→ selected coder receives one write worktree
→ Terra reviews read-only
→ writer fixes findings
→ deterministic scope and secret verification
→ Luna reviews final actual diff
```

Do not run Spark and DeepSeek concurrently against the same files or branch. Do not run competing implementations unless Luna explicitly defines an A/B experiment.

## Mandatory task packet

Every implementation packet must contain:

```text
Phase:
Issue:
Goal:
TARGET=AppCare
Coding lane:
Worker host:
Model provider:
Codex Spark quota involved:
OpenAI API involved:
DeepSeek API involved:
Repository root:
Branch:
Expected base SHA:
Allowed files/paths:
Read-only files/paths:
Do not touch:
Concrete build deliverables:
Acceptance criteria:
Required tests:
Negative/adversarial tests:
Security boundaries:
Maturity before:
Maximum maturity after:
Forbidden commands/capabilities:
Owner-only stop conditions:
```

For the direct DeepSeek lane, the packet metadata must state:

```text
Coding lane=DIRECT_DEEPSEEK
Worker host=PROMPT_OLA_VPS
Model provider=DEEPSEEK_API
Codex Spark quota involved=NO
OpenAI API involved=NO
DeepSeek API involved=YES
```

Broad prompts such as “continue the roadmap” are invalid task packets.

## Engineering and review loop

1. Luna verifies current protected main and active PRs.
2. Luna reads the blueprint, current scope, model routing policy, security gate, and relevant specs.
3. Saveruflo and Graphify are used when available.
4. Luna publishes the dependency-based task packet and chooses Spark or direct DeepSeek.
5. Terra challenges the design before security-critical implementation.
6. The selected coder implements only the approved scope.
7. Deterministic scope and secret scans verify worker output before promotion.
8. Luna reads the actual diff.
9. Terra reads the actual security-sensitive diff.
10. Run deterministic, negative, adversarial, static, dependency, secret, and public-safety gates.
11. Run Codex Security.
12. Fix findings and rerun affected evidence.
13. Require exact-head CI.
14. Merge through protected main only after approvals.
15. Update maturity and capability evidence.
16. Continue only when the phase hard exit permits.

## Hard boundaries

Workers must not:

- access WordPress or WooCommerce implementation;
- access unrelated customer production;
- read `.env` or arbitrary secret files;
- expose credentials;
- use arbitrary SSH/SCP/rsync;
- create arbitrary root/sudo execution;
- run arbitrary SQL;
- run arbitrary scanners;
- deploy;
- commit/push/merge unless the coordinator-controlled GitHub path explicitly assigns that routine repository operation;
- override failed tests;
- approve their own work;
- label reference evidence as live evidence;
- silently route the direct DeepSeek lane through the OpenAI API or Spark quota;
- claim the existing OpenCode-routed launcher is a qualified direct DeepSeek API worker.

## Current worker priority

The current critical-path build begins with:

```text
P01 Blueprint/enforcement
→ P02 Credential custody and SSH onboarding
```

Spec 016 scanning may not displace the credential, baseline, backup, and recovery critical path.

## Direct DeepSeek runtime qualification

Before `DIRECT_DEEPSEEK_LAUNCHER` can advance beyond `COMPONENT_IMPLEMENTED`, AppCare must prove:

- direct DeepSeek API invocation;
- no OpenAI API call;
- no Spark quota consumption;
- server-side API-key custody;
- sealed task packet;
- isolated AppCare worktree on Prompt Ola VPS;
- one-writer enforcement;
- allowlisted writes;
- scope verification;
- secret scan;
- timeout and cleanup;
- Luna actual-diff review;
- Terra security review;
- Codex Security;
- exact-head CI.

Worker summaries are never proof.
