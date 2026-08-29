# AppCare Multi-Model Worker Protocol

## Binding documents

This protocol is subordinate to:

- `APPCARE_PRODUCT_IMPLEMENTATION_BLUEPRINT.md`
- `docs/governance/APPCARE_CURRENT_SCOPE.json`
- `AGENTS.md`
- `.specify/memory/constitution.md`
- `docs/security/PRE_BETA_SECURITY_GATE.md`

## Roles

### GPT-5.6 Luna Max

Owns:

- dependency and architecture plan;
- task decomposition;
- acceptance criteria;
- scope and path allowlists;
- integration decisions;
- actual diff review;
- trust-boundary function approval;
- readiness and maturity decisions;
- merge recommendation;
- owner-facing report.

### GPT-5.3 Spark

Primary coder for Luna-approved packets:

- implementation;
- tests;
- bounded debugging;
- documentation attached to implementation;
- review-finding fixes.

Spark does not approve itself, merge, authorize production, alter architecture independently, or promote readiness.

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

### OpenCode/DeepSeek/Qwen auxiliary workers

Auxiliary workers remain cheap bounded implementation/test lanes. They never own architecture, credential handling, production access, deployment authority, readiness, or final review.

The existing audited `scripts/deepseek-worker.sh` and deny-by-default OS sandbox remain available for qualified auxiliary tasks.

## One-writer rule

Only one writer may edit a given branch/worktree/file set at a time.

Recommended flow:

```text
Luna freezes task packet
→ Spark or auxiliary worker receives write worktree
→ Terra reviews read-only
→ writer fixes findings
→ Luna reviews final actual diff
```

Do not run competing implementations unless Luna explicitly defines an A/B experiment.

## Mandatory task packet

Every implementation packet must contain:

```text
Phase:
Issue:
Goal:
TARGET=AppCare
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

Broad prompts such as “continue the roadmap” are invalid task packets.

## Engineering and review loop

1. Luna verifies current protected main and active PRs.
2. Luna reads the blueprint, current scope, security gate, and relevant specs.
3. Saveruflo and Graphify are used when available.
4. Luna publishes the dependency-based task packet.
5. Terra challenges the design before security-critical implementation.
6. Spark or an auxiliary worker implements only the approved scope.
7. Luna reads the actual diff.
8. Terra reads the actual security-sensitive diff.
9. Run deterministic, negative, adversarial, static, dependency, secret, and public-safety gates.
10. Run Codex Security.
11. Fix findings and rerun affected evidence.
12. Require exact-head CI.
13. Merge through protected main only after approvals.
14. Update maturity and capability evidence.
15. Continue only when the phase hard exit permits.

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
- label reference evidence as live evidence.

## Current worker priority

The current critical-path build begins with:

```text
P01 Blueprint/enforcement
→ P02 Credential custody and SSH onboarding
```

Spec 016 scanning may not displace the credential, baseline, backup, and recovery critical path.

## Auxiliary DeepSeek sandbox

The existing bounded DeepSeek launcher remains pinned to its audited OpenCode/model policy. Any pin or policy change requires separate review and exact-head CI. Auxiliary worker summaries are never proof; Luna must inspect the diff and tests.
