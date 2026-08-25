# BETA-10: Adversarial beta gate and release decision

## Goal

Do not declare the AppCare private beta ready until deterministic evidence covers the required failure modes and the hard BETA-06 live Preview interlock passes.

## Release contract

- Release evidence is immutable, sanitized, and hashed deterministically.
- Required evidence includes exact-head CI, tests, tenant isolation, backup/restore, production verification rollback, operator stop, customer report accuracy, dependency/secret scans, pricing/margin review, and published limitations.
- All named adversarial drills must be present and passed.
- Any Codex Security finding blocks readiness.
- beta06_live_preview must be exactly pass; blocked and unverified are release blockers.
- The decision always reports live_production_enabled=false.

## Controlled fixtures

The initial BETA-10 fixture suite is provider-neutral and makes no network or production calls. It covers seeded secret exposure, vulnerable dependency, tenant isolation, failed/corrupted backups, isolated restore, worker crash, duplicate event, Preview failure, production verification rollback, revoked connector, alert storm deduplication, and unsafe AI patch rejection.

Fixture PASS is not live acceptance. Current repository evidence must still carry the BETA-06 provider result, which is vendor-blocked.

## Acceptance

- A complete all-pass fixture evidence set becomes ready only when BETA-06 live Preview is pass.
- The exact current BETA-06 evidence (blocked) produces status=blocked with BETA06_LIVE_PREVIEW_REQUIRED.
- Missing or failed drills produce a blocked decision.
- Evidence digest and public decision output are deterministic and credential-free.
- No provider, production, WordPress, or customer resource is accessed.

Release evidence is accepted as authoritative only when it includes passed,
sanitized receipts for every named release criterion: exact-head CI, tests,
Codex Security, Graphify, Saveruflo, isolated staging rehearsal, tenant
isolation, backup/restore, production rollback, operator stop, customer report
accuracy, dependency scan, secret scan, pricing/margin review, and published
limitations. Every receipt carries the same exact Git head as the release
evidence; missing, failed, or stale receipts are release blockers even when
the older boolean summary fields are green.
