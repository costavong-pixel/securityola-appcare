# Implementation Plan: Evidence-Backed Security Scanning Foundation

**Branch**: `codex/beta-03-scanning` | **Date**: 2026-08-17 | **Spec**: [spec.md](spec.md)

## Summary

Implement a provider-neutral, deterministic scanning foundation in `appcare/scanning/`. The pipeline will validate and scope adapter observations, create sanitized evidence, normalize and fingerprint findings, deduplicate repeated observations, and represent scanner failures separately. The first slice uses synthetic fixtures only and performs no remediation or live-provider access.

## Technical Context

- **Language/Version**: Python 3.12+ per the existing AppCare package
- **Existing stack**: FastAPI, Pydantic, pytest, Ruff, mypy, existing tenant-scope and redaction services
- **Storage**: No new database migration in BETA-03; the foundation returns deterministic domain records and remains safe to integrate with later persistence
- **Testing**: pytest unit/integration tests with seeded JSON fixtures; negative cases are mandatory
- **Target**: AppCare only; WordPress and production API remain outside the workspace
- **Constraints**: no raw secrets, no live scanner binaries, no remediation writes, no deployment, and no AI explanation before evidence
- **Routing**: Luna owns architecture and security decisions; DeepSeek V4 Flash is the default implementation worker; Qwen3-Coder-Plus is fallback after repeated difficulty; Terra is read-only escalation only

## Constitution Check

| Principle | Design response | Status |
|---|---|---|
| Security before speed | Validate and scope before adapter execution and persistence; fail closed on malformed or out-of-scope input. | PASS |
| Deterministic evidence before AI claims | Findings require sanitized evidence and stable digest/fingerprint; no AI explanation path exists. | PASS |
| Least privilege and tenant isolation | ScanContext is required at the adapter boundary and for suppression/deduplication. | PASS |
| No secrets in artifacts | Central redaction/credential-like detection is reused; fixtures use synthetic sentinels only. | PASS |
| Staging/backup/reversibility | No production or remediation write is introduced. | PASS |
| AppCare and WordPress remain separate | Paths and task packet explicitly exclude WordPress and `/var/www/api.securityola.com`. | PASS |
| Third-party skills are untrusted | No new external skill or scanner binary is installed. | PASS |
| Codex owns final decisions | Workers receive bounded files; Luna/Codex perform actual-diff, security, and release review. | PASS |
| Exact review and CI evidence | Tests, safety/dependency/security scans, Graphify, Saveruflo, and exact-head CI are required. | PASS |

## Design Decisions

1. **Domain contracts before adapters**: common protocols and immutable records prevent provider-specific results from bypassing validation.
2. **Evidence is first-class**: every accepted observation or scanner failure carries sanitized canonical evidence; findings reference evidence rather than embedding arbitrary scanner payloads.
3. **Failure is not a finding**: adapter failures and invalid outputs use a separate state/result type and cannot receive severity or finding fingerprints.
4. **Stable canonicalization**: deterministic JSON normalization, sorted evidence references, and explicit scope fields drive digest and fingerprint generation.
5. **No persistence dependency yet**: the foundation is pure and testable; later stages can persist records after these contracts stabilize.

## Project Structure

```text
appcare/scanning/
├── __init__.py
├── contracts.py       # adapter protocols and result types
├── models.py          # ScanContext, observations, evidence, findings, failures
├── canonical.py       # sanitized canonical serialization, digest, fingerprint
├── scope.py           # tenant/target validation
├── pipeline.py        # validate → scope → evidence → normalize → dedupe
├── adapters.py        # source/secret/dependency adapter boundary helpers
└── suppression.py     # evidence-preserving scoped suppression
tests/fixtures/scanning/
├── vulnerable.json
├── duplicate.json
├── false_positive.json
├── malformed.json
├── out_of_scope.json
└── scanner_failure.json
```

## Verification Strategy

- Unit-test canonicalization, digests, fingerprints, scope checks, redaction, normalization, deduplication, suppression, and failure separation.
- Integration-test each adapter category and the end-to-end pipeline with seeded fixtures.
- Add negative tests for cross-tenant/cross-target submissions, malformed results, unsupported severities, secret-like payloads, and scanner failures.
- Run full existing tests plus Ruff, mypy, public-safety, worker-policy, build-lock, pip-audit, Codex Security, independent Luna review, Graphify, Saveruflo checkpoint, and exact-head CI.

## Risks and Mitigations

- **Overly broad canonicalization**: keep field allowlists explicit and test order/representation variants.
- **False-positive suppression hiding evidence**: suppression changes active status only; evidence and reason remain required.
- **Adapter failure ambiguity**: make failure states structurally distinct and assert zero findings in every failure fixture.
- **Boundary drift**: reuse existing tenant-scope primitives and add cross-tenant negative tests at every public entry point.
