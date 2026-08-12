# SecurityOla AppCare Constitution

## Core principles

### I. Security before speed
AppCare is security-sensitive software. The smallest safe, reversible change is preferred, and no convenience may weaken a trust boundary, tenant boundary, approval gate, or rollback path.

### II. Deterministic evidence before AI claims
Scanner output, worker summaries, model explanations, and generated plans are hypotheses until deterministic tests, source evidence, and independent verification support them. Never report a success state that was not actually observed.

### III. Least privilege and tenant isolation
Every connector, service, worker, database role, environment, and deployment identity receives only the permissions required for its bounded task. Tenant ownership and authorization are enforced by code and tested with cross-tenant negative cases.

### IV. No secrets in artifacts
Credentials, customer data, private infrastructure details, vulnerable-customer evidence, and secret values must not appear in source, logs, prompts, worker packets, checkpoints, tests, issues, or public reports. Presence-only checks and sanitized identifiers are used instead.

### V. Staging, backup, and reversibility before production
Production writes require preserved evidence, a valid backup or snapshot, isolated reproduction, automated validation, explicit policy approval, a known rollback target, and post-change verification. Development and staging never receive production credentials.

### VI. AppCare and WordPress remain separate
AppCare and the SecurityOla WordPress product share no application path, service identity, database, schema, secrets, queues, workers, writable volumes, deployment credentials, logs, backup namespace, or production route. Server actions must explicitly declare `TARGET=AppCare` or `TARGET=WordPress Security`; this project uses only `TARGET=AppCare`.

### VII. Third-party skills are untrusted
A candidate skill is discoverable material until its upstream source, revision, dependencies, permissions, secret handling, sandbox behavior, failure behavior, and regression tests are reviewed. Unsafe or unmaintainable candidates are dropped in favor of AppCare-owned wrappers.

### VIII. Codex owns final decisions
Codex owns architecture, threat-model scope, security policy, dependency and skill acceptance, deployment logic, merge/release decisions, and final verification. OpenCode/DeepSeek may perform only bounded, non-live implementation tasks and may not approve its own work.

### IX. Exact review and CI evidence is required
Every beta issue closes only after the complete diff, dependency changes, Graphify impact, deterministic tests, security/failure tests, secret scan, independent Codex CLI review, exact-head GitHub Actions result, and sanitized Saveruflo checkpoint are recorded.

## Scope and workflow

The product queue is GitHub issue #12 in strict order from BETA-00 through BETA-10. Each issue follows:

`Saveruflo preflight → Graphify query/update → constitution/specify/clarify/plan/checklist/tasks/analyze as needed → bounded implementation → deterministic/security/failure tests → independent review → exact-head CI → checkpoint → Graphify impact review`.

The initial supported stack is GitHub, Vercel, Supabase, and Lovable-generated or similar modern web applications. LangGraph and visual QA are introduced only at their ordered beta stages. No customer production system is touched during BETA-00.

## Governance

This constitution, `AGENTS.md`, `SECURITY.md`, `ARCHITECTURE.md`, `WORKER_PROTOCOL.md`, and the current beta issue are jointly binding. Conflicts are resolved in favor of the stricter security boundary and the explicit user instruction. Any amendment records the reason, affected workflow, tests, and new version before implementation relies on it.

**Version**: 1.0.0 | **Ratified**: 2026-08-12 | **Last Amended**: 2026-08-12
