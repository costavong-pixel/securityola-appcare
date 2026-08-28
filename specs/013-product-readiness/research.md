# Research: Why Core Beta Evidence Did Not Prove Customer Readiness

## Finding 1 — The original specs intentionally bounded live behavior

The connector, scanning, backup, remediation, production-control, monitoring, and adversarial-gate slices were deliberately designed around fixtures, injected adapters, controlled reference targets, or no-network execution for safety. Those choices were correct for subsystem development but insufficient as a final customer-service acceptance definition.

## Finding 2 — The missing boundary is customer integration

Real pilot discovery exposed that ordinary customer applications require live transport, filesystem/database capture, brownfield revisioning, staging, deployment, rollback, monitoring collectors, and scheduling. The existing core contracts can govern these capabilities but cannot substitute for them.

## Finding 3 — Readiness must be layered

A green core-platform release can coexist with red stack/customer readiness. A single global readiness label loses this distinction and therefore creates false confidence.

## Finding 4 — Supportability must be deterministic

A real application must be resolved against a mandatory capability matrix. `UNSUPPORTED` should mean a genuine unsupported boundary, while legacy direct-filesystem sites that AppCare can safely normalize should normally be `NEEDS_CLEANUP`.

## Finding 5 — Real-target evidence is a separate evidence class

Reference/test evidence remains valuable, but final customer-readiness requirements must explicitly demand real-target evidence so an internal test cannot accidentally satisfy a live service gate.

## Decision

Adopt layered readiness, capability matrices, evidence classes, automatic downgrade rules, a mandatory pre-beta security gate, and a real-target end-to-end gate before private beta is considered customer-ready.
