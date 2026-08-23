# BETA-08 Monitoring, Backup Health, Alerts, and Reports

## Boundary

BETA-08 is provider-neutral and records sanitized evidence references only. It
does not perform network calls, deploy production, read provider credentials, or
mutate customer content.

## Required invariants

- A missing, stale, failed, or integrity-unverified backup is never healthy.
- Monitoring state is append-only and can be replayed after worker restart.
- Alert fingerprints deduplicate repeated observations inside a suppression
  window; resolved incidents are explicitly closed.
- Monthly reports aggregate deterministic observations, findings, fixes, backup
  health, incident transitions, and usage/cost evidence.
- Production remains denied unless `BETA06_VERIFIED_LIVE_PREVIEW == PASS`.

## Acceptance fixtures

The branch must prove outage, dependency, backup, resolution, restart, report
determinism, and cost-accounting behavior without any live provider.
