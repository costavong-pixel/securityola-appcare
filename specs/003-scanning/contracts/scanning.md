# BETA-03 Scanning Contracts

## Adapter contract

Each adapter category implements a bounded read-only operation:

```text
scan(context: ScanContext, input: SanitizedTargetInput) -> AdapterResult
```

`AdapterResult` is exactly one of:

- `observations`: a finite list of untrusted `ScannerObservation` candidates
- `failure`: a `ScannerFailure` with sanitized diagnostic evidence

An adapter MUST NOT write to a target, persist a finding, invoke remediation, or return raw credentials.

Categories:

- `source`: source/configuration patterns and code checks
- `secret`: credential-like material detection using sanitized match metadata
- `dependency`: package/version/advisory checks

## Pipeline contract

```text
adapter result
  → validate
  → enforce tenant/target scope
  → create deterministic sanitized evidence
  → normalize
  → deduplicate by fingerprint
  → assign severity/confidence
  → finding or scanner failure
```

Failures terminate the affected observation path and never become findings.

## Suppression contract

```text
suppress(finding, scope, reason, actor) -> suppressed finding
```

The finding fingerprint and evidence references remain unchanged. The reason and actor are sanitized and scope-checked.

## Public safety contract

The scanning foundation is descriptive-only. It does not expose deployment, delete, write, database mutation, provider authorization, or remediation operations. All fixtures and contract tests are synthetic.
