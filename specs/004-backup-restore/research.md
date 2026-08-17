# BETA-04 Research Notes

## Existing repository evidence

- `appcare.models.operations.Backup` is currently descriptive state and does
  not execute provider writes.
- Existing connector credential records store only opaque references and
  fingerprints; this boundary is reused for backup destination metadata.
- Existing configuration rejects production, WordPress, and shared-server
  database targets in development/test environments.
- No B2/AWS backup SDK or reviewed backup skill is installed in the dedicated
  AppCare environment.

## Decisions

- Do not add a third-party backup skill or cloud SDK during the first slice.
- Use a protocol boundary so B2 and Glacier adapters can be reviewed in a
  later task after credentials and retention policy are authorized.
- Treat a controlled test-vault restore as evidence of the domain workflow,
  not evidence that an off-site provider is configured.
- Keep checksum and encryption verification independent: a valid checksum of
  an encrypted object does not replace decrypt-and-restore verification.
