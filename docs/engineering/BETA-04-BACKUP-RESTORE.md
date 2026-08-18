# BETA-04 Backup and Restore Boundary

The AppCare BETA-04 domain treats backup health as a verified recovery claim,
not as proof that an object exists. A backup must be encrypted, have a
canonical manifest and artifact checksum, survive read-back verification, and
restore completely into an isolated destination before it can produce positive
controlled-test evidence.

The repository contains provider-neutral contracts and safe destination
descriptors for Backblaze B2 and AWS S3 Glacier Deep Archive. It does not
contain provider credentials, raw keys, live cloud SDK calls, or customer data.
The live provider boundary is an AppCare-only, locked execution wrapper outside
the repository. Its sanitized non-production rehearsal evidence is recorded in
[BETA-04-LIVE-REHEARSAL-2026-08-18.md](BETA-04-LIVE-REHEARSAL-2026-08-18.md);
that evidence must not be generalized to customer-production readiness.

Restore uses staging plus atomic promotion. Interrupted uploads, checksum
mismatches, unavailable/revoked credentials, duplicate jobs, partial restores,
and retention-locked deletion are explicit unhealthy outcomes. Their evidence
is job/recovery evidence, not a vulnerability finding.

Restore and isolated test-vault roots are canonicalized before use; symlink
crossings, unsafe backup path segments, and pre-existing staging directories
fail closed. The filesystem test vault reconstructs persisted manifests and
encrypted envelopes after reopen so read-back evidence is not limited to one
process's memory.

The customer-paid archive rationale and the distinction between an AWS-native
S3 lifecycle transition and a cross-provider B2-to-AWS archive copy are
documented in [BETA-04-CUSTOMER-ARCHIVE-RETENTION.md](BETA-04-CUSTOMER-ARCHIVE-RETENTION.md).
