# BETA-04 Backup and Restore Boundary

The AppCare BETA-04 domain treats backup health as a verified recovery claim,
not as proof that an object exists. A backup must be encrypted, have a
canonical manifest and artifact checksum, survive read-back verification, and
restore completely into an isolated destination before it can produce positive
controlled-test evidence.

The repository currently contains provider-neutral contracts and safe
destination descriptors for Backblaze B2 and AWS S3 Glacier Deep Archive. It
does not contain provider credentials, raw keys, live cloud SDK calls, or
customer data. Until owner-controlled provider credentials and retention policy
are supplied, the controlled test vault is the only executable destination and
must not be described as live off-site health.

Restore uses staging plus atomic promotion. Interrupted uploads, checksum
mismatches, unavailable/revoked credentials, duplicate jobs, partial restores,
and retention-locked deletion are explicit unhealthy outcomes. Their evidence
is job/recovery evidence, not a vulnerability finding.
