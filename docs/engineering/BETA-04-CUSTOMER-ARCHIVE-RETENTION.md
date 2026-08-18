# BETA-04 Customer-Paid Archive Retention Rationale

**Target:** AppCare only
**Status:** Target product and engineering rationale; not proof of customer-production readiness

## Why AppCare needs an AWS account

AppCare needs a dedicated AWS account or account-owned resource boundary when
the archive-snapshot capability becomes a customer offering. The account
provides:

- a separate billing and ownership boundary for customer-paid archive storage;
- a dedicated IAM identity restricted to the AppCare archive bucket and prefix;
- an independent provider failure domain from the recent-backup provider;
- S3 lifecycle, storage-class, retention, audit, and restore evidence; and
- a place to keep archive-provider credentials outside OpenCode and outside the
  repository.

The AWS account, bucket, IAM identity, and archive namespace must remain
AppCare-only. They must not be shared with WordPress Security, the production
API, unrelated buckets, or customer environments outside the approved scope.

## Intended customer value

The product hypothesis is an optional paid archive-snapshot capability:

1. AppCare creates verified daily backups in the recent-backup tier.
2. A customer who purchases archive retention receives a verified archive
   snapshot covering the agreed 30-day window.
3. The archive copy is retained and recoverable according to the paid plan's
   documented retention, restore-time, and pricing terms.

The 30-day wording must be finalized as either a retention period, an archive
delivery window, or both. Price, SLA, RPO, RTO, retrieval charges, and legal
retention terms are product decisions and are not implied by this document.

## Storage-path distinction

“Move to Amazon S3 after 30 days” has two materially different meanings. The
implementation must choose one explicitly:

### AWS-native lifecycle

Daily backups are written to an ordinary S3 bucket and remain in a recent S3
storage class. An S3 Lifecycle rule transitions eligible objects to the
`DEEP_ARCHIVE` storage class after the configured age. This is an AWS-to-AWS
storage-class transition and does not require a second AWS bucket.

### Cross-provider archive copy

Daily backups remain in Backblaze B2, and AppCare later copies a verified
snapshot to an AWS S3 bucket using the `DEEP_ARCHIVE` storage class. This is a
cross-provider transfer and requires an AppCare-controlled scheduled archive
job with source read permission, destination write permission, checksum
verification, idempotency, and auditable evidence. An S3 Lifecycle rule alone
cannot pull objects from B2.

The current BETA-04 live rehearsal deliberately exercises both provider
boundaries with synthetic data: B2 is the immediate immutable restore source,
and AWS S3/Deep Archive is the archive-provider verification path. That
rehearsal does not claim that the production 30-day transfer or billing flow
has been implemented. The sanitized result is recorded in
[BETA-04-LIVE-REHEARSAL-2026-08-18.md](BETA-04-LIVE-REHEARSAL-2026-08-18.md).

## Cost and retention guardrail

S3 Glacier Deep Archive is an archive storage class, not an instant-restore
tier. AWS currently documents a 180-day minimum storage duration for Deep
Archive objects. A customer-facing 30-day plan may therefore incur charges
beyond the visible 30-day window and must be priced and disclosed accordingly.
The product must not promise “30 days for 30 days of storage cost” without a
current AWS pricing review.

Reference: [AWS S3 Glacier storage classes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/glacier-storage-classes.html).

## Security boundary

- Provider credentials are entered through the locked AppCare BETA-04
  execution boundary and are never stored in OpenCode `auth.json`.
- Repository files, prompts, checkpoints, logs, and test output contain no raw
  cloud credentials or customer backup data.
- The first live rehearsal uses only unique AppCare-owned non-production test
  data.
- B2 Object Lock and AWS archive metadata are verified before evidence is
  reported as positive.
- No remediation writes, production restore, WordPress access, or production
  API access is part of this rationale.

## Decision required before production implementation

Before offering this to customers, AppCare must record:

- the selected AWS-native or cross-provider path;
- what the 30-day window means operationally;
- archive transition timing and retention behavior;
- Deep Archive minimum-duration and retrieval-cost treatment;
- customer-visible RPO/RTO and restore workflow; and
- the exact account, bucket, prefix, IAM, audit, and deletion policy.
