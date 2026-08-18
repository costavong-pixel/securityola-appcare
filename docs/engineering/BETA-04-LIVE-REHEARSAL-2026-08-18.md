# BETA-04 Live Non-Production Rehearsal Evidence

**Target:** AppCare only
**Date:** 2026-08-18 UTC
**Data:** unique synthetic test payload only
**Production/customer data:** not used

This is sanitized evidence from one bounded live provider rehearsal. Provider
credentials, access tokens, private keys, environment contents, and raw
customer data are intentionally absent.

## Scope and source evidence

- `scope-check=PASS`
- B2 bucket: `securityola-appcare-beta04-b2-17293167134`
- B2 prefix: `appcare/beta04/rehearsal/`
- AWS bucket: `securityola-appcare-beta04-aws-17293167134`
- AWS prefix: `appcare/beta04/rehearsal/`
- Object ID: `beta04-20260818021431-8cd6f30a`
- Source SHA-256: `2dafdffddebd1416bb8b7d5974e00c5dee751d82f1b3c7fb743a71a7dd719415`
- `SECRETS_EXPOSED=NO`
- `WORDPRESS=UNTOUCHED`

## Sanitized acceptance record

```text
B2_UPLOAD=PASS
B2_READBACK=PASS
B2_CHECKSUM=PASS
B2_OBJECT_LOCK=PASS
B2_RETENTION_UNTIL=2026-08-19T02:26:03+00:00
B2_SIMPLE_DELETE=DELETE_MARKER_CREATED
B2_DELETE_WHILE_LOCKED=DENIED_AS_EXPECTED
B2_VERSION_READ=PASS

GLACIER_ARCHIVE=PASS
GLACIER_STORAGE_CLASS=DEEP_ARCHIVE
GLACIER_CHECKSUM_METADATA=PASS
GLACIER_RETRIEVAL=ASYNC_NOT_REQUESTED

RESTORE_REHEARSAL=PASS
RESTORE_SOURCE=B2
RESTORE_CHECKSUM=PASS
B2_RESTORE_CONTENT=PASS
RPO_EVIDENCE=RECORDED
RTO_MEASURED=1.103 seconds (B2 retained-version retrieval)

FAILURE_HANDLING=PASS_FOR_SAFE_CASES
```

The B2 data version was read back successfully and matched the source
checksum. Its retention metadata was `COMPLIANCE` through the recorded
retention timestamp. A version-specific delete request was denied and the
locked data version remained readable.

## Delete and immutability semantics

The first versionless S3-compatible delete returned success because versioned
B2/S3 semantics create a delete marker; it does not remove the retained data
version. Therefore the wrapper's earlier `UNEXPECTED_DELETE_SUCCESS` label was
not an accurate interpretation of the provider response. The meaningful safe
immutability check is the version-specific delete attempt against the unique
test object's retained data version, which was denied, followed by a
version-specific read that still matched the source.

The version-specific denial is recorded as expected evidence, but its response
was not separately attributed between Object Lock enforcement and the scoped
application-key delete capability. No retention bypass or governance override
was attempted.

## Failure handling

Safe failure behavior was exercised without damaging unrelated resources:

- missing/unavailable B2 object calls failed closed before upload and returned
  sanitized failure states;
- incorrect checksum/corrupted envelope, duplicate component/job, invalid
  restore path, retention-locked deletion, unavailable credentials, and
  staging/atomic-restore failures are covered by the deterministic BETA-04
  unit/integration tests;
- no live Deep Archive retrieval was requested because it is asynchronous;
- no production, WordPress, unrelated bucket, or credential value was
  accessed or logged.

## RPO/RTO boundary

`RPO_EVIDENCE=RECORDED` means that the synthetic source, B2 upload, B2
read-back, archive checksum metadata, and restored content were all tied to the
same object ID and checksum. It is not a customer-facing RPO/SLA measurement.

`RTO_MEASURED=1.103 seconds` is the measured retrieval of the retained B2
version into the isolated test output. It is not a full production service
restore time and does not represent AWS Deep Archive retrieval time.

## Additional rehearsal artifact

An additional synthetic object, `beta04-20260818021537-912b6065`, was created
by an interrupted earlier attempt in the same dedicated B2 test prefix. It was
not used for the accepted rehearsal and is recorded rather than hidden. It is
not an unrelated resource; any cleanup must be a separately verified,
retention-safe operation after the test retention state is known.
