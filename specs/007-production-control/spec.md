# BETA-07 Production Control

## Status

BETA-07 implementation is active on `codex/beta-07-production-control`, based on protected main `d4f021aa390d8b0c786ddacb9bda01c71f9c58cc`.

Live production remains disabled. The BETA-06 live Vercel Preview disposition is `VENDOR_BLOCKED`; therefore this phase may reach `IMPLEMENTATION_COMPLETE` but may not claim `LIVE_ACCEPTANCE_COMPLETE`.

## Hard interlock

Every production intent carries `beta06_verified_live_preview`. A production request is denied before provider execution unless the value is exactly `pass`. Approval, owner action, model output, emergency paths, and hidden configuration cannot bypass this check.

## Contract boundary

The implementation provides:

- frozen intent records with exact artifact digest, source revision, rollback reference, idempotency key, backup evidence reference, and opaque credential reference;
- explicit backup, approval, credential-revocation, and emergency-stop gates;
- provider target, artifact, and commit identity verification;
- post-deploy verification with automatic rollback bound to the exact rollback reference;
- duplicate-delivery prevention by intent and idempotency key;
- append-only sanitized transition evidence;
- deterministic no-network provider fixtures for failure injection.

No provider SDK, credential value, production alias, customer data, WordPress resource, or live deployment is used by the fixture implementation.
