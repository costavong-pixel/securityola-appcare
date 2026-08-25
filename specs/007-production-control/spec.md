# BETA-07 Production Control

## Status

BETA-07 implementation is active on `codex/authoritative-evidence-staging`, based on protected main `daba95a15a02fbbf20997cd584d8ec9613f91267`.

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

## Authoritative evidence and restart durability

The fixture controller may use the tenant-scoped SQLAlchemy deployment store
for runtime-shaped execution. Intent state, approval identity, provider
identity, verification references, rollback references, emergency-stop state,
and revoked opaque credential references survive a controller restart.
Transition evidence is stored as ordered append-only rows and protected by a
database update/delete guard. If a restart finds an in-flight provider phase,
the controller fails closed with `restart_recovery_required` and does not
invoke the provider again; a terminal record is never duplicated.
