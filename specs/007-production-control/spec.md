# BETA-07 Production Control

## Status

BETA-07 implementation is provider-neutral and runs only against an explicitly
controlled target environment.

Live customer production remains disabled. Vercel Preview is a provider-specific
capability and may be vendor-blocked without blocking a controlled AppCare
preproduction environment.

## Hard interlock

Every production intent carries an exact digest reference to persisted
`PreproductionEvidence`. A production request is denied before provider
execution unless the authoritative record matches tenant, application, source
revision, artifact digest, and status `pass`. Approval, owner action, model
output, emergency paths, and hidden configuration cannot bypass this check.

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
