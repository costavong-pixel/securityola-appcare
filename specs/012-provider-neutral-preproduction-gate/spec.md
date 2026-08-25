# Provider-neutral preproduction gate

AppCare release policy requires `VERIFIED_PREPRODUCTION_ENVIRONMENT=PASS`,
not a provider-specific Preview result. The accepted record is immutable,
tenant/application scoped, exact-head bound, and includes the source revision,
artifact digest, provider and target type, environment identity, deployment
reference and timestamp, smoke/security/rollback receipts, its authoritative
digest, and `status=pass`.

The production controller resolves this record from its durable store using
the exact tenant, application, source revision, artifact digest, and evidence
digest. A caller-supplied boolean, approval, model output, or provider status
cannot substitute for that lookup.

Vercel remains a provider-specific capability profile: read-only and scanning
are supported, Preview is vendor-blocked, and automated production is
disabled. A Vercel status cannot block controlled Linux/AppCare staging or a
future provider adapter.

The controlled reference adapter is loopback-only, uses an AppCare-owned
filesystem target, performs an actual service restart and health check, and
rolls back to a verified exact reference on failure. Monitoring and release
receipts are persisted and replayable after process restart.
