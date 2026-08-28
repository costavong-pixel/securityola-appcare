# Credential custody contract

## Reference-only application model

AppCare persists an opaque credential_reference and lifecycle metadata:
tenant, application, provider kind, version, issued time, expiry, revocation,
and rotation reference. It never persists the secret.

## Resolver boundary

The resolver is an injected/provider-owned interface. It verifies:

1. reference syntax;
2. tenant/application scope;
3. active and non-expired lifecycle;
4. custody path and owner/mode policy;
5. non-WordPress/non-unrelated-project identity.

Only the private transport adapter can use the resolved runtime handle, and it
must not serialize or log it. A resolver failure is a credential failure, not
an invitation to prompt a model or use a different account.

## Lifecycle

Register creates metadata. Activate makes the reference usable. Expiry and
revocation make it unusable immediately. Rotation revokes the old reference
and registers a new version. No transition copies or prints credential
material.

