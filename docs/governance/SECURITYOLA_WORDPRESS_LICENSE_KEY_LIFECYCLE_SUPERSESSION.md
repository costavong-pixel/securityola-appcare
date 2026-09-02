# SecurityOla WordPress license-key lifecycle supersession

Status: **OWNER-APPROVED SUPERSESSION**

Recorded: 2026-09-02

This file supersedes the `## Key replacement` subsection in
`docs/governance/SECURITYOLA_OWNER_DECISIONS.md` where that subsection says a
compromised/stolen WordPress license key costs `$25` to replace.

The current owner decision is:

```text
LICENSE_KEY_REPLACEMENT_PRICE=$0
ACTIVE_SITE_LIMIT=1
OLD_LICENSE_KEY_AFTER_ROTATION=REVOKED
```

Until the main owner register is updated, this file has later-date precedence
for the SecurityOla WordPress key-replacement decision.

## Credential model

The customer activation key and the installed site's runtime credentials are
separate:

```text
CUSTOMER_LICENSE_KEY
→ customer-safe activation/recovery credential

SITE_ID + SITE_TOKEN
→ generated after activation
→ installed-site paid API/update authorization
```

The server registration/operator secret is never a customer credential.

Server-side activation-key storage should use a one-way hash or equivalent
non-recoverable verifier rather than ordinary plaintext storage.

## Lost activation key

When the customer has only lost the activation key:

1. verify ownership through the approved recovery flow;
2. revoke the old activation key;
3. issue a new cryptographically random activation key;
4. preserve the current authorized site's `site_id` and `site_token`;
5. reject reuse of the old activation key;
6. keep exactly one active paid site.

```text
OLD_LICENSE_KEY=REVOKED
NEW_LICENSE_KEY=ACTIVE
EXISTING_SITE_CREDENTIALS=ACTIVE
ACTIVE_SITE_COUNT=1
```

## Suspected compromised activation key

When the activation key may be stolen/exposed:

1. verify ownership;
2. revoke the old activation key;
3. issue a new activation key;
4. preserve existing site credentials by default if only the activation key is
   suspected compromised;
5. if site credentials may also be compromised, revoke/rotate those site
   credentials in the same bounded recovery flow.

## Move license to another WordPress site

A site move is stronger than lost-key rotation:

1. verify ownership;
2. revoke the old activation key;
3. revoke the old site's paid `site_id` / `site_token` authorization;
4. issue a new activation key;
5. activate exactly one replacement site;
6. issue new site credentials;
7. enforce one active paid site throughout the transition.

```text
OLD_LICENSE_KEY=REVOKED
OLD_SITE_CREDENTIALS=REVOKED
NEW_LICENSE_KEY=ACTIVE
NEW_SITE_CREDENTIALS=ACTIVE_AFTER_NEW_ACTIVATION
ACTIVE_SITE_COUNT=1
```

## Local-first revocation boundary

Revocation denies paid authorization but must not damage the customer's site.

```text
PRIVATE_PRO_UPDATE_AUTHORIZATION=DENIED_AFTER_SITE_REVOCATION
PAID_CLOUD_API_AUTHORIZATION=DENIED_AFTER_SITE_REVOCATION
LOCAL_SECURITY_FUNCTIONALITY=REMAINS_FUNCTIONAL_WITHIN_PRODUCT_DESIGN
```

Do not remotely delete, corrupt, or disable local security merely because a paid
credential is revoked.

## Payment and support boundary

No Paddle transaction is required for key rotation/replacement.

No `$25` replacement checkout should be implemented or published unless the
owner explicitly changes this decision in a later decision record.

## Implementation accountability

This is a product decision, not implementation proof. Engineering must still
report the real state of:

- customer-safe activation-key issuance;
- one-way key verification;
- old-key revocation;
- site-token rotation;
- one-site move;
- refund/revocation compatibility;
- old-credential denial;
- local-first behavior after paid authorization revocation.

Use `IMPLEMENTATION_GAP`, `PARTIAL`, `IMPLEMENTED_NOT_TESTED`, or
`IMPLEMENTED_AND_TESTED` according to current evidence.
