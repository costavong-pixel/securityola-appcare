# Live inventory attestor

`securityola-appcare-live-inventory-attestor.service` is the root-controlled
signing boundary for live Linux inventory receipts. It is intentionally
separate from the AppCare API and worker identities.

The service signs only a canonical receipt message that:

- exactly matches the root-owned target policy;
- references fresh, passed connection and inventory operations from the
  root-owned trusted operation-evidence store;
- binds the expected host identity and every approved root's device/inode;
- uses the exact durable receipt path and evidence reference; and
- has not already been consumed by the root-owned replay ledger.

The operation-evidence file is read-only to the AppCare API. A separate,
approved root-controlled transport boundary must publish sanitized evidence to
it. The attestor must reject every request until that independent evidence
exists; an AppCare caller cannot self-authorize an operation by writing its own
receipt input.

Required root-owned paths are:

- `/etc/securityola/appcare/live-inventory/attestor-policy.json`
- `/etc/securityola/appcare/live-inventory/receipt-signing-private-key`
- `/var/lib/securityola/appcare/evidence/live-inventory/operation-evidence.json`
- `/var/lib/securityola/appcare/evidence/live-inventory/attestor-replay.db`
- `/run/securityola/appcare/live-inventory-attestor.sock`

The private key is 32 raw Ed25519 bytes, mode `0600` or stricter, and is never
read by the AppCare worker. The public key is the existing client verification
path `/etc/securityola/appcare/live-inventory/receipt-signing-public-key`.

The service is Unix-socket-only and uses systemd network/filesystem isolation.
It has no shell or model-command execution path. Do not enable it until the
target policy, independent transport evidence publisher, key pair, public-key
installation, socket peer UID, and exact release approval have been reviewed.
