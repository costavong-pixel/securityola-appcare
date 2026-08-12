# Shared-server isolation audit

This public artifact intentionally omits the server address, private paths, account names, database names, and process identifiers. The detailed read-only evidence is machine-local and sanitized before checkpointing.

## Target declaration

Every server operation in this audit used `TARGET=AppCare`. No WordPress-targeted operation was authorized.

## Verified boundaries

- The owner-provided VPS is shared by AppCare and the SecurityOla WordPress product.
- The existing Nginx/API route, WordPress staging tree, WordPress database, PHP workers, DockPanel control-plane services, and their credentials are pre-existing resources and are explicitly DO NOT TOUCH for AppCare.
- BETA-00 created only a dedicated nologin AppCare service identity and empty root-controlled AppCare namespace directories. No AppCare service, database/user, queue, worker, backup job, deployment, or production runtime was created.
- A similarly named empty directory was not treated as an AppCare runtime; no ownership was inferred from its name.
- No AppCare DNS, TLS, Nginx, systemd, Docker, database, service, or production resource was created or changed.

## Required BETA-01 gate

Before control-plane implementation or any server deployment, Codex must establish separate AppCare development, staging, and production identities, paths, databases, secrets, queues, logs, backup namespaces, and deployment configuration. The design must prove non-reuse of every WordPress resource listed above.
