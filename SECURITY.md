# Security Policy

SecurityOla AppCare is security-sensitive software.

## Non-negotiable rules

- No secrets in repository, logs, prompts, or checkpoints.
- No unrestricted root SSH for an AI agent.
- No arbitrary model-generated shell execution in production.
- Least privilege for every connector.
- Back up before any production write.
- Validate in staging or isolation before production.
- Maintain rollback capability for every supported production change.
- Never claim a customer system is completely secure.
- Customer data must not be used for model training without explicit contractual permission.

## BETA-01 control-plane boundary

- Request validation errors return a stable non-sensitive message and never echo
  submitted fields, because rejected fields may contain credential material.
- Tenant-owned reads and writes require an active local identity and are always
  filtered by the authenticated tenant.
- Audit events are sanitized, hash-linked, and database-guarded against update
  and delete operations.
- Connector, backup, approval, and deployment endpoints store descriptive
  development/staging state only. Provider credentials, deployment sockets,
  production write methods, and external provider SDKs remain out of scope.

## Public repository rule

Do not publish customer-specific vulnerabilities, secrets, infrastructure details, exploit evidence, internal credentials, or production access instructions in public issues or commits.
