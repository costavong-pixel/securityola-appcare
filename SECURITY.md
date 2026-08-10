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

## Public repository rule

Do not publish customer-specific vulnerabilities, secrets, infrastructure details, exploit evidence, internal credentials, or production access instructions in public issues or commits.
