# SecurityOla Owner Decision Register

Status: owner-approved product/business decisions. This file is intentionally separate from implementation evidence.

## How to use this file

Every decision below must be tracked independently as:

- `DECIDED` — owner approved the rule.
- `DOCUMENTED` — recorded in repo documentation.
- `IMPLEMENTED` — code/runtime actually supports it.
- `TESTED` — deterministic evidence proves the behavior.

**Do not treat `DECIDED` or `DOCUMENTED` as proof of implementation.** If code/runtime does not support a documented rule, report `IMPLEMENTATION_GAP`. Do not advertise an unimplemented behavior as a live customer guarantee.

---

# 1. SecurityOla commercial structure

Canonical public product family:

- **SecurityOla WordPress** — self-service WordPress security plugin.
- **SecurityOla AppCare** — managed service, not another plugin and not customer-operated native software installed on the customer's site.
- **SecurityOla Emergency** — professional incident assessment and recovery service.

Primary public navigation:

`WordPress | AppCare | Emergency | Pricing | Support`

---

# 2. SecurityOla WordPress commercial policy

## Current launch offer

- Price: **$99 one-time**.
- License scope: **1 WordPress site**.
- One active license key per licensed site.
- Lifetime plugin use.
- Lifetime plugin updates.
- No recurring renewal required for continued plugin use or updates.
- Support is limited to SecurityOla product support and is provided subject to SecurityOla's reasonable assessment/discretion.

Included support may cover:

- license activation problems,
- SecurityOla installation/configuration problems,
- confirmed SecurityOla bugs,
- SecurityOla update/compatibility issues,
- reasonable questions about SecurityOla findings/features.

Not included as ordinary WordPress-plugin support:

- general WordPress troubleshooting,
- unrelated third-party plugin/theme repair,
- hosting/server administration,
- custom development,
- malware cleanup/recovery,
- unrelated website problems.

## Key replacement

- A compromised/stolen key may be replaced for **$25**.
- Issuing a replacement key must deactivate the previous key.
- Key sharing/reuse across sites is not authorized.

## Voluntary refund policy

- **14-day voluntary refund window**, in addition to mandatory Paddle/local consumer rights.
- Abuse, fraud, key sharing, or misuse may disqualify a voluntary refund to the extent legally permitted.
- A refunded license key is deactivated.

## Pricing flexibility

- Publicly show the current **$99 launch price only**.
- Do not publish speculative future WordPress price steps.
- Future new-customer pricing may change according to market conditions.
- Rights attached to completed purchases remain governed by the offer/terms applicable to that purchase.

---

# 3. AppCare commercial policy

## Price and scope

- **$149/month per approved supported application**.
- AppCare is a managed service.
- It is not unlimited development.
- Tier 3 engineering involvement is included while work remains inside normal bounded AppCare scope.
- Additional cost requires owner/customer approval before work begins.

Separately quoted/out-of-scope examples include:

- major architecture changes,
- large feature rewrites,
- complex/major data reconstruction,
- unsupported infrastructure,
- formal or complex forensic investigation,
- incidents that cannot be safely bounded.

## Cancellation

- Customer may cancel at any time.
- Service continues until the end of the already-paid billing period.
- No further renewal is charged after cancellation takes effect.
- At service end, SecurityOla provides one downloadable copy of the latest successful AppCare backup/snapshot at no extra charge.
- SecurityOla retains one final backup copy for **30 days** after service ends, then automatically deletes it.

---

# 4. AppCare backup policy

- Preferred onboarding access: a dedicated **least-privilege AppCare account/key** rather than shared owner/root credentials.
- Normal backup scope: application files + database + necessary application configuration.
- Backups are stored off-site.
- Backup frequency is risk/application based, with **daily as the minimum standard**.
- Active-service backup history: **rolling 30 days**.
- Every backup must be checked for successful completion and readability.
- AppCare performs a **monthly restore test**.
- A backup is not considered healthy merely because a backup job reports success.

---

# 5. AppCare AI support/operations model

AppCare is intended to be AI-operated rather than human-support-hours based.

## Tier model

### Tier 1

- AI agent follows approved playbooks for known issues.
- Handles routine diagnosis and approved remediation.

### Tier 2

- Specialist AI handles issues Tier 1 cannot solve from the current playbook.
- Tier 2 may diagnose, design and execute a new **bounded, reversible** fix.
- The fix must be validated.
- If validation fails, use the approved rollback path.

### Tier 3

- Engineering AI handles complex technical issues Tier 2 cannot safely resolve.
- Owner is not the technical Tier 3.

## Owner/customer escalation boundary

The owner/customer is contacted for a **decision**, not routine technical troubleshooting.

Escalation is required when proceeding would involve a business-sensitive or authorization-sensitive decision such as:

- meaningful downtime,
- material data-loss risk,
- additional cost,
- customer/contract impact,
- security-policy change outside the approved scope,
- unsupported architecture,
- irreversible action.

If a required decision-maker does not respond:

- keep the application in the safest approved reversible containment state,
- continue monitoring,
- continue notifications,
- do not cross the authorization boundary.

---

# 6. Playbook governance

- Tier 1 uses approved playbooks.
- A Tier 2 solution does **not** automatically become a Tier 1 playbook action after one successful run.
- Tier 2 must record diagnosis, fix, validation evidence, failure conditions and rollback path.
- Routine new playbook entries require **Manager approval** before Tier 1 may automate them.
- Supervisor review is additionally required for higher-risk/security-sensitive entries.

Supervisor review is mandatory for playbook entries involving any of:

- database writes/deletes,
- authentication/permission changes,
- firewall/security-policy changes,
- backup deletion/restoration,
- production deployment changes,
- credential/key rotation,
- customer-data exposure risk,
- downtime risk,
- irreversible actions.

## Automated fixes

Agents may execute **pre-approved, bounded, reversible fixes**.

Every automated fix must have:

- evidence/reason for action,
- defined success criteria,
- post-fix validation,
- rollback behavior if validation fails,
- audit logging.

---

# 7. Critical incidents and emergency containment

A Critical incident includes events such as:

- confirmed active compromise/backdoor,
- credible customer-data exposure/exfiltration risk,
- administrator/account takeover,
- production outage caused by security/operational failure,
- backup/recovery failure leaving no known usable recovery point,
- ransomware/destructive activity,
- widespread unauthorized production changes,
- Tier 2 reaching a condition where continuing safely requires an owner/customer decision.

For an active Critical incident:

- agents may execute an **already-approved emergency containment playbook immediately** without waiting for owner/customer approval,
- containment must be bounded and reversible,
- customer/owner is notified promptly,
- anything beyond the approved containment boundary still requires escalation.

If approved containment later proves unnecessary or causes service impact:

- the agent may automatically roll back when predefined approved rollback criteria are met,
- the rollback path itself must already be tested/approved,
- containment, rollback trigger, validation and final state must be logged.

---

# 8. AppCare customer authorization model

During onboarding:

- customer designates one **primary authorized decision-maker** and at least one **backup authorized decision-maker**,
- customer selects/approves a recommended **Standard Protection** preset,
- customer can enable/disable individual pre-approved action categories,
- the customer must explicitly confirm the selected authorization scope before AppCare automation uses it.

Agents may automate only actions that are both:

1. inside an approved playbook, and
2. inside the customer's current authorization scope.

Only designated authorized decision-makers may change the automation scope.

Customers may later change that scope through the portal; changes must be auditable and agents must respect the current scope.

---

# 9. Notifications and reporting

## Incident notifications

- Critical incidents: notify promptly.
- Customer-decision-required events: notify promptly.
- Routine successful fixes: include in normal reporting instead of alerting the customer for every routine action.

## Reporting cadence

- **Weekly summary**: concise status, monitoring results, routine fixes, backup health, notable changes, items requiring attention.
- **Monthly full report**: incidents, fixes, validation results, backup/restore-test status, unresolved risks and recommendations.
- Delivery: email summary + downloadable full report from the customer portal.

## Report retention

- Reports remain available in the portal for the entire active subscription.
- After cancellation, report access remains available for **30 days**.

---

# 10. Security activity audit policy

Security activity should be visible to authorized decision-makers and exportable as **CSV and JSON** with secrets/tokens/credentials redacted.

Security events include, where implemented:

- login success/failure,
- optional-2FA success/failure,
- session invalidation,
- lockout/security alerts,
- recovery actions,
- permission-scope changes,
- session revocation,
- security-log export.

Security activity retention:

- entire active subscription,
- **12 months after cancellation**,
- then delete or irreversibly anonymize.

Full public IP may be visible to authorized decision-makers for security investigation purposes, subject to the same retention policy and applicable privacy requirements.

Existing audit infrastructure is not proof that every event above is already recorded or exposed in the portal.

---

# 11. Authentication policy — current owner clarification

This section supersedes any earlier draft wording that treated authenticator-app 2FA as mandatory for every customer.

## Default login

- **Regular password login is valid and supported.**
- SecurityOla must not require authenticator-app 2FA merely because the user has an AppCare account.

## Optional authenticator-app 2FA

- Authenticator-app TOTP 2FA is **optional and customer-selected**.
- If the customer enables TOTP, it may be used as an additional factor for that account.
- If the customer does not enable TOTP, ordinary authenticated customer flows must remain usable through the normal login model.
- Do not use SMS as the planned TOTP replacement.

## Password policy philosophy

- **No forced periodic password changes.**
- Password reuse is not prohibited by an artificial password-history rule.
- Use proportionate standard protections such as secure password hashing, sensible session handling, brute-force/rate-limit controls and audit logging.
- Do not impose bank-grade friction without a demonstrated product/security need.

## Important supersession note

Any earlier draft requirement that said re-authentication **must always include 2FA** is superseded. If an account has not opted into 2FA, the product must not dead-end that customer solely because TOTP is absent.

Stricter session/IP/recovery controls discussed during design are **not evidence of implementation** and must be verified against product usability before being advertised or relied upon.

---

# 12. Emergency service commercial policy

## Emergency Assessment

- Price: **$199**.
- Assessment determines the incident scope, blast radius, recovery options and whether the case fits bounded recovery.
- Assessment does not guarantee recovery.

## Standard bounded recovery

- Public starting total: **from $999 total**.
- If SecurityOla accepts the incident into a qualifying standard bounded recovery, the paid **$199 assessment is credited**.
- For a qualifying $999 engagement, **$800 remains** after applying the assessment credit.
- Do not represent qualifying bounded recovery as `$999 + $199`.
- Complex/unbounded cases are separately quoted.

Standard bounded recovery may apply when the assessment establishes a controlled recovery path, such as one primarily affected supported application, bounded blast radius, viable backup/repair path, reversible changes and meaningful post-recovery validation.

Complex/unbounded examples may include multiple compromised systems, root/cloud compromise, ransomware, major data exfiltration, major reconstruction, formal forensics or unsupported infrastructure.

---

# 13. Implementation-accountability rule

For every owner decision in this file, engineering/Codex must report one of:

- `IMPLEMENTED_AND_TESTED`
- `IMPLEMENTED_NOT_TESTED`
- `PARTIAL`
- `IMPLEMENTATION_GAP`
- `NOT_APPLICABLE`

No website page, pricing page, onboarding flow, Terms/Privacy/DPA, support documentation or sales material should turn an `IMPLEMENTATION_GAP` into a live operational guarantee.

When implementation intentionally differs from an owner decision, the difference must be returned to the owner for a new decision instead of silently changing the policy.
