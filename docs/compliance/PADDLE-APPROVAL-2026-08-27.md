# SecurityOla Paddle Approval Record — 2026-08-27

**TARGET=WordPress Security / shared SecurityOla public website**

Status: **Paddle Live domain review remains `action_required`**. No real Paddle transaction has been created. The public-site deployment and existing checkout integration were technically healthy at the time of this record.

This file is the permanent, public-safe record of the Paddle review findings, the BarndAI comparison, owner-approved remediation decisions, deployment acceptance criteria, and the boundary between payment/commercial compliance work and deeper security review.

> Public-repository rule: do not add production filesystem paths, IP addresses, credentials, API secrets, customer vulnerability evidence, private Paddle account data, or production-access instructions to this document.

## 1. Known deployment state before the compliance patch

The deployment report supplied on 2026-08-27 recorded:

- `securityola.com`: HTTP 200.
- Public legal routes: HTTP 200.
- `pay.securityola.com`: HTTP 200.
- Paddle.js: preserved and loading.
- Public client configuration: preserved.
- `_ptxn` checkout handling: preserved.
- TLS: PASS.
- Responsive CSS/viewport check: PASS.
- Public secret scan: PASS.
- `api.securityola.com/v1/health`: HTTP 200.
- Production API changed: NO.
- Paddle Live domain review: submitted, `action_required`.
- Real Paddle transaction created: NO.

These facts show that the known blocker is Paddle Live domain approval, not a known outage in Paddle.js, TLS, the API health endpoint, or the existing public checkout plumbing.

## 2. Current Paddle domain-review requirements

Authoritative source checked 2026-08-27:

- Paddle Domain Review: https://www.paddle.com/help/start/account-verification/what-is-domain-verification
- Paddle Acceptable Use Policy guidance: https://www.paddle.com/help/start/intro-to-paddle/what-am-i-not-allowed-to-sell-on-paddle
- Paddle Refund Policy: https://www.paddle.com/legal/refund-policy

Paddle currently requires the website/domain review surface to make the following easy to locate:

1. Clear description of the product or service.
2. Pricing details or pricing page.
3. Key features/deliverables included with purchase.
4. Terms and Conditions.
5. Refund Policy.
6. Privacy Policy.
7. Company name or sole proprietor brand in the Terms.
8. Live HTTPS site.
9. Custom/enterprise pricing information if applicable.

Paddle states that each domain/subdomain from which checkout is launched should be submitted for review, and a subdomain may require separate approval even when the root domain is approved.

Paddle also states that a rejected/soft-declined domain commonly falls into one of these categories:

- the product appears inconsistent with Paddle's Acceptable Use Policy;
- the domain is flagged as high risk or potentially inconsistent with Paddle terms; or
- Paddle requested more information and has not received it.

Additional manual-review evidence may include product ownership, reseller rights, test access, or processing history.

## 3. Acceptable Use Policy issue relevant to SecurityOla

As of Paddle's 13 April 2026 AUP update, relevant categories include:

- technical-support software/services marketed to repair, maintain, or improve the performance or security of an electronic device (restricted category);
- system-health products, including antivirus (prohibited category);
- software that enables unauthorized access to third-party data (prohibited category).

SecurityOla's intended product boundary is different: **WordPress website security software operating on sites the customer owns, administers, or is authorized to secure.**

The product must therefore be described truthfully and consistently so it is not mistaken for endpoint antivirus, device-repair software, remote-access technical support, unauthorized-access tooling, or a managed incident-response service.

This is a classification/positioning requirement. It does **not** authorize removal or concealment of actual product capabilities and must never be used to make a misleading claim to Paddle or customers.

## 4. Why BarndAI is the useful control case

BarndAI has already passed Paddle domain review and provides a useful same-owner/same-market comparison.

Public BarndAI material reviewed around this decision used cautious WordPress-specific positioning such as:

- simple/local-first WordPress security reports/checks;
- suspicious-file and integrity review;
- findings are warnings and are not automatic proof of malware;
- no automatic file deletion;
- not a guaranteed malware remover;
- not a full firewall;
- not a replacement for professional incident response, backups, server security, or a managed security service.

Public references:

- https://barndai.com/
- https://www.barndai.com/download.html

The key lesson is not that every BarndAI sentence should be copied. The lesson is that Paddle has already accepted a WordPress security product when its website makes the product boundary and limitations clear.

BarndAI approval does **not** guarantee SecurityOla approval. SecurityOla has stronger/different capabilities and must be reviewed on its own facts.

## 5. Most likely reasons SecurityOla received `action_required`

### High confidence: product-classification wording

The public SecurityOla homepage used the prominent phrase:

`Malware & backdoor scanning`

That phrase can make a WordPress security tool look closer to Paddle's endpoint-antivirus/system-health categories when evaluated by automated or manual risk review.

Owner-approved replacement positioning:

`Suspicious code & integrity scanning`

Preferred supporting text:

`Bounded checks for suspicious PHP, uploads, database content, options, pages and other high-signal WordPress conditions.`

This preserves the real capability while describing the WordPress-specific function more accurately.

### High confidence: checkout context/domain architecture

`pay.securityola.com` is a checkout-focused subdomain. Paddle's own domain-review rules require product description, price, features and legal policies to be easy to locate, and subdomains used for checkout are reviewed independently.

Owner decision: make the canonical checkout part of the complete product website at:

`https://securityola.com/buy`

Then submit/review `securityola.com` as the primary Paddle domain.

`pay.securityola.com` remains operational as a compatibility/fallback path until the root-domain checkout is approved and a separate retirement/redirect decision is validated.

### Medium confidence: refund/chargeback-risk presentation

The previous SecurityOla policy treated activated digital purchases as generally final. This may be legally permissible in many cases, but a narrow final-sale presentation provides less customer assurance than the already accepted BarndAI model.

Owner decision: add a seller-provided 14-day product assurance for the initial purchase when SecurityOla materially does not work as described and reasonable support cannot resolve the problem, while preserving all mandatory Paddle/consumer rights.

Paddle's own refund policy states that non-waivable local rights and any additional rights offered by the supplier apply. It also provides jurisdiction-specific withdrawal periods and a discretionary refund process. The SecurityOla policy must never attempt to reduce mandatory Paddle or consumer rights.

## 6. Owner-approved public positioning

The following decisions were approved on 2026-08-27.

### Product category

Use:

`WordPress website security software`

Avoid using the following as primary marketing/category labels:

- antivirus;
- system health;
- device security;
- computer repair;
- remote repair;
- guaranteed malware remover.

SecurityOla may truthfully explain that suspicious patterns can indicate malicious code or backdoors where technically appropriate; the key requirement is that the product category remains clearly WordPress website security rather than endpoint/device antivirus.

### Purpose/boundary copy

Preferred public explanation:

`SecurityOla focuses on WordPress detection, integrity, evidence, review, reporting, verified updates and controlled recovery. It is designed for WordPress sites you own or are authorized to administer. It does not access or repair personal computers, phones or other end-user devices, and it does not provide remote-access technical support.`

### Checkout description

Preferred `/buy` description:

`SecurityOla Pro is WordPress website security software for site owners, freelancers and small agencies. It checks WordPress files, integrity, configuration, database conditions and suspicious code patterns and presents findings for review. It operates only on WordPress sites you own or are authorized to administer; it does not access or repair personal computers, phones or other end-user devices and does not provide remote-access technical support.`

Relationship statement:

`Developed and distributed as a BarndAI product.`

Do not invent a corporate legal entity name. If an exact legal entity is later added, it must match verified owner/Paddle records.

## 7. Canonical checkout decision

Primary purchase path:

`https://securityola.com/buy`

Requirements:

- visually match the working SecurityOla checkout experience;
- preserve the existing Paddle.js implementation;
- preserve the existing public client configuration;
- preserve the existing Paddle environment configuration;
- preserve existing product/price mapping;
- preserve `_ptxn` handling;
- preserve Terms, Privacy, Refund and Support links;
- preserve the current price/entitlement facts unless separately changed by the owner;
- do not open a live checkout before the applicable Paddle domain is approved;
- do not create a real transaction as part of domain-approval validation.

All primary SecurityOla purchase CTAs should point to `/buy` once the route is validated.

## 8. Refund-policy decision

Add an initial-purchase assurance substantially equivalent to:

### 14-day product assurance

`For the initial purchase of a SecurityOla license, you may request a refund within 14 calendar days of purchase if SecurityOla materially does not work as described and we cannot resolve the problem through reasonable support. This assurance is in addition to any mandatory consumer or Paddle buyer rights that apply.`

Renewal clarification:

`The 14-day product assurance applies to the initial purchase. Automatic subscription renewals are governed by the renewal, cancellation, Paddle buyer and mandatory-law terms applicable to that transaction.`

Post-assurance wording:

`After the applicable 14-day product-assurance period, and outside mandatory buyer rights, billing errors, duplicate charges or material failure to provide purchased access, digital-software purchases are generally final. We may approve an additional discretionary refund where circumstances reasonably justify it.`

If pricing/billing later changes from one-time to subscription or adds additional plans, the refund text must be reviewed again before publishing.

## 9. Terms/product-scope decision

Preferred Terms description:

`SecurityOla is WordPress website security software. It provides suspicious-code and security-condition scanning, integrity monitoring, findings and review controls, reporting, scheduled checks, private update verification, diagnostics and related WordPress functionality. SecurityOla is designed for WordPress websites that the customer owns, administers or is authorized to secure. It is not designed to provide endpoint protection for personal computers, phones or other end-user devices, remote-access technical support, computer repair, VPN services, or managed incident response.`

This text is a product-scope statement, not a security warranty.

## 10. Product-ownership statement for manual Paddle review

If Paddle asks for a concise product-ownership/category explanation, use a truthful statement substantially equivalent to:

`SecurityOla is developed and distributed as a BarndAI product. It is WordPress security software intended for websites the customer owns, administers or is authorized to secure. It is not a resale of endpoint antivirus, remote computer-repair software or remote-access technical-support services.`

Do not state that every component is proprietary or original; open-source/third-party dependencies may be part of the product.

If Paddle asks for ownership evidence, provide only the minimum appropriate evidence through the Paddle/private support channel, not this public repository.

## 11. Deployment acceptance criteria for the compliance patch

Before resubmitting to Paddle, all of the following must be verified from the deployed public site:

- `securityola.com/` → HTTP 200.
- `securityola.com/buy` → HTTP 200.
- `securityola.com/terms` → HTTP 200.
- `securityola.com/privacy` → HTTP 200.
- `securityola.com/refund` → HTTP 200.
- `securityola.com/support` → HTTP 200.
- legacy `pay.securityola.com/` remains HTTP 200 or has an intentionally validated compatibility redirect.
- Paddle.js is present on `/buy`.
- required public client configuration is available.
- `_ptxn` handling is preserved without generating a live transaction.
- primary SecurityOla purchase CTAs resolve to `/buy`.
- 14-day product assurance is visible and internally consistent.
- public marketing metadata does not categorize SecurityOla as antivirus/system-health/device-repair software.
- responsive/viewport validation passes.
- TLS validation passes.
- public secret scan passes.
- `api.securityola.com/v1/health` remains HTTP 200.
- production API is unchanged by this marketing/checkout deployment.
- real transaction created: NO.

## 12. Paddle resubmission gate

Do not resubmit until the deployed site meets the acceptance criteria above.

Preferred review target:

`securityola.com`

Preferred checkout location:

`https://securityola.com/buy`

Because Paddle reviews checkout-launching domains/subdomains, confirm the domain being submitted exactly matches the domain from which Paddle Checkout will launch.

If the dashboard still reports `action_required`, check the Paddle-account email/review message for the requested information. The domain status itself is not a substitute for the reviewer's written reason.

If Paddle requests further clarification, reply with facts and product boundaries; do not remove or conceal real capabilities merely to obtain approval.

## 13. Separation from the security-assurance track

Paddle approval answers a commercial/risk/compliance question. It does **not** prove that SecurityOla is secure.

The following must remain independent:

- payment-domain approval;
- payment integration security;
- API/application security;
- WordPress plugin/update trust;
- tenant/site authorization;
- scan/remediation safety;
- secret/key management;
- backup/recovery safety;
- supply-chain security;
- privacy/data handling;
- incident response and monitoring.

The active backlog is maintained in:

`docs/security/WORDPRESS-SECURITY-REVIEW-BACKLOG.md`

## 14. Decision log

### 2026-08-27

- Confirmed deployed public site/legal routes and checkout were technically healthy from supplied deployment evidence.
- Paddle Live domain status remained `action_required`.
- Confirmed no real Paddle transaction had been created.
- Compared SecurityOla with Paddle-approved BarndAI positioning.
- Reclassified the legal-name concern as low priority because Paddle permits company name or sole-proprietor brand in Terms; exact legal entity remains preferable when verified.
- Identified product-classification wording and checkout-domain context as the leading remediation targets.
- Approved safer but truthful WordPress-specific marketing language.
- Approved canonical checkout migration to `securityola.com/buy` while preserving the legacy pay subdomain during transition.
- Approved 14-day initial-purchase product assurance.
- Approved preservation of Paddle.js, client configuration, `_ptxn`, product/price binding and existing checkout safety controls.
- Confirmed the production API must remain unchanged by the public-site compliance patch.
- Created a separate security-review backlog so Paddle work is never treated as a security sign-off.

## 15. Update rule

After each Paddle submission/review or security milestone, append a dated entry to this file rather than overwriting history.

For each update record:

- domain submitted;
- Paddle state;
- reviewer request (sanitized; no private account data);
- public changes made;
- test evidence summary;
- API changed YES/NO;
- real transaction created YES/NO;
- next blocker/gate.
