# SecurityOla AppCare repository threat model

## Overview

SecurityOla AppCare is intended to scan, back up, monitor, and eventually
remediate supported modern web applications through controlled connectors. The
current BETA-00 tree is an engineering foundation, not a customer-facing
control plane: the primary product package contains only a version marker,
while the meaningful security surfaces are repository policy, CI, worker
configuration, verification scripts, and checkpoint/tooling artifacts.

The model covers the repository and its development workflow. It does not
authorize access to customer applications, provider accounts, production
systems, or the co-hosted WordPress product.

## Threat Model, Trust Boundaries, and Assumptions

### Assets and security objectives

- Source integrity, review history, CI results, and release decisions.
- Connector credentials, customer data, vulnerability evidence, backup data,
  and deployment authority once later beta stages introduce them.
- Worker permission policy, task packets, audit checkpoints, and exact test
  evidence.
- Separation between AppCare and the co-hosted WordPress product.

The required invariants are least privilege, no secrets in repository or
artifacts, deterministic evidence before AI claims, staging before production,
reversible production changes, tenant isolation, and independent Codex review.

### Actors and boundaries

- A repository contributor controls source changes and task text but must not
  gain connector, production, or release authority through a documentation or
  worker-policy change.
- CI executes repository-defined checks in an external runner. CI credentials
  must remain scoped to the checks and must never be copied into artifacts.
- OpenCode runs a model worker over a bounded checkout. The model is
  untrusted: it may receive only the task context needed for a small job, and
  its filesystem, network, shell, Git, and delegation permissions must remain
  deny-by-default outside explicit safe read/test allowances.
- Codex is the coordinator and final reviewer. This is an operator boundary,
  not a reason to trust generated claims without source and test evidence.
- Future provider connectors cross from AppCare into GitHub, Vercel, Supabase,
  and backup services. Those boundaries are deferred until their ordered beta
  stages and require separate credentials, scopes, tenant checks, and failure
  handling.

### Inputs and assumptions

Attacker-controlled or untrusted inputs include pull requests, issue/task
text, repository content consumed by tools, model output, dependency metadata,
CI action references, and provider responses in later stages. Operator- and
developer-controlled inputs include credentials, release approvals, policy
files, deployment configuration, and backup/restore commands.

Assumptions for BETA-00 are that no customer credential is configured in the
checkout, no AppCare production runtime is being changed, and no WordPress
resource is an AppCare dependency. These assumptions must be re-verified at
each later server or connector gate.

## Attack Surface, Mitigations, and Attacker Stories

### Repository and CI

An untrusted contributor could add a secret, weaken a scanner, replace an
action tag, or make a test report success without exercising the intended
control. The current mitigations are public-safety scanning, dependency audit,
secret scanning, pinned CI action commits, exact-head verification, and an
independent final review. CI changes remain security-sensitive and require
review of permissions and changed dependencies.

### Worker task and execution boundary

A malicious task or model response could attempt to read credentials, leave
the checkout, run SSH or deployment commands, mutate Git history, or broaden
the task. The worker agent denies external directories, network fetch/search,
delegation, and unrestricted shell execution; it allows only explicitly listed
read/test commands. The launcher pins the reviewed OpenCode version and model,
and the coordinator checks the policy independently. A real worker smoke and
negative permission test are required before accepting the worker path.

### Tooling and generated artifacts

Checkpoint, graph, specification, and scan artifacts could accidentally retain
secrets, customer evidence, private infrastructure identifiers, or unverified
success claims. The BETA-00 contract keeps transient task/scan artifacts local,
uses sanitized durable documentation, and scans tracked files without printing
matching secret content. Later artifacts must preserve provenance, hashes,
scope, and explicit unknown/deferred states.

### Future application and connector surfaces

When runtime code exists, the highest-risk boundaries will be authentication,
tenant ownership, connector authorization, provider API calls, webhook/event
deduplication, filesystem/archive handling, backup restore, deployment
promotion, rollback, and model-generated remediation. BETA-00 does not claim
those surfaces are implemented or secure; each must receive its own threat
model updates, deterministic tests, failure injection, and review.

Out of scope for this repository model are attacks requiring access that the
current tree does not expose, including real customer projects, provider
accounts, production servers, mail systems, DNS changes, and WordPress
resources. Their exclusion is a scope boundary, not a security assertion.

## Severity Calibration (Critical, High, Medium, Low)

- **Critical:** a verified path from an untrusted repository/worker input to
  broad production takeover, cross-tenant customer data, or irreversible
  destructive action without an approval or rollback boundary.
- **High:** a realistic, independently reachable path to production credentials,
  cross-tenant access, arbitrary code execution in a privileged AppCare worker,
  or destructive deployment/restore behavior with limited containment.
- **Medium:** a source-backed weakness requiring meaningful additional
  conditions, or a material confidentiality/integrity failure constrained to a
  tenant, CI job, staging boundary, or narrowly scoped connector.
- **Low:** limited metadata leakage, weak defense-in-depth, or a constrained
  local/tooling issue with no demonstrated privilege gain or customer impact.

Security observations must include attacker, entry point, trust boundary,
source evidence, counterevidence, impact, likelihood, and remaining proof gaps.
Absence of a runtime implementation lowers confidence in runtime claims; it
does not justify inventing a vulnerability or claiming a clean future system.

Repository: github.com/costavong-pixel/securityola-appcare
Version: BETA-00 final source review; immutable revision is recorded in the sealed scan manifest.
