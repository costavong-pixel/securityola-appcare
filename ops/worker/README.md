# AppCare direct DeepSeek worker

`TARGET=AppCare`

This directory contains the service boundary for the direct DeepSeek fallback
lane. It is separate from `scripts/deepseek-worker.sh`, which remains the
OpenCode-routed auxiliary launcher and is not evidence of direct API use.

The direct route is intentionally split into two one-shot services. The API
service accepts a sealed coordinator task packet, calls only the fixed
`https://api.deepseek.com/chat/completions` endpoint, validates the structured
response, and writes a normalized completion artifact. It never applies a
patch or runs model-controlled code. The apply service runs as a separate
identity with no API-key access and no network; it reads only that normalized
artifact, applies the patch in a disposable local clone, runs fixed
deterministic checks, scans changed files, and writes a sanitized receipt. It
never executes model-provided shell commands or test commands.

## Host layout

The worker host must be the separately verified Prompt Ola VPS. The service
identity is a dedicated non-login account:

```text
appcare-deepseek-worker
```

The API request service uses a separate non-login account:

```text
appcare-deepseek-api
```

The service uses these fixed boundaries:

```text
/opt/securityola/appcare-deepseek-worker/repository
/opt/securityola/appcare-deepseek-worker/venv
/var/lib/securityola/appcare-deepseek-worker
/etc/securityola/appcare-deepseek-worker/deepseek-api-key
/etc/securityola/appcare-deepseek-worker/model
```

The state root is root-owned and group-accessible only to the dedicated worker
group. Its `requests/` directory is group-readable/writable by the API and
worker identities; `runs/` and `results/` are worker-controlled. The API key
file is root-owned and readable only by the `appcare-deepseek-api` group. The
model file is root-controlled and readable by the worker group. Both files
are checked for ownership, permissions, symlinks, size, and changes during
read. The apply identity cannot read the API-key file.

The owner must enter or rotate the API key directly on the verified worker
host. It must not be pasted into Codex, a task packet, Git, GitHub, a report,
or a normal log. This repository does not provide a command that accepts a
key as an argument or environment variable.

## Qualification sequence

Run the following as the API service identity from the verified worker host
after the owner has completed the protected file setup:

```text
/opt/securityola/appcare-deepseek-worker/venv/bin/python -I -B /opt/securityola/appcare-deepseek-worker/repository/scripts/direct_deepseek_worker.py check-environment --role api
```

The command reports only `PRESENT` or `ABSENT` for key/model presence. The
apply identity can be checked without touching the key:

```text
/opt/securityola/appcare-deepseek-worker/venv/bin/python -I -B /opt/securityola/appcare-deepseek-worker/repository/scripts/direct_deepseek_worker.py check-environment --role worker
```

A successful environment check is not live API proof. Live qualification also
requires a sealed sanitized packet, a successful direct response, receipt
inspection, deterministic tests, secret scan, cleanup, Terra review, Codex
Security, and exact-head CI.

The normal execution order is:

```text
systemctl start securityola-appcare-deepseek-api@<32-hex-run-id>.service
systemctl start securityola-appcare-deepseek-worker@<32-hex-run-id>.service
```

The worker unit requires the matching API unit. The API unit exits before the
apply unit starts, so model-controlled tests cannot share a process with the
API client or its credential.

The service unit is a template. Its instance name selects one packet beneath
the repository's `.codex/tasks` directory; the packet validator still checks
the exact branch and base SHA before any API request.

Current maturity after repository merge is `COMPONENT_IMPLEMENTED`. It must
remain below `RUNTIME_INTEGRATED` until the owner-controlled host and API
qualification evidence exists.
