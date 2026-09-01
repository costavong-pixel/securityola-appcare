# AppCare direct DeepSeek worker

`TARGET=AppCare`

This directory contains the service boundary for the direct DeepSeek fallback
lane. It is separate from `scripts/deepseek-worker.sh`, which remains the
OpenCode-routed auxiliary launcher and is not evidence of direct API use.

The direct worker is intentionally a one-shot service. It accepts a sealed
coordinator task packet from the dedicated AppCare checkout, calls only the
fixed `https://api.deepseek.com/chat/completions` endpoint, validates the
structured response, applies it only in a disposable AppCare worktree, runs
the fixed deterministic checks, scans changed files, and writes a sanitized
receipt. It never executes model-provided shell commands or test commands.

## Host layout

The worker host must be the separately verified Prompt Ola VPS. The service
identity is a dedicated non-login account:

```text
appcare-deepseek-worker
```

The service uses these fixed boundaries:

```text
/opt/securityola/appcare-deepseek-worker/repository
/opt/securityola/appcare-deepseek-worker/venv
/var/lib/securityola/appcare-deepseek-worker
/etc/securityola/appcare-deepseek-worker/deepseek-api-key
/etc/securityola/appcare-deepseek-worker/model
```

The API key file is root-owned, group-readable only by the worker service
group, and never printed or copied into the repository. The model file is
root-controlled and contains only a bounded model identifier. Both files are
checked for ownership, permissions, symlinks, size, and changes during read.

The owner must enter or rotate the API key directly on the verified worker
host. It must not be pasted into Codex, a task packet, Git, GitHub, a report,
or a normal log. This repository does not provide a command that accepts a
key as an argument or environment variable.

## Qualification sequence

Run the following as the dedicated service identity from the verified worker
host after the owner has completed the protected file setup:

```text
/opt/securityola/appcare-deepseek-worker/venv/bin/python -I -B /opt/securityola/appcare-deepseek-worker/repository/scripts/direct_deepseek_worker.py check-environment
```

The command reports only `PRESENT` or `ABSENT` for key/model presence. A
successful environment check is not live API proof. Live qualification also
requires a sealed sanitized packet, a successful direct response, receipt
inspection, deterministic tests, secret scan, cleanup, Terra review, Codex
Security, and exact-head CI.

The service unit is a template. Its instance name selects one packet beneath
the repository's `.codex/tasks` directory; the packet validator still checks
the exact branch and base SHA before any API request.

Current maturity after repository merge is `COMPONENT_IMPLEMENTED`. It must
remain below `RUNTIME_INTEGRATED` until the owner-controlled host and API
qualification evidence exists.
