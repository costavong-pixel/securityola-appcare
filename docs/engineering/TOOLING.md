# AppCare engineering tooling

All versions below are the versions verified for this BETA-00 checkout. A newer upstream version is not adopted without a separate audit and pin update.

| Capability | Verified version/revision | Source and boundary |
| --- | --- | --- |
| Saveruflo | Installed user skill; 13/13 self-tests | Local audited skill; worker launch remains explicit and bounded |
| Graphify | `0.9.32` | `graphifyy` package; generated graph output remains local/ignored |
| Spec Kit | `0.11.3`, tag `7d71d25b5f265389484ed5a41f2aea8cdafe5453` | `github/spec-kit`; bundled templates used without an online fetch |
| Codex CLI | `0.147.0-alpha.6.6` | Local OpenAI CLI; independent final review only |
| OpenCode | `1.18.16`, tag `a3647eb025c7615159d417dcc49fc39fdaeba65b` | `anomalyco/opencode`; npm package integrity verified before installation; worker runs in a disposable Git worktree |
| Worker model | `deepseek/deepseek-v4-flash` | Selected only by the bounded project launcher |
| pip | `26.2.1` | Pinned in `requirements-dev.txt`; CI does not perform an unpinned upgrade |
| Ruff | `0.16.2` | User-local `uv` tool; pinned in `requirements-dev.txt` |
| mypy | `2.3.0` | User-local `uv` tool; pinned in `requirements-dev.txt` |
| pytest | `9.1.1` | Existing verified Python tool; pinned in `requirements-dev.txt` |
| pip-audit | `2.10.1` | User-local `uv` tool; pinned in `requirements-dev.txt` |

The reproducible CI tool set is resolved into `requirements-dev.lock` with
package hashes. CI installs and audits that lock with `--require-hashes`; the
short requirements file remains the human-maintained input to the resolver.

## CI action pins

These are immutable commit pins resolved from the official action repositories:

- `actions/checkout` v4: `11d5960a326750d5838078e36cf38b85af677262`
- `actions/setup-python` v5: `a26af69be951a213d495a4c3e4e4022e16d87065`
- `gitleaks/gitleaks-action` v2.3.9: `ff98106e4c7b2bc287b24eaf42907196329070c7`

## Deferred capability decisions

LangGraph, Supabase, Vercel, backup/storage, monitoring, and visual-QA capabilities are intentionally not installed in BETA-00. They are reviewed at their ordered beta gate using official upstream material first, then AppCare-owned wrappers where a third-party skill cannot meet the permission and rollback contract.
