# Third-party skill decisions

The project does not treat a registry listing or model recommendation as an acceptance decision.

| Capability | BETA-00 decision | Reason and next gate |
| --- | --- | --- |
| Codex Security workflows | Accepted for repository-scoped evidence review | Local skill source was inspected; the BETA-00 standard scan finalized offline with no reportable findings and explicit deferred runtime coverage. |
| Saveruflo | Accepted | Local skill self-tests pass 13/13; launcher defaults remain dry-run/disabled until each task is explicitly packeted. |
| Graphify | Accepted | Local package `0.9.32` produced and diagnosed the initial graph; generated caches stay out of Git. |
| Spec Kit | Accepted at pinned `0.11.3` | Official bundled templates were initialized; the CLI `init` wrapper hung twice, so the verified local package API performed the same bounded scaffold without network access. |
| Spec Kit task-to-issues extension | Dropped | It can publish repository-controlled task text as GitHub issues; it is unnecessary for BETA-00 and is not accepted without a separate owner-approved, public-safety-checked publication workflow. |
| OpenCode | Accepted at pinned `1.18.16`, worker smoke pending | Official upstream release/tag and package integrity were verified. The exact catalog model `opencode/deepseek-v4-flash-free` resolves, static/negative permission tests pass, and the live provider has returned rate-limit responses before a complete smoke. |
| Supabase skills | Deferred, not installed | BETA-02/BETA-03 will inspect official Supabase material and implement least-privilege connector checks; no customer credentials are needed for BETA-00. |
| Vercel skills | Deferred, not installed after BETA-06 audit | The repository has no accepted Vercel skill or live credential boundary. BETA-06 uses an AppCare-owned fixture preview and a fail-closed unapproved adapter; preview/promotion/rollback behavior remains a separately reviewed provider gate. |
| Database/cloud-backup skills | Accepted for BETA-04 provider boundary | The live rehearsal used an AppCare-only AWS CLI boundary for B2 and S3 Deep Archive; raw credentials stayed outside OpenCode and Git. |
| LangGraph | Accepted at pinned `1.2.9` with PostgreSQL checkpoint `3.1.2` | Official persistence/interrupt/fault-tolerance contracts were reviewed; strict serializer setup, AppCare PostgreSQL scope validation, and failure-injection tests are required by BETA-05. |
| Impeccable | Deferred, not installed | Introduced only after functional dashboard/site flows in BETA-09. |

No candidate in the deferred list is authorized to access production, credentials, customer data, or the WordPress application.
