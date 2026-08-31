# AppCare Model Execution Routing

Status: **MANDATORY PROTECTED-MAIN ROUTING POLICY**  
Owner decision date: 2026-08-30  
Target: `AppCare`

This policy amends the coding-lane selection described by the AppCare implementation blueprint. It does not change Luna's coordinator authority, Terra's independent security role, Codex Security, the one-writer rule, phase dependencies, or production boundaries.

## 1. Routing architecture

```text
GPT-5.6 Luna Max coordinator
        ↓
quota/capability routing decision
        ├── GPT-5.3 Spark, when included Spark quota is available
        │
        └── Prompt Ola VPS
              ↓
            direct DeepSeek worker
              ↓
            owner's DeepSeek API
```

## 2. Binding quota and provider facts

For the **direct DeepSeek fallback path**:

```text
CODEX_SPARK_QUOTA_INVOLVED=NO
OPENAI_API_INVOLVED=NO
DEEPSEEK_API=YES
DEEPSEEK_API_CREDENTIAL=OWNER_PROVIDED_SERVER_SIDE_ONLY
```

The direct DeepSeek worker must not route through Codex Spark or the OpenAI API. It uses the owner's DeepSeek API credential from protected server-side custody.

No credential value may appear in:

- chat;
- Git;
- GitHub issues or pull requests;
- task packets;
- model-visible evidence;
- normal logs;
- CI artifacts;
- test fixtures;
- reports.

## 3. Lane selection

### Preferred lane — GPT-5.3 Spark

Use Spark when its included quota is available and the bounded task is suitable.

Spark remains a coder, not a coordinator or approver.

### Quota fallback — direct DeepSeek worker

Use the direct DeepSeek worker when:

- Spark quota is limited, exhausted, or unavailable;
- Luna wants to preserve Spark quota for harder integration/debugging;
- the task is bulk, repetitive, or well-bounded;
- DeepSeek is the cheapest capable coder for the packet.

DeepSeek is not merely optional documentation. It is the required quota fallback once the direct route is runtime-integrated and security-qualified.

### Independent review lanes

GPT-5.6 Terra remains the independent architecture/security challenger.

Codex Security remains the independent security scan/verification lane.

Neither coder may self-approve, decide readiness, merge independently, authorize production, or widen scope.

## 4. Prompt Ola VPS isolation boundary

The Prompt Ola VPS is a **worker host** for the direct DeepSeek route. It is not permission to modify Prompt Ola production.

Required isolation:

- dedicated AppCare checkout or worktree;
- dedicated AppCare worker state directory;
- dedicated non-production worker identity;
- exact AppCare base SHA and branch binding;
- one writer per branch/worktree;
- sealed sanitized task packet;
- allowlisted writable paths;
- deny-by-default command and network policy;
- bounded time, output, CPU, RAM, and disk where available;
- deterministic scope verification before promotion;
- secret scan before promotion;
- complete cleanup of temporary worker state.

The worker must not modify or read Prompt Ola application files, databases, services, credentials, logs, deployment paths, or production directories.

## 5. AppCare repository workflow

The safe default flow is:

```text
Luna verifies protected main
→ Luna freezes a bounded task packet
→ Luna selects Spark or direct DeepSeek
→ selected coder receives one isolated worktree
→ coder writes only allowlisted files
→ deterministic scope and secret checks
→ Luna reads the actual diff
→ Terra reviews security-sensitive changes
→ tests and security gates
→ Codex Security
→ exact-head CI
→ protected merge
```

Do not run Spark and DeepSeek concurrently against the same files or branch.

A worker summary is never proof. Luna must inspect the actual diff and test evidence.

## 6. Existing launcher status

The current repository launcher:

```text
scripts/deepseek-worker.sh
```

is pinned to:

```text
opencode/deepseek-v4-flash-free
```

That existing launcher is a bounded OpenCode-routed worker path. It does **not** by itself prove the owner-approved direct DeepSeek API route.

Current maturity:

```text
DIRECT_DEEPSEEK_ROUTING_POLICY=DOCUMENTED
DIRECT_DEEPSEEK_LAUNCHER=NOT_RUNTIME_INTEGRATED
DIRECT_DEEPSEEK_LIVE_VERIFICATION=NO
```

Before claiming the direct fallback is runtime-integrated, AppCare must build or safely adapt an audited launcher/provider configuration that:

- calls the DeepSeek API directly;
- reads the API credential only from protected server-side custody;
- makes no OpenAI API call;
- consumes no Spark quota;
- preserves the current sealed-task, isolated-worktree, scope-verification, secret-scan, timeout, and cleanup controls;
- passes deterministic and adversarial tests;
- passes Luna, Terra, Codex Security, and exact-head CI review.

## 7. Failure handling

If Spark quota is unavailable and the direct DeepSeek route is not yet runtime-integrated:

- do not pretend DeepSeek ran;
- do not route through an unapproved provider;
- do not use the OpenAI API as an undisclosed substitute;
- park only the blocked coding packet;
- continue independent planning, review, tests, or GitHub work that does not require that coder;
- report the exact routing blocker.

## 8. Reporting contract

Every delegated coding report must include:

```text
CODING_LANE=SPARK | DIRECT_DEEPSEEK
WORKER_HOST=CODEX_RUNTIME | PROMPT_OLA_VPS
MODEL_PROVIDER=OPENAI_INCLUDED_CODEX | DEEPSEEK_API
CODEX_SPARK_QUOTA_INVOLVED=YES | NO
OPENAI_API_INVOLVED=YES | NO
DEEPSEEK_API_INVOLVED=YES | NO
TASK_PACKET=
BASE_SHA=
BRANCH=
ALLOWED_PATHS=
ACTUAL_DIFF_REVIEWED_BY_LUNA=
TERRA_REVIEW=
CODEX_SECURITY=
CI=
SECRETS_EXPOSED=NO
```

For the direct DeepSeek path, the only valid provider values are:

```text
WORKER_HOST=PROMPT_OLA_VPS
MODEL_PROVIDER=DEEPSEEK_API
CODEX_SPARK_QUOTA_INVOLVED=NO
OPENAI_API_INVOLVED=NO
DEEPSEEK_API_INVOLVED=YES
```

## 9. Amendment rule

This routing policy may change only through:

- an explicit owner decision;
- a protected PR;
- updated machine-readable routing data;
- deterministic governance tests;
- security review;
- exact-head CI.
