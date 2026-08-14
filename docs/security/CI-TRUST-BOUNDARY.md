# AppCare CI trust boundary

The AppCare pull_request workflow intentionally runs with a read-only
GITHUB_TOKEN, no checkout credential persistence, and immutable action
commit pins. Those controls limit what untrusted pull-request code can do,
but they do not make a pull-request workflow or its repository-owned checks
trusted release evidence: the workflow file and the scripts it invokes come
from the candidate revision.

## Required GitHub controls

Before accepting a CI result as a merge or release gate, the repository owner
must verify the following settings on the protected main branch:

- require the exact CI / quality status check;
- require review from Code Owners and protect .github/workflows/**,
  scripts/**, dependency lockfiles, and security documentation;
- prevent force-push and branch deletion, require the branch to be current,
  and prevent bypass of the required checks for normal merges;
- keep the Actions default token permission read-only and require maintainer
  approval for untrusted fork workflows;
- restrict workflow execution to approved actors/events when that GitHub
  policy is available.

These settings are external GitHub state and are not asserted by a local
checkout. Codex must record a fresh settings/API observation in the release
evidence before merging a change that modifies a protected path.

## Codex release rule

CI is one evidence source, not the sole security authority. For every
security-sensitive AppCare change Codex must independently inspect the exact
head and complete diff, run the local checks, review the security scan, and
confirm the GitHub controls above. A green status from a candidate workflow
whose trust settings have not been verified is CI_UNTRUSTED, not a release
approval.
