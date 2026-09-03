<!-- SPDX-License-Identifier: Apache-2.0 -->
# v0.16 release-assurance boundary — the merge-process rows

**Owner ruling of 2026-09-03.** Layer 2: a decision about what this release's assurance
closure depends on. It records a disposition; it establishes no theorem.

## The criterion

The release candidate is acceptable only if

```
all authoritative v0.16 assurance evidence
    derives from
maintainer-controlled repository history  +  trusted final release-candidate execution
```

## R9-C025 / R9-C055 — measured against that criterion

`R9-C025` is that the fork-PR guard is an `if:` in `.github/workflows/verification.yml`,
a file a fork pull request's own merge ref supplies. `R9-C055` is that the guard is
complete against RCE only by yielding a **skipped job**, and a skipped job reports success.

Both are true. The question this ruling answers is narrower and is the only one the release
turns on: **does any authoritative v0.16 evidence depend on a fork-controlled result?**

Measured on 2026-09-03 over every merged pull request in the repository's history:

| measurement | result |
|---|---|
| merged PRs whose head repository is not `matssun/mcp-re` | **0** |
| distinct head-repository owners across all merged PRs | `matssun` only |
| PR authors | `matssun`, `app/dependabot` |
| dependabot head branches | `dependabot/*` **inside** the repository, so same-repo |

Every commit reachable from `main` therefore entered through a branch in the maintainer's
own repository and was merged by the maintainer. No fork has ever produced a verification
result, and the guard is the reason: for a fork PR the condition is false, the job is
skipped, and it produces nothing that any attestation reads.

**Conclusion: no v0.16 authoritative evidence depends on a fork-controlled lane.** The
criterion holds, and neither row is a release blocker.

## What is NOT claimed

**Fork-PR verification integrity is not claimed.** The two rows describe a real
merge-process weakness and they stay open:

* a fork PR that edited the guard would be running its own workflow definition, because
  `pull_request` resolves the workflow from the merge ref;
* the skipped job still reports success, so there is no fork-safe lane whose green means a
  measurement happened.

They are recorded as a **post-v0.16 merge-process integrity gap**. The control that
actually holds either of them is Actions settings — fork-PR approval for outside
contributors, and not offering self-hosted runners to fork PRs — which is repository
configuration and is not readable from the tree. `scripts/merge_path_gate.py` already
states that limit in general form.

`pull_request_target` is explicitly NOT adopted. It would execute untrusted code with the
repository's token on the self-hosted host that holds the pinned toolchains and the
operator's cloud credentials — trading a reporting weakness for a compromise path, to turn
a row green.

## Re-measurement

This disposition rests on the table above, which is a fact about repository history at a
date. It must be re-measured before any release that accepts a pull request from a fork, or
that grants an outside contributor push access.
