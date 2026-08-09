# Version bump — what has to move, in what order, and what proves it

`VERSION` is not just a label. It is the **image tag** every deploy artefact names, so a
bump that lands unevenly does not fail at build time — it fails as `ImagePullBackOff` on a
cluster that is already billing, after `gcloud builds submit` has run. That is the failure
this document exists to prevent, and `scripts/deploy_image_tag_gate.py` is the gate that
catches it.

Run `scripts/bump_version.sh <new-version>` rather than editing by hand. This document
says what it does and why, so the gate output is readable when something drifts.

This covers the MECHANICS only. Whether the project is ready to release at all —
licensing, claim wording, conformance evidence, security review — is
[`docs/RELEASE_CHECKLIST.md`](../RELEASE_CHECKLIST.md).

## What carries a version

| surface | file(s) | moves with a bump? |
| --- | --- | --- |
| the canonical version | `VERSION` | **yes** — the single source |
| Rust workspace | `Cargo.toml` (`[workspace.package] version`) | **yes** |
| Rust crates | 12 × `*/Cargo.toml` with a literal `version = ` | **yes** |
| image tags | `deploy/cloudbuild/mcp-re-images.yaml` | **yes** |
| k8s manifests | `deploy/k8s/*.yaml` | **yes** |
| Helm **appVersion** | `deploy/helm/mcp-re-proxy/Chart.yaml` | **yes** — it names the image |
| Helm **chart version** | `deploy/helm/mcp-re-proxy/Chart.yaml` | **only if the chart changed** |
| changelog | `CHANGELOG.md` | **yes** |
| Bazel lock | `MODULE.bazel.lock` | **yes** — it hashes every `Cargo.toml` |
| Python SDK | `sdk/python/pyproject.toml` | **no** — independent cadence |
| TypeScript SDK | `sdk/typescript/package.json` | **no** — independent cadence |

Three of these are routinely got wrong:

* **`MODULE.bazel.lock` records a content hash of every `Cargo.toml`**, so a bump
  invalidates all twelve of them. Nothing fails when it is left stale: Bazel's default
  lockfile mode is `update`, so the next `bazel` invocation silently rewrites the file and
  leaves the tree dirty, and whoever notices it days later reads it as unrelated noise.
  v0.15.0 shipped this way — the lock in git predated its own version bump. Stage 3 of
  `local_gate.sh` regenerates it; commit what it produces.

* **Chart version vs appVersion.** `appVersion` names the image and tracks `VERSION`. The
  chart's own `version` is the chart's semver and moves only when the templates change. A
  bump that moves both in lockstep makes the chart version meaningless; a bump that moves
  neither ships a chart pointing at an image tag that does not exist.
* **The SDKs are NOT the proxy.** They version independently (currently 0.1.x against the
  proxy's 0.14.x) because they are published to PyPI/npm on their own cadence and their
  compatibility surface is the wire profile, not the proxy build. Bumping them in sympathy
  publishes a release with no changes in it.

## Order

1. **Land the work first.** A bump is not a change; it names one. Every functional commit
   should already be merged, and the tree clean.
2. **`scripts/bump_version.sh <new-version>`** — rewrites `VERSION`, the workspace and
   crate versions, the deploy surface and `Chart.yaml`'s `appVersion`. It refuses a
   non-semver argument, refuses a version that is not greater than the current one, and
   refuses to run on a dirty tree.
3. **Write the CHANGELOG entry.** By hand — this is the one part that is judgement, not
   substitution. Say what changed for a reader deciding whether to upgrade, not what the
   commits were.
4. **Bump the Helm chart version** *only* if `deploy/helm/` changed in this release.
5. **`scripts/local_gate.sh --with-kind`** — the full battery. Stage 1 runs the image-tag
   gate; stage 5 deploys the chart against freshly built images, which is what proves the
   tag actually resolves.
6. **Commit the regenerated `MODULE.bazel.lock`.** Stage 3 rewrites it because the crate
   `Cargo.toml` hashes it records all moved. Leaving it out is invisible until someone
   diffs the tree in an unrelated branch.
7. **Commit, PR, merge.** Tag the release commit on `main`.

## Choosing the number

Pre-1.0, so the middle number carries the weight:

* **minor** (`0.15.0` → `0.16.0`) — behaviour a deployment can notice: a changed default,
  a new flag, a serving-path change, a new refusal. Most releases here.
* **patch** (`0.15.0` → `0.15.1`) — fixes with no configuration or behavioural surface.
* A **default change is a minor bump even when the code change is small.** ADR-MCPRE-051
  §1's runtime topology is the worked example: a few lines, but every deployment gets a
  different thread layout on upgrade.

## What the gates check, and what they do not

`scripts/deploy_image_tag_gate.py` (stage 1) asserts that every literal `mcp-re-*:<semver>`
across `deploy/`, `docs/security/` and `tools/` equals `VERSION`. When it fires, the fix is
usually **not** to retype the number — it is to read the tag from `VERSION` at run time,
which the harnesses do (`BENCH_TAG="$(cat VERSION)"`).

It does **not** check:

* that the images were actually built and pushed at that tag — only `gcloud builds submit`
  does that, and a bumped tag with no build is an `ImagePullBackOff` waiting to happen;
* the SDK versions, deliberately (see above);
* the Helm chart's own `version`, which is a human judgement about whether templates moved.

## After the bump

The images at the new tag do not exist until they are built. Before any cloud run:

```sh
gcloud builds submit --config deploy/cloudbuild/mcp-re-images.yaml .
```

and note that the kind lane (`local_gate.sh --with-kind`) builds its own images locally and
stamps them with the git revision, so a green kind stage does **not** prove the registry
holds the tag — only that the source builds and deploys.
