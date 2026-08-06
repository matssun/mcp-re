<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-RE Release Checklist

Use this checklist before a public release or MCP proposal submission.

This checklist is about whether the project is READY to release. The mechanics of moving
the version number — which of the ~22 files carry it, what deliberately does not move, and
why an uneven bump surfaces as `ImagePullBackOff` on a billing cluster rather than as a
build failure — are in [`docs/dev/version-bump.md`](dev/version-bump.md). Run
`scripts/bump_version.sh` from there; do the readiness items here.

## Bump the version

- [ ] `scripts/bump_version.sh <new-version>` has run on a clean tree, after the
      functional work is merged ([`docs/dev/version-bump.md`](dev/version-bump.md)).
- [ ] `CHANGELOG.md` has a hand-written entry for the release — what changed for someone
      deciding whether to upgrade, not a list of commits.
- [ ] The Helm chart's own `version:` moved **only** if `deploy/helm/` changed; its
      `appVersion` tracks `VERSION` and moves every time.
- [ ] The SDK versions were **not** bumped in sympathy — they are on an independent
      cadence.
- [ ] `gcloud builds submit --config deploy/cloudbuild/mcp-re-images.yaml .` has run: the
      images do not exist at the new tag until it does, and no local gate can tell you so.

## Run the local gate first

- [ ] `scripts/local_gate.sh --with-kind` is green — every stage, on this machine,
      before any cloud run or baseline declaration
      ([`docs/dev/local-gate-order.md`](dev/local-gate-order.md)).
- [ ] The ADR-MCPRE-051 §7 local SLO lane (stage 4) passed on a **quiet** box — the
      loadgen is co-located, so a loaded box produces an environmental FAIL and a
      meaningless number.
- [ ] No lane was reported green on a run that selected zero tests (`--ignored` on
      `tls_load_harness_bench` is the known trap; the lane script refuses it).

## Licensing

- [ ] `LICENSE` contains Apache License 2.0.
- [ ] `NOTICE.md` is present.
- [ ] SPDX identifiers are present in source and documentation files.
- [ ] `THIRD_PARTY.md` has verified dependency license information.
- [ ] Contribution licensing is documented in `CONTRIBUTING.md`.

## Status and claims

- [ ] README states the project is experimental / unofficial.
- [ ] README does not imply MCP or Anthropic endorsement.
- [ ] Extension identifier uses a controlled third-party prefix.
- [ ] `docs/SECURITY_BOUNDARY.md` states the current allowed claim.
- [ ] Deferred work is explicitly listed.

## Security

- [ ] Signature verification tests pass.
- [ ] Replay/freshness tests pass.
- [ ] Authorization allow/deny tests pass.
- [ ] mTLS positive and negative tests pass.
- [ ] Verified-context strip/inject tests pass.
- [ ] Response request-hash binding tests pass.
- [ ] Negative tests verify deny-before-dispatch.
- [ ] Security boundary has owner review.

## Conformance and evidence

- [ ] Conformance vectors are present.
- [ ] Test traceability manifest is present.
- [ ] Manifest guard test passes.
- [ ] End-to-end persistent demo passes.
- [ ] Negative demo passes.
- [ ] Hermetic test suite passes.
- [ ] Cold-clone reproducibility job has passed.

## Proposal package

- [ ] Specification exists.
- [ ] Security boundary exists.
- [ ] Test traceability exists.
- [ ] Reference implementation exists.
- [ ] Demo guide exists.
- [ ] Upstream proposal brief exists.
- [ ] Public wording avoids official-status overclaiming.
