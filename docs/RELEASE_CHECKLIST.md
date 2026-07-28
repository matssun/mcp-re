<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-RE Release Checklist

Use this checklist before a public release or MCP proposal submission.

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
