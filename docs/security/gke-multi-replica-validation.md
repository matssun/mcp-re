<!-- SPDX-License-Identifier: Apache-2.0 -->

# Live multi-replica (GKE) validation — runbook (MCPS-90 / MCPS-91)

Re-proves the horizontally-scaled fleet's coherence guarantees on **real GKE
infrastructure**, not just in-process. The four proofs — cross-replica replay
coherence, cross-replica trust-epoch revocation, MRT continuation across a
replica switch, and a zero-drop rolling update — are the live counterpart of the
in-repo tests (`replay_race_harness_test`, the trust-epoch flush tests,
`async_drain_test`), and are the release gate ADR-MCPS-049 clause and the
single-node non-claim retirement (MCPS-91) depend on.

## How to run

```bash
gcloud auth login && gcloud config set project <PROJECT_ID>
# provide the fleet TLS + trust Secret `mcp-re-tls` (see docs/fleet-deployment-guide.md)

# 1. Install the signed-request client the proofs drive (needs jq). MCP-RE is
#    HTTP-profile only: the proofs are driven by the HTTP client mcp_re_gke_client.py,
#    which signs over the mcp-re-sdk core and forwards over mTLS.
pip install ./sdk/python   # provides `mcp_re_sdk`; script runs docs/security/mcp_re_gke_client.py

# 2. Point the client at the fleet's identity + TLS/trust material (same material as
#    the mcp-re-tls Secret). These are the ONLY per-run inputs besides PROJECT_ID:
export MCP_RE_SERVER_NAME=…      MCP_RE_SIGNER_ID=…   MCP_RE_KEY_ID=…
export MCP_RE_SIGNING_KEY_SEED=… MCP_RE_SERVER_SIGNER=… MCP_RE_SERVER_KEY_ID=…
export MCP_RE_SERVER_PUBKEY=…    MCP_RE_AUDIENCE=scheme,host,port,tenant,route,realm
export MCP_RE_TLS_CERT=…         MCP_RE_TLS_KEY=…     MCP_RE_SERVER_CA=…
# Proof 3 (MRT) needs an inner tool that elicits input; set MCP_RE_MRT_TOOL to it,
# or MCP_RE_SKIP_MRT=1 to skip that proof if the inner has none.

# 3. Run (idempotent) / tear down:
PROJECT_ID=<PROJECT_ID> ./docs/security/gke-multi-replica-validation.sh
PROJECT_ID=<PROJECT_ID> ./docs/security/gke-multi-replica-validation.sh --teardown
```

The script is idempotent (create-or-reuse cluster/release), contains no secrets,
and models the same shape as `gcloud-kms-validation.sh`. It deploys the Helm
reference (`deploy/helm/mcp-re-proxy`) with `strict=true fleet=true` over a shared
Redis replay + trust-epoch tier — the fleet guardrail refuses to start on a
node-local cache, so a green rollout already proves the shared tier is wired.

The four proofs are driven by the HTTP-profile client `mcp_re_gke_client.py` (one
signed mTLS POST per request; MCP-RE owns no stdio client) using its proof flags —
`--nonce` (pin a nonce across two replicas for the replay proof), `--expect`
(assert the proxy verdict), and `--save-cont`/`--load-cont` (persist an MRT
continuation opened on one replica and answer it on another). All ports resolve
from `config/ports.toml` (the reserved 8600–8699 band); nothing is hardcoded.

## The physical step (HITL)

Provisioning a GKE cluster + the TLS/trust Secret and running the four proofs is
the live-infra action only the operator can take (authenticated project, billing).
Everything the run needs — chart, guardrails, the four proof procedures, teardown —
is authored here; the run itself is what remains.

## What a green run unlocks (MCPS-91)

The single-node non-claim in [`docs/PROJECT_STATUS.md`](../PROJECT_STATUS.md) is
currently lifted **conditionally**: the fleet posture proves cross-replica replay +
trust coherence in-process, but full retirement is gated on (a) the dedicated
MRT-survives-replica-switch proof (MCPS-82) and (b) this live multi-node run.

On a green run of `gke-multi-replica-validation.sh` (all four proofs pass, with the
run's output attached as evidence), retire the non-claim by updating
`docs/PROJECT_STATUS.md`: move the "fully retired single-node ceiling" bullet out of
**Not yet claimed** and record the live-cluster evidence. **Do not** retire it before
that evidence exists — the claim boundary must track reality, not intent.
