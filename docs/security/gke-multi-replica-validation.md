<!-- SPDX-License-Identifier: Apache-2.0 -->

# Live multi-replica (GKE) validation — runbook (MCPS-90 / MCPS-91)

Re-proves the horizontally-scaled fleet's coherence guarantees on **real GKE
infrastructure**, not just in-process. The four proofs — cross-replica replay
coherence, cross-replica trust-epoch revocation, MRT continuation across a
replica switch, and a zero-drop rolling update — are the live counterpart of the
in-repo tests (`replay_race_harness_test`, the trust-epoch flush tests,
`async_drain_test`), and are the release gate ADR-MCPS-049 clause and the
single-node non-claim retirement (MCPS-91) depend on.

> **Proof 4 (zero-drop rolling update) has a known residual on GKE (as of v0.12.1):**
> a live rollout dropped 2 of 590 in-flight requests to a kube-proxy
> endpoint-propagation timing gap; the in-process and kind lanes are clean.
> Topology-independent zero-drop is **not** claimed — bound any zero-drop expectation
> to a declared, validated LB/NEG topology. Tracked as a follow-up.

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
# MCP_RE_SERVER_* is the ROOT ISSUER anchor (ADR-MCPRE-052); the delegation credential
# in every response chains to it. MCP_RE_TRUST_EPOCH MUST equal the proxy's
# --delegated-trust-epoch (identity.delegatedTrustEpoch), or verification fails closed.
export MCP_RE_SERVER_PUBKEY=…    MCP_RE_TRUST_EPOCH=epoch-1
export MCP_RE_AUDIENCE=scheme,host,port,tenant,route,realm
export MCP_RE_TLS_CERT=…         MCP_RE_TLS_KEY=…     MCP_RE_SERVER_CA=…
# Proof 3 (MRT) needs an inner tool that elicits input; set MCP_RE_MRT_TOOL to it,
# or MCP_RE_SKIP_MRT=1 to skip that proof if the inner has none.

# 3. Run (idempotent) / tear down:
PROJECT_ID=<PROJECT_ID> ./docs/security/gke-multi-replica-validation.sh
PROJECT_ID=<PROJECT_ID> ./docs/security/gke-multi-replica-validation.sh --teardown
```

The script is idempotent (create-or-reuse cluster/release), contains no secrets,
and models the same shape as `gcloud-kms-validation.sh`. It deploys the Helm
reference (`deploy/helm/mcp-re-proxy`) with `fleet=true` (the proxy always runs the
maximal-security posture — there is no strict toggle) over a shared
Redis replay + trust-epoch tier — the fleet guardrail refuses to start on a
node-local cache, so a green rollout already proves the shared tier is wired.

The four proofs are driven by the HTTP-profile client `mcp_re_gke_client.py` (one
signed mTLS POST per request; MCP-RE owns no stdio client) using its proof flags —
`--nonce` (pin a nonce across two replicas for the replay proof), `--expect`
(assert the proxy verdict), and `--save-cont`/`--load-cont` (persist an MRT
continuation opened on one replica and answer it on another). All ports resolve
from `config/ports.toml` (the reserved 8600–8699 band); nothing is hardcoded.

## The physical step — the reproduction runbook

Provisioning a GKE cluster + the TLS/trust Secret and running the four proofs is a
live-infra action (authenticated project, billing). This run **was performed** — the
v0.11 fleet proof and the v0.12.1 KMS-via-Workload-Identity run — and everything it
needs (chart, guardrails, the four proof procedures, teardown) is authored here, so
this remains the reproduction runbook.

## What the green run unlocked (MCPS-91)

The single-node ceiling in [`docs/PROJECT_STATUS.md`](../PROJECT_STATUS.md) is retired
**at the declared shared, quorum-durable replay tier**: both conditions are discharged —
the dedicated MRT-survives-replica-switch proof (MCPS-82) and the live multi-node GKE
run (MCPS-90, v0.11). The retirement is bounded to that declared tier — it validates the
exercised GKE deployment shape, not a universal production SLO or a blanket zero-drop
guarantee across topologies (`--fleet` still fails closed on a node-local cache). To
re-verify, run `gke-multi-replica-validation.sh` (all four proofs; Proof 4's residual is
noted above) and attach the run's output as evidence. The claim boundary tracks reality,
not intent — do not broaden it beyond the declared tier without new evidence.
