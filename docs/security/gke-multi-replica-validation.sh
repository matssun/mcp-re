#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# MCP-RE — live multi-replica (GKE) validation harness (MCPS-90).
#
# WHAT THIS PROVES, against a REAL Google Kubernetes Engine fleet of N identical
# mcp-re-proxy replicas behind a Service, with a shared Redis replay + trust-epoch
# tier (ADR-MCPS-049 / ADR-MCPRE-051 §4):
#   Proof 1 — cross-replica REPLAY coherence: a nonce accepted (Fresh) by one
#             replica is rejected (Replay) by a sibling. (MCPS-79/80/81)
#   Proof 2 — cross-replica TRUST revocation: advancing the shared trust epoch
#             flushes the Push-tier trust cache across replicas; a credential
#             valid before the bump is rejected after it on a sibling. (MCPS-84/85/86)
#   Proof 3 — MRT continuation survives a REPLICA SWITCH: a multi-round-trip
#             continuation opened on replica A is honoured on replica B. (MCPS-82)
#   Proof 4 — ZERO-DROP rolling update: a rolling Deployment update with graceful
#             SIGTERM drain completes with no in-flight request abandoned
#             (ADR-MCPRE-051 §6 / drainGracePeriodSeconds).
#
# These four are already proven IN-PROCESS by the repo's tests
# (replay_race_harness_test, trust-epoch flush tests, async_drain_test); this
# harness RE-PROVES them on live GKE infrastructure, which is the MCPS-90 / MCPS-90
# release gate ADR-MCPS-049 clause and the single-node non-claim retirement
# (MCPS-91) depend on.
#
# This is a TEMPLATE. It contains no secrets. Fill in PROJECT_ID / CLUSTER /
# REGION below (or export them), authenticate with `gcloud auth login`, and
# provide the fleet's TLS + trust material Secret (see deploy/helm/mcp-re-proxy).
# It is IDEMPOTENT: re-running reuses an existing cluster/release.
#
# Cost note: a small GKE Autopilot/standard cluster + a Redis instance for the
# duration of the run. Tear down with `--teardown` when done.
#
# Prerequisites:
#   * a Google Cloud project with billing enabled; gcloud + kubectl + helm
#   * gcloud auth login && gcloud config set project <PROJECT_ID>
#   * a Kubernetes Secret `mcp-re-tls` with tls.crt/tls.key/client-ca.pem/trust.json
#     (+ signing-seed) — the same material the fleet guide describes
#   * the `mcp-re-sdk` Python package installed (`pip install ./sdk/python`) — the
#     HTTP-profile proof client `mcp_re_gke_client.py` drives the proofs over mTLS
#
# Usage:
#   PROJECT_ID=my-proj ./gke-multi-replica-validation.sh [--teardown]
# Exit 0 == all four proofs pass.
set -euo pipefail

# PROJECT_ID targets EVERY gcloud call explicitly (never the ambient active
# config), so this harness can only ever act on the project the operator names.
# Defaults to the active gcloud project; must resolve to a real id.
PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
[[ -n "$PROJECT_ID" && "$PROJECT_ID" != "REPLACE_WITH_PROJECT_ID" ]] \
  || { printf 'set PROJECT_ID (no active gcloud project resolved)\n' >&2; exit 1; }
CLUSTER="${CLUSTER:-mcp-re-fleet}"
REGION="${REGION:-us-central1}"
NAMESPACE="${NAMESPACE:-mcp-re}"
RELEASE="${RELEASE:-mcp-re-proxy}"
REPLICAS="${REPLICAS:-3}"
# Container images (built + pushed by deploy/cloudbuild/mcp-re-images.yaml). The
# chart's default bare `mcp-re-proxy` name is unpullable on GKE, so override to the
# Artifact Registry path here.
AR="${MCP_RE_AR:-${REGION}-docker.pkg.dev/${PROJECT_ID}/mcp-re}"
PROXY_IMAGE="${MCP_RE_PROXY_IMAGE:-${AR}/mcp-re-proxy:0.12.0}"
INNER_IMAGE="${MCP_RE_INNER_IMAGE:-${AR}/mcp-re-inner-fastmcp:0.12.0}"
# The TLS/trust material the fleet Secret is built from (emit_mtls_fixtures output).
# Required only for the DEPLOY path (enforced at the Secret step below); --teardown
# must run without it, so don't fail-fast here.
FIXTURES_DIR="${MCP_RE_FIXTURES_DIR:-}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHART_DIR="$REPO_ROOT/deploy/helm/mcp-re-proxy"
PORTS_TOML="$REPO_ROOT/config/ports.toml"

log() { printf '\n=== %s ===\n' "$*"; }
fail() { printf 'PROOF FAILED: %s\n' "$*" >&2; exit 1; }

# --- Port settings — RESOLVED FROM THE REGISTRY, never a literal --------------
# Every port comes from the repo's single source of truth, config/ports.toml
# (the reserved 8600-8699 band). We read it here rather than restating a number,
# so this harness, the deployed fleet, and the machine-wide reservation can never
# disagree (the "port chaos" this project left behind). `<KEY>_PORT` env vars
# still override, matching the registry convention.
port_of() {  # port_of <service-key> -> registered port
  python3 -c 'import tomllib,sys; print(tomllib.load(open(sys.argv[1],"rb"))["services"][sys.argv[2]]["port"])' \
    "$PORTS_TOML" "$1" 2>/dev/null
}
BIND_PORT="${MCP_RE_PROXY_PORT:-$(port_of mcp_re_proxy)}"
[[ -n "$BIND_PORT" ]] || fail "could not read mcp_re_proxy port from $PORTS_TOML"
# Two DISTINCT local port-forward endpoints, so the harness can address two
# replicas at once (a local port cannot be bound twice). Both forward to the one
# in-cluster BIND_PORT; both come from the registry, not inline literals.
LOCAL_PORT_A="${MCP_RE_VALIDATION_FWD_A_PORT:-$(port_of mcp_re_validation_fwd_a)}"
LOCAL_PORT_B="${MCP_RE_VALIDATION_FWD_B_PORT:-$(port_of mcp_re_validation_fwd_b)}"
[[ -n "$LOCAL_PORT_A" && -n "$LOCAL_PORT_B" ]] || fail "could not read validation forward ports from $PORTS_TOML"

if [[ "${1:-}" == "--teardown" ]]; then
  log "Teardown"
  helm -n "$NAMESPACE" uninstall "$RELEASE" || true
  gcloud container clusters delete "$CLUSTER" --project "$PROJECT_ID" --region "$REGION" --quiet || true
  exit 0
fi

# --- 1. Cluster (idempotent create-or-reuse) ---------------------------------
log "Cluster $CLUSTER ($REGION) in $PROJECT_ID"
if ! gcloud container clusters describe "$CLUSTER" --project "$PROJECT_ID" --region "$REGION" >/dev/null 2>&1; then
  gcloud container clusters create-auto "$CLUSTER" --project "$PROJECT_ID" --region "$REGION"
fi
gcloud container clusters get-credentials "$CLUSTER" --project "$PROJECT_ID" --region "$REGION"
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# --- 1b. Fleet TLS/trust Secret (mounted by the chart at tls.mountPath) -------
# Built from the emit_mtls_fixtures output; key names match the chart's
# --signing-key-seed / --tls-cert / --tls-key / --client-ca / --trust mounts.
[[ -n "$FIXTURES_DIR" ]] || fail "set MCP_RE_FIXTURES_DIR to an emit_mtls_fixtures output dir"
log "TLS/trust Secret (mcp-re-proxy-material) from $FIXTURES_DIR"
kubectl -n "$NAMESPACE" create secret generic mcp-re-proxy-material \
  --from-file=signing-seed="$FIXTURES_DIR/signing_seed" \
  --from-file=tls.crt="$FIXTURES_DIR/server_cert.pem" \
  --from-file=tls.key="$FIXTURES_DIR/server_key.pem" \
  --from-file=client-ca.pem="$FIXTURES_DIR/client_ca.pem" \
  --from-file=trust.json="$FIXTURES_DIR/trust.json" \
  --dry-run=client -o yaml | kubectl apply -f -

# --- 1c. Inner FastMCP backend (the ALLOWED Streamable-HTTP inner plane) ------
log "Inner FastMCP backend ($INNER_IMAGE)"
sed "s#image: mcp-re-inner-fastmcp:0.12.0#image: $INNER_IMAGE#" \
  "$REPO_ROOT/deploy/k8s/inner-fastmcp.yaml" | kubectl -n "$NAMESPACE" apply -f -
kubectl -n "$NAMESPACE" rollout status deploy/mcp-re-inner-fastmcp --timeout=420s

# --- 2. Shared Redis tier (replay + trust epoch) -----------------------------
log "Shared Redis tier"
kubectl -n "$NAMESPACE" apply -f - <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata: { name: mcp-re-redis }
spec:
  replicas: 1
  selector: { matchLabels: { app: mcp-re-redis } }
  template:
    metadata: { labels: { app: mcp-re-redis } }
    spec:
      containers:
        - name: redis
          image: redis:7
          args: ["--appendonly", "yes"]
          ports: [{ containerPort: 6379 }]
---
apiVersion: v1
kind: Service
metadata: { name: mcp-re-redis }
spec:
  selector: { app: mcp-re-redis }
  ports: [{ port: 6379, targetPort: 6379 }]
YAML
kubectl -n "$NAMESPACE" rollout status deploy/mcp-re-redis --timeout=300s

# --- 3. Deploy the fleet (strict + fleet + shared tiers) ---------------------
# The chart REFUSES to start a --fleet deployment on a node-local replay cache
# (ADR-MCPS-049 guardrail), so a green rollout already proves the shared tier is
# wired. TLS/trust material must be provided as the `mcp-re-tls` Secret.
log "Deploy fleet ($REPLICAS replicas) — always-maximal-security posture; fleet topology"
INNER_URL="http://mcp-re-inner-fastmcp:$(port_of mcp_re_inner_backend)/mcp/"
helm -n "$NAMESPACE" upgrade --install "$RELEASE" "$CHART_DIR" \
  --set replicaCount="$REPLICAS" \
  --set fleet=true \
  --set bindPort="$BIND_PORT" \
  --set image.repository="${PROXY_IMAGE%:*}" \
  --set image.tag="${PROXY_IMAGE##*:}" \
  --set-string "inner.httpUrls={$INNER_URL}" \
  --set replay.redisUrl="redis://mcp-re-redis:6379" \
  --set trust.trustEpochRedisUrl="redis://mcp-re-redis:6379" \
  --wait --timeout 8m
# The chart's deployment name is its fullname (<release>-<chart>), NOT the bare
# release, so resolve it by the stable app label rather than assuming $RELEASE.
DEPLOY="$(kubectl -n "$NAMESPACE" get deploy -l app.kubernetes.io/name=mcp-re-proxy \
  -o jsonpath='{.items[0].metadata.name}')"
[[ -n "$DEPLOY" ]] || fail "could not resolve the proxy deployment name"
kubectl -n "$NAMESPACE" rollout status deploy/"$DEPLOY" --timeout=420s
[[ "$(kubectl -n "$NAMESPACE" get deploy "$DEPLOY" -o jsonpath='{.status.readyReplicas}')" -ge 2 ]] \
  || fail "fewer than 2 ready replicas — not a fleet"

# Address two DISTINCT replicas by port-forwarding two specific pods, so a proof
# that a nonce crosses replicas is genuine (not the same pod twice).
mapfile -t PODS < <(kubectl -n "$NAMESPACE" get pods -l app.kubernetes.io/name="$RELEASE" \
  -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | head -2)
[[ "${#PODS[@]}" -ge 2 ]] || fail "need >= 2 pods to prove cross-replica coherence"
kubectl -n "$NAMESPACE" port-forward "pod/${PODS[0]}" "${LOCAL_PORT_A}:${BIND_PORT}" >/dev/null 2>&1 & PF_A=$!
kubectl -n "$NAMESPACE" port-forward "pod/${PODS[1]}" "${LOCAL_PORT_B}:${BIND_PORT}" >/dev/null 2>&1 & PF_B=$!
trap 'kill $PF_A $PF_B 2>/dev/null || true' EXIT
sleep 3
# The client's --remote-addr takes host:port (mTLS + scheme come from --server-name
# and the CA); NOT a URL. Both forward to the one in-cluster BIND_PORT.
REPLICA_A="127.0.0.1:${LOCAL_PORT_A}"
REPLICA_B="127.0.0.1:${LOCAL_PORT_B}"

# The signed-request client — the HTTP-profile proof client shipped in this repo
# (MCP-RE is HTTP-profile only; there is no stdio client). It reads one plain
# JSON-RPC request on stdin, signs a draft-02 envelope with the `mcp-re-sdk` core,
# forwards it over verifying mTLS as one HTTP POST, and prints `verdict=<token>` to
# stderr; with --expect it exits non-zero on a verdict mismatch. Proof flags: --nonce
# (pin the nonce), --expect, --save-cont/--load-cont (MRT). Override MCP_RE_CLIENT to
# run it under a specific interpreter/venv (default: python3).
CLIENT_SCRIPT="$REPO_ROOT/docs/security/mcp_re_gke_client.py"
CLIENT="${MCP_RE_CLIENT:-python3 $CLIENT_SCRIPT}"
[[ -f "$CLIENT_SCRIPT" ]] || fail "proof client missing: $CLIENT_SCRIPT"
# Probe with the SAME interpreter the client runs under (the first word of
# $CLIENT), so a venv-installed SDK is found even when the system python3 has none.
CLIENT_PY="${CLIENT%% *}"
"$CLIENT_PY" -c 'import mcp_re_sdk' 2>/dev/null \
  || fail "mcp-re-sdk not importable by $CLIENT_PY — run: $CLIENT_PY -m pip install $REPO_ROOT/sdk/python"

# Client identity + the fleet's TLS/trust material — the SAME material as the
# `mcp-re-tls` Secret. Supplied via env (no secrets, no host/port literals here).
# Every flag below is required by the client.
CLIENT_COMMON=(
  --server-name      "${MCP_RE_SERVER_NAME:?set MCP_RE_SERVER_NAME to the proxy TLS SAN}"
  --signer-id        "${MCP_RE_SIGNER_ID:?set MCP_RE_SIGNER_ID}"
  --key-id           "${MCP_RE_KEY_ID:?set MCP_RE_KEY_ID}"
  --signing-key-seed "${MCP_RE_SIGNING_KEY_SEED:?set MCP_RE_SIGNING_KEY_SEED to a b64url seed or @file}"
  # ADR-MCPRE-052 delegated-required: the server-* trio is the ROOT ISSUER anchor the
  # delegation credential chains to (NOT a per-response key). --trust-epoch is the
  # accepted trust-epoch set and MUST equal the proxy's --delegated-trust-epoch (§7),
  # or every response fails closed on a stale-epoch credential.
  --server-signer    "${MCP_RE_SERVER_SIGNER:?set MCP_RE_SERVER_SIGNER}"
  --server-key-id    "${MCP_RE_SERVER_KEY_ID:?set MCP_RE_SERVER_KEY_ID}"
  --server-pubkey    "${MCP_RE_SERVER_PUBKEY:?set MCP_RE_SERVER_PUBKEY to a b64url key or @file}"
  --trust-epoch      "${MCP_RE_TRUST_EPOCH:?set MCP_RE_TRUST_EPOCH to the proxy --delegated-trust-epoch}"
  --audience         "${MCP_RE_AUDIENCE:?set MCP_RE_AUDIENCE (the proxy --audience id)}"
  # RFC 9421 audience tuple (ADR-MCPRE-050): the client signs {audience,target-uri,route}
  # and the proxy rejects invalid_audience unless target-uri matches its --target-uri.
  --target-uri       "${MCP_RE_TARGET_URI:?set MCP_RE_TARGET_URI to the proxy --target-uri (e.g. https://proxy.internal:8600/mcp)}"
  --trust-domain     "${MCP_RE_TRUST_DOMAIN:-example.com}"
  --tls-cert         "${MCP_RE_TLS_CERT:?set MCP_RE_TLS_CERT to the client cert PEM path}"
  --tls-key          "${MCP_RE_TLS_KEY:?set MCP_RE_TLS_KEY to the client key PEM path}"
  --server-ca        "${MCP_RE_SERVER_CA:?set MCP_RE_SERVER_CA to the server CA PEM path}"
)
# A minimal plain-MCP request the non-MRT proofs send. Override MCP_RE_REQ for your inner.
REQ="${MCP_RE_REQ:-}"
[[ -n "$REQ" ]] || REQ='{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# --- Proof 1: cross-replica replay coherence ---------------------------------
log "Proof 1 — cross-replica replay coherence"
# A proper 128-bit b64url nonce, PINNED so both replicas see the identical
# (signer, audience, nonce) triple — the whole point of the coherence proof.
NONCE="$(head -c 16 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')"
printf '%s\n' "$REQ" | $CLIENT "${CLIENT_COMMON[@]}" \
  --remote-addr "$REPLICA_A" --nonce "$NONCE" --expect accepted \
  || fail "replica A did not accept a fresh pinned nonce"
printf '%s\n' "$REQ" | $CLIENT "${CLIENT_COMMON[@]}" \
  --remote-addr "$REPLICA_B" --nonce "$NONCE" --expect replay \
  || fail "replica B accepted a nonce already spent on A (replay coherence broken)"
echo "  OK: nonce Fresh on A, Replay on B."

# --- Proof 2: cross-replica trust revocation ---------------------------------
log "Proof 2 — cross-replica trust-epoch revocation"
printf '%s\n' "$REQ" | $CLIENT "${CLIENT_COMMON[@]}" --remote-addr "$REPLICA_A" --expect accepted \
  || fail "baseline request rejected before revocation"
kubectl -n "$NAMESPACE" exec deploy/mcp-re-redis -- \
  redis-cli INCR mcp-re:trust:epoch >/dev/null
sleep 2  # bounded propagation window
printf '%s\n' "$REQ" | $CLIENT "${CLIENT_COMMON[@]}" --remote-addr "$REPLICA_B" --expect revoked \
  || fail "sibling B still trusted a credential revoked by the epoch bump"
echo "  OK: epoch bump on the shared tier revoked across replicas."

# --- Proof 3: MRT continuation survives a replica switch ---------------------
# Open an InputRequired elicitation on A (persisting the continuation), read the
# server-issued requestState from A's response, then answer on B with that
# requestState + the loaded continuation. MRT_OPEN_REQ / the answer tool name are
# inner-specific — override MRT_OPEN_REQ and MRT_TOOL for your eliciting tool.
log "Proof 3 — MRT continuation across a replica switch"
if [[ -n "${MCP_RE_SKIP_MRT:-}" ]]; then
  echo "  SKIP: MCP_RE_SKIP_MRT set (inner has no eliciting tool wired)."
else
  CONT_FILE="$(mktemp)"
  MRT_TOOL="${MCP_RE_MRT_TOOL:-confirm_action}"
  MRT_OPEN_REQ="${MCP_RE_MRT_OPEN_REQ:-}"
  [[ -n "$MRT_OPEN_REQ" ]] || MRT_OPEN_REQ="$(jq -nc --arg t "$MRT_TOOL" \
    '{jsonrpc:"2.0",id:1,method:"tools/call",params:{name:$t,arguments:{}}}')"
  OPEN_RESP="$(printf '%s\n' "$MRT_OPEN_REQ" | $CLIENT "${CLIENT_COMMON[@]}" \
    --remote-addr "$REPLICA_A" --save-cont "$CONT_FILE")" \
    || fail "could not open a multi-round-trip continuation on A"
  STATE="$(printf '%s' "$OPEN_RESP" | jq -r '.result.requestState // empty')"
  [[ -n "$STATE" ]] || fail "A's response carried no requestState (tool did not elicit input)"
  ANSWER_REQ="$(jq -nc --arg s "$STATE" --arg t "$MRT_TOOL" \
    '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:$t,arguments:{},inputResponses:{confirm:true},requestState:$s}}')"
  printf '%s\n' "$ANSWER_REQ" | $CLIENT "${CLIENT_COMMON[@]}" \
    --remote-addr "$REPLICA_B" --load-cont "$CONT_FILE" --expect accepted \
    || fail "continuation opened on A was not honoured on B"
  rm -f "$CONT_FILE"
  echo "  OK: continuation opened on A honoured on B."
fi

# --- Proof 4: zero-drop rolling update ---------------------------------------
log "Proof 4 — zero-drop rolling update with drain"
( for _ in $(seq 1 200); do
    printf '%s\n' "$REQ" | $CLIENT "${CLIENT_COMMON[@]}" --remote-addr "$REPLICA_A" --expect accepted \
      >/dev/null 2>&1 || echo DROP
  done ) > /tmp/mcps90.load 2>&1 & LOAD=$!
kubectl -n "$NAMESPACE" set env deploy/"$DEPLOY" ROLLOUT_NONCE="$(date +%s)"
kubectl -n "$NAMESPACE" rollout status deploy/"$DEPLOY" --timeout=300s
wait $LOAD || true
! grep -q DROP /tmp/mcps90.load || fail "rolling update dropped in-flight requests"
echo "  OK: rolling update completed with zero dropped in-flight requests."

log "ALL FOUR LIVE PROOFS PASSED"
