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
#   PROJECT_ID=my-proj ./gke-multi-replica-validation.sh [--teardown]      # real GKE fleet
#   PROVIDER=kind      ./gke-multi-replica-validation.sh [--teardown]      # local kind, no cost
#
# PROVIDER=kind runs the IDENTICAL proofs against the same image + chart on a local
# kind cluster — the pre-GKE gate. A green kind run is the same test as GKE, run for
# free; only the cluster substrate and the KMS-token source differ (see PROVIDER).
# Exit 0 == all four proofs pass.
set -euo pipefail

# PROVIDER selects the CLUSTER SUBSTRATE — and NOTHING else. `gke` provisions a real
# GKE fleet (costs money); `kind` provisions a local kind cluster (free) and loads the
# same locally-built images. Everything downstream — the TLS/trust Secret, the inner
# backend, the shared Redis tier, the Helm release of the SAME chart, and Proofs 1-4
# with the SAME `--expect` assertions — is byte-identical across both providers. This
# is the whole point: a green `kind` run is the same test as GKE, run for free, so no
# cluster spend happens on a config that hasn't already passed locally.
PROVIDER="${PROVIDER:-gke}"
[[ "$PROVIDER" == gke || "$PROVIDER" == kind ]] || { printf 'PROVIDER must be gke|kind\n' >&2; exit 1; }
KIND_CLUSTER="${KIND_CLUSTER:-mcp-re-fleet}"

# PROJECT_ID targets EVERY gcloud call explicitly (never the ambient active
# config), so this harness can only ever act on the project the operator names.
# Defaults to the active gcloud project; must resolve to a real id. Required only
# for the gke provider (kind provisions no GCP cluster; a KMS key-version, if used,
# carries its own project in MCP_RE_GCP_KEY_VERSION).
PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"
if [[ "$PROVIDER" == gke ]]; then
  [[ -n "$PROJECT_ID" && "$PROJECT_ID" != "REPLACE_WITH_PROJECT_ID" ]] \
    || { printf 'set PROJECT_ID (no active gcloud project resolved)\n' >&2; exit 1; }
fi
CLUSTER="${CLUSTER:-mcp-re-fleet}"
REGION="${REGION:-us-central1}"
# The gke provider provisions a STANDARD, ZONAL cluster (NOT Autopilot, NOT regional):
# exactly the shape docs/security/gke-slo-baseline-runbook.md §2 declares, so the four
# proofs and the §7 SLO baseline run on ONE capacity-correct cluster that fits the
# free-trial 16-vCPU CPUS_ALL_REGIONS cap. Autopilot (`create-auto`) + a regional
# placement (3x nodes) blow past that cap — the reason an earlier run FailedScheduling.
# REGION still names the Artifact Registry host (${REGION}-docker.pkg.dev); ZONE places
# the cluster. Two e2-standard-2 nodes = 4 vCPU: the fleet's default-pool.
ZONE="${ZONE:-us-central1-a}"
GKE_NODES="${GKE_NODES:-2}"
GKE_MACHINE="${GKE_MACHINE:-e2-standard-2}"
NAMESPACE="${NAMESPACE:-mcp-re}"
RELEASE="${RELEASE:-mcp-re-proxy}"
REPLICAS="${REPLICAS:-3}"
# Container images. For gke they are pulled from Artifact Registry (the chart's bare
# `mcp-re-proxy` name is unpullable on a cluster); for kind they are the locally-built
# tags that get `kind load`ed below (native arch — the SAME image the GKE build
# produces, per deploy/docker/Dockerfile). Override with MCP_RE_PROXY_IMAGE / _INNER_.
if [[ "$PROVIDER" == gke ]]; then
  AR="${MCP_RE_AR:-${REGION}-docker.pkg.dev/${PROJECT_ID}/mcp-re}"
  PROXY_IMAGE="${MCP_RE_PROXY_IMAGE:-${AR}/mcp-re-proxy:0.12.1}"
  INNER_IMAGE="${MCP_RE_INNER_IMAGE:-${AR}/mcp-re-inner-fastmcp:0.12.1}"
  LOADGEN_IMAGE="${MCP_RE_LOADGEN_IMAGE:-${AR}/mcp-re-loadgen:0.12.1}"
else
  PROXY_IMAGE="${MCP_RE_PROXY_IMAGE:-mcp-re-proxy:0.12.1}"
  INNER_IMAGE="${MCP_RE_INNER_IMAGE:-mcp-re-inner-fastmcp:0.12.1}"
  LOADGEN_IMAGE="${MCP_RE_LOADGEN_IMAGE:-mcp-re-loadgen:0.12.1}"
fi
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
  log "Teardown ($PROVIDER)"
  helm -n "$NAMESPACE" uninstall "$RELEASE" || true
  if [[ "$PROVIDER" == gke ]]; then
    gcloud container clusters delete "$CLUSTER" --project "$PROJECT_ID" --zone "$ZONE" --quiet || true
  else
    kind delete cluster --name "$KIND_CLUSTER" || true
  fi
  exit 0
fi

# --- 1. Cluster (idempotent create-or-reuse) ---------------------------------
if [[ "$PROVIDER" == gke ]]; then
  log "Cluster $CLUSTER (STANDARD, zonal $ZONE, Workload Identity) in $PROJECT_ID"
  if ! gcloud container clusters describe "$CLUSTER" --project "$PROJECT_ID" --zone "$ZONE" >/dev/null 2>&1; then
    # --workload-pool enables Workload Identity: the KMS-rooted (keySource=gcpKms)
    # fleet authenticates to Cloud KMS with the GKE metadata-server token bound to a
    # GSA (roles/cloudkms.signerVerifier) — NO user access token (which KMS rejects
    # from inside GCP: ACCESS_TOKEN_TYPE_UNSUPPORTED), NO key material in the pod, NO
    # software-seed fallback. The default node pool created here gets GKE_METADATA
    # automatically. Run docs/security/gke-kms-wi-setup.sh once after this to bind the
    # GSA. fileSeed roots ignore all of this; WI just sits unused.
    gcloud container clusters create "$CLUSTER" --project "$PROJECT_ID" --zone "$ZONE" \
      --num-nodes "$GKE_NODES" --machine-type "$GKE_MACHINE" --disk-size 30 --no-enable-basic-auth \
      --workload-pool "${PROJECT_ID}.svc.id.goog"
  fi
  gcloud container clusters get-credentials "$CLUSTER" --project "$PROJECT_ID" --zone "$ZONE"
else
  # kind: create-or-reuse a local cluster and load the SAME images the GKE build
  # produces (native arch, built from deploy/docker/Dockerfile{,.inner}). Build any
  # image that isn't present locally, so a first run is self-contained.
  log "kind cluster $KIND_CLUSTER (local substrate — no cloud spend)"
  kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER" \
    || kind create cluster --name "$KIND_CLUSTER"
  kubectl config use-context "kind-${KIND_CLUSTER}" >/dev/null
  for img_spec in "proxy:$PROXY_IMAGE:deploy/docker/Dockerfile" \
                  "inner:$INNER_IMAGE:deploy/docker/Dockerfile.inner" \
                  "loadgen:$LOADGEN_IMAGE:deploy/docker/Dockerfile.loadgen"; do
    tgt="${img_spec%%:*}"; rest="${img_spec#*:}"; img="${rest%:*}"; dfile="${rest##*:}"
    if ! docker image inspect "$img" >/dev/null 2>&1; then
      log "build $img ($tgt) — not present locally"
      if [[ "$tgt" == proxy ]]; then
        docker build -f "$dfile" --target proxy -t "$img" "$REPO_ROOT"
      else
        docker build -f "$dfile" -t "$img" "$REPO_ROOT"
      fi
    fi
    log "kind load $img"
    kind load docker-image "$img" --name "$KIND_CLUSTER"
  done
fi
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
sed "s#image: mcp-re-inner-fastmcp:0.12.1#image: $INNER_IMAGE#" \
  "$REPO_ROOT/deploy/k8s/inner-fastmcp.yaml" | kubectl -n "$NAMESPACE" apply -f -
# Force a fresh pod so it runs THIS run's freshly built image. An `apply` with an
# unchanged spec (same image tag) does NOT restart the pod, so a rebuilt-and-reloaded
# image under the same tag (e.g. kind load, or a re-pushed registry tag with
# imagePullPolicy: IfNotPresent) would otherwise keep serving the STALE inner — the
# eliciting `confirm_action` tool would be missing and Proof 3 would see no
# requestState. Restart, then wait.
kubectl -n "$NAMESPACE" rollout restart deploy/mcp-re-inner-fastmcp
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
          # The replay + trust-epoch tier is an EPHEMERAL cache for the proof run (the
          # proofs never restart it), so run it purely in-memory: no RDB snapshots
          # (--save "") and no AOF. Crucially this drops `stop-writes-on-bgsave-error`,
          # which otherwise BRICKS all writes the moment a snapshot to the pod's
          # ephemeral disk fails under node disk pressure — silently failing every
          # replay `insert` closed (every request then rejected as a false "replay").
          args: ["--save", "", "--appendonly", "no", "--stop-writes-on-bgsave-error", "no"]
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
# Canonical inner endpoint is `/mcp` WITHOUT a trailing slash: FastMCP 307-redirects
# `/mcp/` -> `/mcp`, and the proxy's raw hyper inner client does NOT follow redirects
# (it maps the 307 to a fail-closed "inner unavailable"). Match http_inner.rs's own
# convention (`http://host:port/mcp`).
INNER_URL="http://mcp-re-inner-fastmcp:$(port_of mcp_re_inner_backend)/mcp"

# Signing-key custody (ADR-MCPRE-052 delegated-required ROOT ISSUER, off the request
# path). Default gcpKms — the branch's subject. The custody CODE is identical on both
# providers; only how the pod obtains the KMS access token differs (the one
# substrate-forced difference): GKE via Workload-Identity metadata (useMetadata=true),
# kind via an operator-token Secret. Set MCP_RE_KEY_SOURCE=fileSeed to root the issuer
# in the mounted seed instead (no KMS).
KEY_SOURCE="${MCP_RE_KEY_SOURCE:-gcpKms}"
KMS_SETS=()
case "$KEY_SOURCE" in
  gcpKms)
    : "${MCP_RE_GCP_KEY_VERSION:?set MCP_RE_GCP_KEY_VERSION to the KMS signing key-version}"
    KMS_SETS+=( --set keySource=gcpKms --set-string gcpKms.keyVersion="$MCP_RE_GCP_KEY_VERSION" )
    # KMS-token acquisition — the ONE substrate-forced difference:
    #   GKE (useMetadata=1): the Workload-Identity metadata-server token bound to a GSA
    #     that holds roles/cloudkms.signerVerifier on the key. This is the ONLY working
    #     KMS path on GKE — a user access token is REJECTED from inside GCP
    #     (ACCESS_TOKEN_TYPE_UNSUPPORTED). It requires (a) the cluster made with
    #     --workload-pool (done above) and (b) the KSA annotated with the GSA + the WI
    #     binding — run docs/security/gke-kms-wi-setup.sh once, then export
    #     MCP_RE_GCP_KMS_GSA=<gsa>@<project>.iam.gserviceaccount.com so the annotation is
    #     applied THROUGH helm here (deterministic; helm owns the SA annotation).
    #   kind (useMetadata=0): no metadata server, so an operator-token Secret is used.
    #     Valid on kind ONLY (its egress looks external to GCP); NEVER a GKE path.
    use_metadata="${MCP_RE_GCP_USE_METADATA:-}"
    [[ -z "$use_metadata" && "$PROVIDER" == gke ]] && use_metadata=1
    if [[ "$use_metadata" == "1" ]]; then
      : "${MCP_RE_GCP_KMS_GSA:?WI path: export MCP_RE_GCP_KMS_GSA=<gsa>@<project>.iam.gserviceaccount.com (run gke-kms-wi-setup.sh first)}"
      KMS_SETS+=( --set gcpKms.useMetadata=true
                  --set "serviceAccount.annotations.iam\.gke\.io/gcp-service-account=$MCP_RE_GCP_KMS_GSA" )
    elif [[ "$PROVIDER" == gke ]]; then
      fail "operator-token KMS (useMetadata=0) does NOT work on GKE — KMS rejects a user token from inside GCP. Use the WI path (leave MCP_RE_GCP_USE_METADATA unset)."
    else
      : "${MCP_RE_GCP_ACCESS_TOKEN:?set MCP_RE_GCP_ACCESS_TOKEN (source work/test-gcp-cloud.sh; never commit it)}"
      kubectl -n "$NAMESPACE" create secret generic mcp-re-kms-token \
        --from-literal=access-token="$MCP_RE_GCP_ACCESS_TOKEN" \
        --dry-run=client -o yaml | kubectl apply -f -
      KMS_SETS+=( --set gcpKms.useMetadata=false --set gcpKms.accessTokenSecretName=mcp-re-kms-token )
    fi ;;
  fileSeed) KMS_SETS+=( --set keySource=fileSeed ) ;;
  *) fail "MCP_RE_KEY_SOURCE must be gcpKms|fileSeed" ;;
esac

helm -n "$NAMESPACE" upgrade --install "$RELEASE" "$CHART_DIR" \
  --set replicaCount="$REPLICAS" \
  --set fleet=true \
  --set bindPort="$BIND_PORT" \
  --set image.repository="${PROXY_IMAGE%:*}" \
  --set image.tag="${PROXY_IMAGE##*:}" \
  --set-string "inner.httpUrls={$INNER_URL}" \
  --set replay.redisUrl="redis://mcp-re-redis:6379" \
  --set revocation.trustEpochRedisUrl="redis://mcp-re-redis:6379" \
  "${KMS_SETS[@]}" \
  --wait --timeout 8m
# The chart's deployment name is its fullname (<release>-<chart>), NOT the bare
# release, so resolve it by the stable app label rather than assuming $RELEASE.
DEPLOY="$(kubectl -n "$NAMESPACE" get deploy -l app.kubernetes.io/name=mcp-re-proxy \
  -o jsonpath='{.items[0].metadata.name}')"
[[ -n "$DEPLOY" ]] || fail "could not resolve the proxy deployment name"
# The proxy reads its TLS/trust + KMS-token material ONCE at startup. When this
# harness is re-run, the fleet's Secret is re-applied with FRESH material (a new CA,
# a new short-lived client cert, a refreshed KMS token), but a spec-unchanged `helm
# upgrade` does NOT restart the pods — so without this they would keep serving the
# PREVIOUS run's cert and fail the client's TLS verify against the new CA. Force a
# rollout onto the current Secret and wait for it. (Mirrors what a Secret-rotation
# would require on GKE too.)
kubectl -n "$NAMESPACE" rollout restart deploy/"$DEPLOY"
kubectl -n "$NAMESPACE" rollout status deploy/"$DEPLOY" --timeout=420s
[[ "$(kubectl -n "$NAMESPACE" get deploy "$DEPLOY" -o jsonpath='{.status.readyReplicas}')" -ge 2 ]] \
  || fail "fewer than 2 ready replicas — not a fleet"

# Address two DISTINCT replicas by port-forwarding two specific pods, so a proof
# that a nonce crosses replicas is genuine (not the same pod twice).
# Select the two NEWEST READY pods — never a stale one. The proxy reads its TLS/trust
# material ONCE at startup, so an OLD-generation pod (still Running while a prior
# ReplicaSet drains after the rollout restart above) serves the PREVIOUS run's cert
# and would fail the client's TLS verify. Filtering to Ready + newest pins the proof
# to the current generation. Portable array fill — no `mapfile` (bash 4+; macOS ships
# bash 3.2, so the harness runs identically there and on a Linux CI runner).
PODS=()
while IFS= read -r _pod; do [[ -n "$_pod" ]] && PODS+=("$_pod"); done < <(
  kubectl -n "$NAMESPACE" get pods -l app.kubernetes.io/name="$RELEASE" \
    --sort-by=.metadata.creationTimestamp \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .status.conditions[?(@.type=="Ready")]}{.status}{end}{"\n"}{end}' \
  | awk -F'\t' '$2=="True"{print $1}' | tail -2)
[[ "${#PODS[@]}" -ge 2 ]] || fail "need >= 2 ready pods to prove cross-replica coherence"
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

# --- In-cluster load generator (for Proof 4) ---------------------------------
# Proof 4 (zero-drop rolling update) MUST drive load THROUGH kube-proxy — the Service
# ClusterIP — so a draining pod is dropped from the endpoints (preStop delay) and new
# connections reroute to live pods. A host `kubectl port-forward` is a direct tunnel to
# ONE pinned pod: when the rollout deletes that pod the tunnel dies and every later
# request fails regardless of drain, so it can never prove zero-drop on ANY provider.
# We therefore run the request loop from a loadgen pod INSIDE the cluster. Skippable
# with MCP_RE_SKIP_ROLLING (e.g. when no loadgen image is available).
LOADGEN_POD=""
if [[ -z "${MCP_RE_SKIP_ROLLING:-}" ]]; then
  log "In-cluster load generator (Proof 4 drives the Service through kube-proxy)"
  # Client-side material Secret (the files behind the client env; strip any leading @).
  seed_path="${MCP_RE_SIGNING_KEY_SEED#@}"; pub_path="${MCP_RE_SERVER_PUBKEY#@}"
  kubectl -n "$NAMESPACE" create secret generic mcp-re-loadgen-material \
    --from-file=client-cert="$MCP_RE_TLS_CERT" \
    --from-file=client-key="$MCP_RE_TLS_KEY" \
    --from-file=client-signing-seed="$seed_path" \
    --from-file=server-pubkey="$pub_path" \
    --from-file=server-ca="$MCP_RE_SERVER_CA" \
    --dry-run=client -o yaml | kubectl -n "$NAMESPACE" apply -f -
  kubectl -n "$NAMESPACE" apply -f - <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: { name: mcp-re-loadgen, labels: { app: mcp-re-loadgen } }
spec:
  replicas: 1
  selector: { matchLabels: { app: mcp-re-loadgen } }
  template:
    metadata: { labels: { app: mcp-re-loadgen } }
    spec:
      containers:
        - name: loadgen
          image: "$LOADGEN_IMAGE"
          imagePullPolicy: IfNotPresent
          command: ["sleep", "infinity"]
          volumeMounts:
            - { name: material, mountPath: /etc/mcp-re-client, readOnly: true }
      volumes:
        - name: material
          secret: { secretName: mcp-re-loadgen-material }
YAML
  # Restart so the pod mounts THIS run's fresh client material (an unchanged spec does
  # not restart on `apply`), then wait for it.
  kubectl -n "$NAMESPACE" rollout restart deploy/mcp-re-loadgen
  kubectl -n "$NAMESPACE" rollout status deploy/mcp-re-loadgen --timeout=180s
  LOADGEN_POD="$(kubectl -n "$NAMESPACE" get pod -l app=mcp-re-loadgen \
    --sort-by=.metadata.creationTimestamp \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .status.conditions[?(@.type=="Ready")]}{.status}{end}{"\n"}{end}' \
    | awk -F'\t' '$2=="True"{print $1}' | tail -1)"
  [[ -n "$LOADGEN_POD" ]] || fail "loadgen pod did not become ready"
fi

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
# Capture the PRE-BUMP epoch value: the shared counter is monotonic AND persistent, so
# its absolute value carries across runs — the replicas' startup baseline is this value,
# not 0. We restore exactly this after the proof so serving recovers (see the reset).
EPOCH_BEFORE="$(kubectl -n "$NAMESPACE" exec deploy/mcp-re-redis -- redis-cli GET mcp-re:trust:epoch | tr -d '\r')"
kubectl -n "$NAMESPACE" exec deploy/mcp-re-redis -- \
  redis-cli INCR mcp-re:trust:epoch >/dev/null
sleep 2  # bounded propagation window
printf '%s\n' "$REQ" | $CLIENT "${CLIENT_COMMON[@]}" --remote-addr "$REPLICA_B" --expect revoked \
  || fail "sibling B still trusted a credential revoked by the epoch bump"
echo "  OK: epoch bump on the shared tier revoked across replicas."

# Proof 2 ADVANCED the shared epoch to prove revocation; that revocation is real and
# fleet-wide, so EVERY subsequent request now fails closed until the trust generation
# is restored. Reset the epoch to the startup baseline so the later, independent proofs
# serve again: each replica's delegated-epoch watch re-issues under the base epoch once
# the counter returns to baseline, and verifiers pinned to it accept once more. (This
# is test isolation between independent proofs — NOT relaxing the revocation just shown.)
log "Reset trust epoch to baseline (restore serving for the remaining proofs)"
if [[ -n "$EPOCH_BEFORE" ]]; then
  kubectl -n "$NAMESPACE" exec deploy/mcp-re-redis -- redis-cli SET mcp-re:trust:epoch "$EPOCH_BEFORE" >/dev/null
else
  # No prior value: the key was unset at startup, so unset it again (reads as 0 = baseline).
  kubectl -n "$NAMESPACE" exec deploy/mcp-re-redis -- redis-cli DEL mcp-re:trust:epoch >/dev/null
fi
# Wait (bounded) for every replica to re-issue the base epoch before continuing.
restored=""
for _ in $(seq 1 30); do
  if printf '%s\n' "$REQ" | $CLIENT "${CLIENT_COMMON[@]}" --remote-addr "$REPLICA_A" --expect accepted >/dev/null 2>&1 \
     && printf '%s\n' "$REQ" | $CLIENT "${CLIENT_COMMON[@]}" --remote-addr "$REPLICA_B" --expect accepted >/dev/null 2>&1; then
    restored=1; break
  fi
  sleep 1
done
[[ -n "$restored" ]] || fail "serving did not recover after resetting the trust epoch to baseline"
echo "  OK: base epoch re-issued across replicas; serving restored."

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
if [[ -z "$LOADGEN_POD" ]]; then
  echo "  SKIP: MCP_RE_SKIP_ROLLING set (no in-cluster load generator)."
else
  PROXY_SVC="$(kubectl -n "$NAMESPACE" get svc -l app.kubernetes.io/name=mcp-re-proxy \
    -o jsonpath='{.items[0].metadata.name}')"
  [[ -n "$PROXY_SVC" ]] || fail "could not resolve the proxy Service"
  # The Service ClusterIP DNS — kube-proxy load-balances across Ready endpoints and
  # drops a draining pod (preStop) BEFORE it stops accepting, so new connections avoid
  # it while in-flight requests on it complete. mTLS SNI/scheme still come from the
  # client's --server-name / --server-ca; --remote-addr is host:port.
  TARGET_ADDR="${PROXY_SVC}.${NAMESPACE}.svc.cluster.local:${BIND_PORT}"
  # In-pod client flags: identity IDENTICAL to CLIENT_COMMON; file paths are the mounted
  # loadgen Secret. No value contains a space, so a space-joined command line is safe.
  LG="--server-name $MCP_RE_SERVER_NAME --signer-id $MCP_RE_SIGNER_ID --key-id $MCP_RE_KEY_ID"
  LG="$LG --signing-key-seed @/etc/mcp-re-client/client-signing-seed"
  LG="$LG --server-signer $MCP_RE_SERVER_SIGNER --server-key-id $MCP_RE_SERVER_KEY_ID"
  LG="$LG --server-pubkey @/etc/mcp-re-client/server-pubkey --trust-epoch $MCP_RE_TRUST_EPOCH"
  LG="$LG --audience $MCP_RE_AUDIENCE --target-uri $MCP_RE_TARGET_URI --trust-domain ${MCP_RE_TRUST_DOMAIN:-example.com}"
  LG="$LG --tls-cert /etc/mcp-re-client/client-cert --tls-key /etc/mcp-re-client/client-key --server-ca /etc/mcp-re-client/server-ca"
  # Time-bounded so the load spans the WHOLE rollout (a fixed request count can finish
  # before the roll does and miss the tail). Counts drops over the window.
  SECS="${MCP_RE_ROLLING_SECS:-75}"
  REMOTE="end=\$(( \$(date +%s) + $SECS )); n=0; drops=0; \
while [ \$(date +%s) -lt \$end ]; do \
  printf '%s\\n' '$REQ' | python /app/mcp_re_gke_client.py $LG --remote-addr $TARGET_ADDR --expect accepted >/dev/null 2>&1 || { echo DROP; drops=\$((drops+1)); }; \
  n=\$((n+1)); \
done; echo \"loadgen: \$n requests, \$drops drop(s)\""
  kubectl -n "$NAMESPACE" exec "$LOADGEN_POD" -- sh -c "$REMOTE" > /tmp/mcps90.load 2>&1 & LOAD=$!
  sleep 2  # let the load loop establish steady traffic before the rollout starts
  kubectl -n "$NAMESPACE" set env deploy/"$DEPLOY" ROLLOUT_NONCE="$(date +%s)"
  kubectl -n "$NAMESPACE" rollout status deploy/"$DEPLOY" --timeout=300s
  wait $LOAD || true
  tail -1 /tmp/mcps90.load || true
  # HONESTY GUARD: the loop MUST have run to completion (it prints a `loadgen:` summary
  # with its request count). A killed/empty exec proves nothing — treat a missing
  # summary or a zero request count as FAILURE, never a silent pass.
  grep -q '^loadgen: ' /tmp/mcps90.load \
    || fail "load generator did not complete (no summary; exec killed?) — cannot confirm zero-drop"
  reqs="$(sed -n 's/^loadgen: \([0-9]*\) requests.*/\1/p' /tmp/mcps90.load)"
  [[ "${reqs:-0}" -gt 20 ]] \
    || fail "load generator ran only ${reqs:-0} requests — too few to span the rollout"
  ! grep -q DROP /tmp/mcps90.load \
    || fail "rolling update dropped in-flight requests ($(grep -c DROP /tmp/mcps90.load) of $reqs)"
  echo "  OK: rolling update completed with zero drops across $reqs requests (load via the Service)."
fi

log "ALL FOUR LIVE PROOFS PASSED"
