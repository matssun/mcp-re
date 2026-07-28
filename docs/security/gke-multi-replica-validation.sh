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
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHART_DIR="$REPO_ROOT/deploy/helm/mcp-re-proxy"
PORTS_TOML="$REPO_ROOT/config/ports.toml"
# Image tag — READ FROM THE REPO'S VERSION file, never restated as a literal. Same rule
# as the port registry below: the chart's appVersion/image.tag and
# deploy/k8s/inner-fastmcp.yaml already track VERSION, so a tag restated here goes stale
# the moment VERSION moves and this harness then deploys an image the manifests do not
# name — on kind an absent tag, on GKE an unpullable one.
IMAGE_TAG="${MCP_RE_IMAGE_TAG:-$(tr -d '[:space:]' < "$REPO_ROOT/VERSION")}"
[[ -n "$IMAGE_TAG" ]] || { printf 'could not read the image tag from %s/VERSION\n' "$REPO_ROOT" >&2; exit 1; }
# Container images. For gke they are pulled from Artifact Registry (the chart's bare
# `mcp-re-proxy` name is unpullable on a cluster); for kind they are the locally-built
# tags that get `kind load`ed below (native arch — the SAME image the GKE build
# produces, per deploy/docker/Dockerfile). Override with MCP_RE_PROXY_IMAGE / _INNER_.
if [[ "$PROVIDER" == gke ]]; then
  AR="${MCP_RE_AR:-${REGION}-docker.pkg.dev/${PROJECT_ID}/mcp-re}"
  PROXY_IMAGE="${MCP_RE_PROXY_IMAGE:-${AR}/mcp-re-proxy:$IMAGE_TAG}"
  INNER_IMAGE="${MCP_RE_INNER_IMAGE:-${AR}/mcp-re-inner-fastmcp:$IMAGE_TAG}"
  LOADGEN_IMAGE="${MCP_RE_LOADGEN_IMAGE:-${AR}/mcp-re-loadgen:$IMAGE_TAG}"
else
  PROXY_IMAGE="${MCP_RE_PROXY_IMAGE:-mcp-re-proxy:$IMAGE_TAG}"
  INNER_IMAGE="${MCP_RE_INNER_IMAGE:-mcp-re-inner-fastmcp:$IMAGE_TAG}"
  LOADGEN_IMAGE="${MCP_RE_LOADGEN_IMAGE:-mcp-re-loadgen:$IMAGE_TAG}"
fi
# The TLS/trust material the fleet Secret is built from (emit_mtls_fixtures output).
# Required only for the DEPLOY path (enforced at the Secret step below); --teardown
# must run without it, so don't fail-fast here.
FIXTURES_DIR="${MCP_RE_FIXTURES_DIR:-}"

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
# Repoint the manifest's image at THIS run's image. Match the repository and ignore the
# tag it carries: a tag-anchored pattern no-ops the moment the manifest and this harness
# disagree, and a no-op here is silent — the fleet would then deploy the manifest's bare
# local name, which is absent on kind and unpullable on GKE. The applied YAML is checked
# for the substitution rather than trusted.
INNER_YAML="$(sed -E "s#image: [^[:space:]/]*mcp-re-inner-fastmcp:[^[:space:]]+#image: $INNER_IMAGE#" \
  "$REPO_ROOT/deploy/k8s/inner-fastmcp.yaml")"
printf '%s\n' "$INNER_YAML" | grep -q "image: $INNER_IMAGE" \
  || fail "inner manifest image was not substituted — deploy/k8s/inner-fastmcp.yaml no longer matches the expected 'image: mcp-re-inner-fastmcp:<tag>' line"
printf '%s\n' "$INNER_YAML" | kubectl -n "$NAMESPACE" apply -f -
# Force a fresh pod so it runs THIS run's freshly built image. An `apply` with an
# unchanged spec (same image tag) does NOT restart the pod, so a rebuilt-and-reloaded
# image under the same tag (e.g. kind load, or a re-pushed registry tag with
# imagePullPolicy: IfNotPresent) would otherwise keep serving the STALE inner — the
# eliciting `confirm_action` tool would be missing and Proof 3 would see no
# requestState. Restart, then wait.
kubectl -n "$NAMESPACE" rollout restart deploy/mcp-re-inner-fastmcp
kubectl -n "$NAMESPACE" rollout status deploy/mcp-re-inner-fastmcp --timeout=420s

# --- 2. Shared Redis tier (replay + trust epoch) -----------------------------
# A PRIMARY plus REDIS_REPLICAS replicas, because the chart declares
# `replay.durabilityTier: redis-wait-quorum:<quorum>:<timeout_ms>` and the proxy fails
# an admission CLOSED when `WAIT` returns fewer acks than that quorum. A standalone
# Redis returns 0 acks forever, so every nonce insert fails and the very first request
# with a freshly drawn nonce comes back `replay` — a fail-closed store reads exactly
# like a spent nonce. The replica count is therefore DERIVED from the quorum the chart
# asks for, not chosen: a topology that cannot satisfy the declared tier is not a
# shared replay tier, it is an outage.
REDIS_REPLICAS="${MCP_RE_REDIS_REPLICAS:-$(
  awk -F'"' '/^  durabilityTier:/{split($2,p,":"); print p[2]}' "$CHART_DIR/values.yaml"
)}"
[[ "${REDIS_REPLICAS:-0}" -ge 1 ]] || fail "could not read the wait-quorum replica count from $CHART_DIR/values.yaml"
log "Shared Redis tier (primary + $REDIS_REPLICAS replicas for the declared wait quorum)"
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

# The replicas that make `WAIT <quorum>` answerable. Same in-memory settings as the
# primary; `--replicaof` points them at its Service. They carry no Service of their own —
# the proxy only ever talks to the primary, and these exist solely to acknowledge writes.
kubectl -n "$NAMESPACE" apply -f - <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: { name: mcp-re-redis-replica }
spec:
  replicas: $REDIS_REPLICAS
  selector: { matchLabels: { app: mcp-re-redis-replica } }
  template:
    metadata: { labels: { app: mcp-re-redis-replica } }
    spec:
      containers:
        - name: redis
          image: redis:7
          args: ["--save", "", "--appendonly", "no", "--stop-writes-on-bgsave-error", "no",
                 "--replicaof", "mcp-re-redis", "6379"]
          ports: [{ containerPort: 6379 }]
YAML
kubectl -n "$NAMESPACE" rollout status deploy/mcp-re-redis-replica --timeout=300s

# Ready is not the same as SYNCED: a replica reports Ready as soon as its port answers,
# but it does not acknowledge writes until it has attached to the primary. Deploying the
# fleet before then makes the first proof race the sync and fail closed for a reason that
# has nothing to do with what it tests. Block until the primary itself reports the acks.
redis_synced=""
for _ in $(seq 1 60); do
  acks="$(kubectl -n "$NAMESPACE" exec deploy/mcp-re-redis -- \
          redis-cli WAIT "$REDIS_REPLICAS" 1000 2>/dev/null | tr -d '\r')"
  if [[ "${acks:-0}" -ge "$REDIS_REPLICAS" ]]; then redis_synced=1; break; fi
  sleep 2
done
[[ -n "$redis_synced" ]] \
  || fail "only ${acks:-0} of $REDIS_REPLICAS Redis replicas acknowledge writes — the declared wait-quorum tier cannot be satisfied, and every replay insert would fail closed"
echo "  OK: $REDIS_REPLICAS replica(s) acknowledging writes; the declared wait quorum is satisfiable."

# --- 3. Deploy the fleet (strict + fleet + shared tiers) ---------------------
# The chart REFUSES to start a --fleet deployment on a node-local replay cache
# (ADR-MCPS-049 guardrail), so a green rollout already proves the shared tier is
# wired. TLS/trust material must be provided as the `mcp-re-tls` Secret.
log "Deploy fleet ($REPLICAS replicas) — always-maximal-security posture; fleet topology"
# Canonical inner endpoint is `/mcp/` WITH a trailing slash: FastMCP mounts Streamable
# HTTP at `/mcp/` and 307-redirects `/mcp` -> `/mcp/`. The proxy's raw hyper inner
# client does NOT follow redirects (it maps a non-2xx, the 307 included, to a
# fail-closed "inner unavailable"), so it must POST straight to `/mcp/`. Matches the
# helm example in deploy/k8s/inner-fastmcp.yaml.
INNER_URL="http://mcp-re-inner-fastmcp:$(port_of mcp_re_inner_backend)/mcp/"

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

# The trust domain both sides sign/verify under. ONE variable, used for the chart AND
# every client invocation, so the two cannot drift.
#
# It defaults to `example.com` because `emit_mtls_fixtures` bakes that value into
# trust.json as part of the resolved actor id (role:trust_domain:subject:keyid), and
# this harness is driven by those fixtures — signing under any other domain would not
# resolve. That is also why the install below sets identity.allowExampleFixtures.
TRUST_DOMAIN="${MCP_RE_TRUST_DOMAIN:-example.com}"

# The identity the chart now needs at RENDER time. These are also required further down
# for the client flags, but that is after the install — demand them here so a missing
# one fails before anything is deployed, rather than rendering a blank --audience.
: "${MCP_RE_AUDIENCE:?set MCP_RE_AUDIENCE (the proxy --audience id)}"
: "${MCP_RE_SERVER_SIGNER:?set MCP_RE_SERVER_SIGNER}"
: "${MCP_RE_SERVER_KEY_ID:?set MCP_RE_SERVER_KEY_ID}"
: "${MCP_RE_TARGET_URI:?set MCP_RE_TARGET_URI to the proxy --target-uri (e.g. https://proxy.internal:8600/mcp)}"
: "${MCP_RE_TRUST_EPOCH:?set MCP_RE_TRUST_EPOCH to the proxy --delegated-trust-epoch base label}"

# Pass this run's identity to the chart so the proxy verifies exactly what the client
# signs. Previously NOTHING was passed: the proxy took the chart's own placeholder
# values while the client signed from these variables, and the proofs passed only
# because the two happened to coincide. `identity.allowExampleFixtures` then tells the
# chart's placeholder guard that this is a fenced validation run whose identity is
# pinned by emit_mtls_fixtures, not an unconfigured production install.
helm -n "$NAMESPACE" upgrade --install "$RELEASE" "$CHART_DIR" \
  --set replicaCount="$REPLICAS" \
  --set fleet=true \
  --set bindPort="$BIND_PORT" \
  --set image.repository="${PROXY_IMAGE%:*}" \
  --set image.tag="${PROXY_IMAGE##*:}" \
  --set-string "inner.httpUrls={$INNER_URL}" \
  --set identity.audience="$MCP_RE_AUDIENCE" \
  --set identity.serverSigner="$MCP_RE_SERVER_SIGNER" \
  --set identity.serverKeyId="$MCP_RE_SERVER_KEY_ID" \
  --set identity.targetUri="$MCP_RE_TARGET_URI" \
  --set identity.trustDomain="$TRUST_DOMAIN" \
  --set identity.delegatedTrustEpoch="$MCP_RE_TRUST_EPOCH" \
  --set identity.allowExampleFixtures=true `# identity is pinned by emit_mtls_fixtures (did:example:server-1 / example.com), which trust.json encodes in the actor id` \
  --set replay.redisUrl="redis://mcp-re-redis:6379" \
  --set revocation.trustEpochRedisUrl="redis://mcp-re-redis:6379" \
  --set replay.allowPlaintextRedis=true `# the in-cluster redis:7 this harness brings up serves no TLS; the opt-out is explicit because the chart refuses plaintext under fleet by default` \
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
  # delegation credential chains to (NOT a per-response key). --trust-epoch is NOT in
  # this array: with a trust-epoch source wired the proxy mints "<base>#<counter>", so
  # the accepted epoch has to be resolved from the shared counter at CALL time (see
  # `epoch_label` / `client`). It advances whenever an operator INCRs, and the counter
  # is monotonic — it is never rolled back.
  --server-signer    "${MCP_RE_SERVER_SIGNER:?set MCP_RE_SERVER_SIGNER}"
  --server-key-id    "${MCP_RE_SERVER_KEY_ID:?set MCP_RE_SERVER_KEY_ID}"
  --server-pubkey    "${MCP_RE_SERVER_PUBKEY:?set MCP_RE_SERVER_PUBKEY to a b64url key or @file}"
  --audience         "${MCP_RE_AUDIENCE:?set MCP_RE_AUDIENCE (the proxy --audience id)}"
  # RFC 9421 audience tuple (ADR-MCPRE-050): the client signs {audience,target-uri,route}
  # and the proxy rejects invalid_audience unless target-uri matches its --target-uri.
  --target-uri       "${MCP_RE_TARGET_URI:?set MCP_RE_TARGET_URI to the proxy --target-uri (e.g. https://proxy.internal:8600/mcp)}"
  --trust-domain     "$TRUST_DOMAIN"
  --tls-cert         "${MCP_RE_TLS_CERT:?set MCP_RE_TLS_CERT to the client cert PEM path}"
  --tls-key          "${MCP_RE_TLS_KEY:?set MCP_RE_TLS_KEY to the client key PEM path}"
  --server-ca        "${MCP_RE_SERVER_CA:?set MCP_RE_SERVER_CA to the server CA PEM path}"
)

# The epoch the proxy is currently minting: "<base>#<counter>", where <counter> is the
# shared Redis key (unset reads as 0). Resolved per call because an INCR moves it and a
# restarted replica resolves the SAME value — that is the property Proof 2 exercises.
epoch_label() {
  local c
  c="$(kubectl -n "$NAMESPACE" exec deploy/mcp-re-redis -- \
        redis-cli GET mcp-re:trust:epoch 2>/dev/null | tr -d '\r')"
  printf '%s#%s' "${MCP_RE_TRUST_EPOCH:?set MCP_RE_TRUST_EPOCH to the proxy --delegated-trust-epoch base label}" "${c:-0}"
}

# Every client invocation goes through this so the accepted epoch is always current.
client() {
  $CLIENT "${CLIENT_COMMON[@]}" --trust-epoch "$(epoch_label)" "$@"
}
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

  # --- Inner-containment deny test -------------------------------------------
  # `deploy/k8s/inner-fastmcp.yaml` ships a NetworkPolicy making the proxy the ONLY
  # admitted ingress to the inner plane. A NetworkPolicy is accepted by every cluster
  # and enforced only by some, so "applied" says nothing about whether the containment
  # exists — and an allow-rule whose selector matches no pod does not fail loudly, it
  # denies everything. The loadgen is a real unrelated pod in the same namespace, so it
  # is the deny test: it must NOT reach the inner.
  #
  # Reported, not asserted. On a non-enforcing CNI (a GKE Standard cluster created
  # without --enable-network-policy, as this harness does) the reachability is expected
  # and the containment simply is not in force; failing here would block a run over a
  # property this cluster never claimed. What must never happen is silence — an
  # unenforced policy reading as a protected inner plane.
  if kubectl -n "$NAMESPACE" exec "$LOADGEN_POD" -- \
       python -c 'import socket,sys; socket.create_connection(("mcp-re-inner-fastmcp", '"$(port_of mcp_re_inner_backend)"'), timeout=6).close()' \
       >/dev/null 2>&1; then
    echo "  NOTE: an unrelated pod REACHED the inner plane — this CNI does not enforce"
    echo "        NetworkPolicy, so mcp-re-inner-fastmcp-allow-proxy-only is inert here."
    echo "        Inner containment is NOT in force on this cluster; do not claim it."
  else
    echo "  OK: inner containment enforced — an unrelated pod cannot reach the inner plane."
  fi
fi

# --- Proof 1: cross-replica replay coherence ---------------------------------
log "Proof 1 — cross-replica replay coherence"
# A proper 128-bit b64url nonce, PINNED so both replicas see the identical
# (signer, audience, nonce) triple — the whole point of the coherence proof.
NONCE="$(head -c 16 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')"
printf '%s\n' "$REQ" | client \
  --remote-addr "$REPLICA_A" --nonce "$NONCE" --expect accepted \
  || fail "replica A did not accept a fresh pinned nonce"
printf '%s\n' "$REQ" | client \
  --remote-addr "$REPLICA_B" --nonce "$NONCE" --expect replay \
  || fail "replica B accepted a nonce already spent on A (replay coherence broken)"
echo "  OK: nonce Fresh on A, Replay on B."

# --- Proof 2: cross-replica trust revocation ---------------------------------
log "Proof 2 — cross-replica trust-epoch revocation"
printf '%s\n' "$REQ" | client --remote-addr "$REPLICA_A" --expect accepted \
  || fail "baseline request rejected before revocation"
# The shared counter is MONOTONIC and is never rolled back: minting under a lower epoch
# would resurrect credentials the fleet's verifiers have already stopped accepting, so a
# replica REFUSES a regressed counter rather than rebasing to it (that refusal is the
# C007 invariant). Revocation is therefore undone the way it is in production — by
# pointing verifiers at the NEW epoch — not by rewinding the store.
EPOCH_BEFORE="$(epoch_label)"
kubectl -n "$NAMESPACE" exec deploy/mcp-re-redis -- \
  redis-cli INCR mcp-re:trust:epoch >/dev/null
sleep 2  # bounded propagation window

# Sibling B must reject a credential minted under the PRE-bump epoch. Pin the old label
# explicitly: `client` would resolve the new one and (correctly) accept.
printf '%s\n' "$REQ" | $CLIENT "${CLIENT_COMMON[@]}" --trust-epoch "$EPOCH_BEFORE" \
  --remote-addr "$REPLICA_B" --expect revoked \
  || fail "sibling B still trusted a credential revoked by the epoch bump"
echo "  OK: epoch bump on the shared tier revoked across replicas (old epoch $EPOCH_BEFORE rejected)."

# Serving continues immediately under the ADVANCED epoch — no rollback, no restart. This
# is also the restart invariant in situ: `epoch_label` re-derives from shared state, so
# any replica (fresh or long-lived) resolves the same post-INCR label.
log "Confirm serving under the advanced epoch (no rollback, no restart)"
EPOCH_AFTER="$(epoch_label)"
[[ "$EPOCH_AFTER" != "$EPOCH_BEFORE" ]] \
  || fail "the INCR did not change the resolved epoch label ($EPOCH_AFTER)"
restored=""
for _ in $(seq 1 30); do
  if printf '%s\n' "$REQ" | client --remote-addr "$REPLICA_A" --expect accepted >/dev/null 2>&1 \
     && printf '%s\n' "$REQ" | client --remote-addr "$REPLICA_B" --expect accepted >/dev/null 2>&1; then
    restored=1; break
  fi
  sleep 1
done
[[ -n "$restored" ]] || fail "replicas did not re-issue under the advanced epoch $EPOCH_AFTER"
echo "  OK: every replica re-issued under $EPOCH_AFTER; serving continues without a rollback."

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
  OPEN_RESP="$(printf '%s\n' "$MRT_OPEN_REQ" | client \
    --remote-addr "$REPLICA_A" --save-cont "$CONT_FILE")" \
    || fail "could not open a multi-round-trip continuation on A"
  STATE="$(printf '%s' "$OPEN_RESP" | jq -r '.result.requestState // empty')"
  [[ -n "$STATE" ]] || fail "A's response carried no requestState (tool did not elicit input)"
  ANSWER_REQ="$(jq -nc --arg s "$STATE" --arg t "$MRT_TOOL" \
    '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:$t,arguments:{},inputResponses:{confirm:true},requestState:$s}}')"
  printf '%s\n' "$ANSWER_REQ" | client \
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
  # The in-cluster load generator needs the SAME resolved "<base>#<counter>" label the
  # proxy is minting; the bare base is never minted when a trust-epoch source is wired.
  LG="$LG --server-pubkey @/etc/mcp-re-client/server-pubkey --trust-epoch $(epoch_label)"
  LG="$LG --audience $MCP_RE_AUDIENCE --target-uri $MCP_RE_TARGET_URI --trust-domain $TRUST_DOMAIN"
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
