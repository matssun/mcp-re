#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# ADR-MCPRE-051 §7 SLO baseline — run one load-harness measurement as a K8s Job
# pinned to a declared machine class, then extract the machine-readable report.
#
# The Job runs the mcp-re-slo-bench image (deploy/docker/Dockerfile.bench), which
# runs tls_load_harness_bench — spawning the REAL mcp-re-proxy async fleet at
# MCP_RE_LOADGEN_CORES cores against an in-process echo backend over mTLS — under
# the pinned envelope (docs/bench/adr-051-benchmark-envelope.json).
#
# PROVIDER selects the CLUSTER SUBSTRATE — and nothing else. The Job spec, envelope
# and report are identical on all three; only the node-pinning label and the image
# registry differ.
#
# Usage:
#   PROVIDER=gke tools/slo/run_slo_job.sh <node-pool> <hw-class-label> <cores> <out.json>
#     tools/slo/run_slo_job.sh pool-e2s8 e2-standard-8 8 e2_8core.json
#
#   PROVIDER=eks ECR_REGISTRY=<acct>.dkr.ecr.<region>.amazonaws.com \
#     tools/slo/run_slo_job.sh <nodegroup> <hw-class-label> <cores> <out.json>
#     PROVIDER=eks tools/slo/run_slo_job.sh ng-m7i2x m7i.2xlarge 8 m7i_8core.json
#
#   PROVIDER=kind tools/slo/run_slo_job.sh - kind-local 1 kind_1core.json
#     PLUMBING DRY-RUN ONLY. kind is a single unpinned node on a developer box; its
#     numbers are NOT a declarable baseline and the gate must never be fed them.
#     Use it to prove the Job spec, sidecars, image and report extraction work.
#
# Then gate the pair (see docs/security/gke-slo-baseline-runbook.md):
#   python3 scripts/slo_gate.py --report e2_8core.json \
#     --baseline e2_1core.json --scaled e2_8core.json \
#     --targets docs/bench/adr-051-slo-targets.json
#
# Env (override the defaults for another project/region/registry):
#   PROVIDER     (default gke)             — gke | eks | kind
#   NS           (default mcp-re)          — namespace
#   BENCH_IMG    (default per PROVIDER)    — the mcp-re-slo-bench image
#   ECR_REGISTRY (PROVIDER=eks)            — <acct>.dkr.ecr.<region>.amazonaws.com
#   CPU_REQUEST  (default 6)               — Job cpu request; lower it only for a
#                plumbing dry-run (kind, or a free-tier EKS node). A declared-hardware
#                measurement keeps 6 so the pod owns the class it is named after.
#   MEM_REQUEST  (default 2Gi)             — Job memory request; same rule. A 2 GiB
#                node cannot admit a 2Gi request at all (kubelet reserves some), so a
#                dry-run on one has to lower it or the pod stays Pending forever.
#   REDIS_IMG    (default redis:7-alpine)  — the sidecar image. Point it at a registry
#                mirror when the nodes cannot reach Docker Hub or would be rate-limited.
set -euo pipefail

NS="${NS:-mcp-re}"
PROVIDER="${PROVIDER:-gke}"
CPU_REQUEST="${CPU_REQUEST:-6}"
MEM_REQUEST="${MEM_REQUEST:-2Gi}"
REDIS_IMG="${REDIS_IMG:-redis:7-alpine}"
# The tag is READ FROM VERSION, never restated: deploy/cloudbuild/mcp-re-images.yaml pushes
# the image at whatever VERSION says, so a literal here goes stale on the next bump and
# the Job then references a tag the registry does not hold (ImagePullBackOff on a
# cluster that is already costing money).
BENCH_TAG="$(tr -d '[:space:]' < "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/VERSION")"

POOL="${1:?usage: run_slo_job.sh <node-pool> <hw-class> <cores> <out.json>}"
HW="${2:?hw-class label, e.g. e2-standard-8}"
CORES="${3:?cores, e.g. 1 or 8}"
OUT="${4:?output report path}"

# Substrate-specific pinning + registry. The node label is the ONE thing that cannot
# be shared: each managed control plane stamps its own pool key onto nodes. kind is a
# single unpinned node, so it carries no selector and the image is side-loaded.
PULL_POLICY="IfNotPresent"
case "$PROVIDER" in
  gke)
    NODE_SELECTOR=$'      nodeSelector:\n        cloud.google.com/gke-nodepool: '"$POOL"
    BENCH_IMG="${BENCH_IMG:-us-central1-docker.pkg.dev/project-b19bbb5e-9be8-4fcb-a2f/mcp-re/mcp-re-slo-bench:$BENCH_TAG}"
    ;;
  eks)
    NODE_SELECTOR=$'      nodeSelector:\n        eks.amazonaws.com/nodegroup: '"$POOL"
    if [ -z "${BENCH_IMG:-}" ]; then
      : "${ECR_REGISTRY:?PROVIDER=eks needs ECR_REGISTRY=<acct>.dkr.ecr.<region>.amazonaws.com (or set BENCH_IMG)}"
      BENCH_IMG="$ECR_REGISTRY/mcp-re-slo-bench:$BENCH_TAG"
    fi
    ;;
  kind)
    NODE_SELECTOR=""
    BENCH_IMG="${BENCH_IMG:-mcp-re-slo-bench:$BENCH_TAG}"
    # The image is loaded with `kind load docker-image`, never pulled: a registry
    # round-trip would fail on a cluster with no registry credentials.
    PULL_POLICY="Never"
    printf '\n*** PROVIDER=kind — PLUMBING DRY-RUN ONLY ***\n'
    printf 'A single unpinned node on a developer box is not a declared hardware class.\n'
    printf 'This report proves the Job spec runs; it is NOT a baseline and must never\n'
    printf 'be fed to scripts/slo_gate.py as one.\n\n'
    ;;
  *)
    echo "PROVIDER must be gke|eks|kind (got '$PROVIDER')" >&2; exit 2 ;;
esac

JOB="slo-$(echo "$HW" | tr -d '.-' | tr 'A-Z' 'a-z')-${CORES}c"
kubectl -n "$NS" delete job "$JOB" >/dev/null 2>&1 || true

cat <<YAML | kubectl -n "$NS" apply -f - >/dev/null
apiVersion: batch/v1
kind: Job
metadata: { name: $JOB }
spec:
  backoffLimit: 0
  completions: 1
  template:
    spec:
      restartPolicy: Never
$NODE_SELECTOR
      # The async per-core serving plane refuses node-local replay, so the bench needs
      # a shared primary+2-replica Redis (WAIT 2 durability tier). Docker is unavailable
      # in a Job pod, so provide it as native sidecars (initContainers restartPolicy:
      # Always, GKE >=1.29) sharing the pod netns on localhost; the bench points at them
      # via MCP_RE_LOADGEN_REDIS_URL. Sidecars are torn down when the bench container exits.
      initContainers:
        - name: redis-primary
          image: $REDIS_IMG
          restartPolicy: Always
          args: ["redis-server","--port","6379","--appendonly","yes"]
        - name: redis-r1
          image: $REDIS_IMG
          restartPolicy: Always
          args: ["redis-server","--port","6380","--replicaof","127.0.0.1","6379","--appendonly","yes"]
        - name: redis-r2
          image: $REDIS_IMG
          restartPolicy: Always
          args: ["redis-server","--port","6381","--replicaof","127.0.0.1","6379","--appendonly","yes"]
      containers:
        - name: bench
          image: $BENCH_IMG
          imagePullPolicy: $PULL_POLICY
          workingDir: /build
          # The image ENTRYPOINT uses a login shell that drops cargo from PATH; override
          # with an explicit PATH. Wait for the two replicas to report online (so WAIT 2
          # is satisfiable), then run ONLY tls_load_harness_bench (the file's other tests
          # need Docker) built WITH redis_replay, and emit the report between markers.
          command: ["bash","-c","export PATH=/usr/local/cargo/bin:\$PATH && sleep 8 && cargo test -p mcp-re-proxy --features async_serve,redis_replay --test tls_load_harness_bench tls_load_harness_bench -- --exact --nocapture && echo && echo '===REPORT_JSON_BEGIN===' && cat \"\$MCP_RE_LOADGEN_OUT\" && echo && echo '===REPORT_JSON_END==='"]
          env:
            - { name: MCP_RE_LOADGEN_REDIS_URL, value: "redis://127.0.0.1:6379" }
            - { name: MCP_RE_LOADGEN_HW_CLASS, value: "$HW" }
            - { name: MCP_RE_LOADGEN_CORES, value: "$CORES" }
            # ADR-MCPRE-051 §1 (amended 2026-08-06) second topology axis. Unset lets the
            # proxy auto-resolve min(8, cpus) workers per shard — the SHIPPED default,
            # which is what a CAPACITY number must be measured at.
            #
            # The SCALING run must pin WORKERS_PER_SHARD=1 instead. The gate computes
            # tput_N / (tput_1 * N) and expects >= 0.6, which assumes --cores N means N
            # serving threads. Under the default it does not: on an 8-vCPU node --cores 1
            # already resolves to 8 workers and saturates the node, so the ratio tends to
            # 1/N by construction. Measured locally at the default: 0.123 at N=8, against
            # a 0.6 floor. Pinning 1 restores cores == threads and makes the ratio mean
            # what the gate reads it as.
            - { name: MCP_RE_LOADGEN_WORKERS_PER_SHARD, value: "${WORKERS_PER_SHARD:-0}" }
            # Pin the CANONICAL v2 envelope (concurrency 128 / 8000 requests) so the
            # GKE run is the SAME involved config as the local baseline — never the
            # lighter v1 defaults. Overridable via CONCURRENCY / REQUESTS env below.
            - { name: MCP_RE_LOADGEN_CONCURRENCY, value: "${CONCURRENCY:-128}" }
            - { name: MCP_RE_LOADGEN_REQUESTS, value: "${REQUESTS:-8000}" }
          resources:
            requests: { cpu: "$CPU_REQUEST", memory: "$MEM_REQUEST" }
YAML

echo "[$JOB] provider=$PROVIDER pool=$POOL hw=$HW cores=$CORES — waiting for completion..."
# 600s: the v2 canonical envelope runs 8000 requests/run (4x the old v1 2000), so a
# 1-core run needs a wider completion window than the old lane.
kubectl -n "$NS" wait --for=condition=complete "job/$JOB" --timeout=600s 2>/dev/null \
  || kubectl -n "$NS" wait --for=condition=failed "job/$JOB" --timeout=10s 2>/dev/null || true

POD="$(kubectl -n "$NS" get pods -l job-name="$JOB" -o jsonpath='{.items[0].metadata.name}')"
kubectl -n "$NS" logs "$POD" 2>&1 \
  | sed -n '/===REPORT_JSON_BEGIN===/,/===REPORT_JSON_END===/p' | sed '1d;$d' > "$OUT"

if [ -s "$OUT" ] && python3 -c "import json,sys; json.load(open('$OUT'))" 2>/dev/null; then
  python3 -c "import json;d=json.load(open('$OUT'));r=d['results'];s=r['successes'];f=r['failures'];print('  [%s] throughput=%.1f rps  p50=%dus p99=%dus p999=%dus  success=%d/%d'%('$HW/${CORES}c',r['throughput_rps'],r['added_latency_us']['p50'],r['added_latency_us']['p99'],r['added_latency_us']['p999'],s,s+f))"
  echo "  report -> $OUT"
else
  echo "[$JOB] NO VALID REPORT — last logs:"; kubectl -n "$NS" logs "$POD" 2>&1 | tail -20; exit 1
fi
