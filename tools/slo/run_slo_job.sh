#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# ADR-MCPRE-051 §7 SLO baseline — run one load-harness measurement as a K8s Job
# pinned to a declared GKE machine class, then extract the machine-readable report.
#
# The Job runs the mcp-re-slo-bench image (deploy/docker/Dockerfile.bench), which
# runs tls_load_harness_bench — spawning the REAL mcp-re-proxy async fleet at
# MCP_RE_LOADGEN_CORES cores against an in-process echo backend over mTLS — under
# the pinned envelope (docs/bench/adr-051-benchmark-envelope.json).
#
# Usage:
#   tools/slo/run_slo_job.sh <node-pool> <hw-class-label> <cores> <out.json>
# e.g.
#   tools/slo/run_slo_job.sh pool-e2s8 e2-standard-8 1 e2_1core.json
#   tools/slo/run_slo_job.sh pool-e2s8 e2-standard-8 8 e2_8core.json
#
# Then gate the pair (see docs/security/gke-slo-baseline-runbook.md):
#   python3 scripts/slo_gate.py --report e2_8core.json \
#     --baseline e2_1core.json --scaled e2_8core.json \
#     --targets docs/bench/adr-051-slo-targets.json
#
# Env (override the defaults for another project/region/registry):
#   NS         (default mcp-re)          — namespace
#   BENCH_IMG  (default AR path below)   — the mcp-re-slo-bench image
set -euo pipefail

NS="${NS:-mcp-re}"
BENCH_IMG="${BENCH_IMG:-us-central1-docker.pkg.dev/project-b19bbb5e-9be8-4fcb-a2f/mcp-re/mcp-re-slo-bench:0.12.0}"

POOL="${1:?usage: run_slo_job.sh <node-pool> <hw-class> <cores> <out.json>}"
HW="${2:?hw-class label, e.g. e2-standard-8}"
CORES="${3:?cores, e.g. 1 or 8}"
OUT="${4:?output report path}"

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
      nodeSelector:
        cloud.google.com/gke-nodepool: $POOL
      # The async per-core serving plane refuses node-local replay, so the bench needs
      # a shared primary+2-replica Redis (WAIT 2 durability tier). Docker is unavailable
      # in a Job pod, so provide it as native sidecars (initContainers restartPolicy:
      # Always, GKE >=1.29) sharing the pod netns on localhost; the bench points at them
      # via MCP_RE_LOADGEN_REDIS_URL. Sidecars are torn down when the bench container exits.
      initContainers:
        - name: redis-primary
          image: redis:7-alpine
          restartPolicy: Always
          args: ["redis-server","--port","6379","--appendonly","yes"]
        - name: redis-r1
          image: redis:7-alpine
          restartPolicy: Always
          args: ["redis-server","--port","6380","--replicaof","127.0.0.1","6379","--appendonly","yes"]
        - name: redis-r2
          image: redis:7-alpine
          restartPolicy: Always
          args: ["redis-server","--port","6381","--replicaof","127.0.0.1","6379","--appendonly","yes"]
      containers:
        - name: bench
          image: $BENCH_IMG
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
            # Pin the CANONICAL v2 envelope (concurrency 128 / 8000 requests) so the
            # GKE run is the SAME involved config as the local baseline — never the
            # lighter v1 defaults. Overridable via CONCURRENCY / REQUESTS env below.
            - { name: MCP_RE_LOADGEN_CONCURRENCY, value: "${CONCURRENCY:-128}" }
            - { name: MCP_RE_LOADGEN_REQUESTS, value: "${REQUESTS:-8000}" }
          resources:
            requests: { cpu: "6", memory: "2Gi" }
YAML

echo "[$JOB] pool=$POOL hw=$HW cores=$CORES — waiting for completion..."
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
