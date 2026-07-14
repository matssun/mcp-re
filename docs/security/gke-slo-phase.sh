#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# ADR-MCPRE-051 §7 SLO baseline — the GKE phase, as ONE deterministic script.
#
# This is docs/security/gke-slo-baseline-runbook.md §4 turned into a rerunnable
# script (no copy-paste). It runs AFTER the four fleet proofs
# (gke-multi-replica-validation.sh), on the SAME Standard zonal cluster, and fits the
# free-trial 16-vCPU CPUS_ALL_REGIONS cap by dropping the 4-vCPU fleet pool and running
# the two 8-vCPU class pools concurrently (8 + 8 = 16). The SLO Job is self-contained
# (tls_load_harness_bench spawns its OWN proxy in-pod), so the live fleet is not needed
# during measurement.
#
#   docs/security/gke-slo-phase.sh                 # run the baseline (4 jobs) + gate
#   docs/security/gke-slo-phase.sh --teardown      # delete the two class pools
#
# Env: PROJECT_ID, CLUSTER, ZONE, NAMESPACE, RELEASE (defaults below); BENCH_IMG
# overrides the SLO bench image (default: current-source AR tag rebuilt by
# deploy/cloudbuild/slo-bench.yaml).
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

PROJECT_ID="${PROJECT_ID:-project-b19bbb5e-9be8-4fcb-a2f}"
CLUSTER="${CLUSTER:-mcp-re-fleet}"
ZONE="${ZONE:-us-central1-a}"
NAMESPACE="${NAMESPACE:-mcp-re}"
RELEASE="${RELEASE:-mcp-re-proxy}"
POOL_E2="pool-e2s8"; POOL_C3="pool-c3s8"
OUT_DIR="${MCP_RE_SLO_OUT_DIR:-work/slo-gke}"; mkdir -p "$OUT_DIR"
TARGETS="docs/bench/adr-051-slo-targets.json"

say() { printf '\n=== %s ===\n' "$*"; }
gke() { gcloud container "$@" --project "$PROJECT_ID" --zone "$ZONE"; }

if [[ "${1:-}" == "--teardown" ]]; then
  say "Delete SLO class pools"
  gke node-pools delete "$POOL_E2" --cluster "$CLUSTER" --quiet || true
  gke node-pools delete "$POOL_C3" --cluster "$CLUSTER" --quiet || true
  exit 0
fi

gcloud container clusters get-credentials "$CLUSTER" --project "$PROJECT_ID" --zone "$ZONE"

# --- Free the 16-vCPU cap: drop the live fleet + its default-pool nodes --------
# The proofs are already done; the SLO Job does not use the fleet Service. Removing
# the fleet's 4 vCPU lets both 8-vCPU class pools fit (8 + 8 = 16 <= 16).
say "Drop fleet (release $RELEASE) + resize default-pool to 0"
helm -n "$NAMESPACE" uninstall "$RELEASE" 2>/dev/null || true
kubectl -n "$NAMESPACE" delete deploy,svc -l app.kubernetes.io/name=mcp-re-proxy --ignore-not-found 2>/dev/null || true
gke clusters resize "$CLUSTER" --node-pool default-pool --num-nodes 0 --quiet || true

# --- Two declared-hardware class pools (idempotent create) --------------------
say "Class pools ${POOL_E2} (e2-standard-8) + ${POOL_C3} (c3-standard-8)"
gke node-pools describe "$POOL_E2" --cluster "$CLUSTER" >/dev/null 2>&1 \
  || gke node-pools create "$POOL_E2" --cluster "$CLUSTER" \
       --machine-type e2-standard-8 --num-nodes 1 --disk-size 40 --workload-metadata=GKE_METADATA
gke node-pools describe "$POOL_C3" --cluster "$CLUSTER" >/dev/null 2>&1 \
  || gke node-pools create "$POOL_C3" --cluster "$CLUSTER" \
       --machine-type c3-standard-8 --num-nodes 1 --disk-size 40 --workload-metadata=GKE_METADATA

# --- Four measurements: {e2,c3} x {1-core, 8-core}, canonical v2 envelope ------
# run_slo_job.sh pins concurrency 128 / 8000 requests (v2) and emits the machine
# report between markers. Each Job pins its pool via nodeSelector.
say "SLO Jobs (v2 envelope: concurrency 128 / 8000 requests)"
NS="$NAMESPACE" tools/slo/run_slo_job.sh "$POOL_E2" e2-standard-8 1 "$OUT_DIR/e2_1core.json"
NS="$NAMESPACE" tools/slo/run_slo_job.sh "$POOL_E2" e2-standard-8 8 "$OUT_DIR/e2_8core.json"
NS="$NAMESPACE" tools/slo/run_slo_job.sh "$POOL_C3" c3-standard-8 1 "$OUT_DIR/c3_1core.json"
NS="$NAMESPACE" tools/slo/run_slo_job.sh "$POOL_C3" c3-standard-8 8 "$OUT_DIR/c3_8core.json"

# --- Gate: capacity on the 8-core report + 1->N scaling, per class ------------
say "Gate e2-standard-8"
python3 scripts/slo_gate.py --report "$OUT_DIR/e2_8core.json" \
  --baseline "$OUT_DIR/e2_1core.json" --scaled "$OUT_DIR/e2_8core.json" --targets "$TARGETS"
say "Gate c3-standard-8"
python3 scripts/slo_gate.py --report "$OUT_DIR/c3_8core.json" \
  --baseline "$OUT_DIR/c3_1core.json" --scaled "$OUT_DIR/c3_8core.json" --targets "$TARGETS"

say "SLO baseline reports in $OUT_DIR/ — both classes gated GREEN"
