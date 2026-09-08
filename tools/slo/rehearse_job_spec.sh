#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Rehearse the EXACT ADR-MCPRE-051 §7 SLO Job spec on the local kind cluster.
#
# WHY THIS EXISTS. Both cloud runbooks stated that local-gate stage 5 "additionally
# rehearses the exact SLO Job spec this runbook schedules". It did not:
# `tools/slo/run_slo_job.sh` was invoked by no gate and by no harness — a documented
# rehearsal that nothing ran, which is the "configured is not alive" class living in the
# prose layer. This script is what makes the sentence true, and
# `scripts/rehearsal_claim_gate.py` is what keeps it true.
#
# TWO VERDICTS, AND THEY ARE NOT THE SAME VERDICT.
#
#   * THIS script decides the JOB-SPEC REHEARSAL: the manifest applies, the Redis
#     sidecars start, the bench image runs, the marker-delimited report is extracted and
#     parses, and the Job completes. That is a plumbing proposition about everything
#     between `kubectl apply` and a report on disk.
#
#   * `scripts/slo_gate.py` decides the SLO REGRESSION verdict, and only against a
#     declared hardware class. It now REFUSES a `kind-local` report outright, so the
#     throughput this rehearsal prints cannot become an SLO result by being pasted into a
#     gate invocation — the rule stopped depending on remembering it.
#
# The number below is a PLUMBING FIGURE. A single unpinned node on a developer box, with
# CPU_REQUEST lowered so the pod is schedulable at all, is not a hardware class.
#
# Usage:
#   tools/slo/rehearse_job_spec.sh [out.json]
#
# Env:
#   KIND_CLUSTER (default mcp-re-fleet)  the cluster the fleet harness created
#   NAMESPACE    (default mcp-re)        the namespace it deployed into
#   CPU_REQUEST  (default 1)             the kind node has 4 CPUs; the Job's own default
#   MEM_REQUEST  (default 512Mi)         of 6 CPU / 2Gi is unschedulable there
#   REBUILD_BENCH=1                      rebuild the bench image even if the tag exists
set -uo pipefail
cd "$(dirname "$0")/../.."

VERSION="$(tr -d '[:space:]' < VERSION)"
IMAGE="mcp-re-slo-bench:$VERSION"
KIND_CLUSTER="${KIND_CLUSTER:-mcp-re-fleet}"
NAMESPACE="${NAMESPACE:-mcp-re}"
OUT="${1:-$(mktemp -d)/kind_1core.json}"

verdict() { printf '\nJOB SPEC REHEARSAL: %s\n' "$1"; }
fail() { echo "  $1" >&2; verdict "FAIL"; exit 1; }

# The disk floor first, and with its own verdict. This lane is the documented cause of the
# v0.17 incident: with the Docker VM full the rollout completes, the Redis sidecars cannot
# create their append-only directories, and the harness reports a proof failure about a
# proof that never ran.
python3 scripts/heavy_lane_disk_preflight.py --lane kind
rc=$?
if (( rc != 0 )); then verdict "INFRASTRUCTURE_UNAVAILABLE"; exit "$rc"; fi

command -v kind >/dev/null 2>&1 || fail "kind is not installed"
kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER" \
  || fail "no kind cluster named '$KIND_CLUSTER' — the rehearsal runs on the fleet the proofs left up"
kubectl get ns "$NAMESPACE" >/dev/null 2>&1 \
  || fail "namespace '$NAMESPACE' does not exist in the current kube context"

# Stage 5 builds the proxy, inner and loadgen images but NOT the bench image, and the Job
# references it by the tag VERSION names. Build it here rather than in the fleet harness:
# it is 3 GB and only this rehearsal needs it.
if [[ "${REBUILD_BENCH:-0}" == 1 ]] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "building $IMAGE (deploy/docker/Dockerfile.bench)"
  docker build -f deploy/docker/Dockerfile.bench -t "$IMAGE" . || fail "the bench image did not build"
fi

# imagePullPolicy is Never for PROVIDER=kind, so the image has to be side-loaded: a kind
# node has no registry credentials and a pull would fail with the cluster already up.
echo "loading $IMAGE into kind cluster '$KIND_CLUSTER'"
kind load docker-image "$IMAGE" --name "$KIND_CLUSTER" || fail "kind load failed"

# THE POINT OF THE WHOLE SCRIPT: the exact command the runbooks name, unmodified.
PROVIDER=kind NS="$NAMESPACE" \
  CPU_REQUEST="${CPU_REQUEST:-1}" MEM_REQUEST="${MEM_REQUEST:-512Mi}" \
  tools/slo/run_slo_job.sh - kind-local 1 "$OUT" \
  || fail "the Job did not complete or produced no extractable report"

python3 - "$OUT" <<'PY' || fail "the extracted report does not answer the rehearsal's question"
import json, sys

ACCEPTED = ("mcp-re-load-harness-report/v1", "mcp-re-load-harness-report/v2")
doc = json.load(open(sys.argv[1]))

# What the rehearsal asserts is that the PLUMBING produced a report that answers the
# question its own schema claims to answer — not that any number in it is good.
assert doc.get("schema") in ACCEPTED, f"schema {doc.get('schema')!r} is not a load-harness report"
hw = doc.get("config", {}).get("hardware_class")
assert hw == "kind-local", f"hardware_class is {hw!r}; the Job did not run under the kind profile"
r = doc["results"]
assert r["successes"] > 0, "the Job completed having served zero requests — nothing was rehearsed"
assert r["failures"] == 0, f"{r['failures']} request(s) failed inside the rehearsal"
print(f"  report OK: {r['successes']}/{r['successes'] + r['failures']} requests, "
      f"{r['throughput_rps']:.1f} rps")
print("  ^ a PLUMBING FIGURE on an unpinned developer node. Not a baseline, and "
      "scripts/slo_gate.py refuses it by hardware class.")
PY

echo "  report -> $OUT"
verdict "PASS"
