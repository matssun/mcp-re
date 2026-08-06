#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Measure the serving runtime's topology (shards x workers-per-shard) ON THIS HOST.
#
#   scripts/runtime_topology_sweep.sh                      # the default matrix
#   scripts/runtime_topology_sweep.sh --shards 1,2,4 --workers 2,4,8,16
#
# ADR-MCPRE-051 §1 shards the serving plane one runtime per core, each a
# single-threaded `new_current_thread()`. That shape is not free: on the box this was
# first measured on it capped throughput at ~10.2k rps with 10.6 ms of scheduler dwell,
# against 44.8k and 47 us once each shard had a worker pool.
#
# The point of this script is that the winning topology is a property of the HOST, not a
# constant to hard-code. Cache domains, SMT, P/E-core asymmetry and epoll-vs-kqueue
# wakeup behaviour all move it, so a number measured on a laptop must not be shipped as a
# server default. Run this where the proxy will actually run.
#
# Two axes, because they are NOT interchangeable. Tokio steals work only WITHIN one
# runtime, so a task readied on a busy shard cannot be picked up by an idle worker in
# another shard. Measured at an identical 16 threads: 8 shards x 2 workers = 19,910 rps,
# 2 shards x 8 workers = 44,816 rps.
#
# This drives the saturation rig, so its numbers are NOT comparable to the
# ADR-MCPRE-051 §7 anchor (different client, warm vs cold). It answers "which topology",
# not "has performance regressed" — for that, run scripts/local_slo_lane.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

SHARDS="1,2,4,8"
WORKERS="1,2,4,8,16"
CONNECTIONS=128
REQUESTS=25000
GENERATORS=6

while [[ $# -gt 0 ]]; do
  case "$1" in
    --shards) SHARDS="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --connections) CONNECTIONS="$2"; shift 2 ;;
    --requests) REQUESTS="$2"; shift 2 ;;
    --generators) GENERATORS="$2"; shift 2 ;;
    *) echo "unknown flag $1" >&2; exit 2 ;;
  esac
done

OUT="${MCP_RE_TOPOLOGY_OUT:-target/runtime_topology.csv}"
mkdir -p "$(dirname "$OUT")"
echo "shards,workers_per_shard,threads,rps,verdict,p50_us,scheduler_latency_us,failures" > "$OUT"

echo "runtime topology sweep: shards={$SHARDS} workers={$WORKERS}"
echo "host: $(uname -sm), $(sysctl -n hw.ncpu 2>/dev/null || nproc) logical cpus"
echo

printf "%7s %8s %8s %11s %9s %10s %13s\n" \
  shards workers threads rps verdict p50_us sched_lat_us

best_rps=0; best_cfg=""
for s in ${SHARDS//,/ }; do
  for w in ${WORKERS//,/ }; do
    stages="target/topo_s${s}_w${w}.csv"
    rm -f "$stages"
    # A row whose verdict is CLIENT is a floor: the generators, not the topology, set it.
    # It is still printed, because hiding it would make the sweep look conclusive.
    row="$(MCP_RE_STAGE_TIMERS="$stages" \
           MCP_RE_SAT_OUT="target/topo_s${s}_w${w}.json" \
           MCP_RE_SAT_WORKERS_PER_SHARD="$w" \
           scripts/saturation_rig.sh --cores "$s" --fixed-generators "$GENERATORS" \
             --connections "$CONNECTIONS" --requests "$REQUESTS" 2>&1 \
           | grep -E "^ *${s} +${GENERATORS} " || true)"
    [[ -z "$row" ]] && { echo "  (no row for shards=$s workers=$w — see the rig output)"; continue; }
    rps="$(echo "$row" | awk '{print $3}')"
    verdict="$(echo "$row" | awk '{print $5}')"
    p50="$(echo "$row" | awk '{print $6}')"
    fails="$(echo "$row" | awk '{print $7}')"
    sched="$(awk -F, '$1=="scheduler_latency"{print $4}' "$stages" 2>/dev/null || echo "")"
    printf "%7s %8s %8s %11s %9s %10s %13s\n" \
      "$s" "$w" "$((s * (w > 1 ? w : 1)))" "$rps" "$verdict" "$p50" "${sched:-n/a}"
    echo "$s,$w,$((s * (w > 1 ? w : 1))),$rps,$verdict,$p50,${sched:-},$fails" >> "$OUT"
    # Only a PROXY row is a measurement of the topology; a CLIENT row cannot win.
    if [[ "$verdict" == "PROXY" ]] && awk -v a="$rps" -v b="$best_rps" 'BEGIN{exit !(a>b)}'; then
      best_rps="$rps"; best_cfg="shards=$s workers-per-shard=$w"
    fi
  done
done

echo
if [[ -n "$best_cfg" ]]; then
  echo "best saturated topology on this host: $best_cfg  (${best_rps} rps)"
  echo "  --cores ${best_cfg#shards=}" | sed 's/ workers-per-shard=/ --workers-per-shard /'
else
  echo "no row reached a PROXY verdict — every point was client-bound, so this sweep"
  echo "measured the generators. Raise --generators and re-run before reading anything."
fi
echo "wrote $OUT"
