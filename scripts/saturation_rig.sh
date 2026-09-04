#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The saturation rig: measure the proxy's OWN ceiling, and prove it is the proxy's.
#
#   scripts/saturation_rig.sh                       # keepalive, cores 1,2,4,8
#   scripts/saturation_rig.sh --mode cold
#   scripts/saturation_rig.sh --cores 1,2,4,8,12 --generators 3
#
# This is NOT the ADR-MCPRE-051 §7 lane and its numbers are NOT comparable to the §7
# anchor. §7 (scripts/local_slo_lane.sh) is a cold, self-contained REGRESSION detector
# and stays exactly as it is. This answers "how fast can the proxy go", which §7 cannot:
# its client is thread-per-connection and signs on the hot path, so it saturates itself
# long before the proxy — measured flat at ~10.4k rps across 1-8 proxy cores AND
# 128-1024 connections.
#
# Every tier is a separate process (proxy / backend / M generators) so `ps` attributes
# CPU per tier, and every sweep point is run at M and M+1 generators. A point where the
# extra generator raises throughput is reported as CLIENT — a floor, not a measurement.
set -euo pipefail
cd "$(dirname "$0")/.."

# A benchmark built by a different compiler than CI is not comparable to anything.
. scripts/use_pinned_toolchain.sh

# The replay fleet the rig requires, shared with the liveness lane so the two cannot
# drift into measuring different admission postures.
. scripts/lib/sat_replay_fleet.sh
trap sat_fleet_down EXIT
sat_fleet_up || exit 2

echo "saturation rig: building release binaries (proxy + rig)"
cargo build --release -p mcp-re-proxy --features async_serve,redis_replay --bins --examples

export MCP_RE_PROXY_CLI="target/release/mcp-re-proxy"
export CARGO_BIN_EXE_DIR="target/release/examples"
export MCP_RE_SAT_OUT="${MCP_RE_SAT_OUT:-target/saturation.json}"

# The rig co-locates every tier on one box, so an unrelated build halves the result the
# same way it does for the §7 lane. Refuse rather than silently measure noise.
CORES="$(sysctl -n hw.ncpu 2>/dev/null || nproc)"
LOAD="$(uptime | sed 's/.*load averages*: //' | awk '{print $1}' | tr -d ',')"
if awk -v l="$LOAD" -v c="$CORES" 'BEGIN{exit !(l > c*0.3)}'; then
  echo "saturation rig: load ${LOAD} on ${CORES} cores — waiting up to 300s to settle..."
  for _ in $(seq 1 60); do
    sleep 5
    LOAD="$(uptime | sed 's/.*load averages*: //' | awk '{print $1}' | tr -d ',')"
    awk -v l="$LOAD" -v c="$CORES" 'BEGIN{exit !(l > c*0.3)}' || break
  done
  echo "saturation rig: proceeding at load ${LOAD}"
fi

# Not `exec`: replacing the shell discards the EXIT trap, which would leave the replay
# fleet running after every measurement.
target/release/examples/saturation_rig "$@"
