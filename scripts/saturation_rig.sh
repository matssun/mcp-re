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

REDIS_URL="${MCP_RE_SAT_REDIS_URL:-}"
STARTED_REDIS=0
NET="mcp-re-sat-net"
PRIMARY="mcp-re-sat-redis-primary"
REPLICAS=("mcp-re-sat-redis-r1" "mcp-re-sat-redis-r2")

cleanup() {
  if (( STARTED_REDIS )); then
    docker rm -f "$PRIMARY" "${REPLICAS[@]}" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [[ -z "$REDIS_URL" ]]; then
  # The per-core serving plane REFUSES node-local replay, and `redis-wait-quorum`
  # requires a POSITIVE quorum — so a lone Redis cannot serve this rig. A primary plus
  # two replicas is the same replay posture the ADR-MCPRE-051 §7 lane uses, which keeps
  # the admission path being measured here the one that runs in the gate.
  if ! command -v docker >/dev/null 2>&1; then
    echo "saturation rig: need Docker for the replay fleet, or set MCP_RE_SAT_REDIS_URL" >&2
    exit 2
  fi
  docker rm -f "$PRIMARY" "${REPLICAS[@]}" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker network create "$NET" >/dev/null
  STARTED_REDIS=1
  docker run -d --name "$PRIMARY" --network "$NET" -p 0:6379 redis:7-alpine >/dev/null
  for r in "${REPLICAS[@]}"; do
    docker run -d --name "$r" --network "$NET" redis:7-alpine \
      redis-server --replicaof "$PRIMARY" 6379 >/dev/null
  done
  PORT="$(docker port "$PRIMARY" 6379/tcp | head -1 | sed 's/.*://')"
  REDIS_URL="redis://127.0.0.1:${PORT}"

  # Wait for BOTH replicas to be online, otherwise the first quorum write blocks for its
  # full timeout and the first sweep point measures replication lag, not the proxy.
  for _ in $(seq 1 100); do
    connected="$(docker exec "$PRIMARY" redis-cli info replication 2>/dev/null \
      | sed -n 's/^connected_slaves:\([0-9]*\).*/\1/p' | tr -d '\r')"
    [[ "${connected:-0}" -ge 2 ]] && break
    sleep 0.2
  done
  echo "saturation rig: redis primary + ${connected:-0} replica(s) up"
fi
export MCP_RE_SAT_REDIS_URL="$REDIS_URL"

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

exec target/release/examples/saturation_rig "$@"
