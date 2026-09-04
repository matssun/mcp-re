# SPDX-License-Identifier: Apache-2.0
#
# The saturation rig's replay fleet, in ONE place.
#
# The per-core serving plane refuses node-local replay and `redis-wait-quorum` requires a
# POSITIVE quorum, so a lone Redis cannot serve the rig at all. A primary plus two
# replicas is the same replay posture the ADR-MCPRE-051 §7 lane uses, which is what keeps
# the admission path the rig exercises the one the gate runs.
#
# It is shared rather than copied because the liveness lane must stand up the SAME
# topology the measurement lane does. A second copy would be free to drift, and a
# liveness check running against a different posture proves nothing about the instrument
# that is actually used.
#
# Sourced, not executed. Defines:
#   sat_fleet_up   -> exports MCP_RE_SAT_REDIS_URL, or returns 2 if it cannot
#   sat_fleet_down -> tears down whatever sat_fleet_up started
#
# Honours a pre-existing MCP_RE_SAT_REDIS_URL and starts nothing in that case.

SAT_FLEET_NET="mcp-re-sat-net"
SAT_FLEET_PRIMARY="mcp-re-sat-redis-primary"
SAT_FLEET_REPLICAS=("mcp-re-sat-redis-r1" "mcp-re-sat-redis-r2")
SAT_FLEET_STARTED=0

sat_fleet_down() {
  if (( SAT_FLEET_STARTED )); then
    docker rm -f "$SAT_FLEET_PRIMARY" "${SAT_FLEET_REPLICAS[@]}" >/dev/null 2>&1 || true
    docker network rm "$SAT_FLEET_NET" >/dev/null 2>&1 || true
    SAT_FLEET_STARTED=0
  fi
}

sat_fleet_up() {
  if [[ -n "${MCP_RE_SAT_REDIS_URL:-}" ]]; then
    echo "saturation fleet: using the supplied MCP_RE_SAT_REDIS_URL"
    return 0
  fi
  if ! command -v docker >/dev/null 2>&1; then
    echo "saturation fleet: need Docker for the replay fleet, or set MCP_RE_SAT_REDIS_URL" >&2
    return 2
  fi
  docker rm -f "$SAT_FLEET_PRIMARY" "${SAT_FLEET_REPLICAS[@]}" >/dev/null 2>&1 || true
  docker network rm "$SAT_FLEET_NET" >/dev/null 2>&1 || true
  docker network create "$SAT_FLEET_NET" >/dev/null || return 2
  SAT_FLEET_STARTED=1
  docker run -d --name "$SAT_FLEET_PRIMARY" --network "$SAT_FLEET_NET" \
    -p 0:6379 redis:7-alpine >/dev/null || return 2
  local r
  for r in "${SAT_FLEET_REPLICAS[@]}"; do
    docker run -d --name "$r" --network "$SAT_FLEET_NET" redis:7-alpine \
      redis-server --replicaof "$SAT_FLEET_PRIMARY" 6379 >/dev/null || return 2
  done
  local port
  port="$(docker port "$SAT_FLEET_PRIMARY" 6379/tcp | head -1 | sed 's/.*://')"
  [[ -n "$port" ]] || { echo "saturation fleet: primary published no port" >&2; return 2; }

  # Wait for BOTH replicas to be online, otherwise the first quorum write blocks for its
  # full timeout and the first thing measured is replication lag, not the proxy.
  local connected=0
  local _i
  for _i in $(seq 1 100); do
    connected="$(docker exec "$SAT_FLEET_PRIMARY" redis-cli info replication 2>/dev/null \
      | sed -n 's/^connected_slaves:\([0-9]*\).*/\1/p' | tr -d '\r')"
    [[ "${connected:-0}" -ge 2 ]] && break
    sleep 0.2
  done
  if [[ "${connected:-0}" -lt 2 ]]; then
    echo "saturation fleet: only ${connected:-0} replica(s) attached; quorum 2 cannot be met" >&2
    return 2
  fi
  # `connected_slaves` says the replicas ATTACHED, not that they acknowledge writes.
  # Until they do, the proxy's first quorum write hits its 2000ms bound and the request
  # is refused `mcp-re.replay_cache_unavailable` — measured as exactly one refusal per
  # connection on a fleet seconds old. Probe the actual operation the replay tier
  # performs: WAIT 2, and require it to return 2.
  local acked=0
  for _i in $(seq 1 100); do
    docker exec "$SAT_FLEET_PRIMARY" redis-cli set __sat_quorum_probe 1 >/dev/null 2>&1 || true
    acked="$(docker exec "$SAT_FLEET_PRIMARY" redis-cli wait 2 500 2>/dev/null | tr -d '\r')"
    [[ "${acked:-0}" -ge 2 ]] && break
    sleep 0.2
  done
  if [[ "${acked:-0}" -lt 2 ]]; then
    echo "saturation fleet: WAIT 2 returned ${acked:-0}; the quorum the replay tier needs is not being met" >&2
    return 2
  fi
  docker exec "$SAT_FLEET_PRIMARY" redis-cli del __sat_quorum_probe >/dev/null 2>&1 || true

  export MCP_RE_SAT_REDIS_URL="redis://127.0.0.1:${port}"
  echo "saturation fleet: redis primary + ${connected} replicas acking WAIT 2 on ${MCP_RE_SAT_REDIS_URL}"
}
