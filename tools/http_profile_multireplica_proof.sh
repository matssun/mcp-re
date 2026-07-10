#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Multi-replica proof of the ADR-MCPRE-050 HTTP-profile fleet: TWO proxy replicas
# behind ONE shared Redis replay tier (redis-wait-quorum), proving CROSS-REPLICA
# replay detection — the horizontal-scaling security linchpin.
#
#   client --sign once--> replica A (8601) : ACCEPTED (nonce admitted to shared Redis)
#          --same request-> replica B (8602): REJECTED replay (B sees A's nonce)
#
# Both replicas run fleet-strict with a declared redis-wait-quorum:2:2000 tier; the
# Redis primary + 2 replicas provide the WAIT quorum acks. Every port is resolved
# from config/ports.toml. Redis runs in Docker (no local redis-server needed).
#
#   tools/http_profile_multireplica_proof.sh
#
set -euo pipefail
cd "$(dirname "$0")/.."

port_of() { python3 -c "import tomllib,sys; print(tomllib.load(open('config/ports.toml','rb'))['services'][sys.argv[1]]['port'])" "$1"; }

A=$(port_of mcp_re_http_profile_proxy)
B=$(port_of mcp_re_http_profile_proxy_b)
INNER=$(port_of mcp_re_inner_backend)
REDIS=$(port_of mcp_re_redis)
NET=mcpre-redis-net
TIER="redis-wait-quorum:2:2000"

echo "ports: A=${A} B=${B} inner=${INNER} redis=${REDIS}  tier=${TIER}  (config/ports.toml)"

pids=()
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done
  docker rm -f redis-primary redis-r1 redis-r2 >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_port() { for _ in $(seq 1 50); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.2; done; return 1; }

# --- 1. Redis primary + 2 replicas (WAIT 2 quorum) ------------------------------
docker rm -f redis-primary redis-r1 redis-r2 >/dev/null 2>&1 || true
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create "$NET" >/dev/null
echo "redis: starting primary (published on ${REDIS}) + 2 replicas in Docker"
# Disk persistence is REQUIRED, not optional: the replay store's whole purpose is
# to remember seen nonces. With `--save ""` (no RDB) and `--appendonly no` a primary
# restart loses every nonce and REOPENS a replay window until the freshness window
# elapses — which contradicts the redis-wait-quorum durability tier this proof
# declares. So both primary and replicas run AOF (fsync everysec) + an RDB save
# policy. Disk persistence also makes default disk-based replication complete
# cleanly (with no persistence the replicas stall in wait_bgsave and WAIT returns 0).
PERSIST=(--appendonly yes --appendfsync everysec --save "60 1000 300 10")
docker run -d --name redis-primary --network "$NET" -p "${REDIS}:6379" redis:7-alpine \
  redis-server "${PERSIST[@]}" >/dev/null
docker run -d --name redis-r1 --network "$NET" redis:7-alpine \
  redis-server --replicaof redis-primary 6379 "${PERSIST[@]}" >/dev/null
docker run -d --name redis-r2 --network "$NET" redis:7-alpine \
  redis-server --replicaof redis-primary 6379 "${PERSIST[@]}" >/dev/null
wait_port "${REDIS}" || { echo "ERROR: redis primary not reachable on ${REDIS}"; exit 1; }

# Wait until BOTH replicas are state=online (synced), so WAIT 2 will get 2 acks.
echo -n "redis: waiting for 2 replicas online"
for _ in $(seq 1 50); do
  n=$(docker exec redis-primary redis-cli info replication 2>/dev/null | tr -d '\r' | grep -c "state=online" || true)
  [ "${n:-0}" = "2" ] && { echo " ok"; break; }
  echo -n "."; sleep 0.3
done

# --- 2. FastMCP inner backend ---------------------------------------------------
if ! nc -z 127.0.0.1 "${INNER}" 2>/dev/null; then
  command -v fastmcp >/dev/null || { echo "ERROR: fastmcp not on PATH"; exit 1; }
  echo "inner: starting FastMCP on ${INNER}"
  FASTMCP_JSON_RESPONSE=true FASTMCP_STATELESS_HTTP=true \
    fastmcp run tools/fastmcp_inner_backend.py:mcp \
      --transport http --host 127.0.0.1 --port "${INNER}" --stateless --path /mcp/ --no-banner \
      >/tmp/hpp_fastmcp.log 2>&1 &
  pids+=($!)
  wait_port "${INNER}" || { echo "ERROR: FastMCP did not come up"; exit 1; }
else
  echo "inner: FastMCP already running on ${INNER}"
fi

# --- 3. Two proxy replicas on the SHARED redis tier -----------------------------
cargo build -q -p mcp-re-proxy --features redis_replay --example http_profile_proxy --example http_profile_client

# Both replicas verify against the SAME canonical @target-uri (the logical service
# URI a load balancer fronts), so one signed request is valid at either.
export HPP_TARGET="http://mcp.local/mcp"
export HPP_INNER_URL="http://127.0.0.1:${INNER}/mcp/"
export HPP_REDIS_URL="redis://127.0.0.1:${REDIS}"
export HPP_REPLAY_TIER="${TIER}"

echo "proxy: starting replica A (${A}) and replica B (${B}) on shared redis"
HPP_BIND="127.0.0.1:${A}" ./target/debug/examples/http_profile_proxy >/tmp/hpp_proxy_a.log 2>&1 &
pids+=($!)
HPP_BIND="127.0.0.1:${B}" ./target/debug/examples/http_profile_proxy >/tmp/hpp_proxy_b.log 2>&1 &
pids+=($!)
wait_port "${A}" || { echo "ERROR: replica A did not bind"; cat /tmp/hpp_proxy_a.log; exit 1; }
wait_port "${B}" || { echo "ERROR: replica B did not bind"; cat /tmp/hpp_proxy_b.log; exit 1; }
echo "  A: $(grep -m1 replay-store /tmp/hpp_proxy_a.log || true)"

# --- 4. Drive: accept on A, replay-reject on B ----------------------------------
echo "----- client (leg 1 -> A, leg 2 -> B) -----"
HPP_POST_A="http://127.0.0.1:${A}/mcp" HPP_POST_B="http://127.0.0.1:${B}/mcp" \
  ./target/debug/examples/http_profile_client
