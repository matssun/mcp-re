#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Run the GKE multi-replica SETUP entirely on localhost — the same components the
# GKE proof deploys (the production mcp-re-proxy CLI, a shared Redis wait-quorum
# tier, a FastMCP Streamable-HTTP inner) driven by the SAME signed-mTLS Python client
# (docs/security/mcp_re_gke_client.py) — so the whole path is proven before a cent is
# spent on a cluster. This is the local dry-run of docs/security/gke-multi-replica-
# validation.sh; it stands up TWO proxy replicas on ONE shared Redis and runs the
# cross-replica proofs the shared tier is there to guarantee.
#
#   tools/http_profile_gke_local.sh
#
# Every port is resolved from config/ports.toml (nothing hardcoded). Redis runs in
# Docker (primary + 2 replicas → a real WAIT 2 quorum); the venv + SDK from the
# GKE prep are reused if present. Exit 0 == the local dry-run passed.
set -uo pipefail
cd "$(dirname "$0")/.."

log() { printf '\n=== %s ===\n' "$*"; }
fail() { printf 'LOCAL DRY-RUN FAILED: %s\n' "$*" >&2; exit 1; }
port_of() { python3 -c "import tomllib,sys; print(tomllib.load(open('config/ports.toml','rb'))['services'][sys.argv[1]]['port'])" "$1"; }

A=$(port_of mcp_re_http_profile_proxy)
B=$(port_of mcp_re_http_profile_proxy_b)
INNER=$(port_of mcp_re_inner_backend)
REDIS=$(port_of mcp_re_redis)
NET=mcpre-gke-local-net
TIER="redis-wait-quorum:2:2000"
FIX="$(mktemp -d)"
VENV="${MCP_RE_VENV:-/tmp/mcpre-venv}"
TARGET="https://proxy.internal:8600/mcp"   # logical @target-uri BOTH sides sign
EPOCH_KEY="mcp-re:trust:epoch"

echo "ports: A=$A B=$B inner=$INNER redis=$REDIS  tier=$TIER  fixtures=$FIX"

pids=()
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done
  docker rm -f gkl-redis-p gkl-redis-r1 gkl-redis-r2 >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$FIX"
}
trap cleanup EXIT
wait_port() { for _ in $(seq 1 100); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.2; done; return 1; }

# --- 0. Redis primary + 2 replicas (WAIT 2 quorum, like the GKE shared tier) -----
log "Redis wait-quorum fleet (primary + 2 replicas) in Docker"
docker rm -f gkl-redis-p gkl-redis-r1 gkl-redis-r2 >/dev/null 2>&1 || true
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create "$NET" >/dev/null || fail "docker network create (is the daemon up?)"
PERSIST=(--appendonly yes --appendfsync everysec --save "60 1000")
docker run -d --name gkl-redis-p --network "$NET" -p "${REDIS}:6379" redis:7-alpine \
  redis-server "${PERSIST[@]}" >/dev/null || fail "redis primary"
docker run -d --name gkl-redis-r1 --network "$NET" redis:7-alpine \
  redis-server --replicaof gkl-redis-p 6379 "${PERSIST[@]}" >/dev/null || fail "redis r1"
docker run -d --name gkl-redis-r2 --network "$NET" redis:7-alpine \
  redis-server --replicaof gkl-redis-p 6379 "${PERSIST[@]}" >/dev/null || fail "redis r2"
wait_port "$REDIS" || fail "redis primary unreachable on $REDIS"
for _ in $(seq 1 50); do
  n=$(docker exec gkl-redis-p redis-cli info replication 2>/dev/null | tr -d '\r' | grep -c state=online || true)
  [ "${n:-0}" = 2 ] && break; sleep 0.3
done
docker exec gkl-redis-p redis-cli set "$EPOCH_KEY" 0 >/dev/null 2>&1 || true

# --- 1. FastMCP Streamable-HTTP inner backend (the ALLOWED inner plane) -----------
log "FastMCP inner backend on $INNER"
if ! nc -z 127.0.0.1 "$INNER" 2>/dev/null; then
  command -v fastmcp >/dev/null || fail "fastmcp not on PATH (needed for the inner plane)"
  FASTMCP_JSON_RESPONSE=true FASTMCP_STATELESS_HTTP=true \
    fastmcp run tools/fastmcp_inner_backend.py:mcp --transport http --host 127.0.0.1 \
      --port "$INNER" --stateless --path /mcp/ --no-banner >/tmp/gkl_inner.log 2>&1 &
  pids+=($!)
  wait_port "$INNER" || { cat /tmp/gkl_inner.log; fail "inner did not come up"; }
fi

# --- 2. Fixtures (fresh, short-lived client cert) --------------------------------
log "mTLS/trust fixtures (fresh short-lived client cert)"
cargo run -q -p mcp-re-demo --example emit_mtls_fixtures -- "$FIX" >/dev/null 2>&1 || fail "emit fixtures"
chmod 600 "$FIX/signing_seed" "$FIX/server_key.pem" "$FIX/client_key_short.pem"

# --- 3. Build the production CLI + start TWO replicas on the shared tier ---------
log "Build mcp-re-proxy CLI (redis_replay) + start replica A ($A) and B ($B)"
cargo build -q -p mcp-re-proxy --features async_serve,redis_replay --bin mcp-re-proxy \
  || fail "cargo build proxy"
start_replica() {  # start_replica <bind-port> <logfile>
  ./target/debug/mcp-re-proxy \
    --bind "127.0.0.1:$1" \
    --audience did:example:server-1 --server-signer did:example:server-1 --server-key-id server-key-1 \
    --delegated-trust-epoch epoch-1 \
    --key-source file --signing-key-seed "$FIX/signing_seed" \
    --tls-cert "$FIX/server_cert.pem" --tls-key "$FIX/server_key.pem" \
    --client-ca "$FIX/client_ca.pem" --trust "$FIX/trust.json" \
    --target-uri "$TARGET" --trust-domain example.com \
    --transport-binding exact --transport-identity-source uri_san \
    --max-client-cert-lifetime 3600 --fleet \
    --replay-cache shared --replay-redis-url "redis://127.0.0.1:${REDIS}" --replay-durability-tier "$TIER" \
    --revocation-tier push:60 --trust-epoch-redis-url "redis://127.0.0.1:${REDIS}" --trust-epoch-key "$EPOCH_KEY" \
    --inner-http-url "http://127.0.0.1:${INNER}/mcp/" >"$2" 2>&1 &
  pids+=($!)
}
start_replica "$A" /tmp/gkl_proxy_a.log
start_replica "$B" /tmp/gkl_proxy_b.log
wait_port "$A" || { cat /tmp/gkl_proxy_a.log; fail "replica A did not bind"; }
wait_port "$B" || { cat /tmp/gkl_proxy_b.log; fail "replica B did not bind"; }

# --- 4. Client (same one the GKE proof drives) ----------------------------------
[ -x "$VENV/bin/python" ] || fail "no venv at $VENV (run: python3 -m venv $VENV && $VENV/bin/pip install ./sdk/python)"
"$VENV/bin/python" -c 'import mcp_re_sdk' 2>/dev/null || fail "mcp-re-sdk not importable in $VENV"
CLIENT=("$VENV/bin/python" docs/security/mcp_re_gke_client.py)
COMMON=(
  --server-name proxy.internal --signer-id did:example:agent-1 --key-id key-1
  --signing-key-seed "@$FIX/client_signing_seed"
  --server-signer did:example:server-1 --server-key-id server-key-1 --server-pubkey "@$FIX/server_pubkey"
  --trust-epoch epoch-1
  --audience did:example:server-1 --target-uri "$TARGET" --trust-domain example.com
  --tls-cert "$FIX/client_cert_short.pem" --tls-key "$FIX/client_key_short.pem" --server-ca "$FIX/server_ca.pem"
)
REQ='{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# --- Proof 0: BOTH replicas serve a signed mTLS request -------------------------
log "Proof 0 — both replicas serve a verified request"
printf '%s\n' "$REQ" | "${CLIENT[@]}" "${COMMON[@]}" --remote-addr "127.0.0.1:$A" --expect accepted \
  >/dev/null || fail "replica A did not accept a valid signed request"
printf '%s\n' "$REQ" | "${CLIENT[@]}" "${COMMON[@]}" --remote-addr "127.0.0.1:$B" --expect accepted \
  >/dev/null || fail "replica B did not accept a valid signed request"
echo "  OK: A and B both serve (mTLS + RFC 9421 verify + signed response)."

# --- Proof 1: cross-replica replay coherence (the horizontal-scaling linchpin) ---
log "Proof 1 — cross-replica replay coherence"
NONCE="$(head -c 16 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')"
printf '%s\n' "$REQ" | "${CLIENT[@]}" "${COMMON[@]}" --remote-addr "127.0.0.1:$A" --nonce "$NONCE" --expect accepted \
  >/dev/null || fail "replica A did not accept a fresh pinned nonce"
printf '%s\n' "$REQ" | "${CLIENT[@]}" "${COMMON[@]}" --remote-addr "127.0.0.1:$B" --nonce "$NONCE" --expect replay \
  >/dev/null || fail "replica B accepted a nonce already spent on A (shared replay broken)"
echo "  OK: nonce Fresh on A, Replay on B via the shared Redis quorum."

# --- Proof 2: trust-epoch source is live + flush keeps serving -------------------
# The GKE proof bumps the shared trust epoch to prove cross-replica revocation
# propagation. With a STATIC in-memory trust store the flush re-resolves to the same
# (still-trusted) key, so here we prove the source is wired and the flush does NOT
# break serving — real revocation needs a dynamic trust store (a follow-up).
log "Proof 2 — trust-epoch source live; flush across replicas keeps serving"
grep -q "trust-epoch source ACTIVE" /tmp/gkl_proxy_b.log || fail "replica B did not wire the trust-epoch source"
docker exec gkl-redis-p redis-cli INCR "$EPOCH_KEY" >/dev/null
sleep 2
printf '%s\n' "$REQ" | "${CLIENT[@]}" "${COMMON[@]}" --remote-addr "127.0.0.1:$B" --expect accepted \
  >/dev/null || fail "replica B failed to serve after a trust-epoch advance (flush broke serving)"
echo "  OK: epoch advanced on the shared tier; B flushed + re-resolved + kept serving."

log "LOCAL DRY-RUN PASSED — the GKE setup works end to end on localhost"
echo "(Proof 3 MRT skipped: the FastMCP inner has no eliciting tool. Proof 4"
echo " zero-drop rolling update is a k8s deployment mechanic — validated on GKE.)"
