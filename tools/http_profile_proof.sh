#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end LOCAL proof of the ADR-MCPRE-050 HTTP-profile topology:
#
#   http_profile_client  --(RFC 9421 signed HTTP)-->  http_profile_proxy
#        (mcp-re-proxy example)                         (mcp-re-proxy example)
#                                                              |
#                                             verify -> replay -> forward -> sign
#                                                              v
#                                        FastMCP Streamable-HTTP backend (/mcp/)
#
# This is the ALLOWED topology: an HTTP-profile proxy that verifies, then calls a
# real Streamable-HTTP MCP backend. NOT the object/legacy path, NOT a stdio inner.
#
# Every port is resolved from config/ports.toml (the single source of truth); no
# literal is baked into the harness. Run from the repo root:
#
#   tools/http_profile_proof.sh
#
set -euo pipefail
cd "$(dirname "$0")/.."

port_of() { python3 -c "import tomllib,sys; print(tomllib.load(open('config/ports.toml','rb'))['services'][sys.argv[1]]['port'])" "$1"; }

FRONT=$(port_of mcp_re_http_profile_proxy)
INNER=$(port_of mcp_re_inner_backend)
export HPP_BIND="127.0.0.1:${FRONT}"
export HPP_INNER_URL="http://127.0.0.1:${INNER}/mcp/"
export HPP_TARGET="http://127.0.0.1:${FRONT}/mcp"

echo "ports: front=${FRONT} inner=${INNER}  (from config/ports.toml)"

pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

wait_port() { for _ in $(seq 1 50); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.2; done; return 1; }

# 1. FastMCP Streamable-HTTP inner backend (start it unless already up).
if nc -z 127.0.0.1 "${INNER}" 2>/dev/null; then
  echo "inner: FastMCP already running on ${INNER}"
else
  command -v fastmcp >/dev/null || { echo "ERROR: fastmcp not on PATH (brew install fastmcp)"; exit 1; }
  echo "inner: starting FastMCP on ${INNER}"
  FASTMCP_JSON_RESPONSE=true FASTMCP_STATELESS_HTTP=true \
    fastmcp run tools/fastmcp_inner_backend.py:mcp \
      --transport http --host 127.0.0.1 --port "${INNER}" --stateless --path /mcp/ --no-banner \
      >/tmp/hpp_fastmcp.log 2>&1 &
  pids+=($!)
  wait_port "${INNER}" || { echo "ERROR: FastMCP did not come up"; cat /tmp/hpp_fastmcp.log; exit 1; }
fi

# 2. Build + launch the HTTP-profile proxy front.
cargo build -q -p mcp-re-proxy --features redis_replay --example http_profile_proxy --example http_profile_client
echo "proxy: starting http_profile_proxy on ${FRONT}"
./target/debug/examples/http_profile_proxy >/tmp/hpp_proxy.log 2>&1 &
pids+=($!)
wait_port "${FRONT}" || { echo "ERROR: proxy did not bind"; cat /tmp/hpp_proxy.log; exit 1; }

# 3. Drive the proof (happy path + replay rejection).
echo "----- client -----"
./target/debug/examples/http_profile_client
