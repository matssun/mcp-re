#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# MCP-RE — local single-node demo (no cloud credentials, no external infra).
#
# MCP-RE is HTTP-profile only. This runs the HERMETIC end-to-end proofs that
# exercise the real production path — an RFC 9421-signed client over mTLS →
# the real `mcp_re_proxy_cli` PEP → a Streamable-HTTP inner MCP backend:
#
#   * mtls_transport_binding_test — a REAL rustls mutual-TLS handshake, binding the
#                         verified request actor to the peer certificate; a
#                         mismatched binding FAILS CLOSED.
#   * mtls_client_leg_e2e_test — the client leg over a real network hop: the client
#                         proxy signs RFC 9421/9530, the verifying mTLS transport
#                         presents a client cert and pins the server, and a forged
#                         response signature fails closed.
#   * delegated_client_server_e2e_test — the full delegated-required round trip,
#                         including the replay refusal and the signed rejection.
#   * verified_context_carrier_test — the reserved-field guard and the injected
#                         verified context.
#
# These suites are RUN BY scripts/local_gate.sh too, so the script cannot rot
# unnoticed again: it previously named two targets that had been deleted, so it
# could not exit 0 and nothing ran it. Each is now a module inside a merged test
# binary, selected by name filter — see `run_suite`, which refuses a filter that
# selects nothing, because that is the same rot wearing a green coat.
#
# No stdio anywhere — a stdio-only MCP server is fronted by an EXTERNAL plain-MCP
# adapter (e.g. FastMCP) that speaks HTTP to MCP-RE (see docs/CURRENT_ARCHITECTURE.md).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Each suite is now a MODULE inside a merged test binary, so it is selected by a
# name filter rather than by being its own `--test` target. A filter that matches
# nothing exits 0, which would let this script report success having run no test —
# so every lane goes through `run_test_lane.sh`, which reads libtest's own count
# back and FAILS on zero. The CI release gates use the same wrapper; one guard
# implementation, not two that can drift apart.
run_suite() {
  local target="$1" module="$2"
  "${REPO_ROOT}/scripts/run_test_lane.sh" \
    bazel test --test_output=all --nocache_test_results "$target" --test_arg="${module}::"
}

echo "== MCP-RE mTLS transport binding (real rustls handshake) =="
run_suite //mcp-re-proxy:integration_test mtls_transport_binding_test

echo
echo "== MCP-RE client leg: signed request over verifying mTLS, bound response =="
run_suite //mcp-re-proxy:integration_async_test mtls_client_leg_e2e_test

echo
echo "== MCP-RE delegated-required round trip + fail-closed matrix =="
run_suite //mcp-re-proxy:integration_async_test delegated_client_server_e2e_test

echo
echo "== MCP-RE verified-context carrier + reserved-field guard =="
run_suite //mcp-re-proxy:integration_async_test verified_context_carrier_test

echo
echo "OK: MCP-RE local demo completed"
