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
# These targets are RUN BY scripts/local_gate.sh too, so the script cannot rot
# unnoticed again: it previously named two targets that had been deleted, so it
# could not exit 0 and nothing ran it.
#
# No stdio anywhere — a stdio-only MCP server is fronted by an EXTERNAL plain-MCP
# adapter (e.g. FastMCP) that speaks HTTP to MCP-RE (see docs/CURRENT_ARCHITECTURE.md).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "== MCP-RE mTLS transport binding (real rustls handshake) =="
cargo test --quiet -p mcp-re-proxy --test mtls_transport_binding_test

echo
echo "== MCP-RE client leg: signed request over verifying mTLS, bound response =="
cargo test --quiet -p mcp-re-proxy --test mtls_client_leg_e2e_test

echo
echo "== MCP-RE delegated-required round trip + fail-closed matrix =="
cargo test --quiet -p mcp-re-proxy --test delegated_client_server_e2e_test

echo
echo "== MCP-RE verified-context carrier + reserved-field guard =="
cargo test --quiet -p mcp-re-proxy --test verified_context_carrier_test

echo
echo "OK: MCP-RE local demo completed"
