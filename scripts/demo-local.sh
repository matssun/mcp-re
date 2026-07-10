#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# MCP-RE — local single-node demo (no cloud credentials, no external infra).
#
# MCP-RE is HTTP-profile only. This runs the HERMETIC end-to-end proofs that
# exercise the real production path — an RFC 9421-signed client over mTLS →
# the real `mcp_re_proxy_cli` PEP → a Streamable-HTTP inner MCP backend:
#
#   * full_stack_test   — spawns the REAL mcp_re_proxy_cli over real mTLS in front
#                         of an in-process Streamable-HTTP echo backend and drives
#                         the security matrix: a signed request round-trips with a
#                         fresh injected verified-context and a bound signed
#                         response; and no-cert / untrusted-cert / tampered-object-
#                         signature / wrong-transport-binding each FAIL CLOSED.
#   * demo_mtls_client  — the host-side HostSession client drives the verifying
#                         mTLS transport against a real proxy server; wrong
#                         response hash and a forged response signature fail closed.
#
# No stdio anywhere — a stdio-only MCP server is fronted by an EXTERNAL plain-MCP
# adapter (e.g. FastMCP) that speaks HTTP to MCP-RE (see docs/CURRENT_ARCHITECTURE.md).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "== MCP-RE local HTTP-profile end-to-end (real proxy CLI over mTLS → HTTP inner) =="
cargo test --quiet -p mcp-re-proxy --test full_stack_test

echo
echo "== MCP-RE client-side mTLS + bound-response verification =="
cargo test --quiet -p mcp-re-demo --test demo_mtls_client_test

echo
echo "OK: MCP-RE local demo completed"
