# SPDX-License-Identifier: Apache-2.0
"""FastMCP Streamable-HTTP inner MCP backend — the ALLOWED inner plane for the
MCP-RE proof topology (ADR-MCPRE-051 §3).

The MCP-RE HTTP-profile proxy verifies each request, then forwards it as a
stateless Streamable-HTTP POST to a real HTTP MCP backend. This is that backend:
an ordinary FastMCP server exposing a couple of tools. It is deliberately NOT a
stdio server — stdio is compat-only (out-of-TCB bridge) and is never the
production inner plane, and never the basis for SLO/fleet/throughput claims.

Run it (port comes from the registry, config/ports.toml, never a literal):

    PORT=$(python3 -c "import tomllib,sys; \
      print(tomllib.load(open('config/ports.toml','rb'))['services']['mcp_re_inner_backend']['port'])")
    FASTMCP_JSON_RESPONSE=true FASTMCP_STATELESS_HTTP=true \
      fastmcp run tools/fastmcp_inner_backend.py:mcp \
        --transport http --host 127.0.0.1 --port "$PORT" --stateless --path /mcp/

`--stateless` matches how the proxy forwards (one independent POST per request,
no session), per mcp-re-proxy/src/http_inner.rs.

Two Streamable-HTTP details the proxy's inner client (http_inner.rs) must honor:
  * FASTMCP_JSON_RESPONSE=true makes the transport return a plain
    `application/json` JSON-RPC body instead of SSE `event: message` framing —
    the shape http_inner.rs parses. Without it, responses are `text/event-stream`.
  * The MCP SDK REQUIRES the request carry `Accept: application/json,
    text/event-stream` (both), even in JSON-response mode; a json-only Accept is
    rejected 406. The inner leg must send that Accept header.
"""

from fastmcp import FastMCP

mcp = FastMCP("mcp-re-inner-backend")


@mcp.tool
def echo(text: str) -> str:
    """Return the given text unchanged — the minimal round-trip probe."""
    return text


@mcp.tool
def add(a: int, b: int) -> int:
    """Return a + b — a trivial typed tool for schema/verify round-trips."""
    return a + b


if __name__ == "__main__":
    # Direct-run fallback (fastmcp run is the primary entry). Bind the registry
    # port; fail loudly if it is missing rather than inventing a literal.
    import os
    import tomllib

    here = os.path.dirname(os.path.abspath(__file__))
    ports = os.path.join(here, os.pardir, "config", "ports.toml")
    with open(ports, "rb") as fh:
        svc = tomllib.load(fh)["services"]["mcp_re_inner_backend"]
    port = int(os.environ.get("MCP_RE_INNER_BACKEND_PORT", svc["port"]))
    mcp.run(transport="http", host=svc["host"], port=port, stateless_http=True)
