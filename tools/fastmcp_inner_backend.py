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

import base64
import json
import secrets

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


# ---- MRTR eliciting tool (ADR-MCPS-047) -------------------------------------
#
# `confirm_action` implements the MCP-RE multi-round-trip convention the proxy and
# SDK understand: the FIRST leg returns an `InputRequiredResult` — a JSON-RPC result
# with `resultType == "input_required"` carrying an opaque `requestState` — and the
# ANSWER leg (the SAME tool called again with `inputResponses` + that `requestState`)
# returns a terminal result. This is NOT expressible as an ordinary FastMCP tool: a
# `@mcp.tool` return is wrapped in a `CallToolResult` envelope (`result.content` /
# `result.structuredContent`), never a raw `result.resultType`. So a thin ASGI shim
# intercepts `tools/call` for `confirm_action` and emits the exact result shape the
# proxy classifies on; every other request (echo/add, tools/list, initialize) is
# delegated to FastMCP unchanged.
#
# The tool is deliberately STATELESS: `requestState` is a self-contained opaque token
# (a per-open nonce) it never has to remember — the cross-replica continuity and the
# anti-splice binding are the PROXY's job (the shared continuation store + the
# client's signed `HttpContinuation`), not the inner application's.

_CONFIRM_TOOL = "confirm_action"


def _mint_request_state() -> str:
    """A self-contained opaque MRTR `requestState`: a per-open random token. Opaque to
    the client and digest-bound by the proxy; the inner keeps no state for it."""
    token = {"t": _CONFIRM_TOOL, "nonce": secrets.token_hex(16)}
    return base64.urlsafe_b64encode(json.dumps(token).encode()).decode().rstrip("=")


def _confirm_action_result(params: dict) -> dict:
    """Build the JSON-RPC `result` for a `confirm_action` call. An answer leg carries
    `inputResponses` (and the opaque `requestState`); an open leg carries neither and
    gets an `InputRequiredResult`."""
    if "inputResponses" in params or "requestState" in params:
        responses = params.get("inputResponses") or {}
        return {
            "resultType": "completed",
            "confirmed": bool(responses.get("confirm")),
            "content": [{"type": "text", "text": "action confirmed"}],
            "isError": False,
        }
    return {
        "resultType": "input_required",
        "requestState": _mint_request_state(),
        "elicitation": {
            "message": "Confirm the action?",
            "requestedSchema": {
                "type": "object",
                "properties": {"confirm": {"type": "boolean"}},
                "required": ["confirm"],
            },
        },
    }


class ConfirmActionShim:
    """A path-agnostic ASGI shim: intercept a JSON-RPC `tools/call` for
    `confirm_action` and answer it directly with the MRTR result shape; delegate all
    else (including lifespan/websocket and every other MCP method) to the wrapped
    FastMCP app unchanged."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return
        # Buffer the (single) request body so we can inspect it and, if not ours,
        # replay it verbatim to FastMCP.
        body = b""
        more = True
        while more:
            message = await receive()
            body += message.get("body", b"")
            more = message.get("more_body", False)
        rpc = None
        try:
            rpc = json.loads(body)
        except (ValueError, TypeError):
            rpc = None
        if (
            isinstance(rpc, dict)
            and rpc.get("method") == "tools/call"
            and isinstance(rpc.get("params"), dict)
            and rpc["params"].get("name") == _CONFIRM_TOOL
        ):
            result = _confirm_action_result(rpc["params"])
            payload = json.dumps(
                {"jsonrpc": "2.0", "id": rpc.get("id"), "result": result}
            ).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
            await send({"type": "http.response.body", "body": payload})
            return
        # Not ours — replay the buffered body to FastMCP.
        sent = False

        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, replay, send)


if __name__ == "__main__":
    # Direct-run fallback (fastmcp run is the primary entry). Bind the registry
    # port; fail loudly if it is missing rather than inventing a literal.
    import os
    import tomllib

    import uvicorn

    here = os.path.dirname(os.path.abspath(__file__))
    ports = os.path.join(here, os.pardir, "config", "ports.toml")
    with open(ports, "rb") as fh:
        svc = tomllib.load(fh)["services"]["mcp_re_inner_backend"]
    port = int(os.environ.get("MCP_RE_INNER_BACKEND_PORT", svc["port"]))
    # Host defaults to the registry (127.0.0.1 for local runs); a containerized /
    # in-cluster deploy sets MCP_RE_INNER_BACKEND_HOST=0.0.0.0 so a Service reaches it.
    host = os.environ.get("MCP_RE_INNER_BACKEND_HOST", svc["host"])
    # Build the FastMCP Streamable-HTTP app (stateless, JSON responses — the shape the
    # proxy's inner client parses) and wrap it with the MRTR eliciting-tool shim, then
    # serve. `mcp.run(...)` would build+serve internally but give no seam to wrap, so
    # we build the app explicitly and run uvicorn on the wrapped app (lifespan passes
    # through the shim to FastMCP's session manager).
    app = mcp.http_app(path="/mcp/", stateless_http=True, json_response=True)
    uvicorn.run(ConfirmActionShim(app), host=host, port=port)
