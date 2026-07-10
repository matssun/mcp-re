"""A minimal, MCP-RE-unaware HTTP MCP backend for the live mTLS e2e tests.

MCP-RE is HTTP-profile only: the real ``mcp-re-proxy`` verifies each signed request
and forwards the stripped, verified-context-injected plain JSON-RPC over HTTP to a
stateless inner backend (``--inner-http-url``), then signs the backend's response.
This is the HTTP analogue of the (removed) stdio ``mcp-re-demo-fileserver`` fixture:
a tiny threaded ``http.server`` that speaks plain MCP JSON-RPC over one POST per
request and implements exactly the surface the e2e tests drive —

  * ``initialize``  → an ``InitializeResult`` (protocol version + server info);
  * ``tools/call`` ``read_file``    → the file's text as an MCP tool result;
  * ``tools/call`` ``delete_files`` → an ADR-MCPS-047 elicit/answer continuation:
      - no ``inputResponses``           → an ``InputRequiredResult`` (non-terminal),
        the pending paths encoded into the opaque ``requestState``;
      - ``inputResponses`` + ``requestState`` → the terminal result (dry-run; the
        demo never touches a filesystem).

The backend is MCP-RE-unaware — it never inspects the injected ``params._meta``; the
proxy owns all signing/verification. ``requestState`` is opaque to the proxy and the
client (echoed verbatim), meaningful only to this backend, which decodes it to
resume — the same hand-rolled hex-of-JSON scheme the old fileserver used.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "mcp-re-http-inner-demo"
# The text every read_file returns (the tests write this into the demo root, but the
# stateless demo backend simply echoes it — it proves the round trip, not a real FS).
FILE_TEXT = "hello from the inner http backend\n"


def _encode_request_state(paths: list) -> str:
    """Encode the pending paths as an opaque ``requestState``: lowercase hex of the
    JSON-array bytes (dependency-free, mirrors the removed fileserver)."""
    return json.dumps(paths, separators=(",", ":")).encode().hex()


def _decode_request_state(state: str) -> "list | None":
    """Decode a ``requestState`` back to the pending paths, or ``None`` if it is not
    valid hex of a JSON array (a tampered/foreign token — refused by the caller)."""
    try:
        raw = bytes.fromhex(state)
    except ValueError:
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, list) else None


def _read_file_result() -> dict:
    return {
        "content": [{"type": "text", "text": FILE_TEXT}],
        "structuredContent": {"content": FILE_TEXT, "size": len(FILE_TEXT)},
        "isError": False,
    }


def _delete_files_elicit(paths: list) -> dict:
    return {
        "resultType": "inputRequired",
        "inputRequests": {
            "confirm": {
                "type": "elicitation",
                "message": f"Delete {len(paths)} file(s)?",
                "schema": {"type": "boolean"},
            }
        },
        "requestState": _encode_request_state(paths),
    }


def _delete_files_terminal(paths: list, responses: dict, request_state: str) -> dict:
    state_paths = _decode_request_state(request_state)
    if state_paths != paths:
        return {
            "content": [{"type": "text", "text": "delete_files requestState invalid"}],
            "isError": True,
        }
    confirmed = bool(isinstance(responses, dict) and responses.get("confirm") is True)
    return {
        "content": [
            {"type": "text", "text": "deleted (dry-run)" if confirmed else "deletion declined"}
        ],
        "structuredContent": {"deleted": paths if confirmed else [], "confirmed": confirmed},
        "isError": False,
    }


def _dispatch(request: dict) -> dict:
    method = request.get("method")
    params = request.get("params") or {}
    if method == "initialize":
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": "0"},
        }
    if method == "tools/list":
        # No `outputSchema` on purpose: the MCP client validates a tool's
        # structuredContent against its outputSchema (calling tools/list to find it);
        # omitting it keeps this MCP-RE-unaware fixture from also owning schemas.
        return {
            "tools": [
                {
                    "name": "read_file",
                    "description": "Read a UTF-8 text file's contents.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                    },
                },
                {
                    "name": "delete_files",
                    "description": "Delete files (elicits confirmation first; dry-run).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"paths": {"type": "array", "items": {"type": "string"}}},
                        "required": ["paths"],
                    },
                },
            ]
        }
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if name == "read_file":
            return _read_file_result()
        if name == "delete_files":
            paths = arguments.get("paths") or []
            if "inputResponses" not in params:
                return _delete_files_elicit(paths)
            return _delete_files_terminal(
                paths, params.get("inputResponses"), params.get("requestState", "")
            )
    # Unknown method/tool: an in-band tool error keeps the wire well-formed.
    return {"content": [{"type": "text", "text": f"unknown method {method}"}], "isError": True}


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 (http.server API)
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            request = {}
        response = {"jsonrpc": "2.0", "id": request.get("id"), "result": _dispatch(request)}
        payload = json.dumps(response, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args) -> None:  # silence per-request stderr logging
        pass


def start_inner_backend() -> "tuple[str, ThreadingHTTPServer]":
    """Start the inner backend on an ephemeral 127.0.0.1 port. Returns
    ``(inner_http_url, server)``; call ``server.shutdown()`` to stop it."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    return f"http://{host}:{port}/mcp", server
