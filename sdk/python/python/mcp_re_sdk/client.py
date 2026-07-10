"""High-level entry point: open an MCP-RE-secured ``ClientSession`` over mTLS/HTTP.

MCP-RE is HTTP-profile only. :func:`connect_mtls_http` wraps a synchronous mTLS
``post`` in :class:`~mcp_re_sdk.http_transport.McpReHttpTransport` and hands the
resulting plain-MCP streams to ``mcp.ClientSession`` — so application code is
unchanged from ordinary MCP while every request is signed and every response
verified. (A stdio-only MCP server is fronted by an EXTERNAL plain-MCP adapter such
as FastMCP that speaks HTTP to ``mcp-re-proxy``; MCP-RE itself owns no stdio path.)
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from .transport import McpReConfig


def make_mtls_post_sync(
    host: str,
    port: int,
    *,
    server_ca: str,
    client_cert: str,
    client_key: str,
    server_name: str,
    timeout: float = 15.0,
):
    """Build a synchronous ``body -> (content_type, response_body)`` mTLS POST — one
    HTTP/1.1 POST per connection (``Connection: close``), the ``mcp-re-proxy`` wire.

    Shared by :func:`connect_mtls_http` and the live session tests so both drive the
    SAME socket path. The client authenticates with ``client_cert`` / ``client_key``
    (the cert's URI SAN is the MCP-RE signer DID) and verifies the proxy's server
    certificate against ``server_ca`` for ``server_name``.
    """
    import socket
    import ssl

    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=server_ca)
    ctx.load_cert_chain(client_cert, client_key)

    def post_sync(body: bytes) -> "tuple[str, bytes]":
        """One mTLS HTTP/1.1 POST; returns ``(content_type, response_body)``."""
        raw = socket.create_connection((host, port), timeout=timeout)
        try:
            tls = ctx.wrap_socket(raw, server_hostname=server_name)
        except Exception:
            raw.close()
            raise
        try:
            head = (
                f"POST / HTTP/1.1\r\nHost: {server_name}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode()
            tls.sendall(head + body)
            chunks: list[bytes] = []
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
            resp = b"".join(chunks)
        finally:
            tls.close()
        head_bytes, _, resp_body = resp.partition(b"\r\n\r\n")
        content_type = ""
        for line in head_bytes.split(b"\r\n"):
            name, sep, value = line.partition(b":")
            if sep and name.strip().lower() == b"content-type":
                content_type = value.strip().decode("latin-1")
                break
        return content_type, resp_body

    return post_sync


@asynccontextmanager
async def connect_mtls_http(
    host: str,
    port: int,
    config: McpReConfig,
    *,
    server_ca: str,
    client_cert: str,
    client_key: str,
    server_name: str,
    timeout: float = 15.0,
    correlation: Any = None,
    clock=None,
    nonce_factory=None,
):
    """Yield an ``mcp.ClientSession`` whose every request is one MCP-RE-signed mTLS
    POST to the production ``mcp-re-proxy`` (verified server-signed response).

    The proxy serves one HTTP/1.1 POST per mTLS connection (``Connection: close``), so each
    ``ClientSession`` request opens its own connection. ``initialize`` round-trips
    as a normal signed request; client→server notifications are dropped (the
    transport has no fire-and-forget channel and the minimal proxy never pushes).

    The client authenticates with ``client_cert`` / ``client_key`` (the cert's URI
    SAN is the MCP-RE signer DID) and verifies the proxy's server certificate against
    ``server_ca`` for ``server_name``.
    """
    from mcp import ClientSession  # lazy: keeps `import mcp_re_sdk` mcp-free

    from .http_transport import McpReHttpTransport

    post_sync = make_mtls_post_sync(
        host,
        port,
        server_ca=server_ca,
        client_cert=client_cert,
        client_key=client_key,
        server_name=server_name,
        timeout=timeout,
    )
    transport = McpReHttpTransport(
        post_sync, config, correlation, clock=clock, nonce_factory=nonce_factory
    )
    async with transport as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            yield session
