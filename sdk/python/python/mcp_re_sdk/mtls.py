# SPDX-License-Identifier: Apache-2.0
"""The mTLS connect helper (ADR-MCPS-044 §client obligation).

The transport adapter takes its HTTP leg as an injected ``poster`` so that layer stays
transport-agnostic and testable. This module builds the leg a real deployment needs: a
**verifying** mutual-TLS connection to ``mcp-re-proxy``.

    async with connect_mtls_http(config, options) as (read, write):
        async with ClientSession(read, write) as session:
            await session.call_tool("read_file", {"path": "/etc/hosts"})

It mirrors the Rust client leg (``mcp_re_transport::remote::MtlsRemoteTransport``), and
the properties that matter are the same ones:

- **only the configured CA authenticates the proxy.** The system trust store is never
  consulted, so a certificate from any other public or corporate root is refused.
- **the server's identity is proven, not assumed.** The certificate must be valid for
  ``server_name`` — which is what the address is dialled for, not merely where it
  answered.
- **a client certificate is presented**, for the proxy's own binding check.
- **one connection per exchange**, matching the proxy's framing.
- **every bound fails closed**: a connect/read that stalls past ``timeout``, or a
  response past ``max_response_bytes``, raises rather than hanging or allocating without
  bound.

There is no way to turn verification off. A helper with a ``verify=False`` knob is how
mTLS deployments quietly become TLS-shaped plaintext, and the evidence layer above it
cannot detect that — a response signature verifies identically whether or not the channel
proved who produced it.

The signed request is carried unchanged: MCP-RE's evidence lives in the headers and body
(RFC 9421 ``Signature``/``Signature-Input``, RFC 9530 ``Content-Digest``), so this must
transmit exactly what was signed and hand back exactly what arrived.
"""
from __future__ import annotations

import http.client
import socket
import ssl
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence, Tuple, Union
from urllib.parse import urlsplit

import anyio

from .custody import McpReSdkError
from .transport import HttpReply, McpReConfig, Poster, mcp_re_http_transport

__all__ = ["MtlsOptions", "MtlsTransportError", "connect_mtls_http", "mtls_poster"]

#: Headers this transport owns because it owns the framing. A caller that could set one
#: could desynchronise the message boundary from what the peer parses — the classic
#: request-smuggling shape — so supplying one fails closed rather than being silently
#: dropped or duplicated. Same list the Rust client refuses.
_TRANSPORT_OWNED_HEADERS = frozenset({"host", "content-length", "connection", "transfer-encoding"})

#: Default response ceiling, mirroring the proxy's own ``max_body_bytes``.
_DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024

#: Default connect/read/write bound in seconds, mirroring the Rust client's ``ClientLimits``.
_DEFAULT_TIMEOUT = 30.0


class MtlsTransportError(McpReSdkError):
    """The channel failed: handshake refused, timed out, or an over-sized response.

    A LOCAL condition, never an MCP-RE verdict. A proxy that cannot authenticate itself
    is a failed channel, not a failed signature, and it must not be reported as bad
    evidence — nothing was signed, verified, or rejected here.
    """


@dataclass(frozen=True)
class MtlsOptions:
    """The material and bounds for one verifying mTLS client."""

    #: PEM bundle of the ONLY roots trusted to authenticate the proxy. A path, or the PEM
    #: bytes themselves. The system trust store is never added to it.
    server_ca: Union[str, Path, bytes]
    #: PEM path of the client certificate chain presented to the proxy.
    client_cert: Union[str, Path]
    #: PEM path of its private key. May be omitted when the key is in ``client_cert``.
    client_key: Optional[Union[str, Path]] = None
    #: Passphrase for an encrypted ``client_key``.
    client_key_password: Optional[str] = None

    #: The identity the proxy must PROVE, matched against its certificate, and sent as
    #: SNI and in the ``Host`` header. Defaults to the host of the config's ``target_uri``.
    server_name: Optional[str] = None
    #: Where to dial, when that is not ``server_name``'s own address — a load balancer,
    #: a port-forward, a test listener. The identity proven is still ``server_name``.
    connect_address: Optional[Tuple[str, int]] = None

    #: Bound on connect and on each socket operation, in seconds. ``None`` disables it,
    #: which lets a stalled peer hold an exchange open indefinitely.
    timeout: Optional[float] = _DEFAULT_TIMEOUT
    #: Response bytes read before failing closed.
    max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES

    def __post_init__(self) -> None:
        if self.max_response_bytes < 1:
            raise McpReSdkError(
                f"max_response_bytes must be a positive integer, got {self.max_response_bytes!r}"
            )
        if self.timeout is not None and self.timeout <= 0:
            raise McpReSdkError(f"timeout must be positive or None, got {self.timeout!r}")


def _ssl_context(options: MtlsOptions) -> ssl.SSLContext:
    """A verifying client context: the configured CA only, hostname checked, mTLS on."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Stated rather than inherited. `PROTOCOL_TLS_CLIENT` sets both today, and a context
    # that silently stopped checking the certificate or the name would still complete a
    # handshake and still carry perfectly verifiable evidence.
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    try:
        if isinstance(options.server_ca, bytes):
            context.load_verify_locations(cadata=options.server_ca.decode())
        else:
            context.load_verify_locations(cafile=str(options.server_ca))
    except (OSError, ssl.SSLError, ValueError) as e:
        # Named here rather than left to surface at the first handshake, where a bundle
        # that is empty, unreadable, or not PEM at all would present as a server fault.
        raise McpReSdkError(
            f"server_ca has no certificate to authenticate the proxy with: {e}"
        ) from e

    context.load_cert_chain(
        certfile=str(options.client_cert),
        keyfile=str(options.client_key) if options.client_key is not None else None,
        password=options.client_key_password,
    )
    return context


def _origin_form(target_uri: str) -> str:
    """The origin-form request target (path + query) of an absolute ``@target-uri``.

    The signature covers the ABSOLUTE target URI; the request line carries the origin
    form of it. Both sides derive the covered value from their own configuration, so this
    conversion never feeds the signature base — it only routes the request at the peer.
    """
    parts = urlsplit(target_uri)
    if not parts.scheme or not parts.netloc:
        raise McpReSdkError(f"target_uri is not absolute: {target_uri!r}")
    return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


def _endpoint(target_uri: str, options: MtlsOptions) -> Tuple[str, int, Tuple[str, int]]:
    """The name to prove, the port, and the address to dial."""
    parts = urlsplit(target_uri)
    if parts.scheme != "https":
        # An http:// target would be signed and sent in the clear. The evidence would
        # still verify, which is exactly why this cannot be left to the deployment.
        raise McpReSdkError(
            f"connect_mtls_http needs an https:// target_uri, got {target_uri!r}"
        )
    server_name = options.server_name or parts.hostname
    if not server_name:
        raise McpReSdkError(f"target_uri has no host to authenticate: {target_uri!r}")
    port = parts.port or 443
    return server_name, port, options.connect_address or (server_name, port)


class _MtlsConnection(http.client.HTTPSConnection):
    """An HTTPS connection that dials one address and proves a possibly different name.

    ``HTTPSConnection`` derives the SNI and the certificate-name check from the address
    it dials, which collapses "where the endpoint answers" into "who it is allowed to
    be". Keeping them apart is what lets a client reach the proxy through a load
    balancer, a port-forward, or a pinned IP while still refusing any certificate not
    valid for the configured ``server_name``.
    """

    def __init__(self, server_name: str, port: int, dial: Tuple[str, int], *, context, timeout):
        super().__init__(server_name, port, context=context, timeout=timeout)
        self._dial = dial

    def connect(self) -> None:
        sock = socket.create_connection(self._dial, self.timeout)
        # `server_hostname` is BOTH the SNI sent and the name the certificate is checked
        # against, and it is `self.host` — the configured identity — not `self._dial`.
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _exchange(
    server_name: str,
    port: int,
    dial: Tuple[str, int],
    context: ssl.SSLContext,
    options: MtlsOptions,
    method: str,
    path: str,
    headers: Sequence[Tuple[str, str]],
    body: bytes,
) -> HttpReply:
    """One blocking request/response over one fresh verified connection."""
    for name, _ in headers:
        if name.lower() in _TRANSPORT_OWNED_HEADERS:
            raise MtlsTransportError(
                f"{name.lower()} is set by the transport and must not be signed into a request"
            )

    connection = _MtlsConnection(server_name, port, dial, context=context, timeout=options.timeout)
    try:
        # Built header by header rather than through `request(headers=...)`, which takes a
        # mapping and would collapse a repeated header name — dropping bytes that the
        # RFC 9421 signature covers.
        connection.putrequest(method, path, skip_accept_encoding=True)
        connection.putheader("Content-Length", str(len(body)))
        # Single request per connection, as the proxy frames it.
        connection.putheader("Connection", "close")
        for name, value in headers:
            # `putheader` refuses a CR/LF in a value, so a header that would split the
            # request into two never reaches the socket.
            connection.putheader(name, value)
        connection.endheaders(body)

        response = connection.getresponse()
        # One byte past the ceiling is enough to know it was exceeded, and stops a
        # hostile length from being allocated to find out.
        payload = response.read(options.max_response_bytes + 1)
        if len(payload) > options.max_response_bytes:
            raise MtlsTransportError(
                f"response exceeded max_response_bytes ({options.max_response_bytes})"
            )
        # Lowercased and in wire order: the profile matches header names
        # case-insensitively, and the signature base is built from what arrived.
        return HttpReply(
            status=response.status,
            headers=[(name.lower(), value) for name, value in response.getheaders()],
            body=payload,
        )
    except ssl.SSLError as e:
        # The proxy did not authenticate: an untrusted chain, a wrong identity, an
        # expired certificate. A failed channel, never a failed signature.
        raise MtlsTransportError(f"the proxy failed TLS authentication: {e}") from e
    except (socket.timeout, TimeoutError) as e:
        raise MtlsTransportError(f"the exchange timed out after {options.timeout}s: {e}") from e
    except OSError as e:
        raise MtlsTransportError(f"the connection failed: {e}") from e
    finally:
        connection.close()


def mtls_poster(config: McpReConfig, options: MtlsOptions) -> Poster:
    """A :data:`~mcp_re_sdk.transport.Poster` that sends each signed request over one
    verifying mTLS connection.

    The TLS material is loaded once, here, so bad material fails at construction rather
    than on the first request. Use this directly to compose the connection with an
    existing transport; :func:`connect_mtls_http` is the one-call form.
    """
    context = _ssl_context(options)
    server_name, port, dial = _endpoint(config.target_uri, options)

    async def post(method: str, target_uri: str, headers, body: bytes) -> HttpReply:
        # `http.client` is blocking, so the exchange runs on a worker thread. Abandoning
        # it on cancellation is the same claim `ConnectionClosed` already makes: a
        # cancelled exchange says nothing about whether the request arrived or what the
        # server did with it — only that this client will not process an answer.
        return await anyio.to_thread.run_sync(
            _exchange,
            server_name,
            port,
            dial,
            context,
            options,
            method,
            _origin_form(target_uri),
            list(headers),
            body,
            abandon_on_cancel=True,
        )

    return post


@asynccontextmanager
async def connect_mtls_http(config: McpReConfig, options: MtlsOptions, **kwargs):
    """The transport adapter over a verifying mTLS connection to the proxy.

    Yields the ``(read_stream, write_stream)`` pair ``mcp.ClientSession`` expects, exactly
    as :func:`~mcp_re_sdk.transport.mcp_re_http_transport` does — this only supplies the
    HTTP leg. Remaining keyword arguments are passed through to it.
    """
    async with mcp_re_http_transport(config, mtls_poster(config, options), **kwargs) as streams:
        yield streams
