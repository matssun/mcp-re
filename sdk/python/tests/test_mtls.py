# SPDX-License-Identifier: Apache-2.0
"""The mTLS connect helper against a real TLS server (#413 slice 2).

The transport adapter's HTTP leg used to be entirely the caller's, which meant the one
part of the deployment that decides whether the channel is authenticated at all had no
shipped implementation and no test. This covers it end-to-end: a genuine TLS handshake
against a server holding a real certificate, with client-auth required.

The interesting cases are the refusals. A response signature verifies identically whether
or not the channel proved who produced it, so nothing above this layer can notice a
connection that was never authenticated — which is exactly why *these* assertions carry
the weight:

- a certificate from a CA the client does not trust is refused;
- a certificate the trusted CA *did* sign, for a DIFFERENT name, is refused.

The second is the one a chain-of-trust-only client passes and should not. The identity
proven is the configured ``server_name``, not wherever the socket happened to land, so
every test here dials loopback while requiring `mcp-re-proxy.test`.

Mirrors ``sdk/typescript/test/mtls.test.ts`` — same generated material, same assertions.
"""
import http.server
import socket
import ssl
import sys
import threading
from pathlib import Path

import pytest

pytest.importorskip("mcp", reason="the mtls helper builds on the transport adapter")
pytest.importorskip("cryptography", reason="the test material is minted with cryptography")

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))

from gen_mtls_test_material import SERVER_NAME, generate  # noqa: E402

from mcp_re_sdk import McpReConfig, McpReSdkError, Signer  # noqa: E402
from mcp_re_sdk.mtls import MtlsOptions, MtlsTransportError, mtls_poster  # noqa: E402

CLIENT_SEED = bytes([11]) * 32


@pytest.fixture(scope="module")
def material(tmp_path_factory):
    """Throwaway X.509, minted once per run. Never committed — see the generator."""
    return generate(tmp_path_factory.mktemp("mtls"))


class _Handler(http.server.BaseHTTPRequestHandler):
    """Echo back what arrived, so a test can assert the request survived the channel."""

    #: Set per-server: how many body bytes to reply with.
    reply_bytes = 16
    #: Extra header pairs to emit, in order, duplicates included.
    extra_headers: list = []

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler's naming
        length = int(self.headers.get("content-length", 0))
        self.rfile.read(length)
        body = b"x" * self.reply_bytes
        self.send_response(200)
        self.send_header("content-type", "application/json")
        for name, value in self.extra_headers:
            self.send_header(name, value)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # a test server that narrates every request drowns the failure output


def _serve(material: Path, cert_stem: str, key_stem: str = None, **handler_attrs):
    """A TLS server on loopback presenting `cert_stem`, requiring a client certificate."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        str(material / f"{cert_stem}.crt"), str(material / f"{key_stem or cert_stem}.key")
    )
    # Client-auth required, so a successful round trip proves the client certificate was
    # presented and accepted — not merely that the server was reachable.
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(str(material / "ca.crt"))

    handler = type("_Bound", (_Handler,), dict(handler_attrs))
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _config(port: int, **over) -> McpReConfig:
    args = dict(
        signer=Signer.software(CLIENT_SEED, "did:example:host-a", "client-key-1"),
        audience_id="verifier-1",
        target_uri=f"https://{SERVER_NAME}:{port}/mcp",
        dpop_token="access-token-xyz",
        issuer_key_id="server-key-1",
        issuer_pubkey_b64url="x" * 43,
        issuer_trust_domain="example.com",
        issuer_subject="did:example:server-1",
        verifier_audiences=["verifier-1"],
        expected_audience_hash="aud-scope-1",
        accepted_epochs=["epoch-1"],
    )
    args.update(over)
    return McpReConfig(**args)


def _options(material: Path, **over) -> MtlsOptions:
    args = dict(
        server_ca=material / "ca.crt",
        client_cert=material / "client.crt",
        client_key=material / "client.key",
        timeout=10,
    )
    args.update(over)
    return MtlsOptions(**args)


async def _post(material: Path, server, options_over=None, headers=None, body=b"{}"):
    port = server.server_address[1]
    config = _config(port)
    options = _options(material, connect_address=("127.0.0.1", port), **(options_over or {}))
    poster = mtls_poster(config, options)
    return await poster("POST", config.target_uri, headers or [], body)


@pytest.mark.anyio
async def test_a_signed_request_round_trips_over_a_verified_channel(material):
    """The happy path — and the only one that says the helper is usable at all."""
    server = _serve(material, "server")
    try:
        reply = await _post(material, server, headers=[("content-type", "application/json")])
    finally:
        server.shutdown()

    assert reply.status == 200
    assert reply.body == b"x" * 16
    # Lowercased, as the profile matches header names: the signature base is built from
    # what arrived, so the reply's headers are handed back verbatim in wire order.
    assert ("content-type", "application/json") in reply.headers


@pytest.mark.anyio
async def test_a_certificate_from_an_untrusted_root_is_refused(material):
    """Chain-of-trust: the certificate is perfectly valid — for the wrong root."""
    server = _serve(material, "foreign_server")
    try:
        with pytest.raises(MtlsTransportError) as raised:
            await _post(material, server)
    finally:
        server.shutdown()
    assert "authentication" in str(raised.value)


@pytest.mark.anyio
async def test_a_certificate_for_a_different_name_is_refused(material):
    """Identity: the TRUSTED CA signed this one — for somewhere else.

    A client that verified only the chain would accept it. That is the failure this
    assertion exists for: the whole point of naming the server is that any certificate
    the CA ever issued is not automatically this server's.
    """
    server = _serve(material, "wrongname")
    try:
        with pytest.raises(MtlsTransportError) as raised:
            await _post(material, server)
    finally:
        server.shutdown()
    assert "authentication" in str(raised.value)


@pytest.mark.anyio
async def test_an_oversized_response_is_refused(material):
    """A ceiling that fails closed, rather than buffering whatever the peer sends."""
    server = _serve(material, "server", reply_bytes=4096)
    try:
        with pytest.raises(MtlsTransportError) as raised:
            await _post(material, server, options_over={"max_response_bytes": 1024})
    finally:
        server.shutdown()
    assert "max_response_bytes" in str(raised.value)


@pytest.mark.anyio
async def test_a_repeated_response_header_is_not_folded(material):
    """Wire order, duplicates intact: the RFC 9421 signature base is built from these.

    A reader that folded repeats into one value would reconstruct a different base than
    the server signed, and the response would fail verification for a reason that has
    nothing to do with the evidence.
    """
    server = _serve(material, "server", extra_headers=[("x-repeat", "one"), ("x-repeat", "two")])
    try:
        reply = await _post(material, server)
    finally:
        server.shutdown()
    assert [v for k, v in reply.headers if k == "x-repeat"] == ["one", "two"]


@pytest.mark.anyio
async def test_a_transport_owned_header_is_refused(material):
    """Framing belongs to the transport. A caller-set `content-length` desynchronises the
    message boundary from what the peer parses — the request-smuggling shape."""
    server = _serve(material, "server")
    try:
        with pytest.raises(MtlsTransportError) as raised:
            await _post(material, server, headers=[("Content-Length", "9999")])
    finally:
        server.shutdown()
    assert "content-length" in str(raised.value)


def test_a_plaintext_target_is_refused(material):
    """An http:// target would be signed and sent in the clear, and the evidence would
    still verify — so this cannot be left to the deployment to notice."""
    with pytest.raises(McpReSdkError) as raised:
        mtls_poster(_config(443, target_uri="http://mcp-re-proxy.test/mcp"), _options(material))
    assert "https://" in str(raised.value)


@pytest.mark.anyio
async def test_connect_mtls_http_opens_a_session_transport_over_the_channel(material):
    """The one-call form: the adapter, with its HTTP leg already built and verified.

    The reply here is not signed evidence, so the exchange fails closed — which is the
    point. It proves the composition reached the network and came back through the
    adapter's verification, rather than that a stub returned something agreeable.
    """
    from mcp.shared.message import SessionMessage
    from mcp.types import JSONRPCRequest

    from mcp_re_sdk import connect_mtls_http

    server = _serve(material, "server")
    port = server.server_address[1]
    try:
        config = _config(port)
        options = _options(material, connect_address=("127.0.0.1", port))
        async with connect_mtls_http(config, options) as (read, write):
            await write.send(
                SessionMessage(JSONRPCRequest(jsonrpc="2.0", id=1, method="tools/list", params={}))
            )
            message = (await read.receive()).message
    finally:
        server.shutdown()

    assert message.error is not None, "an unsigned reply must never read as a result"


def test_a_ca_bundle_may_be_supplied_as_pem_bytes(material):
    """Material does not have to be on disk — a deployment may hold it in a secret store
    and never write it out."""
    poster = mtls_poster(
        _config(443), _options(material, server_ca=(material / "ca.crt").read_bytes())
    )
    assert callable(poster)


@pytest.mark.parametrize(
    "over, expected",
    [
        ({"max_response_bytes": 0}, "max_response_bytes"),
        ({"timeout": 0}, "timeout"),
    ],
)
def test_a_bound_that_would_refuse_everything_is_refused(material, over, expected):
    """Zero is not a degenerate throttle: a zero ceiling refuses every reply and a zero
    timeout every connection, silently, as if every server were hostile."""
    with pytest.raises(McpReSdkError) as raised:
        _options(material, **over)
    assert expected in str(raised.value)


def test_a_relative_target_is_refused(material):
    """`@target-uri` is absolute by construction; a relative one has no host to
    authenticate and nothing to dial."""
    with pytest.raises(McpReSdkError):
        mtls_poster(_config(443, target_uri="/mcp"), _options(material))


def test_an_empty_ca_bundle_is_refused(material, tmp_path):
    """An empty bundle loads without error and then trusts nothing, so every connection
    fails at the handshake looking like a server fault."""
    empty = tmp_path / "empty.pem"
    empty.write_text("")
    with pytest.raises(McpReSdkError) as raised:
        mtls_poster(_config(443), _options(material, server_ca=empty))
    assert "no certificate" in str(raised.value)


# --- the aggregate response-read bound --------------------------------------------


def test_the_response_read_is_bounded_in_wall_clock_not_only_per_recv():
    """``timeout`` on the socket is a PER-RECV bound, and per-recv bounds nothing.

    Every byte that arrives re-arms it, so a peer trickling just under it extends the
    total read without limit while holding a ``CapacityLimiter`` slot;
    ``max_concurrent_exchanges`` such responses wedge the whole client session with no
    error and no timeout. The Rust client leg this module mirrors caps total read time
    (MCPS-093 ``read_response_bounded``); this is that cap.

    Driven against ``_read_bounded`` directly rather than a live trickling TLS server:
    the property is the deadline, and a real socket adds only scheduling noise to it.
    """
    import time as _time

    from mcp_re_sdk.mtls import _read_bounded

    class _Trickle:
        """One byte per read, slower than a real peer but never idle."""

        def __init__(self) -> None:
            self.reads = 0

        def read(self, _amount: int) -> bytes:
            self.reads += 1
            _time.sleep(0.02)
            return b"x"

    options = MtlsOptions(
        server_ca=b"unused",
        client_cert="unused",
        timeout=0.2,
        max_response_bytes=1024 * 1024,
    )
    peer = _Trickle()
    started = _time.monotonic()
    with pytest.raises(MtlsTransportError) as raised:
        _read_bounded(peer, options)
    elapsed = _time.monotonic() - started
    assert "aggregate response read" in str(raised.value)
    assert elapsed < 5.0, f"the deadline did not bound the read ({elapsed:.1f}s)"
    assert peer.reads > 1, "the reader must have been making progress, not stalled"


def test_a_response_inside_both_bounds_still_reads_whole():
    """The bound refuses a trickle, not an ordinary reply delivered in chunks."""

    class _Chunked:
        def __init__(self, payload: bytes) -> None:
            self.rest = payload

        def read(self, amount: int) -> bytes:
            chunk, self.rest = self.rest[:amount], self.rest[amount:]
            return chunk

    from mcp_re_sdk.mtls import _read_bounded

    options = MtlsOptions(
        server_ca=b"unused", client_cert="unused", timeout=30.0, max_response_bytes=64
    )
    assert _read_bounded(_Chunked(b"hello world"), options) == b"hello world"

    # And the byte ceiling still fails closed, one byte past it.
    with pytest.raises(MtlsTransportError) as raised:
        _read_bounded(_Chunked(b"y" * 65), options)
    assert "max_response_bytes" in str(raised.value)


def test_no_timeout_means_no_aggregate_bound_either():
    """``timeout=None`` is the documented "no bound" knob. Honouring it on one of the two
    bounds and not the other would be a different setting wearing the same name."""

    class _Short:
        def __init__(self) -> None:
            self.done = False

        def read(self, _amount: int) -> bytes:
            if self.done:
                return b""
            self.done = True
            return b"ok"

    from mcp_re_sdk.mtls import _read_bounded

    options = MtlsOptions(
        server_ca=b"unused", client_cert="unused", timeout=None, max_response_bytes=64
    )
    assert _read_bounded(_Short(), options) == b"ok"
