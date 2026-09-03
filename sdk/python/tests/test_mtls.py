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
import http.client
import http.server
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

import anyio
import pytest

pytest.importorskip("mcp", reason="the mtls helper builds on the transport adapter")
pytest.importorskip("cryptography", reason="the test material is minted with cryptography")

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))

from gen_mtls_test_material import SERVER_NAME, generate  # noqa: E402

from mcp_re_sdk import McpReConfig, McpReSdkError, Signer  # noqa: E402
from mcp_re_sdk.mtls import (  # noqa: E402
    MtlsOptions,
    MtlsTransportError,
    _read_bounded,
    mtls_poster,
)

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
#
# MEASURED AGAINST A REAL PEER, and the reason is the defect this section replaces. The
# control here used to drive `_read_bounded` with a fake whose `read(n)` returned ONE byte
# per call. Production `http.client.HTTPResponse.read(n)` fills to `n`, so the fake had the
# short-read semantics the real object lacks: in the test the loop's deadline check was
# reached after every byte, and against a real peer it was not reached at all until the
# whole body had arrived. The control could not fail (R9-C094) and the property it claimed
# was false (R9-C010).
#
# So the peer below is a real socket speaking real HTTP, read through a real
# `HTTPResponse`. It trickles: a valid response head, then body bytes frequently enough
# never to trip an ordinary per-recv inactivity bound, for longer than the aggregate bound
# under test. Its trickle budget is finite so a regression fails loudly instead of hanging,
# and the assertions distinguish "the deadline fired" from "the peer stopped on its own".


class _TricklingPeer:
    """A real HTTP peer that answers correctly, then feeds the body one byte at a time.

    Not a fake response object: a socket, a status line, headers, and a body that arrives
    slowly enough to outlive any aggregate bound worth testing while staying far busier
    than any per-recv inactivity bound. A fake cannot be wrong in the way the old one was,
    which is precisely why the evidence has to come from here.
    """

    def __init__(self, *, pause=0.01, budget=8.0, content_length=1_000_000, context=None):
        self.pause = pause
        self.budget = budget
        self.content_length = content_length
        self.context = context
        #: Body bytes actually written. `sent < content_length` when the client leaves is
        #: the evidence that the read ended on the deadline, not on the peer finishing.
        self.sent = 0
        self.completed = False
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self.port = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        conn = None
        try:
            conn, _ = self._listener.accept()
            if self.context is not None:
                conn = self.context.wrap_socket(conn, server_side=True)
            head = b""
            while b"\r\n\r\n" not in head:
                data = conn.recv(4096)
                if not data:
                    return
                head += data
            declared = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    declared = int(line.split(b":", 1)[1])
            body = head.split(b"\r\n\r\n", 1)[1]
            while len(body) < declared:
                data = conn.recv(4096)
                if not data:
                    break
                body += data
            conn.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"content-type: application/json\r\n"
                b"content-length: " + str(self.content_length).encode() + b"\r\n"
                b"\r\n"
            )
            end = time.monotonic() + self.budget
            while self.sent < self.content_length and time.monotonic() < end:
                conn.sendall(b"x")
                self.sent += 1
                time.sleep(self.pause)
            self.completed = self.sent >= self.content_length
        except OSError:
            # The client hung up mid-trickle, which is the outcome under test.
            pass
        finally:
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self):
        self._listener.close()


class _PromptPeer(_TricklingPeer):
    """The same real peer, answering a whole body at once. The positive mirror.

    Without it every assertion above is satisfied by a reader that refuses everything,
    and a bound that refuses ordinary responses is not a bound.
    """

    def __init__(self, *, payload=b"y" * 4096, context=None):
        self.payload = payload
        super().__init__(pause=0, budget=0, content_length=len(payload), context=context)

    def _serve(self):
        conn = None
        try:
            conn, _ = self._listener.accept()
            if self.context is not None:
                conn = self.context.wrap_socket(conn, server_side=True)
            head = b""
            while b"\r\n\r\n" not in head:
                data = conn.recv(4096)
                if not data:
                    return
                head += data
            declared = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    declared = int(line.split(b":", 1)[1])
            body = head.split(b"\r\n\r\n", 1)[1]
            while len(body) < declared:
                data = conn.recv(4096)
                if not data:
                    break
                body += data
            conn.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"content-type: application/json\r\n"
                b"content-length: " + str(len(self.payload)).encode() + b"\r\n"
                b"\r\n" + self.payload
            )
            self.sent = len(self.payload)
            self.completed = True
        except OSError:
            pass
        finally:
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass


def _real_response(peer, *, socket_timeout):
    """A real `http.client.HTTPResponse` from `peer`, with its connection.

    The connection's own timeout is the PER-RECV bound. Every test below sets it far
    larger than the aggregate bound under test, so nothing here can pass because the
    per-recv bound fired: what terminates the read is the aggregate deadline or nothing.
    """
    connection = http.client.HTTPConnection("127.0.0.1", peer.port, timeout=socket_timeout)
    connection.request("POST", "/mcp", body=b"{}", headers={"content-length": "2"})
    return connection, connection.getresponse()


def test_the_aggregate_read_deadline_holds_against_a_real_trickling_peer():
    """The aggregate bound terminates a trickle the per-recv bound never notices.

    The peer sends a byte every 10ms against a 5s per-recv bound, so the socket is never
    idle long enough to time out; the only thing that can end this read is the aggregate
    deadline. Remove that enforcement and the read runs for the peer's whole budget and
    this test goes red — which is the property the fake it replaced could not have.
    """
    peer = _TricklingPeer(pause=0.01, budget=8.0)
    connection, response = _real_response(peer, socket_timeout=5.0)
    options = MtlsOptions(
        server_ca=b"unused", client_cert="unused", timeout=0.5, max_response_bytes=1024 * 1024
    )
    started = time.monotonic()
    try:
        with pytest.raises(MtlsTransportError) as raised:
            _read_bounded(response, options)
        elapsed = time.monotonic() - started
    finally:
        connection.close()
        peer.close()

    assert "aggregate response read" in str(raised.value)
    # It fired ON the deadline: not before it, and nowhere near the peer's 8s budget. An
    # exchange that ended because the peer stopped would land at the budget, not here.
    assert 0.4 <= elapsed < 3.0, f"the aggregate deadline did not bound the read ({elapsed:.2f}s)"
    assert not peer.completed, "the peer finished its body; this measured nothing"
    assert peer.sent > 1, "the peer never trickled; the read stalled rather than progressing"


def test_the_full_mtls_path_bounds_a_trickling_peer(material):
    """The same property through the shipped poster, over real TLS.

    `_read_bounded` is reached from exactly one place, and it is this one. Here the
    aggregate and per-recv bounds are the single `options.timeout` a deployment sets, so
    what is measured is the configuration a caller actually writes.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(material / "server.crt"), str(material / "server.key"))
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(str(material / "ca.crt"))
    peer = _TricklingPeer(pause=0.01, budget=8.0, context=context)

    poster = mtls_poster(
        _config(peer.port),
        _options(material, timeout=0.6, connect_address=("127.0.0.1", peer.port)),
    )
    started = time.monotonic()
    try:
        with pytest.raises(MtlsTransportError) as raised:
            anyio.run(poster, "POST", f"https://{SERVER_NAME}:{peer.port}/mcp", [], b"{}")
        elapsed = time.monotonic() - started
    finally:
        peer.close()

    assert "aggregate response read" in str(raised.value)
    assert elapsed < 4.0, f"the shipped path did not bound the read ({elapsed:.2f}s)"
    assert not peer.completed, "the peer finished its body; this measured nothing"


class _SilentPeer(_TricklingPeer):
    """A peer that answers, sends a few bytes, and then stops without closing.

    The other half of the composed bound. `read1` returns control to the deadline check
    after every byte a peer sends — so a peer that sends NOTHING is the one case the loop
    cannot observe, and what ends it is the per-recv timeout `http.client` already
    carries. Left unmeasured, that case is where "the read is bounded" quietly becomes
    "the read is bounded while the peer keeps talking".
    """

    def __init__(self, *, hold=30.0, context=None):
        self.hold = hold
        super().__init__(pause=0, budget=0, content_length=1_000_000, context=context)

    def _serve(self):
        conn = None
        try:
            conn, _ = self._listener.accept()
            if self.context is not None:
                conn = self.context.wrap_socket(conn, server_side=True)
            head = b""
            while b"\r\n\r\n" not in head:
                data = conn.recv(4096)
                if not data:
                    return
                head += data
            conn.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"content-type: application/json\r\n"
                b"content-length: " + str(self.content_length).encode() + b"\r\n"
                b"\r\nxxx"
            )
            self.sent = 3
            # Held open and silent. Closing would give the reader an EOF to act on, which
            # is the case that is NOT under test.
            time.sleep(self.hold)
        except OSError:
            pass
        finally:
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass


def test_a_peer_that_goes_silent_is_ended_by_the_per_recv_bound():
    """The composed bound's worst case, measured rather than asserted.

    A silent peer is invisible to a deadline checked between reads, so this is the half
    the per-recv timeout owns. The whole read still ends within the stated worst case —
    the aggregate deadline plus one per-recv stall — instead of holding an exchange and
    its concurrency slot until the peer feels like closing.
    """
    peer = _SilentPeer(hold=30.0)
    connection, response = _real_response(peer, socket_timeout=0.5)
    options = MtlsOptions(
        server_ca=b"unused", client_cert="unused", timeout=0.5, max_response_bytes=1024 * 1024
    )
    started = time.monotonic()
    try:
        with pytest.raises((MtlsTransportError, TimeoutError, OSError)):
            _read_bounded(response, options)
        elapsed = time.monotonic() - started
    finally:
        connection.close()
        peer.close()

    # Bounded by `2 * timeout` in the worst case, and nowhere near the peer's 30s hold.
    assert elapsed < 2.0, f"a silent peer held the read open ({elapsed:.2f}s)"


def test_a_response_inside_both_bounds_still_reads_whole():
    """The bound refuses a trickle, not an ordinary reply — measured on the same peer."""
    peer = _PromptPeer(payload=b"hello world")
    connection, response = _real_response(peer, socket_timeout=5.0)
    options = MtlsOptions(
        server_ca=b"unused", client_cert="unused", timeout=30.0, max_response_bytes=64
    )
    try:
        assert _read_bounded(response, options) == b"hello world"
    finally:
        connection.close()
        peer.close()


def test_the_byte_ceiling_still_fails_closed_one_byte_past_it():
    """The two bounds are independent: the ceiling holds with the clock nowhere near."""
    peer = _PromptPeer(payload=b"y" * 65)
    connection, response = _real_response(peer, socket_timeout=5.0)
    options = MtlsOptions(
        server_ca=b"unused", client_cert="unused", timeout=30.0, max_response_bytes=64
    )
    try:
        with pytest.raises(MtlsTransportError) as raised:
            _read_bounded(response, options)
    finally:
        connection.close()
        peer.close()
    assert "max_response_bytes" in str(raised.value)


def test_no_timeout_means_no_aggregate_bound_either():
    """``timeout=None`` is the documented "no bound" knob. Honouring it on one of the two
    bounds and not the other would be a different setting wearing the same name.

    Measured on the prompt peer: with no deadline the read still completes, and nothing
    narrows the socket's own timeout — there is no remaining time to narrow it to.
    """
    peer = _PromptPeer(payload=b"ok")
    connection, response = _real_response(peer, socket_timeout=5.0)
    options = MtlsOptions(
        server_ca=b"unused", client_cert="unused", timeout=None, max_response_bytes=64
    )
    try:
        assert _read_bounded(response, options) == b"ok"
    finally:
        connection.close()
        peer.close()
