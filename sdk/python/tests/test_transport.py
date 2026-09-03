# SPDX-License-Identifier: Apache-2.0
"""Offline unit tests for the transport adapter: the obligations that hold regardless of
what a counterparty says.

The live proof — a real ``mcp.ClientSession`` against the real proxy and a real FastMCP
backend — is in ``test_transport_e2e.py``; these cover the paths a happy round-trip never
reaches, with an injected ``poster`` and no network. Mirrors
``sdk/typescript/test/transport.test.ts``.

The theme throughout: **a failure must be DELIVERED, not dropped.** A transport that
swallowed a failed exchange would leave ``ClientSession`` awaiting a reply that never
comes, and a hang is a worse failure mode than a raise.
"""
import base64
import hashlib
import contextlib
import json

import anyio
import pytest

pytest.importorskip("mcp", reason="the transport adapter needs the upstream MCP SDK")

from mcp.shared.message import SessionMessage  # noqa: E402
from mcp.types import JSONRPCError, JSONRPCNotification, JSONRPCRequest  # noqa: E402

from mcp_re_sdk import (  # noqa: E402
    AuthorizationBindingPolicy,
    AuthzSystemReferenceProvider,
    ClientResponseUnsupported,
    CorrelationStore,
    HttpReply,
    McpReConfig,
    McpReError,
    McpReSdkError,
    NotificationNotAcknowledged,
    OpaqueBytesProvider,
    Signer,
    SignerPolicy,
    SignerUnavailable,
    SigningDevice,
    mcp_re_http_transport,
)
from mcp_re_sdk.mtls import MtlsTransportError  # noqa: E402
from mcp_re_sdk.transport import _binding_context
from mcp_re_sdk.transport import _authz_binding_digest, _bindings_json, _pump  # noqa: E402

CLIENT_SEED = bytes([11]) * 32
TARGET = "https://proxy.internal:8600/mcp"
#: The `server-key-1` root issuer of `sdk/fixtures/delegated_response_replay.json`, so the
#: anchor these tests carry is the one the recorded session actually verifies against.
ISSUER_PUBKEY = "URw0oaLLUh3xa7JGuN6OeZfOI1x-drIqPXUDokgZ3Yo"


def _config(**over) -> McpReConfig:
    """The minimum a config can carry: every optional knob left to its default, so the
    default side of each branch is what runs."""
    args = dict(
        signer=Signer.software(CLIENT_SEED, "did:example:host-a", "client-key-1"),
        audience_id="verifier-1",
        target_uri=TARGET,
        dpop_token="access-token-xyz",
        issuer_key_id="server-key-1",
        issuer_pubkey_b64url=ISSUER_PUBKEY,
        issuer_trust_domain="example.com",
        issuer_subject="did:example:server-1",
        verifier_audiences=["verifier-1"],
        expected_audience_hash="aud-scope-1",
        accepted_epochs=["epoch-1"],
    )
    args.update(over)
    return McpReConfig(**args)


def _request(method="tools/list", id=7, params=None) -> JSONRPCRequest:
    return JSONRPCRequest(jsonrpc="2.0", id=id, method=method, params=params or {})


def _throwing_poster(exc):
    async def post(method, target_uri, headers, body):
        raise exc

    return post


def _capturing_poster(calls):
    async def post(method, target_uri, headers, body):
        calls.append({"headers": list(headers), "body": body})
        # Stop before native verification: this test is about what went out.
        raise McpReError("mcp-re.replay_detected")

    return post


async def _send(config, poster, message, correlation=None):
    """Drive one message through the pump and collect what it hands the session."""
    import anyio

    read_writer, read_stream = anyio.create_memory_object_stream(8)
    write_stream, write_reader = anyio.create_memory_object_stream(8)
    await write_stream.send(SessionMessage(message))
    await write_stream.aclose()
    await _pump(config, poster, write_reader, read_writer, correlation)

    out = []
    while True:
        try:
            out.append(read_stream.receive_nowait())
        except anyio.WouldBlock:
            break
        except anyio.EndOfStream:
            break
    return out


# --- lifecycle -------------------------------------------------------------------


@pytest.mark.anyio
async def test_the_signer_is_checked_before_anything_is_signed():
    posted = []
    config = _config(policy=SignerPolicy.hardened("did:example:host-a"))
    with pytest.raises(McpReError) as ei:
        async with mcp_re_http_transport(config, _capturing_poster(posted)):
            pass
    assert ei.value.wire_code == "mcp-re.actor_binding_failed"
    # A custody violation must fail the CONNECTION; nothing may reach the wire.
    assert posted == []


@pytest.mark.anyio
async def test_the_authorization_policy_is_checked_at_open_too():
    config = _config(
        authorization=[OpaqueBytesProvider("oauth-rar", b"doc")],
        authorization_policy=AuthorizationBindingPolicy.permitting(["human-approval"]),
    )
    with pytest.raises(McpReError) as ei:
        async with mcp_re_http_transport(config, _throwing_poster(RuntimeError("unreachable"))):
            pass
    assert ei.value.wire_code == "mcp-re.authorization_binding_type_unsupported"


@pytest.mark.anyio
async def test_a_satisfied_policy_opens_the_transport():
    config = _config(policy=SignerPolicy("did:example:host-a", profile="development"))
    async with mcp_re_http_transport(config, _throwing_poster(RuntimeError())) as (read, write):
        assert read is not None and write is not None


# --- notifications ---------------------------------------------------------------


@pytest.mark.anyio
async def test_a_notification_is_transmitted_as_a_signed_post():
    """It goes on the wire, signed by the ordinary request rules.

    The adapter used to refuse or drop it: MCP-RE had no ratified one-way profile, so a
    `notifications/cancelled` silently became "keep going". The profile exists now (#418
    / C019b), so the message is carried and its acknowledgement is checked.
    """
    posted = []
    # The capturing poster never returns a 202, so the ack check fails closed; the
    # failure is contained rather than ending the session, and what this test reads is
    # the request that DID reach the wire.
    with _capturing_notification_failures([]):
        await _send(
            _config(),
            _capturing_poster(posted),
            JSONRPCNotification(jsonrpc="2.0", method="notifications/initialized"),
        )

    assert len(posted) == 1, "the notification must reach the wire"
    names = {k.lower() for k, _ in posted[0]["headers"]}
    assert {"signature", "signature-input", "content-digest"} <= names
    body = json.loads(posted[0]["body"])
    assert body["method"] == "notifications/initialized"
    # The serving path classifies a notification by an ABSENT id. `null` is a present id
    # and would be dispatched as a request, answered with a bodied reply nothing awaits.
    assert "id" not in body
    assert body["_meta"], "the request evidence block rides along, as on any request"


@pytest.mark.anyio
async def test_an_unsigned_acknowledgement_fails_the_transport_closed():
    """A 202 with no evidence establishes nothing, so it must not pass as delivery.

    Failing closed means the notification is NOT treated as delivered — and, since
    round 6, that it does not take the session with it. Notifications are started in
    the same task group as every concurrent exchange, so letting the failure escape
    cancelled unrelated in-flight tool calls and tore the transport down on a trigger
    the PEER controls: one unverifiable acknowledgement for a routine
    `notifications/initialized`, from a proxy whose delegated key is merely past `exp`.
    That is the remotely-triggerable session kill round 5 fixed on the request path.
    """
    async def unsigned(method, target_uri, headers, body):
        return HttpReply(status=202, headers=[], body=b"")

    seen = []
    with _capturing_notification_failures(seen):
        out = await _send(
            _config(),
            unsigned,
            JSONRPCNotification(jsonrpc="2.0", method="notifications/initialized"),
        )

    assert out == [], "an unverifiable acknowledgement delivers nothing to the session"
    assert [type(e) for _, e in seen] == [NotificationNotAcknowledged]
    assert seen[0][0] == "notifications/initialized"
    assert "mcp-re." in seen[0][1].wire_code


@pytest.mark.anyio
async def test_a_non_202_answer_to_a_notification_fails_closed():
    """The named bodyless set is checked as a set: a bodied 200 is not an
    acknowledgement, however well-formed it looks."""
    async def bodied(method, target_uri, headers, body):
        return HttpReply(
            status=200,
            headers=[("Content-Type", "application/json")],
            body=b'{"jsonrpc":"2.0","id":null,"result":{"ok":true}}',
        )

    seen = []
    with _capturing_notification_failures(seen):
        out = await _send(
            _config(),
            bodied,
            JSONRPCNotification(jsonrpc="2.0", method="notifications/cancelled"),
        )
    assert out == [], "a bodied 200 is not an acknowledgement"
    assert [type(e) for _, e in seen] == [NotificationNotAcknowledged]


@pytest.mark.anyio
async def test_a_client_side_response_is_refused_rather_than_carried_as_a_notification():
    """A response has no `method`. Signing one as a notification would fabricate a
    message and then report ITS acknowledgement as if the response had been delivered."""
    from mcp.types import JSONRPCResponse

    posted = []
    seen = []
    with _capturing_notification_failures(seen):
        out = await _send(
            _config(),
            _capturing_poster(posted),
            JSONRPCResponse(jsonrpc="2.0", id=1, result={}),
        )
    assert out == [], "a refused message delivers nothing to the session"
    assert [type(e) for _, e in seen] == [ClientResponseUnsupported]
    assert posted == [], "nothing fabricated may reach the wire"


@pytest.mark.anyio
async def test_a_refused_client_side_response_does_not_cancel_other_exchanges():
    """The refusal is correct; ending the session over it is not.

    ``_pump`` reads outbound messages in the parent task of the task group that runs
    every concurrent exchange, so raising there cancelled all of them. The trigger is
    peer-influenceable: a verified reply body carrying a ``method`` parses as a
    server->client ``JSONRPCRequest``, ``ClientSession`` answers it with a
    ``JSONRPCResponse``, and that answer lands on this branch — so one reply body ended
    an entire session, including every unrelated in-flight signed tool call. The
    TypeScript twin fails only the one ``send()``.
    """
    from mcp.types import JSONRPCResponse

    read_writer, read_stream = anyio.create_memory_object_stream(8)
    write_stream, write_reader = anyio.create_memory_object_stream(8)
    # The refused message sits BETWEEN two ordinary requests, so a task-group unwind
    # would take out the one already in flight and never start the one behind it.
    await write_stream.send(SessionMessage(_request(id=1)))
    await write_stream.send(SessionMessage(JSONRPCResponse(jsonrpc="2.0", id=99, result={})))
    await write_stream.send(SessionMessage(_request(id=2)))
    await write_stream.aclose()

    seen = []
    with _capturing_notification_failures(seen):
        await _pump(
            _config(),
            _throwing_poster(McpReError("mcp-re.replay_detected")),
            write_reader,
            read_writer,
        )

    delivered = []
    while True:
        try:
            delivered.append(read_stream.receive_nowait())
        except (anyio.WouldBlock, anyio.EndOfStream):
            break
    assert sorted(m.message.id for m in delivered) == [1, 2], (
        "the refusal cancelled the exchanges around it"
    )
    assert [type(e) for _, e in seen] == [ClientResponseUnsupported]


@pytest.mark.anyio
async def test_a_sub_floor_nonce_override_is_refused_before_a_notification_is_signed():
    """The nonce floor governs both message shapes.

    A notification signed under a guessable nonce is exactly as replayable as a request
    signed under one, and a check that covered only requests would be a hole shaped like
    the message the caller cares least about.
    """
    posted = []
    seen = []
    with _capturing_notification_failures(seen):
        await _send(
            _config(nonce_factory=lambda: "short"),
            _capturing_poster(posted),
            JSONRPCNotification(jsonrpc="2.0", method="notifications/initialized"),
        )
    assert any("at least 22" in str(e) for _, e in seen)
    assert posted == [], "nothing may reach the wire under a sub-floor nonce"


@pytest.mark.anyio
async def test_a_hardened_policy_opens_with_a_non_exporting_signer():
    config = _config(
        signer=Signer.from_device(
            "did:example:host-a", "client-key-1", SigningDevice.from_seed(CLIENT_SEED)
        ),
        policy=SignerPolicy.hardened("did:example:host-a"),
    )
    async with mcp_re_http_transport(config, _capturing_poster([])) as (read, write):
        assert read is not None and write is not None


# --- failure delivery ------------------------------------------------------------


@pytest.mark.anyio
async def test_a_wire_failure_is_delivered_as_a_correlated_json_rpc_error():
    out = await _send(
        _config(),
        _throwing_poster(McpReError("mcp-re.replay_detected", "seen before")),
        _request(),
    )
    error = out[0].message
    assert error.id == 7
    assert error.error.code == -31001
    assert error.error.message == "mcp-re.replay_detected"


@pytest.mark.anyio
async def test_a_local_signer_failure_is_delivered_without_claiming_a_wire_code():
    # The device broke on this side of the boundary; nothing was transmitted, so no peer
    # rejected anything. Reporting `mcp-re.invalid_signature` here would be a lie.
    out = await _send(_config(), _throwing_poster(SignerUnavailable("kms timeout")), _request())
    message = out[0].message.error.message
    assert message.startswith("mcp-re-sdk:")
    assert not message.startswith("mcp-re.")


@pytest.mark.anyio
async def test_the_cores_own_fail_closed_error_is_delivered_rather_than_hanging():
    out = await _send(
        _config(), _throwing_poster(ValueError("mcp-re.response_sig_invalid")), _request()
    )
    assert out[0].message.error.message == "mcp-re.response_sig_invalid"


@contextlib.contextmanager
def _capturing_notification_failures(sink: list):
    """Capture undeliverable outbound messages instead of printing them.

    Neither a notification nor a refused client->server response has a reply channel, so
    this hook is the only place either outcome is observable — which is exactly why it
    exists rather than the failure being swallowed.
    """
    import mcp_re_sdk.transport as t

    previous = t.on_notification_failure
    t.on_notification_failure = lambda method, error: sink.append((method, error))
    try:
        yield
    finally:
        t.on_notification_failure = previous


@pytest.mark.anyio
async def test_an_unexpected_exception_is_delivered_without_claiming_a_wire_code():
    # A defect is not a protocol outcome, so it must not be laundered into a `mcp-re.*`
    # token — but it must still be DELIVERED. It arrives named, correlated to the request
    # that hit it, under the prefix that means "local condition".
    out = await _send(_config(), _throwing_poster(RuntimeError("boom")), _request())

    message = out[0].message.error.message
    assert out[0].message.id == 7
    assert message.startswith("mcp-re-sdk: RuntimeError:")
    assert "boom" in message
    assert not message.startswith("mcp-re."), "a local defect must not claim a wire code"


@pytest.mark.anyio
async def test_one_exchanges_network_error_does_not_take_down_the_session():
    """The property that matters: a per-request failure stays per-request.

    Exchanges share one task group, so an exception escaping one would cancel every other
    in-flight exchange. A reset connection is ordinary and remotely triggerable — a peer
    that can cause one could otherwise end the session, and seven unrelated requests with
    it. Mirrors `transport.test.ts` — a poster rejection rejects only its own `send()`.
    """
    ids = []

    async def poster(method, target_uri, headers, body) -> HttpReply:
        body_doc = json.loads(body)
        ids.append(body_doc["id"])
        if body_doc["id"] == 1:
            raise ConnectionResetError("connection reset by peer")
        raise McpReError("mcp-re.replay_detected")

    read_writer, read_stream = anyio.create_memory_object_stream(8)
    write_stream, write_reader = anyio.create_memory_object_stream(8)
    for rid in (1, 2, 3):
        await write_stream.send(SessionMessage(_request(id=rid)))
    await write_stream.aclose()
    await _pump(_config(), poster, write_reader, read_writer)

    out = []
    while True:
        try:
            out.append(read_stream.receive_nowait())
        except (anyio.WouldBlock, anyio.EndOfStream):
            break

    assert sorted(ids) == [1, 2, 3], "the reset must not cancel the other exchanges"
    delivered = {m.message.id: m.message.error.message for m in out}
    assert delivered[1].startswith("mcp-re-sdk: ConnectionResetError:")
    assert delivered[2] == "mcp-re.replay_detected"
    assert delivered[3] == "mcp-re.replay_detected"


@pytest.mark.anyio
async def test_a_transport_deadline_does_not_synthesize_what_the_peer_never_said():
    """The aggregate response deadline reaches the application as a LOCAL failure.

    The composition this control exists for is `transport deadline → local transport
    failure → application-facing correlated outcome`, and it is the one a low-level
    `_read_bounded` test cannot reach. A future implementation could bound the read
    correctly and still lie about the remote side: report a `mcp-re.*` token nobody sent,
    or fill in `executionStatus: not_executed` / `retrySafety: retry_safe` for an exchange
    whose fate it does not know. Either would turn a timeout — the one condition under
    which the SDK knows LEAST about whether the call ran — into a licence to retry a tool
    call that already executed.

    So what is asserted is not only that the deadline fails the exchange, but everything
    the SDK must NOT say about it, and that the failure stays confined to its own
    correlated exchange.
    """
    store = CorrelationStore()

    async def poster(method, target_uri, headers, body) -> HttpReply:
        if json.loads(body)["id"] == 1:
            # Exactly what `mtls._read_bounded` raises when the aggregate bound expires.
            raise MtlsTransportError(
                "the aggregate response read exceeded 0.5s (slow-loris trickle)"
            )
        raise McpReError("mcp-re.replay_detected")

    read_writer, read_stream = anyio.create_memory_object_stream(8)
    write_stream, write_reader = anyio.create_memory_object_stream(8)
    for rid in (1, 2):
        await write_stream.send(SessionMessage(_request(id=rid)))
    await write_stream.aclose()
    await _pump(_config(), poster, write_reader, read_writer, store)

    out = []
    while True:
        try:
            out.append(read_stream.receive_nowait())
        except (anyio.WouldBlock, anyio.EndOfStream):
            break

    delivered = {m.message.id: m.message.error for m in out}
    timed_out = delivered[1]

    # 1. The affected exchange fails, correlated to its own id. A dropped outcome would
    #    leave `ClientSession` awaiting a reply that never comes.
    assert timed_out is not None
    # 2. No peer verdict is claimed. The peer said nothing; a `mcp-re.*` token here would
    #    be the SDK speaking in the peer's voice.
    assert timed_out.message.startswith("mcp-re-sdk:")
    assert not timed_out.message.startswith("mcp-re.")
    # Delivered as the transport's own words under the local prefix — a `McpReSdkError`
    # is reported by message, so what arrives is the bound that fired, not a peer verdict.
    assert "aggregate response read" in timed_out.message
    # 3/4. No execution or retry fact is invented. These members exist only when a VERIFIED
    #      receipt carried them; a local timeout carries nothing, so the honest answer is
    #      their absence, not a value.
    rendered = json.dumps(timed_out.model_dump(mode="json"))
    for forbidden in ("not_executed", "notExecuted", "executionStatus", "retrySafety", "retry_safe"):
        assert forbidden not in rendered, f"a local timeout must not state {forbidden!r}"
    # 5. Unrelated exchanges are undisturbed, and nothing is left outstanding: a deadline
    #    that leaked its correlation entry would be a remotely triggerable growth lever.
    assert delivered[2].message == "mcp-re.replay_detected"
    assert len(store) == 0, "the timed-out exchange left its correlation entry outstanding"


# --- shutdown (#421) -------------------------------------------------------------
#
# Python's lifecycle IS the `async with` block, so most of the contract holds
# structurally. Mirrors `lifecycle`/shutdown in sdk/typescript/test/transport.test.ts —
# see sdk/PARITY.md for why the two surfaces differ.


@pytest.mark.anyio
async def test_close_aborts_in_flight_work_rather_than_draining_it():
    # Abortive by design, matching the upstream client's rejection of pending requests.
    # It makes NO claim that already-dispatched remote work has stopped.
    started, completed = [], []

    async def slow(method, target_uri, headers, body) -> HttpReply:
        started.append(1)
        await anyio.sleep(5)
        completed.append(1)
        raise McpReError("mcp-re.replay_detected")

    async with mcp_re_http_transport(_config(), slow) as (read, write):
        await write.send(SessionMessage(_request()))
        await anyio.sleep(0.05)

    assert started == [1], "the exchange must have begun"
    assert completed == [], "in-flight work is aborted, not drained"


@pytest.mark.anyio
async def test_close_aborts_an_in_flight_notification_too():
    # #421 applies to a notification for the same reason it applies to a request: the
    # caller has torn the transport down, and an acknowledgement it will never look at
    # must not hold the close open.
    started, completed = [], []

    async def slow(method, target_uri, headers, body) -> HttpReply:
        started.append(1)
        await anyio.sleep(5)
        completed.append(1)
        return HttpReply(status=202, headers=[], body=b"")

    async with mcp_re_http_transport(_config(), slow) as (read, write):
        await write.send(
            SessionMessage(
                JSONRPCNotification(jsonrpc="2.0", method="notifications/initialized")
            )
        )
        await anyio.sleep(0.05)

    assert started == [1], "the notification must have been sent"
    assert completed == [], "in-flight work is aborted, not drained"


@pytest.mark.anyio
async def test_close_refuses_further_work():
    posted = []
    async with mcp_re_http_transport(_config(), _capturing_poster(posted)) as (read, write):
        pass

    # The streams are closed, so a signed request cannot leave a transport the caller has
    # already left. (Broken vs Closed depends on which end shut first; both refuse.)
    with pytest.raises((anyio.ClosedResourceError, anyio.BrokenResourceError)):
        await write.send(SessionMessage(_request()))
    assert posted == []


@pytest.mark.anyio
async def test_close_delivers_nothing_to_a_caller_that_has_left():
    async with mcp_re_http_transport(_config(), _capturing_poster([])) as (read, write):
        pass

    with pytest.raises((anyio.ClosedResourceError, anyio.EndOfStream)):
        read.receive_nowait()


@pytest.mark.anyio
async def test_close_clears_abandoned_correlation_state():
    # Correlation entries would otherwise outlive the transport that owns them.
    store = CorrelationStore()

    async def slow(method, target_uri, headers, body) -> HttpReply:
        await anyio.sleep(5)
        raise McpReError("mcp-re.replay_detected")

    async with mcp_re_http_transport(_config(), slow, correlation=store) as (read, write):
        await write.send(SessionMessage(_request()))
        await anyio.sleep(0.05)
        assert len(store) == 1, "the request must be outstanding"

    assert len(store) == 0, "close must clear abandoned correlation state"


@pytest.mark.anyio
async def test_correlation_state_belongs_to_the_transport_not_the_config():
    """Two transports built from one config must not share — or clear — each other's state.

    The config is a value object a caller may reasonably reuse for a second session. When
    the store hung off it, closing either transport reaped the OTHER's outstanding
    requests, and every response still in flight there failed as an unbound response.
    """
    config = _config()
    first, second = CorrelationStore(), CorrelationStore()

    async def slow(method, target_uri, headers, body) -> HttpReply:
        await anyio.sleep(5)
        raise McpReError("mcp-re.replay_detected")

    async with mcp_re_http_transport(config, slow, correlation=second) as (_r2, w2):
        await w2.send(SessionMessage(_request(id=2)))
        await anyio.sleep(0.05)

        async with mcp_re_http_transport(config, slow, correlation=first) as (_r1, w1):
            await w1.send(SessionMessage(_request(id=1)))
            await anyio.sleep(0.05)
            assert len(first) == 1 and len(second) == 1

        # The inner transport closed. The outer one's request is still outstanding.
        assert len(first) == 0, "the closed transport clears its own state"
        assert len(second) == 1, "and only its own"


@pytest.mark.anyio
async def test_a_failed_exchange_does_not_leave_its_correlation_entry_outstanding():
    """Anything that can fail an exchange is remotely triggerable, so a leak is a lever.

    The entry is recorded before the POST and consumed by the response. A failure in
    between produces no response to consume it, so without an explicit retirement the
    store grows by one per failed request for the life of the session.
    """
    store = CorrelationStore()

    for exc in (
        ConnectionResetError("reset"),
        McpReError("mcp-re.replay_detected"),
        ValueError("mcp-re.response_sig_invalid"),
    ):
        await _send(_config(), _throwing_poster(exc), _request(), correlation=store)

    assert len(store) == 0, f"{exc!r} left its entry outstanding"


# --- signing inputs --------------------------------------------------------------


@pytest.mark.anyio
async def test_freshness_is_generated_here_so_a_caller_cannot_repeat_a_nonce():
    # A nonce that repeats inside the window is a defect, not a policy knob.
    calls = []
    poster = _capturing_poster(calls)
    for _ in range(2):
        await _send(_config(), poster, _request())

    sigs = [
        next(v for k, v in c["headers"] if k.lower() == "signature") for c in calls
    ]
    assert sigs[0] != sigs[1]


@pytest.mark.anyio
async def test_an_injected_clock_and_ttl_are_honoured():
    calls = []
    config = _config(clock=lambda: 1_000, request_ttl=30, route="a")
    await _send(config, _capturing_poster(calls), _request())
    sig_input = next(v for k, v in calls[0]["headers"] if k.lower() == "signature-input")
    assert "created=1000" in sig_input
    assert "expires=1030" in sig_input


@pytest.mark.anyio
async def test_the_signed_body_is_the_request_the_caller_described():
    calls = []
    await _send(_config(), _capturing_poster(calls), _request(method="tools/list", id=7))
    body = json.loads(calls[0]["body"])
    assert body["method"] == "tools/list"
    assert body["id"] == 7


@pytest.mark.anyio
async def test_the_correlation_entry_records_the_authorization_binding_digest():
    # ADR-MCPS-044 enumerates it; retained for audit only, never re-interpreted.
    #
    # The expected value is a LITERAL, not a recomputation. Recomputing it with the
    # SDK's own serializer is what let Python and TypeScript drift: `json.dumps`
    # defaults to `", "`/`": "` separators and `JSON.stringify` emits none, so identical
    # bindings produced different digests and an audit pipeline reconciling the two saw
    # a false "artifact binding changed". The TypeScript twin's test pins this SAME
    # string — that is the point of writing it down.
    store = CorrelationStore()
    config = _config(authorization=[OpaqueBytesProvider("human-approval", b"doc")])

    async def poster(method, target_uri, headers, body) -> HttpReply:
        await anyio.sleep(5)
        raise McpReError("mcp-re.replay_detected")

    async with mcp_re_http_transport(config, poster, correlation=store) as (read, write):
        await write.send(SessionMessage(_request()))
        await anyio.sleep(0.05)
        pending = next(iter(store))
        canonical = (
            '[{"artifact_type":"human-approval","form":"opaque-bytes",'
            '"material_b64url":"ZG9j"}]'
        )
        assert _bindings_json(config, "tools/list") == canonical, (
            "compact separators, sorted keys — byte-identical to JSON.stringify"
        )
        assert (
            pending.authz_binding_digest
            == "sha-256:huucRBvtO7V1Xm8EFbC6ci-xlsf8EYyNZQix9sJx64Q"
        )


def test_the_canonical_bindings_json_emits_raw_utf8_like_json_stringify():
    """A non-ASCII binding field must digest to the same bytes in both SDKs.

    ``json.dumps`` escapes every non-ASCII character as ``\\uXXXX`` unless told not to;
    ``JSON.stringify`` emits raw UTF-8. Since :func:`_authz_binding_digest` is taken over
    exactly this text, an ``authorization_system_id``, ``reference_scheme_id`` or
    ``reference_value`` carrying a non-ASCII character — a tenant name, a grant handle —
    otherwise digested to two different values, and an audit pipeline reconciling a
    Python client's record against a TypeScript client's read that as "the artifact
    binding changed".

    The expected string is a LITERAL, and the TypeScript twin's test pins the same one.
    """
    config = _config(
        authorization=[
            AuthzSystemReferenceProvider(
                "pdp-decision",
                b"doc",
                authorization_system_id="pdp-sé",
                reference_scheme_id="urn:système",
                reference_value="grant-café-✓",
            )
        ]
    )
    canonical = _bindings_json(config, "tools/list")

    assert canonical == (
        '[{"artifact_type":"pdp-decision","authorization_system_id":"pdp-sé",'
        '"form":"authz-system-reference","material_b64url":"ZG9j",'
        '"reference_scheme_id":"urn:système","reference_value":"grant-café-✓"}]'
    )
    assert "\\u" not in canonical, "an escaped non-ASCII character is not JSON.stringify"
    assert _authz_binding_digest(canonical) == "sha-256:5qndaYSZ4RWRPC68gVX125zTyK8XeWHdwWvnFZnr0XI"


@pytest.mark.anyio
async def test_a_request_with_no_bindings_records_no_digest():
    store = CorrelationStore()

    async def poster(method, target_uri, headers, body) -> HttpReply:
        await anyio.sleep(5)
        raise McpReError("mcp-re.replay_detected")

    async with mcp_re_http_transport(_config(), poster, correlation=store) as (read, write):
        await write.send(SessionMessage(_request()))
        await anyio.sleep(0.05)
        assert next(iter(store)).authz_binding_digest is None


# --- the delegated-verification anchor -------------------------------------------


@pytest.mark.parametrize(
    "field",
    [
        "issuer_key_id",
        "issuer_pubkey_b64url",
        "issuer_trust_domain",
        "issuer_subject",
        "expected_audience_hash",
        "verifier_audiences",
        "accepted_epochs",
    ],
)
def test_an_incomplete_trust_anchor_fails_at_construction(field):
    """Empty is not a relaxed check — it is a check nothing can satisfy.

    An empty `accepted_epochs` rejects every response as a stale trust epoch, an empty
    `verifier_audiences` as an audience mismatch. The client is unusable rather than
    unsafe, but it should not have to send a request to find that out. TypeScript makes
    these required interface fields; this is Python stating the same requirement.
    """
    empty = [] if field in ("verifier_audiences", "accepted_epochs") else ""
    with pytest.raises(McpReSdkError) as ei:
        _config(**{field: empty})
    assert field in str(ei.value)
    assert "trust anchor is incomplete" in str(ei.value)


# --- the revocation denylist -----------------------------------------------------
#
# `revoked_identifiers` is the one config field whose wrong value fails OPEN. Every
# sibling anchor field degrades into "nothing verifies"; a malformed denylist degrades
# into "nothing is revoked" while still reporting a denylist as configured. Mirrors
# `McpReHttpTransport revocation denylist shape` in the TypeScript suite.


def test_a_bare_string_denylist_is_refused_rather_than_expanded_per_character():
    """``list("kid-compromised")`` is a NON-EMPTY list of single characters.

    None of them can match a `delegated_kid`, `issuer_kid` or credential `jti`, so the
    compromised key stays accepted for its whole TTL and epoch window while the operator
    believes revocation is in force. No type checker objects, because a `str` IS a
    `Sequence[str]`.
    """
    with pytest.raises(McpReSdkError, match="must be a sequence of identifier strings"):
        _config(revoked_identifiers="kid-compromised")


@pytest.mark.parametrize("bad", [["kid-1", ""], [7], [None]])
def test_a_denylist_entry_that_cannot_match_an_identifier_is_refused(bad):
    with pytest.raises(McpReSdkError, match="non-empty strings"):
        _config(revoked_identifiers=bad)


def test_a_well_formed_denylist_and_the_empty_ttl_only_posture_are_accepted():
    assert _config(revoked_identifiers=["kid-1"]).revoked_identifiers == ["kid-1"]
    assert _config(revoked_identifiers=[]).revoked_identifiers == []
    assert _config().revoked_identifiers == ()


# --- the frozen wire code --------------------------------------------------------
#
# The PyO3 binding spells every core failure `"mcp-re: mcp-re.<token>"`. What REQ-14/POL-6
# make authoritative — and what a caller branches on without parsing prose — is the TOKEN,
# so one wire event must have one spelling in both SDKs and on both message paths.


@pytest.mark.anyio
async def test_the_bindings_prefixed_spelling_is_delivered_as_the_bare_token():
    """The real core's spelling, not a hand-made one.

    A test that injects `ValueError("mcp-re.response_sig_invalid")` never exercises the
    prefix the binding always emits, so it cannot see this.
    """
    out = await _send(
        _config(),
        _throwing_poster(ValueError("mcp-re: mcp-re.response_sig_invalid")),
        _request(),
    )
    assert out[0].message.error.message == "mcp-re.response_sig_invalid"


@pytest.mark.anyio
async def test_a_value_error_that_is_not_a_token_is_labelled_a_local_condition():
    # A `ValueError` from the caller's `poster` doing real I/O must not occupy the field
    # that otherwise only ever holds something the peer said.
    out = await _send(_config(), _throwing_poster(ValueError("socket hang up")), _request())
    message = out[0].message.error.message
    assert message == "mcp-re-sdk: ValueError: socket hang up"


@pytest.mark.anyio
async def test_a_notifications_wire_code_is_the_bare_token_too():
    """`wire_code` is documented as the frozen token, so the notification path strips the
    binding's prefix exactly as the request path does. The TypeScript twin pins the same
    assertion."""
    import re

    async def unsigned(method, target_uri, headers, body):
        return HttpReply(status=202, headers=[], body=b"")

    seen = []
    with _capturing_notification_failures(seen):
        await _send(
            _config(),
            unsigned,
            JSONRPCNotification(jsonrpc="2.0", method="notifications/initialized"),
        )
    assert re.fullmatch(r"mcp-re\.[a-z0-9_]+", seen[0][1].wire_code), seen[0][1].wire_code


# --- the rejection receipt's binding fact ----------------------------------------
#
# `test_a_verified_rejection_receipt_is_delivered_as_an_error_not_a_result` in
# test_transport_replay.py pins the BOUND value against a recorded receipt. It cannot
# distinguish reading `verified.bound` from hard-coding `True`, and the unbound case is
# the security-relevant one, so it is pinned here against a stubbed verdict. The
# TypeScript twin pins the same pair.


@pytest.mark.anyio
async def test_an_unbound_rejection_receipt_is_reported_as_not_request_bound(monkeypatch):
    """A preflight-unbound receipt carries no binding to this request's evidence.

    The core verifies a rejection receipt request-bound first and preflight-unbound
    second, and says which one succeeded. An unbound receipt is genuine evidence from a
    trusted issuer, but it answers no particular transmission — one of them is an answer
    to every request from every client of that issuer for the credential's validity
    window — so an application must be able to tell "the boundary rejected MY request"
    from "a generic rejection arrived" (RSP-7). It is still an error and never a result.
    """
    import mcp_re_sdk.transport as t

    class _Unbound:
        outcome = "rejection"
        wire_code = "mcp-re.authorization_binding_missing"
        bound = False
        request_state = None
        # A preflight refusal that never reached dispatch states no disposition. The
        # transport must emit no member for it rather than inventing one.
        execution_status = None
        retry_safety = None
        continuation_status = None
        retention_status = None

    monkeypatch.setattr(t._core, "verify_response", lambda *a, **k: _Unbound())

    async def rejecting(method, target_uri, headers, body):
        return HttpReply(status=409, headers=[], body=b"{}")

    out = await _send(_config(), rejecting, _request())

    error = out[0].message.error
    assert error.message == "mcp-re.authorization_binding_missing", (
        "the frozen token is what the peer said and must not be rewritten"
    )
    assert error.data == {"requestBound": False}


@pytest.mark.anyio
async def test_a_post_dispatch_rejection_reports_its_execution_and_retry_contract(monkeypatch):
    """ADR-MCPRE-058 §10 (SL-10): the disposition must reach the application.

    The server derives `execution_status` / `retry_safety` from its exchange machine and
    signs them into every rejection at or after dispatch, precisely so a client can tell
    a retry-safe failure from one whose side effect a retry performs twice. Nothing on
    the client side read them: the application saw a bare wire code and a retry-friendly
    status, retried, and the tool call ran again with a fresh nonce that passes replay
    admission. Byte-parity fixtures cannot see this — it is behaviour.
    """
    import mcp_re_sdk.transport as t

    class _PostDispatch:
        outcome = "rejection"
        wire_code = "mcp-re.upstream_unavailable"
        bound = True
        request_state = None
        execution_status = "possibly_executed"
        retry_safety = "unsafe_without_reconciliation"
        continuation_status = "consumed"
        retention_status = None

    monkeypatch.setattr(t._core, "verify_response", lambda *a, **k: _PostDispatch())

    async def rejecting(method, target_uri, headers, body):
        return HttpReply(status=503, headers=[], body=b"{}")

    out = await _send(_config(), rejecting, _request())

    error = out[0].message.error
    assert error.message == "mcp-re.upstream_unavailable"
    assert error.data == {
        "requestBound": True,
        "executionStatus": "possibly_executed",
        "retrySafety": "unsafe_without_reconciliation",
        "continuationStatus": "consumed",
    }, "a member the receipt did not carry must not be invented"


# --- a verified reply that is not a JSON-RPC response ------------------------------


@pytest.mark.anyio
async def test_a_verified_reply_carrying_a_method_is_refused_not_dispatched(monkeypatch):
    """A signed reply must never become a server->client REQUEST.

    `jsonrpc_message_adapter` is a union that accepts a JSONRPCRequest, and the pydantic
    models ignore extras, so a body carrying BOTH a legal `result` and a top-level
    `method` parsed as a request and was injected into `ClientSession` as a
    server-initiated one — running the application's sampling / elicitation / roots
    handlers on attacker-chosen params. The `call_tool` that was actually made then hung
    forever, because its id had been consumed as an inbound request id.

    The Rust ambassador refuses the same body (`plain_response_from_verified`); this is
    the SDK side of that property, and the TypeScript twin pins it too.
    """
    import mcp_re_sdk.transport as t

    class _Ok:
        outcome = "success"
        wire_code = None
        bound = True
        request_state = None
        execution_status = None
        retry_safety = None
        continuation_status = None
        retention_status = None

    monkeypatch.setattr(t._core, "verify_response", lambda *a, **k: _Ok())

    hostile = (
        b'{"jsonrpc":"2.0","id":1,"result":{"ok":true},'
        b'"method":"sampling/createMessage","params":{"x":1}}'
    )

    async def spliced(method, target_uri, headers, body):
        return HttpReply(status=200, headers=[], body=hostile)

    out = await _send(_config(), spliced, _request())

    delivered = out[0].message
    assert isinstance(delivered, JSONRPCError), (
        f"a method-bearing body must not reach the session as {type(delivered).__name__}"
    )
    assert delivered.error.message == "mcp-re.malformed_envelope"

    # And an ordinary reply still round-trips, so the guard refuses a shape rather than
    # the success path.
    async def ordinary(method, target_uri, headers, body):
        return HttpReply(
            status=200, headers=[], body=b'{"jsonrpc":"2.0","id":9,"result":{"ok":true}}'
        )

    out = await _send(_config(), ordinary, _request())
    assert out[0].message.result == {"ok": True}


@pytest.mark.anyio
async def test_a_verified_reply_with_neither_result_nor_error_is_refused(monkeypatch):
    """A signed envelope carrying no answer is not an answer.

    Handing it to the union adapter produced whichever arm happened to match, and an
    empty `{"jsonrpc":"2.0","id":1}` has no reading under which the call completed.
    """
    import mcp_re_sdk.transport as t

    class _Ok:
        outcome = "success"
        wire_code = None
        bound = True
        request_state = None
        execution_status = None
        retry_safety = None
        continuation_status = None
        retention_status = None

    monkeypatch.setattr(t._core, "verify_response", lambda *a, **k: _Ok())

    for body in (
        b'{"jsonrpc":"2.0","id":1}',
        b'{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-1,"message":"x"}}',
        b'[{"jsonrpc":"2.0","id":1,"result":{}}]',
        b'"ok"',
    ):
        async def poster(method, target_uri, headers, body=body):
            return HttpReply(status=200, headers=[], body=body)

        out = await _send(_config(), poster, _request())
        delivered = out[0].message
        assert isinstance(delivered, JSONRPCError), f"{body!r} must not be delivered"
        assert delivered.error.message == "mcp-re.malformed_envelope"


# --- the undeliverable-message sink ----------------------------------------------


@pytest.mark.anyio
async def test_the_config_hook_takes_precedence_over_the_process_global_sink():
    """Two transports in one process must not swallow each other's failures.

    A module-level sink is shared by every transport in the process, so one embedder's
    assignment silently ate another's. The per-config hook is what an application
    installs to learn that a message it emitted was NOT delivered.
    """
    async def unsigned(method, target_uri, headers, body):
        return HttpReply(status=202, headers=[], body=b"")

    mine = []
    global_sink = []
    with _capturing_notification_failures(global_sink):
        await _send(
            _config(on_undeliverable=lambda d, e: mine.append((d, e))),
            unsigned,
            JSONRPCNotification(jsonrpc="2.0", method="notifications/initialized"),
        )
    assert [d for d, _ in mine] == ["notifications/initialized"]
    assert [type(e) for _, e in mine] == [NotificationNotAcknowledged]
    assert global_sink == [], "the config hook must not also reach the process global"


# --- concurrency -----------------------------------------------------------------
#
# Mirrors `concurrency` in sdk/typescript/test/transport.test.ts: the two SDKs must agree
# on how many exchanges may be in flight, not just on the bytes they emit.


def _gated_poster(peak: dict, hold: float = 0.05):
    """Count how many posts are in flight at once."""
    peak.setdefault("now", 0)
    peak.setdefault("max", 0)

    async def post(method, target_uri, headers, body) -> HttpReply:
        peak["now"] += 1
        peak["max"] = max(peak["max"], peak["now"])
        await anyio.sleep(hold)
        peak["now"] -= 1
        raise McpReError("mcp-re.replay_detected")  # stop before native verification

    return post


async def _drive(config, poster, count: int):
    """Send `count` requests at once and wait for all their replies."""
    read_writer, read_stream = anyio.create_memory_object_stream(64)
    write_stream, write_reader = anyio.create_memory_object_stream(64)
    for i in range(count):
        await write_stream.send(SessionMessage(_request(id=i)))
    await write_stream.aclose()
    await _pump(config, poster, write_reader, read_writer)

    replies = []
    for _ in range(count):
        try:
            replies.append(read_stream.receive_nowait())
        except (anyio.WouldBlock, anyio.EndOfStream):
            break
    return replies


@pytest.mark.anyio
async def test_exchanges_run_concurrently_rather_than_head_of_line_blocking():
    # MCP is not lock-step. Awaiting each exchange before reading the next request would
    # make one slow tool call block every other request on the session.
    peak = {}
    replies = await _drive(_config(), _gated_poster(peak), 4)

    assert peak["max"] == 4, f"exchanges serialized (peak {peak['max']} of 4)"
    assert len(replies) == 4, "every request must still get its reply"


@pytest.mark.anyio
async def test_concurrency_is_bounded_so_a_burst_cannot_exhaust_the_poster():
    # Each in-flight exchange holds a connection and a signing operation (a KMS round
    # trip under non-exporting custody); unbounded fan-out would exhaust either.
    peak = {}
    replies = await _drive(_config(max_concurrent_exchanges=2), _gated_poster(peak), 6)

    assert peak["max"] == 2, f"the bound was not honoured (peak {peak['max']}, limit 2)"
    assert len(replies) == 6, "bounding must delay a request, never drop it"


@pytest.mark.parametrize("bad", [0, -1, 2.5, True, None, "8"])
def test_an_invalid_bound_is_refused_rather_than_deadlocking(bad):
    """A bound of 0 does not throttle — it deadlocks.

    Every sender waits for a slot that can never be released, and the session hangs in
    silence. Nothing about that is recoverable at runtime, so it must be refused where
    the value enters. `True` is in here because `isinstance(True, int)` is True in
    Python: a bool would otherwise sail through as a bound of 1.
    """
    with pytest.raises(McpReSdkError, match="positive integer"):
        _config(max_concurrent_exchanges=bad)


def test_a_valid_bound_is_accepted():
    assert _config(max_concurrent_exchanges=1).max_concurrent_exchanges == 1


@pytest.mark.anyio
async def test_every_concurrent_reply_is_correlated_to_its_own_request():
    # Concurrency must not let one request's outcome land on another's id.
    replies = await _drive(_config(), _gated_poster({}), 4)
    assert sorted(r.message.id for r in replies) == [0, 1, 2, 3]


@pytest.mark.anyio
async def test_authorization_bindings_reach_the_core_which_digests_the_real_bytes():
    # bind-not-interpret: the provider supplies the artifact; the core digests it. The
    # bytes themselves must never appear in the evidence.
    import base64

    material = b"human-approval-record"
    calls = []
    config = _config(authorization=[OpaqueBytesProvider("human-approval", material)])
    await _send(config, _capturing_poster(calls), _request())

    evidence = calls[0]["body"].decode()
    assert "human-approval" in evidence
    assert "human-approval-record" not in evidence
    assert base64.urlsafe_b64encode(material).decode().rstrip("=") not in evidence


# --- SD-03: a caller that must know its notification was accepted ------------------


@pytest.mark.anyio
async def test_send_notification_verified_raises_when_the_202_does_not_verify():
    """SD-03: neither SDK may treat a notification as delivered until its 202 verifies.

    The TypeScript twin gives its caller that guarantee directly — `send()` awaits the
    whole obligation and throws `NotificationNotAcknowledged`. `ClientSession.
    send_notification()` cannot: it hands the message to an anyio memory stream and
    returns, so the pump on the other side has no caller left to raise to, and reaching
    back through it would mean raising inside the task group that runs every concurrent
    exchange — the remotely-triggerable session kill round 5 removed.

    So the awaited surface is a separate call, and this pins that it fails closed rather
    than reporting a delivery nothing acknowledged.
    """
    from mcp_re_sdk.transport import send_notification_verified

    async def unsigned(method, target_uri, headers, body):
        # A 202 with no signature: transmitted, but nothing acknowledged it.
        return HttpReply(status=202, headers=[], body=b"")

    with pytest.raises(NotificationNotAcknowledged) as raised:
        await send_notification_verified(_config(), unsigned, "notifications/cancelled")
    assert raised.value.method == "notifications/cancelled"
    assert raised.value.wire_code, "the frozen reason travels with the refusal"


@pytest.mark.anyio
async def test_send_notification_verified_posts_the_signed_notification():
    """It is the same obligation the pump runs, not a second code path: the message is
    signed and POSTed, and only the acknowledgement decides the outcome."""
    from mcp_re_sdk.transport import send_notification_verified

    calls = []

    async def unsigned(method, target_uri, headers, body):
        calls.append((method, target_uri, bytes(body)))
        return HttpReply(status=202, headers=[], body=b"")

    with contextlib.suppress(NotificationNotAcknowledged):
        await send_notification_verified(_config(), unsigned, "notifications/initialized")

    assert len(calls) == 1, "the notification must actually be transmitted"
    method, target_uri, body = calls[0]
    assert method == "POST"
    assert target_uri == TARGET
    assert json.loads(body)["method"] == "notifications/initialized"
    assert "id" not in json.loads(body), "a notification has no id"
