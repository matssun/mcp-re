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
import json

import anyio
import pytest

pytest.importorskip("mcp", reason="the transport adapter needs the upstream MCP SDK")

from mcp.shared.message import SessionMessage  # noqa: E402
from mcp.types import JSONRPCMessage, JSONRPCNotification, JSONRPCRequest  # noqa: E402

from mcp_re_sdk import (  # noqa: E402
    AuthorizationBindingPolicy,
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
from mcp_re_sdk.transport import _binding_context, _pump  # noqa: E402

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
    await write_stream.send(SessionMessage(JSONRPCMessage(message)))
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
        authorization=[OpaqueBytesProvider("pdp-decision", b"doc")],
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
    with pytest.raises(BaseException):
        # The capturing poster never returns a 202, so the ack check below fails closed;
        # what this test reads is the request that DID reach the wire.
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

    There is no request id to correlate an error to and no caller awaiting a reply, so
    failing closed means tearing the transport down. The alternative is continuing a
    session in which an unverifiable claim of acceptance was accepted.
    """
    async def unsigned(method, target_uri, headers, body):
        return HttpReply(status=202, headers=[], body=b"")

    with pytest.raises(BaseException) as ei:
        await _send(
            _config(),
            unsigned,
            JSONRPCNotification(jsonrpc="2.0", method="notifications/initialized"),
        )

    leaves = _flatten(ei.value)
    assert [type(e) for e in leaves] == [NotificationNotAcknowledged]
    assert leaves[0].method == "notifications/initialized"
    assert "mcp-re." in leaves[0].wire_code


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

    with pytest.raises(BaseException) as ei:
        await _send(
            _config(),
            bodied,
            JSONRPCNotification(jsonrpc="2.0", method="notifications/cancelled"),
        )
    assert [type(e) for e in _flatten(ei.value)] == [NotificationNotAcknowledged]


@pytest.mark.anyio
async def test_a_client_side_response_is_refused_rather_than_carried_as_a_notification():
    """A response has no `method`. Signing one as a notification would fabricate a
    message and then report ITS acknowledgement as if the response had been delivered."""
    from mcp.types import JSONRPCResponse

    posted = []
    with pytest.raises(BaseException) as ei:
        await _send(
            _config(),
            _capturing_poster(posted),
            JSONRPCResponse(jsonrpc="2.0", id=1, result={}),
        )
    assert [type(e) for e in _flatten(ei.value)] == [ClientResponseUnsupported]
    assert posted == [], "nothing fabricated may reach the wire"


@pytest.mark.anyio
async def test_a_sub_floor_nonce_override_is_refused_before_a_notification_is_signed():
    """The nonce floor governs both message shapes.

    A notification signed under a guessable nonce is exactly as replayable as a request
    signed under one, and a check that covered only requests would be a hole shaped like
    the message the caller cares least about.
    """
    posted = []
    with pytest.raises(BaseException) as ei:
        await _send(
            _config(nonce_factory=lambda: "short"),
            _capturing_poster(posted),
            JSONRPCNotification(jsonrpc="2.0", method="notifications/initialized"),
        )
    assert any("at least 22" in str(e) for e in _flatten(ei.value))
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
    error = out[0].message.root
    assert error.id == 7
    assert error.error.code == -32001
    assert error.error.message == "mcp-re.replay_detected"


@pytest.mark.anyio
async def test_a_local_signer_failure_is_delivered_without_claiming_a_wire_code():
    # The device broke on this side of the boundary; nothing was transmitted, so no peer
    # rejected anything. Reporting `mcp-re.invalid_signature` here would be a lie.
    out = await _send(_config(), _throwing_poster(SignerUnavailable("kms timeout")), _request())
    message = out[0].message.root.error.message
    assert message.startswith("mcp-re-sdk:")
    assert not message.startswith("mcp-re.")


@pytest.mark.anyio
async def test_the_cores_own_fail_closed_error_is_delivered_rather_than_hanging():
    out = await _send(
        _config(), _throwing_poster(ValueError("mcp-re.response_sig_invalid")), _request()
    )
    assert out[0].message.root.error.message == "mcp-re.response_sig_invalid"


def _flatten(exc: BaseException) -> list:
    """Every leaf of a (possibly nested) ExceptionGroup.

    Exchanges run in a task group, so anything escaping one arrives wrapped. Callers
    already saw this — ``mcp_re_http_transport`` runs the pump in a task group of its own
    — so assert on what was raised, not on how many groups it came wrapped in.
    """
    if isinstance(exc, BaseExceptionGroup):
        return [leaf for e in exc.exceptions for leaf in _flatten(e)]
    return [exc]


@pytest.mark.anyio
async def test_an_unexpected_exception_is_delivered_without_claiming_a_wire_code():
    # A defect is not a protocol outcome, so it must not be laundered into a `mcp-re.*`
    # token — but it must still be DELIVERED. It arrives named, correlated to the request
    # that hit it, under the prefix that means "local condition".
    out = await _send(_config(), _throwing_poster(RuntimeError("boom")), _request())

    message = out[0].message.root.error.message
    assert out[0].message.root.id == 7
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
        await write_stream.send(SessionMessage(JSONRPCMessage(_request(id=rid))))
    await write_stream.aclose()
    await _pump(_config(), poster, write_reader, read_writer)

    out = []
    while True:
        try:
            out.append(read_stream.receive_nowait())
        except (anyio.WouldBlock, anyio.EndOfStream):
            break

    assert sorted(ids) == [1, 2, 3], "the reset must not cancel the other exchanges"
    delivered = {m.message.root.id: m.message.root.error.message for m in out}
    assert delivered[1].startswith("mcp-re-sdk: ConnectionResetError:")
    assert delivered[2] == "mcp-re.replay_detected"
    assert delivered[3] == "mcp-re.replay_detected"


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
        await write.send(SessionMessage(JSONRPCMessage(_request())))
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
                JSONRPCMessage(
                    JSONRPCNotification(jsonrpc="2.0", method="notifications/initialized")
                )
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
        await write.send(SessionMessage(JSONRPCMessage(_request())))
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
        await write.send(SessionMessage(JSONRPCMessage(_request())))
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
        await w2.send(SessionMessage(JSONRPCMessage(_request(id=2))))
        await anyio.sleep(0.05)

        async with mcp_re_http_transport(config, slow, correlation=first) as (_r1, w1):
            await w1.send(SessionMessage(JSONRPCMessage(_request(id=1))))
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
    # ADR-MCPS-044 enumerates it; retained for audit only, never re-interpreted. It must
    # be the digest of the bytes that were SIGNED, not of anything recomputed later.
    store = CorrelationStore()
    config = _config(authorization=[OpaqueBytesProvider("pdp-decision", b"doc")])

    async def poster(method, target_uri, headers, body) -> HttpReply:
        await anyio.sleep(5)
        raise McpReError("mcp-re.replay_detected")

    async with mcp_re_http_transport(config, poster, correlation=store) as (read, write):
        await write.send(SessionMessage(JSONRPCMessage(_request())))
        await anyio.sleep(0.05)
        pending = next(iter(store))
        signed_bindings = json.dumps(
            [p.spec(_binding_context(config, "tools/list")) for p in config.authorization]
        )
        expected = "sha-256:" + base64.urlsafe_b64encode(
            hashlib.sha256(signed_bindings.encode()).digest()
        ).decode().rstrip("=")
        assert pending.authz_binding_digest == expected


@pytest.mark.anyio
async def test_a_request_with_no_bindings_records_no_digest():
    store = CorrelationStore()

    async def poster(method, target_uri, headers, body) -> HttpReply:
        await anyio.sleep(5)
        raise McpReError("mcp-re.replay_detected")

    async with mcp_re_http_transport(_config(), poster, correlation=store) as (read, write):
        await write.send(SessionMessage(JSONRPCMessage(_request())))
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
        await write_stream.send(SessionMessage(JSONRPCMessage(_request(id=i))))
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
    assert sorted(r.message.root.id for r in replies) == [0, 1, 2, 3]


@pytest.mark.anyio
async def test_authorization_bindings_reach_the_core_which_digests_the_real_bytes():
    # bind-not-interpret: the provider supplies the artifact; the core digests it. The
    # bytes themselves must never appear in the evidence.
    import base64

    material = b"pdp-decision-document"
    calls = []
    config = _config(authorization=[OpaqueBytesProvider("pdp-decision", material)])
    await _send(config, _capturing_poster(calls), _request())

    evidence = calls[0]["body"].decode()
    assert "pdp-decision" in evidence
    assert "pdp-decision-document" not in evidence
    assert base64.urlsafe_b64encode(material).decode().rstrip("=") not in evidence
