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
import json

import anyio
import pytest

pytest.importorskip("mcp", reason="the transport adapter needs the upstream MCP SDK")

from mcp.shared.message import SessionMessage  # noqa: E402
from mcp.types import JSONRPCMessage, JSONRPCNotification, JSONRPCRequest  # noqa: E402

from mcp_re_sdk import (  # noqa: E402
    AuthorizationBindingPolicy,
    HttpReply,
    McpReConfig,
    McpReError,
    OpaqueBytesProvider,
    Signer,
    SignerPolicy,
    SignerUnavailable,
    mcp_re_http_transport,
)
from mcp_re_sdk.transport import _pump  # noqa: E402

CLIENT_SEED = bytes([11]) * 32
TARGET = "https://proxy.internal:8600/mcp"


def _config(**over) -> McpReConfig:
    """The minimum a config can carry: every optional knob left to its default, so the
    default side of each branch is what runs."""
    args = dict(
        signer=Signer.software(CLIENT_SEED, "did:example:host-a", "client-key-1"),
        audience_id="verifier-1",
        target_uri=TARGET,
        dpop_token="access-token-xyz",
        issuer_key_id="server-key-1",
        issuer_pubkey_b64url="",
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


async def _send(config, poster, message):
    """Drive one message through the pump and collect what it hands the session."""
    import anyio

    read_writer, read_stream = anyio.create_memory_object_stream(8)
    write_stream, write_reader = anyio.create_memory_object_stream(8)
    await write_stream.send(SessionMessage(JSONRPCMessage(message)))
    await write_stream.aclose()
    await _pump(config, poster, write_reader, read_writer)

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
async def test_a_notification_is_dropped_and_reported_because_it_carries_no_evidence():
    # MCP-RE's wire is one signed POST per request. A notification has no reply, so it
    # carries no evidence and cannot be verified — dropping is honest, silence is not.
    dropped, posted = [], []
    config = _config(on_dropped_notification=dropped.append)
    out = await _send(
        config,
        _capturing_poster(posted),
        JSONRPCNotification(jsonrpc="2.0", method="notifications/initialized"),
    )
    assert dropped == ["notifications/initialized"]
    assert posted == []
    assert out == []


@pytest.mark.anyio
async def test_a_notification_is_dropped_silently_when_no_observer_is_installed():
    posted = []
    out = await _send(
        _config(),
        _capturing_poster(posted),
        JSONRPCNotification(jsonrpc="2.0", method="notifications/cancelled"),
    )
    assert posted == [] and out == []


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
async def test_an_unexpected_exception_propagates_rather_than_being_disguised():
    # A defect is not a protocol outcome; it must not be laundered into a wire code.
    with pytest.raises(BaseException) as ei:
        await _send(_config(), _throwing_poster(RuntimeError("boom")), _request())

    leaves = _flatten(ei.value)
    assert [type(e) for e in leaves] == [RuntimeError]
    assert str(leaves[0]) == "boom"


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
