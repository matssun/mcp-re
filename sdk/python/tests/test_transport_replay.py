# SPDX-License-Identifier: Apache-2.0
"""Replay a RECORDED delegated session through the transport adapter, offline.

``test_transport_e2e.py`` proves the adapter against the real proxy, but it needs a built
Rust example and ``fastmcp`` on PATH, so it self-skips in the SDK downloader CI lane —
exactly where the shipped artifact is gated. This replays a frozen recording of a genuine
delegated session instead, so the whole verification path (credential chain, trust epoch,
audience, RFC 9530 content-digest, request binding, evidence stripping) is exercised with
no infrastructure at all.

The bytes are RECORDINGS, not constructions: the proxy signed them with a real delegated
key under a real credential the root issued. Nothing here imitates the wire format, so a
change to it fails this test rather than passing a hand-rolled lookalike.

The replay is only legitimate if the adapter reproduces the request the recorded response
was signed against, so ``_replaying_poster`` asserts exactly that, byte for byte, before
serving each reply.

Re-record with ``tools/gen_sdk_transport_fixture.py``. Mirrors
``sdk/typescript/test/transport_replay.test.ts`` — same fixture, same assertions.
"""
import base64
import json
import pathlib

import pytest

pytest.importorskip("mcp", reason="the transport adapter needs the upstream MCP SDK")

from mcp.shared.message import SessionMessage  # noqa: E402
from mcp.types import CallToolResult, JSONRPCNotification, JSONRPCRequest  # noqa: E402

from mcp_re_sdk import HttpReply, McpReConfig, Signer, mcp_re_http_transport  # noqa: E402

FIXTURE = json.loads(
    (
        pathlib.Path(__file__).resolve().parents[3]
        / "sdk"
        / "fixtures"
        / "delegated_response_replay.json"
    ).read_text()
)


def _nonce_sequence():
    """The recorded sequence: deterministic, but never repeating."""
    counter = {"n": 0}

    def next_nonce() -> str:
        nonce = f"{FIXTURE['nonce_prefix']}{counter['n']:04d}"
        counter["n"] += 1
        return nonce

    return next_nonce


def _config(**over) -> McpReConfig:
    f = FIXTURE
    args = dict(
        signer=Signer.software(base64.b64decode(f["client_seed_b64"]), f["signer_id"], f["key_id"]),
        audience_id=f["audience_id"],
        target_uri=f["target_uri"],
        route=f["route"],
        dpop_token=f["dpop_token"],
        issuer_key_id=f["issuer"]["key_id"],
        issuer_pubkey_b64url=f["issuer"]["pubkey_b64url"],
        issuer_role=f["issuer"]["role"],
        issuer_trust_domain=f["issuer"]["trust_domain"],
        issuer_subject=f["issuer"]["subject"],
        verifier_audiences=f["verifier_audiences"],
        expected_audience_hash=f["expected_audience_hash"],
        accepted_epochs=f["accepted_epochs"],
        max_clock_skew=f["max_clock_skew"],
        request_ttl=f["request_ttl"],
        # A response is bound to the request that produced it, so the request must be
        # byte-reproducible: pin the only two inputs that float. The same frozen instant
        # is handed to verification, keeping the recorded credential inside its window.
        nonce_factory=_nonce_sequence(),
        clock=lambda: f["created"],
    )
    args.update(over)
    return McpReConfig(**args)


def _replaying_poster(mutate=None):
    """Serve the recorded replies in order, refusing to serve one for a request the
    recording was not made against."""
    state = {"i": 0}

    async def post(method, target_uri, headers, body) -> HttpReply:
        exchange = FIXTURE["exchanges"][state["i"]]
        state["i"] += 1
        # If the adapter did not reproduce the recorded request byte-for-byte, the
        # recorded response does not answer it and replaying it would prove nothing.
        assert body == base64.b64decode(exchange["request_body_b64"]), (
            f"exchange {state['i'] - 1}: the adapter's request bytes drifted from the "
            f"recording; re-record with tools/gen_sdk_transport_fixture.py"
        )
        reply = HttpReply(
            status=exchange["status"],
            headers=[(k, v) for k, v in exchange["headers"]],
            body=base64.b64decode(exchange["body_b64"]),
        )
        return mutate(reply) if mutate else reply

    return post


def _initialize_request() -> JSONRPCRequest:
    """The recorded `initialize`, built here rather than taken from `ClientSession`.

    The recording pins exact request bytes, and the JSON-RPC id counter belongs to the
    session layer, not to this adapter: `mcp` 2.0 numbers from 1 where 1.x numbered from
    0, and adds an empty `params._meta`. Neither is a statement about MCP-RE, and the
    TypeScript SDK at the same major still numbers from 0 — so a recording that captured
    either one could not be replayed by both. Driving the script explicitly keeps the
    fixture a claim about the bytes THIS adapter signs, replayable from both languages.
    A real session is covered end-to-end in `test_transport_e2e.py`.
    """
    return JSONRPCRequest(
        jsonrpc="2.0",
        id=0,
        method="initialize",
        params={
            "capabilities": {},
            "clientInfo": FIXTURE["expect"]["client_info"],
            "protocolVersion": FIXTURE["expect"]["protocol_version"],
        },
    )


async def _call_tool(config, poster):
    async with mcp_re_http_transport(config, poster) as (read, write):
        await write.send(SessionMessage(_initialize_request()))
        await read.receive()
        await write.send(
            SessionMessage(JSONRPCNotification(jsonrpc="2.0", method="notifications/initialized"))
        )
        await write.send(
            SessionMessage(
                JSONRPCRequest(
                    jsonrpc="2.0",
                    id=1,
                    method="tools/call",
                    params={
                        "name": FIXTURE["tool"]["name"],
                        "arguments": FIXTURE["tool"]["arguments"],
                    },
                )
            )
        )
        reply = await read.receive()
        return CallToolResult.model_validate(reply.message.result)


async def _expect_refusal(config, poster) -> str:
    """Drive the recorded open and return the wire code it failed with."""
    async with mcp_re_http_transport(config, poster) as (read, write):
        await write.send(SessionMessage(_initialize_request()))
        reply = await read.receive()
        error = getattr(reply.message, "error", None)
        assert error is not None, f"expected a delivered JSON-RPC error, got {reply.message!r}"
        return error.message


@pytest.mark.anyio
async def test_a_recorded_delegated_session_verifies_and_reaches_the_app_as_plain_mcp():
    result = await _call_tool(_config(), _replaying_poster())

    assert result.structured_content == FIXTURE["expect"]["structured_content"]
    assert result.content[0].text == FIXTURE["expect"]["text"]
    # MCP-RE's own evidence is not part of the MCP result.
    assert "_meta" not in (result.structured_content or {})


@pytest.mark.anyio
async def test_one_appended_byte_of_the_recorded_body_fails_closed():
    # RFC 9530 content-digest covers the raw body. A trailing space keeps the JSON valid
    # on purpose: the response must be refused on its evidence, not on a parse error.
    def tamper(reply: HttpReply) -> HttpReply:
        return HttpReply(reply.status, reply.headers, reply.body + b" ")

    assert "mcp-re." in await _expect_refusal(_config(), _replaying_poster(mutate=tamper))


@pytest.mark.anyio
async def test_an_untrusted_root_anchor_refuses_the_same_recorded_response():
    # The recording is genuine; the anchor is wrong. A delegated response is only as good
    # as the root it chains to, so this must fail as loudly as a forgery. The recorded key
    # is a REAL Ed25519 public key from a different seed — a malformed one would be
    # refused as bad configuration and would prove nothing about the trust decision.
    detail = await _expect_refusal(
        _config(issuer_pubkey_b64url=FIXTURE["foreign_root_pubkey_b64url"]), _replaying_poster()
    )
    assert "mcp-re." in detail


@pytest.mark.anyio
async def test_a_response_outside_the_accepted_trust_epoch_is_refused():
    detail = await _expect_refusal(
        _config(accepted_epochs=["epoch-does-not-match"]), _replaying_poster()
    )
    assert "mcp-re.delegation_trust_epoch_stale" in detail


@pytest.mark.anyio
async def test_a_response_for_a_different_audience_is_refused():
    detail = await _expect_refusal(
        _config(expected_audience_hash="aud-scope-somewhere-else"), _replaying_poster()
    )
    assert "mcp-re." in detail


@pytest.mark.anyio
async def test_a_revoked_delegated_key_is_refused():
    # Revocation is checked against the credential's own delegated kid.
    detail = await _expect_refusal(
        _config(revoked_identifiers=[FIXTURE["delegated_key_id"]]), _replaying_poster()
    )
    assert "mcp-re." in detail


# --- ADR-MCPS-047: the continuation chain -----------------------------------------

ELICIT = FIXTURE["elicitation"]
ANSWER = ELICIT["answer"]


def _elicit_nonces():
    """The open leg's nonce, then the answer leg's. A continuation turn is a fresh
    signed request with its own freshness (continuation profile §10.1)."""
    return iter([ELICIT["nonce"], ANSWER["nonce"]]).__next__


def _chain_poster(legs):
    """Serve the recorded legs in order, refusing to serve one for a request the
    recording was not made against."""
    state = {"i": 0}

    async def post(method, target_uri, headers, body) -> HttpReply:
        assert state["i"] < len(legs), "the adapter sent more legs than were recorded"
        exchange = legs[state["i"]]
        state["i"] += 1
        assert body == base64.b64decode(exchange["request_body_b64"]), (
            f"leg {state['i'] - 1}: the adapter's request bytes drifted from the "
            f"recording; re-record with tools/gen_sdk_transport_fixture.py"
        )
        return HttpReply(
            status=exchange["status"],
            headers=[(k, v) for k, v in exchange["headers"]],
            body=base64.b64decode(exchange["body_b64"]),
        )

    return post


def _call() -> JSONRPCRequest:
    return JSONRPCRequest(
        jsonrpc="2.0",
        id=0,
        method="tools/call",
        params={"name": ELICIT["tool"], "arguments": {}},
    )


async def _drive(config, legs):
    """Run one `tools/call` through the adapter against the recorded legs."""
    async with mcp_re_http_transport(config, _chain_poster(legs)) as (read, write):
        await write.send(SessionMessage(_call()))
        return (await read.receive()).message


@pytest.mark.anyio
async def test_the_adapter_drives_the_answer_leg_to_a_terminal_result():
    """The whole point of #419: a multi-round-trip tool is an ordinary call.

    An `InputRequiredResult` is not a `CallToolResult`, so `ClientSession` cannot carry
    it — the convention lives BELOW the session layer, which is where the adapter
    implements it. So the adapter answers the elicitation itself: it signs the answer leg
    over the VERIFIED handles, posts it, verifies the reply, and hands up the terminal
    result. The caller sees one call and one result.

    The recorded answer-leg request is the load-bearing assertion here. Reproducing it
    byte-for-byte means the adapter built the continuation binding, echoed the opaque
    `requestState`, and carried `inputResponses` exactly as the profile specifies — the
    proxy accepted these very bytes when the fixture was recorded.
    """
    handles, prompts = [], []

    def answer(prompt):
        prompts.append(prompt)
        return ANSWER["responses"]

    config = _config(
        nonce_factory=_elicit_nonces(),
        on_input_required=handles.append,
        answer_input_required=answer,
    )
    message = await _drive(config, [ELICIT["exchange"], ANSWER["exchange"]])

    assert len(handles) == 1, "the adapter did not surface the elicitation"
    h = handles[0]
    expect = ELICIT["expect_handles"]
    assert h.prev_alg == expect["prev_alg"]
    assert h.prev_value == expect["prev_value"]
    assert h.irr_alg == expect["irr_alg"]
    assert h.irr_value == expect["irr_value"]
    assert h.request_state == expect["request_state"]

    # The handler is asked with everything answering needs, read from the VERIFIED reply.
    assert len(prompts) == 1
    assert prompts[0].method == "tools/call"
    assert prompts[0].round == 1
    assert prompts[0].result["resultType"] == "input_required"
    assert prompts[0].result["requestState"] == expect["request_state"]
    assert prompts[0].handles is h

    # A TERMINAL result, not the pause — and under the id the CALLER issued, not the
    # answer leg's own `0/mrt-1`.
    assert message.result == ANSWER["expect_result"]
    assert message.id == ANSWER["expect_id"]
    assert CallToolResult.model_validate(message.result).is_error is False


@pytest.mark.anyio
async def test_an_unanswerable_elicitation_is_refused_not_delivered_as_a_result():
    """A pause is not an outcome (continuation profile §5.2, §9.3).

    With no handler installed there is no answer leg to sign, so the call cannot
    complete. Delivering the `InputRequiredResult` up as the reply would present a call
    still waiting for input as one that finished — the misrepresentation the protected
    non-terminal classification exists to make detectable.
    """
    config = _config(nonce_factory=_elicit_nonces())
    message = await _drive(config, [ELICIT["exchange"]])

    assert message.error is not None, "the pause was delivered as a completed call"
    assert "no answer_input_required handler" in message.error.message


@pytest.mark.anyio
async def test_a_declined_elicitation_is_refused():
    """Declining is a decision not to continue, not a decision to accept the pause."""
    config = _config(
        nonce_factory=_elicit_nonces(),
        answer_input_required=lambda prompt: None,
    )
    message = await _drive(config, [ELICIT["exchange"]])

    assert message.error is not None
    assert "declined" in message.error.message


@pytest.mark.anyio
async def test_the_continuation_round_ceiling_is_enforced_before_the_caller_is_asked():
    """A server decides how long a chain runs, so the client must bound it.

    The ceiling is checked BEFORE the handler: a call that has already spent its
    continuation budget must not prompt for an answer it cannot send.
    """
    asked = []
    config = _config(
        nonce_factory=_elicit_nonces(),
        answer_input_required=lambda prompt: asked.append(prompt) or {},
        max_continuation_rounds=0,
    )
    message = await _drive(config, [ELICIT["exchange"]])

    assert message.error is not None
    assert "max_continuation_rounds" in message.error.message
    assert asked == [], "the handler was asked for an answer that could not be sent"


@pytest.mark.anyio
async def test_a_completed_chain_leaves_no_correlation_entry_outstanding():
    """An open leg is associated, not consumed (ADR-MCPS-047), so something must retire
    it. Left outstanding, every elicitation would leak an entry for the life of the
    session — and a peer that can elicit could grow the store at will."""
    from mcp_re_sdk import CorrelationStore

    store = CorrelationStore()
    config = _config(
        nonce_factory=_elicit_nonces(),
        answer_input_required=lambda prompt: ANSWER["responses"],
    )
    async with mcp_re_http_transport(
        config, _chain_poster([ELICIT["exchange"], ANSWER["exchange"]]), correlation=store
    ) as (read, write):
        await write.send(SessionMessage(_call()))
        await read.receive()
        assert len(store) == 0, "the chain left correlation state behind"


@pytest.mark.anyio
async def test_an_unanswered_elicitation_leaves_no_correlation_entry_outstanding():
    """The same bound on the failure path, which is the one a peer can drive."""
    from mcp_re_sdk import CorrelationStore

    store = CorrelationStore()
    config = _config(nonce_factory=_elicit_nonces())
    async with mcp_re_http_transport(
        config, _chain_poster([ELICIT["exchange"]]), correlation=store
    ) as (read, write):
        await write.send(SessionMessage(_call()))
        await read.receive()
        assert len(store) == 0


@pytest.mark.anyio
async def test_a_verified_rejection_receipt_is_delivered_as_an_error_not_a_result():
    """A recorded DELEGATED rejection: genuine evidence, but NOT an acceptance.

    The proxy refused a replayed nonce and signed the refusal. The adapter must verify
    that receipt, read its frozen wire code from the TRUSTED body (never from the HTTP
    status), and deliver it as a JSON-RPC error correlated to the request — so the caller
    raises instead of hanging, and the refusal never lands as a result.
    """
    rejection = FIXTURE["rejection"]

    async def post(method, target_uri, headers, body) -> HttpReply:
        assert body == base64.b64decode(rejection["request_body_b64"])
        return HttpReply(
            status=rejection["status"],
            headers=[(k, v) for k, v in rejection["headers"]],
            body=base64.b64decode(rejection["body_b64"]),
        )

    config = _config(nonce_factory=lambda: FIXTURE["elicitation"]["nonce"])
    async with mcp_re_http_transport(config, post) as (read, write):
        await write.send(
            SessionMessage(
                JSONRPCRequest(
                    jsonrpc="2.0",
                    id=0,
                    method="tools/call",
                    params={"name": FIXTURE["elicitation"]["tool"], "arguments": {}},
                )
            )
        )
        reply = await read.receive()

    error = reply.message.error
    assert error.code == -31001
    assert error.message == rejection["expect_wire_code"]
    # The core computes whether the receipt is bound to THIS transmission, and that fact
    # must reach the application. An unbound (preflight) receipt carries no binding to
    # this request's nonce or evidence, so one such signed receipt answers any request
    # from any client of that issuer — the caller has to be able to tell "the boundary
    # rejected MY request" from "a generic rejection arrived" (RSP-7). It travels beside
    # the frozen token, never inside it. The TypeScript twin pins the same value.
    assert error.data == {"requestBound": True}
