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

from mcp import ClientSession  # noqa: E402

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


async def _call_tool(config, poster):
    async with mcp_re_http_transport(config, poster) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.call_tool(FIXTURE["tool"]["name"], FIXTURE["tool"]["arguments"])


async def _expect_refusal(config, poster) -> str:
    """Run the session and return the wire code it failed with."""
    async with mcp_re_http_transport(config, poster) as (read, write):
        async with ClientSession(read, write) as session:
            with pytest.raises(Exception) as ei:
                await session.initialize()
            return str(ei.value)


@pytest.mark.anyio
async def test_a_recorded_delegated_session_verifies_and_reaches_the_app_as_plain_mcp():
    result = await _call_tool(_config(), _replaying_poster())

    assert result.structuredContent == FIXTURE["expect"]["structured_content"]
    assert result.content[0].text == FIXTURE["expect"]["text"]
    # MCP-RE's own evidence is not part of the MCP result.
    assert "_meta" not in (result.structuredContent or {})


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
