# SPDX-License-Identifier: Apache-2.0
"""Live e2e: a real ``mcp.ClientSession`` through ``McpReHttpTransport`` against the
real Rust ``http_profile_proxy`` and a real FastMCP Streamable-HTTP backend.

This is the claim the adapter exists to make: **application code calls
``session.call_tool(...)`` and nothing else** — no ``sign_request``, no
``verify_response``, no correlation. If that only worked against a stub, it would prove
nothing, so the counterparty here is the project's own proof harness: it signs
DELEGATED responses (ADR-MCPRE-052) and emits delegated rejection receipts, exactly as
the production serving path does.

Skips cleanly when the harness is unavailable (no `fastmcp`, or the examples are not
built), so the Bazel-free downloader lane stays green without it.

Prerequisites, from the repo root::

    cargo build -p mcp-re-proxy --example http_profile_proxy
    brew install fastmcp
"""
import base64
import os
import shutil
import socket
import subprocess
import sys
import time
import tomllib
from pathlib import Path

import pytest

pytest.importorskip("mcp", reason="the transport adapter needs the upstream MCP SDK")
pytest.importorskip("httpx")
pytest.importorskip("cryptography")

import httpx  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from mcp import ClientSession  # noqa: E402

from mcp_re_sdk import (  # noqa: E402
    HttpReply,
    McpReConfig,
    Signer,
    SignerPolicy,
    mcp_re_http_transport,
)

# The hpp_common demo material — deterministic proof seeds, TEST-ONLY.
CLIENT_SEED = bytes([11]) * 32
ROOT_SEED = bytes([22]) * 32
REPO_ROOT = Path(__file__).resolve().parents[3]
PROXY_BIN = REPO_ROOT / "target" / "debug" / "examples" / "http_profile_proxy"
BACKEND = REPO_ROOT / "tools" / "fastmcp_inner_backend.py"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


ROOT_PUB = _b64url(Ed25519PrivateKey.from_private_bytes(ROOT_SEED).public_key().public_bytes_raw())


def _port(service: str) -> int:
    # No hardcoded ports: config/ports.toml is the single source of truth.
    with (REPO_ROOT / "config" / "ports.toml").open("rb") as f:
        return tomllib.load(f)["services"][service]["port"]


def _wait_port(port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as s:
            s.settimeout(0.2)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


@pytest.fixture(scope="module")
def harness():
    """The real proxy + real FastMCP backend, as the proof script stands them up."""
    if not PROXY_BIN.exists():
        pytest.skip(f"{PROXY_BIN} not built (cargo build -p mcp-re-proxy --example http_profile_proxy)")
    if shutil.which("fastmcp") is None:
        pytest.skip("fastmcp not on PATH")

    front, inner = _port("mcp_re_http_profile_proxy"), _port("mcp_re_inner_backend")
    target = f"http://127.0.0.1:{front}/mcp"
    procs = []

    if not _wait_port(inner, 0.3):
        procs.append(
            subprocess.Popen(
                ["fastmcp", "run", f"{BACKEND}:mcp", "--transport", "http", "--host", "127.0.0.1",
                 "--port", str(inner), "--stateless", "--path", "/mcp/", "--no-banner"],
                env={**os.environ, "FASTMCP_JSON_RESPONSE": "true", "FASTMCP_STATELESS_HTTP": "true"},
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        )
        if not _wait_port(inner):
            for p in procs:
                p.kill()
            pytest.skip("FastMCP backend did not come up")

    procs.append(
        subprocess.Popen(
            [str(PROXY_BIN)],
            env={**os.environ, "HPP_BIND": f"127.0.0.1:{front}",
                 "HPP_INNER_URL": f"http://127.0.0.1:{inner}/mcp/", "HPP_TARGET": target},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    )
    if not _wait_port(front):
        for p in procs:
            p.kill()
        pytest.skip("http_profile_proxy did not bind")

    yield target

    for p in procs:
        p.kill()
        p.wait(timeout=5)


def _config(target: str, **over) -> McpReConfig:
    args = dict(
        signer=Signer.software(CLIENT_SEED, "did:example:host-a", "client-key-1"),
        policy=SignerPolicy("did:example:host-a", profile="development"),
        audience_id="verifier-1",
        target_uri=target,
        route="a",
        dpop_token="access-token-xyz",
        # A standard ClientSession cannot complete its lifecycle without
        # `notifications/initialized`, and MCP-RE has no ratified one-way notification
        # profile yet (#418) — so every live session today needs this unsafe opt-in.
        # That it is required here is the point: the hole is visible, not papered over.
        unsafe_drop_notifications=True,
        # The trusted ROOT anchor only: the delegated key is learned from the credential
        # the response carries, never enrolled here.
        issuer_key_id="server-key-1",
        issuer_pubkey_b64url=ROOT_PUB,
        issuer_role="server",
        issuer_trust_domain="example.com",
        issuer_subject="did:example:server-1",
        verifier_audiences=["verifier-1"],
        expected_audience_hash="aud-scope-1",
        accepted_epochs=["epoch-1"],
        max_clock_skew=60,
    )
    args.update(over)
    return McpReConfig(**args)


def _poster(client: httpx.AsyncClient):
    async def post(method, target_uri, headers, body) -> HttpReply:
        r = await client.request(method, target_uri, headers=dict(headers), content=body)
        return HttpReply(status=r.status_code, headers=list(r.headers.items()), body=r.content)

    return post


@pytest.mark.anyio
async def test_a_real_session_calls_a_tool_with_no_sign_verify_in_app_code(harness):
    dropped = []
    async with httpx.AsyncClient(timeout=15) as http:
        config = _config(harness, on_dropped_notification=dropped.append)
        async with mcp_re_http_transport(config, _poster(http)) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                assert init.serverInfo.name == "mcp-re-inner-backend"

                result = await session.call_tool("add", {"a": 2, "b": 40})

                # The real FastMCP tool ran behind the real proxy.
                assert result.content[0].text == "42"
                assert result.structuredContent == {"result": 42}
                # The app never saw MCP-RE's own evidence block.
                assert "_meta" not in (result.structuredContent or {})

    # A client->server notification has no reply, so it carries no evidence and cannot be
    # verified. Dropping it is the honest behaviour — but it must be observable.
    assert "notifications/initialized" in dropped


@pytest.mark.anyio
async def test_a_signed_rejection_raises_correlated_rather_than_hanging(harness):
    """A replay is refused by the proxy with a DELEGATED rejection receipt.

    The adapter must verify that receipt, read its frozen wire code, and deliver it as a
    JSON-RPC error correlated to the request id — so the awaiting call RAISES. A dropped
    failure would hang the session forever, which is a worse failure than an error.
    """
    async with httpx.AsyncClient(timeout=15) as http:
        # Freeze the nonce so the second call is a byte-identical replay.
        config = _config(harness, nonce_factory=lambda: "nonce-adapter-replay-fixed")
        async with mcp_re_http_transport(config, _poster(http)) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # The replay: `initialize` already consumed this nonce.
                with pytest.raises(Exception) as ei:
                    await session.call_tool("add", {"a": 1, "b": 1})

    assert "mcp-re.replay_detected" in str(ei.value)


@pytest.mark.anyio
async def test_a_tampered_response_fails_closed_and_never_reaches_the_app(harness):
    """Flip one byte of the signed body: verification must refuse it."""
    async with httpx.AsyncClient(timeout=15) as http:
        inner = _poster(http)

        async def tampering(method, target_uri, headers, body) -> HttpReply:
            reply = await inner(method, target_uri, headers, body)
            # RFC 9530 content-digest covers the raw body, so ANY edit must break
            # verification. A trailing space keeps the JSON valid on purpose: the
            # response must be refused on its evidence, not because it failed to parse.
            return HttpReply(reply.status, reply.headers, reply.body + b" ")

        async with mcp_re_http_transport(_config(harness), tampering) as (read, write):
            async with ClientSession(read, write) as session:
                with pytest.raises(Exception) as ei:
                    await session.initialize()

    assert "mcp-re." in str(ei.value)


@pytest.mark.anyio
async def test_an_unsigned_response_fails_closed(harness):
    """A response with the evidence stripped is not evidence — it must be refused."""
    async with httpx.AsyncClient(timeout=15) as http:

        async def unsigned(method, target_uri, headers, body) -> HttpReply:
            return HttpReply(200, [("Content-Type", "application/json")],
                             b'{"jsonrpc":"2.0","id":0,"result":{"ok":true}}')

        async with mcp_re_http_transport(_config(harness), unsigned) as (read, write):
            async with ClientSession(read, write) as session:
                with pytest.raises(Exception) as ei:
                    await session.initialize()

    assert "mcp-re." in str(ei.value)


@pytest.mark.anyio
async def test_the_hardening_profile_refuses_a_software_key_before_connecting(harness):
    """Custody is checked at open, so a violation fails the connection, not a request."""
    from mcp_re_sdk import McpReError

    async with httpx.AsyncClient(timeout=15) as http:
        config = _config(harness, policy=SignerPolicy.hardened("did:example:host-a"))
        with pytest.raises(McpReError) as ei:
            async with mcp_re_http_transport(config, _poster(http)):
                pass
    assert ei.value.wire_code == "mcp-re.actor_binding_failed"
