"""Live end-to-end: Python SDK adapter <-> real Rust server-side MCP-S proxy.

Topology (the SDK adapter e2e — NOT the Rust client proxy):

    mcp request (SessionMessage)
      -> McpsTransport            (this SDK, the client-side MCP-S component)
      -> real subprocess stdio
      -> mcps-stdio-server --mode proxy   (the REAL mcps_proxy::Proxy, server-side
                                           PEP, verifies signature + freshness +
                                           audience, signs the response)
      -> plain echo inner                 (an unmodified MCP-S-unaware server)

This proves the round trip the unit tests could not (a pure-Python test cannot
produce a server-signed response): a signed request the real Rust verifier accepts,
and a real Rust-signed response the adapter verifies + correlates + strips to plain.

Identities are the frozen conformance fixtures (mcps-conformance §fixtures): the
agent signer seed [1;32] (did:example:agent-1 / key-1) the server trusts, and the
server signer seed [2;32] (did:example:server-1 / server-key-1) the adapter trusts.
The server's verification clock is pinned with --now-unix, so the adapter signs in
the fixture freshness window (2026-05-28T20:00:00Z..20:05:00Z).

Requires `mcp` (Python >= 3.10) and the built binary:
    cargo build -p mcps-conformance --bin mcps-stdio-server
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from subprocess import PIPE

import pytest

import mcps_sdk
from mcps_sdk.transport import McpsConfig, McpsTransport, McpsVerificationError

anyio = pytest.importorskip("anyio")
pytest.importorskip("mcp.types")
from mcp.shared.message import SessionMessage  # noqa: E402
from mcp.types import JSONRPCMessage  # noqa: E402

BIN = os.environ.get("MCPS_STDIO_SERVER") or str(
    Path(__file__).resolve().parents[3] / "target" / "debug" / "mcps-stdio-server"
)
if not Path(BIN).exists():
    pytest.skip(
        "mcps-stdio-server not built — run "
        "`cargo build -p mcps-conformance --bin mcps-stdio-server`",
        allow_module_level=True,
    )

# Pinned to the fixture freshness window so requests are fresh at the server's --now.
NOW = int(datetime(2026, 5, 28, 20, 0, 0, tzinfo=timezone.utc).timestamp())


def _base_config(resolver):
    return McpsConfig(
        signer=mcps_sdk.Signer.software(bytes([1] * 32), signer_id="did:example:agent-1", key_id="key-1"),
        policy=mcps_sdk.SignerPolicy("did:example:agent-1", environment="dev-test", require_mcps=True),
        resolver=resolver,
        audience="did:example:server-1",
        on_behalf_of="did:example:user-1",
        binding_digest_alg="sha256",
        binding_digest_value="RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o",
        expected_server_signer="did:example:server-1",
        enforcement_mode="require_mcps",
        ttl_seconds=300,
    )


def _trusting_config():
    resolver = mcps_sdk.TrustResolver()
    resolver.insert_dev_seed("did:example:server-1", "server-key-1", bytes([2] * 32))
    return _base_config(resolver)


def _untrusting_config():
    return _base_config(mcps_sdk.TrustResolver())  # empty: server signer cannot resolve


def _tools_call(rid, text):
    raw = json.dumps(
        {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
         "params": {"name": "echo", "arguments": {"text": text}}}
    )
    return SessionMessage(JSONRPCMessage.model_validate_json(raw))


async def _roundtrip(config, text):
    process = await anyio.open_process(
        [BIN, "--now-unix", str(NOW), "--mode", "proxy"], stdin=PIPE, stdout=PIPE
    )

    async def byte_send(data: bytes) -> None:
        await process.stdin.send(data)

    async def byte_lines():
        buffer = b""
        async for chunk in process.stdout:
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                if line:
                    yield line

    transport = McpsTransport(byte_send, byte_lines(), config, clock=lambda: NOW)
    try:
        with anyio.fail_after(20):
            async with transport as (read_stream, write_stream):
                await write_stream.send(_tools_call("req-1", text))
                return await read_stream.receive()
    finally:
        # Reap the subprocess cleanly (EOF its stdin, then wait) so the event loop
        # closes without a dangling child-process transport.
        with anyio.move_on_after(5, shield=True):
            await process.stdin.aclose()
            process.terminate()
            await process.wait()


def test_live_roundtrip_against_real_rust_server():
    """A plain tools/call is signed, accepted by the real Rust server-side proxy,
    the echo executes, the server-signed response is verified + correlated, and a
    plain MCP result comes back to us."""
    msg = anyio.run(_roundtrip, _trusting_config(), "hello-live")
    assert not isinstance(msg, Exception), msg
    dumped = json.loads(msg.message.model_dump_json(by_alias=True, exclude_none=True))
    assert dumped["result"]["content"][0]["text"] == "hello-live"
    assert "_meta" not in dumped["result"], "MCP-S envelope must be stripped"


def test_live_fails_closed_when_server_untrusted():
    """The server returns a genuinely-signed response, but with no trust anchor for
    its signer the adapter fails closed — no plain MCP result is delivered."""
    msg = anyio.run(_roundtrip, _untrusting_config(), "should-not-deliver")
    assert isinstance(msg, McpsVerificationError)
    assert msg.reason == "mcps.actor_binding_failed"
