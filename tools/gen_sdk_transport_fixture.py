#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Record a REAL delegated session into a replayable transport fixture.

    sdk/fixtures/delegated_response_replay.json

The transport adapters are proved live against the real proxy + a real FastMCP backend
(`test_transport_e2e.py` / `transport_e2e.test.ts`), but those tests need a built Rust
example and `fastmcp` on PATH, so they self-skip in the SDK downloader CI lanes — leaving
the adapters' verification path untested exactly where the shipped artifact is gated. This
fixture closes that hole: it freezes a genuine, delegated, production-shaped session so
both SDKs can replay it offline, deterministically, with no infrastructure.

These are RECORDINGS, not constructions — the proxy signed them with a real delegated key
under a real credential the root issued. Replaying them exercises the whole verification
path (credential chain, trust epoch, audience, RFC 9530 content-digest, request binding)
rather than a hand-rolled imitation of the wire format.

**The recording runs through the adapter**, not around it. A response signature is bound to
the request that produced it, so a replayed request must be byte-identical or verification
correctly refuses it — which means the request bytes must be the adapter's own. Determinism
comes from pinning the only two inputs that float: the clock, and a counter-based nonce
sequence (a frozen single nonce would make the second request a replay of the first, and
the proxy would rightly reject it).

Re-record when the wire format changes; a stale fixture fails the replay test, which is the
point. From the repo root, with the harness up (see sdk/python/tests/test_transport_e2e.py
for how it is started):

    cargo build -p mcp-re-proxy --example http_profile_proxy
    python tools/gen_sdk_transport_fixture.py [target]
"""
import base64
import json
import pathlib
import sys
import time

import anyio
import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp import ClientSession
from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCRequest

from mcp_re_sdk import HttpReply, McpReConfig, Signer, mcp_re_http_transport

# The hpp_common demo material — deterministic proof seeds, TEST-ONLY.
CLIENT_SEED = bytes([11]) * 32
ROOT_SEED = bytes([22]) * 32
NONCE_PREFIX = "nonce-transport-fixture-"
OUT = pathlib.Path("sdk/fixtures/delegated_response_replay.json")

TOOL = "add"
TOOL_ARGS = {"a": 2, "b": 40}
#: The ADR-MCPS-047 eliciting tool. Its OPEN leg returns an `InputRequiredResult`, which
#: is not an ordinary `CallToolResult`, so it is driven through the transport's streams
#: rather than `ClientSession.call_tool` — the elicitation convention lives below the
#: session layer. Served by the backend's ConfirmActionShim (its direct-run entry point;
#: `fastmcp run` bypasses the shim and never elicits).
ELICIT_TOOL = "confirm_action"
ELICIT_NONCE = "nonce-transport-fixture-elicit"


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


ROOT_PUB = b64url(Ed25519PrivateKey.from_private_bytes(ROOT_SEED).public_key().public_bytes_raw())


def nonce_sequence():
    """Deterministic, but never repeating: the proxy's replay window is real."""
    counter = {"n": 0}

    def next_nonce() -> str:
        nonce = f"{NONCE_PREFIX}{counter['n']:04d}"
        counter["n"] += 1
        return nonce

    return next_nonce


def base_config(target: str, created: int, poster_nonce, **over) -> McpReConfig:
    args = dict(
        signer=Signer.software(CLIENT_SEED, "did:example:host-a", "client-key-1"),
        audience_id="verifier-1",
        target_uri=target,
        route="a",
        dpop_token="access-token-xyz",
        issuer_key_id="server-key-1",
        issuer_pubkey_b64url=ROOT_PUB,
        issuer_role="server",
        issuer_trust_domain="example.com",
        issuer_subject="did:example:server-1",
        verifier_audiences=["verifier-1"],
        expected_audience_hash="aud-scope-1",
        accepted_epochs=["epoch-1"],
        max_clock_skew=60,
        request_ttl=300,
        # A standard ClientSession sends `notifications/initialized`; MCP-RE has no
        # ratified one-way notification profile yet (#418), so recording a session needs
        # the unsafe opt-in to get one open at all.
        unsafe_drop_notifications=True,
        nonce_factory=poster_nonce,
        clock=lambda: created,
    )
    args.update(over)
    return McpReConfig(**args)


async def record(target: str, created: int) -> dict:
    exchanges = []
    elicitation = {}

    async with httpx.AsyncClient(timeout=15) as http:

        async def poster(method, target_uri, headers, body) -> HttpReply:
            r = await http.request(method, target_uri, headers=dict(headers), content=body)
            exchanges.append(
                {
                    # The exact bytes the adapter signed. Replay asserts it reproduces
                    # these, which is what makes serving the recorded reply legitimate.
                    "request_body_b64": b64(body),
                    "status": r.status_code,
                    "headers": [[k, v] for k, v in r.headers.items()],
                    "body_b64": b64(r.content),
                }
            )
            if r.status_code != 200:
                raise SystemExit(f"proxy refused a recording request: {r.status_code} {r.text[:200]}")
            return HttpReply(status=r.status_code, headers=list(r.headers.items()), body=r.content)

        config = base_config(target, created, nonce_sequence())

        async with mcp_re_http_transport(config, poster) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                await session.call_tool(TOOL, TOOL_ARGS)

        # --- the ADR-MCPS-047 open leg, recorded separately ------------------------
        #
        # An `InputRequiredResult` is not a `CallToolResult`, so `ClientSession` cannot
        # carry it: the elicitation convention lives BELOW the session layer, which is
        # where the adapter implements it. Drive the transport's streams directly, with
        # its own nonce and a fresh correlation store.
        handles = []
        elicit_config = base_config(
            target,
            created,
            lambda: ELICIT_NONCE,
            on_input_required=handles.append,
        )
        elicit_exchange = {}

        # The signed request is kept whole, so the rejection recording below can re-send
        # the very same bytes rather than a reconstruction of them.
        sent = {}

        async def elicit_poster(method, target_uri, headers, body) -> HttpReply:
            r = await http.request(method, target_uri, headers=dict(headers), content=body)
            sent.update(method=method, target_uri=target_uri, headers=list(headers), body=body)
            elicit_exchange.update(
                {
                    "request_body_b64": b64(body),
                    "status": r.status_code,
                    "headers": [[k, v] for k, v in r.headers.items()],
                    "body_b64": b64(r.content),
                }
            )
            if r.status_code != 200:
                raise SystemExit(f"proxy refused the elicitation open leg: {r.status_code} {r.text[:200]}")
            return HttpReply(status=r.status_code, headers=list(r.headers.items()), body=r.content)

        async with mcp_re_http_transport(elicit_config, elicit_poster) as (read, write):
            await write.send(
                SessionMessage(
                    JSONRPCMessage(
                        JSONRPCRequest(
                            jsonrpc="2.0",
                            id=0,
                            method="tools/call",
                            params={"name": ELICIT_TOOL, "arguments": {}},
                        )
                    )
                )
            )
            await read.receive()

        if not handles:
            raise SystemExit(
                f"the backend did not elicit: {ELICIT_TOOL} returned no InputRequiredResult. "
                "Start it via its direct-run entry point (python tools/fastmcp_inner_backend.py), "
                "not `fastmcp run` — the latter bypasses the ConfirmActionShim."
            )
        # --- a signed REJECTION receipt, recorded ---------------------------------
        #
        # Re-send the open leg's exact bytes. Its nonce is spent, so the proxy refuses the
        # replay with a DELEGATED rejection receipt: genuine evidence, but NOT an
        # acceptance. The adapter must deliver it as an error — a path no accepted
        # response can exercise.
        rr = await http.request(
            sent["method"], sent["target_uri"], headers=dict(sent["headers"]), content=sent["body"]
        )
        if rr.status_code == 200:
            raise SystemExit("the proxy accepted a replayed nonce; it should have refused it")
        rejection = {
            "request_body_b64": b64(sent["body"]),
            "status": rr.status_code,
            "headers": [[k, v] for k, v in rr.headers.items()],
            "body_b64": b64(rr.content),
            # Read from the TRUSTED body by the verifier, not from the HTTP status.
            "expect_wire_code": "mcp-re.replay_detected",
        }

        h = handles[0]
        elicitation = {
            "nonce": ELICIT_NONCE,
            "tool": ELICIT_TOOL,
            "exchange": elicit_exchange,
            # The two evidence handles + opaque state the answer leg must sign over.
            # `prev` is the OPEN leg's request evidence; `irr` is the input-required
            # response's. Frozen so a replay proves the adapter surfaces the right pair.
            "expect_handles": {
                "prev_alg": h.prev_alg,
                "prev_value": h.prev_value,
                "irr_alg": h.irr_alg,
                "irr_value": h.irr_value,
                "request_state": h.request_state,
            },
        }

    return {
        "_comment": (
            "RECORDED delegated exchanges from the real http_profile_proxy, captured "
            "through the transport adapter itself. Replayed offline by the SDK transport "
            "tests so the verification path is exercised where the live harness cannot "
            "run. Re-record with tools/gen_sdk_transport_fixture.py."
        ),
        "client_seed_b64": b64(CLIENT_SEED),
        "signer_id": "did:example:host-a",
        "key_id": "client-key-1",
        "nonce_prefix": NONCE_PREFIX,
        "created": created,
        "request_ttl": 300,
        "target_uri": target,
        "audience_id": "verifier-1",
        "route": "a",
        "dpop_token": "access-token-xyz",
        "issuer": {
            "key_id": "server-key-1",
            "pubkey_b64url": ROOT_PUB,
            "role": "server",
            "trust_domain": "example.com",
            "subject": "did:example:server-1",
        },
        # A REAL Ed25519 public key from a different seed, for the untrusted-anchor test.
        # It is recorded rather than derived in the tests so replaying needs no crypto
        # library in either language; a MALFORMED key would be refused as bad
        # configuration and would prove nothing about the trust decision.
        "foreign_root_pubkey_b64url": b64url(
            Ed25519PrivateKey.from_private_bytes(bytes([99]) * 32).public_key().public_bytes_raw()
        ),
        "verifier_audiences": ["verifier-1"],
        "expected_audience_hash": "aud-scope-1",
        "accepted_epochs": ["epoch-1"],
        "max_clock_skew": 60,
        # The delegated kid the credential authorizes, for the revocation test.
        "delegated_key_id": "server-key-1/delegated/1",
        "tool": {"name": TOOL, "arguments": TOOL_ARGS},
        # In order: initialize, tools/call, then the tools/list the MCP SDK issues to
        # validate structuredContent. The client->server notifications/initialized
        # carries no evidence and never reaches the wire.
        "exchanges": exchanges,
        # The ADR-MCPS-047 open leg, driven below the session layer.
        "elicitation": elicitation,
        # A delegated rejection receipt for the open leg's replayed bytes.
        "rejection": rejection,
        "expect": {
            "server_name": "mcp-re-inner-backend",
            "structured_content": {"result": 42},
            "text": "42",
            # `initialize` params carry the MCP client LIBRARY's identity, not MCP-RE's.
            # Recorded so the other language's replay can announce the same thing and the
            # request bytes stay comparable — a difference here would say nothing about
            # this SDK.
            "client_info": {"name": "mcp", "version": "0.1.0"},
        },
    }


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8601/mcp"
    fixture = anyio.run(record, target, int(time.time()))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(fixture, indent=2) + "\n")
    print(f"wrote {OUT}: {len(fixture['exchanges'])} exchanges, created={fixture['created']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
