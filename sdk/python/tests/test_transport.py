"""Transport-adapter tests (#199, transport slice).

The adapter's security core is two sync functions: sign_outbound (sign + register)
and verify_inbound (correlate + verify + strip). These are tested against the same
golden vectors as the bindings, proving the adapter writes byte-identical signed
requests and verifies responses exactly — the exact pipeline
:class:`~mcp_re_sdk.http_transport.McpReHttpTransport` drives over the mTLS wire.

Requires `mcp` installed (Python >= 3.10).
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import mcp_re_sdk
from mcp_re_sdk.transport import (
    McpReConfig,
    sign_outbound,
    verify_inbound,
)

# These tests exercise the real mcp ClientSession message types; skip cleanly where
# mcp/anyio are not installed (e.g. a core-only Python < 3.10 env).
anyio = pytest.importorskip("anyio")
pytest.importorskip("mcp.types")
from mcp.shared.message import SessionMessage  # noqa: E402
from mcp.types import JSONRPCMessage  # noqa: E402

FIX = Path(__file__).parent / "fixtures"
REQ_VEC = json.loads((FIX / "sign_request_vector.json").read_text())
REQ = REQ_VEC["inputs"]
REQ_EXPECTED_WIRE = REQ_VEC["expected_wire_bytes"]
RESP = json.loads((FIX / "verify_response_vectors.json").read_text())
SERVER = RESP["server"]

# The request fixture was signed with issued_at=20:00:00Z, expires=20:05:00Z.
NOW = int(datetime(2026, 6, 30, 20, 0, 0, tzinfo=timezone.utc).timestamp())
TTL = 300


def _config(**kw):
    signer = mcp_re_sdk.Signer.software(
        bytes.fromhex(REQ["seed_hex"]), signer_id=REQ["signer"], key_id=REQ["key_id"]
    )
    policy = mcp_re_sdk.SignerPolicy(REQ["signer"], environment="dev-test", require_mcp_re=True)
    resolver = mcp_re_sdk.TrustResolver()
    resolver.insert_public_key(
        SERVER["signer_id"], SERVER["key_id"], bytes.fromhex(SERVER["public_key_hex"])
    )
    base = dict(
        signer=signer,
        policy=policy,
        resolver=resolver,
        audience=REQ["audience"],
        on_behalf_of=REQ["on_behalf_of"],
        binding_digest_alg=REQ["binding_digest_alg"],
        binding_digest_value=REQ["binding_digest_value"],
        expected_server_signer=SERVER["signer_id"],
        ttl_seconds=TTL,
    )
    base.update(kw)
    return McpReConfig(**base)


def _sm_request(rid, method, params):
    raw = json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
    return SessionMessage(JSONRPCMessage.model_validate_json(raw))


def _valid_response_bytes():
    return next(s for s in RESP["scenarios"] if s["name"] == "valid")["response_bytes"].encode()


# --- sync security core ----------------------------------------------------

def test_sign_outbound_matches_request_vector():
    """The adapter's writer produces byte-identical signed bytes to the golden
    request vector, and registers the request for correlation."""
    corr = mcp_re_sdk.CorrelationStore()
    sm = _sm_request("req-1", "tools/call", {"name": "echo", "arguments": {"text": "hello"}})
    wire = sign_outbound(sm, _config(), corr, now_unix=NOW, nonce=REQ["nonce"], expires_unix=NOW + TTL)
    assert wire.decode() == REQ_EXPECTED_WIRE
    assert corr.outstanding == 1


def test_sign_outbound_passes_through_notification():
    corr = mcp_re_sdk.CorrelationStore()
    notif = SessionMessage(
        JSONRPCMessage.model_validate_json('{"jsonrpc":"2.0","method":"notifications/cancelled"}')
    )
    wire = sign_outbound(notif, _config(), corr, now_unix=NOW, nonce="n", expires_unix=NOW + TTL)
    assert b"notifications/cancelled" in wire
    assert corr.outstanding == 0  # not a request -> not correlated


def _register_for_valid(corr):
    corr.register(
        correlation_id="req-1",
        request_hash=RESP["client_request_hash"],
        nonce="n1",
        deadline_unix=NOW + TTL,
        now_unix=NOW,
    )


def test_verify_inbound_accepts_and_strips_envelope():
    corr = mcp_re_sdk.CorrelationStore()
    _register_for_valid(corr)
    out = verify_inbound(_valid_response_bytes(), _config(), corr, now_unix=NOW + 1)
    assert out.kind == "accept"
    dumped = json.loads(out.message.message.model_dump_json(by_alias=True, exclude_none=True))
    assert "_meta" not in dumped.get("result", {}), "MCP-RE envelope must be stripped"
    assert corr.outstanding == 0  # correlation consumed


def test_verify_inbound_rejects_tampered():
    corr = mcp_re_sdk.CorrelationStore()
    _register_for_valid(corr)
    tampered = next(s for s in RESP["scenarios"] if s["name"] == "tampered_signature")
    out = verify_inbound(tampered["response_bytes"].encode(), _config(), corr, now_unix=NOW + 1)
    assert out.kind == "reject"
    assert out.reason == "mcp-re.response_sig_invalid"


def test_verify_inbound_uncorrelatable_without_pending():
    """A response with no registered request fails closed (uncorrelatable)."""
    out = verify_inbound(_valid_response_bytes(), _config(), mcp_re_sdk.CorrelationStore(), now_unix=NOW + 1)
    assert out.kind == "reject"
    assert out.reason == "mcp-re.response_hash_mismatch"


def test_verify_inbound_rejects_server_notification_by_default():
    """A server-initiated NOTIFICATION (no id) has no request_hash binding, so the
    core cannot verify it; the safe default fails closed with the frozen reason."""
    notif = json.dumps({"jsonrpc": "2.0", "method": "notifications/message", "params": {"x": 1}}).encode()
    out = verify_inbound(notif, _config(), mcp_re_sdk.CorrelationStore(), now_unix=NOW)
    assert out.kind == "reject"
    assert out.reason == "mcp-re.notification_forbidden"


def test_verify_inbound_rejects_server_request_by_default():
    """A server-initiated REQUEST (id + method, e.g. sampling) is likewise
    unverifiable (no request_hash we hold) and fails closed."""
    req = json.dumps({"jsonrpc": "2.0", "id": "s-1", "method": "sampling/createMessage", "params": {}}).encode()
    out = verify_inbound(req, _config(), mcp_re_sdk.CorrelationStore(), now_unix=NOW)
    assert out.kind == "reject"
    assert out.reason == "mcp-re.missing_envelope"


def test_verify_inbound_passes_through_server_initiated_when_allowed():
    """With the explicit opt-in, a server-initiated message is delivered unverified
    (audited as no-evidence) instead of failing closed."""
    notif = json.dumps({"jsonrpc": "2.0", "method": "notifications/message", "params": {"x": 1}}).encode()
    config = _config(allow_unverified_server_initiated=True)
    out = verify_inbound(notif, config, mcp_re_sdk.CorrelationStore(), now_unix=NOW)
    assert out.kind == "passthrough"
    assert out.message.message.root.method == "notifications/message"


def test_verify_inbound_passes_through_server_request_when_allowed():
    """The fourth cell of the server-initiated matrix: an id-bearing server REQUEST
    under the explicit degraded opt-in is delivered unverified (audited no-evidence),
    keeping its id + method so a session could respond. Strict require_mcp_re still
    rejects it (test_verify_inbound_rejects_server_request_by_default)."""
    req = json.dumps(
        {"jsonrpc": "2.0", "id": "s-7", "method": "sampling/createMessage", "params": {"m": 1}}
    ).encode()
    config = _config(allow_unverified_server_initiated=True)
    out = verify_inbound(req, config, mcp_re_sdk.CorrelationStore(), now_unix=NOW)
    assert out.kind == "passthrough"
    assert out.message.message.root.method == "sampling/createMessage"
    assert str(out.message.message.root.id) == "s-7"
