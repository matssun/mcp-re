"""Authorization-binding providers — real digest from real evidence.

The point of the hardening: the `authorization_binding.digest_value` is computed by
the audited core over the ACTUAL artifact bytes, not handed in as a constant. The
key check is an INDEPENDENT oracle — Python's stdlib SHA-256 + base64url-no-pad must
equal the Rust-computed digest — plus the per-route policy fail-closed behaviour and
that a provider-built binding actually lands in the signed preimage.
"""

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import mcps_sdk
from mcps_sdk.authorization import (
    AuthzReference,
    AuthzSystemReferenceProvider,
    BindingRequestContext,
    OpaqueBytesProvider,
    StaticAuthorizationProvider,
)


def _expected_opaque(data: bytes) -> str:
    """base64url-no-pad(SHA-256(bytes)) — the ADR-MCPS-039 opaque digest, computed
    here independently of the Rust core."""
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def _ctx():
    return BindingRequestContext(
        audience="did:example:server-1", route_id="default",
        method="tools/call", tool_id="read_file", deadline_unix=1_900_000_000,
    )


# --- the binding digest is REAL (independent SHA-256 oracle) ----------------

def test_opaque_digest_matches_independent_sha256():
    data = b"a-real-bearer-token's-decoded-bytes"
    binding = mcps_sdk.AuthorizationBinding.opaque_bytes(data)
    assert binding.binding_type == "opaque-bytes"
    assert binding.digest_alg == "sha256"
    assert binding.digest_value == _expected_opaque(data)


def test_opaque_digest_empty_bytes():
    binding = mcps_sdk.AuthorizationBinding.opaque_bytes(b"")
    assert binding.digest_value == _expected_opaque(b"")


def test_different_bytes_yield_different_digest():
    a = mcps_sdk.AuthorizationBinding.opaque_bytes(b"token-A")
    b = mcps_sdk.AuthorizationBinding.opaque_bytes(b"token-B")
    assert a.digest_value != b.digest_value


def test_authz_system_reference_fields():
    binding = mcps_sdk.AuthorizationBinding.authz_system_reference(
        "sys-1", "scheme-1", "grant-1", "c29tZS1kaWdlc3Q"
    )
    assert binding.binding_type == "authz-system-reference"
    assert binding.digest_alg == "sha256"
    assert binding.digest_value == "c29tZS1kaWdlc3Q"
    assert binding.authorization_system_id == "sys-1"
    assert binding.reference_value == "grant-1"


def test_opaque_binding_has_no_reference_fields():
    binding = mcps_sdk.AuthorizationBinding.opaque_bytes(b"x")
    assert binding.authorization_system_id is None
    assert binding.reference_value is None


# --- per-route policy fails closed -----------------------------------------

def test_policy_both_forms_permits_and_enforces():
    opaque = mcps_sdk.AuthorizationBinding.opaque_bytes(b"x")
    ref = mcps_sdk.AuthorizationBinding.authz_system_reference("s", "sc", "r", "d")
    both = mcps_sdk.AuthorizationBindingPolicy.both_base_forms()
    assert both.permits(opaque) and both.permits(ref)
    both.enforce(opaque)  # no raise
    both.enforce(ref)


def test_policy_opaque_only_rejects_reference():
    ref = mcps_sdk.AuthorizationBinding.authz_system_reference("s", "sc", "r", "d")
    policy = mcps_sdk.AuthorizationBindingPolicy.opaque_only()
    assert not policy.permits(ref)
    with pytest.raises(ValueError) as exc:
        policy.enforce(ref)
    assert "mcps.authorization_binding_type_unsupported" in str(exc.value)


def test_policy_closed_rejects_everything():
    opaque = mcps_sdk.AuthorizationBinding.opaque_bytes(b"x")
    with pytest.raises(ValueError):
        mcps_sdk.AuthorizationBindingPolicy.closed().enforce(opaque)


# --- providers -------------------------------------------------------------

def test_opaque_provider_static_bytes():
    binding = OpaqueBytesProvider(b"token-bytes").provide(_ctx())
    assert binding.digest_value == _expected_opaque(b"token-bytes")


def test_opaque_provider_callable_sees_context():
    seen = {}

    def fetch(ctx):
        seen["tool"] = ctx.tool_id
        seen["audience"] = ctx.audience
        return b"fresh-token-for-" + ctx.tool_id.encode()

    binding = OpaqueBytesProvider(fetch).provide(_ctx())
    assert seen == {"tool": "read_file", "audience": "did:example:server-1"}
    assert binding.digest_value == _expected_opaque(b"fresh-token-for-read_file")


def test_reference_provider_without_resolver_fails_closed():
    with pytest.raises(ValueError) as exc:
        AuthzSystemReferenceProvider().provide(_ctx())
    assert "mcps.authorization_binding_missing" in str(exc.value)


def test_reference_provider_with_resolver():
    binding = AuthzSystemReferenceProvider(
        lambda ctx: AuthzReference("sys-1", "scheme-1", "grant-7", "ZGln")
    ).provide(_ctx())
    assert binding.binding_type == "authz-system-reference"
    assert binding.reference_value == "grant-7"


def test_static_provider_returns_prebuilt_binding():
    binding = mcps_sdk.AuthorizationBinding.opaque_bytes(b"y")
    assert StaticAuthorizationProvider(binding).provide(_ctx()) is binding


# --- the provider digest actually lands in the signed preimage --------------

def test_sign_outbound_embeds_provider_computed_digest():
    """A provider-configured McpsConfig signs a request whose embedded
    authorization_binding carries the provider's real digest — not the legacy
    constant — proving the provider path reaches the signed bytes."""
    pytest.importorskip("mcp.types")
    from mcp.shared.message import SessionMessage
    from mcp.types import JSONRPCMessage

    from mcps_sdk.transport import McpsConfig, sign_outbound

    fix = json.loads((Path(__file__).parent / "fixtures" / "sign_request_vector.json").read_text())
    req = fix["inputs"]
    token = b"the-actual-capability-bytes"

    config = McpsConfig(
        signer=mcps_sdk.Signer.software(
            bytes.fromhex(req["seed_hex"]), signer_id=req["signer"], key_id=req["key_id"]
        ),
        policy=mcps_sdk.SignerPolicy(req["signer"], environment="dev-test", require_mcps=True),
        resolver=mcps_sdk.TrustResolver(),
        audience=req["audience"],
        on_behalf_of=req["on_behalf_of"],
        authorization=OpaqueBytesProvider(token),
        authorization_policy=mcps_sdk.AuthorizationBindingPolicy.opaque_only(),
    )
    now = int(datetime(2026, 6, 30, 20, 0, 0, tzinfo=timezone.utc).timestamp())
    sm = SessionMessage(
        JSONRPCMessage.model_validate_json(
            '{"jsonrpc":"2.0","id":"req-1","method":"tools/call",'
            '"params":{"name":"read_file","arguments":{"path":"x"}}}'
        )
    )
    wire = sign_outbound(sm, config, mcps_sdk.CorrelationStore(), now_unix=now, nonce="n", expires_unix=now + 300)
    envelope = json.loads(wire)["params"]["_meta"]["se.syncom/mcps.request"]
    binding = envelope["authorization_binding"]
    assert binding["binding_type"] == "opaque-bytes"
    assert binding["digest_value"] == _expected_opaque(token)
    # ...and it is NOT the legacy magic constant the dev shortcut used.
    assert binding["digest_value"] != "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"
