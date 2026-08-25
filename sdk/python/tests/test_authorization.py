# SPDX-License-Identifier: Apache-2.0
"""Authorization-binding providers (ADR-MCPS-044 §Authorization-binding hook).

Bind, do not interpret. The provider supplies the artifact; the core digests it and puts
the digest — never the bytes — into the signed evidence.

The digest is checked against an INDEPENDENT stdlib SHA-256 oracle, not against the
core's own opinion of what it computed.
"""
import base64
import hashlib
import json

import pytest

import mcp_re_sdk
from mcp_re_sdk import (
    AuthorizationBindingPolicy,
    AuthorizationDecisionProvider,
    AuthzSystemReferenceProvider,
    BindingRequestContext,
    McpReError,
    OpaqueBytesProvider,
)

SEED = bytes(range(32))
BLOCK_KEY = "se.syncom/mcp-re.http.request"
MATERIAL = b"pdp-decision-document-v1"
OTHER_MATERIAL = b"pdp-decision-document-v2"
#: The GENERIC opaque example. Deliberately not `pdp-decision`: that type carries
#: ADR-MCPRE-065 semantics and reaches the opaque form only through
#: `AuthorizationDecisionProvider`. `human-approval` is used here purely as a registry
#: member with a legitimate generic opaque form — nothing here claims it has a typed
#: semantic verifier.
GENERIC = "human-approval"
GENERIC_MATERIAL = b"approved-by-alice"
OTHER_GENERIC_MATERIAL = b"approved-by-bob"
#: A compact decision document. Shaped like a JWS; never verified in this file.
DECISION = "ZmFrZS1oZWFkZXI.ZmFrZS1jbGFpbXM.ZmFrZS1zaWc"

BASE = dict(
    id_json="1",
    method="tools/list",
    params_json="{}",
    target_uri="https://proxy.internal:8600/mcp",
    audience_id="did:example:server-1",
    route=None,
    dpop_token="dpop-token",
    nonce="nonce-authz-0001-128bit",
    created=1000,
    expires=2000,
)

CTX = BindingRequestContext(
    audience_id="did:example:server-1",
    target_uri="https://proxy.internal:8600/mcp",
    method="tools/list",
)


def _b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _oracle_digest(material: bytes) -> str:
    """An INDEPENDENT digest: stdlib SHA-256, not the core's."""
    return _b64url_nopad(hashlib.sha256(material).digest())


def _sign(providers=(), **over):
    args = dict(BASE)
    args.update(over)
    if providers:
        args["bindings_json"] = json.dumps([p.spec(CTX) for p in providers])
    return mcp_re_sdk.sign_request(SEED, "key-1", **args)


def _bindings(signed) -> list:
    block = json.loads(signed.body())["_meta"][BLOCK_KEY]
    return block["artifact_bindings"]


def _of_type(signed, artifact_type: str) -> dict:
    return next(b for b in _bindings(signed) if b["artifact_type"] == artifact_type)


class TestOpaqueBytes:
    def test_the_core_digests_the_real_artifact(self):
        signed = _sign([OpaqueBytesProvider(GENERIC, GENERIC_MATERIAL)])
        b = _of_type(signed, GENERIC)
        assert b["binding_type"] == "opaque-digest"
        assert b["digest_alg"] == "sha256"
        # Checked against stdlib SHA-256 — an independent oracle.
        assert b["digest_value"] == _oracle_digest(GENERIC_MATERIAL)

    def test_the_binding_carries_metadata_only_never_the_artifact(self):
        signed = _sign([OpaqueBytesProvider(GENERIC, GENERIC_MATERIAL)])
        assert GENERIC_MATERIAL not in signed.body()
        assert _b64url_nopad(GENERIC_MATERIAL).encode() not in signed.body()
        assert set(_of_type(signed, GENERIC)) == {
            "artifact_type",
            "binding_type",
            "digest_alg",
            "digest_value",
        }

    def test_changed_artifact_bytes_change_the_digest(self):
        a = _sign([OpaqueBytesProvider(GENERIC, GENERIC_MATERIAL)])
        b = _sign([OpaqueBytesProvider(GENERIC, OTHER_GENERIC_MATERIAL)])
        assert _of_type(a, GENERIC)["digest_value"] != _of_type(b, GENERIC)["digest_value"]
        # ...and therefore the signed evidence differs too.
        assert a.evidence_digest_value != b.evidence_digest_value

    def test_the_digest_is_deterministic(self):
        a = _sign([OpaqueBytesProvider(GENERIC, GENERIC_MATERIAL)])
        b = _sign([OpaqueBytesProvider(GENERIC, GENERIC_MATERIAL)])
        assert a.body() == b.body()

    def test_a_caller_cannot_pass_a_precomputed_digest(self):
        """`digest_value` is not an input — the spec has no field for it."""
        spec = OpaqueBytesProvider(GENERIC, GENERIC_MATERIAL).spec(CTX)
        assert "digest_value" not in spec
        assert "material_b64url" in spec
        # And the core refuses a spec that tries to smuggle one in.
        smuggled = dict(spec, digest_value="ZmFrZQ")
        with pytest.raises(ValueError, match="authorization_binding_malformed"):
            mcp_re_sdk.sign_request(SEED, "key-1", **BASE, bindings_json=json.dumps([smuggled]))

    @pytest.mark.parametrize("bad", [b"", bytearray()])
    def test_empty_material_fails_closed(self, bad):
        with pytest.raises(McpReError) as ei:
            OpaqueBytesProvider(GENERIC, bad)
        assert ei.value.wire_code == "mcp-re.authorization_binding_missing"

    def test_an_unregistered_artifact_type_fails_closed(self):
        with pytest.raises(McpReError) as ei:
            OpaqueBytesProvider("not-a-registry-token", GENERIC_MATERIAL)
        assert ei.value.wire_code == "mcp-re.authorization_binding_type_unsupported"


class TestAuthzSystemReference:
    def _provider(self, **over):
        args = dict(
            authorization_system_id="authz-1",
            reference_scheme_id="scheme-1",
            reference_value="grant-123",
        )
        args.update(over)
        return AuthzSystemReferenceProvider("pdp-decision", MATERIAL, **args)

    def test_it_binds_the_real_bytes_and_names_the_system(self):
        b = _of_type(_sign([self._provider()]), "pdp-decision")
        assert b["binding_type"] == "reference-digest"
        assert b["digest_value"] == _oracle_digest(MATERIAL)  # still a real digest
        assert b["authorization_system_id"] == "authz-1"
        assert b["reference_scheme_id"] == "scheme-1"
        assert b["reference_value"] == "grant-123"

    def test_the_reference_form_leaks_no_secret_material(self):
        signed = _sign([self._provider()])
        assert MATERIAL not in signed.body()
        assert _b64url_nopad(MATERIAL).encode() not in signed.body()

    def test_the_reference_digest_equals_the_opaque_digest_for_the_same_bytes(self):
        """The form names the issuer; it does not change what is bound.

        Compared across artifact types on purpose: `pdp-decision` has no generic opaque
        form any more, and the claim was never about the type — it is that the digest is
        over the material, whatever the form wraps it in.
        """
        ref = _of_type(_sign([self._provider()]), "pdp-decision")
        opq = _of_type(_sign([OpaqueBytesProvider(GENERIC, MATERIAL)]), GENERIC)
        assert ref["digest_value"] == opq["digest_value"] == _oracle_digest(MATERIAL)

    @pytest.mark.parametrize(
        "missing",
        ["authorization_system_id", "reference_scheme_id", "reference_value"],
    )
    def test_a_partial_reference_fails_closed(self, missing):
        with pytest.raises(McpReError) as ei:
            self._provider(**{missing: ""})
        assert ei.value.wire_code == "mcp-re.authorization_binding_malformed"

    def test_an_unregistered_artifact_type_fails_closed(self):
        with pytest.raises(McpReError) as ei:
            AuthzSystemReferenceProvider(
                "not-a-registry-token",
                MATERIAL,
                authorization_system_id="authz-1",
                reference_scheme_id="scheme-1",
                reference_value="grant-123",
            )
        assert ei.value.wire_code == "mcp-re.authorization_binding_type_unsupported"

    def test_empty_material_fails_closed(self):
        """A reference binding still binds real bytes — a naked reference is not enough."""
        with pytest.raises(McpReError) as ei:
            AuthzSystemReferenceProvider(
                "pdp-decision",
                b"",
                authorization_system_id="authz-1",
                reference_scheme_id="scheme-1",
                reference_value="grant-123",
            )
        assert ei.value.wire_code == "mcp-re.authorization_binding_missing"

    def test_it_reports_its_artifact_type(self):
        assert self._provider().binding_type() == "pdp-decision"


class TestDpopStaysBuiltIn:
    def test_dpop_is_present_and_first_without_any_provider(self):
        b = _bindings(_sign())
        assert [x["artifact_type"] for x in b] == ["oauth-dpop"]
        assert b[0]["digest_value"] == _oracle_digest(b"dpop-token")

    def test_provider_bindings_append_after_dpop(self):
        b = _bindings(_sign([OpaqueBytesProvider(GENERIC, GENERIC_MATERIAL)]))
        assert [x["artifact_type"] for x in b] == ["oauth-dpop", GENERIC]

    def test_the_no_bindings_path_is_unchanged(self):
        """Omitting the parameter must sign exactly as before — frozen vectors depend on it."""
        assert _sign().body() == mcp_re_sdk.sign_request(SEED, "key-1", **BASE).body()

    def test_several_providers_are_all_bound_in_order(self):
        b = _bindings(
            _sign(
                [
                    OpaqueBytesProvider("oauth-rar", MATERIAL),
                    OpaqueBytesProvider(GENERIC, GENERIC_MATERIAL),
                ]
            )
        )
        assert [x["artifact_type"] for x in b] == ["oauth-dpop", "oauth-rar", GENERIC]


class TestPolicyFailsClosed:
    def test_a_permitted_type_passes(self):
        policy = AuthorizationBindingPolicy.permitting({"pdp-decision"})
        policy.check([AuthorizationDecisionProvider(DECISION)])  # must not raise

    def test_an_unpermitted_type_fails_closed(self):
        policy = AuthorizationBindingPolicy.permitting({"pdp-decision"})
        with pytest.raises(McpReError) as ei:
            policy.check([OpaqueBytesProvider(GENERIC, MATERIAL)])
        assert ei.value.wire_code == "mcp-re.authorization_binding_type_unsupported"

    def test_a_required_binding_that_is_absent_fails_closed(self):
        policy = AuthorizationBindingPolicy.permitting({"pdp-decision"}, require_binding=True)
        with pytest.raises(McpReError) as ei:
            policy.check([])
        assert ei.value.wire_code == "mcp-re.authorization_binding_missing"

    def test_an_optional_binding_may_be_absent(self):
        AuthorizationBindingPolicy.permitting({"pdp-decision"}).check([])  # must not raise


class TestAuthorizationDecision:
    """ADR-MCPRE-065 Slice 3: the decision and its binding are produced together.

    The property under test is that an INCONSISTENT carrier — a document committing to
    one digest while another travels with it — is unconstructible through the public API.
    """

    def _block(self, signed) -> dict:
        return json.loads(signed.body())["_meta"][BLOCK_KEY]

    def test_the_document_travels_and_the_core_mints_its_binding(self):
        signed = _sign([AuthorizationDecisionProvider(DECISION)])
        block = self._block(signed)
        assert block["authorization_decision"] == DECISION
        b = _of_type(signed, "pdp-decision")
        assert b["binding_type"] == "opaque-digest"
        # The digest is over the document's EXACT bytes, checked against stdlib SHA-256.
        assert b["digest_value"] == _oracle_digest(DECISION.encode())

    def test_the_document_appears_exactly_once(self):
        body = _sign([AuthorizationDecisionProvider(DECISION)]).body()
        assert body.count(DECISION.encode()) == 1

    def test_there_is_no_parameter_for_the_digest(self):
        """The producer takes the document alone — the two cannot be made to disagree."""
        spec = AuthorizationDecisionProvider(DECISION).spec(CTX)
        assert spec == {
            "artifact_type": "pdp-decision",
            "form": "authorization-decision",
            "material_b64url": _b64url_nopad(DECISION.encode()),
        }
        assert "digest_value" not in spec

    def test_a_request_acts_under_at_most_one_decision(self):
        with pytest.raises(ValueError, match="authorization_binding_malformed"):
            _sign([AuthorizationDecisionProvider(DECISION), AuthorizationDecisionProvider("b.c.d")])

    def test_an_empty_decision_fails_closed(self):
        with pytest.raises(McpReError) as ei:
            AuthorizationDecisionProvider(b"")
        assert ei.value.wire_code == "mcp-re.authorization_binding_missing"

    def test_str_and_bytes_produce_the_same_carrier(self):
        assert (
            _sign([AuthorizationDecisionProvider(DECISION)]).body()
            == _sign([AuthorizationDecisionProvider(DECISION.encode())]).body()
        )


class TestTheGenericProviderCannotMintHalfAPair:
    """The narrowing, held at BOTH layers — the wrapper and the native seam.

    The negative is about the PAIR `(pdp-decision, opaque-bytes)`, never about the token
    `pdp-decision` appearing in a spec: a token-keyed rule would take the legitimate
    reference form with it, which the last test here pins.
    """

    def test_the_wrapper_refuses_the_generic_opaque_form(self):
        with pytest.raises(McpReError) as ei:
            OpaqueBytesProvider("pdp-decision", MATERIAL)
        assert ei.value.wire_code == "mcp-re.authorization_binding_type_unsupported"

    def test_the_native_seam_refuses_it_independently(self):
        """A caller composing the spec JSON never passes through the wrapper class.

        Without this, the guard above would be cosmetic.
        """
        smuggled = {
            "artifact_type": "pdp-decision",
            "form": "opaque-bytes",
            "material_b64url": _b64url_nopad(MATERIAL),
        }
        with pytest.raises(ValueError, match="authorization_binding_type_unsupported"):
            mcp_re_sdk.sign_request(SEED, "key-1", **BASE, bindings_json=json.dumps([smuggled]))

    def test_the_reference_form_is_untouched(self):
        """Mode-1 external decision linkage is a different claim, and stays legal."""
        signed = _sign(
            [
                AuthzSystemReferenceProvider(
                    "pdp-decision",
                    MATERIAL,
                    authorization_system_id="authz-1",
                    reference_scheme_id="scheme-1",
                    reference_value="grant-123",
                )
            ]
        )
        assert _of_type(signed, "pdp-decision")["binding_type"] == "reference-digest"
        # ...and it carries no document: linkage is not evidence.
        assert "authorization_decision" not in json.loads(signed.body())["_meta"][BLOCK_KEY]
