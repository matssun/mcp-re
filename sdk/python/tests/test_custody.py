# SPDX-License-Identifier: Apache-2.0
"""Key custody (ADR-MCPS-044 §Compliance): the two explicit custody classes and the
hardening policy that accepts only the stronger one.

The load-bearing claim is that NON-EXPORTING custody is a pure custody change: the
signed preimage — and therefore every byte of evidence — is identical to the software
path. The key has moved behind a device; the protocol has not changed.
"""
import pytest

from mcp_re_sdk import (
    CustodyClass,
    McpReError,
    Signer,
    SignerPolicy,
    SigningDevice,
    sign_preimage,
)

SEED = bytes(range(32))
OTHER_SEED = bytes([7]) * 32
SIGNER_ID = "did:example:client"
KEY_ID = "key-1"

ARGS = dict(
    id_json="1",
    method="tools/list",
    params_json="{}",
    target_uri="https://proxy.internal:8600/mcp",
    audience_id="did:example:server-1",
    route=None,
    dpop_token="dpop-token",
    nonce="nonce-custody-0001",
    created=1000,
    expires=2000,
)


class TestCustodyClasses:
    def test_labels_software_and_non_exporting_distinctly(self):
        sw = Signer.software(SEED, SIGNER_ID, KEY_ID)
        ne = Signer.non_exporting(SIGNER_ID, KEY_ID, lambda p: sign_preimage(SEED, p))
        assert sw.custody is CustodyClass.SOFTWARE
        assert ne.custody is CustodyClass.NON_EXPORTING

    @pytest.mark.parametrize("bad", [b"", bytes(31), bytes(33)])
    def test_rejects_a_seed_that_is_not_32_bytes(self, bad):
        with pytest.raises(ValueError, match="32 bytes"):
            Signer.software(bad, SIGNER_ID, KEY_ID)
        with pytest.raises(ValueError, match="32 bytes"):
            SigningDevice.from_seed(bad)

    def test_rejects_a_non_callable_sign_callback(self):
        with pytest.raises(TypeError):
            Signer.non_exporting(SIGNER_ID, KEY_ID, "not-a-callable")

    def test_never_renders_key_material(self):
        assert repr(SigningDevice.from_seed(SEED)) == "SigningDevice(<sealed>)"
        r = repr(Signer.software(SEED, SIGNER_ID, KEY_ID))
        assert SIGNER_ID in r
        assert SEED.hex() not in r


class TestNonExportingIsByteIdentical:
    def test_device_path_matches_software_path_exactly(self):
        sw = Signer.software(SEED, SIGNER_ID, KEY_ID)
        ne = Signer.from_device(SIGNER_ID, KEY_ID, SigningDevice.from_seed(SEED))

        a = sw.sign_request(**ARGS)
        b = ne.sign_request(**ARGS)

        assert b.evidence_digest_alg == a.evidence_digest_alg
        assert b.evidence_digest_value == a.evidence_digest_value
        assert b.body() == a.body()
        assert b.headers == a.headers
        assert b.target_uri == a.target_uri
        assert b.method == a.method

    def test_the_device_is_the_sole_holder_of_the_key(self):
        dev = SigningDevice.from_seed(SEED)
        seen = {}

        def sign(preimage: bytes) -> bytes:
            seen["preimage"] = preimage  # the RFC 9421 signature base, not key material
            return dev.sign(preimage)

        signed = Signer.non_exporting(SIGNER_ID, KEY_ID, sign).sign_request(**ARGS)
        assert seen["preimage"]
        # The device returns a 64-byte detached Ed25519 signature over that exact base.
        assert len(dev.sign(seen["preimage"])) == 64
        assert signed.evidence_digest_value

    def test_signing_device_exposes_no_public_route_to_key_material(self):
        dev = SigningDevice.from_seed(SEED)
        assert not hasattr(dev, "seed")
        # No public attribute may hand back the key. `from_seed` is a constructor, not
        # an accessor, so it is read through the value it returns, never its name.
        public = [a for a in dir(dev) if not a.startswith("_")]
        for name in public:
            value = getattr(dev, name)
            assert value is not SEED, f"{name} exposes the seed object"
            assert value != SEED, f"{name} exposes the seed bytes"
        assert public == ["from_seed", "sign"]


class TestDeviceFailsClosed:
    def _raise(self, _preimage):
        raise RuntimeError("HSM unavailable")

    def test_a_throwing_device_maps_to_invalid_signature(self):
        signer = Signer.non_exporting(SIGNER_ID, KEY_ID, self._raise)
        with pytest.raises(ValueError, match="mcp-re.invalid_signature"):
            signer.sign_request(**ARGS)

    @pytest.mark.parametrize("bad", [b"", bytes(63), bytes(65)])
    def test_a_wrong_length_signature_maps_to_invalid_signature(self, bad):
        signer = Signer.non_exporting(SIGNER_ID, KEY_ID, lambda _p: bad)
        with pytest.raises(ValueError, match="mcp-re.invalid_signature"):
            signer.sign_request(**ARGS)

    def test_a_non_bytes_return_maps_to_invalid_signature(self):
        signer = Signer.non_exporting(SIGNER_ID, KEY_ID, lambda _p: "not-bytes")
        with pytest.raises(ValueError, match="mcp-re.invalid_signature"):
            signer.sign_request(**ARGS)


class TestSignerPolicyFailsClosed:
    def setup_method(self):
        self.sw = Signer.software(SEED, SIGNER_ID, KEY_ID)
        self.ne = Signer.from_device(SIGNER_ID, KEY_ID, SigningDevice.from_seed(SEED))

    def test_hardening_rejects_software_custody(self):
        with pytest.raises(McpReError) as ei:
            SignerPolicy.hardened(SIGNER_ID).check(self.sw)
        assert ei.value.wire_code == "mcp-re.actor_binding_failed"

    def test_hardening_accepts_non_exporting_custody(self):
        SignerPolicy.hardened(SIGNER_ID).check(self.ne)  # must not raise

    def test_rejects_a_foreign_signer_id(self):
        wrong = Signer.software(OTHER_SEED, "did:example:impostor", KEY_ID)
        with pytest.raises(McpReError) as ei:
            SignerPolicy(SIGNER_ID).check(wrong)
        assert ei.value.wire_code == "mcp-re.actor_binding_failed"

    def test_the_permissive_profile_accepts_software_custody(self):
        SignerPolicy(SIGNER_ID, profile="development").check(self.sw)  # must not raise
