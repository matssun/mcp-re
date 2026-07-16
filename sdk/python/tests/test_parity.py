# SPDX-License-Identifier: Apache-2.0
"""Cross-language parity gate (ADR-MCPS-044 §shared seam).

Both SDKs bind the SAME audited `mcp-re-client-core`, so the canonical signed preimage
is byte-identical across them *by construction*. This module turns that claim into a
gate: `sdk/fixtures/parity_vectors.json` freezes the bytes, and both this file and its
TypeScript twin (`sdk/typescript/test/parity.test.ts`) assert against them.

Either binding drifting from the other — or from the core — fails here rather than
shipping. Regenerate the oracle with `tools/gen_sdk_parity_fixture.py`.
"""
import base64
import json
import pathlib

import pytest

import mcp_re_sdk
from mcp_re_sdk import Signer, SigningDevice

FIXTURE = (
    pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "parity_vectors.json"
)


def _load() -> dict:
    if not FIXTURE.exists():  # pragma: no cover - the fixture is committed
        pytest.skip(f"parity oracle not found at {FIXTURE}")
    return json.loads(FIXTURE.read_text())


ORACLE = _load()
CASES = sorted(ORACLE["cases"])

# The signing kwargs the fixture carries that are NOT passed through to sign_request.
_META_KEYS = {"seed_b64", "key_id"}


def _sign(name: str):
    """Reproduce a frozen case with this SDK."""
    c = ORACLE["cases"][name]
    inputs = dict(c["inputs"])
    seed = base64.b64decode(inputs.pop("seed_b64"))
    key_id = inputs.pop("key_id")
    if name.startswith("non_exporting"):
        signer = Signer.from_device("did:example:client", key_id, SigningDevice.from_seed(seed))
        return signer.sign_request(**inputs), c["expected"]
    return mcp_re_sdk.sign_request(seed, key_id, **inputs), c["expected"]


def test_the_oracle_covers_the_binding_forms():
    """Both authorization-binding forms must be pinned, not just DPoP."""
    assert "binding_opaque_bytes" in CASES
    assert "binding_authz_system_reference" in CASES


def test_oracle_is_the_expected_schema():
    assert ORACLE["schema"] == "mcp-re-sdk-parity/v1"
    assert CASES, "the parity oracle carries no cases"


def test_profile_tag_matches_the_frozen_oracle():
    assert mcp_re_sdk.profile_tag() == ORACLE["profile_tag"]


@pytest.mark.parametrize("name", CASES)
def test_signed_bytes_match_the_frozen_oracle(name):
    signed, expected = _sign(name)
    assert signed.method == expected["method"]
    assert signed.target_uri == expected["target_uri"]
    assert [list(h) for h in signed.headers] == expected["headers"]
    assert base64.b64encode(signed.body()).decode() == expected["body_b64"]
    assert signed.evidence_digest_alg == expected["evidence_digest_alg"]
    assert signed.evidence_digest_value == expected["evidence_digest_value"]


@pytest.mark.parametrize("name", CASES)
def test_signing_is_deterministic(name):
    """Ed25519 is deterministic: the same inputs must re-sign to the same bytes."""
    a, _ = _sign(name)
    b, _ = _sign(name)
    assert a.body() == b.body()
    assert a.headers == b.headers
    assert a.evidence_digest_value == b.evidence_digest_value


def test_non_exporting_custody_equals_software_custody_in_the_oracle():
    """The frozen bytes themselves must witness that custody does not change evidence."""
    sw = ORACLE["cases"]["software_tools_list"]["expected"]
    ne = ORACLE["cases"]["non_exporting_tools_list"]["expected"]
    assert ne["body_b64"] == sw["body_b64"]
    assert ne["headers"] == sw["headers"]
    assert ne["evidence_digest_value"] == sw["evidence_digest_value"]


def test_the_continuation_leg_signs_differently_from_the_open_leg():
    """A signed continuation must actually change the evidence it rides in."""
    base = ORACLE["cases"]["software_tools_list"]["expected"]
    cont = ORACLE["cases"]["continuation_answer_leg"]["expected"]
    assert cont["body_b64"] != base["body_b64"]
    assert cont["evidence_digest_value"] != base["evidence_digest_value"]
