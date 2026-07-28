# SPDX-License-Identifier: Apache-2.0
"""A verified reply that declares itself non-terminal and withholds its state.

The binding used to hand-roll its own JSON walk over the verified body and collapse
every failure of that walk to ``None`` — which the transport reads as "terminal". So a
delegated-signed, fully verified ``input_required`` reply carrying no usable
``requestState`` was reported as an ordinary completed result: the open leg's
correlation entry was consumed, ``on_input_required`` never fired, no answer leg was
ever signed, and an elicitation reached the application as a finished tool result.

Classification now runs in the audited core, which refuses the malformed middle ground
instead of resolving it to "terminal".

The fixture is a REAL delegated-signed exchange, not a construction: only its body is
malformed, and the generator asserts the response still verifies as genuine evidence
before freezing it — otherwise this would prove refusal for the wrong reason. It cannot
be recorded from the proxy, because a conformant MCP-RE proxy now rejects this body
rather than serving it; it stands for a non-conformant or hostile server. Regenerate
with the command in ``sdk/fixtures/malformed_elicitation.json``'s ``_comment``.

Mirrors ``sdk/typescript/test/malformed_elicitation.test.ts`` — same fixture, same
assertions.
"""
import base64
import json
import pathlib

import pytest

from mcp_re_sdk import verify_response

FIXTURE = json.loads(
    (
        pathlib.Path(__file__).resolve().parents[3]
        / "sdk"
        / "fixtures"
        / "malformed_elicitation.json"
    ).read_text()
)


def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _verify(body: bytes):
    """Run the frozen exchange through the binding, with `body` as the reply."""
    f = FIXTURE
    x = f["exchange"]
    return verify_response(
        x["status"],
        [tuple(h) for h in x["headers"]],
        body,
        x["request_method"],
        x["request_target_uri"],
        [tuple(h) for h in x["request_headers"]],
        _b64url(x["request_body_b64url"]),
        x["request_evidence_digest_alg"],
        x["request_evidence_digest_value"],
        f["issuer"]["key_id"],
        f["issuer"]["pubkey_b64url"],
        f["issuer"]["role"],
        f["issuer"]["trust_domain"],
        f["issuer"]["subject"],
        [f["audience_id"]],
        f["expected_audience_hash"],
        list(f["accepted_epochs"]),
        f["max_clock_skew"],
        [],
        f["now"],
    )


def test_a_non_terminal_reply_without_a_usable_state_is_refused():
    """THE regression: refused, not reported as a terminal result."""
    with pytest.raises(Exception) as raised:
        _verify(_b64url(FIXTURE["exchange"]["body_b64url"]))

    # Refused for the RIGHT reason: the body is malformed, not the signature.
    assert "malformed_envelope" in str(raised.value), (
        "the reply must be refused as a malformed body, not as bad evidence: "
        f"{raised.value}"
    )


def test_the_fixture_is_otherwise_genuine_evidence():
    """The precondition that makes the test above meaningful.

    If the fixture failed verification outright, refusal would prove nothing about
    classification. Tampering with one byte of the signed body must produce a
    DIFFERENT failure than the malformed-classification one — which is only
    observable if the untampered bytes get as far as classification.
    """
    tampered = bytearray(_b64url(FIXTURE["exchange"]["body_b64url"]))
    tampered[-2] ^= 0xFF
    with pytest.raises(Exception) as raised:
        _verify(bytes(tampered))
    assert "malformed_envelope" not in str(raised.value), (
        "a tampered body must fail the content binding, not the classifier: "
        f"{raised.value}"
    )
