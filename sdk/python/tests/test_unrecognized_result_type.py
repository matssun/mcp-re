# SPDX-License-Identifier: Apache-2.0
"""A verified reply whose ``resultType`` is outside the set MCP 2026-07-28 defines.

The specification names ``complete`` and ``input_required``, lets extensions add values
the client has advertised support for, and then closes the set: an unrecognized value
MUST be considered invalid. This SDK advertises no extension result types.

Reading an unrecognized value as terminal is the failure worth naming precisely. An
extension's NON-terminal result would end the exchange: the correlation entry closes,
``on_input_required`` never fires, no answer leg is ever signed, and a continuation
reaches the application as a finished tool result — the same silent completion
``test_malformed_elicitation`` covers, arrived at from the other direction.

The fixture is a REAL delegated-signed exchange; only its result type is unreadable, and
the generator asserts the response still verifies as genuine evidence before freezing it.
A conformant MCP-RE proxy refuses to sign such a reply at all, so this stands for a
non-conformant or hostile server — which is exactly why the SDK must refuse it too.
Regenerate with the command in ``sdk/fixtures/unrecognized_result_type.json``'s
``_comment``.

Mirrors ``sdk/typescript/test/unrecognized_result_type.test.ts`` — same fixture, same
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
        / "unrecognized_result_type.json"
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


def test_an_unrecognized_result_type_is_refused_not_read_as_terminal():
    """Refused, and refused for the right reason.

    The wire code says the message declares a continuation model this reader does not
    implement — not that the evidence was bad, which it was not.
    """
    with pytest.raises(Exception) as raised:
        _verify(_b64url(FIXTURE["exchange"]["body_b64url"]))

    assert "continuation_type_unsupported" in str(raised.value), (
        "an unclassifiable result type must be refused as such, not as bad evidence: "
        f"{raised.value}"
    )


def test_the_fixture_is_otherwise_genuine_evidence():
    """The precondition that makes the test above meaningful.

    If the fixture failed verification outright, refusal would prove nothing about
    classification. Tampering with one byte of the signed body must produce a DIFFERENT
    failure — which is only observable if the untampered bytes get as far as
    classification.
    """
    tampered = bytearray(_b64url(FIXTURE["exchange"]["body_b64url"]))
    tampered[-2] ^= 0xFF
    with pytest.raises(Exception) as raised:
        _verify(bytes(tampered))
    assert "continuation_type_unsupported" not in str(raised.value), (
        "a tampered body must fail the content binding, not the classifier: "
        f"{raised.value}"
    )
