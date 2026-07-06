"""Unit coverage for the conformance-driver helpers (the pure, offline logic).

The driver's live behaviour is proven by the Rust four-hop matrix
(`mcp-re-walkthrough` `sdk_driver_matrix`); these tests guard the pieces that have no
server in the loop and could silently drift — chiefly the audience canonicalization
that must reproduce `mcp_re_client_core::AudienceTuple::to_audience_string` exactly.
"""

import base64
import json

from mcp_re_sdk import driver


def test_canonical_audience_mirrors_rust_audience_tuple():
    # The 6-field form the harness appends -> the exact wire string the Rust
    # AudienceTuple produces (mcp-re-client-core/src/audience.rs).
    out = driver._canonical_audience("https,proxy.internal,8443,acme,tools,prod")
    assert out == (
        "mcp-re-audience:v1:scheme=https;host=proxy.internal;port=8443;"
        "tenant=acme;route=tools;realm=prod"
    )


def test_canonical_audience_rejects_wrong_field_count():
    import pytest

    with pytest.raises(ValueError):
        driver._canonical_audience("https,proxy.internal,8443,acme,tools")  # 5 fields


def test_b64url_decode_tolerates_missing_padding():
    seed = bytes(range(32))
    unpadded = base64.urlsafe_b64encode(seed).decode().rstrip("=")
    assert driver._b64url_decode(unpadded) == seed


def test_read_seed_from_at_file(tmp_path):
    seed = bytes([7]) * 32
    f = tmp_path / "seed"
    f.write_text(base64.urlsafe_b64encode(seed).decode().rstrip("=") + "\n")
    assert driver._read_seed(f"@{f}") == seed


def test_strip_envelope_removes_only_the_mcp_re_key_and_empties_meta():
    import mcp_re_sdk

    key = mcp_re_sdk.response_meta_key()
    obj = {"result": {"content": "x", "_meta": {key: {"sig": "..."}}}}
    stripped = driver._strip_envelope(obj)
    # The envelope key is gone and, being the only _meta entry, _meta is removed.
    assert "_meta" not in stripped["result"]
    assert stripped["result"]["content"] == "x"


def test_strip_envelope_keeps_other_meta_keys():
    import mcp_re_sdk

    key = mcp_re_sdk.response_meta_key()
    obj = {"result": {"_meta": {key: {"sig": "..."}, "keep": 1}}}
    stripped = driver._strip_envelope(obj)
    assert stripped["result"]["_meta"] == {"keep": 1}


def test_reject_shape_is_a_correlated_json_rpc_error():
    err = driver._reject("req-9", "mcp-re.downgrade_forbidden")
    assert err["id"] == "req-9"
    assert err["error"]["message"] == "mcp-re.downgrade_forbidden"
    # One compact line, parseable by the harness.
    assert json.loads(json.dumps(err))["error"]["code"] == driver._MCP_RE_REJECTED_CODE
