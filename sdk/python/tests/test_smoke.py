# SPDX-License-Identifier: Apache-2.0
"""Smoke tests for the installed `mcp_re_sdk` downloader wheel.

These run against the INSTALLED wheel (see the `downloader — Python maturin wheel`
CI lane): they prove the artifact stands on its own — the native `_core` extension
loads, the audited version/profile are exposed, and the RFC 9421 signing path
produces a signed request with the expected header + evidence shape. No live
transport or built workspace binary is required, so this lane never self-skips.
"""
import mcp_re_sdk


def test_core_version_reports_the_audited_core_and_not_this_wrapper():
    """r12 R12-1474 — this used to return the pyo3 wrapper's own `CARGO_PKG_VERSION`.

    A consumer calling a function named `core_version` is asking which AUDITED CORE
    they have; the shim in front of it versions independently, so the answer named the
    wrong artifact. Asserting only "non-empty str" could not see that — the wrapper's
    version is a non-empty string too.
    """
    v = mcp_re_sdk.core_version()
    assert isinstance(v, str) and v
    # The workspace version the audited core carries, not the binding crate's 0.1.x.
    assert v.split(".")[0] != "0" or int(v.split(".")[1]) >= 17, v


def test_profile_tag_is_nonempty_str():
    tag = mcp_re_sdk.profile_tag()
    assert isinstance(tag, str) and tag


def test_sign_request_produces_rfc9421_signed_request():
    seed = bytes(range(32))  # deterministic 32-byte Ed25519 seed
    signed = mcp_re_sdk.sign_request(
        seed,
        "key-1",
        "1",  # id (JSON)
        "tools/list",  # method
        "{}",  # params (JSON object)
        "https://proxy.internal:8600/mcp",  # target_uri
        "did:example:server-1",  # audience_id
        None,  # route
        "dpop-token",  # dpop_token
        "nonce-smoke-0001-128bit",  # nonce
        1000,  # created (unix secs)
        2000,  # expires (unix secs)
    )
    headers = {k.lower(): v for k, v in signed.headers}
    assert "signature" in headers
    assert "signature-input" in headers
    assert "content-digest" in headers
    assert signed.evidence_digest_alg
    assert signed.evidence_digest_value
    assert signed.method == "POST"  # the HTTP method carrying the JSON-RPC body
    assert signed.target_uri == "https://proxy.internal:8600/mcp"
    body = signed.body()
    assert isinstance(body, (bytes, bytearray)) and body
    assert b"tools/list" in body  # the JSON-RPC method rides in the POST body
