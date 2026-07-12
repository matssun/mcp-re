# SPDX-License-Identifier: Apache-2.0
"""Smoke tests for the installed `mcp_re_sdk` downloader wheel.

These run against the INSTALLED wheel (see the `downloader — Python maturin wheel`
CI lane): they prove the artifact stands on its own — the native `_core` extension
loads, the audited version/profile are exposed, and the RFC 9421 signing path
produces a signed request with the expected header + evidence shape. No live
transport or built workspace binary is required, so this lane never self-skips.
"""
import mcp_re_sdk


def test_core_version_is_nonempty_str():
    v = mcp_re_sdk.core_version()
    assert isinstance(v, str) and v


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
        "nonce-smoke-0001",  # nonce
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
