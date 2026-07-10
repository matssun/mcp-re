#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""MCP-RE GKE-proof client — the HTTP-profile signed-request driver for the live
multi-replica validation harness (`gke-multi-replica-validation.sh`).

MCP-RE is HTTP-profile only. This replaces the removed `mcp-re-client-proxy-cli`:
it reads ONE plain MCP JSON-RPC request on stdin, signs a draft-02 envelope with the
audited `mcp-re-client-core` logic (via the `mcp_re_sdk` PyO3 core), forwards it over
verifying mTLS as one HTTP/1.1 POST to `--remote-addr host:port`, verifies the
server-signed response, prints the plain MCP response JSON on stdout, and reports a
verdict token on stderr:

    verdict=accepted        the response verified (a signed result came back)
    verdict=replay          the proxy rejected it as a replay
    verdict=revoked         the proxy rejected it on a trust/epoch/actor-binding reason
    verdict=rejected:<why>  any other fail-closed rejection

With `--expect <token>` the process exits non-zero on a verdict mismatch, so the
harness can assert cross-replica coherence. `--nonce` pins the request nonce (so two
replicas see the identical (signer, audience, nonce) triple). `--save-cont`/
`--load-cont` thread an ADR-MCPS-047 multi-round-trip continuation across a replica
switch: `--save-cont <file>` records the binding after a verified InputRequiredResult,
and `--load-cont <file>` signs the answer leg bound to it.

The MCP-RE wire (signing + mTLS POST) is identical to the SDK's live interop test
(`sdk/python/tests/test_e2e_mtls.py`); only the CLI framing and verdict mapping are
harness-specific. Requires the `mcp-re-sdk` Python package (`pip install ./sdk/python`).
"""

from __future__ import annotations

import argparse
import base64
import json
import secrets
import socket
import ssl
import sys
import time
from datetime import datetime, timezone

import mcp_re_sdk

# A concrete, valid authorization-binding digest (SHA-256 of the empty artifact,
# Base64URL-no-pad). The PEP verifies the signature over the preimage (which includes
# the binding) but enforces no authorization scope, so any self-consistent binding is
# accepted; this one is proven against the real proxy.
_AUTHZ_DIGEST = "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"


def _rfc3339(unix: int) -> str:
    return datetime.fromtimestamp(unix, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _b64url_at_file(spec: str) -> bytes:
    """b64url-decode a value that may be given inline or as ``@<path>`` (the CLI's
    ``@file`` convention) — used for ``--server-pubkey``."""
    raw = spec
    if spec.startswith("@"):
        with open(spec[1:], "r", encoding="utf-8") as fh:
            raw = fh.read().strip()
    return _b64url_decode(raw)


def _read_seed(spec: str) -> bytes:
    """Resolve ``--signing-key-seed`` (a Base64URL seed, or ``@<path>``) to 32 bytes."""
    raw = spec
    if spec.startswith("@"):
        with open(spec[1:], "r", encoding="utf-8") as fh:
            raw = fh.read().strip()
    seed = _b64url_decode(raw)
    if len(seed) != 32:
        raise ValueError(f"signing key seed must be 32 bytes, got {len(seed)}")
    return seed


def _canonical_audience(six_field: str) -> str:
    """Reproduce ``AudienceTuple::to_audience_string`` from the 6-field ``--audience``
    form (``scheme,host,port,tenant,route,realm``); a drift fails closed, never passes."""
    parts = six_field.split(",")
    if len(parts) != 6:
        raise ValueError(f"--audience must have 6 comma fields, got {len(parts)}: {six_field!r}")
    scheme, host, port, tenant, route, realm = parts
    return (
        f"mcp-re-audience:v1:scheme={scheme};host={host};port={port};"
        f"tenant={tenant};route={route};realm={realm}"
    )


def _classify(reason: "str | None") -> str:
    """Map a fail-closed ``mcp-re.*`` reason to a coarse verdict token."""
    r = (reason or "").lower()
    if "replay" in r:
        return "replay"
    if any(k in r for k in ("trust", "epoch", "revok", "actor_binding", "untrusted", "unknown_signer")):
        return "revoked"
    return f"rejected:{reason or 'unknown'}"


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="mcp_re_gke_client", add_help=True)
    p.add_argument("--remote-addr", required=True)          # host:port
    p.add_argument("--server-name", required=True)          # expected server cert SAN
    p.add_argument("--signer-id", required=True)
    p.add_argument("--key-id", required=True)
    p.add_argument("--signing-key-seed", required=True)     # <b64url> | @<path>
    p.add_argument("--server-signer", required=True)
    p.add_argument("--server-key-id", required=True)
    p.add_argument("--server-pubkey", required=True)        # raw-32 b64url
    p.add_argument("--audience", required=True)             # 6-field form
    p.add_argument("--tls-cert", required=True)             # client leaf
    p.add_argument("--tls-key", required=True)
    p.add_argument("--server-ca", required=True)
    p.add_argument("--on-behalf-of", default="did:example:user-1")
    p.add_argument("--nonce")                               # pin the nonce (coherence proof)
    p.add_argument("--expect")                              # accepted|replay|revoked|rejected:*
    p.add_argument("--save-cont")                           # record MRT binding to <file>
    p.add_argument("--load-cont")                           # sign the answer leg bound to <file>
    return p.parse_args(argv)


def _make_post(args: argparse.Namespace):
    """One mTLS HTTP/1.1 POST per call (Connection: close) — the proxy's wire."""
    host, port_s = args.remote_addr.rsplit(":", 1)
    port = int(port_s)
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=args.server_ca)
    ctx.load_cert_chain(args.tls_cert, args.tls_key)

    def post(body: bytes) -> bytes:
        raw = socket.create_connection((host, port), timeout=15)
        try:
            tls = ctx.wrap_socket(raw, server_hostname=args.server_name)
        except Exception:
            raw.close()
            raise
        try:
            head = (
                f"POST / HTTP/1.1\r\nHost: {args.server_name}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode()
            tls.sendall(head + body)
            chunks = []
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            tls.close()
        return b"".join(chunks).split(b"\r\n\r\n", 1)[1]

    return post


def _strip_envelope(obj: dict) -> dict:
    result = obj.get("result")
    if isinstance(result, dict):
        meta = result.get("_meta")
        if isinstance(meta, dict):
            meta.pop(mcp_re_sdk.response_meta_key(), None)
            if not meta:
                result.pop("_meta", None)
    return obj


def main(argv: "list[str] | None" = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)

    signer = mcp_re_sdk.Signer.software(
        _read_seed(args.signing_key_seed), signer_id=args.signer_id, key_id=args.key_id
    )
    policy = mcp_re_sdk.SignerPolicy(args.signer_id, environment="production", require_mcp_re=True)
    resolver = mcp_re_sdk.TrustResolver()
    resolver.insert_public_key(
        args.server_signer, args.server_key_id, _b64url_at_file(args.server_pubkey)
    )
    audience = _canonical_audience(args.audience)
    post = _make_post(args)

    request = json.loads(sys.stdin.readline())
    rid = request.get("id")
    method = request.get("method")
    params = request.get("params", {})

    continuation_kwargs: dict = {}
    if args.load_cont:
        with open(args.load_cont, "r", encoding="utf-8") as fh:
            prev_hash, irr_hash = json.load(fh)
        continuation_kwargs = {
            "continuation_previous_request_hash": prev_hash,
            "continuation_input_required_response_hash": irr_hash,
        }

    now = int(time.time())
    signed = mcp_re_sdk.sign_request_with_signer(
        json.dumps(rid),
        method,
        json.dumps(params),
        on_behalf_of=args.on_behalf_of,
        audience=audience,
        binding_digest_alg="sha256",
        binding_digest_value=_AUTHZ_DIGEST,
        nonce=args.nonce or secrets.token_urlsafe(16),
        issued_at=_rfc3339(now),
        expires_at=_rfc3339(now + 300),
        signer=signer,
        policy=policy,
        **continuation_kwargs,
    )
    body = post(signed.wire_bytes)
    result = mcp_re_sdk.verify_response(
        body,
        resolver=resolver,
        expected_request_hash=signed.request_hash,
        expected_server_signer=args.server_signer,
        enforcement_mode="require_mcp_re",
    )

    if result.accepted:
        verdict = "accepted"
        plain = _strip_envelope(json.loads(body))
        sys.stdout.write(json.dumps(plain, separators=(",", ":")) + "\n")
        if args.save_cont and result.input_required:
            with open(args.save_cont, "w", encoding="utf-8") as fh:
                json.dump([signed.request_hash, result.response_hash], fh)
    else:
        verdict = _classify(result.reason)
        # Echo the proxy's fail-closed body so the harness can still inspect it.
        sys.stdout.write(body.decode("utf-8", "replace") + "\n")

    sys.stderr.write(f"verdict={verdict}\n")
    if args.expect and verdict != args.expect:
        sys.stderr.write(f"verdict mismatch: expected {args.expect}, got {verdict}\n")
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
