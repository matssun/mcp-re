"""MCP-S conformance driver — the Python SDK as an interchangeable client leg.

This is the Python side of the multi-SDK test architecture (see
``mcps-walkthrough`` `ClientDriver`). It is a thin stdio bridge that makes the
Python SDK a drop-in for the Rust reference ``mcps-client-proxy-cli``: it reads one
plain MCP JSON-RPC request per line on stdin, signs it with the SDK, POSTs it over
mTLS to the ``mcps-proxy`` PEP, verifies the server-signed response, strips the
MCP-S envelope, and writes one plain MCP JSON-RPC response per line on stdout.

The signing/verification is the AUDITED ``mcps-client-core`` logic via the SDK's
PyO3 core (``sign_request_with_signer`` / ``verify_response``) — the exact calls the
live mTLS interop test (``tests/test_e2e_mtls.py``) proves against the real proxy.
No ``mcp`` dependency: the harness IS the MCP client, so this bridge never opens a
``ClientSession``; it only signs the raw JSON-RPC it is handed.

Run it as the walkthrough harness's Python client leg::

    MCPS_DRIVER_PYTHON="python3 -m mcps_sdk.driver" \\
      cargo test -p mcps-walkthrough --test sdk_driver_matrix -- --nocapture

The harness appends the shared client CLI arg surface (``--remote-addr`` … ). Only
the file/software key source is supported here (the four-hop's offline tiers);
Cloud KMS signing on the Python side is a later slice.
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

import mcps_sdk

# A concrete, valid authorization-binding digest (SHA-256 of the empty artifact,
# Base64URL-no-pad) — the same value the live mTLS interop test signs with. The
# four-hop PEP verifies the request signature over the preimage (which includes the
# binding) but enforces no authorization scope, so any self-consistent binding is
# accepted; this one is proven against the real proxy.
_AUTHZ_DIGEST = "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"

# JSON-RPC server-error code carrying a fail-closed MCP-S rejection back to the
# harness (matches the SDK's McpsHttpTransport reject code).
_MCPS_REJECTED_CODE = -32099


def _rfc3339(unix: int) -> str:
    return datetime.fromtimestamp(unix, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _b64url_decode(value: str) -> bytes:
    """Decode Base64URL, tolerating missing padding (the SDK/CLI wire form)."""
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def _read_seed(spec: str) -> bytes:
    """Resolve ``--signing-key-seed`` (a Base64URL seed, or ``@<path>`` to a file
    holding one) to the raw 32 seed bytes — the CLI's ``@file`` convention."""
    raw = spec
    if spec.startswith("@"):
        with open(spec[1:], "r", encoding="utf-8") as fh:
            raw = fh.read().strip()
    seed = _b64url_decode(raw)
    if len(seed) != 32:
        raise ValueError(f"signing key seed must be 32 bytes, got {len(seed)}")
    return seed


def _canonical_audience(six_field: str) -> str:
    """Reproduce ``mcps_client_core::AudienceTuple::to_audience_string`` from the
    6-field ``--audience`` form (``scheme,host,port,tenant,route,realm``). Mirrors
    ``mcps-client-core/src/audience.rs``; a drift makes the round trip fail closed
    (audience mismatch), never silently pass."""
    parts = six_field.split(",")
    if len(parts) != 6:
        raise ValueError(f"--audience must have 6 comma fields, got {len(parts)}: {six_field!r}")
    scheme, host, port, tenant, route, realm = parts
    return (
        f"mcps-audience:v1:scheme={scheme};host={host};port={port};"
        f"tenant={tenant};route={route};realm={realm}"
    )


def _strip_envelope(obj: dict) -> dict:
    """Remove the MCP-S response envelope from ``result._meta`` so the harness sees
    plain MCP (and no ``_meta`` at all when the envelope was its only key)."""
    result = obj.get("result")
    if isinstance(result, dict):
        meta = result.get("_meta")
        if isinstance(meta, dict):
            meta.pop(mcps_sdk.response_meta_key(), None)
            if not meta:
                result.pop("_meta", None)
    return obj


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="mcps_sdk.driver", add_help=False)
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
    p.add_argument("--on-behalf-of", required=True)
    # Accepted-but-unused here (this driver is software-key only).
    p.add_argument("--key-source", default="file")
    return p.parse_args(argv)


def _make_post(args: argparse.Namespace):
    """One mTLS HTTP/1.1 POST per call (Connection: close) — the proxy's wire."""
    host, port_s = args.remote_addr.rsplit(":", 1)
    port = int(port_s)
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=args.server_ca)
    ctx.load_cert_chain(args.tls_cert, args.tls_key)

    def post(body: bytes) -> bytes:
        raw = socket.create_connection((host, port), timeout=15)
        tls = ctx.wrap_socket(raw, server_hostname=args.server_name)
        try:
            head = (
                f"POST / HTTP/1.1\r\nHost: {args.server_name}\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode()
            tls.sendall(head + body)
            resp = b""
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                resp += chunk
        finally:
            tls.close()
        return resp.split(b"\r\n\r\n", 1)[1]

    return post


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)

    signer = mcps_sdk.Signer.software(
        _read_seed(args.signing_key_seed), signer_id=args.signer_id, key_id=args.key_id
    )
    policy = mcps_sdk.SignerPolicy(args.signer_id, environment="dev-test", require_mcps=True)
    resolver = mcps_sdk.TrustResolver()
    resolver.insert_public_key(
        args.server_signer, args.server_key_id, _b64url_decode(args.server_pubkey)
    )
    audience = _canonical_audience(args.audience)
    post = _make_post(args)

    out = sys.stdout

    def emit(obj: dict) -> None:
        out.write(json.dumps(obj, separators=(",", ":")))
        out.write("\n")
        out.flush()

    # readline() (NOT `for line in sys.stdin`): iterating the stream read-aheads and
    # would deadlock this one-request-then-await-response protocol.
    while True:
        raw_line = sys.stdin.readline()
        if not raw_line:  # EOF: the harness closed stdin
            break
        line = raw_line.strip()
        if not line:
            continue
        request = json.loads(line)
        rid = request.get("id")
        method = request.get("method")
        if method is None:
            # Not a request we can sign (notification/response); the four-hop only
            # sends id-bearing requests. Fail closed rather than hang.
            emit(_reject(rid, "mcps.missing_envelope"))
            continue
        params = request.get("params", {})

        try:
            now = int(time.time())
            signed = mcps_sdk.sign_request_with_signer(
                json.dumps(rid),
                method,
                json.dumps(params),
                on_behalf_of=args.on_behalf_of,
                audience=audience,
                binding_digest_alg="sha256",
                binding_digest_value=_AUTHZ_DIGEST,
                nonce=secrets.token_urlsafe(16),
                issued_at=_rfc3339(now),
                expires_at=_rfc3339(now + 300),
                signer=signer,
                policy=policy,
            )
            body = post(signed.wire_bytes)
            result = mcps_sdk.verify_response(
                body,
                resolver=resolver,
                expected_request_hash=signed.request_hash,
                expected_server_signer=args.server_signer,
                enforcement_mode="require_mcps",
            )
        except Exception as exc:  # noqa: BLE001 — surface as a fail-closed reject, never hang
            emit(_reject(rid, f"mcps.driver_error: {exc}"))
            continue

        if result.accepted:
            emit(_strip_envelope(json.loads(body)))
        else:
            emit(_reject(rid, result.reason))

    return 0


def _reject(rid, reason) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": rid,
        "error": {"code": _MCPS_REJECTED_CODE, "message": reason or "mcps.verification_failed"},
    }


if __name__ == "__main__":
    raise SystemExit(main())
