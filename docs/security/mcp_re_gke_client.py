#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""MCP-RE GKE-proof client — the HTTP-profile signed-request driver for the live
multi-replica validation harness (`gke-multi-replica-validation.sh`).

MCP-RE is HTTP-profile only. This replaces the removed `mcp-re-client-proxy-cli`:
it reads ONE plain MCP JSON-RPC request on stdin, signs an RFC 9421 + RFC 9530 request with the
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

import mcp_re_sdk

def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _b64url_text_at_file(spec: str) -> str:
    """Return a Base64URL value that may be given inline or as ``@<path>`` (the CLI's
    ``@file`` convention) as the RAW b64url STRING — used for ``--server-pubkey``.
    The SDK's ``verify_response`` takes the server key as a Base64URL string (it calls
    ``VerificationKey::from_b64url`` itself), so the client must NOT pre-decode it."""
    raw = spec
    if spec.startswith("@"):
        with open(spec[1:], "r", encoding="utf-8") as fh:
            raw = fh.read().strip()
    return raw


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


def _classify(reason: "str | None") -> str:
    """Map a fail-closed ``mcp-re.*`` reason to a coarse verdict token."""
    r = (reason or "").lower()
    if "replay" in r:
        return "replay"
    if any(k in r for k in ("trust", "epoch", "revok", "actor_binding", "untrusted", "unknown_signer")):
        return "revoked"
    return f"rejected:{reason or 'unknown'}"


def _body_reject_reason(body: bytes) -> "str | None":
    """The proxy's own ``mcp-re.*`` reason from a fail-closed JSON-RPC error body.

    A fail-closed request may be answered with a signed RFC 9421 rejection, or —
    for a pre-evidence transport/parse failure — an unsigned JSON-RPC error whose
    reason ``verify_response`` cannot read. The authoritative reason is the proxy's
    signed rejection body, whose shape is
    ``error.data.mcp_re_error = {"wire_code": "mcp-re.<reason>"}`` (an object); some
    pre-evidence errors instead carry it as a bare string, and the human ``message``
    embeds it too. Reading it is for VERDICT CLASSIFICATION ONLY: the request is
    already fail-closed (rejected), so this never turns a rejection into an
    acceptance — it just lets the harness distinguish replay from revoked from a
    generic rejection. Returns None if the body is not such an error."""
    try:
        err = json.loads(body).get("error")
        if isinstance(err, dict):
            data = err.get("data")
            me = data.get("mcp_re_error") if isinstance(data, dict) else None
            # The proxy's signed rejection carries the reason as an object.
            if isinstance(me, dict) and isinstance(me.get("wire_code"), str):
                return me["wire_code"]
            # Some pre-evidence errors carry it as a bare string.
            if isinstance(me, str):
                return me
            # Last resort: the embedded reason in the human-readable message
            # (e.g. "mcp-re http-profile proxy rejected: mcp-re.replay_detected").
            msg = err.get("message")
            if isinstance(msg, str) and "mcp-re." in msg:
                return msg
    except (ValueError, AttributeError):
        pass
    return None


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
    p.add_argument("--audience", required=True)             # RFC 9421 audience id
    p.add_argument("--target-uri", required=True)           # canonical @target-uri
    p.add_argument("--route")                               # optional audience route
    p.add_argument("--trust-domain", default="example.com") # server actor trust domain
    p.add_argument("--dpop-token", default="access-token-xyz")  # OAuth-DPoP credential
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

    def post(headers: "list[tuple[str, str]]", body: bytes):
        """Send the RFC 9421 signed request; return (status, response_headers, body)."""
        raw = socket.create_connection((host, port), timeout=15)
        try:
            tls = ctx.wrap_socket(raw, server_hostname=args.server_name)
        except Exception:
            raw.close()
            raise
        try:
            hdr_lines = "".join(f"{k}: {v}\r\n" for k, v in headers)
            head = (
                f"POST / HTTP/1.1\r\nHost: {args.server_name}\r\n"
                f"{hdr_lines}"
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
        raw_resp = b"".join(chunks)
        head_bytes, _, resp_body = raw_resp.partition(b"\r\n\r\n")
        lines = head_bytes.split(b"\r\n")
        status = int(lines[0].split(b" ")[1]) if len(lines[0].split(b" ")) > 1 else 0
        resp_headers = []
        for line in lines[1:]:
            if b":" in line:
                k, _, v = line.partition(b":")
                resp_headers.append((k.decode().strip(), v.decode().strip()))
        return status, resp_headers, resp_body

    return post


#: The RFC 9421 response evidence block key the proxy authors in the body `_meta`.
_RESPONSE_EVIDENCE_BLOCK_KEY = "se.syncom/mcp-re.http.response"


def _strip_envelope(obj: dict) -> dict:
    """Strip the proxy-owned RFC 9421 response evidence block, leaving plain MCP."""
    result = obj.get("result")
    if isinstance(result, dict):
        meta = result.get("_meta")
        if isinstance(meta, dict):
            meta.pop(_RESPONSE_EVIDENCE_BLOCK_KEY, None)
            if not meta:
                result.pop("_meta", None)
    return obj


def main(argv: "list[str] | None" = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)

    seed = _read_seed(args.signing_key_seed)
    server_pub = _b64url_text_at_file(args.server_pubkey)  # b64url STRING; SDK decodes it
    post = _make_post(args)

    request = json.loads(sys.stdin.readline())
    rid = request.get("id")
    method = request.get("method")
    params = request.get("params", {})

    now = int(time.time())
    # Sign the RFC 9421 + RFC 9530 request (zero object/JCS).
    signed = mcp_re_sdk.sign_request(
        seed,
        args.key_id,
        json.dumps(rid),
        method,
        json.dumps(params),
        args.target_uri,
        args.audience,
        args.route,
        args.dpop_token,
        args.nonce or secrets.token_urlsafe(16),
        now,
        now + 300,
    )
    status, resp_headers, resp_body = post(signed.headers, signed.body())

    reason = ""
    try:
        # Verify the signed response bound to THIS request (RFC 9421 `;req` + block).
        mcp_re_sdk.verify_response(
            status,
            resp_headers,
            resp_body,
            signed.method,
            signed.target_uri,
            signed.headers,
            signed.body(),
            signed.evidence_digest_alg,
            signed.evidence_digest_value,
            args.server_key_id,
            server_pub,
            "server",
            args.trust_domain,
            args.server_signer,
            int(time.time()),
        )
        accepted = True
    except ValueError as exc:
        accepted = False
        reason = str(exc)

    if accepted:
        verdict = "accepted"
        plain = _strip_envelope(json.loads(resp_body))
        sys.stdout.write(json.dumps(plain, separators=(",", ":")) + "\n")
    else:
        verdict = _classify(_body_reject_reason(resp_body) or reason)
        # Echo the proxy's signed-rejection body so the harness can still inspect it.
        sys.stdout.write(resp_body.decode("utf-8", "replace") + "\n")

    sys.stderr.write(f"verdict={verdict}\n")
    if args.expect and verdict != args.expect:
        sys.stderr.write(f"verdict mismatch: expected {args.expect}, got {verdict}\n")
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
