#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent RFC 9421 cross-verification of the MCP-RE HTTP-profile corpus
(ADR-MCPRE-050 no-merge gate, MCPRE-99).

This is a PINNED, THIRD-PARTY check: it reconstructs each signed fixture's
RFC 9421 signature base with its OWN parser and verifies the Ed25519 signature
with `cryptography` (a different implementation than the Rust `ed25519-dalek`
the corpus was produced with). If our signer and this external verifier disagree
on a single byte, the gate fails and the merge is blocked.

It checks BOTH directions:
  * our vectors verify externally  — every positive-signature fixture
    (request / response / bound+unbound rejection) verifies here, and h01's
    reconstructed base is byte-compared to the frozen oracle;
  * external → us                  — `external_kat.json` is produced HERE by
    `cryptography` and (in CI) fed back to the Rust verifier
    (`rfc9421_cross_verification_test.rs`); `--emit-external-kat` regenerates it.

Determinism: Ed25519 is deterministic, so byte comparison is honest.

Usage:
    python3 rfc9421_cross_verify.py [CORPUS_DIR] [--emit-external-kat]
Exit code 0 == gate passes.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

# TEST-ONLY key seeds, identical to the Rust corpus writer
# (CLIENT_SEED = [11u8; 32], SERVER_SEED = [22u8; 32]).
CLIENT_SEED = bytes([11]) * 32
SERVER_SEED = bytes([22]) * 32

KEYS: dict[str, Ed25519PublicKey] = {
    "client-key-1": Ed25519PrivateKey.from_private_bytes(CLIENT_SEED).public_key(),
    "server-key-1": Ed25519PrivateKey.from_private_bytes(SERVER_SEED).public_key(),
}

PROFILE_TAG = "mcp-re-http-v1"


def b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def header(headers: list[list[str]], name: str) -> str | None:
    """Exact-once, case-insensitive header lookup; None if absent."""
    found = None
    for k, v in headers:
        if k.lower() == name.lower():
            if found is not None:
                raise ValueError(f"duplicate header {name}")
            found = v.strip()
    return found


def authority_of(target_uri: str) -> str:
    rest = target_uri.split("://", 1)[1]
    end = min([i for i in (rest.find("/"), rest.find("?"), rest.find("#")) if i >= 0] + [len(rest)])
    return rest[:end].lower()


def path_of(target_uri: str) -> str:
    rest = target_uri.split("://", 1)[1]
    idx = [i for i in (rest.find("/"), rest.find("?"), rest.find("#")) if i >= 0]
    if not idx:
        return "/"
    start = min(idx)
    if rest[start] != "/":
        return "/"
    tail = rest[start:]
    end = min([i for i in (tail.find("?"), tail.find("#")) if i >= 0] + [len(tail)])
    return tail[:end]


def component_value(ident: str, req_bool: bool, request: dict | None, response: dict | None) -> str:
    """Resolve one covered component, RFC 9421-style. `;req` resolves against
    the request; otherwise against the response (if any) or the request."""
    msg = request if (req_bool or response is None) else response
    if msg is None:
        raise ValueError(f"no source message for {ident}")
    if ident.startswith("@"):
        name = ident[1:]
        if name == "method":
            return msg["method"].upper()
        if name == "target-uri":
            return msg["target_uri"]
        if name == "authority":
            return authority_of(msg["target_uri"])
        if name == "path":
            return path_of(msg["target_uri"])
        if name == "status":
            return str(msg["status"])
        raise ValueError(f"unsupported derived component {ident}")
    val = header(msg["headers"], ident)
    if val is None:
        raise ValueError(f"missing covered field {ident}")
    return val


def parse_signature_input(member: str) -> tuple[list[tuple[str, bool]], str]:
    """Return the ordered [(identifier, is_req)] list and the literal params
    string (everything after the closing paren, used verbatim in the base)."""
    member = member.strip()
    assert member.startswith("("), "inner list must start with ("
    close = member.index(")")
    inner = member[1:close]
    comps: list[tuple[str, bool]] = []
    for item in inner.split():
        is_req = item.endswith(";req")
        if is_req:
            item = item[: -len(";req")]
        assert item.startswith('"') and item.endswith('"'), f"bad identifier {item}"
        comps.append((item[1:-1], is_req))
    params = member[close + 1 :]
    return comps, params


def dictionary_member(value: str, label: str) -> str:
    """Extract `label=...` from a Structured-Fields dictionary, honoring quotes."""
    members, start, in_q = [], 0, False
    for i, c in enumerate(value):
        if c == '"':
            in_q = not in_q
        elif c == "," and not in_q:
            members.append(value[start:i])
            start = i + 1
    members.append(value[start:])
    for m in members:
        m = m.strip()
        if m.startswith(label + "="):
            return m[len(label) + 1 :].strip()
    raise ValueError(f"label {label} not found")


def reconstruct_base(comps, sig_params_value, request, response) -> bytes:
    """`sig_params_value` is the FULL `Signature-Input` member value
    (`("a" "b");created=...`), used verbatim as the @signature-params line."""
    lines = []
    for ident, is_req in comps:
        suffix = ";req" if is_req else ""
        lines.append(f'"{ident}"{suffix}: {component_value(ident, is_req, request, response)}')
    lines.append(f'"@signature-params": {sig_params_value}')
    return "\n".join(lines).encode()


def signature_bytes(headers, label) -> bytes:
    sig_member = dictionary_member(header(headers, "signature"), label)
    assert sig_member.startswith(":") and sig_member.endswith(":"), "byte-sequence form"
    return base64.b64decode(sig_member[1:-1])


def keyid_and_tag(params: str) -> tuple[str, str]:
    keyid = tag = None
    for p in params.split(";"):
        p = p.strip()
        if p.startswith('keyid="'):
            keyid = p[len('keyid="') : -1]
        elif p.startswith('tag="'):
            tag = p[len('tag="') : -1]
    return keyid, tag


def verify_fixture(fx: dict) -> None:
    kind = fx["kind"]
    label = "mcp-re" if kind == "request" else "mcp-re-response"
    request = fx.get("request")
    response = fx.get("response")
    msg_headers = (request if kind == "request" else response)["headers"]
    si = dictionary_member(header(msg_headers, "signature-input"), label)
    comps, params = parse_signature_input(si)
    keyid, tag = keyid_and_tag(params)
    if tag != PROFILE_TAG:
        raise ValueError(f"foreign tag {tag}")
    base = reconstruct_base(comps, si, request, response if kind != "request" else None)
    KEYS[keyid].verify(signature_bytes(msg_headers, label), base)
    return base


POSITIVE = {
    "h01_request_valid",
    "h07_response_valid",
    "h18_rejection_bound_valid",
    "h19_rejection_unbound_valid",
}


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    corpus = Path(args[0]) if args else Path(__file__).resolve().parents[1] / "tests" / "vectors" / "http-profile"
    manifest = json.loads((corpus / "manifest.json").read_text())

    checked = 0
    for entry in manifest["fixtures"]:
        # Manifest entries are content-pinned (#415 rev 2 §12.2, MCPRE-427): each is
        # {file, sha256}. As the third-party verifier, check the pin before reading —
        # the whole point of §12.2 is that a reviewer proves it read the same bytes.
        name = entry["file"]
        raw = (corpus / name).read_bytes()
        want_hash = entry["sha256"]
        got_hash = hashlib.sha256(raw).hexdigest()
        if got_hash != want_hash:
            print(f"FAIL {name}: manifest sha256 mismatch\n  file={got_hash}\n  manifest={want_hash}")
            return 1
        fx = json.loads(raw)
        # The manifest also pins the external KAT (a third-party artifact with no
        # Fixture `name`); its hash is checked above, and it is replayed by its own
        # harness, not this positive-fixture loop.
        if fx.get("name") not in POSITIVE:
            continue
        base = verify_fixture(fx)
        # Byte-compare h01's reconstructed base against the frozen oracle.
        if fx.get("oracle"):
            want = fx["oracle"]["signature_base_b64url"]
            got = b64url_nopad(base)
            if got != want:
                print(f"FAIL {fx['name']}: base mismatch\n  ext={got}\n  oracle={want}")
                return 1
        checked += 1
        print(f"ok  external-verify {fx['name']}")

    if checked == 0:
        print("FAIL: no positive fixtures verified")
        return 1

    if "--emit-external-kat" in flags:
        emit_external_kat(corpus)

    print(f"PASS: {checked} MCP-RE http-profile signatures verified by an independent RFC 9421 impl")
    return 0


def emit_external_kat(corpus: Path) -> None:
    """external → us: sign a fixed base with `cryptography` and commit it so the
    Rust verifier can confirm it accepts an externally-produced signature."""
    seed = bytes(range(32))
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    base = (
        '"@method": POST\n'
        '"content-type": application/json\n'
        '"@signature-params": ("@method" "content-type");created=1700000000;'
        'keyid="ext-key";alg="ed25519";tag="mcp-re-http-v1"'
    ).encode()
    sig = sk.sign(base)
    out = {
        "note": "Signature produced by python-cryptography (independent of ed25519-dalek).",
        "seed_b64url": b64url_nopad(seed),
        "public_key_b64url": b64url_nopad(
            sk.public_key().public_bytes_raw()
        ),
        "signature_base_b64url": b64url_nopad(base),
        "signature_b64url": b64url_nopad(sig),
    }
    (corpus / "external_kat.json").write_text(json.dumps(out, indent=2) + "\n")
    print("emitted external_kat.json")


if __name__ == "__main__":
    raise SystemExit(main())
