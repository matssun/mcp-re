#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent JOSE/JWS cross-verification of the MCP-RE delegation credential
(ADR-MCPRE-052 §9; mirrors the RFC 9421 gate, MCPRE-99).

The delegation credential is a compact JWS (RFC 7515) with an EdDSA signature
(RFC 8037) over `base64url(header) + "." + base64url(payload)`. This is a PINNED,
THIRD-PARTY check: it reconstructs the canonical credential with its OWN JWS
serializer and signs / verifies the Ed25519 signature with `cryptography`
(a different implementation than the Rust `ed25519-dalek` the corpus is produced
with). If our issuer and this external implementation disagree on a single byte,
the gate fails and the merge is blocked.

It checks BOTH directions:
  * ours → external — the credential embedded in the committed `d01_valid.json`
    fixture is parsed, its EdDSA signature is verified here under the root public
    key, and the whole compact JWS is byte-compared to the one this tool builds
    independently (Ed25519 is deterministic, so byte equality is honest);
  * external → us   — `external_delegation_kat.json` is produced HERE by
    `cryptography` and (in CI) fed back to the Rust verifier
    (`delegation_cross_verification_test.rs`); `--emit-external-kat` regenerates it.

Usage:
    python3 jose_cross_verify.py [CORPUS_DIR] [--emit-external-kat]
Exit code 0 == gate passes.
"""
from __future__ import annotations

import base64
import json
import sys
from collections import OrderedDict
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

# TEST-ONLY seeds, identical to the Rust corpus writer
# (ROOT_SEED = [33u8; 32], DELEGATED_SEED = [44u8; 32]).
ROOT_SEED = bytes([33]) * 32
DELEGATED_SEED = bytes([44]) * 32

# Frozen credential constants (must match delegation_vectors_test.rs).
DELEGATION_TYP = "mcp-re-delegation+jwt"
DELEGATION_ALG = "EdDSA"
KEY_USE_RESPONSE_SIGNING = "response-signing"
JWK_KTY_OKP = "OKP"
JWK_CRV_ED25519 = "Ed25519"
PROFILE_TAG = "mcp-re-http-v1"

ROOT_KID = "root-kid"
DELEGATED_KID = "root-kid/delegated/1"
VERIFIER_AUD = "verifier-1"
AUD_SCOPE = "aud-scope-1"
EPOCH = "epoch-1"
CREATED = 1_700_000_000
EXPIRES = 1_700_000_300
# The resolved server-signer id — ActorIdentity::actor_id() of the delegated
# server signer: `{role}:{trust_domain}:{urlencoded subject}:{keyid}`.
SERVER_SIGNER = "server:example.com:did%3Aexample%3Aserver:root-kid/delegated/1"

RESPONSE_BLOCK_KEY = "se.syncom/mcp-re.http.response"


def b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def canonical_json(obj: "OrderedDict[str, object]") -> bytes:
    """serde_json-compatible compact encoding: no spaces, keys in insertion
    order (serde emits struct fields in declaration order), UTF-8."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()


def delegated_public_x() -> str:
    pub = Ed25519PrivateKey.from_private_bytes(DELEGATED_SEED).public_key()
    return b64url_nopad(pub.public_bytes_raw())


def build_header() -> "OrderedDict[str, object]":
    return OrderedDict(
        (("typ", DELEGATION_TYP), ("alg", DELEGATION_ALG), ("kid", ROOT_KID))
    )


def build_claims() -> "OrderedDict[str, object]":
    return OrderedDict(
        (
            ("iss", "did:example:server"),
            ("iat", CREATED),
            ("nbf", CREATED),
            ("exp", EXPIRES),
            ("jti", "evt-1"),
            ("aud", VERIFIER_AUD),
            ("mcp_re_profile", PROFILE_TAG),
            ("mcp_re_audience_hash", AUD_SCOPE),
            ("mcp_re_server_signer", SERVER_SIGNER),
            ("mcp_re_key_use", KEY_USE_RESPONSE_SIGNING),
            ("delegated_kid", DELEGATED_KID),
            ("issuer_kid", ROOT_KID),
            ("trust_epoch", EPOCH),
            (
                "cnf",
                OrderedDict(
                    (
                        (
                            "jwk",
                            OrderedDict(
                                (
                                    ("kty", JWK_KTY_OKP),
                                    ("crv", JWK_CRV_ED25519),
                                    ("kid", DELEGATED_KID),
                                    ("x", delegated_public_x()),
                                )
                            ),
                        ),
                    )
                ),
            ),
        )
    )


def build_external_compact_jws() -> str:
    """Independently construct + EdDSA-sign the canonical credential."""
    root = Ed25519PrivateKey.from_private_bytes(ROOT_SEED)
    h = b64url_nopad(canonical_json(build_header()))
    p = b64url_nopad(canonical_json(build_claims()))
    signing_input = f"{h}.{p}".encode()
    sig = root.sign(signing_input)
    return f"{h}.{p}.{b64url_nopad(sig)}"


def verify_compact_jws(compact: str, root_pub: Ed25519PublicKey) -> None:
    """EdDSA-verify the compact JWS signature under `root_pub` (raises on
    failure)."""
    h, p, s = compact.split(".")
    root_pub.verify(b64url_decode(s), f"{h}.{p}".encode())


def credential_from_fixture(corpus_dir: Path) -> str:
    """Pull the `server_delegation` compact JWS out of the committed d01
    fixture's signed response body."""
    fixture = json.loads((corpus_dir / "d01_valid.json").read_text())
    body = json.loads(fixture["response"]["body_utf8"])
    return body["_meta"][RESPONSE_BLOCK_KEY]["server_delegation"]


def emit_external_kat(corpus_dir: Path) -> None:
    root_pub = Ed25519PrivateKey.from_private_bytes(ROOT_SEED).public_key()
    kat = OrderedDict(
        (
            (
                "note",
                "Compact JWS delegation credential (EdDSA) produced by "
                "python-cryptography, independent of ed25519-dalek. Consumed by "
                "delegation_cross_verification_test.rs (external -> us).",
            ),
            ("root_seed_b64url", b64url_nopad(ROOT_SEED)),
            ("root_public_key_b64url", b64url_nopad(root_pub.public_bytes_raw())),
            ("delegated_seed_b64url", b64url_nopad(DELEGATED_SEED)),
            ("delegated_public_key_b64url", delegated_public_x()),
            ("issuer_kid", ROOT_KID),
            ("delegated_kid", DELEGATED_KID),
            ("verifier_audience", VERIFIER_AUD),
            ("expected_profile", PROFILE_TAG),
            ("expected_audience_hash", AUD_SCOPE),
            ("expected_server_signer", SERVER_SIGNER),
            ("trust_epoch", EPOCH),
            ("now_unix", 1_700_000_100),
            ("max_clock_skew", 60),
            ("compact_jws", build_external_compact_jws()),
        )
    )
    out = corpus_dir / "external_delegation_kat.json"
    out.write_text(json.dumps(kat, indent=2) + "\n")
    print(f"wrote {out}")


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    corpus_dir = Path(args[0]) if args else (
        Path(__file__).resolve().parent.parent / "tests" / "vectors" / "delegation-profile"
    )
    if "--emit-external-kat" in sys.argv[1:]:
        emit_external_kat(corpus_dir)
        return 0

    root_pub = Ed25519PrivateKey.from_private_bytes(ROOT_SEED).public_key()
    external = build_external_compact_jws()

    # external self-check: our independently built credential verifies here.
    verify_compact_jws(external, root_pub)

    # ours -> external: the credential embedded in the committed corpus verifies
    # under this independent Ed25519 implementation, AND is byte-identical to the
    # one this tool builds (Ed25519 determinism).
    ours = credential_from_fixture(corpus_dir)
    try:
        verify_compact_jws(ours, root_pub)
    except InvalidSignature:
        print("FAIL: committed d01 credential does not verify under python-cryptography")
        return 1
    if ours != external:
        print("FAIL: committed credential differs byte-for-byte from the external build")
        print(f"  ours     = {ours}")
        print(f"  external = {external}")
        return 1

    print("OK: delegation credential cross-verifies against python-cryptography (both directions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
