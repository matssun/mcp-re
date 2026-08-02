#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fetch a transparency service's verification key once, and pin it (MCPRE-501 slice 2).

Offline receipt verification needs the service's public key, and fetching it at verify
time would destroy the property being claimed — a verifier that calls the service is not
verifying offline, and an auditor holding only archived bytes could not reproduce it. So
discovery happens ONCE, here, and writes a `ScittServiceTrustPinV1` artifact that the
verifier consumes with no network at all. `mcp-re-http-profile` is a pure crate; this is
why the fetch is a tool and not a function in it.

**What the pin proves.** Exactly which key a run verified against, and where it came
from. Nothing more. It does not say the service is honest, that its log is append-only,
or that its operator is independent of us — a pinned key from a malicious service is
still a pinned key. Its value is that the interoperability result becomes reproducible
and falsifiable instead of resting on a key nobody wrote down.

Supported discovery:
  * `well-known-scitt-keys` — SCRAPI `GET /.well-known/scitt-keys`, a CBOR COSE_Key Set.
  * `jwks` — `GET <uri>`, an RFC 7517 JWK Set, for services that expose JOSE discovery.

    pip install cbor2 requests
    python tools/scitt_fetch_service_key.py \
        --service-uri http://127.0.0.1:8000 --kid <kid> --out service-key-pin.json

The `kid` should be the one the receipt names; pass `--any-single-key` for a service
whose key set holds exactly one key and whose receipts carry no `kid`.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
import sys
import urllib.request

import cbor2

SCHEMA = "mcp-re-scitt-service-trust-pin/v1"

# COSE_Key parameters (RFC 9052 §7) and algorithms (RFC 9053).
KTY, KID, ALG, CRV, X, Y = 1, 2, 3, -1, -2, -3
KTY_EC2, KTY_OKP = 2, 1
ALG_ES256, ALG_EDDSA = -7, -8
CRV_P256, CRV_ED25519 = 1, 6


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def fetch(uri: str) -> bytes:
    """Fetch the key set over HTTPS only.

    The pin is the ONE thing that says which key an interoperability run verified
    against, so whoever controls the network at pin time chooses that key. A bare
    `urlopen` with no scheme restriction accepted `http://` and `file://` — the first
    hands the choice to anyone on the path, the second to anyone who can drop a file
    where the operator points the tool.

    TLS is not a claim about the SERVICE (see the closing note the tool prints); it is
    what makes the pin a record of the key that service published rather than of the
    key an on-path party substituted.
    """
    if not uri.lower().startswith("https://"):
        raise SystemExit(
            f"refusing to fetch a trust pin over {uri.split(':', 1)[0]!r}: the pin records "
            "WHICH key was trusted, so an unauthenticated fetch lets whoever controls the "
            "network choose it. Use https://."
        )
    with urllib.request.urlopen(uri, timeout=30) as response:  # noqa: S310 - checked above
        return response.read()


def cose_key_thumbprint(kty: int, crv: int, x: bytes, y: bytes | None) -> str:
    """RFC 9679 COSE Key Thumbprint: SHA-256 over the canonical required-parameter map.

    Only the parameters that identify the key go in — not `kid`, not `alg`. A thumbprint
    that included the label would change when a service relabelled the same key, which
    would defeat comparing "is this the key I saw before" across a corpus.
    """
    required = {KTY: kty, CRV: crv, X: x}
    if y is not None:
        required[Y] = y
    canonical = cbor2.dumps(dict(sorted(required.items())), canonical=True)
    return b64u(hashlib.sha256(canonical).digest())


def key_from_cose(entry: dict) -> dict:
    """Normalize one COSE_Key into pin fields, refusing anything unsupported."""
    kty = entry.get(KTY)
    crv = entry.get(CRV)
    x = entry.get(X)
    if kty == KTY_EC2 and crv == CRV_P256:
        y = entry.get(Y)
        if not isinstance(x, bytes) or not isinstance(y, bytes):
            raise SystemExit("EC2 P-256 key is missing bytes-valued x/y")
        if len(x) != 32 or len(y) != 32:
            raise SystemExit(f"EC2 P-256 coordinates must be 32 octets, got {len(x)}/{len(y)}")
        return {
            "algorithm": "ES256",
            "public_key": {"x": b64u(x), "y": b64u(y)},
            "thumbprint": cose_key_thumbprint(kty, crv, x, y),
        }
    if kty == KTY_OKP and crv == CRV_ED25519:
        if not isinstance(x, bytes) or len(x) != 32:
            raise SystemExit("OKP Ed25519 key must carry a 32-octet x")
        return {
            "algorithm": "EdDSA",
            "public_key": {"x": b64u(x)},
            "thumbprint": cose_key_thumbprint(kty, crv, x, None),
        }
    raise SystemExit(
        f"unsupported COSE key (kty={kty!r} crv={crv!r}); this verifier implements "
        "ES256 over P-256 and EdDSA over Ed25519"
    )


def key_from_jwk(entry: dict) -> dict:
    """Normalize one JWK into pin fields."""
    kty, crv = entry.get("kty"), entry.get("crv")
    if kty == "EC" and crv == "P-256":
        x, y = b64u_decode(entry["x"]), b64u_decode(entry["y"])
        if len(x) != 32 or len(y) != 32:
            raise SystemExit(f"P-256 coordinates must be 32 octets, got {len(x)}/{len(y)}")
        return {
            "algorithm": "ES256",
            "public_key": {"x": b64u(x), "y": b64u(y)},
            "thumbprint": cose_key_thumbprint(KTY_EC2, CRV_P256, x, y),
        }
    if kty == "OKP" and crv == "Ed25519":
        x = b64u_decode(entry["x"])
        return {
            "algorithm": "EdDSA",
            "public_key": {"x": b64u(x)},
            "thumbprint": cose_key_thumbprint(KTY_OKP, CRV_ED25519, x, None),
        }
    raise SystemExit(f"unsupported JWK (kty={kty!r} crv={crv!r})")


def select(entries: list, kid: str | None, any_single: bool, key_of, kid_of):
    """Pick the entry the receipt names, or the only one if that is what was asked for."""
    if kid is not None:
        matches = [e for e in entries if kid_of(e) == kid]
        if not matches:
            available = sorted(str(kid_of(e)) for e in entries)
            raise SystemExit(f"no key with kid {kid!r}; the service advertises {available}")
        if len(matches) > 1:
            raise SystemExit(f"{len(matches)} keys share kid {kid!r}; refusing to guess")
        return matches[0], kid
    if not any_single:
        raise SystemExit("pass --kid, or --any-single-key if the set holds exactly one key")
    if len(entries) != 1:
        raise SystemExit(f"--any-single-key needs exactly one key, the set has {len(entries)}")
    return entries[0], kid_of(entries[0])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--service-uri", required=True, help="service base URI, or the full JWKS URI")
    ap.add_argument("--method", choices=("well-known-scitt-keys", "jwks"),
                    default="well-known-scitt-keys")
    ap.add_argument("--kid", help="the kid the receipt names")
    ap.add_argument("--any-single-key", action="store_true",
                    help="accept the only key in the set when receipts carry no kid")
    ap.add_argument("--service-identifier", help="how this deployment names the service")
    ap.add_argument("--out", required=True, help="where to write the pin")
    ap.add_argument("--expect-thumbprint",
                    help="the RFC 9679 COSE key thumbprint confirmed OUT OF BAND; the fetch "
                         "is refused unless it matches. Without it the pin is trust-on-first-use "
                         "and the network chose the key.")
    ap.add_argument("--replace-pin", action="store_true",
                    help="allow overwriting an existing pin that names a different key")
    args = ap.parse_args()

    if args.method == "well-known-scitt-keys":
        uri = args.service_uri.rstrip("/") + "/.well-known/scitt-keys"
    else:
        uri = args.service_uri

    document = fetch(uri)
    # The digest is over the EXACT bytes fetched, so a later reader can tell whether the
    # document it gets is the one this pin was cut from.
    document_digest = b64u(hashlib.sha256(document).digest())

    if args.method == "well-known-scitt-keys":
        decoded = cbor2.loads(document)
        # A COSE_Key Set is an array of COSE_Key maps; some services wrap it in a map
        # under a "keys" label.
        entries = decoded if isinstance(decoded, list) else decoded.get("keys") or decoded.get(1)
        if not isinstance(entries, list):
            raise SystemExit(f"{uri} did not return a COSE_Key Set")

        def kid_of(entry):
            raw = entry.get(KID)
            return raw.decode(errors="replace") if isinstance(raw, bytes) else raw

        entry, kid = select(entries, args.kid, args.any_single_key, key_from_cose, kid_of)
        fields = key_from_cose(entry)
    else:
        entries = json.loads(document).get("keys", [])
        entry, kid = select(entries, args.kid, args.any_single_key, key_from_jwk,
                            lambda e: e.get("kid"))
        fields = key_from_jwk(entry)

    pin = {
        "schema": SCHEMA,
        "service_identifier": args.service_identifier or args.service_uri,
        "discovery_method": args.method,
        "discovery_uri": uri,
        "fetched_at": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        # An EMPTY kid is written only for a service whose receipts genuinely carry
        # none (`--any-single-key`), and `ScittServiceTrustPin::resolve` treats it as
        # "matches an unlabelled receipt". Writing it for any other reason would make
        # the pin match receipts it was never fetched for.
        "kid": kid if kid is not None else "",
        "algorithm": fields["algorithm"],
        "public_key": fields["public_key"],
        "public_key_thumbprint": fields["thumbprint"],
        "discovery_document_digest": document_digest,
    }
    # Never SILENTLY replace an existing pin. Re-running the tool is how a pin gets
    # rotated, and it was also how a pin got swapped: the file was truncated
    # unconditionally, so a second run under an attacker's network chose the trust
    # anchor with no trace. An existing pin must be removed deliberately, or its
    # replacement acknowledged with --replace-pin.
    if os.path.exists(args.out) and not args.replace_pin:
        existing = json.load(open(args.out, encoding="utf-8"))
        if existing.get("public_key_thumbprint") != fields["thumbprint"]:
            raise SystemExit(
                f"{args.out} already pins a DIFFERENT key "
                f"(thumbprint {existing.get('public_key_thumbprint')!r}); refusing to "
                "overwrite it. Pass --replace-pin to rotate deliberately, having "
                "confirmed the new thumbprint out of band."
            )
    if args.expect_thumbprint and args.expect_thumbprint != fields["thumbprint"]:
        raise SystemExit(
            f"fetched key thumbprint {fields['thumbprint']} does not match the expected "
            f"{args.expect_thumbprint}: refusing to write a pin for a key nobody confirmed."
        )
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(pin, handle, indent=2, sort_keys=True)
        handle.write("\n")

    print(f"pinned {fields['algorithm']} key kid={pin['kid']!r}")
    print(f"  thumbprint  {fields['thumbprint']}")
    print(f"  from        {uri}")
    print(f"  doc digest  {document_digest}")
    print(f"  written to  {args.out}")
    print("\nThis records WHICH key was used. It is not a statement that the service is")
    print("trustworthy, that its log is append-only, or that its operator is independent.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
