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
        --service-uri https://transparency.example --kid <kid> \
        --position-profile bound --out service-key-pin.json

The `kid` should be the one the receipt names; pass `--any-single-key` for a service
whose key set holds exactly one key and whose receipts carry no `kid`.

**Why the profiles are arguments and not defaults.** A pin carries two properties of the
SERVICE that no receipt can be asked for, because the receipt is the value under attack:
which bytes the log hashes as its Merkle entry (`--leaf-profile`), and whether its
receipts commit to their own `(tree_size, leaf_index)` (`--position-profile`). The Rust
verifier defaults both to the weaker reading when the field is absent, so a pin that
omits them silently pins the pre-v2 contract — under which a relayer may restate a small
log's receipt as a position in a larger one and it still verifies. `--position-profile`
is therefore required rather than defaulted: it is a thing an operator has to have
established about the service and written down.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime
import hashlib
import io
import json
import os
import sys
import urllib.request

SCHEMA = "mcp-re-scitt-service-trust-pin/v1"

# The two service properties a pin records verbatim. The tokens are the serialized form
# `ScittServiceTrustPin` reads (`ReceiptPositionProfile` and `StatementLeafProfile`), so
# a value this tool accepts is a value the verifier accepts.
POSITION_PROFILES = ("unbound", "bound")
LEAF_PROFILES = ("statement-bytes", "statement-digest")

# COSE_Key parameters (RFC 9052 §7) and algorithms (RFC 9053).
KTY, KID, ALG, CRV, X, Y = 1, 2, 3, -1, -2, -3
KTY_EC2, KTY_OKP = 2, 1
ALG_ES256, ALG_EDDSA = -7, -8
CRV_P256, CRV_ED25519 = 1, 6


def _cbor2():
    """The cbor2 module, imported on demand.

    Only key normalisation needs it. Importing it at module scope made `--selftest`
    — the only proof that the https-only guard below still holds — unrunnable on a
    machine without the dependency, which is every machine the structural gates run
    on. A guard whose test cannot execute is a guard nobody is checking.
    """
    try:
        import cbor2
    except ModuleNotFoundError:
        raise SystemExit(
            "this path needs the cbor2 package: pip install cbor2"
        ) from None
    return cbor2


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _refuse_scheme(uri: str, how: str) -> SystemExit:
    return SystemExit(
        f"refusing to fetch a trust pin over {uri.split(':', 1)[0]!r} ({how}): the pin "
        "records WHICH key was trusted, so an unauthenticated fetch lets whoever "
        "controls the network choose it. Use https://."
    )


class HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only while the target stays https.

    The scheme check on the URI the operator typed is not the check that matters:
    stdlib's default `HTTPRedirectHandler` accepts http, https and ftp targets, so a
    single 302 from the service restores exactly the plaintext leg the guard exists
    to prevent — and the key written into the pin is then whoever is on the path's
    choice. The redirect is where the scheme has to be re-checked, because it is the
    hop the operator never sees.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise _refuse_scheme(newurl, f"HTTP {code} redirect from {req.full_url}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener() -> urllib.request.OpenerDirector:
    """An opener that cannot leave https, on the first hop or any later one."""
    return urllib.request.build_opener(HttpsOnlyRedirectHandler)


def fetch(uri: str) -> bytes:
    """Fetch the key set over HTTPS only, redirects included.

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
        raise _refuse_scheme(uri, "requested URI")
    with _opener().open(uri, timeout=30) as response:  # noqa: S310 - checked above
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
    canonical = _cbor2().dumps(dict(sorted(required.items())), canonical=True)
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


def selftest() -> int:
    """Assert the redirect handler itself, not just the first-hop scheme check.

    Driving this end to end would need a TLS server that 302s to plaintext, so the
    test targets the decision directly: the handler is what stdlib consults on every
    hop, and it must refuse every scheme but https.
    """
    handler = HttpsOnlyRedirectHandler()
    request = urllib.request.Request("https://service.example/.well-known/scitt-keys")
    failures = 0
    for target, allowed in (
        ("http://service.example/keys", False),
        ("HTTP://service.example/keys", False),
        ("ftp://service.example/keys", False),
        ("file:///tmp/keys", False),
        ("https://elsewhere.example/keys", True),
    ):
        try:
            handler.redirect_request(request, None, 302, "Found", {}, target)
            refused = False
        except SystemExit:
            refused = True
        except Exception:  # noqa: BLE001 - stdlib may reject an https target for
            refused = False  # unrelated reasons; only the scheme decision is under test
        if refused == allowed:
            verb = "followed" if allowed else "refused"
            print(f"SELFTEST FAIL: redirect to {target!r} was not {verb}")
            failures += 1
    for uri in ("http://service.example", "file:///tmp/keys"):
        try:
            fetch(uri)
        except SystemExit:
            continue
        except Exception:  # noqa: BLE001
            pass
        print(f"SELFTEST FAIL: fetch({uri!r}) was not refused before any request")
        failures += 1
    # The WIRING, not just the class. `build_opener` installs its own
    # `HTTPRedirectHandler` unless the caller passes that class or a subclass, so a
    # guard class that exists but is not the one the opener consults would leave the
    # plaintext hop open while every case above still passed.
    installed = [h for h in _opener().handlers if isinstance(h, urllib.request.HTTPRedirectHandler)]
    if len(installed) != 1 or not isinstance(installed[0], HttpsOnlyRedirectHandler):
        print(f"SELFTEST FAIL: fetch()'s opener consults {installed!r}, not the https-only handler")
        failures += 1

    # The PIN's own contents. `position_profile` and `leaf_profile` default to the
    # weaker reading on the Rust side, so a pin that omits them pins the pre-v2
    # contract — and nothing downstream can tell that from a deliberate choice.
    parser = _parser()
    base = [
        "--service-uri", "https://service.example",
        "--any-single-key",
        "--out", "/dev/null",
    ]
    try:
        # argparse prints its usage to stderr on the way out; the case under test is the
        # refusal, not the message.
        with contextlib.redirect_stderr(io.StringIO()):
            parser.parse_args(base)
        print("SELFTEST FAIL: a pin was cut with no --position-profile; the verifier's "
              "default is the weaker contract, so it must be stated")
        failures += 1
    except SystemExit:
        pass
    for position, leaf in (("bound", "statement-bytes"), ("unbound", "statement-digest")):
        args = parser.parse_args(
            base + ["--position-profile", position, "--leaf-profile", leaf]
        )
        pin = build_pin(
            args,
            "kid-1",
            {"algorithm": "EdDSA", "public_key": {"x": "AAAA"}, "thumbprint": "TTTT"},
            "https://service.example/.well-known/scitt-keys",
            "DDDD",
        )
        if pin.get("position_profile") != position or pin.get("leaf_profile") != leaf:
            print(f"SELFTEST FAIL: pin recorded {pin.get('position_profile')!r}/"
                  f"{pin.get('leaf_profile')!r}, not {position!r}/{leaf!r}")
            failures += 1
    if failures:
        print(f"{failures} case(s) failed — the https-only guard is not trustworthy.")
        return 1
    print("selftest ok: 11 cases (redirect scheme guard, first-hop scheme guard, opener "
          "wiring, pin profile fields)")
    return 0


def _parser() -> argparse.ArgumentParser:
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
    ap.add_argument("--position-profile", choices=POSITION_PROFILES, required=True,
                    help="whether this service's receipts MUST carry a position "
                         "commitment. 'bound' refuses a receipt without one; 'unbound' "
                         "is the pre-v2 contract, under which tree_size and leaf_index "
                         "are unauthenticated hints a relayer may restate. Required "
                         "because the verifier's own default is the weaker of the two, "
                         "so an omitted field silently pins it.")
    ap.add_argument("--leaf-profile", choices=LEAF_PROFILES, default="statement-bytes",
                    help="which bytes this service's log hashes as the Merkle entry: the "
                         "Signed Statement's own octets (the default) or a digest of "
                         "them. It cannot be inferred from a receipt.")
    return ap


def build_pin(args, kid, fields: dict, uri: str, document_digest: str) -> dict:
    """The pin artifact, exactly as it is written.

    Separated from the fetch so the fields it must carry are assertable without a
    network: a pin that omits `position_profile` or `leaf_profile` deserializes to the
    weaker contract on the Rust side, which is not a difference any later reader of the
    file can see.
    """
    return {
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
        # Written ALWAYS, including for the values that match the verifier's defaults.
        # An absent field and a field set to the default read identically to the
        # verifier and completely differently to a reviewer: one says the operator
        # decided, the other says the tool never asked.
        "leaf_profile": args.leaf_profile,
        "position_profile": args.position_profile,
    }


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    ap = _parser()
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
        decoded = _cbor2().loads(document)
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

    pin = build_pin(args, kid, fields, uri, document_digest)
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
    print(f"  leaf        {pin['leaf_profile']}")
    print(f"  position    {pin['position_profile']}")
    if pin["position_profile"] == "unbound":
        print("\nWARNING: pinned UNBOUND. Receipts from this service are accepted without a")
        print("position commitment, so tree_size and leaf_index stay unauthenticated hints:")
        print("a relayer may restate this receipt at another position and it still verifies.")
        print("Use --position-profile bound for a service whose receipts carry one.")
    print("\nThis records WHICH key was used. It is not a statement that the service is")
    print("trustworthy, that its log is append-only, or that its operator is independent.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
