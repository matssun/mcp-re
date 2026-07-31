#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SCITT two-direction cross-verification against an independent implementation.

The same no-merge shape as the RFC 9421 and JOSE gates, and it exists because its
absence let a non-conforming receipt encoding ship: the receipt used the
pre-publication draft header labels (`-111`/`-222`) instead of RFC 9942 §5.2.1's `vds`
= 395 and `vdp` = 396, and every test passed. They passed because they ran our encoder
against our own decoder, which agrees with itself whatever labels it picks.

* **ours -> external** (default): every committed vector is decoded, checked against
  the RFC's literal labels, and its signatures verified by third-party code — `cbor2`
  for CBOR, `cryptography` for Ed25519/ECDSA — with the RFC 9052 §4.4 `Sig_structure`
  and the RFC 9162 fold written here from the RFC text.
* **external -> us** (`--emit-external-kat`): this script BUILDS Signed Statements and
  RFC 9942 Receipts independently, for EdDSA and ES256, together with the refusals a
  conforming verifier owes. `scitt_cross_verification_test.rs` then requires the Rust
  verifier to accept the positives and refuse each negative.

Direction 2 is the one that catches a wrong label, and it is the control that was
missing. It includes a receipt built with the draft labels specifically so a regression
to them fails here rather than silently producing bytes only MCP-RE accepts.

    pip install -r mcp-re-conformance/tools/requirements-cross-verify.txt
    python3 mcp-re-conformance/tools/scitt_cross_verify.py
    python3 mcp-re-conformance/tools/scitt_cross_verify.py --emit-external-kat
"""

from __future__ import annotations

import argparse
import base64
import glob
import hashlib
import json
import os
import sys

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CORPUS = os.path.join(REPO, "mcp-re-conformance", "tests", "vectors", "scitt")
EXTERNAL_KAT = os.path.join(CORPUS, "external_kat.json")

# RFC 9942 §5.2.1 / §8.2.2.1
VDS, VDP, INCLUSION_PROOF, RFC9162_SHA256 = 395, 396, -1, 1
# The pre-publication draft labels, present ONLY to be refused.
DRAFT_VDS, DRAFT_VDP = -111, -222
# RFC 9943 §6.1 / RFC 9597
CWT_CLAIMS, CWT_ISS, CWT_SUB, CWT_IAT = 15, 1, 2, 6
# COSE header labels and algorithms (RFC 9052 §3.1, RFC 9053).
HDR_ALG, HDR_CTY, HDR_KID = 1, 3, 4
ALG_ES256, ALG_EDDSA = -7, -8

STATEMENT_SUBJECT = "mcp-re:call-evidence"
STATEMENT_CTY = "application/mcp-re-evidence+cbor"
ISSUER_KID = "external-issuer-1"
TS_KID = "external-ts-1"
ISSUED_AT = 1_700_000_000

# Fixed key material so the emitted KAT is byte-stable and the drift guard means
# something. Test keys; they exist only in this corpus.
ISSUER_SEED = bytes([0x11]) * 32
TS_ED_SEED = bytes([0x22]) * 32
TS_EC_SCALAR = 0x33333333333333333333333333333333333333333333333333333333333333


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sig_structure(protected: bytes, payload: bytes) -> bytes:
    """RFC 9052 §4.4: ["Signature1", protected, external_aad, payload]."""
    return cbor2.dumps(["Signature1", protected, b"", payload])


# ---------------------------------------------------------------------------
# Direction 1 — our committed vectors, read by third-party code.
# ---------------------------------------------------------------------------


def verify_sign1_ed25519(cose: bytes, pubkey: bytes) -> bool:
    tag = cbor2.loads(cose)
    assert tag.tag == 18, f"expected COSE_Sign1 tag 18, got {tag.tag}"
    protected, _unprotected, payload, signature = tag.value
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(
            signature, sig_structure(protected, payload)
        )
        return True
    except InvalidSignature:
        return False


def fold_rfc9162(leaf_bytes: bytes, tree_size: int, leaf_index: int, path: list) -> bytes:
    if leaf_index >= tree_size:
        raise ValueError("leaf_index >= tree_size")
    digest = hashlib.sha256(b"\x00" + leaf_bytes).digest()
    index = leaf_index
    for sibling in path:
        pair = digest + sibling if index % 2 == 0 else sibling + digest
        digest = hashlib.sha256(b"\x01" + pair).digest()
        index >>= 1
    return digest


def cross_verify() -> int:
    failures = []
    for path in sorted(glob.glob(os.path.join(CORPUS, "s0*.json"))):
        vector = json.load(open(path, encoding="utf-8"))
        statement = b64u_decode(vector["statement_cose_b64url"])
        receipt = b64u_decode(vector["receipt_cose_b64url"])
        print(f"\n=== {vector['name']}   (vector expects: {vector['expect']}) ===")

        st = cbor2.loads(statement)
        sprot = cbor2.loads(st.value[0])
        claims = sprot.get(CWT_CLAIMS, {})
        statement_ok = st.tag == 18 and CWT_ISS in claims and CWT_SUB in claims
        print(f"  statement  tag18={st.tag == 18}  CWT_Claims(15) iss={claims.get(CWT_ISS)!r} "
              f"sub={claims.get(CWT_SUB)!r}  -> RFC 9943 §6.1: {statement_ok}")

        rc = cbor2.loads(receipt)
        rprot = cbor2.loads(rc.value[0])
        runprot = rc.value[1]
        vdp = runprot.get(VDP)
        vds_ok = rprot.get(VDS) == RFC9162_SHA256
        # cbor2 decodes CBOR maps to frozendict, which is not a dict subclass.
        vdp_ok = hasattr(vdp, "keys") and INCLUSION_PROOF in vdp
        tree_size = leaf_index = None
        proof_path: list = []
        if vdp_ok:
            tree_size, leaf_index, proof_path = cbor2.loads(vdp[INCLUSION_PROOF][0])
        print(f"  receipt    vds(395)={rprot.get(VDS)}  vdp(396) map with -1: {vdp_ok}  "
              f"tree_size={tree_size} leaf_index={leaf_index} path_len={len(proof_path)}")
        print(f"             draft labels absent: "
              f"{DRAFT_VDS not in rprot and DRAFT_VDP not in runprot}   "
              f"path non-empty ([ + bstr ]): {len(proof_path) > 0}")

        if not (statement_ok and vds_ok and vdp_ok):
            # A structure this verifier cannot read is a REFUSAL, not an inconclusive
            # result: an unknown vds means the proof format is undefined here.
            agree = vector["expect"] != "verify_ok"
            print(f"  ==> independent verdict: reject (unreadable structure)  "
                  f"({'AGREES' if agree else 'DISAGREES'})")
            if not agree:
                failures.append(f"{vector['name']}: expected to verify, structure unreadable")
            continue

        issuer_ok = verify_sign1_ed25519(statement, b64u_decode(vector["issuer_pubkey_b64url"]))
        ts_ok = verify_sign1_ed25519(receipt, b64u_decode(vector["ts_pubkey_b64url"]))
        try:
            derived = fold_rfc9162(statement, tree_size, leaf_index, proof_path)
            inclusion_ok = derived == rc.value[2]
        except ValueError as exc:
            inclusion_ok = False
            print(f"             fold refused: {exc}")
        print(f"  crypto     issuer sig={issuer_ok}  ts sig={ts_ok}  "
              f"inclusion re-derives root={inclusion_ok}")

        verdict = "verify_ok" if (issuer_ok and ts_ok and inclusion_ok) else "verify_fail"
        # The negatives carry mcp-re wire codes; an independent verifier owes only the
        # accept/reject decision, not our error taxonomy.
        agree = (verdict == "verify_ok") == (vector["expect"] == "verify_ok")
        print(f"  ==> independent verdict: {verdict}  ({'AGREES' if agree else 'DISAGREES'})")
        if not agree:
            failures.append(f"{vector['name']}: verdict")

    print("\n" + "=" * 60)
    if failures:
        print(f"MISMATCHES: {failures}")
        return 1
    print("ALL COMMITTED VECTORS AGREE (ours -> external)")
    return 0


# ---------------------------------------------------------------------------
# Direction 2 — artifacts this script builds, which MCP-RE must accept or refuse.
# ---------------------------------------------------------------------------


def build_statement(commitment: dict) -> bytes:
    """An RFC 9943 §6.1 Signed Statement, built here rather than by MCP-RE."""
    payload = cbor2.dumps(commitment, canonical=True)
    protected = cbor2.dumps(
        {
            HDR_ALG: ALG_EDDSA,
            HDR_CTY: STATEMENT_CTY,
            HDR_KID: ISSUER_KID.encode(),
            CWT_CLAIMS: {CWT_ISS: ISSUER_KID, CWT_SUB: STATEMENT_SUBJECT, CWT_IAT: ISSUED_AT},
        },
        canonical=True,
    )
    signature = Ed25519PrivateKey.from_private_bytes(ISSUER_SEED).sign(
        sig_structure(protected, payload)
    )
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, signature]))


def merkle(leaves: list[bytes], target: int) -> tuple[bytes, list[bytes]]:
    """RFC 9162 root and audit path for `target`, duplicating the last node on odd levels."""
    level = [hashlib.sha256(b"\x00" + leaf).digest() for leaf in leaves]
    index, path = target, []
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            if i == index or i + 1 == index:
                path.append(right if index % 2 == 0 else left)
            nxt.append(hashlib.sha256(b"\x01" + left + right).digest())
        index //= 2
        level = nxt
    return level[0], path


def build_receipt(
    statements: list[bytes],
    target: int,
    algorithm: int,
    *,
    vds_label: int = VDS,
    vdp_label: int = VDP,
    vds_value: int = RFC9162_SHA256,
    override_leaf_index: int | None = None,
    corrupt_path: bool = False,
    der_signature: bool = False,
) -> bytes:
    """An RFC 9942 §5.2.1 Receipt of Inclusion, built independently of MCP-RE."""
    root, path = merkle(statements, target)
    if corrupt_path and path:
        tampered = bytearray(path[0])
        tampered[-1] ^= 0x01
        path = [bytes(tampered)] + path[1:]
    leaf_index = target if override_leaf_index is None else override_leaf_index
    proof = cbor2.dumps([len(statements), leaf_index, path])

    protected = cbor2.dumps(
        {HDR_ALG: algorithm, HDR_KID: TS_KID.encode(), vds_label: vds_value}, canonical=True
    )
    unprotected = {vdp_label: {INCLUSION_PROOF: [proof]}}
    signed = sig_structure(protected, root)

    if algorithm == ALG_EDDSA:
        signature = Ed25519PrivateKey.from_private_bytes(TS_ED_SEED).sign(signed)
    else:
        key = ec.derive_private_key(TS_EC_SCALAR, ec.SECP256R1())
        # RFC 6979 deterministic ECDSA. Randomized signing would make the emitted KAT
        # differ on every run, and the drift guard (`git diff --exit-code`) would fail
        # forever — a gate that cannot be satisfied gets disabled, not fixed.
        der = key.sign(signed, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        if der_signature:
            # RFC 9053 §2.1 requires fixed-width r||s; DER must be refused.
            signature = der
        else:
            from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

            r, s = decode_dss_signature(der)
            signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")

    return cbor2.dumps(cbor2.CBORTag(18, [protected, unprotected, root, signature]))


def emit_external_kat() -> int:
    commitment = {
        "request_evidence": "external-request-handle",
        "response_evidence": "external-response-handle",
        "chain_label": "complete",
        "chain_commitment": "external-chain-commitment",
    }
    statement = build_statement(commitment)
    other = build_statement({**commitment, "chain_label": "incomplete:1:MissingContinuation"})
    # Two leaves, so the inclusion path is non-empty as `[ + bstr ]` requires.
    log = [other, statement]
    target = 1

    ec_point = (
        ec.derive_private_key(TS_EC_SCALAR, ec.SECP256R1())
        .public_key()
        .public_numbers()
    )
    ed_ts_public = (
        Ed25519PrivateKey.from_private_bytes(TS_ED_SEED).public_key().public_bytes_raw()
    )
    ed_pin = {
        "schema": "mcp-re-scitt-service-trust-pin/v1",
        "service_identifier": "external-cross-verify",
        "discovery_method": "well-known-scitt-keys",
        "discovery_uri": "https://external.invalid/.well-known/scitt-keys",
        "fetched_at": "2026-07-31T00:00:00Z",
        "kid": TS_KID,
        "algorithm": "EdDSA",
        "public_key": {"x": b64u(ed_ts_public)},
        "public_key_thumbprint": b64u(hashlib.sha256(ed_ts_public).digest()),
        "discovery_document_digest": b64u(hashlib.sha256(b"external-discovery").digest()),
    }
    es_pin = {
        **ed_pin,
        "algorithm": "ES256",
        "public_key": {
            "x": b64u(ec_point.x.to_bytes(32, "big")),
            "y": b64u(ec_point.y.to_bytes(32, "big")),
        },
    }

    def case(name, description, receipt, expect, pin, stmt=statement):
        return {
            "name": name,
            "description": description,
            "statement_cose_b64url": b64u(stmt),
            "receipt_cose_b64url": b64u(receipt),
            "issuer_pubkey_b64url": b64u(
                Ed25519PrivateKey.from_private_bytes(ISSUER_SEED).public_key().public_bytes_raw()
            ),
            "ts_trust_pin": pin,
            "expect": expect,
        }

    cases = [
        case(
            "x01_external_eddsa_receipt",
            "An EdDSA Receipt of Inclusion built by an independent implementation from "
            "RFC 9942 §5.2.1. MCP-RE must accept it.",
            build_receipt(log, target, ALG_EDDSA),
            "verify_ok",
            ed_pin,
        ),
        case(
            "x02_external_es256_receipt",
            "The same receipt signed with ES256 (RFC 6979 deterministic), which is what "
            "a real transparency service signs with. MCP-RE must accept it.",
            build_receipt(log, target, ALG_ES256),
            "verify_ok",
            es_pin,
        ),
        case(
            "x03_draft_era_labels_refused",
            "A receipt using the pre-publication draft labels -111/-222 instead of "
            "vds=395/vdp=396. This is the exact defect that shipped; MCP-RE must refuse it, "
            "so a regression to those labels fails here.",
            build_receipt(log, target, ALG_EDDSA, vds_label=DRAFT_VDS, vdp_label=DRAFT_VDP),
            "verify_fail",
            ed_pin,
        ),
        case(
            "x04_unsupported_vds_refused",
            "A vds naming a structure MCP-RE does not implement. It must be refused, never "
            "walked as if it were RFC9162_SHA256.",
            build_receipt(log, target, ALG_EDDSA, vds_value=99),
            "verify_fail",
            ed_pin,
        ),
        case(
            "x05_forged_inclusion_path_refused",
            "A sibling hash altered in the unprotected path. The service signature stays "
            "valid, so only re-deriving the root refuses it.",
            build_receipt(log, target, ALG_EDDSA, corrupt_path=True),
            "verify_fail",
            ed_pin,
        ),
        case(
            "x06_leaf_index_outside_tree_refused",
            "leaf-index == tree-size. RFC 9942 §5.2 requires failing the proof; the tree-head "
            "signature is untouched.",
            build_receipt(log, target, ALG_EDDSA, override_leaf_index=len(log)),
            "verify_fail",
            ed_pin,
        ),
        case(
            "x07_der_es256_signature_refused",
            "An ES256 signature in ASN.1/DER instead of RFC 9053 §2.1 fixed-width r||s. The "
            "same signature mathematically, a different byte string; it must be refused.",
            build_receipt(log, target, ALG_ES256, der_signature=True),
            "verify_fail",
            es_pin,
        ),
        case(
            "x08_receipt_for_another_statement_refused",
            "A genuine receipt for a different statement in the same log. Both signatures "
            "verify; the proof does not re-derive the root from THIS statement's leaf.",
            build_receipt(log, target, ALG_EDDSA),
            "verify_fail",
            ed_pin,
            stmt=other,
        ),
    ]

    document = {
        "schema": "mcp-re-scitt-external-kat/v1",
        "produced_by": "mcp-re-conformance/tools/scitt_cross_verify.py (cbor2 + cryptography)",
        "profiles": ["RFC 9943 §6.1", "RFC 9942 §5.2.1", "RFC 9162", "RFC 9052 §4.4"],
        "cases": cases,
    }
    with open(EXTERNAL_KAT, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"wrote {len(cases)} externally built cases to {EXTERNAL_KAT}")
    print("  positives:", ", ".join(c["name"] for c in cases if c["expect"] == "verify_ok"))
    print("  refusals: ", ", ".join(c["name"] for c in cases if c["expect"] != "verify_ok"))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--emit-external-kat", action="store_true",
                    help="build the external -> us corpus the Rust verifier consumes")
    args = ap.parse_args()
    return emit_external_kat() if args.emit_external_kat else cross_verify()


if __name__ == "__main__":
    sys.exit(main())
