#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the frozen SCITT corpus with third-party code only — no MCP-RE imports.

A corpus checked solely by the encoder that produced it agrees with itself whatever
labels that encoder picked, so it cannot detect using the wrong ones. This script is
the outside opinion: CBOR from `cbor2`, Ed25519 from `cryptography`, and the RFC 9052
§4.4 `Sig_structure`, the RFC 9942 §5.2.1 header shape and the RFC 9162 fold written
here from the RFC text.

It owes only the accept/reject decision, not MCP-RE's error taxonomy: a vector whose
`expect` is a specific `mcp-re.*` wire code is satisfied here by any refusal.

    pip install cbor2 cryptography
    python tools/scitt_independent_verify.py mcp-re-conformance/tests/vectors/scitt

Deliberately not wired into `scripts/local_gate.sh`: the gate must not acquire a pip
dependency. Run it when the statement or receipt encoding changes.
"""

import base64
import glob
import hashlib
import json
import os
import sys

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

VEC = sys.argv[1]

# RFC 9942 5.2.1
VDS = 395
VDP = 396
INCLUSION_PROOF = -1
RFC9162_SHA256 = 1
# RFC 9943 6.1 / RFC 9597
CWT_CLAIMS = 15


def b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sig_structure(protected_bstr, payload):
    """RFC 9052 4.4: Sig_structure = ["Signature1", protected, external_aad, payload]."""
    return cbor2.dumps(["Signature1", protected_bstr, b"", payload])


def verify_sign1(cose_bytes, pubkey_raw):
    tag = cbor2.loads(cose_bytes)
    assert tag.tag == 18, f"expected COSE_Sign1 tag 18, got {tag.tag}"
    protected_bstr, _unprotected, payload, signature = tag.value
    try:
        Ed25519PublicKey.from_public_bytes(pubkey_raw).verify(
            signature, sig_structure(protected_bstr, payload)
        )
        return True
    except InvalidSignature:
        return False


def fold_rfc9162(leaf_bytes, tree_size, leaf_index, path):
    if leaf_index >= tree_size:
        raise ValueError("leaf_index >= tree_size")
    h = hashlib.sha256(b"\x00" + leaf_bytes).digest()
    idx = leaf_index
    for sib in path:
        h = hashlib.sha256(b"\x01" + (h + sib if idx % 2 == 0 else sib + h)).digest()
        idx >>= 1
    return h


failures = []
for f in sorted(glob.glob(os.path.join(VEC, "s0*.json"))):
    v = json.load(open(f))
    stmt, rcpt = b64u(v["statement_cose_b64url"]), b64u(v["receipt_cose_b64url"])
    print(f"\n=== {v['name']}   (vector expects: {v['expect']}) ===")

    # --- Statement: RFC 9943 6.1 shape --------------------------------------
    st = cbor2.loads(stmt)
    sprot = cbor2.loads(st.value[0])
    claims = sprot.get(CWT_CLAIMS, {})
    ok_stmt_shape = st.tag == 18 and 1 in claims and 2 in claims
    print(f"  statement  tag18={st.tag == 18}  CWT_Claims(15) iss={claims.get(1)!r} "
          f"sub={claims.get(2)!r}  alg={sprot.get(1)}  -> RFC9943 shape: {ok_stmt_shape}")

    # --- Receipt: RFC 9942 5.2.1 shape --------------------------------------
    rc = cbor2.loads(rcpt)
    rprot = cbor2.loads(rc.value[0])
    runprot = rc.value[1]
    vdp = runprot.get(VDP)
    ok_vds = rprot.get(VDS) == RFC9162_SHA256
    # cbor2 decodes CBOR maps to frozendict, which is not a dict subclass.
    ok_vdp = hasattr(vdp, "keys") and INCLUSION_PROOF in vdp
    tree_size = leaf_index = None
    path = []
    if ok_vdp:
        tree_size, leaf_index, path = cbor2.loads(vdp[INCLUSION_PROOF][0])
    print(f"  receipt    vds(395)={rprot.get(VDS)}  vdp(396) is map with -1: {ok_vdp}  "
          f"tree_size={tree_size} leaf_index={leaf_index} path_len={len(path)}")
    print(f"             stale draft labels absent: "
          f"{-111 not in rprot and -222 not in runprot}   "
          f"path non-empty ([ + bstr ]): {len(path) > 0}")

    if not (ok_stmt_shape and ok_vds and ok_vdp):
        # A structure this verifier cannot read is a REFUSAL, not an inconclusive
        # result: an unknown vds means the proof format is undefined here, and the
        # only safe answer is to reject without walking it.
        agree = v["expect"] != "verify_ok"
        print(f"  ==> independent verdict: reject (unreadable structure)  "
              f"({'AGREES' if agree else 'DISAGREES'} with vector)")
        if not agree:
            failures.append(f"{v['name']}: expected to verify but structure is unreadable")
        continue

    # --- Crypto -------------------------------------------------------------
    s_ok = verify_sign1(stmt, b64u(v["issuer_pubkey_b64url"]))
    r_ok = verify_sign1(rcpt, b64u(v["ts_pubkey_b64url"]))
    try:
        derived = fold_rfc9162(stmt, tree_size, leaf_index, path)
        incl_ok = derived == rc.value[2]
    except ValueError as e:
        derived, incl_ok = None, False
        print(f"             fold refused: {e}")
    print(f"  crypto     issuer sig={s_ok}  ts sig={r_ok}  inclusion re-derives root={incl_ok}")

    verdict = "verify_ok" if (s_ok and r_ok and incl_ok) else "verify_fail"
    # The negative vectors carry mcp-re wire codes; an independent verifier only owes
    # the accept/reject decision, not our error taxonomy.
    expected_accept = v["expect"] == "verify_ok"
    agree = (verdict == "verify_ok") == expected_accept
    print(f"  ==> independent verdict: {verdict}  "
          f"({'AGREES' if agree else 'DISAGREES'} with vector)")
    if not agree:
        failures.append(f"{v['name']}: verdict")

print("\n" + "=" * 60)
print("ALL VECTORS AGREE" if not failures else f"MISMATCHES: {failures}")
sys.exit(1 if failures else 0)
