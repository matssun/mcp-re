#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regenerate the frozen cross-language SDK parity oracle.

    sdk/fixtures/parity_vectors.json

Both SDKs bind the SAME audited `mcp-re-client-core`, so the canonical signed preimage
is byte-identical across them by construction. This fixture turns "by construction"
into a gate: the bytes are frozen here, and `test_parity.py` (Python) and
`parity.test.ts` (TypeScript) each assert against them. Either binding drifting from
the other — or from the core — fails a test instead of shipping.

Ed25519 is deterministic and every input below is fixed, so freezing bytes is honest.

Run from the repo root, against an INSTALLED wheel:

    python -m venv /tmp/pv && /tmp/pv/bin/pip install maturin
    (cd sdk/python && maturin build --release --out /tmp/pv/dist)
    /tmp/pv/bin/pip install /tmp/pv/dist/*.whl
    /tmp/pv/bin/python tools/gen_sdk_parity_fixture.py
"""
import base64
import json
import pathlib

import mcp_re_sdk
from mcp_re_sdk import (
    AuthzSystemReferenceProvider,
    BindingRequestContext,
    OpaqueBytesProvider,
    Signer,
    SigningDevice,
)

# Fixed, documented TEST-ONLY seed; the corpus is deterministic end-to-end.
SEED = bytes(range(32))
SIGNER_ID = "did:example:client"
KEY_ID = "key-1"
#: A fixed TEST-ONLY authorization artifact the core digests into a binding.
ARTIFACT_MATERIAL = b"pdp-decision-document-v1"

OUT = pathlib.Path("sdk/fixtures/parity_vectors.json")

BASE = dict(
    id_json="1",
    method="tools/list",
    params_json="{}",
    target_uri="https://proxy.internal:8600/mcp",
    audience_id="did:example:server-1",
    route=None,
    dpop_token="dpop-token",
    nonce="nonce-parity-0001",
    created=1700000000,
    expires=1700000300,
)


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def case(signed, inputs) -> dict:
    return {
        "inputs": inputs,
        "expected": {
            "method": signed.method,
            "target_uri": signed.target_uri,
            "headers": [list(h) for h in signed.headers],
            "body_b64": b64(signed.body()),
            "evidence_digest_alg": signed.evidence_digest_alg,
            "evidence_digest_value": signed.evidence_digest_value,
        },
    }


def build() -> dict:
    cases = {}
    meta = {"seed_b64": b64(SEED), "key_id": KEY_ID}

    # An ordinary software-custody request.
    cases["software_tools_list"] = case(
        mcp_re_sdk.sign_request(SEED, KEY_ID, **BASE), {**BASE, **meta}
    )

    # A routed tools/call with non-empty params and a string JSON-RPC id.
    routed = dict(
        BASE,
        params_json='{"name":"read_file","arguments":{"path":"/etc/hosts"}}',
        method="tools/call",
        route="route-a",
        id_json='"req-7"',
        nonce="nonce-parity-0002",
    )
    cases["software_tools_call_routed"] = case(
        mcp_re_sdk.sign_request(SEED, KEY_ID, **routed), {**routed, **meta}
    )

    # Non-exporting custody MUST equal software custody byte-for-byte: the key moved
    # behind a device, the signed preimage did not change.
    ne = Signer.from_device(SIGNER_ID, KEY_ID, SigningDevice.from_seed(SEED))
    cases["non_exporting_tools_list"] = case(ne.sign_request(**BASE), {**BASE, **meta})

    # An ADR-MCPS-047 MRTR answer leg carrying a signed continuation.
    cont = dict(
        BASE,
        nonce="nonce-parity-0003",
        cont_prev_alg="sha-256",
        cont_prev_value="cHJldi1oYW5kbGU",
        cont_irr_alg="sha-256",
        cont_irr_value="aXJyLWhhbmRsZQ",
        cont_request_state="opaque-state-xyz",
    )
    cases["continuation_answer_leg"] = case(
        mcp_re_sdk.sign_request(SEED, KEY_ID, **cont), {**cont, **meta}
    )

    # Provider-supplied artifact bindings: the core digests the artifact, so both SDKs
    # must land on the same digest AND the same evidence bytes.
    ctx = BindingRequestContext(
        audience_id=BASE["audience_id"],
        target_uri=BASE["target_uri"],
        method=BASE["method"],
    )
    opaque = OpaqueBytesProvider("pdp-decision", ARTIFACT_MATERIAL)
    opaque_args = dict(BASE, nonce="nonce-parity-0004")
    cases["binding_opaque_bytes"] = case(
        mcp_re_sdk.sign_request(
            SEED, KEY_ID, **opaque_args, bindings_json=json.dumps([opaque.spec(ctx)])
        ),
        {**opaque_args, **meta, "bindings_json": json.dumps([opaque.spec(ctx)])},
    )

    reference = AuthzSystemReferenceProvider(
        "pdp-decision",
        ARTIFACT_MATERIAL,
        authorization_system_id="authz-1",
        reference_scheme_id="scheme-1",
        reference_value="grant-123",
    )
    ref_args = dict(BASE, nonce="nonce-parity-0005")
    cases["binding_authz_system_reference"] = case(
        mcp_re_sdk.sign_request(
            SEED, KEY_ID, **ref_args, bindings_json=json.dumps([reference.spec(ctx)])
        ),
        {**ref_args, **meta, "bindings_json": json.dumps([reference.spec(ctx)])},
    )

    return {
        "schema": "mcp-re-sdk-parity/v1",
        "comment": (
            "Frozen cross-language parity oracle. Both SDKs bind the same audited "
            "mcp-re-client-core, so every byte below MUST reproduce identically in "
            "Python and TypeScript. Regenerate: tools/gen_sdk_parity_fixture.py"
        ),
        "profile_tag": mcp_re_sdk.profile_tag(),
        "cases": cases,
    }


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w") as f:
        json.dump(build(), f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
