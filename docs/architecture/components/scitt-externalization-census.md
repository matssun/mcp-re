<!-- SPDX-License-Identifier: Apache-2.0 -->

# SCITT externalization census — what is still prototype-only

**Measured on `93d70dc0`, 2026-09-08.** Answers #841 item 4:

> What is genuinely still prototype-only between today's SCITT implementation and a real
> external Transparency Service?

Derived from `mcp-re-http-profile/src/scitt/`, `mcp-re-proxy/src/transparency/`,
`mcp-re-conformance/tests/vectors/scitt/` and `tools/scitt_fetch_service_key.py` as they
stand. Never from #494's or #657's wording — both are stale in opposite directions, which is
the reason this census exists rather than a checklist inherited from them.

A census is dated evidence. Re-measure before implementing from it.

## Method

Every row below is a reachability measurement, not a reading of prose. The question asked of
each capability is: **what non-test caller reaches it, and which lane establishes it?** A
capability with real bytes, a frozen corpus and no non-test caller is *implemented and
unreachable* — which is a different gap from *unimplemented*, and the two want opposite work.

## What is REAL — not a stand-in, measured

| capability | evidence on this tree |
|---|---|
| Signed Statement wire form | Tagged `COSE_Sign1` over CBOR via `coset 0.4` / `ciborium 0.2` (`mcp-re-http-profile/Cargo.toml:21-22`), satisfying RFC 9943 §6.1: CWT claims at RFC 9597 label 15 carrying `iss`/`sub` in the PROTECTED header (`scitt/statement/`, `scitt/wire.rs`) |
| Receipt wire form | Tagged `COSE_Sign1` satisfying RFC 9942 §5.2.1 — `vds` protected, `vdp` → `inclusion-proof` unprotected, RFC 9162 MTH as payload; ATTACHED and DETACHED payload forms both accepted (`scitt/receipt/`, `scitt/offline.rs`) |
| Inclusion proof | RFC 9162 §2.1.3.2 fold consuming leaf index AND tree size (`scitt/merkle.rs`), with a SECOND independent tree implementation in `scitt/prototype/tree.rs` kept deliberately separate as a cross-check |
| Offline verification | `verify_receipt_offline` contacts nobody; the root is DERIVED from the statement under verification, never supplied (`scitt/offline.rs`) |
| Position binding | `mcp-re-position` protected-header commitment over `(profile, log identity, vds, tree_size, leaf_index, root)`, length-delimited (`scitt/wire.rs::position_commitment`) |
| Service trust pinning | `ScittServiceTrustPin` — sealed behind a private `PinDocument` + `TryFrom`, so every inhabitant has had its `(algorithm, public_key)` pair checked (`scitt/trust_pin/`) |
| Key discovery | `tools/scitt_fetch_service_key.py`, SCRAPI `GET /.well-known/scitt-keys` (CBOR COSE_Key Set), with a `--selftest` in local-gate stage 1 |
| Retained/committed split | `verify_retained_evidence` + `RetainedCorrespondence` (`scitt/retained.rs`, `scitt/commitment/correspondence.rs`) |
| Serving-path retention | `--retained-evidence-dir` is a real deployment flag; `serving_capabilities::evidence_retention` opens the store at startup and the serving path fails CLOSED on a retention failure (`transparency/durability.rs`) |
| Frozen corpus | `s01`–`s09`, `external_kat.json`, `interop/` (incl. `capsule-anchor/`) and `retained/`, read by four conformance lanes: `scitt_vectors_test.rs`, `scitt_interop_test.rs`, `scitt_cross_verification_test.rs`, `scitt_retained_corpus_test.rs` |
| Third-party cross-check | `@transmute/cose` (RFC 9942 editor's library) produced a receipt that verifies here and reads receipts produced here — a LIBRARY, not a service |

**Encoding is not the gap.** That was #494's wording and it has been wrong since the COSE
migration.

## What is still prototype-only — three items, and they are not the same kind

### G-1 · No external registration mechanism *(absent)*

`grep -rin scrapi` over the tree returns exactly one hit — a comment in
`tools/scitt_fetch_service_key.py:19` naming the endpoint the key fetcher uses. There is no
Rust registration client, no HTTP submission of a Signed Statement, no receipt polling, and
no typed refusal vocabulary for a registration protocol.

The only producer of a Receipt anywhere in the tree is `PrototypeTransparencyService`, which
is in-process by construction. Everything either side of the registration hop is real; the
hop itself does not exist.

**Kind: unimplemented.** This is the residue #841 predicted and the one item that requires
code rather than a decision.

### G-2 · The auditor half has no entry point *(implemented, unreachable)*

`mcp_re_proxy::transparency::attest_chain` is a `pub` library function with **zero non-test
callers**: its only call sites are five in
`mcp-re-proxy/tests/integration_async/transparency_e2e_test.rs`. The same holds for
`verify_receipt_offline` — every non-re-export caller is a `#[cfg(test)]` module or a
conformance lane. No pin is read from disk by any production path: the only
`ScittServiceTrustPin` deserializations in the tree are in `scitt_interop_test.rs` and
`scitt_cross_verification_test.rs`.

So a deployment can turn retention ON and accumulate evidence it has no shipped way to
attest. The serving half is a product; the auditor half is a library driven from a test
harness.

**Kind: packaging, not mechanism.** The authority exists and is exercised; what is missing is
an artifact an operator can run. This is a precondition for G-1 being usable — a registration
client with nothing to register is not a product step either.

> **Closed.** `mcp-re-auditor` is a shipped executable, exercised as a child process by the
> transparency suite. The measurement above stands as the reason it exists; do not read it as
> the current tree. One limitation it left behind, and it is the retention owner's to decide:
> the auditor needs WRITE access to the archive, because
> `EvidenceRetention::open` proves the directory writable by writing a probe. So it cannot run
> against a read-only mount or a snapshot, and splitting a read-only projection out of that
> authority is a separate slice.

### G-3 · Retained-**store** deployment semantics *(deliberately out of scope, restated)*

`FsRetainedEvidenceStore` is an immutable content-addressed object store over one directory:
`put`/`get` over SHA-256-named blobs, no lifecycle, no expiry, no index, no query, no
cross-replica story. The module says so, and `transparency/mod.rs` states the cost that
follows — a full volume is a total outage, and the store grows without bound by construction.

This is a real deployment gap and it is **not** an interoperability gap. Nothing about
registering with an external service depends on it, and inventing a retention product to
close an interoperability issue would be building the wrong thing.

**Kind: scope boundary, unchanged.** Recorded here so it is not rediscovered as part of G-1.

## The two policy decisions this census sits beside

Both are #841's, both are recorded at the code they govern rather than only here:

* **`PrototypeTransparencyService`** — retained public API with a stated contract
  (`scitt/prototype/mod.rs`). Not feature-gated, not moved to a separate crate, not
  deprecated. Its contract: *an in-process prototype/test-support Transparency Service and
  independent implementation used for conformance/cross-checking; successful use of it is NOT
  evidence that a statement was registered with an external SCITT Transparency Service.*
* **`ReceiptPositionProfile`** — the corrected measurement is that `Bound` **is** already
  selectable, through `tools/scitt_fetch_service_key.py --position-profile` (required when
  cutting a new pin). There is no missing enum or configuration feature. Both variants stay;
  no default-to-`Bound`; no duplicate serving-proxy switch, because the
  `ScittServiceTrustPin` consumed by the auditor owns the receipt-position contract for the
  service it selects. Legacy deserialization keeps the weaker default for pins cut before the
  field existed (`scitt/trust_pin/document.rs`).

## What this census licenses

A v0.18-C product step exists, and it is **G-2 then G-1** in that order: turn the auditor
authority into a runnable artifact, then give it a registration mechanism. G-3 stays out.

G-2 is done; G-1 is what remains.

The interoperability CLAIM is not licensed by either. It is earned by one live run against a
real external Transparency Service whose receipt still verifies offline, against a previously
captured pin, after network access is removed.
