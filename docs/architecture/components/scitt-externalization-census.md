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

> **The MECHANISM is closed; the CLAIM is not.** `mcp-re-auditor --register-to` implements
> `draft-ietf-scitt-scrapi-11` — submission of the exact Signed Statement, `201` and the
> asynchronous `202`→`204`→`200`, bounded polling, typed refusals, and offline verification
> of the receipt against the submitted statement and the operator's pin before anything is
> reported as registered. It is proved against a hermetic transparency service, including
> over a socket through the shipped binary.
>
> What that does NOT earn is the external-registration interoperability claim. That is one
> live run against a real external SCITT Transparency Service, whose receipt still verifies
> offline against the previously captured pin after network access is removed. Until that
> run happens, the honest statement is *the mechanism exists and interoperates with a
> hermetic peer*.
>
> **That run happened on 2026-09-08** (MCPRE-180), over a SECOND mechanism leaf and against a
> service this project does not operate. The claim it earns is *external Transparency Service
> interoperability*; *SCRAPI interoperability* is still unearned, because the peer that
> answered does not speak SCRAPI. See the resolution section at the end of this document.

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
> the current tree.
>
> **The write-access limitation it left behind is also closed** (MCPRE-179 / #849). The
> retention owner's census — EX-012 in
> [`../review-dispositions.md`](../review-dispositions.md) — found that *which bytes this
> archive holds* and *at what instant this deployment became answerable for them* are two
> authorities that shared one constructor. They no longer do: `RetainedArchive` is the read
> projection, `attest_chain` takes it, and the auditor opens it read-only. An audit runs
> against a read-only mount or a snapshot, and the serving constructor still proves its
> directory writable at startup.

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

G-2 is done. G-1's mechanism is done, and its interoperability claim is EARNED for an
externally operated peer as of 2026-09-08 — but only the one the run reached: see the
resolution section, which keeps *external Transparency Service interoperability* and *SCRAPI
interoperability* apart because only the first was measured.

## Addendum, 2026-09-08: which external service, measured

The live run needs a peer, and the census above did not ask which. Asking it changes the
shape of the remaining work, so the measurement is recorded here rather than discovered
during the run.

**There is no SCRAPI peer available today.** #501's finding 4 surveyed the pre-RFC
ecosystem and none of it speaks `draft-ietf-scitt-scrapi-11`:
`scitt-community/scitt-api-emulator` is archived and expects CWT claims at label 14 (RFC
9597/9943 assign 15); `scitt-ccf-ledger` targets Architecture draft 11; DataTrails
advertises draft 10 and MMRIVER, which RFC 9942's registry does not list.

**The one external Transparency Service this project has actually exchanged bytes with
does not speak SCRAPI either.** `capsule-anchor` (action-state-group, Apache-2.0, commit
`a918ba8`) is a real SCITT Transparency Service and it was run locally for #501. Its
registration contract, recorded in
`mcp-re-conformance/tests/vectors/scitt/interop/capsule-anchor/exchange-metadata.json` and
hash-pinned by that corpus's manifest, differs from SCRAPI on every axis the mechanism leaf
owns:

| | `draft-ietf-scitt-scrapi-11` | capsule-anchor |
|---|---|---|
| path | `POST <base>/entries` | `POST /transparency/register-statement` |
| request | the Signed Statement's octets, `application/cose` | JSON `{"signed_statement_b64": …}` |
| response | `201` + Receipt, or `202` + `Location` | JSON `{entry_hash, leaf_index, tree_size}` — **no receipt at all** |

That is not a path this deployment could configure. A `--registration-path` flag would let
a SCRAPI client reach capsule-anchor by coincidence of shape while calling a different
protocol by SCRAPI's name, which is the laundering the mechanism-leaf boundary exists to
prevent.

**What the measurement says about the boundary is good news.** The semantic capability —
*submit these octets, come back with receipt bytes, and the receipt is not accepted until it
verifies* — is unchanged by any of the differences above. A second leaf fetches the receipt
however that service says to and returns bytes; the verifying layer, the certainty
vocabulary and the artifact do not move. The boundary was drawn in the right place; what it
does not do is make one leaf speak two protocols.

**So the live claim needs a decision, not more code against the current leaf.** Either a
second mechanism leaf for a specific non-SCRAPI service, or a SCRAPI-conforming peer that
does not exist yet in the open-source ecosystem. That is an architecture decision and it is
recorded here unresolved.

The interoperability CLAIM is not licensed by either. It is earned by one live run against a
real external Transparency Service whose receipt still verifies offline, against a previously
captured pin, after network access is removed.

## Resolution, 2026-09-08 (MCPRE-180): the decision was taken, and the addendum was partly stale

The decision above is **resolved: a second mechanism leaf**, and it is built. Two of the
addendum's own findings were re-measured first, and one of them was wrong.

### What re-measuring found

| the addendum said | the measurement |
|---|---|
| capsule-anchor's response carries `{entry_hash, leaf_index, tree_size}` — **no receipt at all** | **Superseded.** Its published OpenAPI makes `receipt_b64` a REQUIRED field of `RegisterStatementResponse`, and a live submission returned one. |
| *(not asked)* | The OPERATED instance uses a leaf rule neither corpus had: `SHA-256(0x00 ‖ SHA-256(Sig_structure))`, which it calls `sig_structure`. `StatementLeafProfile::SigStructureDigest` is that reading, and the pin selects it. |
| the peer was a LOCAL run of open-source code | An instance at `witness.agentactioncapsule.org` that we do not run, configure or restart accepted our exact octets. |

Everything else in the addendum stands, and the boundary it praised held: **no semantic type
above `TransparencyRegistration` changed.** The second leaf is a sibling of the SCRAPI one,
the verifying layer is the same function, and the certainty vocabulary is untouched.

### The three evidence levels, kept apart

An implementation existing, a foreign implementation being exercised, and an externally
OPERATED service being exercised are three different things, and only the third was in
question.

| level | reached |
|---|---|
| implementation exists | yes — DataTrails, Tradeverifyd and Microsoft all ship SCITT/SCRAPI implementations, and capsule-anchor is Apache-2.0 |
| foreign implementation exercised | yes, since #501: capsule-anchor run locally, its receipt verified offline |
| externally operated service exercised | **yes, 2026-09-08**: `witness.agentactioncapsule.org`, end to end through the shipped `mcp-re-auditor` |

The third row is one lane —
`transparency_e2e_test::the_auditor_binary_registers_with_a_live_external_service` — and it is
opt-in (`MCP_RE_LIVE_TRANSPARENCY_SERVICE`, `MCP_RE_LIVE_TRANSPARENCY_PIN`), deliberately off
the merge path, because a red build must never mean somebody else's server is down. With the
variables unset it prints that it MEASURED NOTHING rather than passing quietly. What survives
a run is frozen in `.../interop/capsule-anchor-live/`, verified offline by
`scitt_interop_test` on every build.

### What that earns, exactly

> **external Transparency Service interoperability.**

It does **not** earn *SCRAPI interoperability*. That service does not speak SCRAPI, and only
a run against a SCRAPI peer earns that sentence. `AttestationArtifact` records which contract
answered, so an artifact cannot be read as the stronger claim, and
`mcp-re-conformance/tests/vectors/scitt/interop/capsule-anchor-live/exchange-metadata.json`
says so in the corpus a reader would cite.

### The SCRAPI claim is an ACCESS dependency, not an absence

The remaining gap is a credential, not a missing implementation. DataTrails' SCRAPI surface
is behind an account; that is a thing to obtain, and it is categorically different from "no
peer exists", which is what the addendum's first line read as. A SCRAPI run against any of
the three named implementations would earn the stronger sentence, and nothing in the tree
needs to change for it — `--registration-protocol scrapi-11` is the shipped default.
