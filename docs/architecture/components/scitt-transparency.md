<!-- SPDX-License-Identifier: Apache-2.0 -->

# Component Blueprint: SCITT Transparency & Portable Audit Receipts

**Status:** Authority census (ADR-MCPRE-061 §8), MCPRE-139 / issue #575. Investigation only — no code changed by the census.

**Scope split:** this document owns the **target** design for the unit currently at `mcp-re-http-profile/src/scitt.rs`. Current sealed state lives in [`docs/dev/sealed-owners.md`](../../dev/sealed-owners.md) (ADR-061 §13.1). §11 is the diff.

**Measured on `main` @ `0a24acc`.** Every line count below comes from `scripts/module_size_gate.py::production_lines`, not from reading.

## 1. Purpose

Map an MCP call's evidence onto IETF SCITT (RFC 9943) Signed Statements and COSE Receipts (RFC 9942), and verify such a receipt **offline** — so a later auditor can establish that a record about a call was registered on a transparency service, without contacting that service and without trusting it to replay honestly.

## 2. Authority

### Owns

- the **evidence commitment**: which digests a record commits to, and whether it identifies a verified call or merely a submission;
- the **MCP-RE statement type tag**: `iss`/`sub`/content-type agreement that stops another COSE_Sign1 from the same issuer key reading as call evidence;
- the **RFC 9162 inclusion-proof algorithm**, and the honest statement of what it cannot bind;
- the **position commitment** that closes what the fold cannot (C080);
- **COSE algorithm agreement**: the resolved key names the algorithm, never the message;
- the **retained-vs-committed relation**: whether bytes an archivist presents reproduce what a statement committed to;
- the **transparency-service trust pin**: which key an interoperability run verified against, and where it came from.

### Does not own

- the request/response evidence handles themselves (`RequestEvidence`, §7.1 role labels — `evidence-verification`);
- chain reconstruction, its labels, or its submitted-hop digest (`chain.rs`);
- the retained bytes (`mcp-re-proxy/src/retained_evidence.rs` implements the store);
- when a statement is issued for a served call (`mcp-re-proxy/src/transparency.rs`);
- key custody, networking, or discovery — the crate is pure, and the fetch lives in `tools/scitt_fetch_service_key.py`.

## 3. Position in the system

```text
chain::reconstruct_chain ──▶ EvidenceCommitment ──▶ SignedStatement ──▶ (registration)
                                     │                                        │
retained evidence store ─────────────┘                                    Receipt
        │                                                                     │
        └──▶ verify_retained_evidence          verify_receipt_offline ◀───────┘
                                                        ▲
                                        ScittServiceTrustPin (pinned key + profiles)
```

Consumers: `mcp-re-proxy/src/transparency.rs` (issuance, retained verification) and `mcp-re-proxy/src/retained_evidence.rs` (a store implementation). Nothing on the request-serving hot path depends on this unit.

## 4. The twelve questions (ADR-061 §8)

### 1. What single security/control fact does this unit own?

**It does not own one.** The nearest honest single sentence is *"a portable, offline-verifiable record of a call's evidence"* — and stating it requires an `and` at every clause: commitment **and** statement typing **and** Merkle proof **and** position binding **and** COSE algorithm agreement **and** retained-byte correspondence **and** service trust pinning. ADR-061 §8 names an answer that needs an "and" as evidence of a shallow authority boundary, and here the "and" is sevenfold.

### 2. How many independently describable authorities exist inside it?

**Seven**, each with its own proposition, its own failure mode, and (mostly) its own consumers:

| # | authority | proposition | lines |
|---|---|---|---|
| A | **Evidence commitment** | *these digests are what a record about this call commits to, and this is whether it identifies a verified call* | 95–229 (135) |
| B | **SCITT statement type** | *this COSE_Sign1 is an MCP-RE call-evidence statement, attributed to the key that signed it* | 345–553 (209) |
| C | **Receipt wire form** | *these are a well-formed RFC 9942 receipt's fields, and the position tuple is inside the tree it names* | 554–754 (201) |
| D | **RFC 9162 Merkle proof** | *this path folds this leaf to this root at this position* | 755–920 (166) |
| E | **COSE verification** | *this signature is valid under a key whose algorithm the protected header agrees with* | 1014–1163 (150) |
| F | **Retained-evidence correspondence** | *these retained bytes are the ones that statement was made about* | 1164–1350 (187) |
| G | **Service trust pin** | *this is the key an interoperability run verified against, and how it was obtained* | 1351–1470 (120) |

Plus two units that are not authorities: the **wire vocabulary** (230–344, 115 lines — COSE/CWT labels, `position_commitment`, `ReceiptPositionProfile`), which is a shared vocabulary B/C/D read; and `verify_receipt_offline` (921–1013, 93 lines), which is the **composition** of B, C, D, E and the position rule — the only place the seven meet.

**Question 2 decides the outcome, and it has decided it.** Seven authorities in one file is not a size problem that a threshold happened to notice.

### 3. What does it decide?

Whether a statement is an MCP-RE statement (B); whether a proof reaches a root (D); whether a signature is valid under an agreed algorithm (E); whether retained bytes reproduce a commitment (F); whether a receipt's position is authenticated (the composition, under G's pinned profile).

### 4. What does it merely execute?

Signing (`issue_signed_statement` takes an external signer closure — the issuer key never enters the crate); registration (`PrototypeTransparencyService::register` takes a `sign_tree_head` closure); CBOR/COSE encode/decode via `ciborium`/`coset`.

### 5. What does it merely transport?

`Receipt::tree_size` and `Receipt::leaf_index` under an `Unbound` pin — the accessors say so in their own doc comments. The COSE bytes themselves (`to_cose`) are kept verbatim and transported, never re-derived.

### 6. What facts does it reconstruct that another owner already decided?

**One, and it is deliberate and correct.** `verify_retained_evidence` rebuilds the commitment *through `EvidenceCommitment::from_reconstruction`* — the same constructor the issuer used — rather than re-deriving each field. That is the anti-drift shape, not a duplicate authority.

**One that is a real duplication.** `EvidenceDigest::of` computes a plain `SHA-256` + base64url of some bytes. That is the same digest form `RequestEvidence` produces for its role-labelled handles, expressed twice; the doc comment explains that the two are *not* interchangeable, which is exactly why having both spellings in one file is a hazard rather than a convenience.

### 7. What security relationship exists only through call ordering or local variables?

**The position commitment check is ordered, not typed.** `verify_receipt_offline` checks the commitment in step 4, *after* the receipt's signature in step 3, and the comment explains why — before step 3 the protected header is attacker-supplied. The ordering is correct and load-bearing, and nothing in the types enforces it: a future caller that re-implemented the composition could compare the commitment first and report a position mismatch for an unsigned receipt.

**The root is derived, then reused.** `computed` is produced by D and then consumed by E and by the position rule as a local. This is the right relation (never take the root from the caller) held by a local variable rather than by a value that means *this root was derived from the statement under verification*.

### 8. What public interface exists only because tests need it?

**`PrototypeTransparencyService`** — `pub`, re-exported at the crate root (`lib.rs:209`), documented as *"NOT a production ledger"*, and used by exactly three call sites, all of them tests: `scitt_vectors_test.rs` (two) and `transparency_e2e_test.rs` (one). A production crate's public API advertises an in-process Merkle log that nothing in production may use.

**`StatementLeafProfile::StatementDigest`** exists for one named external service (`capsule-anchor`). It is legitimate — a verifier cannot infer the leaf rule — but it is reachable only through a pin, and no shipped pin selects it.

### 9. What branches are unreachable under the current legality model?

`ReceiptPositionProfile::Bound` is never selected by any pin in the tree: the field defaults to `Unbound` and no committed pin artifact sets it. The stronger contract is implemented and tested, and no deployment currently requires it — a gap in configuration, not in the code.

### 10. What facts are represented more than once?

- the Merkle **leaf rule**, in `leaf_hash` (verification) and in `PrototypeTransparencyService::register` (production of test corpora) — the prototype hard-codes `StatementBytes` while the verifier takes a profile, so the two agree only because the prototype is never pinned as `StatementDigest`;
- the **RFC 9162 tree computation**, in `rfc9162_root_from_inclusion_proof` (verify) and `mth_and_path` (build). Two implementations of one structure, kept in agreement by the vector corpus rather than by construction;
- the **digest form**, as noted in question 6.

### 11. What inconsistent values can callers construct?

This is the strongest finding after question 2. **Four types state invariants their representations do not hold.**

| type | claimed | at census | after MCPRE-155 |
|---|---|---|---|
| `EvidenceCommitment` | fields are one reconstruction's outputs (`from_reconstruction`) | all seven fields `pub`; a caller can pair a `complete` label with unrelated handles, or an empty `request_evidence` with a non-empty `chain_commitment` | **CLOSED** — private, two named producers: `from_reconstruction` (derived) and `Deserialize` (a received CLAIM, trusted only after the issuer's COSE_Sign1 verifies) |
| `ResolvedTransparencyService` | *"the two travel together … separating them would let a caller pair a pinned key with a profile nobody pinned"* | all three fields `pub` — a caller can do exactly that | **NOT SEALABLE**, measured rather than asserted — the resolver seam has a second real producer (the prototype log the corpora use). Private fields with two NAMED producers (`pinned`, `stated`) buy legibility, not unconstructibility |
| `CoseVerificationKey::EcdsaP256` | `from_ec2_p256` refuses a point not on the curve | variant fields `pub`; struct-literal construction bypasses the check (**mitigated**: `p256_public_key()` re-checks at verify time, so it fails closed) | **CLOSED** — the payload is a `P256Point` whose representation is the DECODED `VerifyingKey`; the decode is the proof and the re-check is gone |
| `ScittServiceTrustPin` | `verification_key()` refuses an `EdDSA` pin carrying a `y` | all fields `pub`; the illegal pin is constructible and only refused when read | **CLOSED** — private `PinDocument` + `TryFrom`, so the `(algorithm, public_key)` PAIR is checked on the way in and `verification_key` is infallible |

In every case a check existed at one construction site and the type admitted the illegal inhabitant — the R-SEAL shape: *possession does not mean the invariant holds*. `SignedStatement` and `Receipt` were the counter-examples and the model: private representations, `from_cose` the only producer. Three of the four now match them.

### 12. Which test/build/proof lane establishes each claimed property?

See §6. Summary: **36 in-crate unit tests + 21 conformance tests + 8 proxy e2e tests, all in lanes that run in both `cargo test --workspace` and `bazel test //...`**, and **zero theorem-registry entries**.

## 5. Theorem inventory

Registry: [`verification/policy/theorems.toml`](../../../verification/policy/theorems.toml). Referenced, not restated (ADR-061 §12).

**Measured: 0 of 33 registry entries concern this unit.**

| proposition | scope | evidence/unit | status |
|---|---|---|---|
| A verified receipt implies the statement was registered in a tree the pinned service signed | composition | `verify_receipt_offline` + `scitt_vectors_test` | **gap** |
| An MCP-RE statement cannot be attributed to a party other than the key that signed it | local | `iss == kid` in `SignedStatement::from_cose` | **structural, no registry entry** |
| No other COSE_Sign1 from the issuer key reads as call evidence | local | `sub` + content-type type tag | **structural, no registry entry** |
| An unrecognised critical header parameter is refused, never ignored | local | `crit` scan in both `from_cose` | **structural, no registry entry** |
| The algorithm is named by the resolved key, never by the message | local | `verify_cose_sign1_with_payload` alg/key agreement | **structural, no registry entry** |
| A receipt's stated position is authenticated **only** under a `Bound` pin | local | `position_commitment` in the protected header | **structural, no registry entry** — and this is the one whose *scope sentence* matters most |
| Retained bytes that do not reproduce a commitment are refused | relation | `verify_retained_evidence` | **structural, no registry entry** |
| A record with no verified hop binds no retained evidence | relation | `commits_to_verified_evidence` guard | **structural, no registry entry** |

The sixth row is the reason this unit needs registry entries more than most: `Receipt::tree_size`'s doc comment already carries a careful *what this does not establish* clause, and a doc comment is not a lane. THM entries are where a negative scope becomes checkable.

## 6. Test/evidence inventory

| property | test/evidence | lane | negative control |
|---|---|---|---|
| Fold correctness, ambiguity-class enumeration, position binding | 36 unit tests in `scitt.rs` | `cargo test -p mcp-re-http-profile` · `//mcp-re-http-profile:mcp_re_http_profile_test` | forged paths, restated positions, `Bound` pin with no commitment |
| Frozen wire octets (statement + receipt) | `mcp-re-conformance/tests/scitt_vectors_test.rs` — 5 tests + 1 golden writer | `//mcp-re-conformance:scitt_vectors_test` | tampered payload must not verify |
| Interop with `@transmute/cose` (RFC 9942 editor's library) | `scitt_interop_test.rs` — 11 tests + 1 golden writer | `//mcp-re-conformance:scitt_interop_test` | resized/altered receipts refused |
| Third-party cross-verification KAT | `scitt_cross_verification_test.rs` — 4 tests | `//mcp-re-conformance:scitt_cross_verification_test` | every refusal a conforming verifier must make |
| Issuance + retained verification through the serving path | `mcp-re-proxy/tests/integration_async/transparency_e2e_test.rs` — 8 tests | `crate_features = ["async_serve"]` · `//mcp-re-proxy:integration_async_test` | truncated/tampered retained chain refused |

**No vacuous row.** Each lane was executed for this census and reported a non-zero test count. The two `#[ignore]` tests are golden writers that regenerate committed corpora — deliberately not run, and not evidence for any row.

**The gap is not in the tests.** This unit is unusually well tested for its size; what it lacks is a stated theorem inventory and an authority boundary.

## 7. Implementation map

`mcp-re-http-profile/src/scitt.rs` — **1629 production lines**, 3081 total, measured by `scripts/module_size_gate.py::production_lines` on `main` @ `0a24acc`. The largest uncovered unit in the repository. Registered `unreviewed` in `config/module-size-debt.toml`; this census is its investigation.

| lines | region | authority |
|---|---|---|
| 1–94 | module doc + imports | — |
| 95–229 | `EvidenceCommitment`, `label_token` | A |
| 230–344 | COSE/CWT labels, `position_commitment`, `ReceiptPositionProfile` | vocabulary |
| 345–553 | `SignedStatement`, `cwt_claim`, `issue_signed_statement` | B |
| 554–754 | `Receipt`, `as_u64` | C |
| 755–920 | `leaf_hash`, `StatementLeafProfile`, `ResolvedTransparencyService`, `node_hash`, `rfc9162_root_from_inclusion_proof` | D |
| 921–1013 | `verify_receipt_offline` | composition |
| 1014–1163 | `CoseVerificationKey`, `verify_cose_sign1*`, `verify_es256` | E |
| 1164–1350 | `EvidenceDigest`, `RetainedEvidenceStore`, `verify_retained_evidence` | F |
| 1351–1470 | `ScittServiceTrustPin`, `PinnedPublicKey` | G |
| 1471–1629 | `PrototypeTransparencyService`, `mth_and_path` | prototype (test-only consumer) |

## 8. Outcome — decomposition, not a §14 exception

Question 2 answered **seven**, so ADR-061 §5 case A applies. A §14 exception would have to argue that keeping seven authorities in one file makes the security argument *materially clearer*, and the opposite is measurable: F's doc comment has to re-explain A's identity fields, C's accessors have to re-explain D's limits, and the position rule is explained three times in three places because no single unit owns it.

**The proposed split**, in dependency order, each file a named authority:

```text
scitt/commitment.rs      A   EvidenceCommitment + label_token                 ~135
scitt/wire.rs                COSE/CWT labels, position_commitment, profiles   ~115
scitt/statement.rs       B   SignedStatement, issue_signed_statement          ~209
scitt/receipt.rs         C   Receipt parsing                                  ~201
scitt/merkle.rs          D   leaf_hash, node_hash, RFC 9162 fold              ~166
scitt/cose_key.rs        E   CoseVerificationKey, COSE signature verification ~150
scitt/verify.rs              verify_receipt_offline — the composition          ~93
scitt/retained.rs        F   EvidenceDigest, store trait, correspondence      ~187
scitt/trust_pin.rs       G   ScittServiceTrustPin, PinnedPublicKey            ~120
scitt/prototype.rs           PrototypeTransparencyService, mth_and_path       ~159
```

Every file lands under the 200-line threshold except `statement.rs` and `receipt.rs`, which sit at ~200-210 and are then band-1 units to look at on their own terms rather than hidden inside a 1629-line file.

**Sealing work the split enables** (question 11), which is the part worth more than the file boundaries:

1. ~~`EvidenceCommitment`~~ — **DONE (MCPRE-155).** Private fields; the reader path is `Deserialize`, and it is named as a producer rather than pretended away: a received statement is a CLAIM, trusted only once the issuer's COSE_Sign1 verifies over it.
2. ~~`ResolvedTransparencyService`~~ — **ATTEMPTED, and the answer is no (MCPRE-155).** "Constructed only by `ScittServiceTrustPin::resolve`" is not achievable: `verify_receipt_offline` takes the service through a closure seam and the in-process prototype log is a real producer with no pin behind it. Private fields plus two NAMED producers is what the boundary permits.
3. ~~`CoseVerificationKey::EcdsaP256`~~ — **DONE (MCPRE-155),** and better than "the check is owned": the payload is the decoded key, so there is no check left to own.
4. ~~`ScittServiceTrustPin`~~ — **DONE (MCPRE-155),** exactly as sketched.
5. `PrototypeTransparencyService` — move behind a `test-support` feature or into a test-only crate. It is a public production API with three test call sites and a doc comment saying it must never be production. **Still open**, and #657 ruling 4 governs: zero production callers is not a deletion argument, so it must be CLASSIFIED, not removed.

**Follow-up issues, not this one.** ADR-061 orders the campaign; this census recommends and stops.

## 9. Known deviations

| deviation | status |
|---|---|
| Seven authorities in one 1629-line file | **this census's finding**; decomposition proposed above |
| Four types admit inconsistent values (§4 Q11) | recorded; sealing proposed above |
| `PrototypeTransparencyService` is public production API with only test consumers | recorded |
| Two implementations of the RFC 9162 tree (verify / build) | accepted for now — the corpus keeps them in agreement, and an independent build is a real cross-check |
| No theorem-registry entry for any proposition | recorded; §5 is the drafting list |
| `ReceiptPositionProfile::Bound` selected by no shipped pin | recorded — configuration gap, not a code gap |
| No running transparency service; interop is against a library, not a service | pre-existing and documented (#501); an RFC 9942/9943 interoperability CLAIM still waits on it |

## 10. Completion criteria

- [x] All twelve questions answered in writing
- [x] Blueprint committed under `docs/architecture/components/` and linked from the campaign index
- [x] Implementation map measured with `scripts/module_size_gate.py` on a stated SHA (`0a24acc`)
- [x] Theorem inventory distinguishes *in registry* / *structural, no entry* / *gap* — measured as 0 registry entries
- [x] Test/evidence inventory names the exact lane per row; every lane executed and reported non-zero
- [x] Outcome recorded: **decomposition**, with the split and the sealing work it enables
- [x] No code changed
