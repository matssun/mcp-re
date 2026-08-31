<!-- SPDX-License-Identifier: Apache-2.0 -->

# Theorem-architecture ratification — 2026-08-31

**The owner's decision on `theorem-architecture-2026-08-31.md`, under ADR-MCPRE-059 §28.13.**

The proposal packet is ratified **subject to the corrections recorded here**. Where this
record and the proposal disagree, this record governs; the proposal stays as the reasoning
that produced it and is not edited to match, so the corrections remain visible as
corrections.

This is the ratification event §28 requires. It is not an inference from the proposal's
own recommendations, and it is what authorizes permanent `THM` allocation for the roots and
children named below.

---

## 1. What was ratified

The six-root decomposition, with the wording of R1, R2, R4 and R6 corrected, R5 split into a
family of independently owned roots, and every structural leaf re-run under the strict
§28.6 test.

Four decomposition decisions are ratified unchanged:

- `R1.1.5` stays a distinct node and is **not** folded into THM-0015. THM-0015 characterises
  a successful `verify_request`; possession by the pipeline is a different proposition and
  the missing joint is real.
- **R1 and R6 stay separate.** They are two safety implications, never a biconditional.
- **R2 and R3 stay separate.** A deployment may run either side alone, and producer
  attribution and consumer acceptance are different security propositions.
- Existing `THM`s attach only to the lowest node they honestly establish. Nothing is
  broadened to close a parent.

---

## 2. The ratified root propositions

Temporary handles (`R1` …) still name nodes; permanent `THM` ids are allocated in Stage 2
against these statements.

### R1 — No unearned dispatch

> If the serving path invokes the backend for an inbound request, every pre-dispatch
> security obligation selected by the validated deployment was first established by its
> owning authority from the inputs that obligation is defined to consult — request/exchange
> evidence and, where required, authoritative validated/materialized state — and the
> downstream pipeline consumed the earned product of that establishment for the same
> relevant request, actor, subject and exchange.

```text
backend dispatch
    ⇒ selected obligations established
    ∧ by their declared authorities
    ∧ over the correct inputs/state
    ∧ pipeline consumed those earned products
```

**Correction against the proposal.** The proposal's "from evidence that request itself
carried" is withdrawn. Several pre-dispatch obligations are defined over authoritative
validated or materialized state — admission currency against the enforcement point's state,
actor resolution through the materialized trust authority — and request-carried evidence may
not stand in for them. The obligation's own definition names its inputs; R1 quantifies over
that, not over the request.

### R2 — No unearned response attribution

> Whenever MCP-RE emits signed response or refusal evidence, the signature is produced by
> the response-signing capability materialized for that deployment under the supported
> delegation model; bound evidence is bound to the exact request it answers, and evidence
> produced before a request can be established is explicitly unbound and cannot be
> interpreted as bound.

**Correction against the proposal.** The proposal quantified over *every response MCP-RE
emits*. That is false as stated: unsigned transport and error responses exist and are
outside the signing claim. R2 is scoped to **security-bearing signed response or refusal
evidence**. Direct-root response signing remains unsupported.

### R3 — A client accepts only an answer to its own request, under a signer it trusts

Ratified as proposed. Kept as a separate client-side root.

### R4 — No deployment serves a posture nobody selected

> Every security capability held by the serving runtime is derived from validated semantic
> owner state. Illegal, unsupported or internally contradictory deployment postures cannot
> be silently reinterpreted into a weaker posture during materialization or serving.

**Correction against the proposal.** R4 is about **security posture**, not liveness or
permanent runtime availability. A runtime dependency may later fail and cause refusal or
loss of availability; that does not violate R4. What R4 forbids is a *silent weakening* of
the selected security policy.

### R5 — the accountability family (not one theorem)

R5 is **a family of roots, not a single synthetic claim.** The proposal's umbrella —
"every accountability artifact corresponds to work performed" — is not allocated a `THM`,
because no real semantic composition authority owns that conjunction, and none is invented
to make an elegant umbrella possible. In particular no `accountability.system` or
`system.accountability` unit is created.

The permanent root set instead contains the independently owned accountability promises,
separated at minimum as:

| root | proposition | authority family |
|---|---|---|
| **R5a** | lifecycle / state-record correspondence — a recorded terminal state implies the path that reaches it | `proxy.runtime_lifecycle` |
| **R5b** | SCITT / retained-evidence correspondence — a verified receipt proves registration, and retained evidence is what the statement committed to | `http_profile.scitt_*` |
| **R5c** | audit-vocabulary / audit-event totality — the vocabulary is total over the outcomes that occur | refusal/audit authorities (open; §A-5) |

Composition of two of these into one claim is permitted **only if measurement discovers a
genuine composition authority that owns the conjunction.** Prose grouping is not such a
discovery.

### R6 — Refusal is terminal and total

> If an inbound exchange fails to establish a required pre-dispatch obligation, it reaches a
> declared refusal terminal — or a declared pre-exchange transport refusal — before backend
> dispatch. It cannot fall through into a success-path dispatch or success response. Any
> refusal-side effects, including signed refusal evidence, audit/retention, cleanup or
> continuation retirement, must themselves be explicitly authorized by the refusal/lifecycle
> state and must not be readable as success.

```text
failed pre-dispatch establishment
    ⇒ no backend dispatch
    ∧ no success-path effect
```

**Correction against the proposal.** "no signed response, and no partial effect" is
withdrawn as materially too strong. The serving architecture emits signed *refusal*
evidence and performs legitimate refusal-side effects — audit, retention, cleanup,
continuation retirement. R6 forbids a *success-path* effect, not any effect at all.

---

## 3. Strict reclassification of the structural leaves

Every `S-n` re-run under the §28.6 / ADR-MCPRE-061 §11 test, applied literally:

> Delete the check, gate, or construction-site convention. Can the contradictory semantic
> state still be constructed, or can the invalid path still execute?

A source-text gate may be *evidence for* a theorem. It is not unconstructibility. A
construction-site convention may be *evidence for* a theorem. It is not unconstructibility.

| id | proposition | verdict | why |
|---|---|---|---|
| S-1 | serving derives transport identity only from the credential the mechanism accepted | **NOT STRUCTURAL** | held by `scripts/serving_identity_provenance_gate.py`, a gate over source text. Delete it and a second identity source compiles |
| S-2 | a stage cannot omit the event it justifies | **STRUCTURAL** | `Established<T>` has a private `value` field and `ExchangeProgress::establish` is its only opener. Delete `#[must_use]` and the stage's result is *still* unreachable without advancing the machine — the value and the transition arrive together |
| S-3 | no deployment can express direct-root response signing | **STRUCTURAL** | `config_state::delegated_signing` records "no state to choose and no enum to classify into": the mode has no representation. Nothing to delete |
| S-4 | response signing and TLS handshake signing use different KMS keys | **NOT STRUCTURAL** | held by `cli.rs::build_key_source`, a construction site, as the KMS blueprint already records. Delete the site's pairing discipline and the contradictory state is constructible |
| S-5 | the response expectation's handle is derived from the request | **NOT STRUCTURAL** | `ResponseExpectation::new(HttpRequest)` is `pub` and in-process. The proposal's "the wrong pairing is unconstructible in-process" is false; `for_signed` is the preferred constructor, which is a convention |
| S-6 | an illegal cross-owner combination is refused at layer A | **NOT STRUCTURAL** | `cross_machine::validate` returns violations and a caller refuses. Delete it and the combination is still representable in `DeploymentRequest` |
| S-7 | a refusal reason has one authority | **NOT STRUCTURAL** | held by `scripts/refusal_provenance_gate.py` and a drift guard. The representation does not make a second vocabulary impossible; a strong gate is still a gate |
| S-8 | fail-closed revocation is a property of the verifier type | **NOT STRUCTURAL** | the value is `Arc<dyn rustls::…::ClientCertVerifier>`, a foreign trait object that plainly admits permissive implementations — the test module contains one. `build_client_verifier` takes no permissive argument, which is a property of that construction site, not of the type |
| S-9 | possession of a `TransportBinding` implies a recognised mode | **STRUCTURAL** | private representation, one `pub(crate)` constructor `exact_match()` taking no arguments, one recognised mode. No inhabitant denotes an unrecognised mode |

**Three survive: S-2, S-3, S-9.** The other six become propositions their parents require —
each with the deleted "structural" terminal replaced by a proved/evidenced claim or a `GAP`:

| was | becomes | parent |
|---|---|---|
| S-1 | composition/provenance proposition: serving resolves transport identity only through the authenticated-relationship authority. The source-text gate is *evidence*, not the terminal | R1 (R1.2.2) |
| S-4 | **moved out from under R2.2.** Role separation is not logically required for response *attribution*; it is deployment/capability-role integrity. It becomes a conditional R4 proposition: *a validated deployment cannot collapse semantically distinct signing roles where the selected roles and mechanisms require them distinct* | R4 |
| S-5 | **refined at Stage 4 to OUT_OF_SCOPE, not a proposition.** `ResponseExpectation::new` is public because the FFI bindings rebuild the request from scalars, and any caller that can reach it is the caller whose bug a wrong pairing is. Sealing past that seam is theatre, so this is a caller obligation — the disposition O-4 already gave the FFI half, applied honestly to the in-process half rather than claimed away | R3 (no theorem) |
| S-6 | proposition over the layer-A classifier: every illegal cross-owner combination is refused. Evidenced, not structural | R4 (R4.7) |
| S-7 | proposition over the refusal authority: refusal causes have one vocabulary. The drift gate is evidence | R6 (R6.4) |
| S-8 | proposition over the listener-state authority: every production listener obtains a verifier that denies unknown revocation status. Folds into GAP-11's owner | R2.5 / R4 |

---

## 4. Owner-altitude normalization of the GAPs

Re-run under the §28.1 question — *which semantic authority owns the missing proposition
itself?* — never *which existing unit mentions one of the values in it*.

The proposal's §7a list is **not** adopted mechanically. Four of its seven rows were at the
wrong altitude.

| gap | proposal's owner | ratified owner | ruling |
|---|---|---|---|
| GAP-1 · keyid injectivity | `http_profile.keyid` | **unchanged** | distinct keys have distinct keyids is a property of the derivation. Correct altitude |
| GAP-2 · R1.1.5 | `http_profile.verifier_result_separation` | **SPLIT** | that unit owns result-type non-substitutability (**GAP-2a**, registrable now). It does **not** own *the serving pipeline holds the product produced by the verifier invocation for this exchange* (**GAP-2b**) — a serving/composition provenance proposition. GAP-2b goes to the exchange/serving composition authority created in Stage 1. Do not stretch the verifier unit across the caller boundary |
| GAP-3 · admission-assertion authenticity | `http_profile.admission_currency` | **unchanged**, but see §5 | the proposition is about the assertion the currency owner consumes |
| GAP-4 · R1.4.3 | `proxy.pdp_decision_relation` | **MOVED** | that unit owns `decision ↔ verified actor/action/target`. *The authorization stage executes on every path reaching dispatch* is pipeline unbypassability and belongs to the exchange/serving composition authority. THM-0040 remains the authorization-relation child |
| GAP-11 · listener state provenance | `proxy.tls_listener_state` | **unchanged**, widened | that unit's own description is already a composition proposition — "every MCP-RE construction path obtains … through one `TlsListenerSecurityState`". Correct altitude. Reclassified S-8 folds in here |
| GAP-18 · non-trust owners of the composition root | "a per-owner sibling is needed" | **DEFERRED to measurement** | do not clone THM-0038 once per owner because it is easy. Stage 6 first determines whether one real composition authority owns *materialization/serving consumes owner projections and does not re-read raw security semantics from `DeploymentRequest`*. If one exists, use it; if the composition is genuinely distributed by owner, use owner-specific relation units. Semantic ownership decides |
| GAP-19 · pinned transparency service | `http_profile.scitt_receipt_offline` | **SPLIT** | that unit owns *the receipt verifies under THIS supplied/resolved service* — which it already establishes. *THIS supplied service is the service THIS deployment pinned* is deployment composition and is not within the offline verifier's authority. It goes to the deployment-composition stage (Stage 6) |

**Registrable in Stage 2 with no new authority:** GAP-1, GAP-2a, GAP-3, GAP-11.
**Moved to the Stage 1 exchange/serving composition authority:** GAP-2b, GAP-4, GAP-5, GAP-21.
**Deferred to deployment composition (Stage 6):** GAP-18, GAP-19b, A-1.

---

## 5. Internal assumptions

### ASM-0012 — `ASSUMED` → `GAP`

Confirmed for root-architecture purposes. An assumption stating that MCP-RE's *own*
admission-assertion verifier performs the security work is not an acceptable final terminal
when that proposition is load-bearing to R1. It may remain as a Verus proof-cone device
while the real obligation is discharged; it may not close R1.3.1.

### ASM-0019 / ASM-0021 — the stronger rule

They are **not** reclassified merely because they are our code. The rule applied is:

> A load-bearing assumption over MCP-RE-owned code may not close a COMPLETE system root by
> default.

So: if a ratified root ultimately depends on the behaviour ASM-0019 (`ArtifactBinding::validate`
is opaque) or ASM-0021 (`actor_id` accessors have no `ensures`) asserts, the corresponding
proposition is classified `GAP` and discharged structurally, formally or conventionally — or
an explicit owner-ratified TCB exception is obtained. If the assumption disappears as a
proof-engineering detail once another theorem establishes the proposition, it needs no
independent `THM`.

Performing this classification needs no human stop.

---

## 6. Architecture-gap dispositions

| id | disposition |
|---|---|
| **A-1** materialized trust resolver wiring | **ACCEPTED** as a genuine missing composition authority and proposition. No owner is faked. Resolved when its closure stage (Stage 6) arrives |
| **A-2** exchange machine | **RECLASSIFIED — not fundamentally an architecture gap.** The authority already exists in `exchange_state.rs`. What is missing is review/theorem coverage over a real authority and its serving correspondence. Create the smallest honest review unit(s) to measure legal exchange-state reachability to dispatch, refusal coverage, and work/event correspondence. **Do not refactor the exchange machine merely to create a unit.** A-2 remains the first review-unit-creation move because it closes multiple high-level branches |
| **A-3** client-side propositions | **ACCEPTED AS A CLUSTER, NOT AS ONE OWNER.** No `unit://client_core` over a whole crate. Crate boundaries do not determine review-unit boundaries. The six propositions — signer expectation, anchor lifecycle, bound/unbound fallback, preflight evidence, skew relation, execution/retry semantics — are partitioned by the existing semantic owners (`response_expectation.rs`, `trust_manifest/`, `delegated_trust/`, `response.rs`, `delegated_evidence.rs`, `execution_contract.rs`, `result_classification.rs`). One unit is created only where one real authority genuinely owns several. A proposition crossing those owners with no composition authority is itself an architecture gap |
| **A-4** response emission | **ACCEPTED AS A CLUSTER, NOT AS ONE MONOLITH.** No single "response emission" authority absorbing delegation-only signing, custody provenance, request binding and non-exporting custody. The emission composition may own *the relationship between the response and the signer capability it consumes*; custody remains owned by custody; request binding remains its own relation. The non-exporting guarantee is **conditional on a deployment selecting non-exporting custody** and uses the existing `PrivateKeyExposure::NonExporting` vocabulary where that is the owner. `KeySource` is not redesigned because an older KMS census predates ADR-MCPRE-067 — **measure current `main` first** |
| **A-5** audit totality | **ACCEPTED** as an architecture/exception-channel decision. The vocabulary is frozen by ADR-MCPS-035 and the current representation does not establish the required totality. ADR-MCPS-035 is not bypassed to close the theorem tree |

---

## 7. Root ownership before permanent ids

Before a permanent root `THM` is allocated, that root is mapped to a **real** semantic
composition review unit. A root theorem **may** be owned by a relation/composition unit
spanning multiple source files where the relation actually exists. It **may not** be owned
by a synthetic "system" unit invented for the registry.

Expected semantic locations, subject to measurement:

```text
R1 / R6   → exchange / serving composition
R2        → response-emission composition
R3        → client response-verification composition
R4        → validated-deployment → materialized-runtime composition
R5a/b/c   → their respective lifecycle / transparency / audit authorities
```

A required root that cannot be mapped to a real authority is an **architecture gap** and its
`THM` is not allocated.

---

## 8. Ratified closure order

The proposal's "register seven existing-owner gaps" step is **not** used mechanically.

```text
Stage 0  incorporate this ratification; normalize root wording; split R5;
         reclassify S-1…S-9; owner-altitude normalization over every GAP
Stage 1  create review units for REAL existing authorities that merely lack
         measurement — the exchange machine first
Stage 2  register the ratified root/child propositions that now have honest owners;
         declare `root_theorems` once the complete ratified root set has resolvable
         THM identities
Stage 3  discharge owned leaf/relation gaps bottom-up
Stage 4  close client-side semantic-owner gaps
Stage 5  close response-emission / custody composition gaps
Stage 6  close materialized-resolver / deployment-composition gaps
Stage 7  audit-totality exception-channel work
Stage 8  compose the system roots; run T6's whole-system adversarial missing-edge pass
```

Within a stage, dependency order decides implementation order. Theorem count is not an
objective.

---

## 9. Authorization

This record is the human theorem-architecture decision under §28.13. It carries standing
authority to execute the bottom-up closure campaign: allocate permanent `THM` ids for
approved propositions that have a real owner, create review units over existing real
semantic authorities, add and repair evidence and mutation probes, discharge internal
proof-cone assumptions, make local structural changes already implied by this architecture,
repair generated views and fingerprints, re-attest affected units, and compose established
children into parent claims.

It does **not** authorize: inventing a synthetic owner, bypassing ADR-MCPS-035, replacing a
theorem identity, changing root scope, adding a trusted external assumption, or choosing
between materially plausible production designs. Those are §28's semantic stop conditions.

---

## 10. Closure outcome — recorded 2026-08-31

The campaign this record authorized ran to Stage 8. What follows is the state it left, and
it is a record of measurement, not a claim of completeness.

### The permanent root set, and its owners

Nine roots, because R5 is a family. Every one is owned by a real composition review unit;
none is owned by a synthetic "system" unit.

| root | proposition | owner | established |
|---|---|---|---|
| THM-0074 | R1 — no unearned dispatch | `proxy.dispatch_commitment` | no |
| THM-0078 | R6 — refusal is terminal, and no refusal-side effect reads as success | `proxy.exchange_lifecycle` | no |
| THM-0075 | R2 — no unearned response attribution | `proxy.response_signing` | no |
| THM-0076 | R3 — a client accepts only an answer to its own request | `client.response_acceptance` | no |
| THM-0077 | R4 — no deployment serves a posture nobody selected | `proxy.trust_composition_root` | no |
| THM-0012 | R5a — the lifecycle record cannot claim a shutdown that did not happen | `proxy.runtime_lifecycle` | **yes** |
| THM-0072 | R5b-i — a verified receipt proves registration on the pinned service | `http_profile.scitt_receipt_offline` | no |
| THM-0042 | R5b-ii — retained evidence is the evidence the statement was made about | `http_profile.scitt_retained_correspondence` | **yes** |
| THM-0071 | R5c — the refusal vocabulary is total over the outcomes that occur | `proxy.audit_record_coordinates` (provisional) | no |

**Root completeness: INCOMPLETE, 2 of 9.** That is the truthful state of a campaign in
progress. The dominant blocker is not architecture: 40 of the theorems allocated by this
campaign carry no owner specification review, because the ratification was of the
ARCHITECTURE and not of these statements, and a review record inferred from it would record
an event that did not happen.

### What remains open

Eight claims are `GAP` terminals — a ratified proposition, a real owner, no support closure.

| id | proposition | what is missing |
|---|---|---|
| THM-0050 | keyid selector injectivity | one primitive property: SHA-256 collision resistance over the canonical JWK form. **An owner TCB decision**, because ASM-0023's justification records that this project has deliberately declined to assume the digest construction's separation properties |
| THM-0053 | the admission assertion is authentic, in-window, for this audience | ASM-0012 stands in its place inside the proof cone; discharging it is proof work over MCP-RE's own verifier |
| THM-0054 | every production listener denies unknown revocation status | a sole-producer gate over `build_client_verifier`, and a handshake control against an undeterminable status |
| THM-0071 | audit-vocabulary totality | an **ADR-MCPS-035 decision**. Two frozen taxonomies in two crates; the record now keeps their coordinates apart, which is what makes totality answerable, and does not make the union total |
| THM-0073 | signing roles policy requires distinct are not collapsed | held by a construction site (`cli.rs::build_key_source`), so it fails the deletion test; relocated out from under R2 to R4, conditional on the selected roles |
| THM-0080 | serving derives peer identity only from the accepted credential | reclassified out of S-1. Gate and handshake controls exist; no `[[unit]]` binds them, and the controls sit in a feature-gated lane whose selection must be established first |
| THM-0081 | every production refusal is inside the exchange lifecycle | a site-totality clause in the refusal-provenance gate |
| THM-0082 | the serving path signs under the credential source materialization produced | the composition controls `serving_trust_seam_test` writes for the resolver, written for the signer |

Three of the eight are decisions rather than work: THM-0050 (a TCB assumption), THM-0071 (an
ADR amendment), and THM-0073 (whether to seal the role separation or accept the site).

### Structural leaves after strict reclassification

**Three survive: S-2, S-3, S-9** (§3). Six were reclassified, and each became a proposition
or a disposition rather than disappearing: S-1 → THM-0080, S-4 → THM-0073, S-6 → THM-0049,
S-7 → THM-0046, S-8 → THM-0054, and S-5 → OUT_OF_SCOPE as a caller obligation.

### Assumptions

34 registered, unchanged. **No new trusted external assumption was allocated**, which is a
§28 stop condition — THM-0050's residue is recorded and left for the owner rather than
closed by an ASM this campaign wrote for itself. ASM-0012 remains a proof-cone device and no
longer closes a root: THM-0053 is registered as the gap it stands in for.

### Architecture changes made

None to production semantics. What changed:

- `scripts/serving_product_provenance_gate.py` — new, self-tested, wired into the local gate
  and CI;
- clause 10 of `scripts/authorization_provenance_gate.py` — the posture that claims nothing
  has one producer;
- `scripts/check-assumptions` — `assume`/`admit` no longer match a method call, with the
  test pinning both directions;
- `mcp-re-proxy/tests/integration/serving_trust_seam_test.rs` — new controls over the
  composition of the serving trust seam;
- `mcp-re-http-profile/src/keyid.rs` — three controls for the injectivity halves that are
  ours;
- `tools/verification/check-assumptions` — the PRODUCTION scan now reads the shipped half
  only. Its mechanism list exists because the bare words are ordinary Rust, and a test
  region is where ordinary Rust is densest: `replay.rs` has a helper `fn admit(..)`, and
  Verus' `admit()` deletes a proof obligation. A region that ships in no binary cannot
  weaken a proof about one;
- path filters in `.github/workflows/verification.yml` for every new fingerprint input.

### The missing-edge pass

Four edges the proposal packet's tree did not have, found by asking of each root what it
requires rather than by reading the registry upward:

1. **replay admission** — a pre-dispatch obligation R1 quantifies over, with no node at all.
   Closed: `http_profile.replay_key` and THM-0079.
2. **serving identity provenance** — THM-0080, open.
3. **the materialized signer** — THM-0082, open. The counterpart of THM-0066 on the signing
   side, and the same defect shape.
4. **refusal-site totality** — THM-0081, open.

### Census

50 review units · 81 theorems (41 established) · 88 mutation probes · 34 assumptions ·
9 declared roots (2 established). `VERIFICATION: PASS` across every required lane.

The 40 unestablished theorems are dominated by one axis and it is not architecture: every
claim this campaign allocated reports `SPECIFICATION REVIEW UNREVIEWED`. That is correct.
The ratification was of the architecture, not of these statements, and a review record
written from it would record an event that did not happen.
