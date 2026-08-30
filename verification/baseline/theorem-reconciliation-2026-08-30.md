# Theorem reconciliation — 2026-08-30

Measured against `main` at `cf09ad6`, immediately after MCPRE-176 merged and systematic
theorem work was unfrozen.

**This is an inventory, not a repair.** No theorem statement was edited. The tooling can
already measure the current tree — `verify --gate` is PASS, no manifest path is dead, no
`supported_by` names an unknown unit — so the exception permitting a mechanical
source-path update was not needed and not used.

Registry: **37 theorems** (THM-0001 … THM-0038; **THM-0011 was never issued** — it has no
history in `theorems.toml` and is a skipped identifier, not a withdrawn claim) over
**27 review units**.

---

## 1. The headline: one registered theorem is FALSE against `main`

### THM-0008 — "No untyped artifact binding leaves the verifier as verified"

> A binding reported verified is in the opaque-digest form and is one of the three OAuth
> artifact types. The four registry types with no typed verifier can never be reported
> verified.

**Both sentences are contradicted by current code.** `ArtifactType` still has seven
variants and `verify_artifact_binding` still refuses four of them — so the claim is true
*of that function*. But it does not quantify over that function; it quantifies over
"reported verified", and ADR-MCPRE-065 Slice 2 added a **second typed verifier**:

- `mcp-re-http-profile/src/pdp_decision/binding.rs::verify_pdp_decision_binding` accepts
  `ArtifactType::PdpDecision` + `BindingType::OpaqueDigest` and returns `Ok`;
- `mcp-re-http-profile/src/verify/full/request.rs:95` calls it on the full-profile request
  path, ahead of `verify_artifact_binding`, and `continue`s past it.

So `PdpDecision` **has** a typed verifier and **is** reported verified. The count is now
four verified types and three refused, not three and four.

**This was deliberate, and the implementers protected the neighbouring theorem while doing
it.** `request.rs:91` records the reasoning verbatim: dispatching pdp-decision through
`verify_artifact_binding` "would mean widening a function whose proved postcondition is *an
`Ok` result is one of the three OAuth types* — weakening a theorem to save a match arm."
THM-0007 was preserved on purpose; THM-0008 was not re-read afterwards.

**Classification: FALSE.** Not stale — the architecture it describes exists, and the
sentence about it is untrue.

**Dependency damage:** THM-0015 (`A successful full-profile request verification
establishes audience and artifact binding`) lists `depends_on = ["THM-0014", "THM-0007",
"THM-0008"]`. A conjunct of THM-0015 rests on a false premise. THM-0007 is unaffected.

The user's standing note said "stale/falsified by the typed pdp-decision architecture."
Measured, the diagnosis sharpens: **THM-0007 is untouched, THM-0008 is false, and the
falsity is one variant wide, not four.**

---

## 2. The second finding: one STALE STATEMENT

### THM-0013 — "No validated deployment enables online OCSP client-certificate revocation"

> Every `DeploymentRequest` whose `client_ocsp` is `Require` is refused by the legality
> boundary … Every `ValidatedDeployment` therefore carries `client_ocsp = Off`.

**The proposition is intended and still enforced.** `residue::online_ocsp_refusal` still
refuses the mode at `legality_violations`, on the boundary a struct-building caller must
cross.

**The representation it names no longer exists.** ADR-MCPRE-067 Phase 5 replaced the flat
field with `PeerRevocationRequest { lists, online }`, and the mode now lives inside
`OnlineRevocationEvidenceRequest`. The statement describes a field shape the migration
removed — and so does the comment at `config_state/validation/mod.rs:185`, which still
says "`client_ocsp` is one of `DeploymentRequest`'s public fields."

**Classification: STALE STATEMENT.** Repairable by re-expressing the same proposition over
the current owner. Not repaired here.

---

## 3. Evidence staleness: 27 of 27 units, and one cause dominates

Every unit derives DIRTY. Component-level diff against each unit's recorded attestation:

| component that moved | units | why |
|---|---:|---|
| `test_lane_identity` | **27** | `tools/verification/_manifest.py` changed at `d0bc8c0` (MCPRE-175 added boundary-path liveness). It is a `TEST_LANE_INPUTS` member, so the measuring instrument moved for every test-claiming unit at once. |
| `source_inputs` | 16 | MCPRE-175/176 owner subtrees and the partial-operation fixes |
| `proof_dependencies` | 5 | `mcp-re-core/src/time.rs` → `time/mod.rs` + `time/format.rs` |
| `mutation_probes` | 3 | M32/M35 re-adjudicated against the rewritten Ed25519 interpreter; verifier_results |
| `test_sources` | 2 | one integration-test file's content changed |
| `proved_symbols` | 1 | `verify::check_params` → `verify::floor::params::check_params` |
| `test_selection` | 1 | symbol list changed |

**The 27/27 row is a single mechanical event, not 27 findings.** No proposition moved
because of it. It is worth stating plainly because a reader seeing "every unit is dirty"
will otherwise assume the architecture invalidated the whole registry, and it did not.

---

## 4. Owner review: 36 of 37 have never been reviewed

`tools/verification/review` reports **37 theorems `not established`** and **36
`UNREVIEWED: no review record: this has never been reviewed`**.

The single exception is **THM-0002**, reviewed by the owner at `8f620c3a3aaf30db` (issue
#540, second packet; the first was returned NEEDS CHANGE for an upper bound one day looser
than the parser admits). That review **survived MCPRE-176 intact**, and the reason is
structural and worth carrying forward: the review record is over the *theorem claim*
(statement + dependencies), not over the implementation fingerprint. Splitting `time.rs`
into `time/mod.rs` + `time/format.rs` moved the unit's `source_inputs` and
`proof_dependencies` and left the review valid.

**Consequence for the campaign: source refactoring does not cost owner reviews. Statement
edits do.** That is an argument for settling statements before requesting review packets,
and for batching packets by owner family.

---

## 5. By semantic owner family

### 5.1 time / freshness — 2 theorems

| THM | unit | proposition | evidence | fingerprint | review |
|---|---|---|---|---|---|
| 0002 | `core.time_rfc3339` | **UNCHANGED** | STALE (lane, source, proof deps) | source closure follows `time/{mod,format}.rs`; manifest already updated | **REVIEWED** |
| 0001 | `http_profile.freshness_window` | **UNCHANGED** | STALE (lane, source, proof deps, proved symbol) | `proved_symbols` module path moved; manifest already updated | UNREVIEWED |

Verus re-verified `mcp-re-core` at 5 verified / 0 errors after the split. THM-0002's
totality claim is the strongest thing in the registry and is undamaged.

Dependencies: THM-0001 → consumed by nine verifier-result theorems.

### 5.2 verifier results — 9 theorems

THM-0014, 0015, 0016, 0017, 0018, 0019, 0020, 0021, 0022 over
`http_profile.verifier_results` (+ `freshness_window` for six of them).

- Propositions **UNCHANGED** except **THM-0015**, which inherits THM-0008's falsity
  through `depends_on`.
- Evidence STALE for all nine (`mutation_probes` + `source_inputs` + lane).
- MCPRE-176 changed `delegation/verify.rs::check_freshness` to checked arithmetic. That
  **strengthens** the refusal set (an uncomputable edge now refuses); it does not weaken
  any registered conjunct.
- Dependency chain is deep and entirely internal: 0014→0001, 0015→{0014,0007,**0008**},
  0016→0021, 0017→0022, 0018→0016, 0019→0021, 0020→0022, 0021/0022→0001.
- All nine UNREVIEWED.

### 5.3 exchange relation — 8 theorems

Admission currency THM-0003/0004/0005/0006; artifact typing THM-0007/**0008**;
continuation THM-0009/0010.

- **THM-0008 FALSE** (§1). **THM-0007 UNCHANGED** — its Verus postcondition on
  `verify_artifact_binding` is intact and was deliberately protected.
- THM-0004's cited call site was repointed to `admission_enforcer.rs` during ADR-064
  Slice 5; no `reviewed_fingerprint` existed, so nothing was invalidated.
- Remaining six: propositions UNCHANGED, evidence STALE.
- All eight UNREVIEWED.

### 5.4 communication / TLS — 12 theorems

THM-0023 … THM-0034, the deepest dependency chain in the registry
(0023→0024→0029→0031→0033→0034, with 0025→0026→0027 and 0028→{0029,0030,0032}).

- **THM-0025 and THM-0026 are the two MCPRE-176 touched.** `interpret_rfc8410_spki` was
  rewritten from a total-length test plus two slices into `strip_prefix` + fixed-width
  `try_from`. The proposition — *every canonical Ed25519 public key value is the canonical
  RFC 8410 encoding of its own point* — is **UNCHANGED and now structurally enforced**: the
  length equality that used to be a separate assertion is a consequence of the conversion.
  Mutation probes M32/M35 were re-adjudicated to the new anchor, same defect shape, and the
  V0 lane is PASS.
- The other ten: propositions UNCHANGED, evidence STALE (lane only, for eight of them).
- All twelve UNREVIEWED. This is the largest single review batch and the most
  interdependent — a NEEDS CHANGE on THM-0023 or THM-0028 cascades.

### 5.5 trust / revocation — 5 theorems

THM-0035, 0036 (`trust_configuration_state`), 0037 (`trust_plan`), 0038
(`trust_composition_root`), **0013** (`online_ocsp_reachability`).

- **THM-0013 STALE STATEMENT** (§2).
- 0035–0038 propositions UNCHANGED; evidence STALE (`source_inputs`, `test_selection`,
  `test_sources`).
- All five UNREVIEWED.

### 5.6 serving composition — 1 theorem

THM-0012 (`proxy.runtime_lifecycle`) — *the lifecycle record cannot claim a shutdown that
did not happen*. Proposition UNCHANGED; evidence STALE (lane only). UNREVIEWED.

MCPRE-176 made `materializing_runtime`'s completeness an owner and turned four
`take().expect("checked present")` into one checked destructuring, which is adjacent to
this claim and consistent with it.

### 5.7 SCITT / transparency — **0 theorems**

The known zero-of-33 gap. #657's ruling 6 forbade writing entries over the monolith and
required the authority boundaries first. **Those boundaries now exist** — `scitt.rs` is
gone, replaced by an 18-module private owner hierarchy, and EX-004 is re-censused. The
precondition for drafting is therefore satisfied, and this is the largest greenfield item
in the campaign.

### 5.8 admission / authorization — **0 theorems for ADR-065**

The four admission-currency theorems are about ADR-MCPRE-054 admission currency, not about
authorization. The ADR-MCPRE-065 authorization decision — the `pdp-decision` evidence form,
`PolicyError`, the PDP verdict — carries **no registered proposition at all**, while being
the very mechanism that falsified THM-0008. Issue #637 separately recorded that
`AuditEvent.reason` has a fourth producer the drift guard never scans.

**This is the registry's real coverage hole: the newest security authority is the one with
no theorem and no evidence.**

---

## 6. Proposed campaign order

Ordered so that each step makes the next one measurable, and so that nothing re-attests a
claim before its statement is settled.

**A — settle the two defective statements first.** THM-0008 (FALSE) and THM-0013 (STALE
STATEMENT). These must precede re-attestation: attesting a unit whose theorem is false
records evidence for a claim nobody intends. THM-0008 also gates THM-0015. Small, two
statements, one owner ruling each.

**B — re-attest the 27 units.** After A, this is mechanical and mostly one cause. It clears
the UNKNOWN fog so that step C reads real signal rather than the `_manifest.py` edit.
Expect it to be nearly free; the exception is `http_profile.artifact_typing`, which must
wait for A.

**C — owner specification review, batched by family in dependency order.** 36 packets is
not 36 conversations. Batch: time/freshness (2) → exchange relation (8) → verifier results
(9) → communication/TLS (12) → trust/revocation (5) → serving (1). Reviews are over claims,
so they survive later refactoring — which is the argument for doing them now rather than
after more architecture. This is issues #540/#581/#582/#583.

**D — the two coverage holes.** SCITT/transparency (now unblocked, 18 owners, 0 theorems)
and ADR-065 authorization (0 theorems over the authority that falsified THM-0008). Draft
against the owners that exist, not against the units.

**E — #541 extracted-model pilot, in parallel from step B onward.** It is not a
prerequisite for any of the above and must not become one.

### Recommended extraction target for #541

**`mcp-re-core/src/time/format.rs`** — `civil_from_days` and `unix_to_rfc3339_utc`.

The reasons are specific rather than convenient:

- **It is production Rust, not a toy slice** — the requirement #541 states explicitly.
- **It is pure and sequential**: no allocation beyond one `format!`, no I/O, no async, no
  FFI, no traits. `mcp-re-core` forbids all of those by manifest purity (ADR-MCPS-011/012),
  which is why it is the only crate plausibly inside Charon's supported subset.
- **It is the one part of the time owner the Verus cone does NOT reach**, and MCPRE-176
  established that boundary explicitly — `time/format.rs` exists because the audit found
  the formatting inverse carries its bounds in Rust rather than in a proof. A `lean://`
  model would close a real, already-documented gap rather than duplicate `verus://`.
- **Its neighbour is the one owner-reviewed theorem in the registry** (THM-0002), so the
  review machinery around it is exercised and its claim shape is known good.
- **It is small enough to fail cheaply.** If the toolchain cannot express the Gregorian
  era arithmetic, that is a measured limitation to record — which #541 requires as an
  outcome in its own right — and nothing else in the campaign is blocked by it.

The alternative, extracting `parse_rfc3339_utc` itself, would produce a dual-path proof of
a proposition Verus already establishes. That is issue #543 (T7, deferred/HITL), not this
pilot.

---

## 7. What this inventory deliberately did not do

- No theorem statement edited, including the two defective ones.
- No unit re-attested.
- No `PrototypeTransparencyService` classification and no `ReceiptPositionProfile::Bound`
  selectability change — both remain separate recorded questions under #657.
- No SCITT implementation slice opened; the structural remediation is complete.
