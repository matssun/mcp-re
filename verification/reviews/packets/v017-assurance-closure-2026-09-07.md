<!-- SPDX-License-Identifier: Apache-2.0 -->

# v0.17 assurance closure — consolidated report

**Mandate:** the owner's AFK assurance-closure mandate of 2026-09-07, run as one campaign from
`main` at `86e868c8`.

**Result:** the four named gap classes are closed. **109 units** (was 88), **124 theorems**
(was 109), **12 of 12 roots complete**, **124 of 124 established**, measured locally. 42
assumptions — none added, none discharged. 137 probes, each still turning a declared control
red.

Three PRs: **#831** (priority 1), **#832** (priorities 2–4), **#833** (priority 5).

---

## 1. The two architectural rulings

### TLS epoch wrapper — retained as ruled

`unwrap_if_current`'s per-read epoch equality check is untouched. No change was made to the
representation, and none was proposed: the ruling's condition for a future simplification —
*a stored session is returned iff its stored epoch tag equals the epoch governing that
store/listener lookup* — remains the invariant THM-0103 states. #598's retirement suggestion is
resolved exactly as the ruling directs.

### `PolicyError` / `AuthorizationRefusal` / `RefusalCause` — not collapsed

The audit found the delegation chain **already correct**. `PdpRelationRefusal::wire_code`
returns a `PolicyError` *variant*, not a string; `AuthorizationRefusal` asks each arm;
`RefusalCause` composes. No layer reproduces the `PolicyError -> mcp-re.authorization_*` table,
and none acquired a `PolicyError -> McpReError` projection.

One wording correction, as the ruling anticipated: `RefusalCause::wire_code` called itself "the
ONLY rendering point", which reads as a claim to own the subordinate mapping. It now names
itself the final presentation boundary and says where ownership lies.

---

## 2. What each priority found

### Priority 1 — `mcp-re-policy` (#831)

Three of six files had **zero consumers** and were each a second authority over a fact the
RFC 9421 tree already owns: `block.rs` (the deleted `_meta` carrier's parser, already named a
legacy input in `docs/architecture/authorization.md` §2.5), `decision.rs` (strictly weaker than
the ADR-MCPRE-065 posture types) and `wire.rs` (an unsigned JSON-RPC envelope carrying open
finding #144). Deleted; the crate now depends on `thiserror` alone.

**The finding the audit was not looking for:** a **fifth** `mcp-re.*` minting producer.
`BindingSpecRefusal` matched onto two string literals, and **both published SDKs render
refusals through it**. The ADR-MCPRE-066 Slice 2 drift guard's producer list had never been
told the file existed — the exact defect §2.1 names in its own words.

**The list was replaced by a measurement.** `exactly_two_files_decide_what_a_verdict_token_says`
walks every workspace crate's source tree; the crate list is derived from the workspace
manifest, so a new member is scanned or the lane fails.

**And the primitive the walk rests on was broken.** `production_half` knew nothing of raw
strings and forgot its state at every newline — a raw byte string holding JSON closed a
`#[cfg(test)]` region three lines early, and **27 lines of test code were measured as
production** by every guard built on it. Now a stateful lexer, mirrored into
`scripts/module_size_gate.py`. Measured impact: 622 files, one changed count, downward.

### Priority 2 — `mcp-re-host` (#832)

Four files, **zero tests in either lane**, **no Bazel test target at all**.

`signer.rs` is **dormant** — `HostSigner` has no consumer anywhere; the ADR-MCPS-003 property it
documents is held on the live path by `McpReProxy` under THM-0084. Excluded by name; recorded
rather than deleted.

**A control found a real production bug.** `(2^63 + 1) as i64` wraps to `i64::MIN + 1`, whose
negation is `i64::MAX` — a clock set unrepresentably far *before* the epoch reported the
furthest instant in the **future**, which every freshness window accepts. Exactly the
"fabricated plausible time" the code's own comment said must never happen.

### Priority 3 — transparency (#832)

`retained_record.rs` had **zero controls**; seven added. The third covered-set widening had a
control in the wrong module, cited by no unit, with an orphaned doc comment — moved to the
module that owns the rule. `durability_bounds.rs` joined the retention unit's paths because
`MAX_RESERVATIONS` could be set to 1 and THM-0088 would still read `FRESH`.

### Priority 4 — `remote_signer_call` (#832)

Closes the gap THM-0108's scope names by name. **Both realizations measured separately: 14
controls under `aws_kms_keysource` alone, 15 under `gcp_kms_keysource` alone.** The two are
different *types*. An evidence gap inside the ownership gap: the module tested only its parts,
and `quota_verdict` had **no control at all**.

### Priority 5 — the ownership remainder (#833)

Thirteen units, ten theorems, all over evidence that already existed. Ownership: **329 of 509**
source files (was 275).

**The lane caught two of this campaign's own mistakes.** Ten selectors named a module that does
not exist (`verify-tests` reported them `never ran`), and one new control was flaky by
construction — two draws of one byte collide once in 256, so it would have failed on a correct
implementation roughly every four hundredth run.

### Off-mandate: a standing supply-chain red

`cargo deny` had been failing on `main` for at least four merges, including `86e868c8` itself,
on a yanked `wnaf 0.14.0`. A supply-chain gate red on every merge is a gate nobody reads.
Updated in all three lockfiles.

---

## 3. Evidence classes

The mandate asks that the closure report distinguish these. It does.

### PROVED — machine-checked by a prover

Six V1 units under Verus. Unchanged by this campaign; no unit was promoted or demoted.

### STRUCTURALLY ESTABLISHED — a property of the types, not of a battery

Where possession is the proof and the wrong value is unconstructible:

- THM-0108's three seam types, and THM-0111's producer conjunct — a carrier that states which
  Core verdict it *is* rather than spelling a token;
- THM-0122 — no audit constructor takes a string, so a foreign taxonomy does not typecheck;
- THM-0121 — the floor is monotone **by construction**: a max over a set that only grows has
  neither of the single-counter design's two failures;
- THM-0125's `id`-key absence, and THM-0114's infallible `NonceSource::fill`.

### TESTED — executable evidence, class V0

The other 118 theorems. Every one names its battery by **exact selector**, and
`verify-tests` refuses a selector that does not run — which is how ten wrong ones were caught
in this campaign. 137 mutation probes establish the controls are load-bearing.

Feature-gated lanes are named rather than assumed: `aws_kms_keysource`, `gcp_kms_keysource`,
`pkcs11_keysource`, `async_serve`, `redis_replay`. A plain `cargo test --workspace` compiles
several of these units to zero tests.

### ASSUMED — 42 assumptions, unchanged

None added and none discharged by this campaign. ASM-0029 stays a premise for every caller
other than the production resolver THM-0099 instantiates it for; ASM-0040/0041 remain the
durability premises the replay backends' own theorems rest on.

### DEFERRED — visible, not weakened

- **V2/V3 extracted-model work**, until a pinned extraction image can run the Lean pipeline.
  `verify-lean` reports `NOT_REQUIRED` because no V2/V3 unit is declared, and it escalates to
  `FAIL` the moment one is.
- **Real FIPS-140-2 Level 3 custody evidence**, until validated hardware is available. THM-0116
  states this in its own scope: a Cloud KMS `EC_SIGN_ED25519` key version may be SOFTWARE- or
  HSM-protected and the two REST operations used cannot establish which, so the adapters are
  honestly labelled software-protection custody.
- **The live fleet lane** — the seven-proof kind/GKE acceptance gate is opt-in and off the merge
  path.

None of these was weakened to manufacture closure.

### OUT OF SCOPE — with a reason, per surface

Recorded in `verification/reviews/packets/ownership-remainder-2026-09-07.md` §"What remains
outside". In summary: `lib.rs` re-export surfaces and composition roots (nothing to own);
`policy/revocation.rs` and `host/signer.rs` (deliberately dormant, excluded by name);
test-paths, demo fixtures and the Verus reproducer (not production); the two SDK wrapper
sources (separate Cargo workspaces, no Bazel target); and `mcp-re-proxy` / `mcp-re-http-profile`
(not on priority 5's list). `scitt/prototype/` is what the census read it as: two files named
"prototype", an out-of-scope declaration rather than a unit.

### ACTION_REQUIRED — named, not closed

Two surfaces are classified as needing work rather than as out of scope:

- `mcp-re-client-proxy/src/{route,transport,verified_outcome}.rs` — 0 controls.
  `verified_outcome.rs` holds the sharpest unowned client proposition left: an
  `InputRequiredResult` with no usable `requestState` is MALFORMED rather than terminal, and an
  unrecognized `resultType` is never resolved to terminal. A unit here would have to cite
  another unit's controls, which this campaign has refused four times; it needs new ones.
- `mcp-re-client/src/startup.rs` — the anchor refresher is started **unconditionally** because
  it is the only place anchors are WITHDRAWN once the manifest in force has lapsed, and nothing
  on the request path consults that expiry. THM-0120 establishes what the refresher *does*;
  that the deployable always starts one is unmeasured.

---

## 4. Closure conditions, checked

| condition | state |
|---|---|
| the four gap classes closed or classified OUT_OF_SCOPE with justification | **met** — §2, and the per-surface classification in the P5 packet |
| ownership-only surfaces have honest owners/evidence or an explicit reason | **met** — 329/509 owned; every remaining file classified, two as ACTION_REQUIRED |
| no unreviewed duplicated semantic authority remains | **met** — three deleted in P1, one producer projected, one control moved to its owner; the one surviving duplicate (a token spelled by both frozen taxonomies) is reviewed and named in THM-0111's scope |
| all declared theorems establish | **met** — 124 of 124 |
| all declared roots complete | **met** — 12 of 12 |
| ordinary and assurance-platform gates green | **met** — `LOCAL GATE: PASS` on each PR; `cargo deny` green for the first time in five merges |
| the report distinguishes proved / structurally established / tested / assumed / deferred / out-of-scope | **met** — §3 |

## 5. Assurance-platform follow-up

#739 (the pytest colour/unreadable-report defect) is unchanged and stays open. The standing
invariant — *a report the lane cannot parse is `ReportUnreadable`; it is never evidence that
the declared controls did not run* — held during this campaign: `verify-tests` reported ten
selectors as `never ran` and refused, which is the same principle on the libtest reader.
