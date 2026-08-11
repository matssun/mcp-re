<!-- SPDX-License-Identifier: Apache-2.0 -->

# WP2: `mcp-re-http-profile` — what got proved, and what the prover cannot reach

**ADR-MCPRE-059, work packages 2 and 3.** Measured against the pinned prover
(`0.2026.08.09.92f466f`). Four new V1 units landed and one assumption was discharged into a
proved contract; eight prover ceilings were measured, each one a command that was run and
an error that came back.

The stated goal for this crate was "function by function". That goal is not achievable on
this prover, and this document says exactly where it stops rather than reporting the part
that worked.

---

## What landed

| unit | theorem | negative control |
|---|---|---|
| `http_profile.admission_currency` | a live admission verdict implies the call's bound generation **equals** the authoritative one and that state says admitted; a degraded verdict implies the authoritative state was unreachable **and** the deployment opted in | deleting the generation comparison → FAIL; deleting the `allow_degraded_mode` guard → FAIL |
| `http_profile.artifact_typing` | a verified artifact binding is the opaque-digest form of one of the three OAuth types, and each typed verifier admits only its own type | admitting `PdpDecision` → FAIL |
| `http_profile.continuation_unbypassability` | a request carrying a continuation can never be prepared successfully with `continuation_verified == false` | admitting a continuation with no retained bases → FAIL |
| `http_profile.continuation_binding` (WP3) | an accepted continuation's three handles are the labeled digests of the three presented inputs, each under its OWN role label | checking the previous-request handle under the response label → FAIL |

### The currency theorem is the concrete case for Operational Rule 17

`check_admission` calls JWS segment splitting, base64url decoding, JSON deserialization,
Ed25519 signature verification, an audience test, and a SHA-256 commitment check. **None of
them is in the theorem's dependency cone.** The §7 property is established entirely by the
function's own comparisons against the authoritative state, so ASM-0012 trusts
`verify_admission_assertion` with *no `ensures` at all* — the strongest form an assumption
can take, because an assumption without a postcondition cannot weaken the theorem above
it. It can only limit what that theorem says, and what it costs is stated plainly in the
registry: an `Ok` verdict does not, by this proof, mean the assertion was validly signed.

That is the rule the ADR now carries: the proved unit's trusted frontier is a property of
the *proof*, not of the crate it lives in. Here a 75-line function inside a 707-line module
inside a 14 800-line crate has a trusted frontier of four registered items.

### What the negative controls did and did not show

Both currency controls are caught **only** by the proof — no test in the battery fails when
the generation comparison is deleted, because a test fixes the generations it supplies and
the deletion is invisible unless the test happens to supply a mismatched pair *and* assert
the refusal. The battery does contain such a test, so the mutation is caught; what the
proof adds is that it is caught for every pair, including the ones nobody wrote down.

The artifact control is caught by **both** the proof and
`artifact::tests::dispatch_matches_the_typed_verifiers`. Recorded because a negative
control that duplicates an existing test is weaker evidence than one that does not, and
saying so is the difference between calibration and advertising.

## Observed ceilings under the pinned V1 toolchain

**These are measurements of `0.2026.08.09.92f466f` on MCP-RE's code, not statements about
Verus.** The distinction is load-bearing and is the reason each entry carries its exact
reproducer: Verus documents support for executable closures and for constants generally,
so ceiling 1 is a defect on a particular shape and ceiling 4 is about the *associated*-const
form this codebase happens to use. None of them should be read as "Verus cannot do X", and
none should harden into an MCP-RE coding standard — a later release may simply remove them.

Each is a *false red* rather than a false green: the lane fails loudly. That is the right
failure direction, and it is why they are ceilings rather than hazards.

1. **A closure parameter whose signature mentions an unspecified type crashes the prover.**
   Not a diagnostic — an internal panic:
   ```text
   thread '<unnamed>' panicked at vir/src/sst_to_air.rs:510:45:
   called `Option::unwrap()` on a `None` value
   ```
   Bisected to the return type: `impl Fn(u64) -> u64` and `impl Fn(&str) -> u64` verify;
   `impl Fn(&str) -> Option<VerificationKey>` panics. Declaring `VerificationKey` opaque
   (ASM-0013) fixes it. Every MCP-RE trust seam is a closure of this shape, so this one
   ranks first: without the workaround the entire injected-seam surface is unreachable.

   A verifier crashing on a legal type shape is a tool defect, so it reduces to a
   twelve-line standalone crate at
   [`verification/reproducers/verus-ice-closure-return-type/`](../reproducers/verus-ice-closure-return-type/)
   for upstream filing. The opaque-return workaround is fine for the pilot and must not
   quietly become part of MCP-RE's architecture.

2. **`format!` is out of reach.** It expands to `alloc::fmt::format` wrapped in
   `core::hint::must_use`, and specifying those two only exposes the next layer:
   `core::fmt::Arguments`, `core::fmt::rt::Argument`, `core::fmt::rt::Argument::new_display`
   — unstable formatting internals, none specified by vstd. Trusting that pile to prove one
   theorem is a worse trade than not proving it, so it was **not** taken. This is what
   stopped the delegation credential-window theorem (below).

3. **`|_|` is unsupported; `|_e|` is fine.**
   ```text
   error: The verifier does not yet support the following Rust feature:
   only variables are supported here, not general patterns
   ```
   The wildcard closure binding — the crate's universal `.map_err(|_| Error::X)` idiom —
   blocks 40 of 242 functions. The fix is a one-token rename with no semantic content
   whatsoever, which is a materially different trade from ASM-0001's loop restructure.

4. **Associated consts are unsupported**, in the body as well as in the specification:
   `error: mcp_re_http_profile::policy::impl&%1::MAX_CLOCK_SKEW_BOUND is not supported`.
   Free consts work. This alone makes `bounded_skew` — three tokens, `clamp(0, CAP)` —
   unverifiable in place.

5. **`assume_specification` cannot carry a `requires` for a trait method**: "trait method
   implementation cannot declare requires clauses". A side condition has to move into the
   `ensures` as an implication, which is the same strength and worth knowing before
   writing one.

6. **Derived `PartialEq` on an external type needs its own specification.** Without it
   `status != Admitted` is an opaque boolean and the theorem cannot see which paths return
   `Ok`. Registered per enum (ASM-0014, ASM-0020) rather than assumed globally.

7. **A datatype constructor used as a function value is unsupported**: `error: The verifier
   does not yet support the following Rust feature: using a datatype constructor as a
   function value`, on `.map_err(DispatchError::Profile)`. The eta-expanded
   `.map_err(|e| DispatchError::Profile(e))` verifies.

8. **A closure passed to `Option::and_then` is not related back to its receiver.** The
   equivalent `match` proves the same postcondition; the `and_then` form fails it. Measured
   side by side in one run, on one property:

   ```rust
   #[verus_spec(out => ensures out is Some ==> (b matches Some(x) && x.continuation is Some))]
   fn probe_and_then(b: &Option<Block>) -> Option<&Cont> { b.as_ref().and_then(|x| x.continuation.as_ref()) }  // FAILS
   fn probe_match(b: &Option<Block>)    -> Option<&Cont> { match b { Some(x) => x.continuation.as_ref(), None => None } }  // VERIFIES
   ```

9. **`str::replace` is unspecified**: `error: alloc::str::impl&%5::replace is not
   supported`. Reached while measuring whether ASM-0021 could be discharged (below).

## The delegation theorem that did not land

`verify_delegation_credential` was the highest-value remaining target: the property whose
absence produced a **24-hour credential-acceptance window beside a 300-second signature
gate** — a configured `max_clock_skew: 86400` reaching the credential comparison without
the profile's hard cap. The theorem is exactly stateable:

```text
Ok(v) ⇒ v.nbf ≤ now + CAP  ∧  now − CAP ≤ v.exp
```

It stops on ceiling 2. The function builds its JWS signing input with `format!`, so its
body cannot be verified in place, and every workaround is either a production refactor
(Rule 11, the owner's call) or trusting unstable `core::fmt` internals. The attempt is
recorded here in full, including the withdrawn ASM-0015, so the next person does not spend
the afternoon rediscovering it.

## The transparency-cascade experiment — `prepare_http_dispatch`

Run as an experiment with a stop rule, not as a commitment. The question: **can a security
theorem traverse a rich production model without expanding the trusted surface?** Every
item the cascade required was classified before it was taken.

| class | meaning | count | verdict |
|---|---|---:|---|
| A | expose datatype structure to the prover | **12** | taken |
| B | add a view/equality specification | **0** | — |
| C | introduce an assumption | **2** | taken; both carry NO `ensures` |
| D | require production restructuring | **0** | stop sign — none hit |
| E | prover limitation/workaround | **2** | recorded as ceilings 7 and 8 |

**Class D means architectural distortion**, and only that: changed module boundaries, a new
abstraction, moved ownership, a changed public API, new runtime state, altered control
architecture, a crate split for the verifier. An expression-level semantics-preserving
rewrite is class **E** — a prover-enablement workaround — provided ordinary tests establish
equivalent behaviour, it is visibly marked in the source, and we are willing to revert it
when the ceiling disappears. All three hold for both edits below. Letting D swell to cover
syntax would stop it identifying the distortions Rule 11 exists to prevent.

The twelve are `SignerSlot`, `ActorIdentity`, `ResolvedActor`, `AudienceTuple`,
`RequestEvidenceDigest`, `HttpContinuation`, `HttpRequestEvidenceBlock`, `RequestEvidence`,
`VerifiedHttpRequestEvidence`, `HttpReplayKey`, `DispatchError`, `RetainedContinuation` —
each one line, structure only. No views, no equality specifications, no arithmetic.

**The result is the good one, stated precisely.** An earlier draft of this section said
"the cone grew; the frontier did not", which conflates three different things. The accurate
breakdown:

```text
structural proof cone grew        +12 transparent datatypes
semantic premises added             0  (neither seam contributes a fact to the theorem)
registered trusted seams added     +2  (ASM-0021, ASM-0022 — still boundary, still visible)
```

An assumption with no `ensures` cannot hand the prover a convenient fact about its result,
so it cannot make this postcondition easier by asserting one. It is nonetheless part of the
boundary drawn around the proof, it stays in the attestation, and it does not stop being
trusted code because it is silent. The two are different claims and the middle line is the
one that carries the good news.

That distinction may eventually deserve two edge kinds rather than one — a semantic premise
a theorem *uses*, versus an opaque implementation boundary it merely *stops at*. Five units
in, the difference is visible enough to be worth naming; it is not yet urgent enough to
split `TRUSTS_ASSUMPTION`.

Against the empirical curve —

```text
freshness_window     small arithmetic cone
admission_currency   cryptographically rich surroundings, tiny cone (crypto behind ASM-0012)
artifact_typing      several typed verifier paths
continuation_...     twelve model types, still no new trusted surface
```

— this is evidence that the approach scales past leaf predicates into orchestration
decisions. The cone grew; the frontier did not.

### The two mechanical proof-enablement edits, flagged

Ceilings 7 and 8 each needed one expression rewritten in `prepare_http_dispatch`:
`.map_err(DispatchError::Profile)` → `.map_err(|e| DispatchError::Profile(e))`, and
`.as_ref().and_then(|b| b.continuation.as_ref())` → the equivalent `match`. Both are
semantics-preserving (the second *is* `and_then`'s definition), both are attached to an
actual proof rather than speculative, and both are marked in the source as
proof-enablement rather than architectural preference.

Both are class E under the definition above, ruled so deliberately. The measurement that
matters is **0 architectural changes, 2 local syntax workarounds**.

### What this theorem does and does not say — and the composition that closed the gap

It proves **unbypassability**: no successful dispatch preparation can carry forward the
pair (continuation present, `continuation_verified == false`). On its own it does **not**
prove the continuation is correctly bound — swallowing the error inside the `(Some, Some)`
arm would satisfy it while breaking the binding.

That gap was ASM-0022, and it is now **discharged rather than documented**. See
[the composition section](#wp3--composition-discharging-an-assumption-into-a-proved-contract).

The negative control (admitting a continuation with no retained bases) fails the lane, and
is also caught by `continuation_without_retained_context_fails_closed`. As with the
artifact control: what the proof adds is every input, including the arms nobody wrote a
fixture for.

## Crate triage — 242 non-test functions

Against the four *mechanical* blockers (`format!`, `|_|`, iterator `for`, iterator
adapters), **159 of 242 functions — 66% — are clear**. That number is an upper bound on
reachability, not a plan: most of the 159 are constructors and getters whose contracts are
their type signatures.

| blocker | functions blocked |
|---|---:|
| wildcard closure `\|_\|` | 40 |
| iterator adapters (`.iter()`, `.split()`, …) | 35 |
| `format!` | 17 |
| iterator `for` loops | 15 |

| module | clear / total | note |
|---|---|---|
| `scitt.rs` | 27/41 | receipt verification; the inclusion-proof theorem is a V2/Lean shape, not V1 |
| `verify.rs` | 18/33 | `check_params` PROVED (Phase 2) |
| `block.rs` | 14/17 | `validate` trusted (ASM-0019); its own contract is a candidate unit |
| `custody.rs` | 12/13 | unexamined — next target after WP3 |
| `sign.rs` | 10/17 | signing path; most of it is below `boundary.crypto_primitives` |
| `policy.rs` | 9/10 | accessors trusted (ASM-0007/0008) |
| `rejection.rs` | 9/10 | owned by another agent's in-flight work; not touched |
| `artifact.rs` | 8/8 | **PROVED** — 4 theorems |
| `sigbase.rs` | 8/11 | signature-base construction; `format!`-heavy in the parts that matter |
| `bodyless.rs` | 6/15 | signed-202 path (#418) |
| `context.rs` | 6/6 | unexamined |
| `admission.rs` | 4/9 | **PROVED** — the currency theorem |
| `chain.rs` | 4/6 | unexamined |
| `dispatch.rs` | 4/4 | the anti-splice theorem is stateable but needs a ~20-type transparency cascade through `block.rs`; deferred, not blocked |
| `evidence.rs` | 3/3 | thin |
| `mcp_transport.rs` | 3/7 | |
| `message.rs` | 3/4 | |
| `replay.rs` | 3/5 | key construction; `check_and_insert` is a trait method (WP1 Finding 2) |
| `result_class.rs` | 3/4 | owned by another agent's in-flight work; not touched |
| `delegation.rs` | 2/7 | attempted, blocked on ceiling 2 |
| `envelope.rs` | 1/3 | another agent's new file |
| `keyid.rs` | 1/2 | declared `lean-candidate`; RFC 7638 canonicalization is a V2 shape |
| `body.rs`, `digest.rs` | 0/4, 0/2 | wholly iterator/`format!`-bound |

## What "function by function" actually means here

The honest restatement, after measurement: **the reachable surface is decision functions —
match/compare/return over values — and the unreachable surface is everything that parses,
formats, iterates, or dispatches through a trait.** MCP-RE's security properties are
concentrated in the first kind, which is why two real theorems came out of a crate that is
two-thirds mechanically clear and nowhere near two-thirds proved.

Item 2 of the earlier list — `HttpContinuation::verify`'s own contract — is **done**, as
WP3 below. Item 3 was measured and is blocked; see the next section. What remains:

1. `custody.rs`, `context.rs`, `chain.rs` — unexamined, mechanically clear. Deliberately
   NOT next: after Rule 19, breadth for its own sake is the wrong optimization target.

**No crate-wide `|_|` → `|_e|` sweep.** Ruled out deliberately: forty production edits to
enlarge what the current prover can ingest is grooming source for a tool, and verification
should follow the architecture rather than the other way round. The policy is a *local*
rename when a selected proof target actually needs one, recorded as mechanical
proof-enablement — one or three edits attached to real theorems, not forty speculative
ones. If ten more units later show that most of the forty are becoming targets anyway, a
dedicated sweep becomes justified by demonstrated recurring cost. Until then, `|_|`
avoidance is explicitly **not** an MCP-RE coding standard; it is a property of one pinned
prover build and may vanish in the next.

---

## WP3 — composition: discharging an assumption into a proved contract

Five units answered the viability question yes. From there, "number of green units" is a
weak metric; the interesting question is whether the *assumed* boundary underneath the
proofs can be reduced, and whether stronger claims can be composed from weaker ones. WP3
is that experiment, run on the pair WP2 left deliberately open.

### The lower theorem

`HttpContinuation::verify` now carries a **role-labeled binding-discipline contract**: an
accepted continuation's three handles are the modeled digests of the three presented
inputs, *each under its own required role label*.

```text
Ok(()) ⇒ previous_request_evidence.digest_value  == labeled_digest(REQUEST,       previous_request_base)
       ∧ input_required_response_evidence.value  == labeled_digest(RESPONSE,      input_required_response_base)
       ∧ request_state_digest.digest_value       == labeled_digest(REQUEST_STATE, request_state)
```

The shape of ASM-0023 is the whole craft here. `labeled_digest` is an **uninterpreted**
function of `(label, bytes)`: nothing about SHA-256 is assumed — not collision resistance,
not preimage resistance, not even injectivity — only that the same label over the same
bytes yields the same value.

State the result at exactly its strength:

```text
PROVED       the verifier checks each handle under the correct role label
NOT PROVED   distinct role-labelled inputs cannot collide
```

The second would need `label_a != label_b ==> digest(label_a, x) != digest(label_b, y)`,
a domain-separation property of the construction that is absent from the model on purpose.
So this is binding *discipline*, not *separation*, and the collision question stays visibly
at `boundary.crypto_primitives` rather than being assumed away. The distinction is a result,
not an embarrassment: it is what makes the assumption refinement legible —

```text
OLD ASM-0022   trust substantial continuation verification logic
      ↓ discharge
PROVED         continuation verification structure
      +
NEW ASM-0023   trust cryptographic labeled-digest semantics
```

Negative control: checking the previous-request handle under `EVIDENCE_LABEL_RESPONSE`
fails the lane (and two tests).

### The trade, measured

```text
before:  ASM-0022  HttpContinuation::verify opaque, no ensures
                   → 20 lines of role-checking logic meaning nothing to the proof

after:   ASM-0023  matches_labeled, one ensures, digest uninterpreted
                   → 3 lines, and the property it grants is exactly the one used
```

One assumption withdrawn, one narrower assumption added, and roughly twenty lines of
security logic moved from assumed to proved. ASM-0022 is kept in the registry marked
WITHDRAWN rather than deleted: an assumption that simply disappears leaves the earlier
attestations unexplainable.

### The composition, and the propagation demonstration

A `PROOF_DEPENDENCY` edge now runs `continuation_binding → continuation_unbypassability`
(producer → consumer; dirtiness flows along the arrow). The upper claim reaches the lower
theorem instead of a trusted seam.

Demonstrating that this is load-bearing needed one missing piece: the freshness engine could
*derive* states since Phase 4, but nothing ever *wrote* the records it derives them from, so
every unit read `UNKNOWN` and the invalidation rules had never executed on a real unit.
`tools/verification/attest` is that half. With it, on the live manifest:

```text
all eight units attested                       → FRESH

lower proof fails, upper unit's inputs unchanged:
  http_profile.continuation_binding            BLOCKED
      a required proof failed; no freshness may be issued from here
  http_profile.continuation_unbypassability    DIRTY_DEPENDENCY
      http_profile.continuation_binding is BLOCKED over an unsealed PROOF_DEPENDENCY edge
  review closure                               2 unit(s)
```

The upper unit's own fingerprint is byte-identical and its lane would pass again on its own
terms — its theorem never depended on the lower one's `ensures`, only on control flow. Every
earlier version of this system would have shown it green beside a red one. It is not green,
and re-attesting it does not make it green: propagation is recomputed from the producer's
state on every run, so there is no laundering path. Both facts are now regression tests in
`test_invalidation.py`.

This is the line between "we integrated Verus" and the evidence architecture ADR-MCPRE-059
was designed to be.

### The state algebra, corrected

A `BLOCKED` producer initially yielded `DIRTY_DEPENDENCY` downstream. Sound but imprecise,
and the two words carry different obligations:

```text
DIRTY_*   this evidence is stale and can in principle be re-derived here
BLOCKED   no valid freshness may be issued until a prerequisite OUTSIDE this unit is repaired
```

A composed claim standing on a failed proof is the second, so `BLOCKED` now propagates as
`BLOCKED` — over every propagating edge kind, escalating a consumer that was merely dirty,
and **through any seal**: a seal claims the exported contract is the whole of the consumer's
reasoning, which is worthless when the proof establishing that contract failed. No new enum
member; the causal chain is in the reason string.

The live lifecycle, on the real pair:

```text
A pass, B pass                  A FRESH    B FRESH
break A's proof                 A BLOCKED  B BLOCKED
   "required dependency http_profile.continuation_binding is BLOCKED over a
    PROOF_DEPENDENCY edge; re-running this unit cannot repair a failed prerequisite"
re-attest B while A broken      B BLOCKED          <- no laundering path
restore A to the same inputs    A FRESH    B FRESH
```

The last line is worth being explicit about, because it differs from the "B must be
refreshed" shape one might expect. Nothing in B's closure moved: A was repaired to the
fingerprint its own record was taken at, so the composed claim is supported again and B is
genuinely fresh. Propagation is recomputed from A's *current* state on every run, so B can
only be green while A is. Repair A to *different* source and B correctly becomes
`DIRTY_DEPENDENCY` instead — pinned as a test.

An edge-direction control is pinned too, because the first version of this edge in
`verification.toml` had producer and consumer reversed: break A → both affected; break B →
A unaffected.


## ASM-0021 measured, and the shape of the remaining discharge problem

`ActorIdentity::actor_id` injectivity is the strongest remaining candidate on
consequence-if-false: it is the replay-key's identity component, and its escaping is what
stops two distinct actors collapsing to one key. Under Rule 19's priority function it
outranks anything available on centrality, since the graph still reports no shared roots.

It is **not dischargeable on the pinned toolchain**, and that was measured rather than
guessed:

* `field_escape` uses `str::replace` — `error: alloc::str::impl&%5::replace is not
  supported` (ceiling 9);
* `actor_id` builds its join with `format!` — ceiling 2.

Specifying `str::replace` at the strength an injectivity proof needs would mean writing a
full trusted specification of Rust string replacement, which would then be the largest and
least reviewable assumption in the registry. That is the wrong direction: it would grow the
trusted surface in order to claim a discharge.

### What this says about the next increment

Sorting the registry by Rule 19's priority function, the reachable and the valuable barely
overlap on this prover:

| assumption | consequence if false | dischargeable now? |
|---|---|---|
| ASM-0012 JWS verifier opaque | high | no — `format!` (ceiling 2) |
| ASM-0021 actor_id injectivity | high | no — ceilings 2 and 9 |
| ASM-0011 / 0018 / 0019 / 0023 crypto & digest seams | high | no, and correctly so — they ARE `boundary.crypto_primitives` |
| ASM-0013 opaque key type | none (nameability only) | n/a |
| ASM-0014 / 0020 derived `PartialEq` | low | only by a prover that models `derive` |
| ASM-0007 / 0008 policy accessors | low | yes — make `VerifierPolicy` transparent, a modelling choice with no production change |
| ASM-0001 digit-bound loop | low | yes — index-loop rewrite, the Rule 11 trade already recorded |

So the next *real* reduction in trusted surface needs one of: a prover release that lifts
ceiling 2, a decision to specify the `format!` expansion (rejected once already, on the
grounds that trusting unstable `core::fmt::rt` internals is worse than not proving the
theorem), or a production change of a kind Rule 11 reserves to the owner.

Recording this is the point. "No cheap discharge is available" is a finding about where the
assurance boundary currently sits, and it is more useful than adding a sixth unproblematic
unit that would not move it.

### Owner ruling — ASM-0021 stands, and the rejections are recorded

Both alternatives were put to the owner and both were rejected:

* **A broad trusted specification of `format!` / `str::replace`.** Rejected: it would
  retire one named assumption while silently introducing a much uglier trusted model of
  unstable formatting internals. Negative progress.
* **A verifier-driven production rewrite.** Rejected under Rule 11. Replacing a clear
  implementation with a bespoke string builder *because the pinned prover currently handles
  that form better* is precisely the distortion Rule 11 exists to prevent. Absent an
  independent conclusion that the current actor-id construction is undesirable
  architecture, it stays as it is.

ASM-0021 therefore reads: **NOT DISCHARGED**, blocked by observed pinned-toolchain ceilings
2 and 9, with both alternatives rejected and the existing trust left explicit. That is an
honest formal-verification result, not a gap in the work.

## Three boundaries, and why forcing them to coincide is the error

The pilot has produced empirical evidence for three boundaries that are routinely spoken of
as one:

| boundary | question it answers | ASM-0021's position |
|---|---|---|
| **architecture** | which security decisions are worth proving? | good target — identity separation at an authority boundary |
| **proof** | which semantic facts does the theorem actually depend upon? | in cone; injectivity is a genuine premise |
| **prover** | what can the pinned tool express without distorting production code or inflating trusted assumptions? | out of reach |

Security value HIGH, architectural target GOOD, expressibility on this prover POOR. The
correct response is to record the gap, not to move the other two boundaries until they
agree with the third. Every available way of making Verus reach ASM-0021 works by degrading
one of the first two.

## WP2 is frozen

Six units in, the pilot has answered the questions it was set, and unit #7 would answer
none of them again:

* leaf arithmetic verifies;
* decision predicates verify;
* rich surrounding crypto does **not** automatically enter a theorem's cone (Rule 18);
* typed-verifier discipline verifies;
* orchestration verifies;
* an assumption can be discharged into a proved contract and composed (ASM-0022 → WP3);
* graph invalidation works on real proofs, not fixtures;
* `BLOCKED` propagation, recovery, and the anti-laundering controls hold end to end;
* the issuer refuses stale and upstream-broken evidence (Rules 22–24);
* the prover's current ceilings are measured, with reproducers;
* some high-value claims are currently inaccessible without a bad trade, and that is
  written down rather than worked around.

WP2 is closed except for genuine defects. The result worth stating is not "Verus passed six
things" — it is that we now know **where Verus adds high-value assurance in MCP-RE, where it
does not currently reach, how trusted seams enter a claim, how proof dependencies compose,
and how failure and recovery propagate through real evidence without false-green
laundering.** That is enough to justify the V1 approach and to move effort to the next
ADR-059 objective.

`tools/verification/attest` is the bridge from this evidence into Phase 5 shadow review. It
is not another test command, and it is deliberately not part of `scripts/local_gate.sh`:
the local gate asks whether the working tree satisfies its build and test gates; the
evidence pipeline asks whether a freshness record may be issued for exact inputs that were
actually proven. Only the second may write to the attestation store.
