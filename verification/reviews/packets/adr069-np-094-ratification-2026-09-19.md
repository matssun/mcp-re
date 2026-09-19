<!-- SPDX-License-Identifier: Apache-2.0 -->
# HP-9 — A refusal is a document, and its wire code is read only after the signature verifies

R6 referral (**residue** of NP-094), `http_profile` cluster. `SOURCE_REVISION: cdb28a93`.
Read-only.

**Filed as** `verification/reviews/packets/adr069-np-094-ratification-2026-09-19.md` — the
`http_profile` R6 cluster's packet **HP-9**. Sibling handles `HP-4`…`HP-8` name packets for
records this slice did not register, and are not filed here.

## 1. The question

Does the owner ratify a theorem stating that on this profile a REFUSAL is itself a signed
document whose content is read ONLY after its signature verifies — an unsigned rejection is
untrusted, an indeterminate rejection says so rather than inviting a retry, and a rejection
body gains no fields the ordinary path does not have — or decline it, leaving 5 controls at
ADR-069 §5 step 1?

## 2. Records covered and control count

**NP-094 residue — 5 controls.** NP-094 holds **13** rows at `cdb28a93` (`CD-15027…CD-15034`
= 8 in `lib#error::core_projection::tests::*` and `lib#error::tests::*`; `CD-15067…CD-15071` =
5 in `lib#rejection::tests::*`), counted from `control-dispositions.toml` via `tomllib`.

| in this packet (5) | not in this packet (8, the R2 half) |
|---|---|
| `an_ordinary_rejection_body_gains_no_new_fields` | the 5 `error::core_projection::tests::*` |
| `bound_rejection_verifies_and_exposes_the_wire_code` | the 3 `error::tests::*` |
| `the_indeterminate_rejection_states_that_a_retry_is_unsafe` | |
| `unsigned_rejection_is_untrusted` | |
| `wire_code_is_read_only_after_signature_verifies` | |

The eight on the right are contained by **THM-0111**, statement, quoted verbatim and
match-verified against `git show cdb28a93:verification/policy/theorems.toml`:

> Every other taxonomy that reaches the wire states which of those verdicts it IS, through an
> exhaustive projection with no wildcard arm, and derives its token from that projection
> rather than keeping a table beside it: **the RFC 9421 carrier**, the replay-tier dispatch
> gate, the PDP relation adapter (which returns a `PolicyError`, never a string), and the
> client seam's binding-spec refusal.

*The RFC 9421 carrier* is `mcp-re-http-profile`'s `error::core_projection`, named in the claim
while having no unit of its own (THM-0111's three units are
`conformance.verdict_vocabulary_scope`, `policy.authorization_taxonomy`,
`client.binding_spec_refusal`). Re-tested here and confirmed R2; campaign work, not an owner
decision, and this packet does not ask about them.

### 2.1 The record's title describes the minority of its rows

NP-094 is titled *"A refusal carries its own provenance and is read only after verification"*
and its `carrier` field is `mcp-re-http-profile: src/rejection/mod.rs`. Measured, **8 of its
13 rows are in `src/error/core_projection.rs` and `src/error.rs`** and measure verdict
projection — a different authority with a different theorem (THM-0111). The title and the
carrier are true of **5 of 13**, which are the five in this packet. This is the same defect
class as NP-103's ("dispatch", measures replay), and it matters here for a specific reason:
an owner reading NP-094's title and being shown its 13-row count would be asked about a
13-control refusal proposition that does not exist. **The question in §1 is phrased over the
5 measured rows only.**

### 2.2 Correction to the work package's premise

The work package describes this as a residue "left behind by a record whose landable half has
already merged". Measured: `git show --stat cdb28a93` and its commit message show HP-S1
registered halves of NP-093/095/096/097/098/100/103/105 and referred NP-099. **NP-094 is named
nowhere in it, and HP-S1 added no `[[unit]]` at all.** The split above is therefore proposed,
not executed; this packet re-derives it rather than inheriting it.

### 2.3 One proposition?

Tested. The five are one: *a refusal is a document, and nothing in it is believed before its
signature is.* `unsigned_rejection_is_untrusted` and
`wire_code_is_read_only_after_signature_verifies` are the ordering rule;
`bound_rejection_verifies_and_exposes_the_wire_code` is its positive control (the code IS
available once verification succeeds, so the rule is not a refusal to ever read);
`an_ordinary_rejection_body_gains_no_new_fields` is the closure that stops the refusal path
being a side channel; `the_indeterminate_rejection_states_that_a_retry_is_unsafe` is the one
value the document must be able to say and that a default would get wrong. No split.

## 3. Why existing authority does not answer it — including the two units that already hold
its neighbours

`src/rejection/mod.rs` contains **8** `#[test]` functions, and **three are already
registered**:

- `http_profile.bound_response_shared_facts` holds
  `lib#rejection::tests::tampered_message_does_not_change_the_trusted_wire_code` and
  `lib#rejection::tests::spliced_rejection_onto_a_different_request_fails`;
- `http_profile.unbound_response_shared_facts` holds
  `lib#rejection::tests::unbound_rejection_verifies_without_request_context`.

So the tempting move is obvious: put the other five in beside them. **Re-tested, and it
fails.** `http_profile.bound_response_shared_facts`, `description`, quoted verbatim and
match-verified against `git show cdb28a93:verification/policy/verification.toml`:

> The facts EVERY bound-response operation establishes, whichever of the three returned Ok:
> the covered `Content-Digest` agreed with the body, the parameters were admitted as current
> under a policy-accepted algorithm, and the signature verified over a base whose `;req`
> components resolved against the request being answered.

Three conjuncts, all about what a successful verification establishes. **Nothing about a wire
code, about reading order, about an unsigned document, or about retry safety.**
`bound_rejection_verifies_and_exposes_the_wire_code` is the closest of the five and still
fails: its first half is contained, its second half — *and exposes the wire code* — is the new
clause, and registering the control there would silently extend the unit's sentence by that
clause. That is the ADR-069 §5 quiet widening, performed one control at a time.

**THM-0021**'s statement is the same three conjuncts, match-verified, and its scope,
match-verified, narrows rather than extends: *"It says WHO the signature was accepted under
and never WHY that signer is acceptable."*

The estate's refusal theorems are elsewhere and exclude this by their own words:

- **THM-0046**, scope, match-verified: *"It does not establish that every production refusal
  site is inside the exchange lifecycle, that the audit record is written, **or that the
  refusal is signed**"* — and its unit is `proxy.refusal_provenance`, in `mcp-re-proxy`.
- **THM-0061**, statement, match-verified: *"a rejection body carrying no execution contract
  yields the silent one rather than a guess … The wire code and the contract are read in one
  parse."* This is the client-side twin — `client.execution_contract`, whose `paths` are
  `mcp-re-client-core/src/execution_contract.rs` and `…/result_classification.rs`. It is about
  what a client makes of a rejection body it already has, not about when the server's document
  may be read.

## 4. Which subsumption clause fails

**Clause 2 fails.** The proposition is an ORDERING constraint — *verify, then read* — and
THM-0021's and THM-0022's claims are conditionals on a successful return. A conditional on Ok
says nothing about what may be read before Ok is reached; the ordering rule is precisely the
part that is not derivable from it.

**Clause 3 fails.** *"An unsigned refusal is untrusted"* and *"an indeterminate refusal says a
retry is unsafe"* are externally meaningful promises: they are what stops an off-path attacker
ending an exchange by injecting an unsigned `mcp-re.*` refusal, and what stops a client
retrying an operation whose execution status is unknown. THM-0046's scope declines the first
in its own words (*"or that the refusal is signed"*), which is the estate confirming the gap
rather than filling it.

**Not because the controls sit inside a shared `paths` entry — and this is the cluster's
hazard in its sharpest form.** `src/rejection/mod.rs` is in **two** successors' `paths` AND
three of its controls are in their batteries. The five here are *inside a successor's `paths`
and outside every successor's `description`*, which is exactly the line this cluster's prior
analysis drew and the campaign accepted. The three already-registered neighbours are not
precedent for the five; they are the demonstration that the boundary is a sentence, not a
file.

## 5. Proposed theorem text

- **statement** — A refusal on this profile is a signed document, and nothing it says is read
  before its signature verifies. A rejection whose signature has not verified yields no wire
  code — an unsigned rejection is untrusted rather than partially believed — and a rejection
  whose signature HAS verified exposes the wire code it carries. The document's vocabulary is
  closed the same way the ordinary path's is: an ordinary rejection body gains no fields
  beyond those the profile already defines. One value is stated rather than defaulted: a
  refusal reached at a point where execution may or may not have occurred is INDETERMINATE and
  says so, so that a retry is known to be unsafe rather than assumed safe.
- **security_consequence** — The excluded outcome is an unsigned refusal that ends an
  exchange. A wire code read before verification is a string an off-path attacker can supply,
  and it is acted on — logged as the reason, surfaced to the caller, used to decide whether to
  retry — with all the credibility of the server that never sent it. The indeterminate arm
  excludes the second, quieter failure: a refusal whose execution status is unknown, reported
  as a clean not-executed, invites a retry of an operation that may already have run. A
  default is the wrong answer there in exactly one direction, and it is the direction that
  duplicates side effects. And the no-new-fields closure keeps the refusal path from becoming
  a channel the ordinary path is not: a refusal document that may carry arbitrary extra
  members is a place to put things nothing checks.
- **scope** — THE REFUSAL DOCUMENT ON THIS PROFILE'S SERVING SIDE. It establishes nothing
  about WHICH refusal a given failure is — the carrier's verdict projection is THM-0111's,
  and its groupings are a ratified owner decision that no guard can check. It does not
  establish that every production refusal site is reached, that an audit record is written, or
  that the refusal's cause is correct — those are THM-0046's and the serving path's, and
  THM-0046 explicitly declines the signing question this claim answers. It is not THM-0061:
  that is the client's reading of a rejection body it already holds, in another Cargo project.
  It says nothing about whether the signature is valid or whose key made it, which are
  THM-0021's and THM-0022's; this claim is about the ORDER, and is conditional on their
  machinery rather than restating it.
- **depends_on** — `["THM-0021", "THM-0022"]`. Named exactly, and both are used: "read only
  after the signature verifies" is only meaningful relative to what verifying establishes, and
  a refusal may be bound (THM-0021) or unbound (THM-0022) — the claim covers both arms, so
  both are premises. THM-0046 is NOT a premise: it is another project's refusal-vocabulary
  claim and this argument does not consume it.
- **review_requirement** — `Owner security-specification review`.

## 6. Units that would support it

One.

| unit | paths | test_features | symbols | exist today |
|---|---|---|---|---|
| `http_profile.refusal_document_order` | `mcp-re-http-profile/src/rejection/mod.rs`, `mcp-re-http-profile/src/rejection/retry_contract.rs` | none (default lib lane) | the 5 `lib#rejection::tests::*` rows (`CD-15067…CD-15071`) | yes, all 5 |

**A `paths` overlap the owner should see:** both files are already in
`http_profile.bound_response_shared_facts`'s `paths` (and `rejection/mod.rs` in
`http_profile.unbound_response_shared_facts`'s). Granting this makes `rejection/mod.rs`
dirty-detect for three units. That is legitimate — `paths` is a dirty-detection surface, not
an ownership claim — and it is the correct outcome here: three authorities genuinely read that
file.

`evidence_class = "tested"`; `direct_consequence_severity` **critical** — the registry's value
for NP-094. Note that the registry's `critical` was assigned to the whole 13-row record; for
these five the packet argues it is still right (an unsigned refusal ending an exchange is an
authenticity bypass), unlike the NP-151 precedent where the divergence was flagged.

**N1, effective severity critical ⇒ a demonstrated falsifier. Two arms:**

| probe | anchor | weakening | expect_red |
|---|---|---|---|
| `mutation://http_profile/rejection/verify_before_read` | the verification call guarding the wire-code projection in `rejection/mod.rs` | `let _ = verify…` and return the wire code regardless | `unsigned_rejection_is_untrusted`, `wire_code_is_read_only_after_signature_verifies` |
| `mutation://http_profile/rejection/indeterminate_is_not_not_executed` | the indeterminate arm in `rejection/retry_contract.rs` | map indeterminate onto the not-executed outcome | `the_indeterminate_rejection_states_that_a_retry_is_unsafe` |

The second weakening is the one a plausible simplification would make — collapsing a
three-valued retry contract to two — and it is the reason `retry_contract.rs` is in the
`paths`.

## 7. Lane correspondence — measured, not assumed

`mcp-re-http-profile/src/lib.rs:72` is a bare `pub mod rejection;` — no feature gate.
`src/rejection/mod.rs`: **8** `#[test]` functions (5 in this packet, 3 already registered
elsewhere), `grep -cE '#\[cfg\(feature|#\[ignore'` = **0**. Crate features at `cdb28a93` are
`verify` alone (the Verus lane).

Lane: `cargo test -p mcp-re-http-profile --lib`, `test_features` unset and required to stay
unset — the same lane the two units already holding this file's controls run in, so no lane
boundary is crossed. All 5 compile and run there. **None compiles to zero tests in that
lane.**

## 8. Fingerprint consequence

New theorem, `depends_on = ["THM-0021", "THM-0022"]`, one new unit, no existing field edited.
Re-verified at `cdb28a93`: `_dependency_closure`
(`tools/verification/_fingerprint.py:683-704`) seeds from the NEW theorem's `depends_on` and
walks **downward**, so THM-0021's and THM-0022's claim digests — and transitively THM-0001's,
since both `depends_on = ["THM-0001"]` — enter the NEW theorem's closure and nothing enters
theirs. `supported_by` is not one of `fingerprint_theorem`'s five components (`:707-727`).
**Granting this packet moves ZERO existing fingerprints.**

The eight-row R2 half (§2) is also fingerprint-free: a new unit appended to THM-0111's
`supported_by`, which is not a component.

Conditional cost, priced and not proposed: amending **THM-0046**'s scope to delete *"or that
the refusal is signed"* would edit `theorem_claim` and move THM-0046's fingerprint — and,
transitively, **THM-0111**'s, which `depends_on = ["THM-0046"]`. Two fingerprints. This packet
does not propose it: THM-0046's unit is in `mcp-re-proxy` and the sentence is true of it.

## 9. What the owner is NOT being asked

Not to rule on the eight verdict-projection rows (THM-0111 contains them; campaign work). Not
to rule on WHICH verdict a carrier failure is — THM-0111's scope says that is a separate
ratified decision (MCPRE-92) and *"no guard can see"* it. Not to re-ratify THM-0046 or
THM-0021/THM-0022. Not to fix NP-094's title or carrier field (§2.1 is a registry-hygiene
correction for the campaign).

## 10. If declined

The 5 controls stay `new-proposition` at ADR-069 §5 step 1. The terminal state is stated in
another theorem's own words: THM-0046's scope says it *"does not establish … that the refusal
is signed"*, and after a decline nothing else does either — while three of this file's eight
controls sit in two units' batteries, making the gap look smaller than it is.
