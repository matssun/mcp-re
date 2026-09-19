<!-- SPDX-License-Identifier: Apache-2.0 -->
# HP-2 — The evidence block's identity coordinates are injective encodings

R6 referral (**residue** of NP-087), `http_profile` cluster. `SOURCE_REVISION: cdb28a93`.
Read-only.

**Filed as** `verification/reviews/packets/adr069-np-087-ratification-2026-09-19.md` — the
`http_profile` R6 cluster's packet **HP-2**. Sibling handles `HP-4`…`HP-8` name packets for
records this slice did not register, and are not filed here.

## 1. The question

Does the owner ratify a theorem stating that the actor-id join and the audience hash — the
two coordinates every replay key, audit record and trusted-key identity in this estate is
built from — are INJECTIVE encodings of their fields, so that no two distinct actors and no
two distinct audiences can produce the same coordinate? Or decline it, leaving 7 controls at
ADR-069 §5 step 1?

## 2. Records covered and control count

**NP-087 residue — 7 controls.** NP-087 holds **11** rows at `cdb28a93`
(`CD-14001…CD-14011`, all `mcp-re-http-profile`, all `lib#block::tests::*`), counted from
`control-dispositions.toml` via `tomllib`.

**Which half landed:** none, yet. The work package described this as "a residue left behind
by a record whose landable half has already merged". **Measured, that is not true at
`cdb28a93`** — see §2.1. The seven below are the residue of the split `ANALYSIS-http-profile.md`
proposes and `PLAN-v2.md` queues; the R2 half has not been written.

| in this packet (7) | not in this packet (4, the R2 half) |
|---|---|
| `actor_id_is_deterministic_and_pinned` | `block_round_trips` |
| `actor_id_is_injective_across_colon_boundaries` | `unknown_field_fails_closed` |
| `separator_cannot_be_forged_across_fields` | `foreign_profile_fails_closed` |
| `the_escape_marker_itself_does_not_create_a_collision` | `empty_artifact_bindings_fails_closed` |
| `a_separator_inside_a_field_does_not_collapse_two_audiences` | |
| `audience_hash_is_deterministic_and_b64url` | |
| `different_audiences_on_one_endpoint_hash_differently` | |

The four on the right are contained by **THM-0015**, statement, match-verified: *"the request
evidence block parsed and validated under the profile tag"*. Re-tested here and confirmed;
they are campaign work, not an owner decision, and this packet does not ask about them.

### 2.1 Correction to the work package's premise

`git show --stat cdb28a93` and its message: HP-S1 registered halves of NP-093, NP-095,
NP-096, NP-097, NP-098, NP-100, NP-103, NP-105 and referred NP-099 whole. **NP-087, NP-088,
NP-089 and NP-094 are named nowhere in it**, and no `[[unit]]` was added by it at all. All
four "residues" in this packet set are therefore PROSPECTIVE: the boundary between the
landable half and the residue is a proposal that has not been executed, so each packet
re-derives and re-tests that boundary rather than inheriting it. HP-1 §2.1 is where
re-testing changed the answer.

### 2.2 The record's title is a two-authority title

NP-087 is titled *"The evidence block is injective and closed"*. The **"and"** is the ADR-061
question-1 signal, and it is accurate rather than sloppy: the record really does hold two
independently describable authorities — block closure (4 rows, THM-0015's) and coordinate
injectivity (7 rows, nobody's). The title is not a mis-title; it is a correct description of
a record that should never have been one proposition.

## 3. Why existing authority does not answer it

The injectivity of the actor-id join is **asserted as a premise, in a ratified theorem, and
established by none**.

**THM-0034**, statement, match-verified against `git show cdb28a93:verification/policy/theorems.toml`:

> The coordinate is `ActorIdentity.subject`, and NOT `ActorIdentity::actor_id()`. The
> composite is the injective `role:trust_domain:subject:keyid` join, and it is the canonical
> coordinate for replay keys, audit records and trusted-key identity.

That sentence *names the property and then declines to claim it*: THM-0034's own claim is a
binary relation over the **subject**, its unit is `proxy.request_peer_binding` in a different
Cargo project, and its scope says *"Exact-subject equality is the only relation here."* The
composite's injectivity is consumed there as background, never established.

**THM-0079**, statement, match-verified:

> The replay five-tuple — profile id, signature label, actor id, audience hash, nonce — is
> pre-serialized onto the core cache's three slots with a separator that cannot appear in any
> component, so equality of the composite slots holds exactly when the full five-tuple is
> equal; every component discriminates; and a key admitted once is reported as a replay
> thereafter.

This is the closest call in the cluster, and it fails on a quantifier. THM-0079's
biconditional is over the five-tuple **as a tuple**: slots equal ⟺ tuple equal. It is
satisfied whenever the tuple is well defined. It says nothing about whether *actor id* is
itself an injective function of `(role, trust_domain, subject, keyid)`. Two distinct actors
collapsing to one actor-id string produce **equal five-tuples**, so THM-0079 remains true
while the security property fails silently — two principals sharing one replay key, one
audit identity and one trusted-key coordinate.

**The source says so in its own words.** `git show cdb28a93:mcp-re-http-profile/src/block.rs:86-95`:

```rust
/// Escape a single actor-id component so `:` joins stay unambiguous. `%` first
/// (so the escape is reversible), then `:`.
fn field_escape(s: &str) -> String {
    // `%` first (so its own escape is not re-escaped), then EVERY separator any
    // consumer of this string uses. `:` joins the actor-id fields here; U+001F joins
    // the HTTP replay-key components downstream, and leaving it unescaped meant the
    // injectivity that key's construction ASSERTS was not enforced — an actor id
    // containing U+001F could produce the same joined key as a different
    // (actor, audience, nonce) triple.
```

*"the injectivity that key's construction ASSERTS was not enforced"* — a defect that was
real, is fixed here, and is claimed by no theorem. `separator_cannot_be_forged_across_fields`
and `the_escape_marker_itself_does_not_create_a_collision` are its controls.

**THM-0055** excludes the keyid-only reading, scope, match-verified: *"It establishes nothing
about the trust seam, about which keys are enrolled"* — and its claim is over the JWK
thumbprint, one field of four.

## 4. Which subsumption clause fails

**Clause 2 fails**, on the quantifier argument in §3. Injectivity of the ENCODING is not a
decomposition of a biconditional over the DECODED tuple; it is the premise that biconditional
needs and does not carry.

**Clause 3 fails** for the audience arm. *"Two logical audiences multiplexed on one HTTP
endpoint are distinguishable"* (`different_audiences_on_one_endpoint_hash_differently`) is an
externally meaningful product promise — it is the property a multi-tenant deployment behind
one URL depends on, and `AudienceTuple`'s own doc comment (`block.rs:200-203`) says the
`route` discriminator exists *"so audience binding is not aliased by a shared HTTP
endpoint"*. That is a deployment topology MCP-RE supports, promised by no theorem.

**Not merely because the file sits in a shared `paths` tail.** `src/block.rs` is in the
`paths` of **eleven** units at `cdb28a93` and in the `tested_symbols` of two
(`http_profile.artifact_verification_boundary` holds
`lib#block::tests::opaque_binding_with_reference_fields_fails_closed` and
`…reference_binding_missing_fields_fails_closed`). The seven here fall on the far side of
the line this cluster's hazard defines: **inside successors' `paths`, and outside every
successor's `description`.** `http_profile.artifact_verification_boundary`'s description,
match-verified, is *"The closed artifact-type dispatch of full-request verification: a
binding reported verified matched one explicitly supported typed verification branch…"* —
no coordinate, no join, no hash. Registering seven injectivity controls there because
`block.rs` is in its `paths` is precisely the §5 quiet widening, and this packet exists so
that argument is not made.

## 5. Proposed theorem text

- **statement** — The evidence block's two identity coordinates are injective encodings of
  the fields they join. `ActorIdentity::actor_id()` escapes every separator any consumer
  uses — `%` first so the escape is reversible, then `:` for its own join and U+001F for the
  replay key's — before joining `role:trust_domain:subject:keyid`, so distinct field tuples
  produce distinct actor ids: a separator inside a field cannot migrate across a field
  boundary, the escape marker itself cannot manufacture a collision, and the encoding is
  deterministic and pinned to a golden form. `AudienceTuple::audience_hash()` is a
  deterministic unpadded base64url digest over the audience identity, target URI and optional
  route, carrying no prefix, and two audiences differing in any of the three hash
  differently.
- **security_consequence** — Every downstream key in this estate is built from these two
  coordinates: the THM-0079 replay five-tuple, the audit record's actor field, and the
  trusted-key identity THM-0034 names. A collision in either coordinate is therefore not a
  local defect but a shared identity — two principals sharing one replay admission, one
  audit attribution and one key binding, with every downstream check still passing. The
  concrete instance is on record: an actor id containing an unescaped U+001F could produce
  the same joined replay key as a different `(actor, audience, nonce)` triple, so the
  injectivity the replay key's construction asserts was not enforced. THM-0079 remains true
  under such a collision, because its biconditional quantifies over the decoded tuple.
- **scope** — THE ENCODINGS, NOT THE FIELDS AND NOT THEIR AUTHORITY. It says nothing about
  whether the role, trust domain, subject or keyid are correct, who resolved them, or whether
  the actor is trusted — those are the trust seam's and THM-0014's. It does not restate
  THM-0079's replay biconditional; it is that biconditional's missing premise, in the
  opposite direction. It is not a collision-resistance claim about the digest: as in
  THM-0079's scope, the hash is an opaque primitive here, and
  `different_audiences_on_one_endpoint_hash_differently` establishes discrimination over
  concrete audiences, not a cryptographic bound. It does not establish that the actor-id
  encoding is DECODABLE, only that it is injective — no consumer in this workspace parses it
  back, and a claim that it could be would need its own evidence.
- **depends_on** — `[]`. It is a premise, not a consumer; it must not depend on THM-0079 or
  THM-0034, both of which consume it. An edge in either direction from those two would invert
  the argument.
- **review_requirement** — `Owner security-specification review`.

### 5.1 An alternative the owner may prefer, and its price

The property could instead be added to **THM-0079**'s statement. That is an edit to a
fingerprinted field and this packet does not recommend it, but it is priced in §8 so the
choice is informed.

## 6. Units that would support it

One. A second would be an artefact of the file, not of the authority.

| unit | paths | test_features | symbols | exist today |
|---|---|---|---|---|
| `http_profile.identity_coordinate_encoding` | `mcp-re-http-profile/src/block.rs` | none (default lib lane) | the seven `lib#block::tests::*` in §2 | yes, all 7 |

`evidence_class = "tested"`; `direct_consequence_severity` **critical** (the registry's
value for NP-087, and this packet does not argue it down: a shared identity coordinate is a
replay-admission and audit-attribution bypass).

**A `paths` caution.** `src/block.rs` is large and already carries other authorities'
controls. The unit above takes the whole file because `field_escape` and `actor_id` live in
it; if the owner wants a tighter boundary, the honest move is to split `block.rs`, not to
narrow the `paths` to a line range the gate cannot express.

**N1, effective severity critical ⇒ a demonstrated falsifier:**

| probe | anchor | weakening | expect_red |
|---|---|---|---|
| `mutation://http_profile/identity_coordinate/field_escape` | `fn field_escape` in `block.rs:88-96` | return `s.to_owned()` — the pre-fix behaviour the comment describes | `actor_id_is_injective_across_colon_boundaries`, `separator_cannot_be_forged_across_fields`, `a_separator_inside_a_field_does_not_collapse_two_audiences`, `the_escape_marker_itself_does_not_create_a_collision`, `actor_id_is_deterministic_and_pinned` |

This is an unusually strong falsifier: the weakening is a real historical state of the code,
and the comment at the anchor names the defect it reintroduces.

The audience arm needs its own, because deleting `field_escape` leaves it green:

| probe | anchor | weakening | expect_red |
|---|---|---|---|
| `mutation://http_profile/identity_coordinate/audience_hash_inputs` | the digest input assembly in `AudienceTuple::audience_hash` | drop `route` from the hashed input | `different_audiences_on_one_endpoint_hash_differently` |

If that second probe does **not** go red, the audience arm is not evidenced by this battery
and the unit should carry only the actor-id arm — this packet would rather the owner learn
that before ratifying than after.

## 7. Lane correspondence — measured, not assumed

`mcp-re-http-profile/src/lib.rs:53` is a bare `pub mod block;` — no feature gate. `block.rs`
contains **18** `#[test]` functions and **two** `#[cfg(feature = "verify")]` attributes, at
lines **43 and 45**, both above Verus spec items in the production half and neither over a
test. `grep -c '#\[ignore'` = 0. Crate features at `cdb28a93` are `verify` alone.

All seven controls therefore compile and run under `cargo test -p mcp-re-http-profile --lib`
with `test_features` unset, which is the lane the proposed unit names. **None compiles to
zero tests in that lane.**

## 8. Fingerprint consequence

New theorem, `depends_on = []`, one new unit, no existing field touched. `_dependency_closure`
(`tools/verification/_fingerprint.py:683-704`) walks downward; `fingerprint_theorem`
(`:707-727`) does not include `supported_by`. **Granting this packet moves ZERO existing
fingerprints.**

**The §5.1 alternative is NOT free.** Adding the injectivity clause to THM-0079's `statement`
changes `theorem_claim`, so THM-0079's fingerprint moves — and, because `_dependency_closure`
is transitive, so does every theorem with THM-0079 in its closure. Measured at `cdb28a93`,
THM-0079 has **no dependents** (`depends_on = []` on THM-0079 itself, and no theorem names it
in `depends_on`), so the blast radius is **THM-0079 alone** — one re-ratification. That is
cheap, and the owner may reasonably prefer it. The reason this packet still proposes a
separate theorem is §3's quantifier argument: folding a premise into the claim it supports
makes the claim self-supporting, which is the shape ADR-069 is built to prevent.

## 9. What the owner is NOT being asked

Not to rule on the four block-closure controls (THM-0015 contains them; campaign work). Not
to claim collision resistance of any digest. Not to claim the actor id is decodable. Not to
re-ratify THM-0034 or THM-0079 — unless the owner takes §5.1, which is offered and priced,
not recommended.

## 10. If declined

The seven controls stay `new-proposition` at ADR-069 §5 step 1. The terminal state is
specific and worth stating plainly: **THM-0034 and THM-0079 both rest on an injectivity
property that this estate tests on every PR and claims nowhere**, and the `field_escape`
comment remains the only place in the tree where that dependency is written down.
