# Per-site escape-hatch registration — 2026-09-07

`R9-C037` / `R9-C067` / `R9-C068`, from [#739](https://github.com/matssun/mcp-re/issues/739).
The owner ruling of the v0.17 objective settles the design question the earlier measurement
left open: **per-site registration, not a count ratchet.**

The reason is worth keeping. A count ratchet is weaker than it looks — with ten registered
hatches, one legitimate hatch can disappear and an unrelated new one appear while the count
stays ten, and the gate stays green although the semantic trust boundary moved. A count is
not an identity.

## What the registry said before

`registered_by_unit()` returned `{unit_id: {mechanism_kind}}` and `is_registered` answered by
membership. `scope` names whole crates, so `ASM-0024` — `verus:uninterp`, scoped to five
units — licensed **every present and future uninterpreted spec function** in every file those
units declare. The registry recorded

> this unit trusts uninterpreted spec functions

which is not a fact about any seam.

## Step 1 of the recorded order was already done

The earlier measurement's first instruction was to strip comments in `scan()`, because
`PRODUCTION_MECHANISMS` matched `\bexternal_body\b` against whole lines and prose counted as
a seam. That landed with `_seams.code_of`, whose docstring records the two examples on
`main`. **Re-measured rather than assumed**: the census is now 55 sites, none of them a
comment. The "59, of which 4 are prose" figure is dated.

## The site key

`<repo-relative path>#<qualified item>`, from `_seams.item_at`.

- **The item, never a line number.** A line number moves when a comment is added above it,
  and a registry that goes stale on formatting is one people regenerate without reading.
- **Qualified by the enclosing `impl`/`mod`.** `mcp-re-http-profile/src/block.rs` declares
  `actor_id` twice — in `impl ActorIdentity` and in `impl ResolvedActor`. An unqualified key
  would make two seams one site, and registering either would license both.
- **`assume_specification[ X ]` is answered from its own brackets**, bracket-balanced rather
  than non-greedy: `<[T]>::split_last` contains a `]`, and the prototype's non-greedy match
  truncated it to `<[T` — a key that silently merged two different standard-library seams.
- **Literals are removed before braces are counted**, so a `{` inside a string does not open
  a block and mis-attribute every item after it.

All 55 sites resolve to a key, and no two share one. A seam that resolved to no item would be
UNREGISTRABLE and the gate says so rather than inventing a key — the same fail-closed
direction as the rest of this change, and the earlier prototype's "11 resolve to no nameable
item" no longer occurs.

## The rule

A seam is registered iff some assumption satisfies **all three**:

| conjunct | why it is not implied by the others |
|---|---|
| the MECHANISM matches | trusting an uninterpreted spec function is not trusting an `external_body` |
| a unit in `scope` declares the file | a trusted computing base belongs to the unit whose proofs rest on it |
| `sites` names this seam | a seam is a place a proof stops proving, and the registry is a statement about places |

**An assumption with no `sites` registers nothing.** That is the fail-closed direction and
the only one available: "absent means all" is the rule being replaced. `sites` is therefore
the one OPTIONAL key in the schema and is excluded from `_ASSUMPTION_REQUIRED` — making it
required would force an entry to name seams before the decision about which seams it covers
had been taken, which is how the kind-level rule came to license every future site.

**A registration naming no live seam FAILS**, which is the same defect read backwards. A site
key survives formatting but not a rename or a deletion, and an entry left pointing at a seam
that no longer exists records trust nothing in the tree still needs.

`sites` enters every consuming fingerprint with no further work: `assumption_digest` is a
canonical digest of the whole entry, so widening a `sites` list derives DIRTY_ASSUMPTION for
every unit in that assumption's scope — exactly as widening a `scope` already did.

## The allocation

55 seams. **25 are the ones the existing entries actually describe**, and those allocations
are determined rather than chosen: each entry's `description` already names its symbol
(`u8::is_ascii_digit`, `VerifierPolicy::max_clock_skew`, `ActorIdentity::actor_id` /
`ResolvedActor::actor_id`, `labeled_digest`), and sixteen of the sites carry an `ASM-NNNN`
comment in the source beside them, which corroborates the mapping without being read as
evidence for it.

**30 were being covered silently**, and that is the finding this change exists to surface.
They are the `Ex…` type specifications in `mcp-re-http-profile/src/verus_std_specs.rs` that
let a Verus specification NAME the profile's own datatypes. Under kind-level registration
they were `[registered]` because *some* entry in their units used the mechanism; no entry
described them.

Two new premises, because there are **two propositions, not thirty**:

- **ASM-0045** — each `Ex…` declaration mirrors the datatype it names, so a specification
  about the mirror is a specification about the real type. Nameability, not meaning: no impl,
  derive or accessor is in scope. 27 sites.
- **ASM-0046** — three of those are additionally OPAQUE (`ExVerifierPolicy`,
  `ExProfileAlgorithm`, `ExVerificationKey` carry `external_body`). The weakest premise in
  the registry: opacity REMOVES the ability to reason about a representation rather than
  adding a claim about one, and the accessors are registered separately (ASM-0007/8/9). 3
  sites.

Site granularity is not assumption granularity. Splitting one proposition into thirty entries
would say nothing more while making the registry unreadable; what per-site registration buys
is the **future** site — a twenty-eighth `Ex…` declaration does not become trusted by
inheriting these entries. It fails the gate until somebody decides it belongs, which is the
whole content of the change.

## What did NOT come back to the owner

Nothing. The earlier investigation stopped because the required trusted proposition for ~55
seams was unclear and it declined to write them unreviewed. It is not unclear now: 25 are
described by entries that already exist, and the remaining 30 are two uniform propositions
about type mirroring and type opacity, each stated once with its own discharge condition.

## Still open in #739, and not touched here

**Fork-PR verification integrity (`R9-C025`).** The decisive control is repository and
Actions configuration, not something a workflow file can prove about itself — a file-based
fork guard lives in the file a fork PR's merge ref supplies. It is an owner decision about
whether outside contributors are accepted now, and it does not gate v0.17.
