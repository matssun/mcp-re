<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-047 — R6 ratification packet: retaining one exchange twice yields one object

**Disposition:** R6, referred entire. One control, nothing landed, record unchanged in
substance and annotated with this measurement.

**1 control**, `mcp-re-proxy`, rust unit test, **default cargo lane**, carrier
`mcp-re-proxy/src/transparency/durability.rs`:

- `lib#transparency::durability::tests::retaining_the_same_exchange_twice_yields_one_object`

## What it asserts

Two `EvidenceRetention::retain` calls over the same request/response pair return the same
`EvidenceDigest`. The whole assertion is `assert_eq!(first, second)` over two digests. It is
content addressing: the object's NAME is a function of its bytes, so one exchange names one
object.

## Why the mechanism is available and the claim is not

This is the record where the easy route is the wrong one, and it is worth stating because
the next reader will find the same shortcut. `transparency/durability.rs` IS in
`proxy.retention_commitment`'s `paths`, so the selector would resolve, `verify --manifests`
would accept it and the battery would run. Nothing mechanical refuses this row. What refuses
it is that neither theorem over the retention estate claims the proposition.

**THM-0112 names it as somebody else's, by name.** Its scope:

> NOT A CLAIM ABOUT THE STORE. Content addressing, durability, capacity and the fail-closed
> serving posture are elsewhere.

Content addressing is the first of the four. That sentence is what let S-11 register three
NP-048 controls under this theorem while refusing this one: the enumeration is the boundary,
and this control is inside it while those three are not.

**And the *elsewhere* it points at holds no theorem.** `core.content_address` is the unit
over the content-address grammar, and it is one of the twenty units carrying no ratified
theorem — deliberately so, and `verification.toml` records the decision:

> the content-address grammar is registered as an owner and left without one, because "a
> parser accepts exactly what it emits" is a property its controls state directly and a
> theorem would only restate.

That unit is also over `mcp-re-core/src/hash.rs`, not over this store, so even had it
carried a theorem the selector would name a module it does not measure.

**THM-0088 is the other axis.** Its scope:

> It is about WHEN responsibility was accepted and crossed, never about WHAT the retained
> record contains.

Neither *when* nor *what* is *how many*. The operational test agrees: every clause of
THM-0088 — the two stages, the two names, the rename, the opposite drop dispositions, the
withdrawal and its durability — holds unchanged under a store that writes a second object
for a repeated exchange. Nothing in it is falsified by duplication.

## Why it matters enough to keep as debt rather than close

The `if false` is an auditor's count. A chain reconstructed from an archive holding two
records of one exchange shows a call that happened twice, and the auditor has no way to tell
a duplicate from a genuine repeat, because the only thing that distinguishes them is the
addressing rule this control measures.

## What would discharge it

A theorem over the evidence store's object identity — that a retained object's name is a
function of its bytes and therefore that one exchange occupies one object — which would also
give `core.content_address` the reader it currently lacks. Until then the honest state is
one unratified proposition with one control.
