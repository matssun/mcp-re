# The authorization vocabulary's authorities, measured — 2026-09-07

Priority 1 of the v0.17 assurance-closure mandate. The census
(`census-gap-remeasurement-2026-09-06.md`, ranked remainder item 5) left `mcp-re-policy`
wholly unowned — 0/6 files — with the note that it "holds `PolicyError`, and
ADR-MCPRE-066's whole point is that its vocabulary is a second authority; that makes it a
decision about authority rather than a registration."

The owner made that decision on 2026-09-07:

> Do NOT collapse `PolicyError` / `AuthorizationRefusal` / `RefusalCause`. They are
> different semantic authorities. The required work is an ownership/correspondence audit,
> NOT type unification. Ensure there is exactly one semantic authority for each mapping.
> Higher layers must delegate rather than reproduce `PolicyError -> authorization wire
> token`. Do not introduce `PolicyError -> McpReError`.

This is the audit. It measured rather than assumed, and what it found changed the answer
twice.

## 1. The delegation chain was already correct

Every layer above `PolicyError` delegates. Measured, not read:

```text
PdpRelationRefusal::wire_code  -> PolicyError            (returns the VARIANT, not a string)
AuthorizationRefusal::wire_code -> PolicyError::wire_code | McpReError::wire_code
RefusalCause::wire_code         -> asks each arm
```

No layer reproduces the `PolicyError -> mcp-re.authorization_*` table. `PolicyError` has no
projection into `McpReError` and did not acquire one.

One wording correction was needed and is the whole of the change on this axis.
`RefusalCause::wire_code` called itself "the ONLY rendering point", which reads as a claim
to own the subordinate policy-token mapping. It does not; it composes. Corrected to name it
the final PRESENTATION boundary, with the ownership stated where it belongs.

## 2. Three of the six files were a second authority with no consumer

`mcp-re-policy` was measured for consumers outside the crate. Two of five public surfaces
had any; three had none, and each of those three was a second authority over a fact the
RFC 9421 tree already owns:

| file | measured | what owns the fact now |
|---|---|---|
| `block.rs` | 0 consumers | `RequestBlock.artifact_bindings[]`. `docs/architecture/authorization.md` §2.5 already named `extract_authorization_block` a legacy input that must not be reused: it reaches past the verifier into representation and keys off the deleted `_meta` carrier. |
| `decision.rs` | 0 consumers | `AuthorizationPosture` / `AuthorizationRefusal`. `Allow \| Deny(PolicyError)` is strictly weaker: it cannot tell an unconfigured deployment from a permitting one (THM-0056's subject) and it flattens the two refusing authorities (THM-0046's). |
| `wire.rs` | 0 consumers | `mcp_re_proxy::receipt::ResponseSigning`. Refusals are SIGNED and their posture is a decision; an unsigned JSON-RPC envelope is the pre-ADR-MCPRE-050 sidecar shape, and it carried an open low-severity finding (#144) about a fallback emitting the wrong JSON-RPC code. |

Deleted. The crate's dependency closure went with them — it now depends on `thiserror` and
nothing else, which is a stronger statement of the ADR-MCPS-011/012 firewall than the
comment that used to assert it.

`revocation.rs` is retained and is NOT in the registered unit. `LiveTrustResolver`'s
revocation seam is `#[allow(dead_code)]` and documents itself as NOT WIRED; no production
path installs a `RevocationSource`. Excluded on the precedent that kept
`trust_plane/window_policy.rs` out of `proxy.trust_plane_runtime` and
`async_replay/l1_fast_reject.rs` out of `proxy.async_replay_retention`.

## 3. The finding the audit was not looking for: a fifth minting producer

ADR-MCPRE-066 Slice 2 established that exactly one file decides what an `mcp-re.*` token
says, and the conformance guard `no_producer_outside_core_mints_a_wire_token` enforces it
over a list of four producer files. §2.1 of that ADR names the defect in the shape it chose:

> its scope was a hand-maintained list of files, so it described yesterday's producer set on
> exactly the day a producer moved. #637 found a fourth producer it had never been told
> about.

There was a fifth. `mcp-re-client-core/src/binding_spec/refusal.rs` matched
`BindingSpecRefusal` onto two `&'static str` literals — `mcp-re.authorization_binding_type_unsupported`
and `mcp-re.authorization_binding_malformed` — and **both published SDKs render refusals
through it** (`sdk/python`, `sdk/typescript`, via `build_authorization`). A token renamed in
Core would have left two shipped surfaces emitting the old spelling with nothing able to
notice.

Fixed the way Slice 2 fixed the other four: `mcp-re-client-core/src/core_projection.rs` now
holds an exhaustive `From<&BindingSpecRefusal> for McpReError` with no wildcard arm, and
`wire_code` is derived from it.

## 4. The list was replaced by a measurement

Adding the fifth file to the producer list would have repeated the mistake. So the guard
gained a control that does not read a list:

`exactly_two_files_decide_what_a_verdict_token_says` walks EVERY workspace crate's source
tree, takes each file's production half, and asserts the set of files holding a verdict-token
literal is exactly `{mcp-re-core/src/error.rs, mcp-re-policy/src/error.rs}`. The crate list is
derived from the workspace `Cargo.toml` at compile time by
`the_scanned_crate_set_is_the_workspace`, so a new member is scanned or the lane fails.

A **verdict token** is `mcp-re.<name>` with no further dot; the dotted spellings are audit
event types, whose sets three existing controls already pin exactly.

Scoped to the Cargo/Bazel workspace. `sdk/python` and `sdk/typescript` are separate Cargo
workspaces with no Bazel target, so they cannot be delivered as runfiles and a cargo-only
scan would make the lane measure two different things in its two lanes. They are covered by
the producer check on the file they render through.

## 5. The primitive the walk rests on was wrong

`mcp_re_test_paths::rust_source::production_half` is the shared definition of *which lines
are production*, used by several architectural guards and mirrored by
`scripts/module_size_gate.py`. Writing the walk found it broken in the class its own module
documentation warns about.

`brace_significant` blanked ordinary string literals per line. It did not know about raw
strings, and it forgot its state at every newline. `mcp-re-client-core/src/execution_contract.rs`
writes a raw byte string holding JSON across five lines inside a `#[cfg(test)] mod tests` —
`br#"{"error":{"data":{...}}}"#` — and the unbalanced braces closed the region three lines
early. **Twenty-seven lines of test code were measured as production**, by every guard built
on the primitive.

The scanner is now a stateful lexer (`rust_source/brace_scan.rs`) that carries mode across
lines and knows ordinary strings, raw strings with their hash count, character literals,
lifetimes, line comments and nested block comments. Five regression tests cover each shape,
and `scripts/module_size_gate.py` gained the same scanner so the two cannot drift.

**Measured impact of the correction:** 622 tracked `.rs` files, ONE changed count —
`rust_source.rs` itself, 334 → 296, downward. No registered file grew, so the module-size
ratchet is unaffected.

Two files crossed the 200-line threshold as a result of this slice's work, and both were
decomposed along real seams rather than to satisfy the number:

* `rust_source.rs` (296) held two authorities — *which characters are code* and *where a
  test region begins and ends*. The lexer moved to `rust_source/brace_scan.rs`. That is the
  invalidation boundary too: a new literal form cannot alter the region rule, and a change
  to which attributes open a region cannot alter what counts as a brace.
* `source_fallbacks.rs` (203) mixed *where a guard's input lives* with *which test witnesses
  a manifest claim*. The witness map moved to `traceability_sources.rs`; a relocation and a
  re-evidencing are not the same event. The new source-TREE sentinels went to
  `source_trees.rs` for the same reason — a tree entry says *walk everything under here*,
  which is what lets a guard state a property over code nobody listed.

## 6. What is registered

Three units and one theorem.

| unit | owns |
|---|---|
| `policy.authorization_taxonomy` | the frozen ADR-MCPS-013 mapping, and the revoked/unavailable split |
| `client.binding_spec_refusal` | which provider lists are legal, and which Core verdict each refusal IS |
| `conformance.verdict_vocabulary_scope` | how many files decide what a verdict says, measured over the workspace |

THM-0111 states the proposition once, `depends_on = ["THM-0046"]` — that theorem establishes
a refusal reaches the boundary carrying WHICH authority reached it, and this one establishes
that the vocabulary each authority speaks has exactly one owner.

## 7. What the audit deliberately did not change

**`mcp-re.authorization_binding_profile_required` is spelled by both frozen taxonomies**,
with different meanings: Core's is a structured binding presented without a binding profile;
the authorization one is a deployment having configured no authority to validate against.
The JSON-RPC envelope separates them by `data.policy`, and the Core spelling has no
production producer on this tree. Left as measured, and named in THM-0111's scope, because
the tokens are frozen and re-spelling one is an ADR — not something an ownership audit
decides.

**No `PolicyError -> McpReError` projection**, per the ruling. The audit found no place that
wanted one.
