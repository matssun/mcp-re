# The census gap crosswalk, re-measured — 2026-09-06

Backlog item 8 of the v0.17 AFK mandate: "remaining unowned replay/KMS/conformance surfaces
where the census showed real assurance gaps". The census is §4 of
`system-assurance-completeness-audit-2026-08-31.md`, the **boundary action → root
crosswalk**, whose GAP rows are the authoritative list.

The first thing this slice measured is that **the list has decayed**. Five of its rows are
wholly or partly closed by work that landed after 2026-08-31, and two of the three items this
mandate's own earlier slices touched (#581 row 3, #583 deliverable 2) turned out to be
already stated for the same reason. Acting on the audit's entries without re-measuring would
have produced duplicate authorities over facts the tree already holds — which is the failure
ADR-MCPRE-059 rev1 produced three times.

So this slice re-measures the crosswalk rather than implementing from it. The measurement is
mechanical: every unit's `paths` are expanded against the tracked `.rs` files, and each area
is reported as *files owned / files present*, with the units and theorems that cover them.

## The crosswalk today

| census §4 row | 2026-08-31 | measured 2026-09-06 |
|---|---|---|
| Replay / continuation stores | **GAP** | **partly closed.** Continuation store 2/2 owned (`proxy.continuation_correlation_store`, THM-0087). **Replay stores 0/10 owned** — `async_replay/` (8), `shared_replay.rs`, `replay_tier.rs`. The *gate* is THM-0092 with ASM-0040/ASM-0041; the *stores* own nothing. |
| Shared Redis/etcd stores | **GAP** | **open.** 1/5 owned. `async_redis_store.rs`, `async_etcd_store.rs`, `redis_store.rs`, `etcd_store.rs` are the mechanisms ASM-0040/ASM-0041 name, and belong to no unit. |
| Audit / retained evidence / transparency | **GAP** | **partly closed.** 6/11 owned (`proxy.retention_commitment`, THM-0088). Unowned: `attestation.rs`, `covered_set.rs`, `durability_bounds.rs`, `mod.rs`, `retained_record.rs`. |
| Outbound credential acquisition | **GAP** | **partly closed.** 9/23 owned (`proxy.kms_endpoint_authority` THM-0089, `proxy.outbound_destination` THM-0090). The keysources themselves are unowned and carry substantial batteries: `gcp_kms_keysource.rs` (2 660 lines, 39 tests), `aws_sts.rs` (1 507, 26), `aws_kms_keysource.rs` (1 181, 14), plus `kms_keysource/`, `pkcs11_keysource/`, `remote_signer_call/`. |
| Client sidecar local ingress | **GAP** | **partly closed.** 7/15 owned (`client.local_ingress_authority`, THM-0091). |
| SDK client exchange | **GAP** | **closed.** `sdk_python.exchange_path` and `sdk_typescript.exchange_path` are units with measured `test://` evidence across the pinned runtimes. |
| `mcp-re-transport` (9 files) | no unit at all | **unchanged** — 0/9 owned. |
| `mcp-re-policy` (6 files) | no unit at all | **unchanged** — 0/6 owned. |
| Conformance / SCITT | — | 16/18 owned (`http_profile.scitt_*`, THM-0041/0042/0068/0072). The two unowned are `scitt/prototype/{mod,tree}.rs`. |

Also re-measured and closed since the audit, by this mandate's earlier slices or by work
between: #581's row 3 (THM-0080, ADR-MCPRE-064 Slice 2) and #583's §5 refusal inventory
(THM-0081).

## The largest remaining gap in the named triad, and what a slice for it must know

**The replay stores: 0 of 10 files owned.** That is the biggest fully-unowned
security-relevant surface among replay, KMS and conformance, and the census's phrase "the
durability-tier fail-closed claim has no theorem" is now only half true — THM-0092 states the
*gate's* fail-closed order, with ASM-0040/ASM-0041 carrying the mechanisms' durability
premises. What has no owner is the **store seam's own contract**.

A slice for it must know one measured fact before it starts, or it will state a property of
code that does not run:

> **The `L1FastRejectStore` is DORMANT, and the whole release-gate battery goes through it.**
> `app.rs` installs the L2 directly on every backend; nothing outside `async_replay_test`
> constructs an L1; there is no configuration surface that selects one. The module documents
> this itself and the census asked the question mechanically (MCPRE-175 §C): no live
> guarantee rests on it, because an L1 can only ever fast-REJECT.
>
> All five controls of `async_replay_test` — the named CI release gate "§4 cross-core /
> cross-replica replay race" — construct an `L1FastRejectStore`. They are not vacuous: the
> exactly-one-Fresh and fail-closed properties they exercise belong to the shared L2 beneath,
> and the L1 is pass-through on a miss. But **no control measures those properties on the
> composition that ships**, and a unit citing this battery would carry evidence about a
> two-tier architecture no deployment runs.

So the slice is: add controls over `InMemoryAsyncAtomicReplayStore` and the
`AsyncAtomicReplayStore` seam **directly** — exactly one Fresh under concurrency, distinct
keys independent, an outage yielding `Unavailable` rather than any decision, and clean
recovery — then register a unit over `async_replay/{mod,in_memory}.rs` that **excludes
`l1_fast_reject.rs` as dormant**, on the precedent by which `trust_plane/window_policy.rs` was
excluded from `proxy.trust_plane_runtime`. The theorem is then about the store the async path
installs, and the L1's `L1-never-Fresh` invariant stays what it is: a documented property of
defined-but-dormant code, claimed by nothing.

Deferred here rather than done, because it needs new controls in a feature-gated integration
target and a theorem whose statement depends on them; it is not a registration of evidence
that already exists, which is what every other slice in this mandate was.

## Ranked remainder

1. **Replay store seam** — 0/10 owned, shape described above, needs new controls.
2. **Shared Redis/etcd stores** — 1/5 owned; they are the mechanisms ASM-0040/ASM-0041 name,
   so registering them would put the premises' own subjects under an owner.
3. **Keysources** — 9/23 owned; three files carry 79 existing tests between them, so this is
   an ownership gap over evidence that already exists, not an evidence gap. The R9 critical
   lived in this area.
4. **Transparency residue** — 5 files, including the reservation/marker vocabulary.
5. **`mcp-re-transport`, `mcp-re-policy`** — wholly unowned crates. `mcp-re-policy` holds
   `PolicyError`, and ADR-MCPRE-066's whole point is that its vocabulary is a second
   authority; that makes it a decision about authority rather than a registration.
6. **`scitt/prototype/`** — two files, named "prototype"; likely an out-of-scope declaration
   rather than a unit.

None of these is an escalation condition. Each is ordinary work whose first step is the
measurement above rather than the audit's dated entry.
