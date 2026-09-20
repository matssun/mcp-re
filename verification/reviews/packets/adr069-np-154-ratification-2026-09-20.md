<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-154 residue — R6 ratification packet: the shipped auditor, and the fail-closed retention posture

**Disposition:** R1 in part, R6 for the residue. Two of NP-154's seventeen controls landed as
`tested_symbols` of `unit://proxy.retention_commitment` under THM-0088, falsifier
`M354-proxy-the-pre-dispatch-reserve-is-skipped`, demonstrated red. Fifteen rows remain, in
**four** describable propositions. NP-154's `[[proposition]]` entry and record stay in place.

Nothing here is a claim that the fifteen are unevidenced. Each is a live, passing control. The
finding is that no RATIFIED theorem contains what it asserts, so registering it would make a
theorem's battery claim something the theorem wrote down that it does not.

## The lane, measured first — and it is not the lane the plan named

The slice's analysis recorded this carrier's lane as `async_serve`. Measured:

| selection | `transparency_e2e_test` controls |
|---|---|
| `cargo test -p mcp-re-proxy --features async_serve --test integration_async -- --list` | **23** |
| `cargo test -p mcp-re-proxy --test integration_async -- --list` | **23** |

`transparency_e2e_test.rs` carries no `#![cfg(feature = "async_serve")]` — six of its siblings
in the same binary do, and it is not one of them. The battery is therefore a DEFAULT-lane one,
`test_features` is correctly absent from `proxy.retention_commitment`, and declaring
`async_serve` on it would have named a lane the evidence is not taken in. This is the same
determination `proxy.retention_commitment` already recorded for
`tests/integration_async#root_key_lifecycle_test::…` one unit over.

**A second lane fact, for the six auditor rows.** They are selected exactly like any other
`tests/integration_async#` name, but they do not RUN like one: each spawns the shipped
`mcp-re-auditor` through `mcp_re_test_paths::resolve_runfile("MCP_RE_AUDITOR_CLI")`, which
under Bazel reads the target's injected runfile and under cargo falls back to
`target/<profile>/mcp-re-auditor` and PANICS if it is absent. So `cargo test` alone is not the
lane; `cargo build --workspace --bins` first is. A unit registering them would own that
precondition, and no field in `verification.toml` states it today — `test_features` names
crate features, not a built sibling binary. That is a second reason these rows are not a
`tested_symbols` addition to anything.

## Residue 1 — the fail-closed serving posture (3 rows)

`CD-19252` `an_exchange_whose_evidence_cannot_be_retained_is_refused`,
`CD-19254` `retention_is_off_by_default_and_nothing_is_kept`,
`CD-19261` `the_serving_constructor_still_proves_the_archive_writable`.

THM-0088 was the proposed home. Its scope, verbatim:

> It says nothing about which HTTP refusal each failure earns — that is the serving owner's,
> under THM-0078.

> It is about WHEN responsibility was accepted and crossed, never about WHAT the retained
> record contains.

`CD-19252` asserts a status and a frozen refusal code and nothing else, which is the first
sentence exactly. Its sibling `a_retention_store_that_cannot_accept_the_call_refuses_before_the_backend_runs`
asserts the same pair AND that the inner backend ran zero times, and it is the dispatch count —
not the status — that puts it inside this claim; that row landed.

`CD-19254` runs a deployment with no store at all. THM-0088's whole subject is two durable
stages under two names; a deployment that publishes neither has no crossing for a claim about
when one was accepted to be about.

`CD-19261` calls `EvidenceRetention::open` against a `0555` directory and
`RetainedArchive::open_read_only` against the same path, and asserts the asymmetry. Opening is
not a stage. The nearest ratified home is THM-0077, whose `supported_by` already carries the
sentence in terms —

> an unopenable retention directory refuses rather than resolving to OFF — the "silent
> reinterpretation into a weaker posture" verbatim

— for `unit://proxy.serving_capability_posture`. That unit's `paths` are
`serving_capabilities.rs`, and its two retention controls are `lib#` tests of the CLASSIFIER.
`CD-19261` measures `transparency/durability.rs` and `transparency/retained_archive.rs`
instead, so placing it there would require widening `paths` into the retention machinery. The
same is true of `CD-19252` under THM-0078's `proxy.refusal_site_totality`, whose existing
`each_pre_dispatch_fault_earns_its_own_answer` is its `lib#` twin: admissible in principle,
but it is a different proposition from this slice's, and it is recorded here rather than
taken.

**Referred as:** one proposition — *a deployment that turned retention on refuses what it
cannot account for, and one that did not keeps nothing* — to be placed under THM-0077/THM-0078
by an owner who may move a `paths` list.

## Residue 2 — the shipped auditor binary (6 rows)

`CD-19246`, `CD-19250`, `CD-19251`, `CD-19253`, `CD-19255`, `CD-19260`.

THM-0113 was the proposed home, and the clause-2 question the analysis raised — *is "the CLI is
the caller that does this" a decomposition, or a new promise about a deliverable?* — answers
itself out of the theorem's own scope, verbatim:

> NOT A CLAIM THAT THE CHAIN IS COMPLETE OR THAT ITS HOPS VERIFY. The `ChainLabel` reports
> that, and this theorem's content is that the label reaches the caller rather than that it
> says a particular thing.

> OFF THE REQUEST PATH, AND THAT IS THE CLAIM'S PREMISE. A chain is not whole until its last
> hop, the audit posture is the auditor's to choose, and registering against a transparency
> service is network I/O; the serving path retains and does nothing else.

> NOT A CLAIM ABOUT THE TRANSPARENCY SERVICE. Registration, inclusion proofs and the receipt a
> service returns are outside this seam entirely.

Row by row:

* `CD-19260` `the_auditor_binary_turns_a_served_call_into_a_verifiable_attestation` asserts
  `chain().is_complete()` and `correspondence() == BoundToVerifiedCall` — the label saying a
  PARTICULAR THING, which the first quotation excludes by name — and then registers the
  statement and verifies the receipt, which the third excludes by name.
* `CD-19251` `an_audit_posture_the_call_was_not_served_under_attests_an_incomplete_record` is
  the closest of the six: `BoundToSubmissionOnly` carried rather than collapsed is THM-0113's
  own security consequence. But the posture it drives is one the auditor CHOSE, and the scope
  assigns that choice away — *"the audit posture is the auditor's to choose"* — and the
  assertions are again `Incomplete { hop: 0, RequestUnverifiable }`, the label's content.
  `proxy.evidence_attestation` already carries `a_chain_with_no_verified_hop_is_still_attested`
  for the clause that IS THM-0113's.
* `CD-19246` and `CD-19253` assert that a refused run leaves NO artifact on disk, and that the
  service pin is loaded before anything is signed. Both are the binary's output and ordering
  discipline; `attest_chain` neither writes files nor loads pins.
* `CD-19250` asserts the content-addressed archive detects a replaced object. That is the
  store's property. THM-0112's scope hands it away — *"NOT A CLAIM ABOUT THE STORE. Content
  addressing, durability, capacity and the fail-closed serving posture"* — and THM-0088's
  subject is stages and names, not bytes.
* `CD-19255` asserts the binary audits a `0555` archive. That is a deployment capability of a
  shipped executable.

**Clause 3 refuses this independently of clause 2.** *The shipped auditor refuses rather than
writing an artifact describing an audit that did not happen* is an externally meaningful
promise about a DELIVERABLE. It is not a decomposition of a claim about a function's return
value; it is a product behaviour a user could rely on and an operator could observe, and this
campaign's authority is explicitly bounded away from minting one.

**Clause C5 refuses filing it whole.** The six span at least four describable propositions —
artifact-output discipline, pin-before-signature ordering, content-addressed tamper detection,
and read-only archive access.

**Referred as:** four propositions, and the honest parent is a theorem about the shipped
auditor as a deliverable, which does not exist. The auditor tree is largely unclaimed:
`run.rs`, `invocation/**`, `artifact/**`, `inputs.rs`, `refusal.rs`, `profile/**`,
`trust_view.rs` and seven files under `registration/` are in no unit's `paths`. Only the two
mechanism leaves are — and those, per NP-154's own siblings, are themselves theorem-less.

## Residue 3 — registration (5 rows) and residue 4 — the live service (1 row)

`CD-19245`, `CD-19249`, `CD-19256`, `CD-19257`, `CD-19258`; and `CD-19259`.

Untouched by this slice and recorded here only so the residue is whole. Their owners —
`proxy.capsule_anchor_registration_leaf` and `proxy.scrapi_registration_leaf` — appear in no
`supported_by` list in `theorems.toml`, verified at this tree state, and THM-0113's scope
excludes registration in terms (quoted above).

`CD-19259` `the_auditor_binary_registers_with_a_live_external_service` carries a separate
warning, and it is this repository's own named defect in a different costume. The test opens:

```rust
let Some((base, pin)) = live_transparency_service() else {
    println!("SKIPPED and therefore MEASURED NOTHING: ...");
    return;
};
```

With `MCP_RE_LIVE_TRANSPARENCY_SERVICE` unset — every merge-path run — it PASSES having
asserted nothing. Verified at this tree state: the guard is the function's first statement.
Registering it as `tested` would put a green that measured nothing inside an attestation
closure. ADR-MCPRE-068 N4 forbids substituting a class to make it fit; the honest class is not
`tested`, and the honest disposition is a referral.

## What this packet does not do

It creates no `not-evidence` family — the register stands at 13 families / 13 records here —
sets `ratified_as` nowhere, amends no unit `description`, widens no `paths`, and lowers no
`direct_consequence_severity`. The only theorem-level fact it establishes is a negative one:
THM-0088 and THM-0113 do not reach these fifteen controls, in their own words.
