# The measured remainder — 2026-09-07

Priorities 2, 3 and 4 of the v0.17 assurance-closure mandate, measured together because each
turned out to be the same shape: a surface the census called an evidence gap, which on
measurement was partly an ownership gap and partly something else entirely.

## Priority 2 — `mcp-re-host`, four files and zero tests

The crate had **no test in either lane** and **no Bazel test target at all**, so the Bazel
lane said nothing whatsoever about it.

### `signer.rs` is dormant

`HostSigner` has zero consumers. Not the deployable client, not the client proxy, not
`sdk/python`, not `sdk/typescript`, not a test, not the demo surface. Every real signing site
calls `mcp_re_client_core::build_signed_request` directly.

The ADR-MCPS-003 property `HostSigner` documents — a private signing key with no accessor, so
model logic can request a signature and never forge one — **is held on the live path**, by
`mcp_re_client_proxy::McpReProxy`, whose `signing_key` field is private and whose owner is
`client.proxy_request_correspondence` under THM-0084.

Excluded from the registered unit on the `window_policy.rs` / `l1_fast_reject.rs` precedent.
It was given controls for the file-level code standard and is cited by nothing. **Recorded
rather than deleted**: retiring a documented signing-locus expression is an architectural
decision, not an audit's to take.

`mcp-re-client`'s own manifest says what the crate is actually used for: *"the clock and the
OS-CSPRNG nonce source"*.

### A control found a real production bug

`clock.rs` computed a pre-epoch reading as:

```rust
(err.duration().as_secs() as i64).checked_neg().unwrap_or(i64::MIN)
```

and its comment asserted `i64::MIN` was the answer for magnitudes past the boundary. It is
not. `(2^63 + 1) as i64` wraps to `i64::MIN + 1`, and `checked_neg` on that succeeds with
`i64::MAX`.

**A clock set unrepresentably far before the epoch reported the furthest instant in the
FUTURE** — which every freshness window accepts, and which is precisely the "fabricated
plausible time" the comment says must never happen.

Unreachable on a real host, and the code claimed a property it did not have. Fixed with
`try_from`, so the magnitude is refused before it is negated. The arithmetic was extracted to
a pure function first, because `SystemTimeError` is not constructible and a control over
`now_unix` could never have reached that arm at all.

### A second control measured the carrier

The signer controls first used `"nonce-1"` as a nonce and were refused with
`MalformedEvidence("nonce is below the 128-bit entropy floor")`. That is the carrier's floor
holding, measured rather than assumed.

### The fixture boundary got its own owner

Audit #81 made the deterministic fixtures an **enforced** boundary. It has two halves that
fail independently:

| half | how it fails alone |
|---|---|
| the `#[cfg]` on each item | a fixture item without it compiles into every build |
| the feature not being default | `default = ["test-fixtures"]` satisfies every `#[cfg]` in the crate with no source line changing |

A third way in is a non-dev self-dependency, which would enable the feature for every
downstream consumer. All three are now controlled, from the source and manifest that are
actually built (`include_str!`, at compile time), in `fixture_boundary.rs` — a module with no
production item, because the fact is a property of the crate's build configuration and neither
of the two modules whose types it protects can state it about the other. `Cargo.toml` is a
unit path for exactly that reason.

## Priority 3 — the transparency remainder

The census's instruction was explicit: do not absorb the five files into an existing unit
simply for coverage. Measured, they are three different things.

`proxy.retention_commitment`'s own declaration already draws the line — `retained_record.rs`
and `covered_set.rs` are deliberately absent from it because *what* a hop contains is a
different authority from *when* responsibility was accepted, and THM-0088's scope names it in
the other direction.

### `retained_record.rs` had zero controls

Seven added: the round trip, both exclusion directions, the schema token refusing an unknown
shape, `deny_unknown_fields` refusing an unrecognized field, an undecodable body refused
rather than read as empty, and the written token being the accepted one.

The round trip is what stops the exclusion control being satisfiable by deleting everything.

`RETAINED_HOP_SCHEMA` moved from `transparency/mod.rs` into `retained_record.rs` and narrowed
from `pub` to `pub(super)`: the record is its only reader anywhere in the tree, and it was
public for a consumer that does not exist.

### The third widening was named and misplaced

The module documents three ways a sender can make `signature-input` look wider than it is: a
signature PARAMETER, a decoy dictionary MEMBER, and a component's own PARAMETERS. The third
had a control — in `durability.rs`, testing `covered_set`'s rule, cited by no unit, carrying an
orphaned doc comment whose first line had been lost to an earlier edit.

Moved to the module that owns the rule rather than duplicated. A fourth was added: the covered
set is read from *this* label's member only, so a response's own list cannot decide what a
request retains.

### `durability_bounds.rs` and `mod.rs` join the retention unit

Not for coverage. `MAX_RESERVATIONS` could be changed to 1 and THM-0088 would still read
`FRESH` — the bounds **are** that unit's argument (the queue is twice the ceiling so `complete`
is never refused for capacity), and they were a fingerprint input belonging to no unit.

### `attestation.rs` is an ownership gap, not an evidence one

Three controls already existed in `transparency_e2e_test.rs` and no unit cited any of them.

## Priority 4 — `remote_signer_call`, both realizations

This closes the gap THM-0108's scope names by name:

> How a failed remote-signer call is classified, and whether it arms the handshake-path
> throttle, is `remote_signer_call`'s authority. It has no unit, it is gated on
> `any(aws_kms_keysource, gcp_kms_keysource)` — the shape that makes a single-feature lane
> silent about the other — and it is recorded as a named gap rather than absorbed here.

**Both realizations measured separately:** 14 controls under `aws_kms_keysource` alone, 15
under `gcp_kms_keysource` alone. The two are different *types* — `RemoteSignerFailure::after`
and `::describe` are GCP-only, because Cloud KMS has a refused-bearer-token retry and AWS
SigV4 re-signs per call and has no round to chain a cause from.

Two units, on the `proxy.continuation_materialization` / `_shared` precedent: whichever lane
runs, the other's control does not exist, so a single unit would name a battery member that is
absent half the time. The GCP unit measures **one** control — what its realization adds and
the other cannot — because everything the two arms share runs in both lanes already.

### An evidence gap inside the ownership gap

The module tested only its **parts** — `is_load_shedding_status` and `json_string_field` — and
`quota_verdict`, the rule that composes them, had **no control at all**.

Five added, over both providers' real data shapes: a shed-load status is exhaustion whatever
the body says (a front-door 429 states no service error shape at all, so reading the body first
would leave the window unarmed); a stated name arms the window at each provider's own path,
with AWS's namespace suffix compared rather than the whole string; a body that states no name
arms nothing; one provider's vocabulary does not arm the other's window; and a call that got
no answer arms nothing.

The negative direction is the one that matters most: a permanent misconfiguration classified
as exhaustion becomes a permanent *local* refusal that hides the misconfiguration it came from.

## The standing supply-chain red

`cargo deny` had been failing on `main` for at least four merges — `5b385e41`, `740bb7bb`,
`7d6ffbc7` and `86e868c8`, the accepted v0.17 baseline — on a yanked `wnaf 0.14.0` reached
transitively through `primeorder`. Not caused by any of those diffs, and not a reason to leave
a supply-chain gate red: updated to `0.14.1` in all three lockfiles, and `cargo deny check`
now reports advisories, bans, licenses and sources ok.
