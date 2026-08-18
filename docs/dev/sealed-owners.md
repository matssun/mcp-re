# Sealed owners and the composition root

The rules this implements are in [`CLAUDE.md`](../../CLAUDE.md) — **R-SEAL** and
**R-COMPOSE**. This file records which owners are sealed, what each one projects, and how
to seal the next one.

## The failure mode being removed

> The invariant is enforced at a construction site, but the constructed value does not own
> the invariant.

Validation existed at every one of these owners. The defect was that correctness depended
on remembering where and how to construct the value — so the system could only say *if you
possess this value, and everyone constructing it remembered the rules, the invariant
probably holds*, where it needs to say *if you possess this value, my invariant holds*.

`ReplayState` stated the gap in its own doc comment:

> *"Outside this crate the only way to obtain a value is `classify_and_validate`, so a
> caller cannot hand itself a `SharedRedis` whose quorum parameters no validator ever
> saw."*

Every consumer of `ReplayState` is **inside** this crate. The seal held against none of
them.

## The mechanism

`#[non_exhaustive]` and `pub(crate)` bind only *other crates*. An owner's consumers —
`app.rs`, `startup_plan.rs`, `cli.rs`, `http_profile_serve.rs`, `tls_plane.rs`,
`serving_capabilities.rs` — all live in `mcp-re-proxy`, the same crate as the owners. The
only lever that works at that distance is **module privacy**:

```rust
pub struct ReplayState { kind: ReplayKind }   // public type, private field
enum ReplayKind { … }                          // private to the owner's module
```

Consumers then reach the state only through named projections on `impl ReplayState`.

## Sealed owners

| owner | module | projections |
|---|---|---|
| `ReplayState` | `config_state/replay.rs` | `materialization_plan()`, `durability_tier()`, `required_feature()` |
| `ReplayPlan` | `config_state/replay.rs` | `store() -> PlannedStore<'_>`, `tier()`, `needs_control_runtime()` |
| `ContinuationControlState` | `config_state/continuation_control.rs` | `continuation_plan()`, `is_shared()` |
| `ContinuationControlPlan` | `config_state/continuation_control.rs` | `shared_store() -> Option<&str>`, `needs_control_runtime()` |
| `AdmissionState` | `config_state/admission.rs` | `enforced() -> Option<EnforcedAdmission<'_>>`, `is_enforced()` |
| `RetentionState` | `config_state/evidence.rs` | `directory() -> Option<&str>`, `is_on()` |
| `McpTransportContractState` | `config_state/mcp_transport_contract.rs` | `enforced_versions() -> Option<&[String]>`, `is_enforced()` |
| `TrustRevocationState` | `config_state/trust_revocation.rs` | `epoch_source() -> Option<EpochSource<'_>>`, `reload_cadence()`, `tier()`, `declared_window_secs()`, `push_channel_is_inert()`, `has_networked_epoch()` |
| `CrlRevocationState` | `config_state/transport.rs` | `client_revocation_plan()`, `paths()`, `reload_cadence_secs()`, `is_enforced()` |
| `ClientRevocationPlan` | `config_state/transport.rs` | `paths()`, `reload_cadence_secs()`, `is_enforced()` |
| `TlsCustodyState` | `config_state/tls_custody.rs` | `exported_key_path()`, `delegated_pkcs11_label()`, `delegated_aws_key_id()`, `delegated_gcp_key_version()`, `is_delegated()` |
| `CustodyState` | `config_state/custody.rs` | `material() -> CustodyMaterial<'_>`, `disk_secret_paths()`, `locators_are_filesystem_paths()`, `is_non_exporting_device()` |

A plan produced by an owner lives **with that owner**, not in `startup_plan.rs`.
`startup_plan` re-exports it. The plan is the owner's projection of its own validated
state, so building it in the planner was the planner restating the owner's semantics.

## Borrowed views

Where a consumer must still branch — materialization has to pick a backend client —
the owner hands out a **borrowed view**: `PlannedStore<'a>`, `CustodyMaterial<'a>`,
`EnforcedAdmission<'a>`, `EpochSource<'a>`.

A view is matchable, so selecting a backend still reads naturally, and borrowed, so it is a
way to READ a state and never a way to assemble one. Holding a `CustodyMaterial` does not
let you build a `CustodyState`.

## What sealing found

- `ReplayPlan::Redis { url, tier: Linearizable }` was an ordinary expression in any module.
  The startup audit line would have advertised a durability guarantee no store implements.
- `AdmissionState`'s two enforcing variants carried identical fields, and the gate was
  built by destructuring both — so the enforcement level and the authority key it enforces
  under were paired only by the caller doing it correctly.
- `replay_plane`'s tests materialized `ReplayPlan::Redis { tier: SingleStoreFailClosed }`,
  a tier `classify` refuses. The "backend not compiled in" refusal was being proven against
  a plan no configuration can reach.
- `McpTransportContractState::Enforced { versions: vec![] }` was constructible;
  `is_enforced()` called it true and the request path had nothing to check against.
- `key_files_read_from_disk` in `app.rs` reconstructed a security answer — which secrets
  land on local disk, for a permissions floor — out of two owners' representations.

## Sealing the next owner

1. Make the representation private: `pub struct X { kind: XKind }`, `enum XKind` private.
2. `cargo check -p <crate> --all-targets`. **The error list is the consumer set.** It is
   the measurement; greps and audit findings are not.
3. For each error ask *what does this consumer actually need to know?* The answer is
   normally much narrower than the fields it was destructuring. Name that projection.
4. Where the consumer must branch, give it a borrowed view rather than the representation.
5. Tests that built the state as a literal go through the owner's classifier — see
   `config_state::test_support`. A literal can express combinations the classifier refuses;
   a fixture built through it cannot.
6. State the theorem the seal makes available: not *this constructor checks X* but *every
   inhabitant satisfies X*.

Never work around a compile failure with `#[non_exhaustive]`, a runtime re-check, or a doc
note. The failure is the boundary detector; those consume the signal.

## Property 1 needs no separate witness here

*Illegal state cannot be publicly constructed* is the first completion property, and the
obvious way to evidence it is a compile-fail test. **For these owners that would prove the
wrong thing.**

A `trybuild` case, and equally a ```compile_fail doctest, compiles a standalone file as a
SEPARATE crate. It can only witness the crate boundary — that a downstream crate cannot
construct the value. The consumers that mattered here are all *inside* `mcp-re-proxy`, and
the crate boundary already held against them before any of this work: that is exactly what
`ReplayState`'s "outside this crate" doc comment claimed, while the seal held against none
of its actual callers.

The in-crate seal is instead enforced **continuously, by every build**. With the
representation private to the owner's module, the violating expression cannot be written
anywhere in the crate and still compile — there is no file that could hold the negative
case, because such a file would not build. `cargo check -p mcp-re-proxy --all-targets`
passing IS the witness, and it is a stronger one than a single pinned case: it re-proves
the property over the whole crate on every run rather than over one example.

What a compile-fail lane would still be worth: pinning the *crate*-boundary claims for
types re-exported to SDK or integration consumers. That is a narrower property than the one
this campaign was about, and it is not a prerequisite for any owner above.

## Open

Nothing structural. The remaining owners (`ChannelBindingState`, `DelegatedSigningFacts`,
`ServerIdentityFacts`, `AuditState`, `VerifiedContextState`) carry no representation a
consumer reads: measured at 0 external destructuring sites each, and the fieldless ones
have no illegal inhabitant to exclude.
