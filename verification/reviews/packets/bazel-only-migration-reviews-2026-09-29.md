# Specification reviews after the Bazel-only migration — 2026-09-29

The migration (branch `build/bazel-only-execution`) moved theorem claim fingerprints in two
ways: pure wording about the lane that measures a claim, and two claims whose meaning
changed with the build model. This packet records which reviews were refreshed, which await
the owner, and which were already stale on `origin/main` before the branch.

Measured with `tools/verification/review --json`, comparing each theorem's reviewed claim
digest (`statement`, `security_consequence`, `scope`) with `origin/main`'s and the branch's.

## 1. The bounded wording event — refreshed

Owner ruling, 2026-09-29: the pure "default Cargo lane" → Bazel wording changes are ONE
bounded review event, valid only where the proposition and its scope are unchanged.

Every edit below is one of four spellings of the lane: "measured in the default cargo lane"
→ "measured in the default Bazel lane (`bazel test //...`)"; "a plain `cargo test
--workspace` compiles … to zero tests" → "the crate's default-feature test targets compile …
to zero tests"; "says nothing about it" likewise; "different Cargo packages" → "different
Bazel packages". Each record's `notes` quotes its own lines.

| theorem | moved by |
|---|---|
| THM-0083 | "Cargo packages" → "Bazel packages" |
| THM-0102 | `cargo test --workspace` → default-feature targets |
| THM-0106, THM-0107 | `cargo test --workspace` → default-feature test targets |
| THM-0115, THM-0116 | `cargo test --workspace` → default-feature test targets |
| THM-0108, THM-0109, THM-0110, THM-0112, THM-0113, THM-0118, THM-0120, THM-0121, THM-0122, THM-0124, THM-0125 | default cargo lane → default Bazel lane |
| THM-0077 | dependency only: THM-0102 |
| THM-0092 | dependency only: THM-0106, THM-0107 |

Each lane named is a non-`manual` Bazel test target, checked against
`verification/generated/rust-targets.json` when the wording was changed.

## 2. Substantive — APPROVED by the owner, 2026-09-29

The claim's meaning changed with the build model, so the approval was the owner's. Both were
approved and recorded; the statements below were refined to the approved formulation first.

### THM-0114 — a signed request's freshness inputs are real, and the deterministic ones cannot reach a production build

The protected property is unchanged: the deterministic nonce source and frozen clock are
unreachable from a production build. The MECHANISM the claim states changed, because Bazel
does not unify features.

- **statement** — was: "the feature is not a default one and is enabled for this crate's
  own tests as a dev-dependency only." Now: "the production library target compiles no
  fixture feature, and the one target that does is `testonly`, so no production target can
  depend on it."
- **security_consequence** — was two halves (`default = [...]`; a non-dev dependency). Now
  three parts: the `#[cfg]` on each item, no `crate_features` on `:mcp_re_host`, and the
  fixture flavor `testonly`.
- **scope** — the lane is `//mcp-re-host:mcp_re_host_test`.

What establishes it now: `fixture_boundary::tests::the_production_library_compiles_no_fixture_feature`
and `the_fixture_flavor_is_testonly` (each mutation-checked red), Bazel's own analysis
refusal of a non-testonly consumer (demonstrated with a probe target), and
`scripts/fixture_feature_gate.py` over every target in the graph.

**Approved.** The fixture flavor may be deliberately built as a `testonly` target, but it
cannot enter the dependency closure of any non-testonly/production target: the plain
production library carries no fixture feature, every target that does carry it is
`testonly`, and the graph-wide gate enforces that condition. The statement now says exactly
that.

### THM-0111 — two vocabularies decide what an `mcp-re.*` verdict token says

- **scope** — was: "SCOPED TO THE CARGO/BAZEL WORKSPACE", with both SDKs excluded as
  separate Cargo workspaces with no Bazel target. Now: "SCOPED TO THE RUST SOURCES OF THE
  CRATES BAZEL BUILDS, both SDK bindings included. The TypeScript SDK's `.ts` files spell
  tokens it receives and are not scanned; the clippy activation probes are excluded by
  name."
- the lane is `//mcp-re-conformance:audit_vocabulary_guard_test`.

The claim WIDENED: the scanned set is now every crate package in the build graph's target
table, which includes `sdk/python` and `sdk/typescript` (their Rust sources mint no verdict
token, so the measurement is unchanged at two minting files).

**Approved.** The widened corpus is the correct scope and both SDK Rust bindings belong in it.
`config/clippy-strict` is excluded by name as an activation-probe package, and the
corpus-completeness control requires every Bazel crate package to be scanned or explicitly
accounted for. The theorem is scoped to the first-party Rust crate estate and claims nothing
over TypeScript or Python sources; the scope now says so.

## 3. Mixed — the migration wording plus a change that predates the branch

Not refreshed: a record binds to the whole claim, and the part below was never reviewed.

| theorem | pre-existing change on `origin/main` |
|---|---|
| THM-0105 | the dormant-L1 paragraph rewritten (`replay_plane/backends.rs`, the `async_replay_test` split) |
| THM-0119 | scope names `proxy.trust_resolution_window` and `proxy.trust_reload_cadence` |
| THM-0123 | scope names `client.bind_scope`, `client.accepted_authority`, `client.caller_shape_admission` |
| THM-0126 | scope names `client.response_signer_authorization`, `client.response_binding_disposition` |
| THM-0127 | scope names `client.local_leg_declaration` |

## 4. Stale on `origin/main` before this branch

Unchanged by the migration; listed so the count is complete.

- Own claim: THM-0023, THM-0084, THM-0091 (statement rewritten), THM-0094 (statement
  rewritten), THM-0098.
- Dependency closure only: THM-0024, THM-0029, THM-0031, THM-0033, THM-0034, THM-0080 (all
  through THM-0023); THM-0099 (THM-0098); THM-0074, THM-0075, THM-0076, THM-0082 (several
  premises, including ones this branch moved).
- Never reviewed: THM-0130, THM-0131.

## 5. Claim-correction chains carried forward

THM-0074, THM-0075, THM-0076 and THM-0105 publish on `origin/main` through recorded claim
corrections. The lane wording moved THM-0105's own claim and the other three's premises, so
each chain gained one link under `authority = "bazel-lane-wording-2026-09-29"`
(`verification/claim-corrections/<THM>-bazel-lane-wording-2026-09-29.json`), from the
fingerprint the chain ended at on `origin/main` to the branch's. Every entry quotes its lines.

## 6. Awaiting the owner — `scripts/claim_surface_gate.py` refuses them on this branch

The gate enforces every theorem whose claim moved on the branch. These five moved only by lane
wording here, but each also carries a change from BEFORE the branch that no review or
correction record covers, so neither the bounded event nor a correction link may carry it:

| theorem | unreviewed change on `origin/main` |
|---|---|
| THM-0119 | scope: `proxy.trust_plane_runtime` → `proxy.trust_resolution_window` and `proxy.trust_reload_cadence` |
| THM-0123 | scope: `client.local_ingress_authority` → `client.bind_scope`, `client.accepted_authority`, `client.caller_shape_admission` |
| THM-0126 | scope: `client.response_acceptance` → `client.response_signer_authorization` / `client.response_binding_disposition` |
| THM-0127 | scope: `client.config_lattice` → `client.local_leg_declaration` (a correction, not a rename: `client.config_lattice` was never a registered unit) |
| THM-0082 | premise set grew after its review: THM-0116 became a direct premise in #990 (2026-09-18), adding THM-0108 and THM-0089 transitively. No correction or review record carries the new edge. |

THM-0119, THM-0123 and THM-0126 are ADR-069 unit renames in scope prose. THM-0127 is not a
rename: `client.config_lattice` never appeared in any version of `verification.toml`, so the
sentence cited an authority that was never registered, and its replacement is a scope
correction (`28394a14`). THM-0082's recorded premise digests are NOT unreproducible: the
tree at `1a86f331` reproduces its reviewed fingerprint exactly. The objection this table
originally recorded was withdrawn on measurement; the open item is the unreviewed edge to
THM-0116. A review at the current fingerprint clears the gate, but the evidence for each is in
`bazel-only-specification-review-evidence-2026-09-30.md`, which also records four findings the
fingerprint alone does not show.
