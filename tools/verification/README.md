<!-- SPDX-License-Identifier: Apache-2.0 -->

# `tools/verification/` — the central wrappers

The executable half of ADR-MCPRE-059. Policy, model, and proofs live in
[`verification/`](../../verification/).

These are the only supported entry points. ADR-MCPRE-059's "What must not happen"
list opens with the failure mode they exist to prevent: every module inventing its own
proof convention, every engineer pinning a different tool version, arbitrary local scripts
where a central wrapper would do. Add an operation here rather than beside the thing that
needs it.

Stdlib Python only. They are analysis tooling, not production code, and they must run
before any verification toolchain exists — which is exactly the state they are in now.

## The commands

| Command | Does | Today |
|---|---|---|
| `verify` | umbrella; runs the lanes in the ADR's CI order and reports one verdict | works, report-only |
| `verify --gate` | authoritative mode: a failing lane fails the build | works |
| `verify --manifests` | validate the policy files and stop | works |
| `verify-tests` | runs each unit's declared test battery, by target | works |
| `check-assumptions` | the proof escape-hatch gate | works |
| `fingerprint` | deterministic `ReviewFingerprint` per unit | works, partial components |
| `evidence-graph` | declared units and typed edges | works; freshness is Phase 4 |
| `verify-verus` | full `cargo verus verify` for the declared scope | refuses — Verus unpinned |
| `verify-lean` | lake build and theorem check | refuses — pipeline unpinned |
| `regenerate-lean` | Charon → LLBC → Aeneas → Lean extraction | refuses — pipeline unpinned |
| `check-generated` | drift gate for BOTH generated artifacts: the Lean model and the assurance views | works for the views; Lean reports "nothing to drift" |
| `generate-views` | renders `verification/generated/` from the three catalogues | works |
| `review-frontier` | minimum review obligation | Phase 4; falls back to everything-dirty |
| `review` | theorem fingerprints, review state, and the establishment conjunction | works |

`_manifest.py` is the shared loader. Its validation is strict: an unknown key is a
failure, not an ignored field, because a mistyped security declaration must not read as an
absent one. `_theorems.py` loads `verification/policy/theorems.toml` — the `THM-NNNN`
security claims — under the same rule, and `verify --manifests` validates it with the
others.

A theorem holds the human claim and two edges: `supported_by = ["unit://…"]` and
`depends_on = ["THM-…"]`. Everything below the claim keeps its existing owner, so a key
restating a `[[unit]]` fact is refused by name, and a support edge that resolves to no unit
fails closed rather than deriving an empty — and therefore vacuously satisfied — closure.
`_review.py` derives the human-review axes. An approval is a record naming the fingerprint it
reviewed (`verification/reviews/`), never a field on the object approved, so weakening a claim
takes specification review dirty while every prover stays green — the property T2 exists to
establish. Review records are source, unlike attestations, because a human approval is not
re-derivable by re-running anything.

`_views.py` renders the generated assurance views under `verification/generated/`, gated by
`check-generated` — the same staleness owner as the Lean model, not a second gate. It owns
one fact, the set of views that exist, so the generator and the drift gate cannot disagree
about it; the renderers sit beside it split by what they read — `_theorem_views.py` for the
registry alone, `_catalogue_views.py` for the derivations crossing all three catalogues,
`_view_format.py` for the do-not-edit banner every page carries. That split is the
invalidation boundary, not a file-length concession: a change to `verification.toml` cannot
alter a byte of the theorem-only views. They are
pure functions of the three catalogues, so they are byte-reproducible and may be committed;
anything that reads the attestation store (the live blast radius, the frontier) stays in
`review-frontier`, because a view of local machine state cannot be checked in. Reverse edges
— an assumption's consumers, a unit's theorems — are computed at render time and never stored.

Structural support is derived: a theorem is *structurally supported* only if a unit supports
it and every theorem it depends on is, which is why an unsupported claim may be declared but
never reads as a supported one. That is a structural property and it is named as one — the
unit's evidence may still be stale, `BLOCKED`, or resting on a dirty assumption. `established`
is deliberately reserved for the later conjunction (structural support AND fresh unit evidence
AND established dependencies AND fresh specification review AND fresh assumption review),
which T2 makes derivable and T3 displays.

## Three verdicts, never conflated

```
PASS      a check ran and was satisfied
SKIPPED   a check could not run, and says why
FAIL      a check ran and was not satisfied
```

A `SKIPPED` lane never counts toward a `PASS`; the umbrella reports `INCOMPLETE` instead.
The repository's standing rule is that a command exiting 0 having measured nothing is
worse than a red one, and a verification platform is the last place to break it.

## Why the unimplemented lanes refuse instead of passing

Every lane that cannot yet do its job exits non-zero or reports `SKIPPED` with a reason.
None of them returns success.

- `verify-verus` / `verify-lean` refuse while their tools are unpinned rather than running
  against whatever is on `PATH`. A proof checked by a prover of unknown identity is not
  evidence, and accepting it is the "stale or mismatched cache accepted as proof" threat.
- They escalate from `SKIPPED` to `FAIL` the moment a unit is declared `V1`/`V2`/`V3`,
  because a unit cannot claim evidence no pinned tool produced.
- `review-frontier` refuses because a partial frontier would emit a smaller set than the
  truth with no signal distinguishing "nothing was invalidated" from "invalidation is not
  implemented". That is under-invalidation — the one failure mode this design treats as
  unacceptable.
- `evidence-graph` reports the declared structure but no freshness state, and emits no
  placeholder for one. A placeholder invites a consumer to read it.

## Negative controls

The validation was verified by breaking it, not by inspection. Each of these was
introduced, observed to fail, and reverted:

| Broken input | Refused with |
|---|---|
| unknown key in a `[[unit]]` | unknown-key failure naming the key |
| `unknown_is_dirty = false` | policy-change refusal |
| unit path matching no file | unknown-provenance failure |
| `sealed` edge on an unexported contract | sealing failure |
| unregistered `assume` under `verification/` | escape-hatch failure |
| the same `assume`, registered | passes, and reports it as registered |
| `V1` unit declared with Verus unpinned | lane escalates `SKIPPED` → `FAIL` |
| a `tested_symbol` renamed in the source | the battery's `--exact` selection matches nothing, and zero-selected is a lane FAIL |
| a `tested_symbol` with no target prefix | malformed-symbol failure, never a default target |
| `test://` evidence with no `tested_symbols` | manifest validation failure — an unrunnable claim is not evidence |
| `supported_by` naming no declared unit | fail-closed refusal, never an empty closure |
| a cycle in a theorem's `depends_on` | cycle failure naming the ring |
| a theorem key restating a `[[unit]]` fact | duplicate-authority failure naming the owning file |
| a stored `review = "approved"` in the registry | refused — an approval is evidence about a fingerprint |
| a theorem no unit supports | declared, and reported as without a structural support closure |
| a theorem statement weakened, prover untouched | specification review `STALE_CLAIM`, unit fingerprint unmoved |
| a premise restated two levels down | every claim above it `STALE_DEPENDENCY_CLAIM` |
| `review_requirement` relaxed | `STALE_REVIEW_REQUIREMENT` — an approval under a stronger bar is not one under a weaker |
| a review record carrying `approved: true` | dropped by the closed record schema; the axis reads `UNREVIEWED` |
| a review record predating the component set | `UNKNOWN`, never `REVIEWED` |
| a stored approval key in any policy registry | `registry_approval_gate` failure naming the file and key |
