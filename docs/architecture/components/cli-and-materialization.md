<!-- SPDX-License-Identifier: Apache-2.0 -->

# Component Blueprint: CLI, Legality Residue & Capability Materialization

**Status:** Authority census (ADR-MCPRE-061 §8), MCPRE-142 / issue #578. Investigation only — no code changed by the census.

**Scope split:** this document owns the **target** design for `mcp-re-proxy/src/cli.rs`. Current sealed state lives in [`docs/dev/sealed-owners.md`](../../dev/sealed-owners.md) (ADR-061 §13.1). §9 is the diff.

**Measured on `main` @ `7ec8f92`: 1170 production lines**, 4713 total, by `scripts/module_size_gate.py::production_lines`. The registry and the campaign index both say 1177; the difference is the ADR-MCPRE-065 §11 authorization-flag family moving to `cli/authorization_flags.rs` (95 lines, its own unit).

**On ADR-MCPRE-058.** That ruling made `parse_args` a §14 reviewed exception, and it remains valid. It is **function-granular**, and this census treats it as evidence for neither side of the file's disposition — *review granularity equals exception granularity*. `parse_args` is not re-litigated below; what is examined is what shares its file.

## 1. Purpose

Turn an operator's argument list into a deployment request, and materialize a validated request into the key-custody capability the composition root serves with.

That sentence contains an "and", and the "and" is §4 Q1.

## 2. Authority

### Owns

- **argv syntax and provenance**: flag spellings, value parsing, the CLI's own defaults, and the difference between a value chosen and a value never mentioned;
- **requiredness** — which flags an argument list may not omit;
- **capability materialization**: turning a decided custody state into a `KeySource`, an attested-ingress binding, or an OCSP checker;
- **one legality predicate**: `key_file_mode_is_insecure`.

### Does not own

- **deployment legality.** `ValidatedDeployment` and `unsafe_config_violations` live in `config_state::validation`; this module *calls* them;
- the request model (`deployment_request`), deliberately outside so the state machines do not depend on the parser;
- the configuration state machines (`config_state::*`), which decide what a request means.

**The module doc is one-third stale.** It states that three things live here and names *"[`ValidatedDeployment`] and [`unsafe_config_violations`] — the layer-A boundary"* as the second. They do not live here and have not for some time. What remains at this position is a single call, and the file's own self-description therefore claims an authority it no longer holds.

## 3. Position in the system

```text
argv ──▶ parse_args ──▶ DeploymentRequest ──▶ ValidatedDeployment::try_from ──▶ into_inner()
                                                                                     │
                                                              DeploymentRequest ◀────┘
                                                                     │
main.rs ─────────────────────────────────────────────────▶ app::run(config)
                                                                     │
                                              ValidatedDeployment::try_from  ← again
                                                                     │
                                                  run_validated ──▶ build_key_source(...)
```

The right-hand `try_from` is not a typo in the diagram. See §4 Q7.

## 4. The twelve questions (ADR-061 §8)

### 1. What single security/control fact does this unit own?

None. The honest sentence needs two "and"s: *"argv becomes a request, **and** requiredness is enforced, **and** a validated request becomes a key-custody capability."* The first and third are separated by the entire Layer-A boundary and by `app::run`; they are not two aspects of one fact.

### 2. How many independently describable authorities exist inside it?

**Three**, and they are exactly the three the census issue asked to be distinguished:

| # | authority | proposition | lines |
|---|---|---|---:|
| A | **argv transport** | this argument list denotes this request, with these defaults, and states each value once | 817 |
| B | **legality residue** | this file mode is insecure | 14 |
| C | **capability materialization** | this decided custody state becomes this `KeySource` / binding / checker | 297 |

A is `parse_args` (722), `parse_timeout` + `parse_cert_lifetime` (69), `second_admission_limit` (26). C is `read_pkcs11_pin` (34), `build_attested_ingress_binding` (47), `build_key_source` (205), `build_ocsp_checker` (11).

**A and C never meet.** Nothing in A calls anything in C; the Layer-A boundary and `app::run` sit between them. They share a file and nothing else.

### 3. What does it decide?

Requiredness (A) — the one legality-shaped decision the parser genuinely owns, because "was this flag given" is a fact about the *input*, not about the request. `second_admission_limit` is the same shape and its doc explains precisely why it cannot move to the boundary: `InFlightLimitRequest` holds one limit, so a request naming both is unconstructible and the boundary has no state left to refuse.

`key_file_mode_is_insecure` (B) decides a permission posture. It is a pure predicate about a `u32`.

### 4. What does it merely execute?

C, entirely. `build_key_source` selects a constructor per `CustodyMaterial` arm; it performs no I/O itself and re-decides nothing — the custody state already decided. `read_pkcs11_pin` executes filesystem reads.

### 5. What does it merely transport?

A, entirely — that is its job, and the module doc says so: *"it decides no deployment legality, which is why any other way of building a request reaches the same answer."*

### 6. Does it reconstruct decisions now owned by `config_state::*`?

**No, and this is the unit's genuine strength.** The census went looking for the classic drift — a parser that re-decides what a state machine owns — and did not find it. `parse_args` reads `InFlightLimitRequest::Unspecified` rather than applying a default; the delegated-signing rotation defaults are `DelegatedSigning`'s constants, not local numbers; `has_delegated_tls` is computed *for the struct literal* with a comment explicitly disclaiming it as a check ("whether the two custodies may be asserted together is relation X2b's"); `build_key_source` matches on `CustodyState::material()` instead of re-reading the request.

A previous round of this campaign clearly did this work, and it holds.

### 7. What security relationship exists only through call ordering?

**The proof of validation is created, discarded, and recreated.**

`parse_args` ends with `ValidatedDeployment::try_from(config).map(ValidatedDeployment::into_inner)` — it validates, then **unwraps**, returning a bare `DeploymentRequest`. `app::run` then calls `ValidatedDeployment::try_from` **again**, recomputing every state machine.

`into_inner`'s own doc says the wrapper is *"named rather than a public field so the wrapper cannot be reconstructed around an unchecked `DeploymentRequest`"* — the seal exists, is earned in `parse_args`, and is opened one line later.

**This is not a hole.** `app::run` re-validates, so a mutated or hand-built request still meets the boundary and the path fails closed. What it costs is representational: the argv path's type says nothing about having been validated, the work is done twice, and the one place where the proof is genuinely available throws it away.

The pipeline relationship the module doc calls "the order is the pipeline" is therefore held by ordering, in a codebase that has a type for it.

### 8. What public interface exists only because tests need it?

`key_file_mode_is_insecure` is `pub` and its doc says it was *"factored out of `main.rs`'s key-file-permission check so the warn-vs-reject decision is black-box testable without touching the filesystem"* — a stated testability factoring of a pure predicate, which is legitimate. Its production caller is elsewhere; it is the one item of B and it does not belong to the CLI at all.

Otherwise the public surface is small (6 public functions over 1170 lines) and each has a production consumer.

### 9. What branches are unreachable under the current legality model?

`build_ocsp_checker` is `#[cfg(feature = "online_ocsp")]` and, per THM-0013, is handed no `Require` deployment in any build — the same three-gate structure EX-006 measured. `build_attested_ingress_binding` materializes Mode C, which Layer-A refuses (EX-005). Both are correctly retained.

So **two of C's four items materialize capabilities no validated deployment can select** — a fact about C's cohesion rather than a defect in either.

### 10. What facts are represented more than once?

The **validation** itself (Q7). Nothing else: the census specifically looked for duplicated defaults, duplicated requiredness, and duplicated custody interpretation, and found single owners for each.

### 11. Can callers bypass the Layer-A checks that the parser enforces?

**Yes, for requiredness — and the file says so itself.**

`parse_args`'s `require` closure enforces eleven required flags (`--bind`, `--audience`, `--server-signer`, `--server-key-id`, `--target-uri`, `--trust-domain`, `--tls-cert`, `--client-ca`, `--trust`, …). Those fields are public `String`s on `DeploymentRequest`, and the boundary does not re-check emptiness for the identity coordinates. A test comment in this very file states the consequence:

> *"Requiredness for these lives in `parse_args`'s `require` closure, and the fields are public `String`s — so an embedder or a test that builds the struct reaches the serving path with an empty coordinate and no parser runs."*

The same comment records why the exposure is bounded — nothing dereferences those coordinates; they are minted into what the proxy signs and compared by verifiers, so an empty one *"fails no startup step, it just stops distinguishing this deployment from another that also set none"*.

That is an honest assessment and it is still a **parser-only rule on a public field**, which is precisely the shape the residue module exists to eliminate (`docs/architecture/review-dispositions.md` EX-002's family). The `--client-ocsp`, `--revocation-list` and `--authz reference` refusals were all moved to the boundary for this reason; requiredness was not.

### 12. Which lane proves parsing, which legality, which materialization?

**158 unit tests in one module, classified by what they actually call:**

| what it proves | tests | how |
|---|---:|---|
| parsing / argv transport | **119** | call `parse_args` |
| legality | **23** | call `boundary_reports` → `unsafe_config_violations`, or build a `ValidatedDeployment` |
| materialization | **6** | call `build_key_source` / `read_pkcs11_pin` / `build_ocsp_checker` / `build_attested_ingress_binding` |
| helpers and pure predicates | 10 | — |

**One lane must not stand in for another, and here it nearly does.** The 23 legality tests live in the CLI's test module and reach the boundary through a local helper; they are testing `config_state::validation`, from inside `cli.rs`. They are good tests in the wrong file — the same observation EX-005 recorded about `transport.rs` reaching into `communication_assurance`.

And **materialization has 6 tests for 297 lines**, against 119 for A's 817. C is the least-tested authority in the file by an order of magnitude, and it is the one that constructs key custody.

## 5. Theorem inventory

Registry: [`verification/policy/theorems.toml`](../../../verification/policy/theorems.toml). Referenced, not restated (ADR-061 §12).

**Measured: 0 of 33 entries are owned by this unit.** THM-0013 concerns a refusal this module's `build_ocsp_checker` is downstream of, but its owner is `proxy.online_ocsp_reachability`.

| proposition | scope | evidence/unit | status |
|---|---|---|---|
| A request `parse_args` returns has met the Layer-A boundary | local | true by construction, then **discarded** (Q7) | **structural, unstated — and the type that would state it is unwrapped** |
| An argument list may not state one admission limit twice | local | `second_admission_limit` | structural, no registry entry |
| A required flag's absence is refused | local | the `require` closure | **structural — and holds for argv only** (Q11) |
| `build_key_source` selects the custody the state decided, never a re-read of the request | relation | matches on `CustodyState::material()` | structural, no registry entry |

The first row is the interesting one: the proposition is *true*, it is *earned*, and the codebase has the type to carry it. Stating it as a theorem would be premature while the value is thrown away at the moment of proof.

## 6. Test/evidence inventory

| property | test/evidence | lane | note |
|---|---|---|---|
| argv → request, defaults, provenance, refusals | 119 unit tests in `cli.rs` | `cargo test -p mcp-re-proxy --lib` · `//mcp-re-proxy:proxy_unit_test` | the ADR-058 exception's own evidence |
| Layer-A legality reachable from a hand-built request | 23 unit tests in `cli.rs` (via `unsafe_config_violations`) | same | **testing `config_state::validation` from inside `cli.rs`** |
| Materialization | 6 unit tests in `cli.rs` | same, plus feature lanes for the KMS arms | **6 tests for 297 lines of key-custody construction** |
| Legality through `app::run`, however the request was built | `tests/integration/app_startup_characterization_test.rs`, `config_legality_characterization_test.rs`, `config_refusal_precedence_test.rs` | `//mcp-re-proxy:integration_test` | the lane that proves the bypass-resistance the parser cannot |
| The documented command line starts | `tests/integration/documented_cli_test.rs` | `//mcp-re-proxy:integration_test` | runs the real parser *and* the real boundary |

**No vacuous row.** All executed for this census.

## 7. Implementation map

`mcp-re-proxy/src/cli.rs` — **1170 production lines** on `main` @ `7ec8f92`.

| lines | region | authority |
|---|---|---|
| 1–42 | module doc + imports | — |
| 43–764 | `parse_args` | **A** — ADR-058 §14 reviewed exception |
| 765–790 | `second_admission_limit` | A |
| 791–804 | `key_file_mode_is_insecure` | **B** |
| 805–838 | `read_pkcs11_pin` | **C** (filesystem + secret) |
| 839–907 | `parse_timeout`, `parse_cert_lifetime` | A |
| 908–954 | `build_attested_ingress_binding` | C |
| 955–1159 | `build_key_source` | C |
| 1160–1170 | `build_ocsp_checker` | C |

Child module: `cli/authorization_flags.rs` (95) — A, and the model for how a flag family should live.

### 7.1 — re-measured at the ADR-MCPRE-067 Phase-9 closure

`mcp-re-proxy/src/cli.rs` — **230 production lines**. B and C are gone; A is what is left, and it
is one authority (EX-007's Phase-9 re-run).

| lines | region | note |
|---|---|---|
| 1–38 | module doc + the fourteen child declarations | corrected: it no longer claims the Layer-A boundary or the `KeySource` builders live here |
| 40–63 | `struct Flags` | the family list, projection 1 of 3 |
| 65–174 | `impl Flags` — `take_switch`, `take` (projection 2), `finish` (projection 3) | no decision; each family already answered its own question |
| 176–195 | `refused_or_unknown` | the routing table's answer for the empty case, incl. the `--pkcs11-pin` refusal |
| 197–200 | `require` | shared by four families |
| 202–229 | `parse_args` — **22 production lines** | orchestration and the hand-off to layer A |

Fourteen flag families now live under `cli/`, four of them as owner subtrees
(`admission_flags/`, `peer_identity_flags/`, `signing_source_flags/`, `runtime_flags/`).

## 8. Outcome — move the materialization out; `parse_args` keeps its exception

Question 2 answered three, and the split is unusually clean: **A and C never call each other.** The Layer-A boundary and `app::run` sit between them, so this is not a case where separating authorities costs locality — there is no locality to lose.

**1. Move C — capability materialization (297 lines) — to its own owner.** A module named `cli` that reads a PKCS#11 PIN off the filesystem, constructs KMS-backed key sources, and builds an attested-ingress binding is not a CLI module. `app::run_validated` is C's only consumer, and C's input is a *decided* `CustodyState`, not an argument list. The natural home is beside the other materializers (`signing_plane`, `trust_plane`, `serving_capabilities`), not beside a parser.

**2. Move B — `key_file_mode_is_insecure` (14 lines)** — to whichever owner performs the permission check. It is a legality predicate about a file mode and has no relationship to argv.

**3. Then `cli.rs` is ~860 lines of A**, of which `parse_args` is 722 and already a recorded §14 exception. The residue is the flag-family pattern `authorization_flags.rs` established, and whether more families follow it is a question for the *next* census of this file, not this one.

**4. Stop discarding the validation proof (Q7).** Whether `parse_args` should return a `ValidatedDeployment` — and `app::run` take one — is a real design question with a real counter-argument (`app::run` must remain callable by an embedder that never met a parser, and re-validating is how that stays true). The census does not rule on it; it records that the proof is earned and thrown away, and that the double validation is the observable consequence.

**5. Record requiredness as a parser-only rule (Q11).** Either it moves to the boundary like its three predecessors, or the fields stop being public `String`s. The file's own test comment already argues the exposure is bounded; that argument should live in a disposition record, not in a test.

**`parse_args` is not reopened.** ADR-058's exception stands, and nothing in this census bears on it.

## 9. Known deviations

| deviation | status |
|---|---|
| Capability materialization (297 lines, incl. filesystem + secret handling) lives in the CLI module | **this census's finding**; move proposed |
| The validation proof is created, discarded, and recreated; the argv path validates twice | **this census's finding**; recorded, not ruled |
| Requiredness is a parser-only rule over public `String` fields | **this census's finding**; the file documents the consequence in a test comment |
| The module doc claims the Layer-A boundary lives here; it lives in `config_state::validation` | recorded |
| 23 legality tests test a neighbour's owner from inside this file | recorded |
| 6 materialization tests for 297 lines of key-custody construction | recorded |
| Two of C's four builders materialize capabilities no validated deployment can select | not a defect — EX-005/EX-006 territory, correctly retained |
| Index and registry say 1177; the file is 1170 | corrected in this change |
| `parse_args` at 722 lines | **ADR-058 §14 reviewed exception, not reopened** |

**Status of the deviations at the ADR-MCPRE-067 Phase-9 closure:**

| deviation | status |
|---|---|
| capability materialization in the CLI module | **discharged** — Phase 8 moved C to `capability_materialization::*` and B to the policy that owns it |
| the module doc claims the Layer-A boundary lives here | **discharged** — the doc was corrected in Phase 9 |
| `parse_args` at 722 lines | **spent** — it is 22 lines; the ADR-058 exception has no function left to cover, and EX-007 records it as spent rather than revoked |
| the validation proof is created, discarded and recreated | **open**, recorded not ruled — unchanged |
| requiredness is a parser-only rule over public `String` fields | **open** — `require` still enforces it at parse time over public fields; it belongs in a disposition record or at the boundary |
| 23 legality tests test a neighbour's owner from inside this file | **open** — test placement, not a production authority |
| 6 materialization tests for 297 lines of key custody | **moved with C**; it is `capability_materialization`'s coverage question now |

## 10. Completion criteria

- [x] All twelve questions answered in writing
- [x] Blueprint committed under `docs/architecture/components/` and linked from the campaign index
- [x] Implementation map measured with `scripts/module_size_gate.py` on a stated SHA (`7ec8f92`), and the stale 1177 corrected
- [x] Theorem inventory distinguishes *in registry* / *structural, no entry* / *gap* — 0 owned
- [x] Test/evidence inventory names the lane per row **and does not let one lane stand in for another**: parsing 119, legality 23, materialization 6, counted by what each test calls
- [x] The three distinctions the issue asked for — argv transport, legality decision, capability materialization — measured separately
- [x] ADR-058's `parse_args` ruling treated as evidence for neither side
- [x] Outcome recorded: **move materialization and the legality predicate out; `parse_args` keeps its exception**
- [x] No code changed
