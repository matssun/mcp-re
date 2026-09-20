<!-- SPDX-License-Identifier: Apache-2.0 -->
# ADR-MCPRE-069 — NP-153 ratification packet (CO-S3-6)

**Slice** CO-S3-6, the last landable slice of the CO-S3 queue.
**Scope** CO-S3-P13, P15, P17, P18 — twenty-one of NP-153's thirty-six rows, all in the
default `tests/integration` lane.
**Outcome** **15 registered, 6 refused.**
**What is NOT in scope.** NP-153's other fifteen rows — the refusal-precedence family
(CO-S3-P14), the inter-plane transcript order (P16), the documented-CLI pair (P19), the
recommended-replay-backend row (P20) and the five normalizer self-tests (P21) — were not
examined here and are left exactly as they are, so that nothing below reads as a judgement
about them.

---

## 1. Lane correspondence, measured before anything else

`cargo test -p mcp-re-proxy --test integration -- --list`. The work package's command named
`--lib`; these twenty-one controls are `tests/integration#` selectors and select **zero**
names there, which is a failure and not a pass, so the target was corrected first.

| selection | selected |
|---|---:|
| default | **145** |
| `--features aws_kms_keysource` | **146** |
| `--features gcp_kms_keysource` | **146** |

**All twenty-one select in the default lane** — checked by exact name, one at a time, never
by subtracting totals.

**The subtraction the work package warned about is real and was confirmed by name.**
`app_startup_characterization_test::app_run_refuses_unbuildable_key_sources_and_replay_tiers`
— a CO-S3-P17 row, registered here — selects **1** in the default lane and **0** under both
KMS features. It is
`#[cfg(not(any(aws_kms_keysource, gcp_kms_keysource, pkcs11_keysource, cpstore_etcd)))]`,
because its premise is that those backends are ABSENT from the build. So the KMS lanes'
146 is 145 + two `tls_test` names − this one, and a worker comparing totals would read one
addition where there were two, while silently measuring this control's absence as presence.
The new unit that holds it declares no `test_features` and says so in a registry comment:
its battery cannot move to a feature lane, because a unit holds one set.

## 2. The organising question, and why it is not the one the analysis asked

Every one of the twenty-one drives a real startup — eleven through `app::run`, three through
`ValidatedDeployment::try_from`, six by spawning the shipped binary, one through `app::run`
in process. The tempting reading is that they therefore all measure a *route* conjunct — *the
composition root consults this authority* — and belong to a new unit over `app.rs`.

**Measured, that reading is wrong, and the measurement is what decides the slice.** The route
is type-enforced: `run_validated` takes `&ValidatedDeployment` and
`ValidatedDeployment::try_from` is its only constructor, so there is no edit to `app.rs` that
admits an unvalidated request. The refusal string these rows assert —
`"mcp-re-proxy refuses unsafe configuration:"` — is produced at
`config_state/validation/mod.rs:110`, not in `app.rs`. A unit over `app.rs` for these rows
would fingerprint a file no weakening of which can turn them red: provenance without
evidence, which is the defect `proxy.online_ocsp_reachability`'s own registry comments were
written to avoid.

So the question per row is the ordinary one — **which unit owns the clause that decides it**
— and the analysis's §3 table is substantially right about that. Where it is wrong, it is
wrong about the carrier or about whether the owner has a theorem at all.

The one place the route conjunct IS falsifiable is where the failure comes from *outside*
the boundary: an authority, a store or a backend that cannot be established. Nothing in
`config_state` decides that; what `app.rs` contributes is that the failure leaves `run`
instead of resolving to an OFF posture or a weaker tier. That is a real, deletable fact, and
it is the new unit's whole proposition. M358 deletes it.

## 3. Per-row attribution — all twenty-one

### Registered (15)

| CD | control | entrance | deciding clause | home | theorem |
|---|---|---|---|---|---|
| `CD-19025` | `a_config_that_skipped_the_parser_still_cannot_bypass_the_safety_guards` | `app::run` | `config_state/client_credential_window.rs` | `proxy.client_credential_window` | THM-0102 |
| `CD-19032` | `…delegated_custody_the_rotor_cannot_honour` | `try_from` | `config_state/delegated_signing.rs` | `proxy.delegated_signing_configuration_state` | THM-0077 |
| `CD-19036` | `…unboundedly_long_lived_delegated_credential` | `app::run` | `config_state/delegated_signing.rs` | `proxy.delegated_signing_configuration_state` | THM-0077 |
| `CD-19035` | `…hot_spin_the_crl_reloader` | `app::run` | `config_state/transport.rs:238` | `proxy.transport_binding_and_crl_state` | THM-0077 |
| `CD-19042` | `mode_c_attested_ingress_is_refused_at_the_configuration_boundary` | `app::run` | `config_state/transport.rs` | `proxy.transport_binding_and_crl_state` | THM-0077 |
| `CD-19043` | `the_boundary_alone_refuses_an_lb_assertion_binding` | `app::run` | `config_state/transport.rs` | `proxy.transport_binding_and_crl_state` | THM-0077 |
| `CD-19033` | `…disable_the_request_target_reconstruction_check` | `app::run` | `config_state/validation/residue.rs` | `proxy.legality_boundary_totality` | THM-0077 |
| `CD-19034` | `…enable_an_unaccepted_authz_profile` | `app::run` | `config_state/validation/residue.rs` | `proxy.legality_boundary_totality` | THM-0077 |
| `CD-19046` | `config_legality…refused_at_the_boundary` | `try_from` | `config_state/validation/**` (many machines) | `proxy.legality_boundary_totality` | THM-0077 |
| `CD-19047` | `config_legality…the_baseline_is_admitted` | `try_from` | `config_state/validation/**` | `proxy.legality_boundary_totality` | THM-0077 |
| `CD-19037` | `…root_key_endpoint_at_a_plaintext_host` | `app::run` | `kms_endpoint_policy/**` | `proxy.kms_endpoint_authority` | THM-0089 |
| `CD-19041` | `enabling_trust_reload_changes_the_tier_line_and_the_reload_line_together` | binary | `trust_plane/mod.rs` | `proxy.trust_posture_declaration` | THM-0100 |
| `CD-19026` | `a_configured_profile_with_no_enrolled_authority_refuses_to_start` | binary | `app.rs` (the `?` on the evaluator) | **new** `proxy.unestablishable_capability_refusal` | THM-0077 |
| `CD-19039` | `an_unopenable_replay_tier_refuses_startup_and_names_why` | binary | `app.rs` (the replay plane's `?`) | **new** `proxy.unestablishable_capability_refusal` | THM-0077 |
| `CD-19040` | `app_run_refuses_unbuildable_key_sources_and_replay_tiers` | `app::run` | `app.rs` (the key-source / tier `?`) | **new** `proxy.unestablishable_capability_refusal` | THM-0077 |

Each registration carries its own registry comment naming what the added member establishes
that the existing battery does not. Four of them are worth stating here.

* **`CD-19025` is THM-0102's own sentence at deployment width.** The statement, verbatim and
  match-verified: *"A deployment that disables either bound, or names a lifetime past the
  ceiling, resolves no window and is refused naming the flag."* The lib battery holds
  `disabling_either_bound_resolves_no_window` — the first half. *Refused naming the flag* is
  a fact about a deployment, and this is the only control that has one. THM-0102's measured
  caveat — the *"obligation this theorem names and does not establish"* sentence — is about
  `async_serve/connection.rs` and is not touched.
* **`CD-19046` is evidence for TOTALITY rather than for any machine.** One control walking
  the boundary across the delegated-custody, inner-plane, custody, replay, required-coordinate
  (8 cases), numeric-range (4 cases) and responder-value clauses, plus a positive
  recognition case. No single machine's deletion turns it green, which is exactly why it is
  not any single machine's evidence. `proxy.legality_boundary_totality`'s description is
  *"THE LAYER-A BOUNDARY IS TOTAL AND NAMES WHAT IT REFUSED"*.
* **`CD-19047` is its anti-vacuity half**, and the integration twin of a member the unit
  already holds, `the_fixture_these_controls_mutate_is_otherwise_legal`. Its own assertion
  message says so: *"the baseline must be legal, or every case below measures the wrong
  thing"*.
* **`CD-19041` is admitted on the unit's own width.** `proxy.trust_posture_declaration`'s
  description, verbatim: *"It is a claim about the TRANSCRIPT the replica prints"* — the
  replica, not the formatter. The lib members assert each line from the formatter; this is
  the only member that asserts the PAIR moving together on a real startup, which is where
  they could disagree.

### Refused (6)

| CD | control | ground |
|---|---|---|
| `CD-19029` | `…dangling_custody_or_ingress_selector` | THM-0049 `scope` declines the conjunct |
| `CD-19031` | `…deny_list_nothing_enforces` | THM-0049 `scope` declines the conjunct |
| `CD-19030` | `…decision_scope_that_selects_nothing` | owner `proxy.authorization_configuration_state` is theorem-less |
| `CD-19038` | `a_push_tier_without_an_event_source_is_qualified_where_it_is_declared` | asserts a presentation adjacency no theorem states |
| `CD-19027` | `…install_the_authorization_authority_and_the_transcript_declares_it` | carrier is `authorization/capability.rs`, whose unit is theorem-less |
| `CD-19028` | `a_deployment_with_no_authority_declares_the_off_posture` | same |

**`CD-19029` / `CD-19031`.** THM-0049's `scope`, verbatim and match-verified:

> It does not establish that the illegal combination is unrepresentable — `DeploymentRequest`
> can hold one, which is why the refusal is a check the classifier performs and not a
> structural fact. It does not establish that the classifier is consulted on every startup
> path.

Both rows reach X2a and X6 *through* the boundary's clause list, which is in
`proxy.legality_boundary_totality`'s closure and not in `proxy.cross_machine_legality`'s.
Delete the entry that calls the cross-machine pass and both go red while every word of
THM-0049 stays true. That is the operational test for *not evidence for this claim*, and the
theorem says the same thing in prose. The asymmetry with the rows that DID land under
THM-0077 is textual and measured, not a preference: THM-0077's statement contains the
materialization conjunct — *"cannot be silently reinterpreted into a weaker posture during
materialization or serving"* — and THM-0049's scope excludes it.

**`CD-19030`.** `--authz-decision-scope` is decided in `config_state/authorization.rs`. Its
unit, `proxy.authorization_configuration_state`, appears in no theorem's `supported_by` and
owns none. C1 forbids adding what is not attached, and a theorem-less unit attaches nothing.

**`CD-19037` LANDED, and the analysis was wrong about it twice in the other direction.**
§3 homes it under THM-0089 but names `proxy.outbound_destination` as the unit, and §9
judgement 3 frames the difficulty as a LANE conflict to be solved by a different home or a
lane twin. Measured: THM-0089's unit is `proxy.kms_endpoint_authority`, not
`proxy.outbound_destination`, and there is no lane conflict at all. The statement, verbatim
and match-verified, names this control's entrance as one of three consumers:

> The decision belongs to one owner and is consumed by the command line, the validation
> boundary, and the AWS-KMS, AWS-STS and GCP-KMS key sources alike — none of them obtains it
> from another.

The fourteen `lib#` members measure the DECISION. This row is the validation-boundary
consumer at deployment width. Its nine refusals each assert the flag AND the reason — three
of those fields are named by unrelated coherence rules, so a flag-only assertion would let
another cause stand in — and its eight negative controls, each run under all three endpoint
fields, are the anti-vacuity half.

**One measurement nearly went the other way and is worth recording.** The file the analysis
implicitly points at, `mcp-re-proxy/src/config_state/kms_endpoint.rs`, is in NO unit's
`paths`, and a first pass refused the row on that ground. That file is not the decision: its
own module doc says so — *"The decision itself is
`crate::kms_endpoint_policy::kms_endpoint_authority`; this is only how a `DeploymentRequest`
answers it, and how the offending flag is named in the refusal."* The decision lives in
`kms_endpoint_policy/**`, which IS a closure. The adapter's absence from every closure
survives as a residual; it was not a reason to refuse.

**The lane, measured in the combined lane rather than inferred.**
`proxy.kms_endpoint_authority` declares `test_features = ["aws_kms_keysource",
"gcp_kms_keysource"]`. With both enabled the integration target selects **148** names, this
control is among them, and it was RUN there: `1 passed; 0 failed; 0 ignored; 147 filtered
out`. It is not feature-gated, so it selects in the default lane too and joining this battery
costs it nothing.

**`CD-19038`.** The control's load-bearing third assertion is
`assert!(t.emits_in_order(&tier, &caveat), "the caveat must follow the claim it weakens")`,
and its name says the same: *qualified WHERE IT IS DECLARED*. THM-0100 states the arithmetic
the transcript prints and where the line's arithmetic comes from; it says nothing about
adjacency. Print the caveat three lines later and the row goes red while THM-0100 is
untouched. This is the clause-3 shape the analysis itself assigns to CO-S3-P14 (refusal
ORDER) and CO-S3-P16 (inter-plane order), both R6 — so landing this one would have had the
campaign refuse the order proposition and accept it in the same record. The other half of
P15, `CD-19041`, asserts no order and is registered.

**`CD-19027` / `CD-19028`.** §2 calls P18 *"the cleanest R1 in NP-153"* and homes it in
`proxy.serving_capability_posture`, on a matched quotation from that unit's description —
*"the transcript says this protection is running"*. The quotation matches; the home does not.
`mcp-re-proxy/src/serving_capabilities.rs`, that unit's only path, **contains the word
`authorization` exactly once, in a doc sentence saying the carrier must NOT make an
authorization decision.** The seam these two rows assert is `Seam::Authorization`, declared
in `startup_posture/seam.rs` and produced by `authorization::capability::evaluator`; the unit
that owns that file, `proxy.authorization_capability`, is `critical`, holds 29 controls —
including these two rows' own lib twin,
`a_configured_profile_with_no_enrolled_authority_refuses_startup` — and **carries no
theorem.** The unit whose description was quoted enumerates its seams (verified context,
security audit, retention) and authorization is not among them.

## 4. Quotation checks

**Twenty quotations, whitespace-normalised (comment and blockquote markers stripped),
asserted as substrings of the named field of the named theorem in
`verification/policy/theorems.toml`, of the named unit's `description` in
`verification/policy/verification.toml`, or of the named source file: 20 OK, 0 MISS.**

Covering THM-0049 `scope`, THM-0077 `statement` and `scope`, THM-0089 `statement`, THM-0100
`statement`, THM-0102 `statement` and `scope`; the `description`s of
`proxy.trust_posture_declaration`, `proxy.legality_boundary_totality`,
`proxy.transport_binding_and_crl_state` ×2, `proxy.delegated_signing_configuration_state`,
`proxy.client_credential_window`, `proxy.serving_capability_posture` and
`proxy.online_ocsp_reachability`; and `config_state/transport.rs`,
`config_state/validation/mod.rs`, `config_state/kms_endpoint.rs`, `app.rs` and
`config_legality_characterization_test.rs`.

**Two quotations MISSED on first check and were corrected to the source text, never
paraphrased.** THM-0102's caveat was written as *"obligation this theorem names and does not
establish"* where the field says *"that a connection is in fact closed at the configured age
is an OBLIGATION this theorem names and does not establish"*. The `config_state/kms_endpoint.rs`
module-doc sentence missed until `//!` markers were stripped from the haystack, which is the
normalisation this check is specified with. Nothing was kept that failed to match.

## 5. Falsifiers, demonstrated in their lanes

| probe | change | result |
|---|---|---|
| `M358-proxy-a-capability-that-cannot-be-established-serves-anyway` | **new** | **PASS** — red on **all three** members of the new unit |
| `M359-proxy-a-disabled-client-credential-bound-resolves-a-window` | **new** | **PASS** — red on the lib row and on `CD-19025` |
| `M306-proxy-a-delegated-ttl-above-the-ceiling-is-refused` | `expect_red` widened | **PASS** — red on the lib row and on `CD-19036` |
| `M307-proxy-attested-ingress-is-refused-by-name` | `expect_red` widened | **PASS** — red on the lib row and on `CD-19042` |
| `M311-proxy-a-scheme-less-target-uri-is-refused` | `expect_red` widened | **PASS** — red on the lib row and on `CD-19033` |
| `M327-proxy-the-tier-line-names-its-reload-floor` | widened, then **narrowed again** | **PASS**, unchanged from `origin/main` |
| `M216-proxy-the-host-allowlist-is-what-a-resolver-can-answer-for` | widened, then **narrowed again** | **PASS**, unchanged from `origin/main` |

**M358 is the new unit's own falsifier and it is deliberately coarse.** The weakening turns
`run`'s outcome into `.or_else(|_| Ok(()))`, so every startup refusal becomes a clean exit.
That is exactly the unit's conjunct — *the failure leaves `run`* — and it is the only thing
`app.rs` contributes, since all three refusals are DECIDED in three other modules whose own
batteries stay green under it. A narrower anchor on one `?` would have measured one of the
three call sites and said nothing about the other two. The note in the registry says so
rather than leaving the coarseness to be inferred. All three declared controls went red,
which is stronger than the registry requires.

**M359 was minted because the existing battery is blind on its arm.** M113 weakens the
relation between the two bounds and M114 the ceiling; neither touches the arm where a bound
is ABSENT, which is the arm `CD-19025` exercises. Its weakening resolves a disabled
`--max-client-cert-lifetime` to the CEILING instead of refusing — the silent reinterpretation
THM-0077's statement forbids, written out — and both declared rows went red.

**M359's first adjudication FAILED: `STALE — an anchor matches 0 site(s)`.** The arm carries
a Rust line-ending backslash inside its diagnostic string, and in a TOML BASIC string that is
read as TOML's own line-ending escape and the newline is trimmed, so the anchor could not
match text that is plainly in the file. The probe now uses TOML LITERAL strings and the
registry comment records why. The refusal is reported rather than quietly fixed, because an
anchor that matched a DIFFERENT site would have measured a different function and reported
PASS.

**TWO declarations were made, measured, and REMOVED.** `CD-19041` was first added to M327's
`expect_red` and `CD-19037` to M216's. Both **executed and stayed GREEN**. For M327 the
reload floor is a suffix of the tier line and `startup_transcript` reads
`store_change_bounded` from a clause the floor text does not carry, so the floor can stop
naming the cadence while the transcript still reports the store as bounded; for M216 the five
userinfo cases are refused before the host allowlist is consulted, so deleting the allowlist
does not admit them. `verify-mutations` requires only that ONE declared control fail, so both
probes would have reported `PASS` with a false claim inside. Both rows were removed and both
registry comments state the measurement. This is the standard CO-S3-5 set on the same shape,
held to — and it fired twice here, on two probes whose names correspond to their rows
perfectly.

**Seven landed rows are named by no probe** — `CD-19032`, `CD-19034`, `CD-19035`,
`CD-19037`, `CD-19043`, `CD-19046`, `CD-19047`. Each joins a unit that already carries a demonstrated-red falsifier,
which is what ADR-MCPRE-068 requires of the unit; none of them is a new conjunct. Recorded so
that the absence reads as a measurement rather than an oversight.

## 6. Every measured count against the analysis's

| item | analysis | measured | verdict |
|---|---|---|---|
| slice size | 21 controls | 21 | correct |
| lane | default for all four propositions | default, all 21 by name | correct |
| KMS subtraction | flagged by CO-S3-5 for this slice | confirmed, `CD-19040`, by name | correct |
| P13 size | 14 controls | 14 | correct |
| P13 shape | *"NOT one unit"*, seven owners | four owners took rows; three could not | half correct |
| P13 entrance | *"asserts `app::run` / `try_from` refuses it"* | 11 / 3 respectively | correct |
| `CD-19029`/`CD-19031` home | `proxy.cross_machine_legality`, *"statement names it verbatim"* | statement does; `scope` declines the conjunct the control carries | **WRONG** |
| `CD-19030` home | `proxy.legality_boundary_totality`, with a judgement | decides in `config_state/authorization.rs`; that unit is theorem-less | **WRONG** |
| `CD-19037` unit | `proxy.outbound_destination` | `proxy.kms_endpoint_authority` | **WRONG** |
| `CD-19037` lane | *"lane conflict, resolve before landing"* | none: selects in default AND in the combined KMS lane (148), run in both | **WRONG** |
| P15 class | R1, both rows | 1 of 2; the other asserts an unclaimed adjacency | **WRONG** |
| P15 which unit | `trust_posture_declaration` / `trust_reload_cadence` | `trust_posture_declaration` for the landed row | resolved |
| P17 home | new unit over `app.rs` + `startup_plan.rs`, or extend `startup_plan_legality` | new unit over `app.rs` alone | correct in kind |
| P18 home | `proxy.serving_capability_posture`, *"cleanest R1"* | that file contains no authorization seam; the real owner is theorem-less | **WRONG** |
| landable | 21 | **15** | upper bound, as instructed |

### Where the analysis was wrong, summarised

1. **THM-0049's `scope` was read for what it grants and not for what it declines.** §3 cites
   the statement naming X2a and X6 verbatim — true — and does not reach the sentence two
   paragraphs later that excludes the startup-path conjunct both controls carry.
2. **`CD-19037` is not a lane problem and its named unit is the wrong one.** §9 judgement 3
   poses a choice between a different home and a lane twin. There is neither problem: the
   owner is `proxy.kms_endpoint_authority`, THM-0089's statement names the validation
   boundary as a consumer, and the control selects and passes in that unit's own combined
   feature lane as well as in the default one.
3. **P18's home has no authorization in it.** The quotation matches;
   `serving_capabilities.rs` does not carry the seam.
4. **P15 is not one class.** One row is THM-0100's; the other is the adjacency family the
   analysis itself rates R6 twice elsewhere.
5. **Two more theorem-less owners surfaced**, `proxy.authorization_configuration_state` and
   `proxy.authorization_capability` — the latter `critical`, with 29 controls. Neither is
   counted in the campaign's theorem-less total moving, because that total counts UNITS and
   both already existed.
6. **The route is type-enforced, so the `app::run` / `try_from` distinction the table draws
   carries no falsifiable difference** for the boundary rows — which is why a new unit over
   `app.rs` was right for P17 and wrong for P13.

## 7. Residuals

1. **`mcp-re-proxy/src/config_state/kms_endpoint.rs` is in no unit's `paths`.** It is the
   adapter that asks the endpoint-authority rule on a `DeploymentRequest`'s behalf and names
   the offending flag in the refusal. The DECISION it delegates to is in
   `proxy.kms_endpoint_authority`'s closure and `CD-19037` landed there, so nothing is
   unclaimed — but a change to the adapter moves no unit's fingerprint. Widening `paths` is
   outside this work package.
2. **`proxy.authorization_capability` is a `critical` theorem-less unit holding 29 controls**,
   including the lib twin of a row this slice registered elsewhere. It is the same orphan
   class CO-S3-3 recorded for the two registration leaves.
3. **`proxy.authorization_configuration_state` is theorem-less**, which is what refuses
   `CD-19030`.
4. **The cross-machine pass has no unit stating that the boundary consults it.** THM-0049
   declines it, `proxy.legality_boundary_totality` owns the clause list but does not name the
   relations, and `CD-19029`/`CD-19031` sit between the two.
5. **`proxy.unestablishable_capability_refusal`'s `paths` are `app.rs` alone**, so the
   modules that DECIDE its three refusals are outside its closure. That is deliberate — its
   proposition is propagation, not decision — and the direction is conservative: a change in
   an establishing module turns the controls red rather than silently green.
6. **Fifteen NP-153 rows were not examined**, and the record says which.
