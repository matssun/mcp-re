<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-069 control dispositions

The durable records that `verification/policy/control-dispositions.toml` points at through
its `reason_family` and `proposition` fields. `tools/verification/control-census --gate`
fails when a cited record is absent, so a disposition points at a reason rather than at a
memory of one.

This is the same mechanism [ADR-MCPRE-061 §14](review-dispositions.md) uses for oversized
units, and a **separate register** for the reason the ADR-069 ratification gives: the two
authorities are different. 061 adjudicates *a unit that is too large*; 069 adjudicates *a
control that no proposition claims*. One register per authority is what keeps a record
citable by exactly one gate.

## What a record here settles, and what it does not

**A `not-evidence` family answers ADR-069 §8 question 1** — *is `not-evidence` load-bearing
enough to need a review record?* It is, and this is the record. D3 already requires a
reason and checks its shape; without somewhere durable to look the reason up, a large
`not-evidence` population and a campaign that gave up are the same artefact. A family
record states:

- what kind of control it covers, in terms a reader can check against a control;
- **why controls of that kind are not evidence for a security proposition** — which is a
  claim about the control's relationship to the production carrier, not about the control
  being unimportant;
- what would move a control OUT of the family, so the record is falsifiable.

**A record here grants nothing.** There is no exception state and nothing is excused from
the census: a `not-evidence` control is still measured, still enumerated, and still listed
under its family. What the record buys is that the reason is written once, reviewed once,
and cited by every row that relies on it — rather than retyped, slightly differently, 700
times.

**A `new-proposition` record is step 1 of ADR-069 §5 and no more.** It identifies a
proposition the graph does not hold and says what would establish it. It does not ratify a
theorem, and the campaign may not widen an existing unit to swallow it. Until the ordinary
ADR-MCPRE-059 §28 route registers it, it is visible unresolved assurance debt and the
census reports it as such.

---

## The criterion this register applies to a gate

A gate is a control by every test ADR-069 applies: it executes on the merge path, it can
fail, and what it refuses is a rule somebody wrote down. The question is narrower — is it
the **production carrier of a security proposition**? — and it is answered the same way for
all sixty-three:

> **A gate carries a proposition when a violation of it changes what the SHIPPED SYSTEM
> admits, emits, signs or exposes.** A gate whose violation changes only what the
> repository's own process knows, measures or enforces about itself does not.

Two secondary readings, both used below and both stated because they decide the close calls:

- **Can the gate go red on a weakening that leaves runtime behaviour unchanged?** If yes it
  is a shape or a mirror rule, not a behavioural carrier — which is not a smaller thing, it
  is a different thing, and calling it evidence would put an architecture rule inside a
  behavioural proposition's fingerprint.
- **Does a theorem name it, in its own text, as what establishes it?** That was ADR-068
  Phase 1's criterion and it registered four gates. It is a sufficient condition here, not a
  necessary one: a gate can be the carrier of a proposition the graph has simply never
  stated, which is the whole subject of ADR-069.

`scripts/merge_path_gate.py` already rules on part of this population, and its rulings are
reused rather than re-derived: it names `module_map.py` and `startup_backedges.py` as
"an architecture report with no verdict", `demo-local.sh` as "a demo runner, not a control",
and `local_slo_lane.sh` as "an SLO measurement, not an admissibility control". Those are
ADR-069 dispositions in everything but name, and ND-008 records them as such.

---

## The families

## ND-001 — the assurance platform's own self-tests

**Covers:** every control carried by `tools/verification/test_*.py`.
**Scope:** `carrier-scope: admitted`.
**Recorded:** 2026-09-19, ADR-MCPRE-069 Phase 069-B batch 1.

These are the controls that establish that a `verify` verdict means what ADR-MCPRE-059 says
it means: the verdict algebra, the invalidation rules, the measured-input closure, the
escape-hatch detector, the theorem loader and review model, the per-ecosystem lane adapters,
the structural and measured lanes' fail-closed-on-zero-execution behaviour, the premise
ontology, the severity derivation, and this census's own ability to see.

**Why they are not evidence for a security proposition, and the authority for saying so.**
ADR-MCPRE-068 states it directly:

> **Assurance TCB, not a product claim.** Everything here sits where issue #739 sits:
> outside the product theorem roots, inside the layer that decides whether the word
> `ESTABLISHED` may be believed. No entry in this record becomes a `THM-`.

That is the boundary, and it decides these controls. A test of `_verdict_algebra` does not
demonstrate anything about the proxy, the client or either SDK; it demonstrates that the
apparatus which reports on them computes what it says it computes. **Its failure invalidates
other evidence rather than falsifying a proposition** — which is exactly the relationship
that makes something an instrument rather than a witness. Nothing in the registry could
claim one of these without inventing a product promise about the measuring equipment, and
ADR-069 §5 forbids widening a unit to swallow a proposition it does not state.

**This is not the campaign giving up.** These controls are required on the merge path, they
are named one per line in `ci.yml` and `local_gate.sh` precisely so that
`scripts/merge_path_gate.py` can see them, and several of them are the only liveness a lane
has. What is being said is narrower and exact: *they are load-bearing for whether the
evidence may be believed, and they are not themselves evidence for any proposition the
product makes.*

**Why the disposition is carrier-scoped.** What makes these controls not evidence is a
property of the FILE's role — it measures the instrument — and that is true of every control
inside it and of the next one added. A control-scoped register here would record 595 copies
of one reason and would go stale the moment a lane grew a case. ADR-MCPRE-061's rule applies
unchanged: review granularity equals exception granularity, and the thing reviewed here is
the instrument.

**What would move a control out of this family.** Any control in one of these files that
demonstrates a property of a PRODUCT carrier — a proxy, client, core, http-profile or SDK
source file — rather than of the assurance platform. Such a control is misplaced rather than
misdispositioned: it belongs beside the carrier it is about, and its disposition is
`reattribute`, not this family.

## ND-002 — the SLO harness's own self-tests

**Covers:** every control carried by `tools/slo/test_*.py`.
**Scope:** `carrier-scope: admitted`.
**Recorded:** 2026-09-19, ADR-MCPRE-069 Phase 069-B batch 1.

The load harness's host gate, environment preflight, run supervisor, evidence store, VM
participant and admission hook. Same boundary as ND-001 and a sharper instance of it: these
controls exist so that a measurement is refused when the box cannot support one — the
`ALLOW_NOISY_BOX` case — and refusing to measure is the opposite of establishing something.

**Not to be confused with a `measured://` apparatus control.** ADR-MCPRE-068 §4.1 makes an
apparatus control part of a measured unit's declared evidence: the demonstration that the
number can still MOVE. That is a different control from these. `MSR-0001` carries such a
control (`the_measurement_moves_when_the_scanned_set_shrinks`) and it is registered. If the
SLO measurement is ever registered as `measured://`, its `measurement_control` will be a
sensitivity or reproducibility control on the number — not a test that the harness declines
to run on a busy machine.

**Extended 2026-09-19, batch 21:** `mcp-re-proxy/tests/tls_load_harness_bench.rs`, the Rust
load harness itself. Same reason, and one more that is this repository's own worked example
of a false green: the file is gated to the `redis_replay` feature rather than marked
`#[ignore]`, so the `-- --ignored` form selects ZERO tests, exits 0 and writes no report.
`scripts/slo_invocation_gate.py` exists to keep that form out. A harness whose invocation had
to be policed is not a control over the product.

**What would move a control out of this family.** A control here that IS the reproducibility
or sensitivity control of a registered `measured://` record. That control is that unit's
declared evidence and leaves the census by being named in the registry.

## ND-003 — assurance-process ratchets and registries

**Covers:** `assurance_obligation_gate.py`, `claim_surface_gate.py`, `clippy_ratchet_gate.py`,
`control_census_gate.py`, `evidence_class_ratchet.py`, `merge_path_gate.py`,
`module_size_gate.py`, `registry_approval_gate.py`, `release_assurance_gate.py`,
`rehearsal_claim_gate.py`, `slo_invocation_gate.py`, `slo_evidence_identity.py`,
`unit_closure_gate.py`, `verification_trigger_gate.py`, `adr051_slo_gate.py`, `slo_gate.py`.
**Recorded:** 2026-09-19, ADR-MCPRE-069 Phase 069-B batch 2.

Each of these refuses a way the repository's own assurance machinery could lie about itself:
a debt register that grew, a published claim whose statement moved since the owner read it,
a lint count that rose, a unit whose closure is unanswered, a workflow whose trigger cannot
see its own fingerprint, an SLO verdict quoted from a report nobody produced.

**Why they are not evidence.** Same boundary as ND-001, one level out: they protect the
process that produces and holds evidence, not the system the evidence is about. Weaken any
of them and the shipped proxy admits, emits and signs exactly what it did before; what
changes is what the repository can honestly say. That is the definition of an instrument.

**What would move a control out.** A gate here that begins refusing a property of production
source — as the four `*provenance*` gates do — is a carrier and belongs with them, registered
against the unit whose proposition it establishes.

## ND-004 — build-system, toolchain and runner wiring

**Covers:** `bazel_gazelle_gate.py`, `bazel_srcs_gate.py`, `cargo_test_target_gate.py`,
`workspace_lints_gate.py`, `node_matrix_state.py`, `self_hosted_docker_gate.py`,
`heavy_lane_disk_preflight.py`, `prepare_node_matrix.sh`, `prepare_python_matrix.sh`,
`use_pinned_toolchain.sh`, `verification_runner_preflight.sh`.
**Recorded:** 2026-09-19, ADR-MCPRE-069 Phase 069-B batch 2.

These keep the machinery that RUNS the batteries able to run them: a Bazel target list that
matches the module tree, a named `--test` lane that names a target that exists, a workspace
lint table a member actually opts into, a prepared runtime that is present rather than
assumed, a runner whose Docker credential and disk contracts hold.

**Why they are not evidence.** Their subject is the lane, not the claim. Each one's failure
mode is *a battery that cannot run or that runs over the wrong thing* — which is a reason a
measurement is worthless, never a reason a proposition is false. They belong to the same
class as ADR-MCPRE-068's fail-closed-on-zero-execution rule, from the other side: that rule
makes an unexecuted lane refuse to report; these make the lane executable in the first place.

**Note, because it is the closest call in this family.** `workspace_lints_gate.py` enforces
that a crate opts into `[workspace.lints]`, and those lints include ADR-MCPRE-061 §6
protections over production code. A crate that failed to opt in would compile with
`unwrap_used` unenforced — but nothing about the shipped binary changes until somebody then
writes an `unwrap`, and THAT is caught by the ratchet. The gate protects the enforcement, not
the property.

## ND-005 — mirrored and documented values

**Covers:** `jcs_vocabulary_gate.py`, `proxy_flag_doc_gate.py`, `check_port_registry.py`, and
`mcp-re-transport`'s crate-root `no_run` doctest (added 2026-09-19, batch 8).
**Recorded:** 2026-09-19, ADR-MCPRE-069 Phase 069-B batch 2.

Each holds a second copy of a fact equal to its source: the deprecation vocabulary against
the live profile decision, a guide's `--flag` against the parser that accepts it, the Helm
chart's `bindPort` against `config/ports.toml`.

**Why they are not evidence.** A violation changes what a READER is told, not what the
system admits. The proxy binds the port the registry names whether or not the chart's mirror
agrees; the parser accepts the flags it accepts whether or not a guide lists them; the
carrier is RFC 9421 + RFC 9530 whatever a design document's framing says.

**The doctest belongs here for the same reason as `proxy_flag_doc_gate.py`.** A `no_run`
rustdoc example COMPILES and does not run: it establishes that the documented usage still
type-checks against the current API, which is the same fact that gate establishes for a
`--flag`, one language layer down. Its failure means the guide teaches an API that is not
there.

**Stated because it is the sharpest close call in this register.**
`check_port_registry.py` also enforces a band invariant — every registered port falls inside
the machine-wide reservation — and that one IS about what the system binds. It is not
separated out, because the band is a property of the REGISTRY and the registry is the single
source the binding reads: there is no production text a weakening could touch that this gate
would catch and the registry would not already decide. Should a binding ever be written that
does not read the registry, this splits, and the split is a `new-proposition`, not a
re-labelling.

## ND-006 — repository and build-infrastructure security controls

**Covers:** `tracked_secrets_gate.py`, `codebuild_guard_gate.py`.
**Recorded:** 2026-09-19, ADR-MCPRE-069 Phase 069-B batch 2.

Two genuine security controls, and neither is about the product. One refuses operator
credential material and personal identifiers in tracked files; the other refuses a CodeBuild
context that carries credential material, on the premise that every path it names is a path
`git archive HEAD` cannot produce.

**Why they are not evidence.** Their subject is the repository and the build environment.
A leak either has already happened or has not, and no proposition MCP-RE makes about
dispatch, signing, admission or attribution is true or false depending on it. Filing them as
evidence for a product claim would say the product's security rests on them, which is both
untrue and a way of losing what they actually protect.

**This is the family most at risk of being read as "unimportant".** It is not that. The
disposition says where the control sits, not how much it matters, and `tracked_secrets_gate`
exists precisely because a previous version of this guard was described in a template, was
allowlisted as a permanent exemption, and had never existed at all.

## ND-007 — architecture shape rules

**Covers:** `semantic_altitude_gate.py`, `lifecycle_purity_gate.py`, and
`mcp-re-core` `tests/firewall_test#mcp_re_core_stays_pure_no_networking_async_fs_or_upstack_dependencies`
(added 2026-09-19, ADR-MCPRE-069 RM-S1).
**Recorded:** 2026-09-19, ADR-MCPRE-069 Phase 069-B batch 2.

ADR-MCPRE-067 §16.3's rule that a new provider adds a typed mechanism payload and never a
provider-qualified sibling on `DeploymentRequest`; and ADR-MCPRE-056's rule that the two
state machines that are VALUES — `runtime_state.rs`, `exchange_state.rs` — depend on no
production module.

**Why they are not evidence, and why this is the closest call in the whole gate lane.** Both
gates read production source, and both refuse a shape whose reintroduction is a historical
defect rather than a hypothetical: seventeen sibling fields whose meaning depended on a
discriminator, and a lifecycle whose transition table could only be reviewed in isolation
because nothing else reached into it. But apply the secondary test — **a weakening of either
leaves runtime behaviour unchanged.** Adding an unused sibling field admits nothing new;
adding a `use` of another production module to `runtime_state.rs` changes no transition.
What each violation costs is the reviewability of a claim somebody else makes: the altitude
rule keeps inconsistent values unconstructible by keeping the shape from existing, and the
purity rule is what makes the transition relation's argument a local one.

That is a property of the EVIDENCE, not of the system, which is this register's boundary.

**The purity firewall is the same rule one layer up, and was admitted by the same test.**
`lifecycle_purity_gate.py` holds that two state machines that are VALUES depend on no
production module; the firewall test holds that `mcp-re-core` — the crate those and every
other verdict are computed in — declares no networking, no async-runtime, no filesystem and
no up-stack dependency. It reads `mcp-re-core`'s own `Cargo.toml` and `BUILD.bazel`, both
baked in with `include_str!`, and compares the declared dependency names against a forbidden
set. Apply the secondary test and the answer is the same: **adding `tokio` to
`mcp-re-core`'s dependency list admits, emits and signs exactly what it did before.** No
verdict changes, no timestamp is read differently, no signature is accepted that was not.
What the violation costs is the LOCALITY of every argument made about the Core — that a
Core verdict is a function of its inputs is reviewable because there is nothing else for it
to be a function of — and *that is a property of the EVIDENCE, not of the system, which is
this register's boundary.*

Note precisely what is and is not being said, because the forbidden-crate list names async
runtimes. The proposition is about the SHAPE of the dependency graph, not about how the Core
schedules, how fast it runs, how much it holds or what it does concurrently; none of those
is a fact this family admits, and a reading of the firewall that reached for one would be
widening the family rather than applying it. `mcp-re-proxy` is deliberately not guarded —
ADR-MCPRE-051 admits the async stack into the serving path, which is why the firewall is a
statement about where an argument is local and not a statement about async being unsafe.

**What would move a control out.** A demonstration that a violation admits, emits or signs
something the system does not today. `semantic_altitude_gate` is the likelier of the three:
if a sibling field is ever READ on a path that decides anything, the proposition stops being
about shape and the disposition becomes `new-proposition`. For the firewall the exit is
sharper still — a Core verdict that depends on something the Core reads from outside its
inputs. On that day purity is a runtime property and this is the wrong family.

## ND-009 — data-structure API robustness with no security proposition

**Covers:** `sdk/python/tests/test_correlation.py::TestRecordAndTake::test_iterating_yields_the_outstanding_requests`,
`::TestReaping::test_reaping_an_empty_store_is_a_no_op`,
`::TestTheStoreIsBounded::test_abandon_is_idempotent_and_never_raises`.
**Recorded:** 2026-09-19, ADR-MCPRE-069 Phase 069-B batch 5.

Three controls over the correlation store's API surface: that iterating yields the
outstanding entries, that reaping an empty store does nothing, and that abandoning twice
does not raise.

**Why they are not evidence.** Each asserts a TOTAL or IDEMPOTENT API behaviour. A violation
is a crash or a wrong iteration inside the adapter — not something the system admits, emits
or attributes, and not a clause of any proposition the graph holds. They are the reason the
adapter does not fall over, which is a different kind of good from the reason it cannot be
made to lie.

**Stated because `abandon` is the close call.** If `abandon` raised, an error path could
fail to retire an entry — which WOULD bear on `sdk_python.correlation_lifecycle`'s clause
that no remotely triggerable outcome leaves an entry outstanding. It is not registered
there because the control does not measure that: it measures that a second call does not
raise, over a store that the first call already emptied. The outstanding claim is measured
by the three boundedness controls registered in that unit, and those are the controls whose
failure would make it false.

**What would move a control out.** A control here that exercises the store on a path a
remote peer can drive. These three are driven by the test, not by a reply.

## ND-010 — a `compile_fail` doctest superseded by a structural probe

**Covers:** `mcp-re-http-profile` `doc#verified_response::bound::VerifiedMcpResponse`,
`doc#verified_response::bound::VerifiedDelegatedMcpResponse`,
`doc#verified_request::VerifiedMcpRequest`; `mcp-re-client-core`
`doc#delegated_trust::DelegatedResponseTrust`.
**Recorded:** 2026-09-19, ADR-MCPRE-069 Phase 069-B batch 8; the client-core item added by
the S-05/CL-CLIENT slice, which built its probes first.

Six `compile_fail` examples over four items, each a hostile construction the type system
must refuse. ADR-MCPRE-068 §12.1 called these "the best worked example of the defect in the
repository" — they were registered as `test://` evidence for a claim only a compile refusal
can make — and Phase 0B/0D moved the claim to `structural://` probes S01, S02, S03 and S05,
each of which names the very `doc_item` above in `structural-probes.toml`.

**Why the doctest itself is not evidence.** ADR-068's own reason, in the probe registry's
words: *rustdoc's expected-error-code annotation is checked only on nightly, so on the
pinned stable toolchain `compile_fail,E0308` and bare `compile_fail` are the same
declaration.* The doctest therefore passes when the example fails to compile for ANY reason
— a renamed import, a typo, an unrelated error — and cannot attribute the refusal to the
boundary. The structural probe compiles the identical construction itself and requires the
declared rustc error code with its primary span on the marker line.

So the example is **documentation of the seal, and the probe is the evidence for it.** That
is not a demotion: the doctest is the thing a reader reaches for first, and keeping it is
what makes the probe's construction checkable against a human-readable statement. It is
simply not the control the claim rests on.

**What would move a control out.** The pinned toolchain gaining a checked error-code
annotation for doctests, or the probe for an item being withdrawn. Either makes the doctest
the only control over that boundary again, and `test_structural_lane.py` already holds the
case where a probe's documented example has drifted from what the registry says it does.

**The ordering is part of the family, not a note beside it.** This record's own premise —
that the example is *superseded by a probe* — was FALSE for
`doc#delegated_trust::DelegatedResponseTrust` at `cf1cdf35`: `structural-probes.toml` held
four `doc_item` rows and none of them named `delegated_trust`, so ADR-MCPRE-069 §2.1's named
instance was covered by nothing at all. A control does not join this family because a probe
is planned for it. S26 and S27 were registered and demonstrated green BEFORE that row was
moved here, so at no point between the two states was the boundary claimed by a family whose
reason had not yet become true.

## ND-011 — a carrier the legality model admits no deployment to reach

**Covers:** every control in `mcp-re-proxy/src/ocsp.rs` (38).
**Recorded:** 2026-09-19, ADR-MCPRE-069 Phase 069-B batch 11.
**Scope:** `carrier-scope: admitted`.

The online-OCSP checker: responder signature verification, certid binding, freshness and
skew, nonce round-trip and match, delegated-responder validity window, the AIA-URL policy
that refuses a `file:` scheme, `localhost` and a loopback host BEFORE any fetch, the
hard-fail/soft-fail policy table, and a SHA-1 known-answer vector. Careful controls over a
careful verifier.

**Why they are not evidence.** `proxy.online_ocsp_reachability` is a registered unit whose
whole statement is that this carrier is unreachable: *"The legality model admits no
online-OCSP deployment: `OnlineRevocationEvidenceRequest::Required` is refused on the only
route to a `ValidatedDeployment`."* Its battery includes
`a_programmatic_config_cannot_claim_an_ocsp_check_the_serving_path_never_makes`. So no legal
deployment builds an `OcspChecker`, and a control over what that checker does establishes
nothing about any deployment MCP-RE admits.

**This is ADR-MCPRE-061 §8 question 9 arriving as a census result** — *what branches are
unreachable under the current legality model* — and the answer is unusual in being already
OWNED: the estate does not merely fail to reach this code, it has a unit that says so.

**What this is NOT.** It is not a finding that the code is dead in the delete-it sense, and
it is not a reason to remove the controls. `proxy.online_ocsp_reachability` exists so that
the refusal is a measured fact rather than an assumption, and the verifier's own controls
are what make re-admitting the mode a decision rather than a leap.

**What would move a control out, precisely.** The legality model admitting
`OnlineRevocationEvidenceRequest::Required` on any route to a `ValidatedDeployment`. On that
day `proxy.online_ocsp_reachability`'s statement becomes false, these 38 controls become
evidence for a proposition that must then exist, and the disposition is `register` or
`new-proposition` — never this family. The exit condition is mechanical: that unit's battery
goes red.

## ND-012 — a fixture or report GENERATOR

**Covers:** `mcp-re-conformance/tests/delegation_vectors_test.rs::write_delegation_fixtures`,
`http_profile_vectors_test.rs::write_http_profile_fixtures`,
`scitt_vectors_test.rs::write_scitt_fixtures`,
`scitt_interop_test.rs::write_verification_reports`,
`scitt_retained_corpus_test.rs::write_retained_corpus`.
**Recorded:** 2026-09-19, ADR-MCPRE-069 Phase 069-B batch 15.

Five `#[test]` functions that do not test anything: each regenerates a committed corpus or
verification report when run deliberately. They are the write half of the
regenerate-and-compare pattern whose READ half — *regenerated fixtures match the committed
bytes* — is a control and is dispositioned with its corpus.

**Why they are not evidence.** A generator cannot fail in a way that says a proposition is
false; it can only fail to produce a file. The proposition is carried entirely by the
comparison, and registering the generator beside it would put a control in a battery that,
if it went red, would mean the fixtures could not be rewritten — which is not a security
fact about anything.

**Why they are enumerated at all.** Because the census enumerates every `#[test]`, and a
kind of function that is not a control is exactly the kind of thing a person filters out of
a list and a machine must be told about. The alternative — teaching the enumerator to skip
`write_*` — would be a name-shaped rule that goes stale silently.

**What would move a control out.** A generator that also compares. Then it is a control and
belongs with its corpus.

## ND-013 — demo fixture material

**Covers:** `mcp-re-demo/tests/demo_fixtures_test.rs` (5).
**Recorded:** 2026-09-19, ADR-MCPRE-069 Phase 069-B batch 18.
**Scope:** `carrier-scope: admitted`.

Controls over the demo's own generated material: that the matching client identity
round-trips and equals the signer, that the mismatched client chains to the same CA but
differs from the signer, that the server leaf does not chain to the client CA, that the
trust JSON carries the signer's public key, and that writing the files materialises every
input and cleans up on drop.

**Why they are not evidence.** Their subject is the DEMO's fixtures — they establish that
the demo presents the situations it means to present. A violation makes a demonstration
misleading, not a deployment insecure, and no proposition MCP-RE makes is true or false
depending on them. `scripts/merge_path_gate.py` already rules on the demo runner in the same
words: *a demo runner, not a control*.

**What would move a control out.** A fixture that becomes a conformance vector. Then its
pinning is NP-080's subject and it is claimed there.

## ND-014 — an inert measurement apparatus no production path reads

**Covers:** `mcp-re-proxy` `lib#stage_timers::tests::` (7):
`stage_discriminants_are_distinct_and_cover_every_slot`,
`every_stage_indexes_within_the_accumulator`, `the_name_table_covers_every_slot`,
`each_stage_slot_carries_its_own_name`, `a_timer_started_while_disabled_reads_no_clock`,
`an_inflight_guard_taken_while_disabled_is_inert`,
`the_rewrite_period_cannot_divide_by_zero`.
**Recorded:** 2026-09-20, ADR-MCPRE-069 S-11/PX-STORE.

**The admission test, and it has three conjuncts because two would admit too much.** A
control belongs here when its carrier is a MEASUREMENT APPARATUS, meaning all three of:

1. its entire output is elapsed-time or count numbers about this process's own execution;
2. **no production path reads or branches on that output** — the numbers leave through a
   file or a stream and re-enter no decision; and
3. it is **INERT unless an operator switches it on**, so a deployment that configures
   nothing carries the apparatus and none of its behaviour.

**Why controls of that kind are not evidence.** Apply the register's own criterion — does a
violation change what the SHIPPED SYSTEM admits, emits, signs or exposes? Transpose two
stage discriminants and the system admits the same requests, emits the same bytes, signs
them under the same key and exposes the same surface; what changes is a number in a report
nobody's code reads. The boundary is not new and this family only transcribes it. THM-0012's
scope draws it in as many words about a value in the runtime record: *"RuntimeState::admits_requests
is a DESCRIPTIVE value, not a control: no production path consumes it"* — the distinction is
the consumer, not the subject. THM-0040's scope draws the same line for a whole vocabulary,
and reaches the same disposition: *"the refusal algebra is tested and deliberately carries no
theorem, because its vocabulary has no production reader today."* A family over apparatus
with no production reader is those two sentences applied to a carrier neither of them names.

**RR-002's ban does not reach this family, and the reason is stated rather than left to a
reader.** That review forbids creating or widening a family whose ADMISSION TEST turns on
availability, throughput, concurrency, latency, a resource ceiling or scheduling. This test
turns on none of the six: it turns on what the carrier IS (a measurement apparatus), on who
reads its output (nobody, in production), and on whether it is inert by default. That the
apparatus HAPPENS to measure latency is the subject of the numbers, not a term in the
admission test — the same seven controls would be admitted if the accumulator counted bytes
— and a test that admitted a control because a violation cost throughput would be the banned
shape. `a_timer_started_while_disabled_reads_no_clock` is the control that makes this worth
saying: its motivation is cost, and it is admitted here for conjunct 3, that the apparatus is
inert when off, which is a fact about the apparatus rather than a bound on anything.

**No standing unit declares a proposition this test would admit, and it was checked rather
than assumed.** The near miss is `proxy.client_revocation_currency` under THM-0131, whose
whole subject is operator-facing reporting — *"An operator reading this replica's revocation
posture is reading what it is doing"*, reaching the operator *"through stderr"*. It fails
conjunct 1: its output is not elapsed time or counts, it is a statement about whether a
SECURITY CONTROL is being enforced and at what cadence, and the theorem exists because a
replica went on advertising a hot reload while nothing re-read the files. It fails conjunct 3
as well — the posture is not something an operator switches on. `proxy.async_replay_retention`
is the other near miss and fails conjunct 1 for the same reason. No unit in the estate has
`stage_timers` in its `paths`, and the seven controls here are the whole of that carrier's
battery.

**What would move a control out.** The day a production path READS a stage timer's output:
if an accumulator is ever consulted by an admission, shedding, routing, retry or refusal
decision, the numbers stop being a report and become an input, and the control becomes
evidence for whatever that decision claims. Conjunct 3 gives a second exit — an apparatus
that stops being inert by default is running on every deployment, and a divide-by-zero or an
out-of-range slot in it is then a live refusal path rather than a report's arithmetic. Either
one makes this the wrong family, and the disposition becomes `new-proposition`.

## ND-008 — not a control: drivers, runners, reports and demos

**Covers:** `bump_version.sh`, `coverage.sh`, `demo-gcp-kms.sh`, `demo-local.sh`,
`local_gate.sh`, `local_slo_lane.sh`, `merge_readiness_gate.py`, `merge_verified_pr.py`,
`module_map.py`, `run_gate.sh`, `run_gate_selftest.sh`, `run_test_lane.sh`,
`runtime_topology_sweep.sh`, `saturation_liveness.sh`, `saturation_rig.sh`,
`startup_backedges.py`, `test-demos.sh`.
**Recorded:** 2026-09-19, ADR-MCPRE-069 Phase 069-B batch 2.

The census enumerates every executable file under `scripts/`, deliberately: an
under-inclusive enumeration is how a control kind goes dark, and ADR-069 §2.1 is what that
costs. These are the files that enumeration catches which are not controls at all — they
drive other controls, they print a report with no verdict, they run a demo, or they perform
an operation on the repository.

**Why they are not evidence.** They state no verdict, so there is nothing for a proposition
to rest on. `module_map.py` and `startup_backedges.py` print an architecture report;
`run_gate.sh` is the wrapper that keeps a verdict and an exit status one fact;
`local_gate.sh` is the driver that runs the others; `merge_verified_pr.py` performs a merge.

**This ruling is reused, not invented.** `scripts/merge_path_gate.py` already names four of
these in its own exemption list, in these words — *an architecture report with no verdict*,
*a demo runner, not a control*, *an SLO measurement, not an admissibility control*, *sourced
toolchain shim*. A second authority reaching a different answer about the same file would be
the defect this campaign exists to remove.

**What would move a control out.** A file here that grows a verdict of its own — an exit
status that means a property failed rather than an operation failed. `run_gate.sh --selftest`
is deliberately NOT such a case: it proves the wrapper cannot report a false green, which is
ND-003's subject, and it is invoked as a control from `local_gate.sh` stage 1 rather than
being one itself.

---

## The propositions

Eight, all from the gate lane, all at ADR-069 §5 **step 1: identified, not ratified**. Each
names a control that runs today, the production carrier it is about, what would be false if
the proposition failed, and the unit that would hold it. **None is registered against an
existing unit**, because §5 forbids widening a unit to swallow a proposition it does not
state — and in every one of these cases the nearby unit's proposition is about something
else.

## NP-001 — the SDK runtime support claim

**Controls:** `scripts/python_runtime_gate.py`, `scripts/node_runtime_gate.py`.
**Carrier:** `sdk/python/pyproject.toml`'s `requires-python`, `sdk/typescript/package.json`'s
`engines.node`, the prepared runtime matrices, and the deploy Dockerfiles that install the
shipped wheel.
**Statement.** *The interpreters a shipped package claims to support do not exceed the ones
its battery is measured on, and every deploy image installing that package names one of them
exactly.*
**If false.** A package advertises support for an interpreter no lane ever ran it on, and a
deploy image installs the wheel on one. Every behavioural proposition either SDK root makes
— exchange binding, verdict delivery, correlation lifecycle, nonce floor, bounded read — is
then asserted over a runtime nothing measured.
**Likely owner:** a new unit under each SDK; none exists. Measured over every `sdk_python.*`
and `sdk_typescript.*` unit: each is about a behavioural proposition of the transport, and
not one states a support claim.
**Root relationship.** Directly under **THM-0094** and **THM-0095**, the two SDK system
roots, both `critical`. Both theorems name these gates in their own text as what establishes
the claim.
**Provenance.** Identified by ADR-MCPRE-068 Phase 1 and recorded in
`verification/reviews/packets/gate-carriers-are-unowned-2026-09-18.md`, which corrected its
own first answer: an earlier version said REGISTER for all six unowned gate carriers, and
four were registered while these two were not, because there is no unit to register them
against. This record carries that disposition forward rather than restating it; what is new
here is that it is now machine-visible in the census instead of living in a packet.

## NP-002 — P-256 is confined to receipt verification

**Control:** `scripts/es256_containment_gate.py`.
**Carrier:** the `p256` dependency edge, the SCITT receipt verifier's modules, and the
http-profile verifier policy's algorithm registry
(`mcp-re-http-profile/src/policy.rs`), whose one-arm match over `ALG_ED25519` answers `None`
for every other token. `mcp-re-core`'s `ensure_ed25519_alg` was named here until it was
deleted: it gated on `SIG_ALG_ED25519` = `"Ed25519"`, a token the carrier never emits and the
live policy explicitly refuses, and it had no production caller.
**Statement.** *ECDSA P-256 is reachable only from receipt verification: `p256` is a
dependency of exactly one crate, referenced from exactly the COSE-key owner and its verifier
inside it, absent from `mcp-re-core`, and `ES256` stays refused by name for MCP-RE's own
request and response signatures.*
**If false.** MCP-RE's message-signing policy widens to admit ECDSA P-256 for the signatures
its authorization decisions rest on, without any decision being recorded — by someone
reaching for the P-256 verifier already sitting in the workspace. An algorithm accepted for a
third party's countersignature is not thereby accepted for MCP-RE's own.
**Likely owner:** a new unit over the containment edge; `core.*` owns the refusal and no unit
owns the reachability.
**Root relationship.** Under the signing roots. THM-0072's statement already says both
signatures are attempted "only under an algorithm the protected header names and the resolved
key agrees with, out of EdDSA and ES256 and nothing else" — which is the VERIFICATION
direction. The containment direction, that ES256 cannot cross into signing, is stated
nowhere.
**Severity:** `critical`.

## NP-003 — every long-lived worker's lifetime is an owned value

**Controls:** `mcp-re-proxy/src/managed_worker` (8).
**Carrier:** `managed_worker/mod.rs` and `managed_worker/halt.rs`.
**Statement.** *A long-lived worker's lifetime is represented by an owned value: a structural
halt is raised for every worker the set owns and by either source alone, it stays raised
after the set is gone so a straggler that wakes exits rather than resuming, reclamation is
bounded rather than guaranteed and a worker that does not stop in time is surfaced BY NAME
rather than silently detached, an interrupted sleep reports that it was cut short, and
reclaiming twice is harmless.*
**If false.** A worker outlives every value it was conceptually part of: nothing can stop it
and nothing can observe that it stopped. This is the historical defect, not a hypothetical —
startup had four, each looping on a SIGTERM flag no error path sets, so a `run` that failed
after the first spawn returned `Err` with threads still reading files and minting keys. The
fourth was found by accident, days after a survey that swept one file and concluded there
were three.
**Likely owner:** a new unit over `managed_worker`.
**Root relationship.** ADR-MCPRE-056 §9. Bears on the lifecycle roots — a recorded terminal
`Stopped` that leaves threads minting keys is the thing THM-0012 is about — without being
what THM-0012 states.
**Severity:** `high`.

**Narrowed and re-measured, ADR-MCPRE-069 S-11.** Two changes, and the second is the one that
matters.

**`scripts/owned_worker_gate.py` left this record for ND-007.** It is a SHAPE rule and its own
docstring says so: *"That is a syntactic check on two spellings, and the claim stops there."*
Apply the register's secondary test — can it go red on a weakening that leaves runtime
behaviour unchanged? — and the answer is yes twice over. It refuses the spelling wherever it
appears, including a spawn whose `JoinHandle` IS owned and joined, which is why its
allowlist has to carry the sound sites by hand; and it passes a helper that wraps the spawn,
a type alias, a `tokio::spawn` or a thread started inside a dependency, which the record
above already said. What it protects is the reviewability of the ownership argument, not an
admission the system makes.

**The eight behavioural controls stay, and S-11 measured why rather than inheriting it.** The
slice's plan expected them registered under THM-0104. They cannot be. THM-0104 is about
REQUESTS in the async serving path — *"ADMISSION STOPS. The accept loop exits before the drain
begins, so no request admitted after the signal exists."* — and its scope closes the door in
terms: *"ONE core, and the async path."* A background OS thread owned by a `WorkerSet` is
neither an admitted request nor a per-core runtime task, and the carrier says the two are
different lifetime questions: *"Tokio tasks on the per-core serving runtimes are a different
lifetime question — the fleet owns its runtimes and joins them on drain — and are
deliberately out of scope."* No other ratified theorem reaches it either: a sweep of all 130
`[[theorem]]` rows for worker, thread or teardown vocabulary returns THM-0012, whose scope is
*"Establishes what the RECORD can say"*, and this record already said that is not it.
Subsumption clause 2 needs a proposition contained in a ratified claim, and there is none.
**Packet:** `verification/reviews/packets/adr069-np-003-ratification-2026-09-20.md`.
## NP-004 — every optional capability states ON or OFF, in every lane

**Control:** `scripts/seam_posture_gate.py`.
**Carrier:** `startup_posture::Seam`, `Seam::ALL`, and the `posture.declare` calls in
`app.rs`.
**Statement.** *Every variant of `Seam` appears in `Seam::ALL` and is declared exactly once
at startup, so an operator reading a transcript can always distinguish "this capability is
off in this deployment" from "this build does not have this capability".*
**If false.** A seam ships silently unstated. Those two situations call for opposite
responses — set a flag, or rebuild — and a silent seam is indistinguishable from either.
**Why a runtime check does not cover it.** `PostureLog::assert_complete` refuses startup when
a seam went unstated and is strictly stronger where it runs — and it is never reached
hermetically, because the posture phase sits after the replay tier is established and every
accepted tier needs a live Redis or etcd. In `cargo test --workspace` and `bazel test //...`
the runtime check measures nothing, so a seam added without a declaration ships green.
**Likely owner:** `proxy.continuation_installation` owns ONE seam's declaration conjunct and
its unit comment says so in terms — *"the gate remains the repo-wide backstop for the other
seven seams, which is not this claim's subject."* The proposition over all eight is unowned.
**Severity:** `medium`.

## NP-005 — the `input_required` discriminator is open-coded in one place

**Control:** `scripts/discriminator_gate.py`.
**Carrier:** the client core, chain reconstruction, the proxy's open-leg recorder, and both
SDK bindings.
**Statement.** *The SEP-2322 `input_required` discriminator literal appears in exactly one
place, so the conformance guard that pins its VALUE protects every reader.*
**If false.** A rename in the final SEP-2322 text fails the value guard while leaving every
open-coded reader silently treating continuations as terminal — which is precisely the
outcome the value guard exists to prevent. Measured, not hypothetical: the literal had been
open-coded in five places, three of which collapsed a malformed non-terminal reply to
"terminal".
**Likely owner:** a new unit; the shape is exactly `conformance.verdict_vocabulary_scope`'s,
which ADR-MCPRE-068 §12.2 made the estate's first `measured` unit — *exactly two files decide
what a verdict token says*. This is the same proposition about a different vocabulary, and it
is a strong candidate for the same evidence class.
**Root relationship.** Under the client execution-contract roots; THM-0061 owns the
three-way discriminator itself and says nothing about how many places open-code it.
**Severity:** `high`.

## NP-006 — a deployment runs the artifact that was qualified

**Control:** `scripts/deploy_image_tag_gate.py`.
**Carrier:** `VERSION`, `deploy/cloudbuild/*.yaml`, `deploy/k8s/*.yaml`, the Helm chart, and
the runbooks and live-validation harnesses that deploy them.
**Statement.** *Every image reference on the deploy surface names the version in `VERSION`,
so what is built, what is referenced and what is deployed are one artifact.*
**If false.** A deployment runs an image that is not the one the release evidence is about,
and every assurance verdict that release carries is a statement about a different artifact.
**Likely owner:** a new unit over the deploy surface; no unit's `paths` name `deploy/`.
**Root relationship.** Bears on the transparency and release-evidence roots: the product's
own subject is that a record can be tied to what produced it, and an image tag retyped by
hand is that relation breaking one level below where the theorems look.
**Severity:** `high`.

## NP-007 — the shipped chart's fail-closed guards refuse

**Control:** `scripts/helm_render_gate.py`.
**Carrier:** `deploy/helm/mcp-re-proxy/templates/_helpers.tpl`.
**Statement.** *Each `{{- fail … }}` guard in the shipped chart actually refuses the
configuration it names at render time: a fleet on a node-local replay cache, a plaintext
Redis hop carrying admitted nonces, the shipped `did:example:` / `example.com` / `epoch-1`
placeholders, a transport binding that cannot start, an admission ceiling of zero.*
**If false.** An operator installs a chart whose guards render without refusing, and a fleet
starts on a node-local replay cache or a plaintext hop carrying admitted nonces — both of
which are refusals the proxy's own units establish for the proxy, and which the chart is the
only thing establishing for the deployment.
**Likely owner:** a new unit over the chart; no unit's `paths` name `deploy/helm/`.
**Root relationship.** THM-0077 — *no deployment serves a posture nobody selected* — is the
proposition one layer up, and the chart is where an unselected posture would be installed.
**Severity:** `critical`.

## NP-008 — no advertised conformance category lacks an executable witness

**Control:** `scripts/conformance_claims_gate.py`.
**Carrier:** the category table in `docs/conformance-guide.md`, the corpora under
`mcp-re-conformance/tests/vectors/`, and the `nt_rust_test` targets that reach them.
**Statement.** *Every advertised conformance category names a corpus that exists with a
manifest and at least one declared harness that reaches it; every corpus appears as a row;
and a corpus publishing a `corpus_digest` has a reaching harness that recomputes it.*
**If false.** A category advertised with no harness underneath it is a claim with no witness,
and it reads to an operator — or an auditor — exactly like a category that is proven. The
failure mode is silent in both directions.
**Likely owner:** `conformance.retained_corpus` is the nearest unit and is about the corpus's
retention, not about the advertised surface. A new unit, or an extension ratified as one.
**Root relationship.** This is a CLAIM-SURFACE proposition for a product-facing document,
which is `claim_surface_gate.py`'s shape applied to conformance rather than to theorems —
and unlike that gate, its subject is what the product tells an auditor.
**Severity:** `high`.

## NP-009 — the shipped adapter's end-to-end composition

**Controls:** `sdk/typescript/test/transport_e2e.test.ts` (5),
`sdk/python/tests/test_transport_e2e.py` (5).
**Carrier:** `McpReHttpTransport` / the Python transport adapter, against the real Rust
`http_profile_proxy` and a real MCP SDK Streamable-HTTP backend.
**Statement.** *An application calls `callTool` and nothing else — no sign, no verify, no
correlation — and the composition fails closed: a tampered response never reaches the
application, an unsigned one is refused, a signed rejection raises correlated rather than
hanging, and the hardening profile refuses a software key before connecting.*
**If false.** The claim each SDK adapter exists to make is false, and it is the composition
claim: every unit below it is about one property in isolation, and none of them says the
shipped adapter puts them together.
**Likely owner:** none. Measured over every `sdk_python.*` and `sdk_typescript.*` unit: each
states a property of the transport; not one states the composition.
**Root relationship.** THM-0094 and THM-0095 directly. This is their headline demonstration.
**Severity:** `critical`.

**The blocker, and it is the reason this is recorded rather than registered.** *These ten
controls run in no lane.* Both are conditional, for two different reasons, and both were
measured rather than assumed:

- the TypeScript half is `describe.runIf(existsSync(PROXY_BIN) && haveInnerBackend())`, and
  the vitest job builds the napi addon and runs `npx vitest run --coverage` without ever
  building `cargo build -p mcp-re-proxy --example http_profile_proxy` or installing the MCP
  SDK server. Every case skips.
- the Python half calls `pytest.importorskip("httpx")`, and `uv.lock` resolves `httpx2`.
  The whole module skips on import. ADR-MCPRE-068 Phase 1 recorded this and it is still
  true on main.

So registering them is not available: `verify-tests` requires each declared control to
PASS, and a skipped case is not a pass. **Ratifying this proposition means provisioning the
harness in a lane**, not writing a `tested_symbols` entry — and until then the strongest
evidence either SDK root could have is evidence nothing produces. That is the honest state,
and hiding it inside a unit that does run would be the false green this campaign exists to
remove.

## NP-010 — the shipped SDKs reproduce the frozen oracle byte for byte

**Controls:** `sdk/typescript/test/parity.test.ts` (7), `sdk/python/tests/test_parity.py` (8).
**Carrier:** each SDK's signing path, and `tools/gen_sdk_parity_fixture.py`'s frozen oracle.
**Statement.** *For every case the frozen oracle pins, each SDK's emitted signature bytes
equal the oracle's exactly and are deterministic across runs, and the two SDKs agree with it
on the profile tag.*
**If false.** The two SDKs and the Rust core disagree on the wire while every per-property
unit stays green, because each measures its own implementation against its own expectation.
Parity is the only control that compares them to a common fixed point.
**Likely owner:** none. `*.authorization_binding` says binding specs are "serialized
canonically and byte-identically to the TypeScript twin" / "to the Python twin" — which is
ONE conjunct of parity, about one field family, and is already claimed.
**Root relationship.** Under THM-0094 and THM-0095 jointly. It is the only proposition in
either root's neighbourhood that is about BOTH.
**Severity:** `critical`.
**Scope controls, and why they belong to this proposition rather than beside it.** Five of
the fifteen assert what the oracle CONTAINS — the expected schema, non-emptiness, all three
binding forms and not just DPoP, the pinned decision carrier holding the document and its
digest, the generic opaque case staying off the decision type, the notification envelope.
They are this proposition's `measurement_scope` in ADR-MCPRE-068 §4.1's sense: a parity
claim over a corpus that had quietly lost a case is a claim about a smaller corpus, and it
would read identically. They are not separable evidence and are not separately registered.
**What the controls do NOT establish, and any ratification inherits it.** That the two SDKs
BEHAVE the same. The fixtures pin emitted bytes for the cases they name and nothing else.

## NP-011 — custody class does not change the bytes

**Controls:** `sdk/typescript/test/parity.test.ts` (3), `sdk/python/tests/test_parity.py` (3),
`sdk/python/tests/test_custody.py` (1).
**Carrier:** each SDK's signer abstraction over software and non-exporting custody.
**Statement.** *Non-exporting custody produces byte-identical output to software custody; a
notification envelope carries no id in either custody class; and a signed continuation leg
signs differently from the open leg it answers.*
**If false.** Custody becomes observable on the wire — a verifier or a log could tell which
custody a deployment uses — or, in the other direction, a continuation leg signs the same
bytes as the leg before it, which is the evidence-reuse failure the continuation chain
exists to prevent.
**Likely owner:** `*.signer_policy` owns the POLICY — that the transport does not open
unless the signer satisfies the route's custody requirement. It says nothing about whether
the two custody classes are distinguishable afterwards.
**Root relationship.** Under THM-0094/THM-0095 beside NP-010, and bearing on the custody
propositions the proxy side already holds.
**Severity:** `high`.

## NP-012 — the artifact that ships implements the profile

**Controls:** `sdk/typescript/test/smoke.test.ts` (2), `sdk/python/tests/test_smoke.py` (3).
**Carrier:** the BUILT package — the napi native addon and the PyO3 wheel — not the source
tree every other unit's battery measures.
**Statement.** *The package as built and packed loads, reports a non-empty core version and
the RFC 9421 profile tag, and signs an MCP request as an RFC 9421 message.*
**If false.** Every `sdk_python.*` and `sdk_typescript.*` proposition is established over
source that the published artifact does not faithfully carry. This is not hypothetical
distance: both SDKs are native extensions, so the artifact is a build product and not the
files the unit paths name.
**Likely owner:** none. No unit's `paths` name a build product, and none could — a unit's
source closure is source.
**Root relationship.** Under THM-0094/THM-0095, and the same shape as NP-001: a claim about
what ships rather than about what was written.
**Severity:** `high`.

## NP-013 — every exchange terminates, and no slot is leaked

**Controls:** `sdk/typescript/test/transport.test.ts` (6),
`sdk/python/tests/test_transport.py` (4).
**Carrier:** each SDK transport's concurrency semaphore and exchange completion path.
**Statement.** *The number of exchanges in flight is bounded, so a burst cannot exhaust the
poster; exchanges run concurrently rather than head-of-line blocking; an invalid bound is
refused at construction rather than deadlocking; a slot is released even when an exchange
throws a non-`Error`; and a failure still completes the call when no handler is installed.*
**If false.** A caller's transport deadlocks or leaks slots until it stops making progress —
a client-side denial of service reachable by a peer that returns the wrong shape, and one
that presents as a hang rather than as an error.
**Likely owner:** `*.post_close_emission` (TypeScript) mentions "a request still queued at
the concurrency semaphore", which presumes the semaphore without claiming its bound;
`*.bounded_read` bounds a single response, not the number in flight.
**Root relationship.** Under THM-0094/THM-0095. The TypeScript file says in its own comment
that the two SDKs "must agree on how many exchanges may be in flight, not just on the bytes
they emit" — which is this proposition, stated in a test file and nowhere in the graph.
**Severity:** `medium`.

## NP-014 — after close, the Python SDK signs and transmits nothing

**Controls:** `sdk/python/tests/test_transport.py` (4).
**Carrier:** the Python transport adapter's `close`.
**Statement.** *After `close()`, further work is refused, in-flight work is aborted rather
than drained, an in-flight notification is aborted too, and nothing is delivered to a caller
that has left.*
**If false.** A transport keeps signing and transmitting after the application closed it.
**Likely owner:** none on the Python side.
**Root relationship.** Under THM-0094 — **and this is an ASYMMETRY between the two SDK
roots, which is why it is recorded separately from NP-013.** `sdk_typescript.post_close_emission`
exists, is `critical`, and states exactly this for the TypeScript adapter. There is no
`sdk_python.post_close_emission`. The Python controls are written, they pass, and the root
above them makes no claim they support. A twin promise held by one root and not the other
is not a bookkeeping gap; it is the two system roots promising different things.
**Severity:** `critical`, matching its TypeScript twin.

**Referred whole, ADR-MCPRE-069 S-07/SDK-S1.** All four rows stay. The blocker is
SUBSUMPTION, and it is not the one the slice's cluster analysis named — that analysis argued
that adding `sdk_python.post_close_emission` to THM-0094's `supported_by` republishes the
root, and `tools/verification/_fingerprint.py::fingerprint_theorem` refutes it: its
components are `encoding_version`, `theorem_id`, `theorem_claim` (`statement` +
`security_consequence` + `scope`), `theorem_dependencies` and `theorem_review_requirement`,
and `supported_by` is not among them. Adding the edge moves nothing.

What blocks it is that there is no edge to add. A new unit must be attached, and an
attachment asserts that the unit DECOMPOSES a proposition the ratified theorem already
contains. THM-0094 contains none: across its `statement`, `security_consequence` and `scope`
the only occurrence of *close* is *"fails the call closed"*, and the nearest clause — *"A
LOCAL failure — a transport deadline, a cancellation, a local I/O or signing failure — is
reported as a local and ambiguous failure under the SDK's own prefix"* — is about how an
aborted exchange is REPORTED, not about whether one is signed and transmitted. No unit in
its closure states it either: `sdk_python.correlation_lifecycle` already declares
`test_close_clears_abandoned_correlation_state`, and its claim is that no entry is left
outstanding, not that nothing is emitted.

THM-0095 does contain it, in scope, verbatim: *"The guard that stops a request still queued
at the concurrency semaphore from being signed and sent after `close()` reads this
transport's own state — assigned synchronously by `close()` before anything is aborted —
rather than `AbortSignal.aborted`."* So the asymmetry this record found at the unit layer is
also at the THEOREM layer, and closing it means amending THM-0094's `statement` or `scope`.
Both are `theorem_claim` components, so that is a ratification event and an owner decision
about what the Python root promises — R6, not a registration. Packet at
`verification/reviews/packets/adr069-np-014-ratification-2026-09-20.md`.

**Lane.** The four controls are in `sdk/python/tests/test_transport.py`, which opens with
`pytest.importorskip("mcp")`. They are selected and PASS in the authoritative lane — the
prepared `.venv-cp314` that `scripts/prepare_python_matrix.sh` builds, where the `dev` extra
supplies `mcp` — and select to ZERO in an environment without it. Whoever ratifies this
inherits that: the lane is the prepared interpreter, never a bare `pytest`.

## NP-015 — a device that cannot sign emits no evidence (Python)

**Controls:** `sdk/python/tests/test_custody.py::TestDeviceFailsClosed` (7).
**Carrier:** `sdk/python/python/mcp_re_sdk/custody.py`'s device signer.
**Statement.** *A signing device that throws, returns a non-`bytes` value, or returns a
signature of the wrong length raises `SignerUnavailable` and emits no evidence; the
underlying cause travels with it; `SignerUnavailable` is not a wire error; and a failure in
the CORE is not attributed to the device.*
**If false.** The adapter emits unsigned or wrongly-signed evidence when the device
misbehaves, or reports a local device failure as a peer-originated wire verdict — which is
the provenance confusion `*.local_failure_provenance` exists to prevent, arriving through
the custody path instead of the transport path.
**Likely owner:** `sdk_python.signer_policy`, and this is why it is a proposition rather
than a registration: **`sdk_typescript.signer_policy` says "a device that cannot sign fails
closed rather than emitting unsigned evidence" and `sdk_python.signer_policy` does not.**
The Python statement stops at the policy check and the rendering refusal. Seven controls are
written, they pass in the measured lane, and the unit above them makes no claim they support.
**Root relationship.** Under THM-0094. A second asymmetry between the two SDK roots, found
the same way as NP-014 and recorded separately from it because it is a different clause.
**Severity:** `high`, matching its TypeScript twin.
**Note on shape.** One of the seven is parametrised over signature lengths, and pytest's
generated ids for it embed raw bytes. That is a registration-mechanics problem for whoever
ratifies this, not a reason the proposition is absent, and it is recorded here so the
ratification meets it deliberately.

## NP-016 — the signing device is the key's sole holder

**Controls:** `sdk/python/tests/test_custody.py::TestNonExportingIsByteIdentical::test_the_device_is_the_sole_holder_of_the_key`,
`::test_signing_device_exposes_no_public_route_to_key_material`.
**Carrier:** `custody.py`'s non-exporting signer.
**Statement.** *Under non-exporting custody the device is the only holder of the key, and the
signer exposes no public route by which the material could be obtained.*
**If false.** Non-exporting custody is a label rather than a property: the material is
reachable from the process that was supposed not to hold it, and every hardening-profile
refusal above it is enforcing a distinction that does not exist.
**Likely owner:** `sdk_python.signer_policy` says *key material is never rendered*. That is
about RENDERING — a `repr`, a log line, a string conversion. **Unconstructibility is a
different and stronger claim**, and registering these two against the rendering clause would
make the unit's evidence cover a seal its statement does not assert. This is exactly the
`register`-misapplied case ADR-069 §5 names.
**Root relationship.** Under THM-0094, and the same shape as the proxy-side
`*_sole_producer` units ADR-MCPRE-068 Phase 0D created — which suggests the ratified form is
`structural`, not `tested`.
**Severity:** `critical`.

## NP-017 — a signer cannot be constructed from illegal material

**Controls:** `sdk/python/tests/test_custody.py::TestCustodyClasses::test_rejects_a_seed_that_is_not_32_bytes`,
`::test_rejects_a_non_callable_sign_callback`.
**Carrier:** `custody.py`'s two constructors.
**Statement.** *No software signer exists whose seed is not exactly 32 bytes, and no device
signer exists whose sign callback is not callable.*
**If false.** A signer is constructible over a short seed — a weaker key than Ed25519's
contract — or over a device that cannot be called at all, and the failure appears later, at
signing time, as something else.
**Likely owner:** `sdk_python.signer_policy` is about what the POLICY admits at open time;
this is about what the VALUE admits at construction. The repository's own rule is the
distinction: *the invariant belongs to the value, not to the code that builds it*, and a
policy check is the code that builds it.
**Root relationship.** Under THM-0094.
**Severity:** `high`.

## NP-018 — the correlation entry is the request's audit record

**Controls:** `sdk/python/tests/test_correlation.py::TestRecordAndTake::test_the_correlation_id_is_the_request_evidence_handle`,
`::test_the_store_carries_the_audit_fields_the_adr_enumerates`.
**Carrier:** `sdk/python/python/mcp_re_sdk/correlation.py`'s entry.
**Statement.** *A request's correlation id IS its evidence handle — not a separate local
key that happens to accompany one — and the entry carries every audit field ADR-MCPS-044
enumerates.*
**If false.** The adapter holds a local bookkeeping key beside the evidence handle, and the
two can diverge: an entry retired under one identity while a reply arrives under the other,
and an audit record that names fewer facts than the ADR says it must. The first is the
`identity, not locator` failure this repository has ruled on before; the second is an audit
record that reads as complete.
**Likely owner:** `sdk_python.correlation_lifecycle` is a WINDOW claim plus the store's
refusals. It says nothing about what the entry IS or what it carries.
**Root relationship.** Under THM-0094, and adjacent to the proxy-side audit-record
propositions, which are about the record the proxy writes rather than the one the client
keeps.
**Severity:** `high`.

---

## The Python authorization-binding asymmetry — NP-020 through NP-024

One clause, present in the TypeScript unit and absent from its Python twin, accounts for
twenty-two unclaimed controls in one file. `sdk_typescript.authorization_binding` says:

> … the core digests the real artifact material and a caller is given no way to supply a
> precomputed digest or to mint half a binding pair; and the digest retained per outstanding
> request identifies which artefacts the request was bound to without ever being
> re-interpreted.

`sdk_python.authorization_binding` says everything after the semicolon and nothing before
it. This is the THIRD asymmetry between the two SDK roots this campaign has measured, after
NP-014 and NP-015, and it is the largest: the Python file's controls are written, they pass
in the measured lane, and the unit above them makes no claim they support.

The clause is not one proposition. It is decomposed here the way the controls decompose,
rather than registered as one, because question 1 of ADR-MCPRE-061 §8 applies: an answer
that needs an "and" is a shallow boundary.

**`sdk_python.authorization_binding` IS AND STAYS THEOREM-LESS, and this is settled here
rather than inherited.** Two registries appeared to disagree about it: it is in no theorem's
`supported_by`, while `mutation-probes.toml` had `M211` and `M212` carrying
`theorem = "THM-0094"`. THM-0094's ratified `scope` decides it, in its own words:

> REQUEST-SIDE ATTRIBUTION IS OUTSIDE IT. Which identity may sign, and under which custody
> class, is `sdk_python.signer_policy`; which authorization artefacts a request is bound to
> is `sdk_python.authorization_binding`. Remove either and the answer the application
> receives still binds to the request that was sent, which is why neither is in this
> closure.

So the unit is theorem-less BY DECISION, and attaching it would contradict a ratified
sentence rather than decompose one — `scope` is a `theorem_claim` component, so changing that
sentence is a ratification event. The probes are the side that was wrong, and `M178`, `M201`,
`M202`, `M211` and `M212` — every probe on a Python unit that same scope excludes by name —
no longer carry a `theorem`. They are reported under their unit, which is what they evidence.
The key is optional and the lane reads it only to print it, so nothing else moves.

## NP-020 — the core digests the real artifact, and the caller supplies no digest

**Controls:** `test_authorization.py` (9) — the core digests the real artifact, a caller
cannot pass a precomputed digest, there is no parameter for the digest, changed bytes change
the digest, the digest is deterministic, the reference form binds the real bytes and names
the system, the document travels and the core mints its binding, the reference digest equals
the opaque digest for the same bytes, and `str` and `bytes` produce the same carrier.
**Carrier:** `sdk/python/python/mcp_re_sdk/authorization.py` and the native binding seam.
**Statement.** *The digest in the signed evidence is computed by the core over the artifact
material the provider supplied; no caller-facing route accepts a precomputed one; the same
material always produces the same digest whatever its Python type; and different material
produces a different one.*
**If false.** A caller supplies a digest that does not correspond to the artifact, and the
signed evidence binds a request to something that was never presented. That is the whole
point of a binding, and it is the failure the file's own docstring names — *bind, do not
interpret* — checked against an independent stdlib SHA-256 oracle rather than the core's own
opinion of what it computed.
**Likely owner:** `sdk_python.authorization_binding`, once its statement carries the clause
its TypeScript twin already does.
**Root relationship.** Under THM-0094.
**Severity:** `critical`.

## NP-021 — a binding carries metadata, never the artifact

**Controls:** `test_authorization.py` (2) — the binding carries metadata only and never the
artifact; the reference form leaks no secret material.
**Statement.** *What travels in the signed evidence is the digest and the metadata naming
the artifact's type and system — never the artifact bytes, and never secret material a
reference form was given.*
**If false.** Authorization material — a token, a document, a credential — is copied into
evidence that is signed, transmitted and retained. A signature base carries covered values,
so anything placed there is in every retained copy of the base.
**Likely owner:** `sdk_python.authorization_binding`.
**Severity:** `critical`.

**Referred whole, ADR-MCPRE-069 S-07/SDK-S1.** Both rows stay. `sdk_python.authorization_binding`
states, in full: *"The authorization binding specs a request carries are the ones the
configured policy permits, serialized canonically and byte-identically to the TypeScript
twin, and the digest retained per outstanding request identifies which artefacts the request
was bound to without ever being re-interpreted."* It claims what a request carries is the
PERMITTED set and that the retained digest is not re-interpreted. It does not claim that the
artifact bytes never travel, and it says nothing whatever about secret material a reference
form was given. Registering these two there means writing that clause into the unit — which
is minting a proposition at the unit layer, the same edit that puts NP-020, NP-023 and
NP-024 out of this slice, and the severity gap says the same thing from the other side: this
proposition is `critical` and the unit is `medium`. Packet at
`verification/reviews/packets/adr069-np-021-ratification-2026-09-20.md`.

## NP-022 — the generic provider cannot mint half a binding pair

**Controls:** `test_authorization.py::TestTheGenericProviderCannotMintHalfAPair` (3) — the
wrapper refuses the generic opaque form, the native seam refuses it independently, and the
reference form is untouched.
**Statement.** *No caller can produce one half of a binding pair through the generic opaque
provider: the Python wrapper refuses it, and the native seam refuses it independently of the
wrapper.*
**If false.** A binding exists whose two halves were minted separately, so the pair asserts
a correspondence nothing established.
**Why the third control matters, and why it is in this proposition rather than beside it.**
"the reference form is untouched" is the anti-vacuity arm: a refusal that also refused the
legitimate form would satisfy the first two and break the feature.
**Likely owner:** `sdk_python.authorization_binding`. Its TypeScript twin states this clause
verbatim.
**Severity:** `high`.

**Referred whole, ADR-MCPRE-069 S-07/SDK-S1.** All three rows stay, and *the TypeScript twin
states it verbatim* is the reason rather than the remedy. `sdk_typescript.authorization_binding`
carries *"a caller is given no way to supply a precomputed digest or to mint half a binding
pair"*; the Python twin's description carries everything after that clause's semicolon and
not the clause. Registering these three under the Python statement asserts a promise it does
not make, which is the unit-layer minting this slice forbids. Packet at
`verification/reviews/packets/adr069-np-022-ratification-2026-09-20.md`.

## NP-023 — a binding provider refuses illegal material at construction

**Controls:** `test_authorization.py` (6) — empty material fails closed in both provider
forms, an unregistered artifact type fails closed in both, a partial reference fails closed,
and an empty decision fails closed.
**Statement.** *No binding provider exists over empty material, an unregistered artifact
type, a partially specified reference, or an empty decision.*
**If false.** A provider is constructible over material that names nothing, and the failure
appears later — at signing time, as something else, or not at all.
**Likely owner:** `sdk_python.authorization_binding` is about what the POLICY permits at
request time. This is about what the VALUE admits at construction, which is the same
distinction NP-017 draws for custody: the invariant belongs to the value, not to the code
that builds it.
**Severity:** `high`.

## NP-024 — a request acts under at most one authorization decision

**Controls:** `test_authorization.py::TestAuthorizationDecision::test_a_request_acts_under_at_most_one_decision`,
`::test_the_document_appears_exactly_once`.
**Statement.** *A request carries at most one authorization decision, and the decision
document appears exactly once in the evidence it rides in.*
**If false.** A verifier reading the evidence has two answers to *what authorized this
call*, or one answer written twice — and a duplicate is how two readers of one message come
to disagree about what it says.
**Likely owner:** `sdk_python.authorization_binding`.
**Severity:** `high`.

---

## The command line is an authority nothing owns — NP-025 through NP-035

`mcp-re-proxy/src/cli.rs` holds **142 controls and is in no unit's `paths`** — and the `cli`
module tree it declares (the fourteen `mcp-re-proxy/src/cli/*_flags*` files) holds **59 more,
also unclaimed, for 201 across 15 files.** It is the
single largest unclaimed carrier in the repository, and its controls are not incidental:
*a zero timeout is refused because it disables the slow-loris defense*, *attested ingress
without pinned mTLS fails closed*, *the default build rejects the AWS KMS key source*, *a
plaintext KMS endpoint to a remote host is refused*, *an argv PKCS#11 PIN is refused with
the replacement named*.

**A constraint on whoever registers NP-026, recorded here because it is invisible from the
registry.** Four of NP-026's `cli.rs` controls sit behind NEGATIVE feature gates —
`default_build_rejects_pkcs11_key_source` under `#[cfg(not(feature = "pkcs11_keysource"))]`,
and the same shape for `dev_env_key_source`, `aws_kms_keysource` and `gcp_kms_keysource`. They
exist only in the DEFAULT-feature lane. A unit declaring
`test_features = ["aws_kms_keysource", "gcp_kms_keysource"]` — which the neighbouring
`proxy.kms_endpoint_authority` already declares — compiles all four to zero tests and reports
green, which is this repository's standing false-green shape. **The argv key-source unit must
declare no `test_features`.**

**It is invisible to the adjacent authority as well.** `scripts/unit_closure_gate.py`
registers files the module tree REACHES from a measured unit; `cli.rs` is declared by a
crate root no unit names, so it is not reached, and its production half is outside that
register too. That is ADR-MCPRE-061's question and is referred there rather than answered
here — but it is worth recording that two registers disagree about nothing, because neither
can see this file.

**Why these are propositions and not registrations.** The `config_state::*` units are
carefully scoped to a CLASSIFIER at its own API — `proxy.cross_machine_legality` says so in
terms: *"Every relation reads classified owner states rather than raw request fields"*. The
CLI is the authority one layer up: it decides what an operator can SAY, and it refuses
things no classifier ever sees. `default_build_rejects_aws_kms_key_source` is a fact about
a Cargo feature, `unknown_flag_errors` is a fact about the parser, and
`argv_pkcs11_pin_is_refused_with_the_replacement_named` is a fact about a withdrawn flag.
Registering these against a classifier unit would put the argv boundary inside a statement
that explicitly excludes raw request fields.

**Eleven propositions and not one.** *The command line admits no illegal deployment* needs
an "and" for every authority it covers, and ADR-MCPRE-061 §8 question 1 is that an answer
needing an "and" is a shallow boundary. Each of the eleven below has a distinct
`config_state` neighbour one layer down, which is the evidence that the decomposition
follows the estate's own seams rather than the file's headings.

| id | proposition | controls | severity |
|---|---|---:|---|
| NP-025 | the parser is total and diagnoses completely | 11 | `medium` |
| NP-026 | a key source is admitted only in a build that carries it, with its whole flag set | 30 | `critical` |
| NP-027 | a KMS endpoint is a literal HTTPS authority, or loopback HTTP for an emulator | 8 | `critical` |
| NP-028 | admission is off unless an argv names a complete enforcing configuration | 12 | `high` |
| NP-029 | the strict guard is always on for a safe configuration and reports every violation at once | 17 | `critical` |
| NP-030 | the client-certificate posture an argv can express fails closed by default | 20 | `critical` |
| NP-031 | a replay tier is named exactly once and carries what it cannot run without | 11 | `critical` |
| NP-032 | the trust-refresh posture an argv can express holds its cadence to its window | 14 | `high` |
| NP-033 | attested ingress is configured whole or not at all | 9 | `critical` |
| NP-034 | no command line disables a liveness bound | 4 | `high` |
| NP-035 | the serving target an argv names binds something | 6 | `high` |

## NP-025 — the parser is total and diagnoses completely

**Controls:** `mcp-re-proxy/src/cli.rs` (11), `mcp-re-proxy/src/cli/protocol_flags` (1).
**Carrier:** `mcp-re-proxy/src/cli.rs` — the argv boundary.
**Likely owner:** none. Its `config_state::*` neighbour owns the CLASSIFICATION of the same subject and explicitly does not own raw request fields.
**Root relationship:** THM-0077 — *no deployment serves a posture nobody selected* — is the root above this family, and the command line is where a posture is selected.
**Severity:** `medium`.

*Every argv is answered: an unknown flag, a missing required flag and a bad
value are each named, a command line wrong three ways is answered about all three, and every
default a minimal configuration takes is stated rather than inferred.* If false, an operator
who mistypes a security flag gets a deployment that silently omits it — the class where a
misspelling reads as an absent declaration rather than as an error.

## NP-026 — a key source is admitted only in a build that carries it

**Controls:** `mcp-re-proxy/src/cli.rs` (30), `mcp-re-proxy/src/cli/channel_flags` (2),
`mcp-re-proxy/src/cli/signing_source_flags` (5).
**Carrier:** `mcp-re-proxy/src/cli.rs` — the argv boundary.
**Likely owner:** none. Its `config_state::*` neighbour owns the CLASSIFICATION of the same subject and explicitly does not own raw request fields.
**Root relationship:** THM-0077 — *no deployment serves a posture nobody selected* — is the root above this family, and the command line is where a posture is selected.
**Severity:** `critical`.

*A key source reaches a deployment only from a build that carries it — the
default build refuses AWS KMS, GCP KMS, PKCS#11 and the env source — and only with every
flag that source cannot operate without; a TLS key named through a KMS may not also be
exported; and the withdrawn argv PKCS#11 PIN is refused with its replacement named.* If
false, a deployment signs under a key source nobody built for, or under a half-configured
one, or an operator's PIN travels in a process argument list where every other process on
the host can read it. `critical`, and the largest group in the file.

## NP-027 — a KMS endpoint is a literal HTTPS authority

**Controls:** `mcp-re-proxy/src/cli.rs` (8).
**Carrier:** `mcp-re-proxy/src/cli.rs` — the argv boundary.
**Likely owner:** none. Its `config_state::*` neighbour owns the CLASSIFICATION of the same subject and explicitly does not own raw request fields.
**Root relationship:** THM-0077 — *no deployment serves a posture nobody selected* — is the root above this family, and the command line is where a posture is selected.
**Severity:** `critical`.

*A KMS endpoint an operator names is an `https` URL with a literal host and no
userinfo, or an `http` loopback for an emulator, and nothing else.* If false, key operations
are directed at a host resolved by name at use time, over plaintext, or under credentials
smuggled in an authority — three different ways to move signing to an endpoint the operator
did not choose.

**PARTIALLY DISCHARGED, 2026-09-19 (ADR-MCPRE-069 §5).** One control of the nine this record
had carried since batch 12 —
`lib#kms_endpoint_policy::tests::a_bracketed_host_must_be_an_ipv6_literal` — is an **R1**: the
existing `[[unit]]` `proxy.kms_endpoint_authority` already declares
`mcp-re-proxy/src/kms_endpoint_policy/mod.rs` in its `paths`, and its description already
states the proposition — *"A KMS endpoint's literal spelling and its machine interpretation
name the same authority: the host and port a reader sees are the host and port that will be
reached."* A bracket is IPv6 notation and nothing else, so a bracket-shaped host that is not an
address is exactly a spelling whose interpretation differs from its reading. The selector was
registered into that unit's `tested_symbols`; no `paths` widened, no unit was created, no
theorem field moved, and the unit's three existing falsifiers — M215, M216 and M217, all
demonstrated red before — continue to carry it.

**WHAT REMAINS.** The eight `cli::tests` controls above are the argv arm and this record keeps
them. They belong with NP-025 … NP-035 to a pending owner decision about the command-line
boundary; `cli.rs` is in no unit's `paths` and must not be added to one to make a selector
resolve.

## NP-028 — admission is off unless an argv names a complete enforcing configuration

**Controls:** `mcp-re-proxy/src/cli.rs` (12), `mcp-re-proxy/src/cli/admission_flags` (13),
`mcp-re-proxy/src/cli/runtime_flags` (3).
**Carrier:** `mcp-re-proxy/src/cli.rs` — the argv boundary.
**Likely owner:** none. Its `config_state::*` neighbour owns the CLASSIFICATION of the same subject and explicitly does not own raw request fields.
**Root relationship:** THM-0077 — *no deployment serves a posture nobody selected* — is the root above this family, and the command line is where a posture is selected.
**Severity:** `high`.

*Admission is off by default; an enforcing configuration parses only with an
authority and a source; a dangling setting, an unknown mode, both limits at once, a zero
ceiling and an undecodable authority key are each refused; and an explicit ceiling equal to
the default is not an absent one.* If false, a deployment reads as admitting nothing while
admitting everything, or an operator's explicit choice is indistinguishable from silence —
which is the provenance failure this repository has ruled on before.

## NP-029 — the strict guard is always on, and reports every violation at once

**Controls:** `mcp-re-proxy/src/cli.rs` (17).
**Carrier:** `mcp-re-proxy/src/cli.rs` — the argv boundary.
**Likely owner:** none. Its `config_state::*` neighbour owns the CLASSIFICATION of the same subject and explicitly does not own raw request fields.
**Root relationship:** THM-0077 — *no deployment serves a posture nobody selected* — is the root above this family, and the command line is where a posture is selected.
**Severity:** `critical`.

*The unsafe-configuration guard is on for every safe configuration, reports
every violation of an unsafe one at once, and refuses the legacy CN identity source, a
disabled or over-ceiling certificate lifetime, an LB assertion binding, a `none` transport
binding and a weak replay durability tier — and a fully configured Mode C clears every
completeness check and is still refused.* If false, the guard passes a deployment it exists
to refuse, or reports one violation and hides the rest, so a fix produces a second failure
and the operator learns the shape of the guard rather than the shape of the problem.

## NP-030 — the client-certificate posture an argv can express fails closed by default

**Controls:** `mcp-re-proxy/src/cli.rs` (20), `mcp-re-proxy/src/cli/revocation_flags` (2).
**Carrier:** `mcp-re-proxy/src/cli.rs` — the argv boundary.
**Likely owner:** none. Its `config_state::*` neighbour owns the CLASSIFICATION of the same subject and explicitly does not own raw request fields.
**Root relationship:** THM-0077 — *no deployment serves a posture nobody selected* — is the root above this family, and the command line is where a posture is selected.
**Severity:** `critical`.

*By default there are no CRLs, unknown revocation status fails closed and online
OCSP is off and hard-fail; `client-ocsp-require` fails closed in every build; a responder URL
without the requirement, an empty segment in a CRL or revocation list, an unparseable or
overflowing certificate lifetime, and an unknown identity source are each refused; repeated
and comma-separated CRL flags accumulate rather than replace; and a revocation list nothing
consults is refused rather than accepted and ignored.* If false, a listener admits a client
certificate whose revocation status was never established, and the deployment's transcript
says it was configured to check.

## NP-031 — a replay tier is named exactly once and carries what it cannot run without

**Controls:** `mcp-re-proxy/src/cli.rs` (11), `mcp-re-proxy/src/cli/storage_flags` (3).
**Carrier:** `mcp-re-proxy/src/cli.rs` — the argv boundary.
**Likely owner:** none. Its `config_state::*` neighbour owns the CLASSIFICATION of the same subject and explicitly does not own raw request fields.
**Root relationship:** THM-0077 — *no deployment serves a posture nobody selected* — is the root above this family, and the command line is where a posture is selected.
**Severity:** `critical`.

*Exactly one replay store is named; omitting the configuration is refused;
naming both on one command line is refused; a shared store carries its URL and its
durability tier; a linearizable tier carries its cpstore endpoint and a cpstore endpoint
without one is refused; and a single node may take the file cache.* If false, a fleet runs
on a node-local replay cache while reading as configured for a shared one — the exact
deployment the shipped Helm chart's own guard refuses (NP-007).

## NP-032 — the trust-refresh posture holds its cadence to its window

**Controls:** `mcp-re-proxy/src/cli.rs` (14), `mcp-re-proxy/src/cli/currency_flags` (4),
`mcp-re-proxy/src/cli/delegated_signing_flags` (2).
**Carrier:** `mcp-re-proxy/src/cli.rs` — the argv boundary.
**Likely owner:** none. Its `config_state::*` neighbour owns the CLASSIFICATION of the same subject and explicitly does not own raw request fields.
**Root relationship:** THM-0077 — *no deployment serves a posture nobody selected* — is the root above this family, and the command line is where a posture is selected.
**Severity:** `high`.

*A trust epoch is named; a URL-shaped epoch source and the push tier require
each other; live and push tiers require a reload cadence and every cadence is held to the
window it claims; the revocation tier defaults to a bounded cache; a degraded window is
positive and its refusal names the clock-skew term; and the maximum clock skew is accepted
across its whole bound and refused at parse outside it.* If false, a replica enforces a
trust picture it stopped refreshing, or refreshes on a cadence longer than the window it
claims to hold — a posture that states a currency it does not have.

## NP-033 — attested ingress is configured whole or not at all

**Controls:** `mcp-re-proxy/src/cli.rs` (9), `mcp-re-proxy/src/cli/peer_identity_flags` (4).
**Carrier:** `mcp-re-proxy/src/cli.rs` — the argv boundary.
**Likely owner:** none. Its `config_state::*` neighbour owns the CLASSIFICATION of the same subject and explicitly does not own raw request fields.
**Root relationship:** THM-0077 — *no deployment serves a posture nobody selected* — is the root above this family, and the command line is where a posture is selected.
**Severity:** `critical`.

*Attested ingress is configured whole or not at all: it requires an attestor key,
an identity and an audience, it fails closed without pinned mTLS, its flags do not dangle
without the binding, an invalid or malformed LB key is refused, a duplicate LB key id is
refused, and an LB assertion binding requires at least one key.* If false, ingress
attestation is half-configured — flags present, binding absent — and the deployment believes
a hop it never verified.

## NP-034 — no command line disables a liveness bound

**Controls:** `mcp-re-proxy/src/cli.rs` (4), `mcp-re-proxy/src/cli/runtime_flags` (2),
`mcp-re-proxy/src/inner_plane_bound.rs` (1).
**Carrier:** `mcp-re-proxy/src/cli.rs` — the argv boundary.
**Likely owner:** none. Its `config_state::*` neighbour owns the CLASSIFICATION of the same subject and explicitly does not own raw request fields.
**Root relationship:** THM-0077 — *no deployment serves a posture nobody selected* — is the root above this family, and the command line is where a posture is selected.
**Severity:** `high`.

*No command line disables a liveness bound: a zero timeout is refused because it
disables the slow-loris defense, the connection-age bound is defaulted and zero is refused,
a request deadline over the cap is refused, and the defaults are bounded so the refusal
never fires by default.* If false, a single operator flag turns off the defence against a
class of denial of service, and the default configuration is the one that exercises it.

## NP-035 — the serving target an argv names binds something

**Controls:** `mcp-re-proxy/src/cli.rs` (6), `mcp-re-proxy/src/cli/protocol_flags` (1),
`mcp-re-proxy/src/cli/serving_flags` (3).
**Carrier:** `mcp-re-proxy/src/cli.rs` — the argv boundary.
**Likely owner:** none. Its `config_state::*` neighbour owns the CLASSIFICATION of the same subject and explicitly does not own raw request fields.
**Root relationship:** THM-0077 — *no deployment serves a posture nobody selected* — is the root above this family, and the command line is where a posture is selected.
**Severity:** `high`.

*The serving target an argv names binds something: an empty or missing target
URI is refused, a target that binds nothing is refused at the validation boundary, an inner
HTTP URL is present and has no empty segment, repeated and comma-separated URLs accumulate,
and a fleet-wide target does not erase the per-core default.* If false, the proxy serves an
endpoint nobody named, or silently drops one an operator did name.

## NP-037 — a guard's inputs resolve, or the guard fails loudly

**Controls:** `mcp-re-test-paths/src/lib.rs` (4),
`src/traceability_sources.rs` (2).
**Carrier:** `mcp-re-test-paths`'s binary/fixture resolver and the two declaration tables it
falls back through — `SOURCE_FALLBACKS` and `TRACEABILITY_SOURCES` — beside `BINARY_KEYS`.
**Statement.** *An unknown key is refused rather than resolved to an empty path; no key is
declared twice; no binary key is also a source fallback; and every declared fallback and
witness names a file that exists.*
**If false.** A guard resolves its input to an empty path, walks nothing, finds nothing and
reports a clean tree. That is the exact false-green class this repository has already
measured twice — a `tests/` glob that silently exempted a crate from the srcs gate for a
whole campaign, and an empty join that read as a clean tree — and the resolver is where the
first of those enters.
**Likely owner:** none. The resolver is in no unit's `paths`; the tables it holds decide
what several guards see.
**Root relationship.** Not under a product root. It is a premise of the guards.
**Severity:** `high`.
**Registered in part, ADR-MCPRE-069 RM-S2 — the source-TREE half only, and the record now
describes exactly the six controls that remain.** The record was filed over nine controls and
three tables, and ADR-069 RR-002 C5 forbids one disposition over a heterogeneous set. The
three `src/source_trees.rs` controls are now `unit://conformance.scanned_tree_declaration`
under **THM-0111**, whose scope states the walk they are a premise of in terms — *"The control
walks every crate's source tree, takes each file's production half, and asserts the set of
files holding a verdict literal is exactly the two frozen vocabularies"* — with falsifier
`M325`, which makes an unknown key resolve to an EMPTY path and turns
`an_unknown_key_names_no_tree` red. That is this record's own "if false" reproduced in one
edit, and it is why the sentinel table could be separated from the rest: the walk THM-0111
runs resolves through `SOURCE_TREES` and through nothing else here.
**Six rows REMAIN, and they are a second proposition rather than a remainder.** `BINARY_KEYS`,
`SOURCE_FALLBACKS` and `TRACEABILITY_SOURCES` name a built executable, a fixture FILE a guard
parses, and a test that witnesses a claim. THM-0111's walk consults none of them, so a
registration reaching them would have to widen a unit's `paths` past the source it measures —
the quiet widening ADR-069 §5 holds to be strictly worse than leaving a control unregistered.
They serve the proxy and auditor integration lanes and the traceability manifest guard, which
are several theorems rather than one, and no theorem in this registry states that a guard's
declared inputs resolve. The referral and the shape a ratification would take are recorded in
[`verification/reviews/packets/adr069-np-037-ratification-2026-09-19.md`](../../verification/reviews/packets/adr069-np-037-ratification-2026-09-19.md).

## The external transparency auditor — NP-039 through NP-043

`mcp-re-proxy/src/transparency/auditor/**` holds **58 controls and is in no unit's
`paths`.** It is the v0.18-C auditor: a shipped binary (`mcp-re-auditor`) with its own
invocation parser, its own trust profile, its own registration client and its own artifact
format. The whole feature is outside the assurance graph.

It is the same shape as the command line (NP-025 … NP-035) one product step later: a
deployable whose controls are careful and whose propositions are unstated. Five
propositions, one per authority the subtree actually separates — the directories are the
seams here, and they were drawn by the implementation rather than by this campaign.

## NP-039 — the auditor's invocation is total

**Controls:** `auditor/invocation/mod.rs` (14), `invocation/flag.rs` (3),
`invocation/instant.rs` (4).
**Statement.** *Every auditor invocation is answered: a single-valued flag given twice is
refused rather than resolved, a value never given is refused BY NAME, an unknown flag is
refused with the usage, a flag with no value is refused, every required flag is required, a
hop that is not a digest is refused, hop order is kept, a registration budget without a
target and an inadmissible target are refused at parse, an audit instant that is not a
timestamp or is at or before the epoch is refused, and the default instant is the system
clock.*
**If false.** An auditor runs against a different set of hops, at a different instant, or
against a registration target nobody named — and it emits an artifact that says it audited
something. "A value given twice is refused rather than RESOLVED" is the sharp one: silently
taking the last occurrence is how an operator's first, correct argument disappears.
**Likely owner:** none.
**Root relationship.** The auditor's product claim, which the graph does not hold.
**Severity:** `high`.

## NP-040 — the auditor trusts exactly what its profile enrolls

**Controls:** `auditor/profile/mod.rs` (5), `auditor/trust_view.rs` (4).
**Statement.** *A coherent trust document becomes a profile and an incoherent one never
does; an unknown member and a negative clock skew are refused; the revoked set answers for
the keys it names; and in the resulting view an enrolled request signer resolves with the
auditor's labels, the response anchor resolves ONLY in the response slot, an unenrolled key
id resolves to nothing, and a revoked key resolves in no slot.*
**If false.** The auditor attributes evidence to a key it was never told to trust, or in a
slot that key was not enrolled for, or one that has been revoked — and an audit verdict is
exactly as good as the trust picture it was computed under.
**Likely owner:** none. The proxy's own trust-plane units are about the SERVING path's
trust; this is the auditor's, and the two are deliberately different pictures.
**Severity:** `critical`.

## NP-041 — a registration target is admissible before anything is submitted

**Controls:** `auditor/registration/endpoint/mod.rs` (4), `endpoint/flags.rs` (5),
`registration/policy.rs` (4), `registration/protocol.rs` (2).
**Statement.** *A registration target is an endpoint the network policy admits — plaintext
only off no interface but loopback — carrying a bounded, pollable budget and a named
protocol; an unknown protocol refuses BEFORE anything is submitted; a term without a
service, an unterminating budget, an unbounded wait and a budget that cannot poll are each
refused; an invocation that names no service registers nothing; and the default protocol is
the one that was the only one.*
**If false.** The auditor submits a statement to an endpoint over plaintext, or waits
forever on a service that never answers, or registers nowhere while reporting that it
registered. The plaintext arm is the one with a peer: the same refusal the CLI makes about
a KMS endpoint (NP-027), one product step out.
**Likely owner:** none.
**Severity:** `critical`.

## NP-042 — a statement is registered only against a receipt about itself

**Controls:** `auditor/registration/capability.rs` (5),
`registration/ureq_exchange.rs` (3), `registration/exchange.rs` (1).
**Statement.** *A verifying receipt about THIS statement, from a pinned log, produces a
registered statement; an answer that is not a receipt, a receipt about another statement,
and a receipt from an unpinned log are each refused; a mechanism refusal is carried through
with its certainty rather than flattened; and the exchange carries the body verbatim across
the socket, refuses a disallowed scheme with no transport at all, and reads a header
case-insensitively taking the first.*
**If false.** The auditor records a registration that a transparency service never made, or
made about something else — which is the whole of what a transparency claim is worth. The
"carried through with its certainty" clause is the one this repository has ruled on before:
a refusal must not be flattened into the safe side, because *did not run* and *unknown
whether it ran* are different facts.
**Likely owner:** none. `http_profile.scitt_retained_correspondence` is about the
commitment a Signed Statement carries, not about what the auditor will accept as a receipt
for it.
**Severity:** `critical`.

## NP-043 — the auditor's artifact is its own schema and round-trips its verdicts

**Controls:** `auditor/artifact/mod.rs` (3), `artifact/verdict.rs` (1).
**Statement.** *An artifact round-trips its verdicts; a foreign schema is refused; a
statement that is not base64url is refused on the way IN; and every incomplete reason has
its own token.*
**If false.** An audit artifact is read as this schema when it is another's, or an
incomplete audit reports a reason indistinguishable from a different one — which is the
bare-boolean failure `http_profile.retained_chain_record` exists to prevent, arriving in the
artifact instead of in the chain label.
**Likely owner:** none.
**Severity:** `high`.

---

## NP-044 — the retention read side distinguishes absent from error

**Controls:** `mcp-re-proxy/src/transparency/retained_archive.rs::a_missing_hop_is_absent_rather_than_an_error`,
`::a_read_only_archive_opens_where_the_retention_authority_refuses`.
**Carrier:** `transparency/retained_archive.rs`.
**Statement.** *Reading a retained archive distinguishes a hop that is absent from a read
that failed, and a read-only archive opens in exactly the places the retention WRITE
authority refuses to.*
**If false.** An auditor reading the archive cannot tell "this hop was never retained" from
"this read did not work" — the execution-certainty collapse this repository has ruled on —
and a read is refused wherever a write is, so evidence that exists cannot be examined.
**Likely owner:** `proxy.retention_commitment` is the WRITE authority and says so. The read
side is a separable authority, which ADR-MCPRE-061 §14's `EX-012` census already found and
recorded when it decomposed `retained_evidence.rs`.
**Severity:** `high`.

## NP-045 — the proxy's own store refuses an incomplete chain

**Control:** `mcp-re-proxy/src/transparency/durability.rs::a_chain_with_a_missing_hop_is_refused_rather_than_reconstructed`.
**Carrier:** `transparency/durability.rs`.
**Statement.** *A chain presented to the proxy's retention store with a hop missing is
refused rather than reconstructed into a shorter chain that would read as complete.*
**If false.** The store itself manufactures the complete-looking truncated record that
`http_profile.retained_chain_record` exists to make impossible downstream.
**Likely owner:** `http_profile.retained_chain_record` states exactly this proposition —
**and it cannot claim this control.** That unit's battery runs in `mcp-re-http-profile`, the
control lives in `mcp-re-proxy`, and a unit's lane is project-scoped, so no selector in that
unit can name it. This is the first REATTRIBUTION this campaign has found to be
mechanically impossible, and it is recorded in the unit itself as well as here.
**Root relationship.** The proxy-side twin of an http-profile proposition; the same shape as
NP-014 and NP-015 one crate over.
**Severity:** `high`.

## NP-048 — a stored object that is not a retained record is refused by the read-only archive

**Control:** `mcp-re-proxy/src/transparency/retained_archive.rs::an_object_that_is_not_a_retained_record_is_refused`.
**Carrier:** `transparency/retained_archive.rs`.
**Statement.** *An object in the evidence directory that is not a retained record at all is
refused by the read-only archive, as `Malformed`, rather than read as one.*
**If false.** An auditor's reconstruction is built from bytes nothing wrote as a hop, and the
chain it produces is about something else with no way for the reader to tell.
**Likely owner:** none.
**Root relationship.** The archive's own read authority.
**Severity:** `high`.

**Narrowed, ADR-MCPRE-069 S-11.** Three of the original four are REGISTERED as
`unit://proxy.retained_record_at_the_store` under THM-0112 — `only_the_signed_headers_are_retained`,
`a_record_without_the_schema_token_is_refused` and `a_retained_exchange_comes_back_byte_identical`,
all three in `transparency/durability.rs`, with `M348` as the demonstrated-red falsifier. The
scope sentence that had to be reconciled is THM-0112's *"NOT A CLAIM ABOUT THE STORE"*, and
the reading taken is recorded beside the unit rather than by editing a fingerprinted field:
that sentence ENUMERATES what is elsewhere — *"Content addressing, durability, capacity and
the fail-closed serving posture"* — and the new unit claims none of the four. It claims that
the contract the statement already carries is what the store PERFORMS, which the statement's
own last clause is about: *"A record this implementation writes reads back as the bytes it
was written from."*

**This one is not reachable from there, and the carrier is why.** Registering it would need
`retained_archive.rs` in that unit's `paths`, and the file's own header refuses the merge
before any registry does: *"One fact, and it is not the one [`super::durability`] owns."* It
records the split as an ADR-MCPRE-061 §8 question 2 finding — *"independently describable, and the second one's consumer needs none of the first's"* — and the consequence was
concrete, an auditor that could not run against a read-only mount. A unit about what the
WRITER performs may not swallow the reader. Its two in-file siblings
(`a_read_only_archive_opens_where_the_retention_authority_refuses`,
`a_missing_hop_is_absent_rather_than_an_error`) are the rest of that authority and no theorem
states it.
**Packet:** `verification/reviews/packets/adr069-np-048-ratification-2026-09-20.md`.
## NP-046 — no durable write blocks a runtime worker

**Control:** `mcp-re-proxy/src/transparency/durability.rs::the_fsync_does_not_run_on_the_runtime_worker`.
**Statement.** *The fsync that makes a retention record durable does not run on a runtime
worker.*
**If false.** A durable write stalls the async runtime, and the proxy stops serving while it
is being answerable — a liveness failure produced by the very mechanism that records
answerability.
**Likely owner:** `proxy.retention_commitment` is about WHEN the deployment became
answerable and says nothing about what the recording costs the runtime. The nearest stated
neighbour is NP-003, which is about worker LIFETIME rather than worker occupancy.
**Severity:** `medium`.

## NP-047 — retaining one exchange twice yields one object

**Control:** `mcp-re-proxy/src/transparency/durability.rs::retaining_the_same_exchange_twice_yields_one_object`.
**Statement.** *Retaining the same exchange twice yields one object, not two.*
**If false.** The archive holds two records of one exchange, and an auditor counting
exchanges, or reconstructing a chain from what is stored, sees a call that happened twice.
**Likely owner:** `proxy.retained_record_content` says WHAT a record contains, not how many
there are of it.
**Severity:** `medium`.

**Re-measured and RETAINED WHOLE, ADR-MCPRE-069 S-11.** The slice's plan expected this under
THM-0088, and the file makes it look easy — `transparency/durability.rs` is in
`proxy.retention_commitment`'s `paths`, so the selector would resolve and the battery would
start. It is refused on the claim rather than on the mechanism.

The control asserts that two `retain` calls over one exchange return the SAME
`EvidenceDigest`, which is content addressing. THM-0112 names that as somebody else's in
terms — *"NOT A CLAIM ABOUT THE STORE. Content addressing, durability, capacity and the
fail-closed serving posture are elsewhere."* — and measured, the *elsewhere* it points at is
`core.content_address`, which is one of the twenty units carrying NO ratified theorem, and
which is over `mcp-re-core/src/hash.rs` rather than over this store. THM-0088 is the other
axis again: its subject is WHEN, two stages under two names, and its own scope says *"It is
about WHEN responsibility was accepted and crossed, never about WHAT the retained record
contains."* Neither *when* nor *what* is *how many*.

So a theorem-shaped gap is exactly what this is, and the honest state is the one it is
already in.
**Packet:** `verification/reviews/packets/adr069-np-047-ratification-2026-09-20.md`.
## The layer-A legality boundary is half-owned — NP-049 through NP-061

`mcp-re-proxy/src/config_state/` holds sixteen configuration classifiers. **Five have a
unit** — admission, custody, trust revocation, trust document, continuation control,
authorization — and **eleven do not**, and the eleven are not the small ones: replay,
delegated signing, transport and CRL, channel credential custody, freshness, key-file
access, server identity, evidence retention, in-flight limit, MCP transport contract,
topology.

The granularity below is the estate's own: one proposition per classifier, which is exactly
how the five owned ones are units. The decomposition was not chosen — it was read off the
module boundary the implementation already drew, and the fact that the owned and unowned
modules are indistinguishable in shape is the finding.

**THE FAMILY IS NOW CLOSED EXCEPT FOR ITS ARGV FRAGMENTS, 2026-09-19.** SL-POSTURE-1 gave
seven of the eleven owners; SL-POSTURE-2 gave the remaining four — NP-056 the evidence
machines (`proxy.evidence_retention_state`, M315), NP-057 the in-flight limit basis
(`proxy.in_flight_limit_basis`, M316), NP-058 the MCP transport contract
(`proxy.mcp_transport_contract_state`, M317) and NP-059's classifier half
(`proxy.deployment_topology_state`, M318) — plus NP-061's clause
(`proxy.continuation_control_subject_boundary`, M319). All five are attached to THM-0077's
`supported_by` and all five falsifiers were demonstrated red. What is left of this family is
`cli/` controls and NP-060's one `config_state/mod.rs` control, and none of them is a
registry edit.

## NP-054 — key-file access policy

**Controls:** `config_state/key_file_access.rs` (5), and — added in batch 12 —
`mcp-re-proxy/src/app.rs` (10): the composition root applying the policy to every key file
it actually opens. A world-readable key file is refused; a group-readable one is refused
without the opt-in and accepted with it only when the process is in that group; group write
is refused even with the opt-in; an owner-only file is accepted; an absent file is not an
error; a file whose posture cannot be established is refused; the PKCS#11 PIN file is
permission-checked; the TLS key is checked under EVERY custody mode; and a delegated TLS key
contributes no file to check.

**Two halves of one proposition, and both are needed.** The classifier half says the policy
is right; the root half says it is applied to every file, which is the half a correct policy
nobody calls would satisfy. They are recorded together rather than as two propositions
because neither is a claim on its own: *no policy accepts world access* and *this file was
checked* are the same sentence about different objects.
**Statement.** *Owner-only accepts 0600 and 0400 and nothing else; no policy accepts world access or group write; group read is accepted only for a group this process is IN; the mode predicate flags group and world bits; and the default deployment is owner-only.*
**If false.** A signing key sits on disk readable by another account on the host. This is the one proposition in the configuration layer whose violation needs no protocol at all to exploit.
**Likely owner:** none. Its five sibling classifiers are units; this one is not.
**Root relationship.** Under THM-0077 — *no deployment serves a posture nobody selected* — with the command-line family (NP-025 … NP-035) one layer above it.
**Severity:** `critical`.

## NP-055 — the server-identity classifier

**Controls:** `config_state/server_identity.rs`.
**Statement.** *A legal request yields ONE canonical identity; a missing coordinate leaves no identity and NAMES ITSELF; a request missing both coordinates reports both in one pass; a whitespace coordinate is empty and names itself; and the identity keyid follows the RESOLVED ISSUER rather than the server key id.*
**If false.** The proxy signs under an identity assembled from a coordinate nobody supplied, or advertises a keyid that is not the one the issuer resolved — which is the identity-not-locator failure at the configuration layer.
**Likely owner:** `proxy.server_identity_facts` owns the classifier half. The two `cli::identity_flags` controls are the argv half and it does not own them.
**Root relationship.** Under THM-0077 — *no deployment serves a posture nobody selected* — with the command-line family (NP-025 … NP-035) one layer above it.
**Severity:** `critical`.

**PARTIALLY DISCHARGED, 2026-09-19 (ADR-MCPRE-069 §5).** The five
`config_state::server_identity::tests` controls are now claimed by `[[unit]]`
`proxy.server_identity_facts`, attached to THM-0077's `supported_by`, with falsifier
`M310-proxy-the-identity-keyid-follows-the-resolved-issuer` demonstrated red.

**WHAT REMAINS, AND WHY IT DID NOT LAND.** `lib#cli::identity_flags::tests::a_complete_set_is_accepted`
and `lib#cli::identity_flags::tests::every_coordinate_is_required_and_named_when_absent` state a
different proposition — what the COMMAND LINE admits as a coordinate, not what the classifier
resolves — and `mcp-re-proxy/src/cli/identity_flags.rs` is in no unit's `paths`. Declaring it in
this unit would make one unit answer for two authorities, and
`_manifest.py::_validate_in_crate_selectors` refuses the selector without it, so the two are
mechanically exclusive. The argv boundary has no ratified theorem, so registering them is an
R6 owner decision rather than a registry edit. The prepared packet is
[`verification/reviews/packets/adr069-np-055-ratification-2026-09-19.md`](../../verification/reviews/packets/adr069-np-055-ratification-2026-09-19.md).

## NP-059 — the topology classifier

**Controls:** `config_state/topology.rs`.
**Statement.** *The default deployment is a single node; zero is a DEFERRAL and not a count; the runtime projection spells auto as zero; and the topology and the shard request do not constrain each other.*
**If false.** A fleet-shaped deployment runs single-node, or a zero core count is read as a count of zero rather than as 'decide at runtime' — and the two-machine independence clause is what keeps a shard request from silently deciding the topology.
**Likely owner:** none. Its five sibling classifiers are units; this one is not.
**Root relationship.** Under THM-0077 — *no deployment serves a posture nobody selected* — with the command-line family (NP-025 … NP-035) one layer above it.
**Severity:** `medium`.

**PARTIALLY DISCHARGED, 2026-09-19 (ADR-MCPRE-069 §5).** The four
`config_state::topology::tests` controls are now claimed by `[[unit]]`
`proxy.deployment_topology_state`, attached to THM-0077's `supported_by`, with falsifier
`M318-proxy-the-fleet-topology-is-the-one-the-deployment-declared` demonstrated red.

**WHAT REMAINS, AND WHY IT DID NOT LAND.**
`lib#cli::runtime_flags::tests::the_topology_counts_admit_zero_as_the_auto_posture` states what
ARGV admits as a shard count, not what the classifier resolves, and
`mcp-re-proxy/src/cli/runtime_flags.rs` is in no unit's `paths`. It is the same shape as
NP-055's residue: `_manifest.py::_validate_in_crate_selectors` refuses the selector without the
path, and declaring the path would make one unit answer for two authorities. The argv boundary
has no ratified theorem, so it is an R6 owner decision. The prepared packet is
[`verification/reviews/packets/adr069-np-059-ratification-2026-09-19.md`](../../verification/reviews/packets/adr069-np-059-ratification-2026-09-19.md).

## NP-060 — the validation boundary is total and names what it refused

**Controls:** `config_state/validation/* , config_state/mod.rs and config_state/trust_document.rs`.
**Statement.** *Every required coordinate is refused when empty HOWEVER the request was built, and a whitespace coordinate is refused like an empty one; a target URI that would disable the reconstruction check is refused; the inventory IS the file rather than a list beside it; a machine with no clauses contributes nothing to the violation list; the internal error names the machine that recognised nothing; a refusal names the flag; and the state carries what the planes would otherwise re-derive.*
**If false.** A required coordinate reaches a plane empty because the request was built the other way, or an operator gets a refusal that does not say what to change. 'The inventory IS the file' is the anti-drift clause: a hand-maintained list of what must be validated is a list that goes stale.
**Likely owner:** `proxy.legality_boundary_totality` owns the boundary's own clauses. It does not own the `config_state/mod.rs` control.
**Root relationship.** Under THM-0077 — *no deployment serves a posture nobody selected* — with the command-line family (NP-025 … NP-035) one layer above it.
**Severity:** `high`.

**PARTIALLY DISCHARGED, 2026-09-19 (ADR-MCPRE-069 §5).** Eight of the nine controls — the
three `validation::required_coordinate_tests`, `validation::machine_violations`,
`validation::recognition`, the two `validation::residue` and `trust_document::the_refusal_names_the_flag`
— are now claimed by `[[unit]]` `proxy.legality_boundary_totality`, attached to THM-0077's
`supported_by`, with falsifier `M311-proxy-a-scheme-less-target-uri-is-refused` demonstrated
red. Two entries left `config/unit-closure-exclusions.toml` in the same change, because
`validation/machine_violations.rs` and `validation/recognition.rs` are now inside a unit's
closure.

**WHAT REMAINS, AND WHY IT DID NOT LAND.**
`lib#config_state::tests::the_state_carries_what_the_planes_would_otherwise_re_derive` lives in
`mcp-re-proxy/src/config_state/mod.rs`, and `_manifest.py::_validate_in_crate_selectors` will
not accept the selector unless that file is in the unit's `paths`. Declaring it makes
`config_state/mod.rs` a MEASURED file, at which point `scripts/unit_closure_gate.py` flags each
of its nineteen `mod` children as an unanswered neighbour — the gate says so in terms: *"walking
out of a registered file was tried and is wrong — `config_state/mod.rs` is itself outside every
closure, so demanding that its nineteen children be measured is a demand for COVERAGE, not a
report of DRIFT"*. Six of those children have no unit in this slice's scope, and
`config/unit-closure-exclusions.toml` may only shrink. So this one control lands when the rest
of the `config_state` family does, and not before; it is not an owner decision and needs no
ratification packet.

## NP-061 — a configuration machine decides only its own subject

**Controls:** `config_state/continuation_control.rs`.
**Statement.** *The continuation-control machine does not read the replay tier.*
**If false.** One configuration machine re-derives another's decision from raw fields, so two owners answer the same question and can disagree. `proxy.cross_machine_legality` states exactly this shape — 'every relation reads classified owner states rather than raw request fields', with `the_trust_epoch_posture_is_not_re_derived_here` as its registered control — and it CANNOT claim this one: its paths are `cross_machine.rs` alone, and `verify --manifests` refuses a `lib#` selector whose module the unit does not measure. The third mechanically impossible reattribution this campaign has measured.
**Likely owner:** none. Its five sibling classifiers are units; this one is not.
**Root relationship.** Under THM-0077 — *no deployment serves a posture nobody selected* — with the command-line family (NP-025 … NP-035) one layer above it.
**Severity:** `high`.

**PARTIALLY DISCHARGED, 2026-09-19 (ADR-MCPRE-069 §5).**
`lib#config_state::continuation_control::tests::the_replay_tier_does_not_reach_this_machine` is
now claimed by `[[unit]]` `proxy.continuation_control_subject_boundary`, attached to THM-0077's
`supported_by`, with falsifier
`M319-proxy-the-replay-tier-does-not-reach-the-continuation-machine` demonstrated red. It is a
unit of its own rather than a symbol added to a neighbouring battery:
`continuation_control.rs` is already in `proxy.continuation_materialization`'s and
`proxy.continuation_materialization_sole_producer`'s `paths`, but neither states what this
machine may READ — one says what the plan YIELDS, the other is the compile-time fact that the
plan came from this classifier — and registering the control under a proposition that does not
contain it is the quiet widening ADR-069 §5 forbids.

**WHAT REMAINS, AND WHY IT DID NOT LAND.** The two `cli::runtime_flags::tests` controls —
`every_claimed_flag_routes_to_the_authority_that_owns_it` and
`the_composed_runtime_carries_the_ceiling_the_admission_authority_read` — state a different
proposition: which authority each runtime FLAG is routed to, which is the argv boundary's own
subject. `mcp-re-proxy/src/cli/runtime_flags.rs` is in no unit's `paths` and the argv boundary
has no ratified theorem, so they are R6. The prepared packet is
[`verification/reviews/packets/adr069-np-061-ratification-2026-09-19.md`](../../verification/reviews/packets/adr069-np-061-ratification-2026-09-19.md).

## NP-062 — a malformed client CRL is refused at construction rather than skipped

**Control:** `mcp-re-proxy/src/client_revocation.rs::a_malformed_crl_is_refused_rather_than_skipped`.
**Carrier:** `ClientRevocationIndex::from_crl_ders`.
**Statement.** *A malformed CRL among the bytes an index is built from is a hard error, so no
index exists, rather than being skipped and leaving the request path enforcing a smaller
revoked set than the handshake.*
**If false.** A CRL the handshake verifier refuses is silently absent from the per-request
index, so a serial published only on that list stops being enforced between requests while
rustls goes on refusing it at each new handshake — the two disagreeing about what is
enforced, in the direction that admits.
**Likely owner:** none.
**Root relationship.** Under the client-certificate roots.
**Severity:** `critical`.

**Narrowed, and the plan's theorem was the one theorem that refuses this file,
ADR-MCPRE-069 S-11.** Eleven of the twelve are REGISTERED under **THM-0032** as two units —
`proxy.client_revocation_index_verdict` (9 controls, `M346`) and
`proxy.client_revocation_snapshot` (2, `M347`). Three things were measured on the way and
each changed the answer.

**THM-0054 cannot take any of them, and says so.** Its scope: *"it establishes nothing about
the per-request revocation check, which is a separate authority holding the same invariant."*
`client_revocation.rs` IS that separate authority — its header opens *"PER-REQUEST
client-certificate revocation, so a warm connection is not a hole."* THM-0131 closes the same
door from the other side: *"It says nothing about whether a revoked peer is refused — that is
THM-0054's handshake half and the per-request index beside it"*. So the plan's 6/12 split
inside THM-0054's statement is 0/12.

**THM-0032 states the index's answer twice, in its own words.** *"leaf revocation `admits`: an
empty index admits, otherwise Revoked AND Unknown refuse"*, and *"The revocation index it
carries is the SNAPSHOT in force for the request, not the atomic cell: the leaf check and the
issuer check therefore cannot read two different indexes across a reload."* Its family
already measures the consumer — the predicate, the policy that captures the index, the
serving composition — and `proxy.per_request_revocation_serving`'s own description points
here: *"It states nothing the predicate states: WHICH certificates the index refuses, the
leaf/issuer strength asymmetry and the one-snapshot-per-request rule are
`proxy.credential_currency`'s"*. That unit could not have taken them anyway: it declares
`test_features = ["async_serve"]`, and all twelve are default-lane `lib#` controls.

**TWO units, on a different axis from the plan's.** Not *inside THM-0054* versus *index
algebra*, but ADR-MCPRE-061 §8 question 2: WHAT the index answers about one certificate, and
WHICH index a request reads. One unit over both would need an "and".

**This control is in neither, and the reason is not its subject.** It is a CONSTRUCTOR
refusal — `from_crl_ders` returns `Err` and no index is built — and both of THM-0032's
clauses are about a value that exists. A theorem clause about what an index answers cannot be
falsified by an index that was never made.
**Packet:** `verification/reviews/packets/adr069-np-062-ratification-2026-09-20.md`.
## NP-063 — a revocation tier's published guarantee is its own

**Controls:** `mcp-re-proxy/src/revocation_tier.rs` (9).
**Carrier:** the revocation tier vocabulary and its published guarantees.
**Statement.** *Every tier has a non-empty guarantee, each tier's guarantee is DISTINCT from
every other's, no tier claims a zero window unless proven — LIVE is near-zero with a hard
availability dependency and PUSH is near-zero with a bounded fallback, neither a zero window
— the wire names are the semantic ADR names, parsing round-trips each tier and refuses
unknown and malformed ones, and the startup audit line carries the backend, the tier and the
guarantee and no key material.*
**If false.** A deployment publishes a revocation guarantee it does not have. Two tiers
sharing a guarantee makes the choice between them meaningless; a tier claiming a zero window
makes a bounded staleness read as none; and a wire name that is not the ADR's name is an
operator selecting a posture by a word that means something else.
**Likely owner:** none. `proxy.trust_revocation_classification` classifies which posture a
deployment REQUESTS; this is what each posture, once requested, is allowed to SAY about
itself.
**Root relationship.** Under THM-0077 beside the configuration family.
**Severity:** `high`.
**The audit-line clause belongs here rather than with the redaction unit.**
`proxy.operator_facing_redaction` owns the two fields that carry credentials; this control is
about a line whose subject is the tier, and what it must contain as much as what it must not.

## NP-064 — the root resolves exactly one bind, and refuses an unresolvable one

**Controls:** `mcp-re-proxy/src/app.rs::an_unresolvable_bind_is_refused_and_names_the_flag`,
`::the_fleet_config_carries_the_topology_and_resolves_the_bind`.
**Statement.** *A bind address that cannot be resolved is refused, and the refusal NAMES THE
FLAG; and the fleet configuration carries the topology and resolves the bind, so one place
decides what the process listens on.*
**If false.** The process listens somewhere the operator did not name, or fails with a
diagnostic that does not say which flag to change. The client side of this repository holds
the sharper form of the same claim — `client.bind_scope` is `critical` and sealed — and the
proxy's root has no statement at all.
**Likely owner:** none. `proxy.trust_composition_root` is about which fields the root reads
raw; this is about what it does with the one that decides the listener.
**Severity:** `high`.

## NP-065 — a faulted deployment clock refuses exactly where it would disable a refusal

**Controls:** `mcp-re-proxy/src/app.rs::a_faulted_clock_refuses_only_when_it_disables_the_crl_refusal`,
`mcp-re-proxy/src/startup_plan.rs::an_epoch_or_pre_epoch_clock_reading_is_a_fault`,
`::a_plausible_deployment_clock_is_not_a_fault`.
**Statement.** *An epoch or pre-epoch clock reading is a fault and a plausible one is not;
and a faulted clock refuses startup exactly where the fault would otherwise disable a
refusal — the CRL expiry check — and not elsewhere.*
**If false.** A replica starts with a clock that makes every CRL look current, so expiry
stops refusing anything — or, in the other direction, a plausible clock is treated as a
fault and a healthy deployment will not start. The precision is the proposition: *refuses
ONLY when it disables the CRL refusal*.
**Likely owner:** none. `proxy.client_revocation_currency` is about the CRLs' own windows,
not about the clock those windows are read against.
**Severity:** `critical`.

## NP-066 — no record enqueued before teardown is lost

**Control:** `mcp-re-proxy/src/app.rs::a_record_enqueued_immediately_before_teardown_still_reaches_stderr`.
**Statement.** *A record enqueued immediately before teardown still reaches its sink.*
**If false.** The last records before shutdown — the ones describing why the process is
shutting down — are the ones dropped.
**Likely owner:** none, and the estate has already said so in a different register:
ADR-MCPRE-061 §14 records `app.rs` as `reviewed-action-required` precisely because *the
audit-drain teardown authority is separable and has an owner next door.* This control is
that authority's only evidence, sitting in the file the census says should not keep it.
**Severity:** `high`.

## NP-067 — every plane transitions and the substrate is reclaimed, on every path

**Controls:** `mcp-re-proxy/src/materialized_runtime.rs` (11),
`mcp-re-proxy/src/materializing_runtime` (6).
**Statement.** *A populated runtime transitions every plane and then reclaims the substrate;
a runtime dropped without serving reclaims it; one that reaches Stopped leaves no plane
holding authority; a PANICKED worker still leaves its plane transitioned and the substrate
reclaimable; a worker that never stops bounds teardown without skipping the other planes;
the transition phase leaves the substrate intact; shutdown is idempotent; a serve that never
bound justifies no lifecycle event; the post-drain sequence is refused before the drain is
PROVEN and is unreachable from a serve that never started; and a served shutdown records
serving and the drain.*
**If false.** A plane keeps authority after the runtime reports Stopped — which is exactly
the conclusion THM-0012's lifecycle record is relied on for — or the post-drain sequence runs
on a drain nobody proved. The panicked-worker clause is the one that makes it a claim about
teardown rather than about the happy path.
**Likely owner:** none. `proxy.runtime_lifecycle` owns the RELATION — eleven states, ten
events, one closed transition relation — and `proxy.runtime_lifecycle_sole_mutator` owns the
seal. Neither says what MATERIALIZING that lifecycle does to the planes, and
`materialized_runtime.rs` is in neither's `paths`.
**Root relationship.** THM-0012 — *the lifecycle record cannot claim a shutdown that did not
happen* — is the root above it, and this is the half about what the shutdown DID.
**Severity:** `critical`.

**NP-068, NP-069 AND NP-070 ARE DISCHARGED, 2026-09-19 (ADR-MCPRE-069 §5).** All 31 of the
startup planner's controls that were theirs are now claimed by three `[[unit]]`s over
`mcp-re-proxy/src/startup_plan.rs` — `proxy.startup_plan_provenance` (10),
`proxy.startup_plan_legality` (17) and `proxy.startup_plan_pool_ceiling` (4) — each attached
to THM-0077's `supported_by`, with falsifiers M312, M313 and M314 demonstrated red. The file
was in no unit's `paths` before this; it now is, so a change to the planner moves the
fingerprint of every claim resting on it. The two remaining `startup_plan::tests` controls
are NP-065's clock-fault pair and stay in the queue with that record.

---

## Batch 13 — the per-axis flag adapters

`mcp-re-proxy/src/cli/` holds 59 more controls in eighteen small modules, one per
configuration axis: admission flags, authorization flags, audit flags, channel flags,
currency flags, delegated-signing flags, identity flags, peer-identity flags, protocol
flags, revocation flags, runtime flags, serving flags, signing-source flags, storage flags.

**These are the same eleven propositions one layer down**, and they are attached to them
rather than given propositions of their own. `cli.rs` is the parser; these are the adapters
that turn each axis's flags into the request an owner classifies. A control here — *an
enforcing gate without a record-currentness budget is refused* — is the argv arm of exactly
the proposition `cli.rs`'s own control of the same subject is an arm of, and splitting them
would give one authority two records.

Two axes had no proposition at all, and get one.

## NP-071 — the authorization axis is exactly four flags, and names its alternatives

**Controls:** `mcp-re-proxy/src/cli/authorization_flags.rs` (7).
**Statement.** *Exactly four flags reach the authorization axis; the production mechanism is
selectable with its two parameters; an unknown selection names the THREE that exist and an
unknown scope names the TWO the signed claims can carry; a staleness bound that is not a
number is refused BY NAME; a deny list accumulates across repetition and commas; and a
parameter supplied beside no selection still parses and is refused later, by the owner.*
**If false.** An operator selects an authorization mechanism that does not exist and learns
only which flag was wrong, not which values are possible — or a deny list silently keeps the
last spelling instead of accumulating, so entries an operator wrote are not enforced.
**Likely owner:** `proxy.authorization_configuration_state` classifies what the deployment
RECOGNISES; this is what an operator can say. The last clause is the layering, stated as a
control: a parameter beside no selection PARSES and is refused by the owner, rather than the
adapter deciding a question that is not its.
**Root relationship.** Under THM-0077 with the rest of the argv family.
**Severity:** `high`.

## NP-072 — the audit axis records and forwards nothing unsigned by default

**Controls:** `mcp-re-proxy/src/cli/audit_flags.rs` (2).
**Statement.** *The defaults record, and forward nothing unsigned; an unknown selection is
refused rather than defaulted.*
**If false.** A deployment forwards audit records nobody signed, or an operator's misspelled
selection silently takes the default — which is the one case where a typo turns a chosen
posture into an unchosen one on the axis whose whole subject is what gets recorded.
**Likely owner:** none.
**Severity:** `high`.

---

## The ingress and transport-binding plane — NP-073 through NP-078

`mcp-re-proxy/src/transport/` holds 47 controls and no unit's `paths` name any of it. It is
the hop in front of the proxy: the load-balancer assertion in two frozen formats, the
transport binding between a channel peer and a request actor, the asserted-identity value,
and the routing headers. Six propositions, split along what each one is ABOUT rather than by
file — v1 and v2 share a proposition because they are two encodings of one claim, and the
guarantee each format PUBLISHES is separated from the verification because it is a statement
about what the deployment may say.

## NP-073 — an ingress assertion binds to the request in hand

**Controls:** `transport/ingress/v2.rs` (14), `transport/ingress/mod.rs` (1), over the one
frozen format.
**Statement.** *An accepted ingress assertion carries a signature that verifies under a
KNOWN key id, over a length-prefixed and unambiguous preimage, binds to the hash of the
request in hand, is inside its window — stale and implausibly-future rejected, a future
expiry accepted — names this audience and a trusted ingress identity; a tampered field, a
malformed framing, a malformed identity shape, a malformed enum discriminant and a
cross-request binding are each rejected; recorded-facts admission fails closed; the wire
form round-trips through parse; and the preimage is domain-separated by a VERSION-QUALIFIED
tag.*
**If false.** A peer replays one request's ingress assertion onto another — the
cross-request arm — or an assertion signed for one audience is accepted by another
deployment, and the proxy believes a hop it never verified. The domain-tag clause is the
cross-version version of the same attack: a signature produced under another version of this
mechanism must not verify as one of these.
**Likely owner:** none. NP-033 is the CONFIGURATION side — attested ingress configured whole
or not at all; this is the verification the configuration turns on.
**Root relationship.** Under the peer-identity roots.
**Severity:** `critical`.
**"Length-prefixed and unambiguous" is a proposition about the preimage and not about the
signature**, and it is registered here because it is what makes every other clause mean
what it says: a preimage two different messages can produce makes a valid signature evidence
for the wrong one.

## NP-074 — each ingress format publishes the guarantee it actually gives

**Controls:** `transport/ingress/v2.rs::v2_guarantee_is_attested_delegation_not_end_to_end`.
**Statement.** *The guarantee the ingress format publishes is what it gives: v2's is
attested delegation and not end-to-end.*
**If false.** A deployment reads an ingress assertion as end-to-end channel evidence and
stops requiring the thing that would have been end-to-end. This is NP-063's shape at a
different layer — a mechanism publishing a guarantee it does not have — and it is separated
from NP-073 because verification and publication are different authorities: an assertion can
verify perfectly and still be described as more than it is.
**Likely owner:** none.
**Severity:** `critical`.

## NP-077 — a routing header is well-formed and singular, or the request fails closed

**Controls:** `transport/mod.rs` (6), `mcp-re-proxy/src/tls.rs` (1).
**Statement.** *An absent routing header passes and a well-formed one passes; a duplicate, an
empty and a malformed one each FAIL CLOSED; and request-header parsing skips the request
line and is case-insensitive.*
**If false.** Two routing headers disagree and the proxy picks one — the header-smuggling
shape — or a malformed header is ignored rather than refused. The absent/present pair is what
keeps "fails closed" from meaning "refuses everything".
**Likely owner:** none.
**Severity:** `critical`.

## NP-078 — the historical identity facade refuses, and its product cannot be manufactured

**Controls:** `transport/identity.rs` (2).
**Statement.** *A certificate that does not carry the configured field yields NOTHING at the
historical `extract_identity` surface; and a `TransportIdentity` cannot be built outside the
module that owns it, so a value of that type exists only where a verification put it there.*
**If false.** A consumer reads a certificate field directly and gets an identity the
interpreter would have refused, or asserts one it never read — the manufactured
`spiffe://…/admin` the module's own note names.
**Likely owner:** none. Measured in this slice rather than argued, and the measurement
overturns the earlier record on both halves.

**THE SEAL HOLDS, AND IT IS MEASURED.** ADR-MCPRE-068 §12.1 says a passing `cargo check`
witnesses nothing, so the hostile constructions were written FIRST and the compiler's
refusals are the result:

| route | site | verdict |
|---|---|---|
| struct literal, downstream crate | `mcp-re-proxy/tests/` | `E0451: fields value and source of struct TransportIdentity are private` |
| `attested_by_verified_ingress`, downstream crate | `mcp-re-proxy/tests/` | `E0624: associated function attested_by_verified_ingress is private` |
| struct literal, sibling module of `transport` | `mcp-re-proxy/src/` | `E0451` |
| `attested_by_verified_ingress`, sibling module of `transport` | `mcp-re-proxy/src/` | `E0624` |

The in-crate pair is the load-bearing one: `pub(crate)` seals nothing against this crate's
own composition root, and the lever that works here is module privacy. `value` and `source`
are bare-private to `transport::identity`, and `attested_by_verified_ingress` is
`pub(super)`, so the set privacy admits is `transport` and its descendants — which is
exactly the documented producer list, `transport::ingress::v2`. The other producer
paths are answered too: no `Default`, `From`, `FromStr` or derived `Deserialize` exists on
the type, and no `#[cfg(test)]` constructor widens it.

**WHY IT IS STILL NOT REGISTERED, AND THIS IS THE FINDING.** A measured seal is not a
theorem. THM-0024 is the only candidate and it excludes the claim in terms — *"It
characterizes values successfully returned by the interpretation operation. It says nothing
about arbitrary possession of a `CertificatePeerIdentityEvidence` value, whose construction
closure is the module boundary rather than a proved postcondition."* — and the type here is
not even that one. THM-0080 names the historical extractor only to say the serving paths do
not take it: *"the historical extractor is a published API with its own X.509 conformance
suite over real DER, so it cannot be removed to make the wrong call unavailable"*. Neither
claims what `extract_identity` returns, and neither claims who may build a
`TransportIdentity`.

The owner already ruled on this, and the ruling is in the source: *"It is deliberately NOT
written down as a theorem here. The proposition is an open gap in
`docs/architecture/components/transport-binding.md`, and closing it in prose ahead of the
deployment reachability that makes it true is the over-claim ADR-MCPRE-061 exists to prevent
(EX-005, ruling 5)."* Registering a unit for it now would be that over-claim arriving through
the assurance registry instead of through prose. ADR-069 §5 holds an unregistered control
strictly better than a unit whose declared proposition no ratified theorem contains.

**What is missing, precisely.** A `[[theorem]]` over the transport identity product, which
this slice may not add. Its two conjuncts are already measured and its structural half is
already true; what does not exist is a ratified sentence to attach them to.
**Packet:** `verification/reviews/packets/adr069-np-078-ratification-2026-09-20.md`.
**Severity:** `critical`.

## NP-079 — a third party's receipt verifies offline, and only for its own statement

**Controls:** `scitt_interop_test.rs` (15), `scitt_cross_verification_test.rs` (4).
**Statement.** *A real transparency service's receipt, an operated service's receipt and a
third party's receipt each verify OFFLINE under the MCP-RE verifier; a wrong pinned service
key, a mutated receipt, a draft-era label set, an externally built negative, and a receipt
about another statement are each refused; the wrong leaf profile REFUSES RATHER THAN FALLING
BACK and neither older leaf profile verifies the operated service's receipt; the two
capsule-anchor deployments do not verify for each other; a statement identifying no
submission binds no retained record and the pre-revision corpus cannot bind one; and the
committed verification reports match a fresh run.*
**If false.** MCP-RE accepts a transparency receipt that does not attest what it is read as
attesting — by falling back to an older leaf profile, by verifying under another
deployment's anchor, or by binding a statement that identifies no submission.
**Likely owner:** none. `http_profile.scitt_retained_correspondence` owns the commitment
relation inside the profile crate; this is the interop claim over real services' output.
**Root relationship.** Under the transparency roots.
**Severity:** `critical`.

## NP-080 — every published corpus is pinned, and regenerates to the committed bytes

**Controls:** `scitt_vectors_test.rs` (5), `corpus_pinning_test.rs` (5),
`http_profile_vectors_test.rs` (2), `delegation_vectors_test.rs` (3).
**Statement.** *Every committed fixture matches its published hash and a tampered one fails
it; the corpus digest commits to the manifest entries, is order-independent, and CHANGES
when a vector is added or removed; the corpus directory holds no unpinned vector;
regenerating the fixtures reproduces the committed bytes; each committed vector reaches its
expected verdict; the wire form is a tagged `COSE_Sign1`; and the delegation corpus covers
the full taxonomy.*
**If false.** An advertised conformance corpus is not the corpus that was verified — a
vector quietly added, removed or edited, with the digest still agreeing. "Adding or removing
a vector CHANGES the digest" and "order-independent" are the two halves that make the digest
an identity rather than a checksum of whatever order the walk produced.
**Likely owner:** `conformance.retained_corpus` is one corpus; this is the pinning
discipline over all of them.
**Severity:** `high`.

## NP-081 — the shipped profile has the security properties it advertises

**Controls:** `rfc9421_security_properties_test.rs` (14),
`full_profile_parity_test.rs` (8), `rfc9421_cross_verification_test.rs` (2).
**Statement.** *Over the shipped profile end to end: an expired request, a replayed one, a
mutated payload, a tampered body, an untrusted signer key, an unauthorized key id and a
wrong audience are each rejected; a request within the skew bound is accepted and one beyond
it is not, a future-dated request inside the bound is accepted, and the strict tier restores
exact freshness; the transport identity binds to the request actor; caller-supplied proxy
meta is NOT the signed authority; a response bound to the wrong request is rejected, and in
the integrated path a body tamper, a response splice, an artifact mismatch, a continuation
mismatch and a replay each fail, with a response-evidence mismatch emitting request-binding
mismatch; a full exchange activates ALL blocks; and an externally produced signature is
accepted by the MCP-RE verifier, with key and signature agreeing byte for byte across
implementations.*
**If false.** The profile MCP-RE publishes does not have the properties published for it.
`full_exchange_activates_all_blocks` is the anti-vacuity clause for the whole file: without
it every rejection above could be produced by a path that never assembled the evidence.
**Likely owner:** none. The `http_profile.*` units own the profile's internals; this is the
shipped composition measured as a conformance claim.
**Severity:** `critical`.

## NP-082 — delegation interoperates in both directions

**Controls:** `delegation_cross_verification_test.rs` (2).
**Statement.** *An external credential verifies under the MCP-RE verifier, and the MCP-RE
issuer reproduces the external bytes.*
**If false.** MCP-RE's delegation is compatible in one direction only, which is not
compatibility. Both directions are one proposition for the same reason the peek/take split
in `unit://sdk_python.correlation_lifecycle` is: half of it is a different claim, not a
weaker one.
**Severity:** `high`.

## NP-084 — the security traceability manifest is derived, not remembered

**Controls:** `security_traceability_guard_test.rs` (10).
**Statement.** *Every section-A claim maps to a manifest entry and the source table names
exactly the manifest sources; every named test function appears in its source and every
Bazel target is declared in a BUILD file; each entry's source matches its target package;
the recorded count is DERIVED rather than stale; the required gate guards are mapped; the
four server-auth cases are present; the drift detector rejects a renamed target and function;
and the guard's inputs are non-empty.*
**If false.** The traceability manifest names evidence that does not exist — a test function
that was renamed, a Bazel target nobody declares — and a claim reads as traced to something
unrunnable. "The recorded count is derived not stale" is the clause that keeps the manifest
from agreeing with itself.
**Severity:** `high`.

## NP-085 — the shipped codes and names are the ones the MCP revision defines

**Controls:** `mcp_2026_07_28_alignment_test.rs` (5),
`method_name_drift_guard_test.rs` (2), `method_transparency_test.rs` (1).
**Statement.** *The MRTR `input_required` discriminator matches SEP-2322; the rejection code
is outside the JSON-RPC reserved range and in neither MCP sub-range; the Core and
http-profile codes are the SAME INTEGER; the recognised result types are the two the core
protocol defines; no banned method literal appears in non-test Core source, with the region
scan looking BELOW a test module; and the accepted verdict is identical across all methods.*
**If false.** MCP-RE emits a code another implementation reads as something else, or two of
its own crates disagree about the same integer. NP-005 is this proposition's structural
precondition — the discriminator open-coded in one place — and they were found from opposite
ends: one from a gate with no unit, one from a conformance file with no unit.
**Severity:** `critical`.

## NP-086 — no forbidden claim is asserted anywhere in the published surface

**Controls:** `forbidden_claim_guard_test.rs` (4).
**Statement.** *No forbidden phrase appears as an ASSERTED claim; the detector catches an
asserted claim while allowing a repudiation; the legacy security boundary is a stub with no
live claim; and the guard's inputs are non-empty.*
**If false.** The published surface asserts a security property the implementation does not
have — the exact failure the deprecation vocabulary exists to prevent, and the one whose
consequence is entirely borne by a reader.
**Likely owner:** none. `scripts/jcs_vocabulary_gate.py` is ND-005 because it holds a
documented value equal to its source; this is a claim about what the surface ASSERTS, which
is not a mirror.
**Severity:** `high`.

---

## The signature-base plane — NP-087 through NP-090

`block.rs`, `body/`, `sigbase.rs` and `structured_fields_strictness_test.rs` hold 54
unclaimed controls. The three source files are in **ten to fourteen units' `paths` each** —
they are the shared bottom of the profile, so almost every `http_profile.*` unit measures
them — and not one of those units claims a single control in them.

**That combination is worth stating on its own.** A file inside fourteen fingerprints whose
own controls belong to none of them is not a gap in any one unit's battery; it is a layer
everybody depends on and nobody answers for. The four propositions below are what those
controls establish, and each of them is a premise of every unit above it.

## NP-087 — the evidence block is injective and closed

**Controls:** `mcp-re-http-profile/src/block.rs` (7).
**Statement.** *No two distinct evidence blocks produce the same identifier: the actor id is
deterministic, pinned, and INJECTIVE ACROSS COLON BOUNDARIES; the separator cannot be forged
across fields; the escape marker itself creates no collision; a separator inside a field does
not collapse two audiences; different audiences on one endpoint hash differently; and the
block is closed — an unknown field, a foreign profile and empty artifact bindings each fail
closed.*
**If false.** Two different actors, or two different audiences, share one identifier — so
evidence about one is evidence about the other. Injectivity across the colon boundary is the
whole of it: `a:bc` and `ab:c` must not be the same actor.
**Likely owner:** none of the fourteen units that measure this file. Each of them is about
what its own verdict means; this is about the identifier they all compare.
**Severity:** `critical`.
**Registered in part, ADR-MCPRE-069 HP-S2 — the CLOSURE half only.** The record's title
carries an "and", and the "and" is accurate: it holds two independently describable
authorities. The closure half is now `unit://http_profile.evidence_block_closure` under
**THM-0015**, whose statement contains it verbatim — *"the request evidence block parsed and
validated under the profile tag"* — carrying `block_round_trips`,
`unknown_field_fails_closed`, `foreign_profile_fails_closed` and
`empty_artifact_bindings_fails_closed`.
**The INJECTIVITY half is not registered, and the unit's description says so.** That the
`role:trust_domain:subject:keyid` join and the audience hash are injective ENCODINGS is
asserted as a premise by THM-0034 (*"The composite is the injective
`role:trust_domain:subject:keyid` join, and it is the canonical coordinate for replay keys,
audit records and trusted-key identity"*) and established by no theorem. THM-0079 is the
closest and fails on a quantifier: its biconditional is over the five-tuple AS A TUPLE, so two
distinct actors collapsing to one actor-id string produce EQUAL tuples and THM-0079 stays true
while the property fails. Seven rows REMAIN, and letting the registered unit's description
drift onto injectivity would be the widening ADR-069 §5 holds to be worse than leaving a
control unregistered.

Packet at `verification/reviews/packets/adr069-np-087-ratification-2026-09-19.md`.

## NP-088 — the body is signed as written, or refused

**Controls:** `mcp-re-http-profile/src/body/mod.rs` (9),
`src/body/decimal_token.rs` (5).
**Statement.** *A number the carrier's round trip would alter is REFUSED, NOT REWRITTEN —
decimal or integer — while a representable one, including a wide but exactly carried
decimal, composes unchanged; one number written many ways is one value and numbers that
differ are not equal, compared digit for digit across a wide significand, with an unstateable
exponent and a non-number both reading as none; a duplicate member name is refused and
lookalikes are not, an escaped duplicate is refused like a plain one, a non-object body and a
foreign field each fail closed; insert preserves existing meta entries and insert-then-extract
round-trips; an absent block is MISSING EVIDENCE; and the representability scan never reads
past the body.*
**If false.** The composer rewrites a value on its way into the signature, so the bytes
signed are not the bytes the caller wrote — which is the one thing a signature over a body
is for. "Refused, not rewritten" is the clause: silently normalising is how a signature
comes to cover something nobody sent.
**Likely owner:** none of the eleven units that measure this file.
**Severity:** `critical`.
**Registered in part, ADR-MCPRE-069 HP-S2 — the CARRIER, not the values it may carry.**
Five controls are now `unit://http_profile.evidence_block_carriage`, whose `paths` is
`src/body/mod.rs` alone. Four are contained by **THM-0015**'s *"the request evidence block
parsed and validated under the profile tag"* — `foreign_field_fails_closed`,
`non_object_body_fails_closed`, `absent_block_is_missing_evidence`, and
`insert_then_extract_roundtrips`, which is their anti-vacuity partner: without the round trip
the three refusals are green under an `extract_meta_block` that always errs. The fifth,
`insert_preserves_existing_meta_entries`, is contained by **THM-0125**'s *"the MCP-RE evidence
block lands at the body root rather than inside the caller's content"* and its companion
clause *"The caller's own `params._meta` survives signing unchanged"*; the unit is appended to
THM-0125's `supported_by`, and NOT to `client.request_construction`, whose `paths` are in
`mcp-re-client-core` and which a cross-project widening would be required to reach.
**Fourteen rows REMAIN**, and they are one proposition rather than three: *what the carrier
cannot carry unchanged does not get signed*. The decimal-token algebra is the comparison
`reject_unrepresentable_json` is DEFINED in terms of, and the duplicate-member arm is the same
predicate over a different JSON construct. No theorem in the registry states a
composition-side refusal over the body — THM-0014 is verification-side and about bytes already
fixed, and THM-0125's scope hands the carrier's composition here in terms.

Packet at `verification/reviews/packets/adr069-np-088-ratification-2026-09-19.md`.

## NP-089 — the signature base is exactly the covered components

**Controls:** `mcp-re-http-profile/src/sigbase.rs` (8).
**Statement.** *A missing covered field and a duplicated one each fail closed; CRLF in a
field value and in a derived component each fail closed; a `req` component on a request fails
closed; derived components resolve; the method case is carried VERBATIM into the base; and a
nonce the profile cannot carry is never emitted.*
**If false.** The base a verifier reconstructs differs from the base the signer produced — by
a folded header, an injected line, a component that belongs to the other direction, or a case
change — and a valid signature verifies over the wrong bytes. The CRLF clauses are request
smuggling arriving inside the signature base.
**Likely owner:** none of the ten units that measure this file.
**Severity:** `critical`.
**Referred whole, ADR-MCPRE-069 HP-S2 — and the one R2 candidate was re-tested and refused.**
The scheduling analysis routed `sigbase::tests::req_component_on_request_fails_closed` to
**THM-0022** under its clause *"a `;req` component is refused as malformed, because no request
exists to resolve it against"*. Re-tested against the source, clause 2 fails twice over.
THM-0022 is a conditional over values successfully returned by
`verify_unbound_response_floor` and `verify_delegated_unbound_response`, and its scope says so
— *"It characterizes values successfully returned by those two operations"* — while the
control calls `signature_base` directly and no verification operation runs at all. And the
theorem's clause states its GROUND, which is false for this control: measured at
`src/sigbase.rs`, the source message is `SourceMessage::Request(&r)`, so the refusal here is
the base composer's own and not the response verifier's. A refusal in the base composer over a
request message is not a strict decomposition of a statement about what an unbound-response
verification establishes. All eight rows stay; the record is whole-R6, not R2(1) + R6(7).

Packet at `verification/reviews/packets/adr069-np-089-np-090-ratification-2026-09-19.md`,
which takes NP-089 and NP-090 jointly.

## NP-090 — the structured-field surface is closed and canonical

**Controls:** `mcp-re-http-profile/tests/structured_fields_strictness_test.rs` (16).
**Statement.** *The component set and the parameter set are CLOSED — a foreign component, a
foreign parameter and a foreign tag are each rejected; a duplicated component or parameter
fails closed; component and parameter reordering change the base and fail, while canonical
order still verifies; RFC 8941 quoting cannot be used to merge or split members — a semicolon
inside a quoted value does not split parameters, an escaped quote in a neighbouring member
does not merge it, a decoy signature member does not merge into this profile's member, and a
string parameter carrying an escape fails closed on verify; non-canonical integer parameter
forms fail closed; a string parameter RFC 8941 cannot carry is NEVER SIGNED; ordinary string
parameters still sign and verify; and a `req` component on a request fails closed.*
**If false.** A signature over one structured field is read as a signature over another —
the parser-differential attack this file is entirely about. "Never signed" rather than
"rejected on verify" is the direction that matters: a value the format cannot carry must not
enter the base in the first place.
**Likely owner:** none. This file is in no unit's `paths` at all, unlike the three above it.
**Severity:** `critical`.

---

## The rest of the HTTP profile — NP-091 through NP-105

The remaining 165 unclaimed controls in `mcp-re-http-profile`, in fifteen propositions
grouped by subject. The pattern is the one batch 16 found: these files are measured by many
units and claimed by none, and the propositions below are what each file's own controls
establish rather than what any unit above them promises.

**Referred with NP-089, ADR-MCPRE-069 HP-S2.** Packet at
`verification/reviews/packets/adr069-np-089-np-090-ratification-2026-09-19.md`, which takes
this record's sixteen structured-field rows jointly with NP-089's eight.

## NP-091 — the MCP transport contract is agreed and enforced on the wire

**Controls:** `mcp-re-http-profile/tests/mcp_transport_headers_test.rs`, `mcp-re-http-profile/src/mcp_transport/mod.rs`, `mcp-re-http-profile/src/mcp_transport/agreement.rs`.
**Statement.** *The transport headers a peer may send and must send are a closed, agreed set: the accepted contract is the one both sides named, a header outside it is refused rather than ignored, and what the agreement records is what the exchange is held to.*
**If false.** A peer negotiates one transport contract and is held to another, so a header that decides framing or session identity is honoured under an agreement that never admitted it.
**Likely owner:** none. The `http_profile.*` units that measure these files are each about what their own verdict means.
**Severity:** `critical`.

**Referred, ADR-MCPRE-069 HP-S2 — one row only.** `the_component_allowlist_is_still_closed`
measures the generic component allowlist rather than a transport header, so it is argued in
`verification/reviews/packets/adr069-np-089-np-090-ratification-2026-09-19.md` §2.2. This
record's other thirty-one rows are unpacketed.

## NP-092 — a result is classified once, and never read as terminal by default

**Controls:** `mcp-re-http-profile/src/result_class.rs`.
**Statement.** *The recognised set is complete — input-required and absent; a body with no result member is terminal; a near-miss discriminator, an unparseable body, and an input-required reply without a usable state are each REFUSED and not read as terminal; a non-string or unadvertised result type is unrecognized, and unrecognized is not terminal; a terminal reply has no continuation state and an input-required one yields its state.*
**If false.** A continuation is consumed as a completed call. Every clause names a different way to arrive there, and the repeated 'not read as terminal' is the point: the default on doubt must not be the one that ends the exchange.
**Likely owner:** none. The `http_profile.*` units that measure these files are each about what their own verdict means.
**Severity:** `critical`.

## NP-094 — a refusal is a document, and its wire code is read only after the signature verifies

**Controls:** `mcp-re-http-profile/src/rejection/mod.rs` (5).
**Statement.** *A wire code is read ONLY AFTER the signature verifies, an unsigned rejection is untrusted, a bound rejection verifies and exposes its code, an ordinary rejection body gains no new fields, and the indeterminate rejection states that a retry is unsafe.*
**If false.** A refusal an attacker wrote is read as one the peer signed — the refusal path becomes the one place in the profile where content is believed before its signature is.
**Likely owner:** none. The `http_profile.*` units that measure these files are each about what their own verdict means.
**Severity:** `critical`.
**Split and partly registered, ADR-MCPRE-069 HP-S2 — and the record is RE-TITLED to what it
now holds.** The record covered 13 controls over two authorities, and ADR-069 RR-002 C5
forbids one disposition over such a set. Its previous title — *a refusal carries its own
provenance and is read only after verification* — and its `carrier` field were true of **5 of
its 13 rows**; the other 8 were verdict projection in `src/error.rs` and
`src/error/core_projection.rs`, which is a different authority with a different theorem. An
owner shown "NP-094, 13 controls, a refusal proposition" would have been asked about something
that did not exist.
Those 8 are now `unit://http_profile.carrier_verdict_projection` under **THM-0111**, whose
statement names this carrier in the claim itself: *"Every other taxonomy that reaches the wire
states which of those verdicts it IS, through an exhaustive projection with no wildcard arm,
and derives its token from that projection rather than keeping a table beside it: the RFC 9421
carrier, the replay-tier dispatch gate, the PDP relation adapter …"*. It is the twin of
`core.verification_taxonomy` and `policy.authorization_taxonomy`, and the unit's description
carries the same disclaimer THM-0111's scope does — it says nothing about whether the
GROUPING is right, which is the ratified MCPRE-92 owner decision.
**Five rows REMAIN**, and they are the ones this record now describes: *a refusal is a
document, and nothing in it is believed before its signature is.* The tempting registration is
`http_profile.bound_response_shared_facts`, which already holds three of this file's eight
controls — and its description is three conjuncts about what a SUCCESSFUL verification
establishes, with nothing about a wire code, a reading order, an unsigned document or retry
safety. `bound_rejection_verifies_and_exposes_the_wire_code` is the closest and still fails:
its first half is contained and its second half, *and exposes the wire code*, is the new
clause. THM-0046 is `proxy.refusal_provenance` in another project and its scope excludes this
by name; THM-0061 is the client-side twin.

Packet at `verification/reviews/packets/adr069-np-094-ratification-2026-09-19.md`.

## NP-095 — delegation verifies the chain it was given

**Controls:** `mcp-re-http-profile/src/delegation/mod.rs`, `mcp-re-http-profile/src/delegation/verify.rs`, `mcp-re-http-profile/tests/delegation_e2e_test.rs`.
**Statement.** *The delegated credential chain presented is the one verified, end to end.*
**If false.** A delegated signature is accepted under a chain that was not the one presented.
**Likely owner:** none. The `http_profile.*` units that measure these files are each about what their own verdict means.
**Severity:** `critical`.
**Registered in part, ADR-MCPRE-069 S1.** Four credential-shape controls are now in `unit://http_profile.delegated_credential_chain`, whose description already states each clause: *"three segments under the profile's own algorithm, type and key use"* (`a_cnf_that_names_another_key_is_an_invalid_credential`, `each_scope_failure_names_what_it_is`), *"at an accepted trust epoch"* (`a_stale_trust_epoch_is_its_own_refusal`) and *"named on no revocation list by delegated kid, issuer kid or jti"* (`revocation_is_consulted_with_every_identifier_the_credential_carries`). The e2e control is in `unit://http_profile.delegated_signing_custody`, whose description opens *"The delegated-signing credential lifecycle: the root is never touched within a key's life"* — the assertion that test closes on. The four `delegation::tests::seam_*` rows REMAIN: they measure the ISSUANCE signer seam, which is NP-102's proposition and which no theorem in this project states. Packet at `verification/reviews/packets/adr069-np-095-ratification-2026-09-19.md`.

## NP-096 — a PDP decision carries exactly the claims it was issued with

**Controls:** `mcp-re-http-profile/src/pdp_decision/claims.rs`, `mcp-re-http-profile/src/pdp_decision/issue.rs`, `mcp-re-http-profile/src/pdp_decision/mod.rs`, `mcp-re-http-profile/src/pdp_decision/verify.rs`.
**Statement.** *The claims a decision carries are the ones it was issued with, and verification reads no others.*
**If false.** An authorization decision is honoured for claims nobody issued it for.
**Likely owner:** none. The `http_profile.*` units that measure these files are each about what their own verdict means.
**Severity:** `critical`.
**Registered in part, ADR-MCPRE-069 S1.** Nine of ten controls are now in `unit://http_profile.pdp_decision_authentication`, whose description states *"what the AUTHORITY said, and that it was said to this enforcement point. A decision's JWS shape, its issuer's resolution through the authorization trust seam, its signature, the profile and audience it names"* — the scope-algebra five are facts about what the signed claims carry, the issuance three about the JWS shape and signature, and the `typ` control about the shape. One row REMAINS: `lib#pdp_decision::tests::the_linkage_form_and_the_evidence_form_are_not_interchangeable` lives in `src/pdp_decision/mod.rs`, which is in NO unit's `paths`, so `_validate_in_crate_selectors` refuses the selector and widening `paths` is what ADR-069 §5 forbids. Packet at `verification/reviews/packets/adr069-np-096-ratification-2026-09-19.md`.

## NP-097 — the SCITT value types parse only their own shapes

**Controls:** `mcp-re-http-profile/src/scitt/retained.rs`, `mcp-re-http-profile/src/scitt/cose_key/mod.rs`, `mcp-re-http-profile/src/scitt/merkle.rs`, `mcp-re-http-profile/src/scitt/receipt/mod.rs`, `mcp-re-http-profile/src/scitt/statement/mod.rs`.
**Statement.** *Each SCITT value — retained record, COSE key, Merkle node, receipt, statement — parses its own shape and refuses another's.*
**If false.** One SCITT structure is read as another, so an inclusion proof or a key is interpreted under the wrong shape.
**Likely owner:** none. The `http_profile.*` units that measure these files are each about what their own verdict means.
**Severity:** `high`.
**Registered in part, ADR-MCPRE-069 S1.** The record is a grab-bag over five SCITT owners, so it is split at registration and never registered as one unit. Three controls land where the owner's description already says it: `scitt::receipt::tests::a_leaf_index_outside_the_tree_is_refused` → `unit://http_profile.scitt_receipt_shape` (*"a leaf index that names a position the tree has"*); `scitt::merkle::tests::the_tree_size_determines_the_leaf_index_within_every_ambiguity_class` → `unit://http_profile.scitt_inclusion_fold` (*"a path of the wrong length does not reach the root"*, beside its existing right-edge-ambiguity controls); `scitt::statement::tests::editing_a_decoded_view_does_not_change_what_was_signed` → `unit://http_profile.scitt_statement_attribution` (*"not by what it says about itself"*). Three rows REMAIN: `scitt_retained_correspondence` claims commitment EQUALITY, not digest-token canonicality, and `scitt_algorithm_agreement` claims AGREEMENT between `alg` and key, not key well-formedness. Packet at `verification/reviews/packets/adr069-np-097-ratification-2026-09-19.md`.

## NP-098 — the cryptographic floor refuses what it cannot state exactly

**Controls:** `mcp-re-http-profile/src/verify/floor/sf_dictionary.rs`, `mcp-re-http-profile/src/verify/floor/signature_input.rs`, `mcp-re-http-profile/src/verify/floor/signature_parameters.rs`, `mcp-re-http-profile/src/verify/bound_request.rs`, `mcp-re-http-profile/tests/proof_path_test.rs`, `mcp-re-http-profile/tests/algorithm_confusion_test.rs`.
**Statement.** *An empty dictionary member and dictionary-member spacing are REFUSED, NOT normalised or ignored; alternate signature-input spellings are refused rather than normalised, while a space inside a quoted parameter value is kept; negative zero is not an SF integer; a request with no signature-input has no handle; and the proof path admits no algorithm the header did not name.*
**If false.** A verifier normalises an input into something that verifies, so two different wire forms produce one base — the parser-differential attack again, at the floor rather than at the surface. 'Refused, not normalised' is the same clause NP-088 makes about the body, at the other end of the exchange.
**Likely owner:** none. The `http_profile.*` units that measure these files are each about what their own verdict means.
**Severity:** `critical`.
**Registered in part, ADR-MCPRE-069 S1.** Six controls are now in `unit://http_profile.request_floor_result`, whose description states *"the RFC 9421 signature verified over the reconstructed base under a policy-accepted algorithm ... and the presented keyid resolved through the trust seam for the Request slot"* — the three algorithm-confusion controls are what makes *policy-accepted* non-vacuous (the unit already carries `an_ed25519_signature_declaring_ml_dsa_is_rejected`), and `unsigned_request_fails_closed`, `verified_request_exposes_resolved_actor_identity` and `same_keyid_different_slots_do_not_collapse_actor_id` are the signature and the slot-resolution clauses. `verified_response_exposes_resolved_server_actor` is in `unit://http_profile.bound_response_seam_result` (*"the actor the seam returned IS the accepted signer"*). Ten rows REMAIN: the five floor parser-strictness controls (*refused, not normalised* — NP-090's family, stated by no theorem), `foreign_tag_fails_closed` and `signer_and_verifier_derive_the_same_evidence_handle` (NP-087 / NP-100 handle family), `content_encoding_fails_closed` and `duplicate_authorization_fails_closed` (body representation and header strictness, and the second measures `sign_request`, not the verifier's return at all), and `a_request_with_no_signature_input_has_no_handle`, which measures `request_evidence_of` rather than `Verifier::verify_request_floor` — the function the unit's description names. Packet at `verification/reviews/packets/adr069-np-098-ratification-2026-09-19.md`.

## NP-099 — each verifier product states what it established, without an Option

**Controls:** `mcp-re-http-profile/src/verified_request/mod.rs`, `mcp-re-http-profile/src/verified_response/bound.rs`, `mcp-re-http-profile/src/verified_response/facts.rs`, `mcp-re-http-profile/src/verified_response/unbound.rs`.
**Statement.** *A full product states its audience, a bound one its binding and a delegated one its issuer WITHOUT AN OPTION; a floor product carries the slot trust resolved it in; a seam-authorized floor projects the signer it resolved; the shared facts carry who signed and no authorization; bound and unbound facts are not the same type; an agreement records both handles and not only the verdict; and the unbound products carry no request binding and no trust-seam resolution TO MISREAD.*
**If false.** A product admits two proof strengths in one type, so a consumer reads an absent fact as a weaker establishment rather than as a different product. The repository has ruled on this exact shape: one Verified type, one proof strength, and an Option documented 'None on the minimal path' is a type admitting two.
**Likely owner:** none. The `http_profile.*` units that measure these files are each about what their own verdict means.
**Severity:** `critical`.
**Referred whole, ADR-MCPRE-069 S1.** The three substitutability controls could only go to `unit://http_profile.verifier_result_separation`, and that unit is `evidence_class = "structural"` with an EMPTY `tested_symbols` and a `structural://` evidence URI only. `_manifest.py` refuses `tested_symbols` with no `test://` entry claiming them, so registering them means adding a test lane to a structural unit — an ADR-MCPRE-068 class change, not a registration, and ADR-069 §5 does not admit it. The remaining eight are the *without an Option* family; THM-0047 declines it in its own words: *"It establishes nothing about what any of the operations verify."* Packet at `verification/reviews/packets/adr069-np-099-ratification-2026-09-19.md`.

## NP-100 — the evidence handle is domain-separated and derived, never a bare digest

**Controls:** `mcp-re-http-profile/src/evidence.rs`, `mcp-re-http-profile/src/context.rs`, `mcp-re-http-profile/src/digest.rs`, `mcp-re-http-profile/src/artifact.rs`, `mcp-re-http-profile/src/policy.rs`, `mcp-re-http-profile/src/replay.rs`, `mcp-re-http-profile/src/authoritative_admission/record/currentness.rs`.
**Statement.** *A handle is split-form and deterministic, is NOT a bare digest of the base, differs when the base differs, cannot confuse a label with an input, and separates roles by domain over IDENTICAL BYTES; the proxy's own meta keys are stripped and application meta preserved, with a meta of only proxy keys removed entirely and a strip without meta a no-op; a digest round-trips, a tampered body fails closed, and an absent sha-256 member of a present header is malformed.*
**If false.** Two different roles over the same bytes produce the same handle, so evidence for one is evidence for the other — which is NP-087's injectivity failure at the handle rather than at the actor. 'Not a bare digest of the base' is what makes the domain separation structural instead of conventional.
**Likely owner:** none. The `http_profile.*` units that measure these files are each about what their own verdict means.
**Severity:** `critical`.
**Registered in part, ADR-MCPRE-069 S1.** The record spans seven files and three security stories, so it is split at registration. Six controls land: `digest::tests::{digest_round_trip, tampered_body_fails_closed, sha256_member_absent_from_present_header_is_malformed}` and `policy::tests::{an_algorithm_without_a_verifier_cannot_be_allowlisted, the_registry_maps_tokens_to_implemented_verifiers}` → `unit://http_profile.request_floor_result` (*"the covered `Content-Digest` agreed with the body ... under a policy-accepted algorithm"*); `replay::tests::the_principal_slot_is_the_subject_without_its_keyid` → `unit://http_profile.replay_key` (*"its injective pre-serialization onto the core cache's three slots"*). Ten rows REMAIN. The five `evidence.rs` handle controls are the record's headline clause and THM-0010 EXCLUDES it by name: *"It does NOT establish collision-resistant separation between roles."* The three `context.rs` proxy-meta-stripping controls are named by no theorem. `artifact::tests::bearer_token_extraction` measures a string parser, not *"a binding reported verified matched one explicitly supported typed verification branch"*, and `authoritative_admission::record::currentness::tests::every_class_has_a_distinct_index_inside_the_published_count` measures a refusal-enum bijection, which `admission_state_provenance`'s description does not state — both would be stretches, so neither is R1. Packet at `verification/reviews/packets/adr069-np-100-ratification-2026-09-19.md`.

## NP-101 — the JSON mode carries the profile and nothing else

**Controls:** `mcp-re-http-profile/tests/json_mode_test.rs`.
**Statement.** *The JSON carrier admits exactly the profile's own members and refuses a foreign one.*
**If false.** A JSON-mode exchange carries a member the profile never defined and a reader interprets it.
**Likely owner:** none. The `http_profile.*` units that measure these files are each about what their own verdict means.
**Severity:** `high`.

## NP-102 — the signer seam takes a preimage in and a signature out

**Controls:** `mcp-re-http-profile/tests/signer_seam_test.rs`.
**Statement.** *The signer seam accepts a preimage and returns a signature, and carries nothing else across.*
**If false.** The seam carries key material or a decision across a boundary whose whole purpose is that it does not.
**Likely owner:** none. The `http_profile.*` units that measure these files are each about what their own verdict means.
**Severity:** `critical`.

## NP-104 — the profile reproduces the RFC 9421 known-answer vectors

**Controls:** `mcp-re-http-profile/tests/rfc9421_kat.rs`.
**Statement.** *The implementation reproduces the RFC's own published vectors byte for byte.*
**If false.** The profile is self-consistent and wrong: every internal control passes and no other RFC 9421 implementation agrees with it.
**Likely owner:** none. The `http_profile.*` units that measure these files are each about what their own verdict means.
**Severity:** `high`.

## NP-105 — an admission binding names one identifier and binds to it

**Controls:** `mcp-re-http-profile/tests/admission_binding_test.rs`, `mcp-re-http-profile/tests/binding_identifier_test.rs`.
**Statement.** *An admission binding names exactly one identifier, and the binding it produces is to that identifier.*
**If false.** A request is admitted against a binding identifier other than the one it named.
**Likely owner:** none. The `http_profile.*` units that measure these files are each about what their own verdict means.
**Severity:** `critical`.
**Registered in part, ADR-MCPRE-069 S1.** The four `binding_identifier_test` controls are now in `unit://http_profile.artifact_verification_boundary`, whose description states *"a binding reported verified matched one explicitly supported typed verification branch and satisfied that branch's required binding form; every other artifact type is refused"* — the unit already carries `lib#block::tests::opaque_binding_with_reference_fields_fails_closed` and `reference_binding_missing_fields_fails_closed`, the in-crate twins of two of them. The four `admission_binding_test` rows REMAIN: the admission plane's theorems (THM-0003, THM-0006, THM-0053) are about the ASSERTION, and THM-0003/0006 rest on `http_profile.admission_currency`, a `proved` unit — attaching `tested` selectors there would misstate its class. Packet at `verification/reviews/packets/adr069-np-105-ratification-2026-09-19.md`.

---

## The small crates — NP-106 through NP-113

Seventy-six controls outside `mcp-re-proxy`. Nine REGISTER — seven into
`client.binding_spec_refusal`'s own file, and two that are the ANTI-VACUITY arm of
`client.transport_server_identity`: they show that the declared fault injector is what makes
an untrusted or wrong-identity server certificate accepted, so the rejections that unit
claims are the real verifier's and not an artefact of a test that never presented a bad
certificate.

The rest are eleven propositions, and four of them are premises of everything above
them. Four of the eleven are the RR-002 C5 split of the original NP-106.

## NP-106 — the Ed25519 floor accepts the material it is supposed to accept

**Controls:** `mcp-re-core/src/crypto.rs`.
**Statement.** *A signature this system's own signer produces over a preimage verifies under the matching verification key — through the request wrapper `verify_ed25519` and through the raw primitive, neither of which inspects a declared algorithm.*
**If false.** MCP-RE cannot verify what MCP-RE signed. Nothing is forged and nothing is admitted that should not be: the floor simply refuses everything, the proxy admits no request, and the deployment is down. That is the whole reason this is a separate record from the refusals — the two halves fail in opposite directions and only one of them is a soundness fact.
**Likely owner:** none. `core.ed25519_primitive` is the unit over this file, and THM-0014 is its theorem; the accepting direction is outside that theorem, for the reason stated below.
**Severity:** `critical`.
**Narrowed from "the Core's Ed25519 primitive is exact and total", ADR-MCPRE-069 RM-S1-FIX.** The record covered thirteen controls spanning five propositions, and RR-002 C5 forbids filing a heterogeneous record whole. Three controls stay here; `signature_is_deterministic_for_fixed_seed` is NP-170, the three error-rendering controls are NP-171, `verification_key_round_trips_bytes_and_b64url` is NP-172, and five REGISTERED. Packet at `verification/reviews/packets/adr069-np-106-ratification-2026-09-19.md`.

**The clause-2 argument for the five that left, in full, because it is the argument that has to survive.** THM-0014 says:

> If `Verifier::verify_request_floor` returns Ok, then for the request supplied: the covered
> `Content-Digest` agreed with the body, the RFC 9421 signature verified over the
> reconstructed signature base under an algorithm the verifier's policy accepts, the
> signature parameters were admitted as current, and the presented keyid was resolved through
> the trust seam for the Request slot.

It is a conditional over SUCCESSFUL returns, and its security consequence is stated entirely in the negative: *"An attacker cannot obtain a floor-verified request by tampering with the body, by presenting a signature under an algorithm the deployment does not accept, by replaying expired parameters, or by presenting a key the seam vouches for only in the Response slot."* So the containment test is a single question asked control by control: **does a world in which this control is false contain a successful `verify_request_floor` return for which one of those clauses is false?**

- `wrong_key_fails` — **contained**, by the verb in clause 2. If `verify_ed25519` accepted a signature under a key that did not produce it, "the RFC 9421 signature verified over the reconstructed signature base" is false of a request the floor returned Ok for. This is the conjunct M312 falsifies.
- `tamper_preimage_fails` — **contained**, same clause and the same probe. A tampered signature base that still verifies is a floor-verified request whose signature covered different bytes.
- `malformed_signature_base64_fails` — **contained**, clause 2. `verify_ed25519_with` returning Ok on input it never decoded is a floor-verified request under a signature that was never checked at all. It refuses at the decode arm rather than at `verify_strict`, which is why M312 leaves it green: a different arm of the same clause.
- `wrong_length_signature_fails` — **contained**, clause 2, at the `try_into` arm. Sixty-four bytes is what an Ed25519 signature IS; accepting fewer is accepting a value the clause's verb cannot be true of.
- `ensure_ed25519_alg_rejects_unknown_alg_with_supplied_error` — **RETIRED with its subject, and the containment argument it rested on was false of the tree.** It read as contained by clause 2's qualifier *"under an algorithm the verifier's policy accepts"*. But the premise — *"if the gate admitted `RS256` or `ES256`, an envelope declaring an algorithm the deployment does not accept would reach the raw primitive"* — required the gate to stand on a path to the floor, and it stood on none: `ensure_ed25519_alg` was called from nothing but its own two tests, and it gated on `SIG_ALG_ED25519` = `"Ed25519"`, which `policy.rs` pins as NOT accepted because the profile token is lowercase. Falsifying it could not have admitted anything. THM-0014's clause is owned by `http_profile.request_floor_result` and carried there by six registered controls — the four `tests/algorithm_confusion_test` cases plus `lib#policy::tests::an_algorithm_without_a_verifier_cannot_be_allowlisted` and `…the_registry_maps_tokens_to_implemented_verifiers`. Nothing the theorem claims lost a carrier.

And the eight that did not leave, with the clause that decides each:

- `ensure_ed25519_alg_accepts_the_supported_alg` — **not contained, and RETIRED with its subject.** The vacuity argument stood and still does: falsify it and `ensure_ed25519_alg` rejects `Ed25519` too, `verify_request_floor` returns Ok for nothing, and the conditional holds vacuously over an empty set of successful returns. The theorem names no algorithm, so it never pinned WHICH token the policy accepts. Its disposition `CD-16003` is retired with the control rather than left pointing at a control that no longer exists.
- `raw_primitive_verifies_without_any_alg_plumbing` — **not contained**, identically. Its single assertion is `verify_ed25519(preimage, &sig, &vk).is_ok()`. A primitive that refuses genuine material produces no successful return to be a counterexample. What it protects is the ADR-MCPS-02 layering split staying ergonomic for fixed-Ed25519 callers with no envelope — KMS self-checks, LB assertions, conformance vectors — which is a statement about this module's API and not about `verify_request_floor`. Here, under NP-106.
- `sign_then_verify_round_trip` — **not contained**, identically, and this is the control whose registration the review named first. It is the completeness half of the primitive. THM-0014 has no completeness clause. Here, under NP-106.
- `signature_is_deterministic_for_fixed_seed` — **not contained.** It asserts `sk.sign(m) == sk.sign(m)`, a property of SIGNING; THM-0014 constrains a VERIFIER and mentions no signer. A randomised Ed25519 signer falsifies this control and leaves every clause of THM-0014 true, because every signature it emits still verifies. NP-170.
- `malformed_key_b64url_maps_to_actor_binding_failed` — **not contained.** It fixes WHICH variant a malformed key renders as. THM-0014 says nothing about any error variant; it has no failure clause at all, and clause 4's key arrives "resolved through the trust seam", not through `VerificationKey::from_b64url`. NP-171.
- `malformed_key_bytes_map_to_actor_binding_failed` — **not contained**, same clause, same reason, at `from_bytes`.
- `response_variant_maps_to_response_sig_invalid` — **not contained.** It is on the RESPONSE path, and THM-0014 is the request floor; its clause 4 is about the Request slot specifically. THM-0021 was read as the second candidate and declines it too, for the reason recorded in the packet: what this control STATES is which sentinel comes back, and THM-0021 is an Ok-conditional that is indifferent to the sentinel. NP-171.
- `verification_key_round_trips_bytes_and_b64url` — **not contained**, and refusing it is what makes this commit consistent with itself. NP-107 is referred to R6 on the finding that *base64url is the exact encoding in both directions* is a premise THM-0014 USES rather than a proposition it contains — replace base64url with hex at every site and every clause still holds. A key round-tripping through that same codec is the same premise on a different carrier; it cannot be outside THM-0014 in `encoding.rs` and inside it in `crypto.rs`. NP-172.

## NP-170 — Ed25519 signing is a deterministic function of seed and message

**Controls:** `mcp-re-core/src/crypto.rs`.
**Statement.** *`SigningKey::from_seed_bytes(seed).sign(message)` returns the same Base64URL signature every time it is called.*
**If false.** A published conformance vector stops reproducing, and the SDK-parity fixtures that pin emitted bytes cease to be a test of anything: a mismatch would no longer distinguish a wrong implementation from a fresh signature. `SigningKey`'s own documentation gives this as the reason signing lives in the library at all — *"needed to generate reproducible conformance vectors (MCPS-002)"* — so it is the premise a whole evidence lane rests on.
**Likely owner:** none. It is a property of the signer, and every theorem over this file constrains a verifier.
**Severity:** `high`.
**Split out of NP-106, ADR-MCPRE-069 RM-S1-FIX.** Packet at `verification/reviews/packets/adr069-np-170-ratification-2026-09-19.md`.

## NP-171 — the crypto primitive never invents an error variant: each failure renders as the one its own layer owns

**Controls:** `mcp-re-core/src/crypto.rs`.
**Statement.** *Every failure this module reports is the variant its own layer owns: a resolved-but-malformed verification key — whether it arrived as bytes or as Base64URL — is `ActorBindingFailed`, and the error-agnostic verification core returns the sentinel its CALLER supplied, so a response-path failure surfaces as `ResponseSigInvalid` and never as the request path's `InvalidSignature`.*
**If false.** A key problem is reported as a signature problem, or a response failure as a request failure. Nothing is admitted that should not be — the refusal still happens — but the operator, the audit record and the peer are all told the wrong thing about WHY, and an alarm that cannot tell a malformed key from a bad signature sends the responder to the wrong place. That is the whole content of the module's own *"# Error mapping (deliberate)"* section, and this record is that section's measurement.
**Likely owner:** none, and the one authority this could belong to is a taxonomy theorem rather than a verification theorem — THM-0111 owns the frozen rendering of `mcp-re-core/src/error.rs`, not which site chooses which variant, which is a ratified owner decision no guard can see.
**Severity:** `high`.
**Split out of NP-106, ADR-MCPRE-069 RM-S1-FIX.** Packet at `verification/reviews/packets/adr069-np-171-ratification-2026-09-19.md`.

## NP-172 — a verification key round-trips through its raw bytes and its Base64URL spelling

**Controls:** `mcp-re-core/src/crypto.rs`.
**Statement.** *`VerificationKey::to_bytes` and `VerificationKey::from_bytes` are mutual inverses, and so are `to_b64url` and `from_b64url`: a key put through either projection and rebuilt holds the same 32 bytes.*
**If false.** A key enrolled in one spelling and presented in the other is not recognised as the same key — or, worse, two different keys have one spelling. Every comparison the system makes over an encoded key, and every keyid derived from one, inherits whatever this loses.
**Likely owner:** none, and deliberately the same answer as NP-107's. This is NP-107's proposition on a second carrier: the codec being exact in both directions, measured through the key type instead of through the helpers. It should be ratified with NP-107 or not at all.
**Severity:** `high`.
**Split out of NP-106, ADR-MCPRE-069 RM-S1-FIX.** Packet at `verification/reviews/packets/adr069-np-172-ratification-2026-09-19.md`.

## NP-107 — base64url is the exact encoding, in both directions

**Controls:** `mcp-re-core/src/encoding.rs`.
**Statement.** *Encoding uses the URL-safe alphabet and emits NO padding; decoding rejects a non-alphabet character and rejects padding; an empty input decodes to empty; arbitrary bytes round-trip; and a known answer is reproduced.*
**If false.** Two spellings of one value both decode, so a comparison over the encoded form does not mean what a comparison over the bytes would. Rejecting padding is the clause that makes the encoded form canonical rather than merely decodable.
**Likely owner:** none.
**Severity:** `high`.
**Referred whole, ADR-MCPRE-069 RM-S1.** THM-0014 was the candidate and it was read strictly rather than assumed. It contains the Ed25519 primitive's REFUSALS by its own verb — "the RFC 9421 signature VERIFIED" is false if the primitive accepts a wrong key or a tampered preimage — but it does not contain the codec. Swap base64url for hex everywhere and every clause of THM-0014 still holds; the codec is a premise it USES, not a proposition it promises, which is exactly the distinction ADR-069 §5 clause 2 turns on. Two of the seven controls fail clause 3 outright: `encode_has_no_padding` and `encode_uses_url_safe_alphabet` state MCP_RE_SPEC §3's wire promise — *"All MCP-RE signature and hash values are Base64URL WITHOUT padding"* — which is an independently, externally meaningful product promise to a peer and belongs to no theorem here. THM-0055 was checked as the second candidate and declines it too: it claims only that *"The keyid's base64url-no-pad encoding is injective over the fixed 32-byte width of a SHA-256 output"*, a narrower proposition over a different carrier, and its unit `http_profile.keyid` would need a `paths` widening to reach `mcp-re-core/src/encoding.rs`. Its seven rows and this record stay. Packet at `verification/reviews/packets/adr069-np-107-ratification-2026-09-19.md`.

## NP-108 — the profile-agnostic constants the RFC 9421 carrier stands on are frozen

**Controls:** `mcp-re-core/src/ids.rs`.
**Statement.** *`EXTENSION_ID`, `SIG_ALG_ED25519` and `DIGEST_ALG_SHA256` hold exactly `se.syncom/mcp-re`, `Ed25519` and `sha256`.*
**If false.** The carrier advertises an extension identifier, an algorithm token or a digest token a peer does not recognise — or recognises as something else. These are defined once and referenced everywhere precisely so no site can re-spell them; the control is what makes "once" a measured fact.
**Likely owner:** none. `mcp-re-core/src/ids.rs` is in no unit's `paths`, so no existing battery can take the selector and giving it one means a `paths` widening.
**Severity:** `critical`.
**Narrowed from the frozen error taxonomy, ADR-MCPRE-069 RM-S1.** This record used to cover eleven controls spanning two propositions, and ADR-069 RR-002 C5 forbids filing a heterogeneous record whole. The ten `mcp-re-core/src/error.rs` controls are the VERDICT TAXONOMY and are now `unit://core.verification_taxonomy` under THM-0111, whose statement names that file and says of it *"Each owns its own mapping totally — one variant per token, rendered by `wire_code()` and by `Display` alike"*. This one is not a verdict token: an extension identifier, an algorithm name and a digest algorithm name are carrier vocabulary, and THM-0111's *"A **verdict token** is `mcp-re.<name>` with no further dot"* excludes all three by construction. ND-005 (*mirrored and documented values*) was tested and declines it: a mirrored value fails by changing what a READER is told, while re-spelling `SIG_ALG_ED25519` changes the `alg` token the system emits and admits. It stays an unratified proposition with one control.

## NP-109 — the formatter inverts the parser across the admitted era, and the parser's fixed-width helper is total beyond the widths it is called with

**Controls:** `mcp-re-core/src/time/mod.rs`.
**Statement.** *`unix_to_rfc3339_utc` round-trips every end of the admitted era back through `parse_rfc3339_utc`; and `parse_fixed_digits` returns `None` for a start past the end, a width past the end, and a width wide enough that an unchecked accumulator would leave `i64` — widths `parse_rfc3339_utc` never calls it with.*
**If false.** A legal instant has no representation, or formats to something a peer parses as a different time; or the parser's one `external_body` helper is partial at a width some future caller uses.
**Likely owner:** `core.time_rfc3339` is the unit over this file, and THM-0002 is its theorem. Neither half above is inside that theorem.
**Severity:** `high`.
**Split and partly registered, ADR-MCPRE-069 RM-S1.** The record covered five controls over two propositions and RR-002 C5 forbids one disposition over the set. THM-0002 SPLITS it in its own words. It CONTAINS the boundary half — *"The two endpoints specifically are reachable, and are pinned by boundary controls at their exact Unix seconds, but the claim is containment."* — so `boundary_lowest_admitted_instant`, `boundary_highest_admitted_instant` and `boundary_a_five_digit_year_is_refused` joined `unit://core.time_rfc3339`'s existing battery, with no new unit, no `paths` change and no new obligation: that unit is `proved`, and these are the controls its own theorem's scope cites. It EXCLUDES the formatter half in terms — *"It says nothing about the inverse direction: that unix_to_rfc3339_utc round-trips a value in this range is a different proposition with its own evidence."*
**Why the helper control is here and not in the battery.** `fixed_digit_fields_are_total_outside_the_parser_widths` is not about the formatter at all, and the grouping it inherited from the scheduling analysis was imprecise. It was judged on its own. Three of its six assertions are inside THM-0002's reach and three — start 100, width 10, width 35 — are widths `parse_rfc3339_utc` never issues, so the control as a whole states a proposition about `parse_fixed_digits` as a standalone total function, strictly WIDER than THM-0002's claim about `parse_rfc3339_utc`. Clause 2 asks for a strict decomposition of a contained proposition; a wider one is not that, and a control cannot be split. Both rows stay. Packet at `verification/reviews/packets/adr069-np-109-ratification-2026-09-19.md`.

## NP-111 — a rebuilt plain reply is a JSON-RPC response or it is nothing

**Controls:** `mcp-re-client-proxy/src/proxy.rs`'s `plain_response_from_verified` (6).
**Statement.** *Rebuilding the plain MCP reply from the verified bytes yields a JSON-RPC
response or it yields a refusal, and never something in between: a JSON-RPC `error` reply is
carried through rather than flattened to a null result; a body that is not a single response
object carrying EXACTLY ONE of `result`/`error` — an empty envelope, a batch array, a bare
scalar, both members at once, a legal result beside a top-level `method` — fails closed;
bytes that are not JSON at all are a VERIFICATION failure and never a malformed REQUEST,
because the exchange has already run; an ordinary result still rebuilds; the proxy-owned
`_meta` block is stripped from both positions; and the reply carries the id THE PROXY SIGNED
rather than the one the server echoed.*
**If false.** A signed reply the local client cannot act on is delivered as a completed tool
call returning `null`, or a caller "fixes" its request after a 400 and retries a side effect
the server already performed, or a server addresses its answer to a different outstanding
call by choosing the id. Each one is a truthful-looking success the server never sent.
**Likely owner:** none, and the asymmetry is the finding rather than an accident. The Python
and TypeScript SDKs each have an `sdk_*.reply_envelope` unit over exactly this question; the
Rust client proxy has none. Three implementations of one profile, two of which state the
proposition and one of which does not.
**Root relationship.** The reply-envelope proposition. No client theorem holds it: THM-0084
owns the request/expectation pairing, THM-0126 owns what a verified reply ENTITLES, and
THM-0061 owns what the receipt SAYS — none of the three says anything about the shape of the
bytes handed back.
**Severity:** `critical`.
**Referred (R6).** Packet:
[`verification/reviews/packets/adr069-np-111-ratification-2026-09-19.md`](../../verification/reviews/packets/adr069-np-111-ratification-2026-09-19.md).

**What left this record in the S-05/CL-CLIENT slice.** It was filed whole over fifteen
controls and held four independently describable propositions. Six are now registered
evidence under THM-0061 in `client.proxy_reply_disposition` and
`client.receipt_contract_carriage`; three moved to records of their own (NP-181, NP-182,
NP-183); six remain here, and they are the ones that share a production function and a
question.

---

## NP-181 — a verified error reply is a failed call at the place that decides

**Control:** `mcp-re-client-proxy` `lib#proxy::tests::a_verified_error_reply_is_classified_as_a_failed_call_not_a_success`.
**Carrier:** `mcp-re-client-proxy/src/verified_outcome.rs`'s `read_outcome`.
**Statement.** *A verified reply carrying a JSON-RPC `error` member resolves to `CallFailed`
carrying the server's code, and never to `Success`. `classify_result` reads the `result`
member, an error reply has none, and an absent `result` classifies Terminal — which is the
success label — so without a distinct arm the failure is announced to the local client as a
completed call.*
**If false.** A tool call that the inner backend failed is delivered to the application as a
success. The signature verifies either way; what differs is what the server said, and the
difference is not recoverable once the header has been written.
**Why it is a record and not a registration, and this is the finding.** The control does not
measure the production arm. It rebuilds the reply and then writes the selection itself —

> ```rust
> let kind = match plain.get("error").map(|e| e.get("code").and_then(Value::as_i64)) {
>     Some(code) => ResponseKind::CallFailed { code },
>     None => match classify_result(plain.get("result")) { … },
> };
> ```

— which is a transcription of `read_outcome`'s first arm, not a call to it. Delete that arm
from `verified_outcome.rs` and this control stays GREEN. It is the shape this repository has
ruled on before: name the production function whose change turns it red, or it is a
tautology. What it does establish is that `plain_response_from_verified` carries the `error`
member through, and NP-111's first clause already owns that.
**Likely owner.** `client.verified_outcome` under THM-0126, whose statement covers the
composition — but not with this control. The registration this record refuses is the
attractive one: the unit's project and file are right, and its battery would then hold a
control that cannot go red on any edit to the file. Closing it means a control that CALLS
`read_outcome`, next to the five that already do, and that is production-adjacent work this
slice did not have authority for.
**Severity:** `critical`.
**Referred (R6).** Packet:
[`verification/reviews/packets/adr069-np-181-ratification-2026-09-19.md`](../../verification/reviews/packets/adr069-np-181-ratification-2026-09-19.md).

---

## NP-182 — an unstated contract is not a did-not-run verdict

**Control:** `mcp-re-client-core` `lib#response::delegated_tests::an_unstated_contract_is_not_a_did_not_run_verdict`.
**Carrier:** `mcp-re-client-core/src/execution_contract.rs`.
**Statement.** *`ExecutionStatus::Unstated` and `ExecutionStatus::NotExecuted` are distinct
inhabitants; an empty contract is not stated, reports neither a consumed continuation nor a
failed retention, and yields `RetrySafety::Unstated`; and a token this client does not know
is `Unrecognized` carrying the string, is STATED, and refuses the retry.*
**If false.** "Unknown whether it ran" becomes "it did not run" at the one call site that
decides whether to retry, and a side effect is performed a second time.
**Why it is a record and not a registration.** The proposition is THM-0061's first clause,
and it is already registered: `client.execution_contract` holds
`a_receipt_that_says_nothing_is_not_a_receipt_that_says_it_did_not_run` and
`an_unrecognized_value_is_carried_and_never_read_as_a_known_one` over the same production
property, in the owner's own module. This control is a superset of the two, and its BODY
lives in `response.rs` — a file `client.execution_contract` does not list in `paths` and
therefore does not digest. Registering it would give that unit a control it could lose the
body of without its fingerprint moving, which is the drift `_fingerprint._test_sources`
exists to stop, arriving through the one door it cannot see.
**What would close it.** Moving the control into `execution_contract.rs`'s own `mod tests`
and adding the selector to `client.execution_contract`. That is a source move, and moving a
test is the operation this repository has measured as breaking several tables at once, so it
is not a registry edit and did not belong in this slice.
**Severity:** `high`.
**Referred (R6).** Packet:
[`verification/reviews/packets/adr069-np-182-ratification-2026-09-19.md`](../../verification/reviews/packets/adr069-np-182-ratification-2026-09-19.md).

---

## NP-183 — a configured clock skew cannot widen the credential window

**Control:** `mcp-re-client-core` `lib#response::delegated_tests::an_out_of_range_skew_cannot_widen_the_credential_window`.
**Carrier:** `mcp-re-client-core/src/response.rs`, the delegation verify parameters.
**Statement.** *The operator-configured `max_clock_skew` does not reach the credential's
`nbf`/`exp` window unclamped: a receipt whose RFC 9421 freshness is current at the
verification instant, signed off a credential that expired long before it, fails on the
CREDENTIAL window rather than being admitted by a skew allowance.*
**If false.** An operator who sets a week of skew gets a week on the delegated credential's
TTL — the bound on a compromised delegated key's exposure — while the signature gate they
could observe is silently clamped, so testing the setting shows nothing wrong. That is the
worst shape a configuration defect takes: the observable half behaves and the unobservable
half does not.
**Why it is here at all.** It was filed as one of NP-111's fifteen and is not a reply-
disposition control in any reading. The receipt's disposition is not what it measures; the
credential's validity window is. Nothing in NP-111's statement, in THM-0061 or in THM-0126
asks the question, and the units that do own credential validity —
`client.response_signer_authorization` under THM-0058 — state WHICH signer is authorized
rather than how long the material stays current under a configured skew. Whether that
theorem's clause contains this is the ratification question, and answering it needs the
owner rather than this slice.
**Severity:** `critical`.
**Referred (R6).** Packet:
[`verification/reviews/packets/adr069-np-183-ratification-2026-09-19.md`](../../verification/reviews/packets/adr069-np-183-ratification-2026-09-19.md).

## NP-112 — a host signer signs under its own identity and renders no key

**Controls:** `mcp-re-host/src/signer.rs`.
**Statement.** *A signed request names the signer's OWN key id; the identity is readable and the key is not; and the tool-call convenience signs under the same identity.*
**If false.** A host signs under an identity that is not the one it advertises, or the convenience path signs under a different one from the explicit path — two identities for one signer.
**Likely owner:** none.
**Severity:** `high`.

## NP-113 — a revocation source reports availability honestly

**Controls:** `mcp-re-policy/src/revocation.rs`.
**Statement.** *An empty source revokes nothing; an in-memory source is always available; a revoked id is reported revoked; and an unavailable source carries its details for diagnostics.*
**If false.** An unavailable revocation source is read as an empty one, so nothing is revoked and the deployment cannot tell the difference. That is the execution-certainty collapse this repository has ruled on, in the one place where 'we could not check' and 'nothing is revoked' must never be the same answer.
**Likely owner:** none.
**Severity:** `high`.

---

## The proxy's top-level source — NP-114 through NP-128

117 controls in `mcp-re-proxy/src/*.rs` and `src/continuation_store/`. Nine REGISTER into
three units whose own statements name the clause the control measures — the "minimal audited
SigV4" the AWS adapter's statement ends on, the poller's liveness bound and the rotation
overlap, and the signing budget `proxy.listener_state_assembly` lists as one of its four
terms. Four more attach to propositions this campaign already recorded.

The rest are fifteen propositions, and one of them is **ADR-MCPRE-069 §3's own worked
instance**, still unclaimed on main.

## NP-114 — what a Cloud KMS token refusal costs, and what it discards

**Controls:** `mcp-re-proxy/src/gcp_kms_keysource.rs` (7).
**Statement.** *A Cloud KMS 401 means the bearer token was not honoured, so that token is discarded and the call retried exactly once, and a 401 a fresh token fixes self-heals every time; a 403 says nothing about the token and discards none, and costs one call rather than two; a PERSISTENT 401 stops costing a metadata round trip per call and probes again only past the cool-off; only a refusal with a token to discard costs a second call, so a success, a quota refusal and a source that caches nothing each cost one; and eviction is keyed on the token that was PRESENTED, so a refusal about a superseded token does not discard the successor another thread just minted, while invalidating the source really does force the next call to re-fetch.*
**If false.** The response signer stops signing for a reason that was never about the token — a 403 threw away a good credential, or a permanently unbound identity turned every unauthenticated peer's handshake into a metadata fetch plus a second Cloud KMS call. Or the other direction: a rotation stops self-healing, and a stale token fails every signature for the whole reuse window.
**Likely owner:** none.
**Severity:** `high`.
**Registered in part, ADR-MCPRE-069 S-10.** Fifteen of this record's original twenty-three rows are now `unit://proxy.gcp_metadata_token_lifetime` under **THM-0117**, falsified by `M344-proxy-the-reuse-floor-extends-a-stated-token-lifetime`, and a sixteenth is NP-192. THM-0117's statement contains each of the fifteen by name: *"A credential acquired from AWS STS or from the GCE/GKE metadata server carries the expiry its issuer stated, and that expiry is never extended"*, *"An expiry that CANNOT be read — absent, unparseable, or a lifetime the issuer did not establish — is treated as already expired, never as unlimited."*, *"The credential is still reused briefly rather than re-exchanged per call, and that brief window is a floor on churn rather than an extension of a stated lifetime."*, and *"Concurrent callers perform ONE exchange between them, a failed exchange is not repeated by every waiter, and the cool-off after a failure expires on its own and is cleared by a success."* Its scope names the lane as well: *"TWO LANES. The AWS acquirer exists under `aws_kms_keysource` and the metadata acquirer under `gcp_kms_keysource`; neither is in the default lane."*
**These seven are not, and the theorem's own text is why.** THM-0117's scope opens *"THE LIFETIME, NOT THE CREDENTIAL'S POWER."* and adds *"NOT A CLAIM ABOUT THE ISSUER."* — what is established is that this implementation *"never reads more lifetime out of an answer than the answer states"*. A 401 or a 403 is the issuer's RUNTIME VERDICT on a credential whose stated lifetime has not lapsed; honouring it, bounding what it costs and keying the eviction on identity are a second authority over the same value, and nothing in the statement reaches them. Nor can they be absorbed as the theorem's admitted availability conjuncts: it names exactly two — *"The single-flight and cool-off conjuncts are availability with a security edge"* — and these are neither. **Under review RR-002 they also cannot be dispositioned `not-evidence`**: the admission test would turn on cost and amplification, which is the availability axis that review forbids a family to be created or widened along. So they stay a proposition.
**A correction to the plan this slice worked from, and it goes the other way.** The brief said two of the twenty-three clauses were availability. Measured against the tree there are seven controls in this authority, on two sides of one seam — five driving `UreqGcpClient::with_token_retry` and two driving `MetadataServerTokenSource::invalidate` — and the plan counted record-statement clauses rather than controls.
**Packet:** `verification/reviews/packets/adr069-np-114-ratification-2026-09-20.md`.

## NP-115 — the delegated TLS signer offers Ed25519 and nothing else

**Controls:** `mcp-re-proxy/src/delegated_tls.rs`.
**Statement.** *The handshake offers Ed25519 ONLY; the signer scheme is Ed25519 and the signature is 64 bytes; and a wrong-length signature fails closed.*
**If false.** The TLS handshake negotiates a scheme the remote signer does not implement, or accepts a signature of the wrong length as a valid one. This is NP-002's containment argument at the handshake: the set of algorithms offered is the set that can be used.
**Likely owner:** none.
**Severity:** `critical`.

## NP-116 — channel peer resolution yields nothing where the channel carries no identity

**Controls:** `mcp-re-proxy/src/tls.rs` (2).
**Statement.** *An absent acceptance resolves NO identity, and an LB-assertion deployment
resolves no transport identity at all even while a live accepted credential is in hand.*
**If false.** The proxy produces a transport identity in a deployment where the channel is
terminated in front of it, which would let NP-074's guarantee be read as end-to-end; or it
answers from something other than an acceptance.
**Likely owner:** none, and the reason is the same on both arms. THM-0031 takes an acceptance
BY VALUE — *"a free function taking a `MechanismVerifiedCredentialEvidence` by value and a
`CertificateIdentityPolicy`, and nothing else"* — so an ABSENT acceptance is outside its
domain rather than a case it decides. And no theorem states the provenance switch: THM-0080
is about the route both direct-TLS paths take, not about a deployment in which neither takes
it. The nearest statement is NP-074's, which is itself unratified.

The other five controls of this record landed: `proxy.channel_peer_resolution` under
THM-0031, falsifier `M341`.
**Packet:** `verification/reviews/packets/adr069-np-116-ratification-2026-09-20.md`.
**Severity:** `critical`.

## NP-119 — a continuation leg is established exactly once

**Controls:** `mcp-re-proxy/src/continuation_store/mod.rs`, `mcp-re-proxy/src/redis_continuation_store.rs`.
**Statement.** *The first open leg stores; a second open on a LIVE key is refused and changes nothing; concurrent creators yield exactly ONE stored; an expired key may be established again; a backing failure is UNAVAILABLE and never a collision; and at the Redis backend the open leg records the bases under an NX-guarded, bounded PX TTL, a taken key answers collision rather than an error, and a non-positive TTL still asks for an expiring entry.*
**If false.** Two writers each believe they opened the same continuation leg, so an answer leg signs over bases that belong to the other — or a backing outage is reported as a collision, which tells the caller the leg exists when nobody knows. THIS IS ADR-MCPRE-069 §3's OWN WORKED INSTANCE: five controls in `continuation_store/mod.rs` that the record used to show that a proposition can be real, passing, and claimed by nothing. `proxy.continuation_correlation_store` registers two controls from the same file and states a different proposition — reachability by the resolved actor and the peek/consume split — and §5 forbids widening it to cover establishment. The three Redis controls are the same proposition at the backend and are recorded with them.
**Likely owner:** none.
**Severity:** `critical`.

## NP-120 — the shared replay store admits a nonce once, across instances

**Controls:** `mcp-re-proxy/src/shared_replay.rs`.
**Statement.** *A fresh request is admitted and a replay refused on one instance; a request inserted via instance A is a replay via instance B; distinct tuples do not alias; an already-stale request is rejected PRE-STORE and not recorded as fresh; a non-positive window is flagged stale pre-store; the skew folded into `retain_until` matches the in-memory semantics; the ceiling FAILS CLOSED when full and the store recovers once its entries expire; a stale request via the shared cache fails closed; and the durability class delegates to the backing store.*
**If false.** A replayed request is admitted — because the second instance never saw the first's insert, because two distinct tuples aliased to one key, or because a full store failed open. 'Rejected pre-store and NOT RECORDED AS FRESH' is the clause that keeps a stale request from consuming the slot that would have caught its replay.
**Likely owner:** none.
**Severity:** `critical`.

## NP-121 — a replay tier's published guarantee is its own

**Controls:** `mcp-re-proxy/src/replay_tier.rs` (10).
**Statement.** *Every tier has a non-empty guarantee and NO TIER CLAIMS UNCONDITIONAL; a tier promising wait supplies its wait parameters and wait-quorum parsing extracts the quorum and timeout; the async tier's claim ceiling is not linearizable; parsing round-trips the simple tiers and refuses unknown and malformed ones; the wire names are the semantic ADR names; and the startup audit line carries the backend, tier and guarantee and NO NONCE.*
**If false.** A deployment publishes a replay guarantee it does not have, or an async tier is read as linearizable. This is NP-063's proposition for the other tier vocabulary, and the two are recorded separately because they are two vocabularies with two ceilings — the audit-line clause differs too: no key material there, no NONCE here.
**Likely owner:** none.
**Severity:** `high`.
**Registered in part, ADR-MCPRE-069 S-06.** One row — `strict_production_minimum_is_wait_quorum_or_stronger` — is now `unit://proxy.replay_tier_production_minimum` under **THM-0092**, falsified by `M335-proxy-the-production-minimum-excludes-the-async-tier`. THM-0092's statement quantifies over it by name: replay admission refuses when the deployment *"declares one below the strict-production minimum"*, and this row is the membership behind that threshold — without it the refusal is well formed and empty.
**A correction, and it goes the other way.** This campaign's own referral packet (`work/campaigns/mcp-re-adr069-product-claim-closure/packets/NP-121-residue.md`) states that **seven** of these rows are R2 under **THM-0086** and are *"ordinary registration work, not an owner question"*. Re-measured against the tree, six of the seven are refused and the seventh belongs under THM-0092, not THM-0086. THM-0086 is a *"CONFIGURATION PROJECTION ONLY"* claim about which tier `MaterializedReplay::materialize` hands the serving path; its *"a backend this build does not carry is refused by name rather than substituted"* clause is about a BACKEND the build lacks, already measured by `a_backend_the_build_lacks_is_refused_and_named` inside `proxy.replay_materialization`, and not about an unknown tier NAME in operator input. The operational test settles it: rename every wire name, empty every guarantee string, and THM-0086 still holds. THM-0118 cannot take them either — its scope is *"THE SEAM, NOT A DEPLOYMENT'S TIER"* and its owner is in another crate, so no unit's `paths` can reach this carrier from there. The packet was matched on the concept rather than on the carrier, which is the same error S-04 corrected for NP-140. **Root relationship.** A premise of the proxy units above it. The ten rows that remain are two propositions — the tier vocabulary, and the published guarantee — and NP-063 asks the identical question for the revocation-tier vocabulary. Packet at `verification/reviews/packets/adr069-np-123-np-143-np-147-np-148-np-184-np-185-ratification-2026-09-19.md`.

## NP-122 — the handshake quota opens on quota failures only, and never shortens

**Controls:** `mcp-re-proxy/src/handshake_quota.rs`.
**Statement.** *ONLY quota failures open the window; a throttled signature stops calling the signer for the cooldown; a successful probe reopens the path AT ONCE and does not clear a window armed later; only one handshake probes at the cooldown boundary; a straggler cannot SHORTEN the window; a slow throttled call still opens a live window; the window is never shorter than the network timeout; and a poisoned window lock still signs.*
**If false.** A remote signer under quota pressure is hammered by every handshake — or, in the other direction, an unrelated failure opens a cooldown and the listener stops signing for a reason that was never quota. 'A straggler cannot shorten the window' is the race: a late reply from before the window must not end it.
**Likely owner:** none.
**Severity:** `high`.

## NP-123 — every OFF posture line tells the operator what to do about it

**Controls:** `mcp-re-proxy/src/serving_capabilities.rs` (1) —
`tests::every_off_line_tells_the_operator_what_to_do_about_it`.
**Carrier:** the OFF-line prose constants, asserted over the constants themselves.
**Statement.** *Every OFF posture line names a flag to set or the build feature that is missing, and says that the capability is off — so an operator reading a transcript can decide what to DO about the line rather than only that something is absent.*
**If false.** A capability reports OFF and the operator has no way to tell whether it can be turned on, or how. This is NP-004's operator problem solved from the other side: not merely that a seam states its posture, but that the statement is actionable.
**Likely owner:** none.
**Severity:** `high`.
**Registered in part, ADR-MCPRE-069 S-06.** The other five rows are `unit://proxy.serving_capability_posture` under **THM-0077**, falsified by `M336-proxy-an-unopenable-retention-directory-is-not-an-off-posture`. THM-0077's statement contains them: *"Every security capability held by the serving runtime is derived from validated semantic owner state. Illegal, unsupported or internally contradictory deployment postures cannot be silently reinterpreted into a weaker posture during materialization or serving."* An ON posture over no artifact, and an unopenable retention directory resolving to OFF, are that reinterpretation.
**This row is not.** What the OFF line's PROSE tells an operator to do is an operator-facing product promise about the transcript, not a decomposition of a posture claim: the deployment's posture is identical whether or not the sentence names a flag. It is the same axis as NP-132's refusal-token vocabulary and NP-145's rendering agreement, both of which this campaign referred. **Root relationship.** A premise of the proxy units above it; no theorem states what a posture line must tell an operator. Packet at `verification/reviews/packets/adr069-np-123-np-143-np-147-np-148-np-184-np-185-ratification-2026-09-19.md`.

## NP-124 — a control-plane runtime exists only where it is needed, and outlives no owner

**Controls:** `mcp-re-proxy/src/control_runtime.rs`.
**Statement.** *A deployment that needs no control-plane client starts NO runtime; a single contributor is enough and no contributor is not; every consumer receives a handle to the SAME runtime; a runtime built before a later failure does not escape it; and dropping the owner stops work a surviving handle had started.*
**If false.** A runtime outlives the failure that should have torn it down, or a surviving handle keeps work going after its owner is gone. NP-003 is the same rule for threads; this is it for the runtime that owns them.
**Likely owner:** none.
**Severity:** `high`.

## NP-125 — a key source signs by delegation and never by export

**Controls:** `mcp-re-proxy/src/key_source.rs`.
**Statement.** *A boxed source signs BY DELEGATION AND NEVER BY EXPORT; an export attempt registers on the counter; a TLS-only source names no signing seed; the default is no delegated TLS signer; and the refusal vocabulary separates ABSENT from MALFORMED.*
**If false.** Key material leaves the custody boundary through a source that was supposed to sign inside it. The counter is the measurement that makes 'never by export' checkable rather than asserted, and the absent/malformed separation is the same rule NP-106 makes about the primitive's errors.
**Likely owner:** none.
**Severity:** `critical`.

## NP-126 — a configured client CRL is loaded or the listener fails closed

**Controls:** `mcp-re-proxy/src/client_crl_publication.rs` (2) —
`client_crl_loading_tests::missing_client_crl_file_fails_closed`,
`client_crl_loading_tests::no_crl_paths_loads_empty_vec`.
**Statement.** *A configured-but-unreadable client-CRL path is a HARD ERROR naming the path, never a silently skipped revocation check; and an empty CRL list loads as an empty list rather than as a failure, because configuring no CRL is a posture and not a mistake.*
**If false.** A listener starts with a revocation list it could not read and believes it is enforcing revocation — the fail-open an operator cannot see, because every later line about the CRL posture is then about a list that was never loaded.
**Likely owner:** none.
**Severity:** `critical`.
**Registered in part, ADR-MCPRE-069 S-04.** The `nextUpdate` gate over a CRL VALUE — a CRL that states one is accepted, a CRL that never falls out of force is refused by name and by index — is now `unit://proxy.client_crl_next_update_gate` under THM-0131, falsified by `M326-proxy-a-crl-with-no-expiry-is-not-fresh`. THM-0131's statement contains that half verbatim: *"A set of client CRLs is installable only when every one of them is inside its own `nextUpdate` window and states one at all."* The two rows above are the LOADER, one layer below the value, and THM-0131 reaches them nowhere: its claim is a property *"of the value, not of a call site"*, and a path that cannot be read yields no value to classify. THM-0054 is about the VERIFIER's three postures and says explicitly that it *"does not establish that the CRLs a deployment loads are current or complete"*. Packet at `verification/reviews/packets/adr069-np-126-ratification-2026-09-19.md`.

## NP-127 — a configuration handle keeps serving the configuration it was taken under

**Controls:** `mcp-re-proxy/src/config_snapshot.rs`.
**Statement.** *A handle taken BEFORE a swap keeps serving its configuration; load returns the current one and store swaps; reload swaps on a successful rebuild and KEEPS THE LAST GOOD one on failure.*
**If false.** An in-flight exchange is decided half under the old configuration and half under the new — NP-118's failure for configuration rather than trust — or a failed reload leaves the process with no configuration at all instead of the one that was working.
**Likely owner:** none.
**Severity:** `high`.

## NP-128 — the deployment clock reads a plausible present and never runs backwards

**Controls:** `mcp-re-proxy/src/clock.rs`.
**Statement.** *The clock reads a plausible present instant, does not run backwards between reads, and a sane host clock is not diagnosed as faulted.*
**If false.** Every freshness window, every expiry and every cool-off is computed against a clock that moved the wrong way. NP-065 decides what a FAULTED clock does; this is what makes 'faulted' a measurement rather than a guess, and its third clause is the false-positive arm.
**Likely owner:** none.
**Severity:** `high`.

---

## The proxy's subtrees — NP-129 through NP-148

229 controls across twenty subtree modules of `mcp-re-proxy/src/`. Twenty propositions, one
per authority the subtree separates — and fifteen more controls attach to propositions this
campaign already recorded: eight managed-worker controls to NP-003, six
materializing-runtime controls to NP-067, and one KMS bracketed-host control to NP-027.

Three subtrees hold two authorities each and are split accordingly: the serving path
separates *what it refuses before spending* from *what an acknowledgement may assert*, the
authorization plane separates *where the actor and action come from* from *what each refusal
is called*, and the trust plane separates *the cache* from *the posture*.

## NP-129 — the serving path refuses before it spends or signs

**Controls:** `mcp-re-proxy/src/http_profile_serve`.
**Statement.** *A body the profile cannot carry unchanged is refused BEFORE ANYTHING IS SPENT and an unrepresentable one before any reserialization; a saturated plane refuses BEFORE A BYTE IS TRANSMITTED; a document that is not an MCP message is refused at 400 and request state is read only as a string under `params`; a notification and a request are told apart ONCE; an uncorrelated reply is refused before anything signs it, an unrecognized result type is NEVER SIGNED, and a JSON-RPC error is a terminal answer rather than a malformed one; an open leg yields the state its answer re-presents and a collision fails the leg closed WITHOUT RETRYING; the carrier holds the terminal the request selected and the reply carries the class the classifier read; the audience the store keys under is the one the verifier enforces; the binding prerequisite and the assertion coordinate are different facts and the binding stage hands on the FACT rather than a unit; and application meta survives the PEP-owned strip.*
**If false.** The proxy spends a budget, transmits bytes, or signs a reply for a request it was going to refuse — and 'never signed' is the clause that matters most: an unrecognized result type that gets signed is MCP-RE attesting to something it could not classify.
**Likely owner:** none.
**Severity:** `critical`.
**Registered in part, ADR-MCPRE-069 S1.** The refuse-before-the-spend clauses — a non-MCP document at 400, a body the profile cannot carry unchanged, an unrepresentable body before any reserialization, a saturated plane before a byte is transmitted — are now `unit://proxy.pre_dispatch_refusal_precedence` under THM-0078, falsified by `M283-pre-dispatch-envelope`. The thirteen rows that remain are the clauses THM-0078's statement and scope do NOT contain: the never-signed pair (THM-0075 is about attribution, not protocol legality), reply classification, the single-decision and audience clauses, the pre-admission carrier and the PEP-owned strip. They need a theorem stated, not a wider unit — packet at `verification/reviews/packets/adr069-np-129-ratification-2026-09-19.md`.

## NP-130 — an acknowledgement asserts only what actually happened

**Controls:** `mcp-re-proxy/src/http_profile_serve`.
**Statement.** *A message that MAY NOT HAVE ARRIVED is not acknowledged, and neither is a notification the backend may not have received; a timeout is NEITHER A REPLY NOR A DEFINITE FAILURE; an unusable answer to a notification still says the backend WAS REACHED; a deployment that retains nothing owes nothing on any of the three and nothing is owed where retention is not configured; an unconfigured deployment claims nothing about permission and the carrier does not flatten the authorization posture; only a REAL retirement spends an approval; the record budget is bounded and small; and a disabled plane still carries the default lifetime.*
**If false.** The proxy tells a caller something happened that may not have. Every clause is the same refusal to collapse execution certainty onto the convenient side — the rule this repository has ruled on and measured before — and the last of them is its opposite arm: reaching the backend IS a fact, and an unusable answer must not erase it.
**Likely owner:** none.
**Severity:** `critical`.
**Referred, ADR-MCPRE-069 S1.** No ratified theorem's statement or scope contains *an acknowledgement asserts only what actually happened*. THM-0101 is the nearest and EXCLUDES it in its own words — `TerminalResponseServed` and `OpenLegResponseServed` are two of the six assembly-owned transitions the correspondence claim does not cover. Ratification packet at `verification/reviews/packets/adr069-np-130-ratification-2026-09-19.md`.

## NP-132 — each authorization refusal is its own token

**Controls:** `mcp-re-proxy/src/authorization/pdp/refusal.rs` (6),
`authorization/verified_action.rs` (2).
**Statement.** *An actor mismatch and an action mismatch are DIFFERENT TOKENS; no configured
authority and an untrusted issuer are different tokens; a digest mismatch is not reported as
a malformed artifact; a scope the deployment does not accept is not an actor mismatch; a
request presenting nothing says so RATHER THAN BORROWING A DENIAL; an explicit deny and an
action mismatch deliberately collapse onto one token; a signed body that is not JSON and one
with no method are different facts; and a malformed request is REPORTED rather than refused
by this authority.*
**If false.** An operator reading a refusal is sent to the wrong place, or a request that
presented nothing is recorded as having been denied — which is a denial nobody made. The one
deliberate collapse is stated as a control rather than left as a coincidence, which is what
makes the other separations claims instead of accidents.
**Likely owner:** none.
**Severity:** `high`.

**Narrowed and split, ADR-MCPRE-069 S-11.** Thirteen controls, three propositions, and one
ratified sentence that decides the largest of them.

**Three are REGISTERED**, appended to `unit://proxy.authorization_coordinate_provenance`'s
battery under THM-0040 — no new unit, no `paths` change, no new falsifier owed, because that
unit already measures all three files. `a_method_that_names_no_target_is_not_the_same_as_one_missing_its_target`
is the statement's own clause, verbatim: *"a decision naming no target matches only a
not-applicable one and an absent signed target matches neither"*.
`every_verified_dimension_is_projected_separately` carries three of the four projections the
comparison reads one at a time: *"the decided actor's trust domain and subject equal the
request's VERIFIED actor's, and under credential scope its keyid does too"*.
`a_request_carrying_no_decision_is_not_a_refusal` is the arm that must NOT be a refusal in
that unit's own description — *"none, two, or a reference-form binding produce no candidate
at all"* — whose two other arms were already in the battery.

**Eight stay, and THM-0040 declines them in terms.** Its scope: *"Nor does it establish that
a refusal is reported faithfully to an operator; the refusal algebra is tested and
deliberately carries no theorem, because its vocabulary has no production reader today."*
That is a ratified authority saying this exact population is deliberately unclaimed, so
registering it under any theorem would contradict a fingerprinted scope sentence rather than
decompose one. THM-0069 does not rescue it: THM-0069 is about what a RECORD may say, its
authorization clause stops at *"the two authorization refusal arms stay distinguishable"* —
already `proxy.refusal_provenance`'s `the_two_authorization_arms_stay_distinguishable` — and
these eight are one altitude below that, inside the PDP's own token set.
`a_malformed_request_is_reported_rather_than_refused_by_this_authority` is here with them: it
adds nothing to the target algebra that the registered control does not already assert, and
what it is FOR — which authority owns the refusal — is the axis the scope sentence names.

**Two are split out under RR-002 C5**, because they are not this proposition at all:
**NP-195** (an unbound deployment says not-claimed rather than asserting a channel binding)
and **NP-196** (the authorization-authority seam is populated separately from the
request-signer seam).
**Packet:** `verification/reviews/packets/adr069-np-132-np-195-np-196-ratification-2026-09-20.md`.
## NP-133 — a request form carries only its own material

**Controls:** `mcp-re-proxy/src/deployment_request`.
**Statement.** *Each form carries ONLY ITS OWN MATERIAL: a replay store is one backend with only its own locator, a coordinate cannot exist without the store it names a place in, and the derived coordinates start unnamed; an attested form cannot exist without the acknowledgement and the off request supplies no parameter any machine could dangle; the unenforced form has no gate inputs to dangle and both enforcing forms carry the gate they apply, an applied gate always naming the record it compares against; a degraded window exists only where one opens and only above zero, and failing closed is the default and carries no window; the cadence is optional under exactly one tier and only the pushing tier can name an epoch source; an empty set is the unconfigured posture, configuring neither mechanism IS a posture, and the two mechanisms COMPOSE rather than excluding each other; the durability claim and the store are separately stated and the locator projection names no backend; one Redis can serve two roles without the roles becoming one; a source without a named key is still a source and a store that does not exist drives the same consumer; the default form is the channel credential and the default identity field is the URI SAN; a scope beside off is representable because refusing it is NOT THIS TYPE'S JOB; and the verification set can be empty and is judged at the boundary.*
**If false.** A request value exists that carries a parameter no machine will read — the dangling-input class the classifiers refuse one layer up — or a form is inhabitable without the material it cannot operate without. The last clause is the layering, stated as a control: this type represents, and the boundary refuses.
**Likely owner:** none.
**Severity:** `critical`.

## NP-134 — the trust cache stops caching before it stops answering

**Controls:** `mcp-re-proxy/src/trust_plane` (4) —
`trust_cache::tests::{expired_entries_are_swept_rather_than_merely_ignored,
not_found_uses_short_ttl_so_a_new_key_propagates, past_the_ceiling_the_cache_stops_caching_but_keeps_answering,
prune_evicts_closed_windows}`.
**Statement.** *Past its entry ceiling the cache STOPS CACHING BUT KEEPS ANSWERING, so a memory bound does not become an outage; an expired entry is SWEPT rather than merely ignored on read, and `prune` evicts closed windows, so a distinct keyid from an unauthenticated peer does not leave a permanent entry behind; and a not-found answer is cached under a SHORT TTL so a freshly published key propagates well before the full `T` would elapse.*
**If false.** Two opposite failures, both real. A cache that stopped answering when it stopped caching turns a memory bound into a load-triggered self-inflicted outage; a cache that never sweeps grows one entry per keyid an unauthenticated peer presents, because the keyid gate runs before trust resolution.
**Likely owner:** none.
**Severity:** `critical`.
**Registered in part, ADR-MCPRE-069 S-04; split.** Three rows are registered. The ENTRY-ADDRESSING half — `trust_cache::tests::compose_key_is_injective_across_delimiter_containing_pairs` and `push_trust::tests::push_for_a_different_key_does_not_evict_the_active_entry` — is `unit://proxy.trust_cache_entry_addressing` under THM-0097, whose statement quantifies *"for every Request-slot `(signer, key_id)` its trust plane's resolver is asked about"*, falsified by `M328-proxy-the-cache-key-is-injective`. It is NOT registered under THM-0119 even though THM-0119 states the identical shape: THM-0119's scope says *"THE SEAM AND THE REFERENCE IMPLEMENTATION. Nothing here is about the runtime trust plane's tiers, its caching windows, or its revocation channel"*, which is this carrier. `live_trust::tests::no_positive_caching_consults_inner_every_call` is an R1 into `proxy.trust_resolution_window`, whose paths already hold `live_trust.rs` and whose declared proposition already carries the live tier; THM-0097 says *"always under the live tier"*. Three further propositions were separated out of this record rather than left inside it: NP-178, NP-179 and NP-180. The four rows that remain are the DEGRADATION half, which THM-0097 excludes in its own words — *"Not a liveness claim"* and *"What is cached NEGATIVELY — a revoked or unknown pair, and for how long — is an availability fact and is not part of this claim"*. Packet at `verification/reviews/packets/adr069-np-134-np-178-np-179-np-180-ratification-2026-09-19.md`.

## NP-135 — a handle that outlives its trust plane keeps answering only where an answer carries no authority

**Controls:** `mcp-re-proxy/src/trust_plane` (2) —
`handle_lifetime_tests::{a_directory_that_outlives_the_plane_still_answers_from_the_last_snapshot,
surviving_handles_do_not_keep_the_refresh_workers_alive}`.
**Statement.** *After the owning plane is dropped, the SIGNER DIRECTORY keeps answering from the last snapshot — legitimately, because a kid to signer coordinate is not verification material and admits nothing by itself — while the resolver refuses; and a surviving handle of either kind does not keep the refresh workers alive.*
**If false.** Either half is a different defect. A directory that emptied or panicked on its plane's drop turns a retirement into a request-path failure; a handle that kept the refresh workers alive makes a plane's lifetime unbounded by its owner, so a retired plane goes on re-reading `--trust` for a deployment that retired it.
**Likely owner:** none.
**Severity:** `critical`.
**Registered in part, ADR-MCPRE-069 S-04.** Six of the eight rows are registered. The four `store_cadence_tests` rows are `unit://proxy.trust_posture_declaration` under THM-0100, whose statement contains them — *"The interval the startup transcript prints as the delivered revocation window is exactly this arithmetic: `R + T` for the caching tiers, `R` for the live tier, and `UNBOUNDED` when no cadence is configured — in which case the snapshot is the startup read for the process's lifetime"* — falsified by `M327-proxy-the-tier-line-names-its-reload-floor`. The two `freshness::tests` rows are an R1 into `proxy.trust_resolution_window`, needing no `paths` widening: THM-0097 states *"The two terminal cases are irreversible; a successful reload landing afterwards does not reopen the resolver"*, and that unit already drives the same transition through the plane. The two rows above stay because THM-0097 disclaims exactly what they assert: *"Not a liveness claim: that an admitted key IS served is not stated."* Both are claims that something KEEPS ANSWERING, and the second is additionally a runtime-lifetime proposition of the family NP-124 carries. Packet at `verification/reviews/packets/adr069-np-135-ratification-2026-09-19.md`.

## NP-136 — retained bytes come back under their digest, from an owner-only store

**Controls:** `mcp-re-proxy/src/retained_evidence`.
**Statement.** *Retained bytes come back UNDER THEIR DIGEST and modified evidence gets a different one; a non-token digest CANNOT ESCAPE THE ROOT; bytes replaced on disk are refused by the read view and a truncated object is REWRITTEN rather than reported as retained; retaining the same bytes twice is idempotent and staging the same object concurrently leaves one object and no residue; temp residue from an interrupted write does not block a later put; a missing object is ABSENT RATHER THAN AN ERROR; a created root, store root and file are OWNER-ONLY; creating over an existing path is refused and a path that is not a directory is refused at open; opening an unwritable directory fails at open, opening for reading does not create the directory, and a read-only directory opens for reading and serves its objects; the writability probe leaves nothing in the store; and no two suffixes are the same.*
**If false.** Retained evidence is not the evidence that was retained — replaced on disk, truncated and read back as whole, or fetched from outside the root by a digest that was never a token. The path-traversal clause and the owner-only clauses are the two that need no protocol at all to exploit.
**Likely owner:** none.
**Severity:** `critical`.

## NP-137 — a credential-currency or identity refusal names what it read

**Controls:** `mcp-re-proxy/src/communication_assurance`.
**Statement.** *A presented leaf that REFUSES is never reported as an ABSENT one and an optional leaf that is `None` is the same evidence as absent; a refusal names the CONFIGURED field rather than the field that was present; rubbish DER reads no facts and the projections report what was constructed; an authentication that never happened CANNOT BE MADE CURRENT; a span within the ceiling is current and NAMES THE CONTROL THAT RAN; an inverted window is not orderable and contains nothing, and being orderable is not the same question as containing now; a self-issued certificate in the chain is exempt from the window; only the unevaluated policy applies no controls; and the defaults are the URI SAN and the channel credential.*
**If false.** A refusal says a credential was absent when it was present and refused — different facts with different operator responses — or an authentication that never happened is reported as current. 'Names the control that ran' is what makes currency a measurement rather than a verdict.
**Likely owner:** none.
**Severity:** `critical`.
**Registered in part, ADR-MCPRE-069 S1.** The certificate refusal vocabulary is `unit://proxy.certificate_identity_refusal_vocabulary` under THM-0024 (`M285`); the currency reporting clauses are `unit://proxy.credential_currency_evidence_reporting` under THM-0032 (`M286`). Three rows remain: the two DEFAULT-value clauses (which field, which provenance) are a choice between product behaviours no theorem states, and `peer_identity_provenance.rs` is in no unit's paths and no theorem's source closure. Packet at `verification/reviews/packets/adr069-np-137-ratification-2026-09-19.md`.

## NP-138 — the blocking harness parses HTTP/1 strictly and bounds its reads

**Controls:** `mcp-re-proxy/src/blocking_mtls_harness`.
**Statement.** *A bare CR in the header section, a bare LF line ending, an obs-fold continuation line, a duplicate `Content-Length` — even with the same value — and a negative one are each REJECTED; a single valid `Content-Length` parses and an absent one is a zero-length body; the aggregate deadline fires on a sub-per-read trickle; and a disabled deadline does not cut off a completing read.*
**If false.** Request smuggling: two parsers disagree about where one message ends. Rejecting a duplicate `Content-Length` WITH THE SAME VALUE is the clause that makes it strictness rather than a de-duplication convenience, and the trickle clause is the slow-loris bound NP-034 configures.
**Likely owner:** none.
**Severity:** `critical`.

## NP-139 — an unhealthy backend is ejected, probed once, and readmitted on success

**Controls:** `mcp-re-proxy/src/http_inner`.
**Statement.** *Consecutive failures trip the breaker open at the threshold and a success resets the failure run; an open backend is readmitted as a PROBE after the cooldown and closes on success, while a failed probe reopens for another cooldown; each probe claim takes a slot NO SECOND CLAIM CAN TAKE, and preparing claims the recovery probe while dropping it gives the probe back; all-open selection returns none before the cooldown and preparing refuses only while EVERY backend is ejected; a health-aware balancer skips an open backend and uses a healthy one; a held preparation consumes the in-flight bound; a closure inner reports a backend reply; and the post-commitment outcomes are distinguishable.*
**If false.** Every replica probes an unhealthy backend at once — the thundering-herd recovery — or a backend that never recovers keeps taking traffic. 'Preparing refuses only while EVERY backend is ejected' is the availability arm: one ejection must not stop the proxy.
**Likely owner:** none.
**Severity:** `high`.

## NP-140 — what a CRL-less or cadence-less deployment is actually bounded by

**Controls:** `mcp-re-proxy/src/tls_plane` (4) —
`fleet_crl_bound_tests::{a_reload_cadence_bounds_established_connections_not_only_handshakes,
without_a_cadence_the_bound_is_the_crls_own_expiry, without_a_crl_the_bound_is_the_certificate_lifetime}`,
`handle_lifetime_tests::a_snapshot_that_outlives_the_plane_still_serves`.
**Statement.** *Every deployment has a STATED bound on how long a revoked client may keep a connection it already established, and the bound is a total function of what the deployment configured: with a reload cadence it is the cadence, and it applies to ESTABLISHED connections rather than only to new handshakes; without a cadence it is the CRL's own expiry; without a CRL at all it is the client certificate's lifetime. A snapshot taken before the plane retired goes on serving under the bound in force when it was taken.*
**If false.** A revoked client keeps a connection it established before the revocation, with nothing in the handshake path able to see it — and an operator who configured no CRL is left with an unknown exposure rather than a stated one, when the truth is that the certificate lifetime bounds it.
**Likely owner:** none.
**Severity:** `critical`.
**Registered in part, ADR-MCPRE-069 S-04; split.** Three rows are registered. `handle_lifetime_tests::a_retired_plane_stops_claiming_a_cadence` is `unit://proxy.retired_plane_cadence_retraction` under THM-0131, near verbatim — *"a replica whose reload worker has died, or whose plane has retired, retracts the cadence it advertised: the maintenance verdict is latched, and no later reload can clear it"* — falsified by `M329-proxy-a-retired-plane-retracts-its-cadence`; it is its own unit rather than an addition to `proxy.client_revocation_currency` because the retirement happens in `tls_plane/mod.rs`, which is not that unit's source closure, and a unit's `paths` may not be widened to reach a control. The two `trust_epoch_binding_tests` rows are an R1 into `proxy.listener_state_assembly` under THM-0048 — *"The epoch is a function of the anchor set alone"* — needing no `paths` widening, and measured rather than assumed: neither control constructs a `TlsPlane` at all, both drive `TlsListenerSecurityState` directly. The two `custody_agreement_tests` rows were separated out as NP-177. **A correction of law, carried from this campaign's adversarial review and re-checked here against the file.** `ANALYSIS-proxy-premise.md` blocked this record on THM-0102's sentence *"that a connection is in fact closed at the configured age is an OBLIGATION this theorem names and does not establish"*. That sentence names `async_serve/connection.rs` two clauses earlier — *"The bound on a live connection's age is enforced in `async_serve/connection.rs`"* — and this record's carrier is `tls_plane/`. The blocker was matched on the concept rather than on the carrier and does not apply; what remains unregistered here is unregistered because no theorem states the bound's TOTALITY over the CRL-less and cadence-less postures, not because THM-0102 declined it. Packet at `verification/reviews/packets/adr069-np-140-np-177-ratification-2026-09-19.md`.

## NP-141 — the async core budgets bodies and frames without double counting

**Controls:** `mcp-re-proxy/src/async_serve`.
**Statement.** *The core budget admits a maximum-size body and refuses past the ceiling; absorbing a frame does not release its bytes TWICE and an abandoned body read RETURNS ITS CHARGE; a clone shares the core's bounds rather than making new ones; the handshake bound leaves workers for the rest of the core; and the origin check compares the received path and query, treats a root target as matching a root request, does not compare the configured authority, and does not check an empty configured target here.*
**If false.** A double release or a lost charge makes the body budget drift until it bounds nothing — the accounting failure that presents as a memory bound that quietly stopped existing. The clone clause is the same defect one level up: a per-core bound remade per clone is no bound at all.
**Likely owner:** none.
**Severity:** `high`.

## NP-143 — the retained Mode-C ingress verifier refuses rather than defaulting

**Controls:** `mcp-re-proxy/src/capability_materialization/ingress.rs` (4).
**Carrier:** `build_attested_ingress_binding`.
**Statement.** *A Mode-C verifier missing its audience FAILS CLOSED RATHER THAN DEFAULTING and rejects an unusable attestor key rather than DROPPING IT; it is built only for the attested-ingress binding; and the retained verifier still admits an assertion minted by its configured attestor.*
**If false.** A verifier is built with a defaulted audience, so it admits assertions minted for another node's route — or with an unusable attestor key silently dropped, so it trusts fewer attestors than configured and fails closed later, far from the configuration that caused it.
**Likely owner:** none.
**Severity:** `critical`.
**Split, ADR-MCPRE-069 S-06, under RR-002 C5.** The three `key_source::pin` rows left this record: they are two further propositions over a different carrier — NP-184 (the PIN file reader) and NP-185 (the secret string's redaction at the consumer).
**Refused, ADR-MCPRE-069 S-06 — THE CARRIER IS DORMANT, and that is the finding.** The scheduling analysis routed these four to THM-0077 as materialization refusals. They cannot go there, because no validated deployment reaches the code at all: `config_state::transport::undeployable_transport_binding_refusal` returns a refusal for `PeerIdentityEvidenceRequest::AttestedIngress` unconditionally, with no `cfg` and no configuration that turns it off, so `build_attested_ingress_binding` is retained capability rather than a deployment posture. THM-0077 quantifies over *"Every security capability held by the serving runtime"*; a capability no deployment can hold is not one of them, and attaching these rows would make the root's evidence range over code the serving runtime never executes. Whether dormant code gets a claim at all is the question NP-146's residue already puts to the owner and this record joins it rather than answering it. **Root relationship.** A premise of the proxy units above it. Packet at `verification/reviews/packets/adr069-np-123-np-143-np-147-np-148-np-184-np-185-ratification-2026-09-19.md`.

## NP-144 — an admission record is addressed by its workload and reported once

**Controls:** `mcp-re-proxy/src/redis_admission_source`.
**Statement.** *The record is addressed by THE WORKLOAD'S OWN NAME; a store writer without the signing authority produces NOTHING ADMITTED; a restored admitted record does not outlive the authorized window; every class has its own latch, a class is reported once and then suppressed, and one class being reported does not suppress another; and a key is readable by an operator.*
**If false.** An admission record is read for the wrong workload, or a restored record admits past the window it was authorized for. The per-class latches are the diagnosis argument: one noisy failure class must not silence a different one that starts later.
**Likely owner:** none.
**Severity:** `high`.
**Registered in part, ADR-MCPRE-069 S1.** The addressing and non-mintability clauses are `unit://proxy.admission_record_addressing` under THM-0129 (`M287`). The three per-class refusal-latch rows remain: report-once-per-class is diagnosis hygiene, and THM-0129 says nothing about how often a class is reported. Packet at `verification/reviews/packets/adr069-np-144-ratification-2026-09-19.md`.

## NP-145 — every correspondence refusal renders to its own operator sentence

**Controls:** `mcp-re-proxy/src/communication_assurance/credential_key_correspondence.rs` (2).
**Statement.** *Seven distinct correspondence facts render to seven distinct sentences
through `CredentialKeyCorrespondenceRefusal`'s `Display`, and an unsupported algorithm tells
the operator WHICH algorithm was given.*
**If false.** An operator reading two different incidents reads the same sentence, and
cannot tell an empty chain from an unreachable signer.
**Likely owner:** none. THM-0026 is the authority and it stops one level above the rendering:
its statement is about the returned refusal value — *"the refusal names which authority
failed — the credential side, the signing-key side, or the relation"* — a three-way
distinction, while these controls measure a seven-way one over a `String` the theorem never
mentions. Its consequence reaches the operator once, with *"an operator is told which half of
the deployment to look at"*, and naming the OID is not naming a half. A unit declaring seven
distinct sentences under a theorem that states three distinguishable refusal values would be
the registration ADR-069 §5 calls strictly worse than none.

Two other controls of this record measured the trusted-ingress facade's delegation to the
peer-identity value owner. RA3-002 deletes that facade — its callers construct
`PeerIdentityValue` directly — so both controls and `proxy.asserted_identity_delegation`
are retired with it. The third is separated as NP-187.
**Packet:** `verification/reviews/packets/adr069-np-145-np-186-np-187-ratification-2026-09-20.md`.
**Severity:** `medium`.

## NP-146 — a budget refusal is diagnosable without the reporter being able to take the tier down

**Controls:** `mcp-re-proxy/src/async_replay/budget_report.rs` (2),
`async_replay/retention_ledger.rs` (1).
**Statement.** *The line that tells an operator a refusal was a BUDGET refusal and not a store
outage is rendered OUTSIDE the ledger guard, is paced by the process while every refusal is
COUNTED IN FULL, and never panics — including on an actor name carrying control bytes.*
**If false.** The mechanism that exists to make one over-quota peer visible is the one that
fails under it: a blocking write inside the guard serialises every serving core behind a file
descriptor the proxy does not control, and a panicking write unwinds with the guard held,
poisoning the mutex so every reserve on the replica refuses for the process lifetime.
'Paced but counted in full' is the pair: suppressing output must not suppress the count.
**Likely owner:** none.
**Severity:** `high`.

**Narrowed and split, ADR-MCPRE-069 S-11, and nothing landed.** The slice's plan expected
these three appended to `proxy.async_replay_retention`, on the stated premise that *both
carrier files are already in its `paths`*. Measured, one is not: that unit's `paths` are
`mod.rs`, `bounds.rs`, `charge.rs`, `in_memory.rs`, `local_refusals.rs`, `retained_set.rs`
and `retention_ledger.rs`, and `budget_report.rs` is absent. Two of the three selectors would
be refused by `verify --manifests`, and widening the `paths` is outside this campaign's
authority. So it is not that shape, exactly as the plan said to check.

**And the third would not have landed either.** THM-0105's statement is the retention ACCOUNT
— charged first and to the principal, a share that leaves a reserve, handed back only by an
authoritative `Replay`, and *"Every refusal on this path — over budget, over ceiling, an
already-stale `retain_until`, a poisoned lock — is `Unavailable`, never `Fresh`"*. Which lock a DIAGNOSTIC is rendered outside of is not a conjunct of any of those
four, and the operational test settles it: every clause of THM-0105 holds under an
implementation that renders its line inside the guard. That the refusal happened, and that it
was `Unavailable`, is the theorem's; that an operator can tell it from a store outage without
the reporter being able to stall or poison the tier is this record's.

**One is split out under RR-002 C5.** `l1_fast_reject_never_fresh_and_evicts_fifo` is
**NP-197**: THM-0105's scope excludes it by name — *"NOTHING ABOUT THE DORMANT L1."*
**Packet:** `verification/reviews/packets/adr069-np-146-np-197-ratification-2026-09-20.md`.
## NP-147 — the automatic fleet topology is at least one shard of one worker

**Controls:** `mcp-re-proxy/src/async_fleet` (2) —
`topology_tests::{auto_is_always_at_least_one_shard_of_one_worker, auto_keeps_a_shard_per_cpu_and_adds_depth}`.
**Statement.** *Where the operator stated nothing, the automatic topology keeps a shard per CPU, adds depth on top up to the default maximum, and is never degenerate — at least one shard of one worker on any host the runtime reports.*
**If false.** A deployment that configured no topology starts with zero shards and serves nothing, or trades shards away for depth on a profile where shards are what parallelise `accept`.
**Likely owner:** none.
**Severity:** `high`.
**Registered in part, ADR-MCPRE-069 S-06.** `explicit_topology_is_never_overridden` is now `unit://proxy.fleet_topology_provenance` under **THM-0077**, falsified by `M337-proxy-an-explicit-worker-depth-is-not-capped`. THM-0077's security consequence is the clause: *"a serving component cannot disagree with the owner about what was configured."*
**The lane, determined and stated.** `async_fleet` sits behind NO feature gate: `pub mod async_fleet;` at `mcp-re-proxy/src/lib.rs:214` carries no `cfg`, nothing inside `async_fleet/mod.rs` or `core_runtime.rs` is feature-gated, and `cargo test -p mcp-re-proxy --lib -- --list` selects all three controls in the DEFAULT lane. No `test_features` is needed or declared, and the scheduling analysis's open question about this record is closed.
**Refused, ADR-MCPRE-069 S-06, for two independent reasons.** First, what the automatic path computes is a THROUGHPUT and AVAILABILITY policy — shard count against CPU count, worker depth against a measured rps envelope — and THM-0077's scope excludes exactly that: *"SECURITY POSTURE, not liveness and not permanent runtime availability."* Second, and measured rather than argued: both rows assert over `auto_for`, a helper defined INSIDE `topology_tests` that restates the policy rather than calling `resolve_topology`, so no edit to production code turns either of them red. A control that cannot be falsified by a production change is not evidence for any theorem, whichever one it is attached to. **Root relationship.** A premise of the proxy units above it. Packet at `verification/reviews/packets/adr069-np-123-np-143-np-147-np-148-np-184-np-185-ratification-2026-09-19.md`.

## NP-148 — signing-plane materialization publishes a usable key and owns one rotation worker

**Control:** `mcp-re-proxy/src/signing_plane` —
`rotation_owner_tests::materialize_publishes_a_usable_key_and_owns_one_rotation_worker`.
**Statement.** *A `materialize` that returns `Ok` leaves the hot path with a usable delegated key AND the plane owning EXACTLY ONE rotation worker.*
**If false.** The plane starts with a rotation worker nobody owns, or with two — NP-003's lifetime rule at the one plane whose worker mints keys.
**Likely owner:** none.
**Severity:** `critical`.
**Registered in part, ADR-MCPRE-069 S-06.** Two rows left this record. `materialize_refuses_when_the_root_cannot_issue_the_first_key` is an **R1** into `unit://proxy.delegated_signing_credential` under **THM-0062** — *"yields none before the first rotation"* — needing no `paths` widening, because `signing_plane/mod.rs` is already that unit's and the same refusal is already measured there at the wiring level by `failing_root_fails_closed_at_first_issuance`. `materialize_refuses_when_the_configured_shared_epoch_cannot_be_read` is `unit://proxy.signing_plane_epoch_read_refusal` under **THM-0077**, falsified by `M338-proxy-an-unreadable-kill-switch-is-not-a-label`; it is a unit of its own for a LANE reason, stated in full below.
**The reading taken on the NP-124 question, and why.** The work package asks whether this record's *owns ONE rotation worker* clause is the same lifetime family as NP-124, which is R6 — and if so, whether NP-148 should follow NP-124 out of the slice. It should not, and the tree says why. NP-124's proposition is about the shared control-plane RUNTIME in `control_runtime.rs` — *"a deployment that needs no control-plane client starts NO runtime"* and *"dropping the owner stops work a surviving handle had started"* — which is the outliving question. The signing plane's own outliving question is not open at all: `a_surviving_signer_does_not_keep_the_rotation_worker_alive`, `a_signer_that_outlives_the_plane_stops_signing` and `a_mint_completing_inside_the_drop_join_window_cannot_restore_signing` are already registered under THM-0062. What is left here is a COUNT at materialization — `worker_count() == 1` — which is ADR-MCPRE-056 §9's worker-ownership rule and is stated by no theorem. So this record stays, as one row, and it is a neighbour of NP-124 rather than a member of it: both are worker- and runtime-ownership propositions with no claim above them, and an owner settling one should settle the other in the same sitting.
**Why the whole control could not simply be registered.** Its two assertions are one symbol: a usable key published (which THM-0062 does contain, and whose twin `builds_and_first_rotate_publishes_a_snapshot` is already in that unit) and exactly one worker owned (which it does not). Registering the symbol would put the second proposition inside a battery whose theorem never states it, which ADR-MCPRE-069 §5 holds strictly worse than leaving it unregistered.
**The lane, stated.** `materialize_refuses_when_the_configured_shared_epoch_cannot_be_read` is `#[cfg(feature = "redis_replay")]`. The default lane lists 1,498 proxy lib tests and does not contain it; the `redis_replay` lane lists 1,536 and does. `proxy.delegated_signing_credential` declares no `test_features` and its own closure note already refuses the control by name for exactly that reason, and a unit's `test_features` are ONE set for the WHOLE battery — so the row could not join it without moving that whole battery into a non-default lane. Hence a separate unit. **Root relationship.** A premise of the proxy units above it. Packet at `verification/reviews/packets/adr069-np-123-np-143-np-147-np-148-np-184-np-185-ratification-2026-09-19.md`.

---

## The proxy's integration lanes — NP-149 through NP-168

The last 327 controls, in `mcp-re-proxy/tests/`. These are the COMPOSITIONS: each one takes
propositions this campaign recorded at a component's own API and establishes that the
components work together on a real serving path. That is why almost none of them could be
registered against an existing unit — a unit is the smallest authority whose source can be
fingerprinted, and a composition's source is every unit under it.

**Two of them carry a lane fact that any ratification inherits**, and it is recorded here
rather than discovered later: NP-149 runs only in the opt-in nightly cloud lane, and NP-150
only where a live Redis and etcd exist. NP-167 runs only under Bazel. Registering any of
them without saying so would put a control the merge path never executes inside a battery
the merge path checks.

## NP-149 — MCP-RE signs under a real cloud KMS key, end to end

**Controls:** `mcp-re-proxy/tests/integration_live` and its siblings.
**Statement.** *Against a real AWS or GCP KMS key: the HTTP profile serves, the delegated-required posture serves, the delegated-TLS handshake signs, delegated signing issues, and a root rotation completes — each under a key the process never holds.*
**If false.** The custody argument holds against a fixture and not against the cloud. Every unit above these is measured against an in-process signer; this is the only evidence that the same composition works where the key is somewhere else.
**The lane.** These run ONLY in the opt-in nightly `cloud-kms-live.yml` lane, which needs real cloud credentials. A unit registering them would fail the merge-path lane on every pull request — the same mechanical constraint NP-009 records, with the difference that here the lane exists and runs. Ratifying this proposition means deciding what a claim established only nightly is worth, which is exactly the question ADR-MCPRE-068's evidence classes were built to ask.
**Likely owner:** none — a composition's source is every unit under it.
**Severity:** `critical`.

## NP-150 — the external-backend tiers behave as the tier promises

**Controls:** `mcp-re-proxy/tests/integration_ext` and its siblings.
**Statement.** *Against a real Redis and a real etcd: the replay tier admits a nonce once, the continuation store establishes a leg once, the trust-epoch source turns reads into invalidation events, the cpstore endpoint serves a linearizable tier, and the OCSP path behaves as configured.*
**If false.** A tier's published guarantee (NP-121) is established against an in-memory stand-in and not against the backend that has to provide it. The stand-in cannot lose a write, and the backend can.
**The lane.** These are feature-gated lanes that need a live Redis and etcd; `cargo test --workspace` compiles them to zero tests. The property includes the lane it exists in, and a unit claiming them without that lane would report green over nothing.
**Likely owner:** none — a composition's source is every unit under it.
**Severity:** `critical`.

## NP-151 — the MRT continuation is driven correctly across replicas

**Controls:** `mcp-re-proxy/tests/integration_async/mrt_continuation_serving_test.rs` and its siblings.
**Statement.** *The stateless cross-replica continuation: an open leg is established, its handles reach the answer leg, a non-terminal reply pauses the call and a terminal one resolves it, and no replica can be made to answer a leg it did not open.*
**If false.** A continuation is answered by a replica that never saw its open leg, or an answer leg signs over handles from a different exchange. This is the serving-path composition above NP-119's store.
**Likely owner:** none — a composition's source is every unit under it.
**Severity:** `critical`.

## NP-152 — the listener's own admission, the historical identity facade's returns, and the delegated TLS handshakes

**Controls:** `mcp-re-proxy/tests/integration/tls_test.rs` (25), `mcp-re-proxy/tests/integration/mtls_transport_binding_test.rs` (3), `mcp-re-proxy/tests/fault_injection_test.rs` (2).
**Statement.** *End to end over a real listener, and over the two things that listener is built from: a client certificate that is untrusted, revoked, expired or over-long is refused during the handshake and the transport binding holds between the channel peer and the request actor, with the declared fault injector as the anti-vacuity arm; the historical `extract_identity` facade returns the configured field of a real DER leaf and returns NOTHING rather than falling back to another one; the published CRL says how close it is to falling out of force and what its own digest and dates are; and a delegated TLS listener — local, AWS-KMS-backed or GCP-KMS-backed — completes a real handshake whose CertificateVerify the delegated signer produced, and fails it when that signature is corrupted.*
**If false.** The listener admits a peer it was configured to refuse; or a deployment that configured URI SANs is silently downgraded to a Common Name by a facade the authority's own no-fallback controls do not measure; or a handshake is signed by a key the served certificate does not present. The fault-injection controls are here because a handshake refusal nobody can make fail is a refusal nobody has measured.
**Likely owner:** none — a composition's source is every unit under it.
**Severity:** `critical`.
**Registered in part, ADR-MCPRE-069 CO-S3-5.** Three of this record's original thirty-three rows are now `tested_symbols`. Two join `unit://proxy.delegated_resolver_materialization` under **THM-0027** — `validated_delegated_build_rejects_cert_signer_key_mismatch` and `validated_delegated_build_rejects_non_ed25519_leaf`, which enter the correspondence gate at `TlsListenerSecurityState::build_delegated_config`, the published entrance the scope names: *"Within the API this crate publishes, delegated-resolver materialization has no route that bypasses the validated correspondence gate."* Every `lib#` name already in that battery reaches the gate from inside the crate. One joins `unit://proxy.client_crl_next_update_gate` under **THM-0131** — `crl_freshness_rejects_malformed_der`, the arm where both existing controls are blind because both mint a CRL that parses: a classifier answering `Fresh` for undecodable DER installs a document demonstrably inside no window, which is the negation of *"installable only when every one of them is inside its own `nextUpdate` window and states one at all."* A new probe, `M357-proxy-an-undecodable-crl-is-not-a-fresh-one`, demonstrates it red.
**The eleven certificate-identity rows are refused because their carrier decides nothing.** The slice's analysis called `transport::extract_identity` a *"SECOND production implementation"* of THM-0024's proposition; it is a five-statement delegation whose own doc says it *"owns nothing. It parses no certificate, selects no field, validates no value, and decides no fallback."* Its `Option` return collapses all four of the authority's refusals into `None`, so THM-0024's *"Present-but-uninterpretable is never reported as absent"* is unobservable through it — the exact reason `certificate_identity_no_fallback_test.rs` was written against `interpret_identity` instead. THM-0080's scope names this suite and declines it: *"the historical extractor is a published API with its own X.509 conformance suite over real DER … What can be held is that the SERVING PATHS do not take it, which is a call-site fact."* The proposition is **NP-078**, already refused R6 on `origin/main`.
**The two KMS delegated-build rows are refused because THM-0027 already quantifies over them.** Both are the landed pair's test with the signer swapped for a KMS backend, and both select ZERO tests in the default lane, so they could not join that unit's battery in any case. CO-S3-4 ruled the identical shape for the PKCS#11 TLS signer one slice earlier. The analysis's justification — *"Same shape THM-0116 scope already blesses"* — names the RESPONSE signer's theorem, which CO-S3-4 measured does not reach the TLS handshake signer.
**`crl_freshness_classifies_fresh_near_and_stale` is refused because its warn band is claimed nowhere.** `Fresh` and `NearExpiry` are both ADMITTED by `require_in_force`; folding the two together would turn the control red while THM-0131 stays true and every deployment installs the same CRLs. Its sibling landed; the two are separate propositions, so C5 forbade filing them as one.
**Packet:** [`verification/reviews/packets/adr069-np-152-ratification-2026-09-20.md`](../../verification/reviews/packets/adr069-np-152-ratification-2026-09-20.md).

## NP-153 — the startup transcript is what the deployment actually did

**Controls:** 21 — `app_startup_characterization_test` (8), `config_refusal_precedence_test` (5), `startup_transcript::normalize_tests` (5), `documented_cli_test` (2), `config_legality_characterization_test` (1). All in `mcp-re-proxy/tests/integration`, all in the default lane.
**Statement.** *Over a real startup: a refusal precedence is stable and names the first thing wrong rather than merely refusing; the startup-transcript normalizer reads every state-carrying seam in both directions and fails rather than guessing; the authorization seam declares both of its postures; the documented sidecar command line is a configuration the proxy will start with; and the boundary's recommended replay backend is not a state the next stage will start.*
**If false.** An operator reads a transcript that describes a deployment other than the one running, or follows a remedy the next stage refuses. This is the composition above NP-004, NP-123 and the argv family: each of those says a posture is stated; this says the statement is true of this process.
**Likely owner:** none — a composition's source is every unit under it.
**Severity:** `critical`.

**Registered in part (ADR-MCPRE-069 CO-S3-6).** Fifteen of this record's original thirty-six rows left it as attached evidence and are no longer dispositions: the layer-A legality rows into `proxy.client_credential_window` (THM-0102), `proxy.delegated_signing_configuration_state`, `proxy.transport_binding_and_crl_state` and `proxy.legality_boundary_totality` (THM-0077), the root-key endpoint row into `proxy.kms_endpoint_authority` (THM-0089, whose statement names the validation boundary as one of the decision's three consumers), the tier/reload transcript pair's surviving half into `proxy.trust_posture_declaration` (THM-0100), and the three unestablishable-capability refusals into a new unit, `proxy.unestablishable_capability_refusal`, added to THM-0077's `supported_by`. No theorem fingerprint field moved.

**Six rows were examined and REFUSED, and the reasons are not interchangeable.**

* **Two rows reach a classifier whose theorem declines the conjunct they carry.** `a_programmatic_config_cannot_carry_a_dangling_custody_or_ingress_selector` and `a_programmatic_config_cannot_carry_a_deny_list_nothing_enforces` decide in `config_state/cross_machine.rs`, under THM-0049, whose `scope` says in terms: *"It does not establish that the classifier is consulted on every startup path."* Both rows reach X2a and X6 through the boundary's clause list, which is not in that unit's closure, and deleting the list's entry turns them red while THM-0049 stays true.
* **Two rows are owned by units that carry no theorem.** `a_programmatic_config_cannot_carry_a_decision_scope_that_selects_nothing` decides in `config_state/authorization.rs`, whose unit `proxy.authorization_configuration_state` is theorem-less; `a_deployment_can_install_the_authorization_authority_and_the_transcript_declares_it` and its OFF twin are decided by `authorization::capability::evaluator`, whose unit `proxy.authorization_capability` is theorem-less and `critical`. Attaching to a theorem-less unit attaches to nothing.
* **One row asserts a presentation adjacency no theorem states.** `a_push_tier_without_an_event_source_is_qualified_where_it_is_declared` asserts `emits_in_order(tier, caveat)` — *the caveat must follow the claim it weakens*. THM-0100 states the arithmetic the line prints, not where the qualification sits, and that is the same clause-3 shape as the refusal-ORDER rows still in this record.

Packet: [`../../verification/reviews/packets/adr069-np-153-ratification-2026-09-20.md`](../../verification/reviews/packets/adr069-np-153-ratification-2026-09-20.md).

## NP-154 — the shipped auditor over a served archive, and the retention posture the serving path refuses under

**Controls:** `mcp-re-proxy/tests/integration_async/transparency_e2e_test.rs` (15).
**Statement.** *Over a real exchange, and then over the archive it left behind: a deployment that turned retention on refuses what it cannot account for and one that did not keeps nothing; the shipped `mcp-re-auditor` turns a served call into a portable attestation and refuses — writing nothing — an archive it cannot reconstruct, a tampered object or an illegal service pin; and that attestation registers with a transparency service over either of two mechanisms, hermetically, and against a live external one when a deployment opts in.*
**If false.** The answerability record and the exchange diverge on the live path, which is where they are relied on; or the shipped auditor attests a record it should refuse, which is worse than refusing one it should attest, because the artifact is the thing a third party reads.
**Likely owner:** none — a composition's source is every unit under it.
**Severity:** `critical`.
**Registered in part, ADR-MCPRE-069 CO-S3-3.** Two of this record's original seventeen rows are now `tested_symbols` of `unit://proxy.retention_commitment` under **THM-0088**, falsified by `M354-proxy-the-pre-dispatch-reserve-is-skipped`, demonstrated red. They are `a_retention_store_that_cannot_accept_the_call_refuses_before_the_backend_runs` — *"A publication taken before the exchange may dispatch"*, asserted by COUNTING inner dispatches rather than inferred from a status — and `a_retention_failure_after_execution_is_indeterminate_and_leaves_its_reservation`, which observes both stage names on disk in order: *"only `commit_to_dispatch` advances it to `<digest>.pending`, and it advances by RENAMING"*.
**The lane is not the one the slice's analysis named, and that was measured rather than assumed.** `transparency_e2e_test.rs` carries no `#![cfg(feature = "async_serve")]` — six of its siblings in the same binary do — and `--test integration_async -- --list` reports all 23 of its controls with and without the feature. The battery is default-lane, so `proxy.retention_commitment` correctly declares no `test_features`.
**The fifteen that remain are FOUR propositions, not one, and no ratified theorem contains them.** Three are the fail-closed serving posture — a 503 and its frozen code, a deployment with no store at all, and the serving constructor's writability proof. THM-0088's scope hands all three away: *"It says nothing about which HTTP refusal each failure earns — that is the serving owner's, under THM-0078"*, and *"It is about WHEN responsibility was accepted and crossed, never about WHAT the retained record contains"*. Six drive the shipped BINARY, and THM-0113 excludes them in terms: *"NOT A CLAIM THAT THE CHAIN IS COMPLETE OR THAT ITS HOPS VERIFY. The `ChainLabel` reports that, and this theorem's content is that the label reaches the caller rather than that it says a particular thing"*, and *"the audit posture is the auditor's to choose"*. A CLI's refusal-and-output contract is an externally meaningful promise about a deliverable, which is a new claim rather than a decomposition of one. Five more are registration, which THM-0113 excludes by name — *"NOT A CLAIM ABOUT THE TRANSPARENCY SERVICE. Registration, inclusion proofs and the receipt a service returns are outside this seam entirely"* — and whose two mechanism leaves are in no `supported_by` list. The last is the live external lane, which returns early with `SKIPPED and therefore MEASURED NOTHING` whenever `MCP_RE_LIVE_TRANSPARENCY_SERVICE` is unset, so on every merge-path run it passes having asserted nothing; ADR-MCPRE-068 N4 forbids choosing `tested` to make it fit.
**Packet:** [`verification/reviews/packets/adr069-np-154-ratification-2026-09-20.md`](../../verification/reviews/packets/adr069-np-154-ratification-2026-09-20.md).

## NP-155 — the delegated client-server composition works end to end

**Controls:** `mcp-re-proxy/tests/integration_async/delegated_client_server_e2e_test.rs` (14);
`mcp-re-proxy/tests/integration_async/delegated_serving_test.rs` (4) —
`a_notification_is_served_a_verifiable_delegated_202`,
`the_client_cores_own_notification_envelope_earns_a_202`,
`the_client_facing_crate_can_verify_the_202_the_server_emits`,
`direct_root_response_rejected_in_delegated_required_mode`;
`mcp-re-proxy/tests/integration_async/mtls_client_leg_e2e_test.rs` (3).
**Statement.** *A real client, a real proxy and a real backend over delegated signing and mTLS: the request is signed, the response is verified as bound to it, the delegated credential chains to a trusted root, the root manifest's publication and revocation govern the round trip, and an accepted notification is answered with a signed bodyless 202 both ends agree on.*
**If false.** Every delegated-path unit is established over a component; this is the only evidence that the components compose. It is the proxy-side twin of NP-009 — and unlike NP-009, this one does run.
**Likely owner:** none — a composition's source is every unit under it.
**Severity:** `critical`.
**Lane, corrected.** This record said the controls run "in the Bazel `async_serve` lane".
Measured at ADR-MCPRE-069 CO-S3-2: `cargo test -p mcp-re-proxy --test integration_async --
--list` selects 167 tests and `--features async_serve` selects 197, and every control this
record has ever held is in BOTH listings. They run in the plain default cargo lane as well,
and every registration taken off this record declares no `test_features` for that reason.
The claim was not false about Bazel; it was silent about the lane that also runs them, which
is the form that makes a feature-gated battery look measured when it is not.
**Root relationship.** Eight of the record's twenty-nine rows left in ADR-MCPRE-069 CO-S3-2,
registered as evidence under THM-0045, THM-0062, THM-0069, THM-0070 and THM-0075 in
`proxy.dispatch_commitment`, `proxy.delegated_signing_credential`,
`proxy.audit_authority_coordinates`, `proxy.audit_delivery` and `proxy.response_signing`.
`delegated_required_wiring_serves_verifies_and_rotates` is cited by TWO units — the serving
and bound-rejection halves under THM-0075, the expiry and rotation halves under THM-0062 —
because one control asserting four properties is evidence for two propositions, and splitting
the control would have measured neither half in the order the wiring imposes. M355 and M356
name it for its two conjuncts separately, so the double citation is measured twice.

What is left here is three propositions and one residue, and the residue was examined and
refused rather than deferred.

`direct_root_response_rejected_in_delegated_required_mode` never constructs a proxy. It
builds a pre-052 direct-root response from a test-only fixture and asserts that
`mcp_re_http_profile::Verifier::verify_delegated_bound_response` returns
`DelegationCredentialMissing` — a claim about the VERIFIER, whose production carrier is in
`mcp-re-http-profile` and in no path of the proxy-side signer unit the analysis proposed for
it. THM-0062's scope excludes it in terms: *"The credential's existence, not its content: it
does not establish that the credential chains to the deployment's root, that its scope is
right, or that a verifier will accept it."* A verifier's acceptance is the axis the theorem
wrote down that it does not reach. The row stays, and the candidate direction —
THM-0076 and the http-profile verification units — is recorded in the packet rather than
acted on here.

The three signed-202 rows stay together and stay whole. The EMISSION half is inside
THM-0075 — a signed 202 is signed response evidence, produced by the delegated capability
and bound to the notification it acknowledges — but the controls do not measure only that
half. Each asserts the wire contract: status 202, a bodyless response, and the credential in
a covered `mcp-re-delegation` HEADER rather than in the body's evidence block. THM-0075's
scope declines that subject in terms — *"SECURITY-BEARING SIGNED evidence only. Unsigned
transport and error responses exist ... and they are outside this claim, which is why it does
not say every response carries evidence."* A theorem that deliberately does not say WHICH
responses carry evidence does not contain a claim fixing it for the notification class, so
clause 2 fails; and *an accepted notification is answered with a signed bodyless 202* is an
externally meaningful promise between two ends, settled by the #424 owner ruling, so clause 3
fails independently. `the_client_cores_own_notification_envelope_earns_a_202` fails a third
way: it asserts that `mcp_re_client_core::build_signed_notification`'s PRODUCER and the
proxy's classifier agree on the absence of `id`, a cross-crate correspondence whose client
half is THM-0125's and whose server half no theorem states.

The fourteen `delegated_client_server_e2e_test` rows that remain are the manifest, issuer-pin
and revocation round trips, blocked behind NP-009, plus the two audit-surface rows CO-S3-2 did
not reach.

## NP-156 — the inner-backend health machinery works under a real serving load

**Controls:** `mcp-re-proxy/tests/integration_async/http_inner_test.rs` and its siblings.
**Statement.** *Over a real inner backend: ejection, cooldown, single-probe recovery and health-aware selection behave as NP-139 describes, under concurrent serving rather than at the unit's API.*
**If false.** The breaker is correct in isolation and wrong under concurrency — which is the only condition it exists for.
**Likely owner:** none — a composition's source is every unit under it.
**Severity:** `high`.

## NP-157 — the replay tier admits a nonce once under contention

**Controls:** `mcp-re-proxy/tests/integration_async/replay_race_harness_test.rs` and its siblings.
**Statement.** *Under a deliberate race: concurrent presentations of one nonce yield exactly one admission, and the async tier's accounting survives the contention.*
**If false.** A replay is admitted because two workers checked before either recorded. NP-120 establishes the store's semantics; this establishes that the serving path uses them in a way the race cannot defeat.
**Likely owner:** none — a composition's source is every unit under it.
**Severity:** `critical`.

## NP-158 — the projected token file is the pod's only credential, and it is read fresh

**Controls:** `mcp-re-proxy/tests/aws_irsa_web_identity_test.rs` (3).
**Statement.** *The projected token is re-read from its mount on EVERY exchange rather than captured at construction, so a `kubelet` rewrite in place is picked up; and where the mount cannot supply one — the file is gone, or it exists and is still empty — the exchange is refused with nothing posted and nothing substituted, never falling back to whatever ambient AWS credentials the process environment happens to hold.*
**If false.** Either the pod keeps presenting a projected token STS has stopped accepting, and the failure reads as an IAM problem; or, worse, a missing mount silently promotes the process environment to the credential source, so the proxy signs under an identity nobody granted it for this workload.
**Likely owner:** none — a composition's source is every unit under it.
**Severity:** `critical`.
**Registered in part, ADR-MCPRE-069 S-10.** Six of this record's original twelve rows are now `unit://proxy.aws_web_identity_credential_exchange` under **THM-0117**, falsified by `M345-proxy-the-refresh-margin-is-dropped-from-the-cache-hit`. Three more are NP-193.
**These three are not, and the reason is where the statement begins.** THM-0117 is about *"A credential acquired from AWS STS or from the GCE/GKE metadata server"* — the projected web-identity token is the INPUT to that acquisition, not the credential acquired by it. The one place the scope mentions it is about destination and nothing else: *"WHERE THE TOKEN IS SENT is a conjunct of the AWS unit and not of the metadata one: a projected web-identity token handed to a re-pointed STS endpoint is a credential leak, and it is refused at construction."* Where the token is READ FROM, how often, and what happens when the mount is empty are a different authority, and it is the one that decides whether this pod's credentials are the workload's at all.
**Packet:** `verification/reviews/packets/adr069-np-158-ratification-2026-09-20.md`.

## NP-159 — which roots a verifier admits, at each instant of a rotation

**Controls:** `mcp-re-proxy/tests/integration_async/root_key_lifecycle_test.rs` (9).
**Statement.** *Across a root rotation driven through the same issuer seam a KMS root plugs into: a credential under the current root is accepted; during the overlap BOTH roots are accepted and after it the old root is rejected while the new one is accepted; the retirement window's boundary is inclusive and then closes; an unknown issuer is rejected and an EMPTY trust-anchor set trusts no root at all; revoking one root leaves the other undisturbed, a revoked root fails closed with its split seam gone, and a revoked issuer invalidates every descendant before that descendant's own `exp`.*
**If false.** A rotation leaves a window in which nothing verifies, or the old root stays acceptable after it was meant to be withdrawn — the two failure directions of every key rotation. The revocation half is the sharper one: a descendant that outlives its revoked issuer is a credential the ceremony believes it withdrew.
**Likely owner:** none — a composition's source is every unit under it.
**Severity:** `critical`.
**Registered in part, ADR-MCPRE-069 S-10.** One of this record's original eleven rows — `root_issuance_failure_serves_until_delegated_key_expiry_then_fails_closed` — joins `unit://proxy.delegated_signing_credential`'s battery under **THM-0062**, whose statement contains it verbatim: *"An issuance failure serves the still-valid key and then fails closed at its expiry rather than extending it, and the retry schedule never sleeps past a still-valid key."* A second is NP-194.
**THE QUESTION `PKT-COMPOSITION` §11.3 LEFT OPEN IS CLOSED HERE, AND THE ANSWER IS NO.** It asked whether the rotation ceremony is `http_profile.delegated_signing_custody`'s authority, so that the other ten rows could land with it. Three independent measurements say it is not.

*First, that unit carries no ratified theorem at all.* It is one of the twenty units no `[[theorem]]` names as `owner` or in `supported_by` — the count this campaign holds at 20. Clause 2 of the subsumption test requires a proposition *already contained in the ratified theorem's claim*, and there is no claim. Registering here would mean minting a theorem, which is outside every slice's authority.

*Second, the unit's declared proposition is the opposite axis.* Its description reads, in full: *"The delegated-signing credential lifecycle: the root is never touched within a key's life, a successor is minted in the overlap window and under an advanced trust epoch, a signature window never outlives the credential it was issued under, and an issuance that fails after expiry fails closed rather than continuing on the predecessor."* Every clause is about the DELEGATED key under a root held fixed — the first one says so in terms. These ten rows change the root. The carrier's own header states the same division: *"The complement to the delegated-KEY lifecycle: a delegated key rotates every few minutes under ONE root (the hot path, covered elsewhere); this proves the RARE, high-stakes ceremony of rotating the ROOT the whole fleet chains to."*

*Third, the lane could not run it.* That unit's `paths` are four files under `mcp-re-http-profile/src/custody/`, so `test_package_for` resolves to `mcp-re-http-profile`, and a `tests/integration_async#` selector names a `mcp-re-proxy` target that package does not have. The battery would refuse to start. This is the weakest of the three reasons and is recorded last on purpose: a mechanical refusal is not a judgement, and the judgement is the second reason.

**And no other ratified theorem takes them either.** The verification side of all ten is `mcp_re_client_core::verify_delegated_response` against a `TrustedIssuerSet`. The nearest statement is THM-0057, whose scope is *"Establishes what the document says and for how long."* — the manifest as a document, at rest, and not which roots a live exchange is admitted under at each instant of a ceremony; its owner's paths are in `mcp-re-client-core`, so the same package refusal applies. The question does not need asking a third time.
**Packet:** `verification/reviews/packets/adr069-np-159-np-194-ratification-2026-09-20.md`.

## NP-160 — a presented admission assertion is authentic and bound to the caller presenting it

**Controls:** `mcp-re-proxy/tests/integration_async/admission_currency_serving_test.rs` (3) —
`an_assertion_from_an_untrusted_authority_is_refused`,
`an_assertion_issued_to_another_actor_does_not_admit_this_caller`,
`a_binding_naming_another_workload_does_not_borrow_its_admission`.
**Statement.** *An admission assertion the CALLER presents admits only where it was issued by an
authority this deployment enrolled for admission, was issued to this caller, and names a binding
this caller can hold.*
**If false.** A borrowed or foreign-signed assertion admits its holder, so §7 measures the
presenter's copy of somebody else's admission.
**Likely owner:** none — a composition's source is every unit under it.
**Severity:** `critical`.
**Root relationship.** The record's other seven rows left in ADR-MCPRE-069 S-09/CO-S1; this is what
is left, and it is the half THM-0129 excludes in terms. Four rows are now registered evidence under
THM-0129 in `proxy.admission_state_source`, and three became NP-188, NP-189 and NP-190 because they
are three further propositions rather than this one. THM-0129's ratified scope refuses these three
by name: *"Says nothing about the assertion the CALLER presents (ASM-0012), nor about whether the
call matches the state — that is THM-0004."* The nearest claim is THM-0006 (presenter binding),
whose owner is `http_profile.admission_currency`, a PROVED unit whose battery is a Verus
specification and not a place a serving-path integration control can join without substituting a
probe class. Packet at
`verification/reviews/packets/adr069-np-160-np-188-np-189-np-190-ratification-2026-09-20.md`.

## NP-161 — dispatch carries the request the caller signed, unchanged

**Controls:** `mcp-re-proxy/tests/integration/http_profile_dispatch_test.rs` (1) —
`http_profile_request_flows_verify_dispatch_serve_end_to_end`;
`mcp-re-proxy/tests/integration_async/forwarded_body_fidelity_test.rs` (3);
`mcp-re-proxy/tests/integration_async/rfc9421_round_trip_test.rs` (2) —
`replayed_request_is_rejected`, `rfc9421_round_trip_zero_object_evidence`.
**Statement.** *Over a real dispatch: the body forwarded to the backend is the body the signature covered, byte for byte; an RFC 9421 round trip through the proxy verifies at both ends; a second presentation of the same signed request is rejected on the async serving path; and the wire carries no legacy object-profile evidence.*
**If false.** The proxy forwards something other than what it verified, so the backend acts on bytes no signature covered. NP-088 says the composer does not rewrite; this says the forwarder does not either.
**Likely owner:** none — a composition's source is every unit under it.
**Severity:** `critical`.
**Root relationship.** The record's other seven rows left in ADR-MCPRE-069 CO-S3-1: all seven are
now registered evidence under THM-0092 in `proxy.replay_admission_gate`, as the integration twins of
conjuncts that unit's description already carried, and three of them are named in M139's `expect_red`
so the added lane is measured rather than listed. What is left here is three separate propositions,
and one of them was examined and refused rather than deferred.
`replayed_request_is_rejected` is a positive replay DETECTION on the async serving path, and no
ratified theorem contains it. THM-0092's scope declines the direction in terms — *"It is
one-directional and is not a liveness claim: it says an unestablished replay state does not dispatch,
never that an established one does"* — and the refusal here is not that an unestablished state failed
to dispatch but that an ALREADY-established one was recognised, which is the other proposition.
THM-0079 states *"a key admitted once is reported as a replay thereafter"*, and its scope then
excludes exactly what this control adds: *"It does not establish that the cache is consulted on every
path reaching dispatch."* Driving `HttpProfileProxy::handle` twice establishes that consultation, so
joining THM-0079's owner would make a battery claim what that theorem wrote down that it does not.
THM-0086 is *"CONFIGURATION PROJECTION ONLY"* and reaches no request. The row stays.

## NP-162 — a configuration reachback and hot reload change what is served and nothing else

**Controls:** `mcp-re-proxy/tests/integration/plane_config_reachback_test.rs` and its siblings.
**Statement.** *A plane's configuration reachback answers from the configuration in force, and a hot reload swaps it without disturbing exchanges already in flight.*
**If false.** An in-flight exchange is decided half under each configuration — NP-127's failure on the live path — or a reachback reports a configuration that is not the one serving.
**Likely owner:** none — a composition's source is every unit under it.
**Severity:** `high`.

## NP-163 — the SDK's authorization producer builds what this enforcement point accepts and cannot build what it refuses

**Controls:** `mcp-re-proxy/tests/integration_async/pdp_authorization_serving_test.rs` (2) —
`a_decision_attached_through_the_sdk_producer_is_authorized_end_to_end`,
`the_sdk_producer_cannot_build_the_half_pair_this_pep_refuses`.
**Statement.** *The decision block `mcp_re_client_core`'s producer emits is authorized end to end by
this enforcement point, and the half-pair the enforcement point refuses cannot be built by that
producer at all.*
**If false.** The shipped producer and the shipped enforcement point disagree about what a decision
binding is, so either a well-formed client is refused or a client can build a shape the PEP has to
reject at serving time.
**Likely owner:** none — a composition's source is every unit under it.
**Severity:** `critical`.
**Root relationship.** The record's other five rows left in ADR-MCPRE-069 S-09/CO-S1: four are now
registered evidence under THM-0069 in `proxy.audit_authority_coordinates`, and one became NP-191.
This residue is refused for two independent reasons and needs only the first. THE PRODUCER IS IN
ANOTHER CRATE: the proposition is about `mcp-re-client-core`'s `build_authorization` and
`build_signed_request`, which is in no proxy unit's `paths`, and a unit's `paths` may not be widened
to reach a control. And THM-0040 excludes the second row's subject in terms — *"The reference
binding form produces no authorization at all and is outside this claim"* — so the construction this
control proves impossible is one the theorem already declines to reason about. Packet at
`verification/reviews/packets/adr069-np-163-np-191-ratification-2026-09-20.md`.

## NP-164 — the file and dev key sources' own load and refusal behaviour, and the PKCS#11 token's second key

**Controls:** `mcp-re-proxy/tests/key_source_test.rs` (6), `mcp-re-proxy/tests/dev_env_key_source_test.rs` (4), `mcp-re-proxy/tests/pkcs11_keysource_e2e_test.rs` (5).
**Statement.** *Each source opened DIRECTLY, not through the materializer: the file source loads the signing seed, the channel credential and the client anchors and tells a missing file from a malformed seed; the dev-only environment source does the same without mutating the process and scrubs its seed temporaries; neither source's error carries the secret; and the token's SECOND object — the delegated TLS handshake key — is established at `open` or the deployment does not start.*
**If false.** A source reports material it did not load, or names the wrong failure, and an operator debugs the wrong half of a deployment; or a secret seed reaches a log through an error value; or the proxy serves a handshake under a token key nobody established, which is the one case where the delegated-TLS correspondence gate compares a key the signer did not actually sign with.
**Likely owner:** none — a composition's source is every unit under it.
**Severity:** `critical`.
**Registered in part, ADR-MCPRE-069 CO-S3-4.** One of this record's original sixteen rows is now a `tested_symbol` of `unit://proxy.pkcs11_adapter` under **THM-0116**: `pkcs11_sign_verifies_against_token_public_key`, the ANTI-VACUITY half of the emit guard and the only control in that unit's battery taken over a real, dynamically loaded Cryptoki surface. THM-0116's statement contains it in terms — *"Every signature the adapter produces is verified against that advertised public key, with the deployment's own verifier, before it is returned."* — and the unit's lane already is the control's: `test_features = ["pkcs11_keysource"]`, measured at 6 selected with the feature and **0** without.
**The three file-source rows are refused because no ratified theorem claims what a key source LOADS.** THM-0082 was the proposed home and it refuses them in its own scope: *"`FileKeySource` and the KMS adapters are public constructors, as external embedders need, so a root that opened one beside it would compile."* These three controls construct `FileKeySource` literally — the struct with four public path fields — so they exercise precisely the route THM-0082 names as the DEFECT it measures against, never the materializer whose use is its claim. THM-0064, the other candidate, excludes the custody class by name: *"it establishes nothing about a deployment that selects file custody, which is `ProcessReadable` and honestly says so."* The carrier is `mcp-re-proxy/src/key_source.rs`, which is in no unit's `paths`, and not `capability_materialization/key_source/**` as the slice's analysis recorded.
**The five delegated-TLS rows are refused because THM-0116 is the RESPONSE signer's theorem.** Its statement opens *"Each non-exporting response signer — AWS KMS, GCP Cloud KMS, PKCS#11 — establishes the key it advertises BEFORE it will sign anything"*, and THM-0073 is the registry's own authority for the two roles being different things: *"the response-signing role and the channel-signing role resolve to the same cryptographic signing-key identity"* is the condition it REFUSES. `Pkcs11TlsSigner::open` proves a second, differently labelled token object exists, is Ed25519 and is UNAMBIGUOUS; no theorem states any of that, and the ambiguity rule — two objects under one label — is stated nowhere in the registry at all. Two of the five are excluded a second time by THM-0116's own scope: *"NOT A CUSTODY CLAIM. That the private key never leaves the KMS or the token is the provider's property and the trait's shape"* and *"NOT A PROTOCOL-CONFORMANCE CLAIM."*
**Packet:** [`verification/reviews/packets/adr069-np-164-ratification-2026-09-20.md`](../../verification/reviews/packets/adr069-np-164-ratification-2026-09-20.md).

## NP-166 — the verified-context carrier is attached only where the inner channel is trusted

**Controls:** `mcp-re-proxy/tests/integration_async/verified_context_carrier_test.rs` and its siblings.
**Statement.** *Over a real exchange: the verified-context carrier reaches the backend only when the inner channel is trusted, and carries exactly what was verified.*
**If false.** A backend receives a verified-context assertion over a channel that did not earn it, and treats a claim MCP-RE made about itself as one it can rely on.
**Likely owner:** none — a composition's source is every unit under it.
**Severity:** `critical`.

## NP-167 — the async drain is bounded and ordered

**Controls:** `mcp-re-proxy/tests/async_drain_test.rs` and its siblings.
**Statement.** *Teardown drains in-flight work within a bound, in the documented order, and nothing is accepted after the drain begins.*
**If false.** A shutdown either hangs on work that never completes or abandons work that had been accepted. Only the Bazel lane runs this file — it is `#![cfg(feature = "async_serve")]` and `cargo test --workspace` compiles it to zero tests — which is a fact any ratification inherits.
**Likely owner:** none — a composition's source is every unit under it.
**Severity:** `critical`.

---

## NP-169 — the server-authentication control is load-bearing

**Controls:** `mcp-re-transport/tests/fault_injection_test.rs` (2) —
`fault_accept_any_server_makes_untrusted_server_cert_accepted`,
`fault_accept_any_server_makes_wrong_identity_server_cert_accepted`.
**Carrier:** the client transport's server verifier, under the `fault_accept_any_server`
feature.
**Statement.** *With the server-authentication control deliberately broken, an untrusted
server certificate and a wrong-identity one are ACCEPTED — so the rejections
`client.transport_server_identity` claims are the real verifier's work and not an artefact
of a test that never presented a bad certificate.*
**If false.** The three rejections that unit claims pass for a reason other than the
verifier — a harness that never completes a handshake would produce them too — and the whole
unit is vacuous while reading as `critical` evidence.
**Likely owner:** `client.transport_server_identity`, **and it cannot claim them.** This is a
sixth mechanically impossible registration, of a kind the others did not show:

> A unit's `test_features` are ONE set for the WHOLE battery, and an anti-vacuity control
> whose purpose is to FALSIFY the property cannot live in the same battery as the property.

`fault_injection_test.rs` compiles only under `fault_accept_any_server`, which is off by
default and never in the normal build; without it the target reports ZERO tests, which is
the false green this repository has a gate for. Declaring the feature on the unit would run
the whole battery under it, and `untrusted_server_cert_is_rejected` — the control the feature
exists to break — would fail. Measured, not reasoned: the registration was written, the
target was run, and it reported `0 passed; 0 filtered out`.
**Root relationship.** Under the client transport roots, beside the unit whose vacuity it
refuses.
**Severity:** `critical`.
**What ratification would look like:** a separate unit over the same carrier declaring
`test_features = ["fault_accept_any_server"]`, whose battery is these two controls and
nothing else — which is what "one `test_features` set per battery" makes the only shape
available.

## NP-174 — the client posture line reports the floor the deployment actually has

**Controls:** `mcp-re-client/src/main.rs` (2).
**Carrier:** `mcp-re-client/src/main.rs` — the startup posture line.
**Statement.** *The startup posture line reports the bootstrap the floor actually has, and
reports whether the floor is bounded upward.*
**If false.** An operator reads a posture line describing a floor the process is not running
under, so the transcript and the deployment disagree about the one fact the line exists to
state.
**Likely owner:** none. `mcp-re-client/src/main.rs` is in no unit's `paths` and is listed in
`config/unit-closure-exclusions.toml`.
**Root relationship.** A premise of the units above it.
**Severity:** `high`.

## NP-175 — a client nonce clears the 128-bit emission floor

**Controls:** `mcp-re-client/src/lib.rs` (1).
**Carrier:** `mcp-re-client/src/lib.rs` — the client's nonce emission.
**Statement.** *A nonce the client emits clears the 128-bit emission floor.*
**If false.** The client emits a nonce with less entropy than the freshness argument assumes,
so replay protection is weaker than every consumer of it believes.
**Likely owner:** none. `mcp-re-client/src/lib.rs` is in no unit's `paths` and is listed in
`config/unit-closure-exclusions.toml`.
**Root relationship.** A premise of the units above it.
**Severity:** `high`.

## NP-176 — the startup posture state answers enabled without reparsing the line

**Controls:** `mcp-re-proxy/src/startup_posture.rs` (2) —
`one_startups_declarations_do_not_satisfy_another`,
`state_answers_enabled_without_parsing_the_line`.
**Carrier:** `mcp-re-proxy/src/startup_posture.rs` — the posture state itself.
**Statement.** *One startup's declarations do not satisfy another's completeness check, and
the posture state answers whether a seam is enabled from its own representation rather than
by parsing the rendered transcript line.*
**If false.** A reader asking "is this seam on" gets its answer by re-deriving it from the
text a different authority produced, so the state and the transcript are two representations
of one fact that can disagree — and a completeness check satisfied by another startup's
declarations would pass for a run that declared nothing.
**Likely owner:** `proxy.continuation_materialization`. The file is already in that unit's
`paths` and five of its `startup_posture` symbols are already in its battery, so this is an
R1 candidate needing no `paths` widening.
**Root relationship.** Under THM-0096 — *but THM-0096's scope narrows the conjunct these two
controls sit beside, in its own words*:

> THE DECLARATION CONJUNCT IS CLAIMED AT THE STRENGTH ITS EVIDENCE HAS, which is less than
> it first appears. `PostureLog::assert_complete` proves that every executed startup states
> each seam exactly once, and it is NEVER REACHED hermetically — the posture phase sits after
> the replay tier is established, and every tier validation accepts needs a live Redis or etcd.
> What the registered evidence establishes is therefore two weaker facts: that the completeness
> check refuses an undeclared or doubly-declared seam when it is run, and that the continuation
> seam is declared exactly once in the composition root's SOURCE. "The path actually taken
> reached exactly one declaration" is not claimed by this theorem in any hermetic lane.

If the owner reads either control as outside that narrowed conjunct, this record stays
unregistered rather than being absorbed. That reading is the owner's and this record does not
take it.
**Severity:** `medium`.
**Why this record exists at all.** These two controls were filed under NP-004, *every optional
capability states ON or OFF, in every lane*, whose remaining control is
`scripts/seam_posture_gate.py` — a repo-wide backstop carrying the quantifier over all eight
seams, in no unit's `paths`, and genuinely referred. One record cannot be both landable and
referred: NP-004's own `likely_owner` field said its owner "owns ONE seam's conjunct and says
so", which is the record documenting its own split.

## NP-177 — the TLS plane refuses a key source that disagrees with the declared channel custody

**Controls:** `mcp-re-proxy/src/tls_plane` (2) —
`custody_agreement_tests::{a_key_source_that_disagrees_with_the_declared_custody_refuses,
agreeing_custody_passes_the_check_and_fails_on_something_else}`.
**Carrier:** `mcp-re-proxy/src/tls_plane/mod.rs` — the one place the REQUESTED custody and the
ESTABLISHED custody meet.
**Statement.** *A deployment configured for delegated handshake custody and handed an exported
key materializes NO TLS plane, and the refusal names both sides; and agreement is not refused —
an agreeing pair passes this check and fails later, on something else, so the diagnostic proves
which check ran.*
**If false.** The deployment serves handshakes under weaker custody than its own transcript
claims. Nothing else compares these two facts: layer A classifies the custody from the TLS key
selectors, the key source produces an actual signer, and every startup line reports the
DECLARED custody — so a divergence is invisible in exactly the place an operator looks.
**Likely owner:** none.
**Severity:** `critical`, carried from NP-140 rather than reassessed.
**Root relationship.** A premise of the proxy units above it. Neither custody theorem contains
it. THM-0064 is about the CLASSIFIER — *"The custody owner classifies each legal selection into
exactly one state carrying the material that made it inhabitable, and projects a single semantic
fact"* — and its scope says it establishes *"what the classified STATE asserts, not that the
remote signer implementation honours it"*; a plane handed a key source contradicting the state
falsifies neither. THM-0073 is the comparison between the two SIGNING ROLES' materialized public
keys, a different relation over different values. THM-0082 is the nearest in spirit — *"A
deployment cannot announce one signing custody at startup and sign with another on the data
plane"* — but it is the RESPONSE-signing composition root, *"the counterpart of THM-0066 on the
signing side"*, and this is the channel. Packet at
`verification/reviews/packets/adr069-np-140-np-177-ratification-2026-09-19.md`.
**Why this record exists at all.** It was two rows of NP-140, *the TLS plane republishes its own
epoch and bounds established connections*, whose epoch half is now registered and whose
remaining rows are the fleet-CRL bound. Custody agreement is neither, and one record describing
three authorities is the defect RR-002 C5 names.

## NP-178 — revocation is conjunctive across authorities, and a source outage fails closed

**Controls:** `mcp-re-proxy/src/trust_plane` (2) —
`live_trust::tests::{revocation_source_outage_fails_closed,
second_revocation_authority_rejects_even_when_key_status_active}`.
**Carrier:** `mcp-re-proxy/src/trust_plane/live_trust.rs`.
**Statement.** *A second revocation authority's rejection stands even where the key status is
active — the two authorities COMPOSE rather than being alternatives — and an outage of a
revocation source fails closed rather than resolving to "not revoked".*
**If false.** A revoked key keeps verifying for as long as the revocation source stays down,
which is exactly when an attacker would want it down; and the weaker authority's silence
overrides the stronger authority's rejection, which is the composition defect this repository
has ruled on before — two mechanisms that COMPOSE must not be read as alternatives.
**Likely owner:** none.
**Severity:** `critical`, carried from NP-134 rather than reassessed.
**Root relationship.** A premise of the proxy units above it. THM-0097 states what a resolver
may ANSWER under one snapshot and one cache; it says nothing about how many revocation
authorities are consulted or how their answers combine, and `proxy.trust_resolution_window`
already carries the single-authority outage case as `live_trust::tests::store_outage_fails_closed_never_active`.
The conjunctive-composition clause is a claim about the ALGEBRA over two authorities and is
stated nowhere. Packet at
`verification/reviews/packets/adr069-np-134-np-178-np-179-np-180-ratification-2026-09-19.md`.
**Why this record exists at all.** It was two rows of NP-134, whose remaining rows are the
cache's degradation behaviour. Revocation-authority composition is a different authority in the
twelve-questions sense, and filing them together was hiding that.

## NP-179 — the trust window in force is the strictest applicable one, and a long one is flagged

**Controls:** `mcp-re-proxy/src/trust_plane` (2) —
`window_policy::tests::{strictest_applicable_t_picks_the_tightest_window,
t_exceeds_recommended_max_flags_long_windows}`.
**Carrier:** `mcp-re-proxy/src/trust_plane/window_policy.rs` — in no unit's `paths`, and listed
in `config/unit-closure-exclusions.toml`.
**Statement.** *Where several window rules apply, the one in force is the TIGHTEST of them; and
a configured window past the recommended maximum is flagged rather than silently accepted.*
**If false.** A deployment matching two rules is served under the looser one, so the revocation
window an operator computed from the stricter rule is not the window in force. The flag clause
is the operator-facing half: a window nobody objected to reads as a window somebody approved.
**Likely owner:** none.
**Severity:** `critical`, carried from NP-134 rather than reassessed.
**Root relationship.** A premise of the proxy units above it, and a premise in the strict sense.
THM-0097's arithmetic takes `T` as given — *"The deadline is the cache's clock reading at first
caching plus the declared window `T`"* — so how `T` is DERIVED from the applicable rules is an
input to that claim rather than a decomposition of it, and `t_exceeds_recommended_max` is an
advisory about the deployment's choice rather than a statement about what is served. Packet at
`verification/reviews/packets/adr069-np-134-np-178-np-179-np-180-ratification-2026-09-19.md`.
**Why this record exists at all.** It was two rows of NP-134. Selecting the window and honouring
the window are two authorities, and this campaign's own prepared analysis read these two rows as
landing under THM-0097 on the strength of the word "window" appearing in both.

## NP-180 — the only window rule production can construct is the identity

**Control:** `mcp-re-proxy/src/trust_plane` —
`window_policy::tests::the_only_input_production_can_build_makes_the_rule_the_identity`.
**Carrier:** `mcp-re-proxy/src/trust_plane/window_policy.rs`.
**Statement.** *Over the inputs production can actually build, the window rule is the identity:
no reachable construction produces a rule that moves a window at all.*
**If false.** The rule's other branches are reachable from somewhere, and a window an operator
configured is transformed before it is applied — the transformation being invisible precisely
because the ordinary path never takes it.
**Likely owner:** none.
**Severity:** `critical`, carried from NP-134 rather than reassessed.
**Evidence class.** `structural`, NOT `tested`, and this is the reason the row is its own record.
It is a *possession is the proof* statement about which inputs a constructor admits — ADR-MCPRE-068
§4.1 classes that `structural`, whose falsifier is a COMPILE REFUSAL over the illegal
construction, not a `mutation://` weakening of a runtime branch. ADR-MCPRE-068 N4 forbids
substituting one probe class for another, so sweeping this row into a `tested` unit beside its
two `window_policy` file-mates would have registered it under evidence that cannot falsify it.
A passing `cargo check` witnesses no seal: the owner adopting this record owes a hostile refusal
probe naming the construction that must not compile.
**Root relationship.** A premise of the proxy units above it. No theorem states the
constructibility of a window rule. Packet at
`verification/reviews/packets/adr069-np-134-np-178-np-179-np-180-ratification-2026-09-19.md`.

## NP-184 — the PIN file reader refuses a group-readable file and an empty one

**Controls:** `mcp-re-proxy/src/capability_materialization/key_source/pin.rs` (2) —
`tests::{a_group_readable_pin_file_is_refused, the_pin_file_reader_trims_a_trailing_newline_and_refuses_an_empty_file}`.
**Statement.** *A PKCS#11 User PIN read from a file is refused when the file is readable by
anyone but its owner, and the reader trims a trailing newline and refuses an empty file rather
than presenting the empty string as a PIN.*
**If false.** The credential that unlocks the token holding the response-signing key sits on
disk readable by every account in the file's group, and nothing at startup says so — or a file
containing only a newline is presented to the token as a PIN and the refusal an operator sees
is the token's, at a layer that cannot name the file.
**Likely owner:** none.
**Severity:** `critical`, carried from NP-143 rather than reassessed.
**Root relationship.** A premise of the proxy units above it. No theorem states the file MODE a
credential on disk must have. THM-0077 is the nearest and does not reach it: its subject is the
deployment POSTURE an owner selected, and a PIN file's permission bits are a custody fact about
the host rather than a posture anyone selected — nothing in the statement, the consequence or
the scope quantifies over what the filesystem says. Split out of NP-143 under RR-002 C5 in
ADR-MCPRE-069 S-06. Packet at
`verification/reviews/packets/adr069-np-123-np-143-np-147-np-148-np-184-np-185-ratification-2026-09-19.md`.

## NP-185 — a secret string prints neither its value nor its length at the consumer

**Control:** `mcp-re-proxy/src/capability_materialization/key_source/pin.rs` —
`tests::a_secret_string_does_not_print_its_value_or_length`.
**Statement.** *A secret string rendered at the point it is CONSUMED discloses neither its value
nor its length.*
**If false.** The PIN's length reaches an operator transcript and the log pipeline behind it,
which is a materially smaller search space for the credential that unlocks the signing token.
'Or its length' is the clause that makes redaction a rule rather than a habit.
**Likely owner:** `proxy.operator_facing_redaction` owns this subject — and cannot take this row.
**Severity:** `critical`, carried from NP-143 rather than reassessed.
**Root relationship.** A premise of the proxy units above it, and the reattribution that looks
obvious is refused twice over. `proxy.operator_facing_redaction` states exactly this proposition,
but over `deployment_request/secret_string.rs` and `inner_backend_display.rs`; this control's
source is `capability_materialization/key_source/pin.rs`, which is not in that unit's `paths`, and
a unit's `paths` may not be widened to reach a control. That unit's own closure note already says
so, by name: `capability_materialization::key_source::pin` *"asserts the same property at the
CONSUMER and is deliberately NOT named: its source is not in this unit's `paths`, so citing it
would be the SF-1 defect"*. And it would close nothing if it could — `proxy.operator_facing_redaction`
is itself one of the twenty units no theorem supports, so an R1 there is a re-filing and not a
discharge. No theorem in the estate claims redaction. Split out of NP-143 under RR-002 C5 in
ADR-MCPRE-069 S-06. Packet at
`verification/reviews/packets/adr069-np-123-np-143-np-147-np-148-np-184-np-185-ratification-2026-09-19.md`.

## NP-188 — an admission call whose generation does not match the authoritative state is refused on the serving path

**Control:** `mcp-re-proxy/tests/integration_async/admission_currency_serving_test.rs` —
`a_generation_ahead_of_the_authority_is_refused`.
**Statement.** *The currency rule is EQUALITY and not "at least": a call claiming an admission
generation the authority has not issued is refused, not treated as a fresher client.*
**If false.** A caller can admit itself by naming a generation nobody published.
**Likely owner:** none — THM-0129's scope assigns the call/state comparison to THM-0004.
**Severity:** `critical`.
**Root relationship.** Split out of NP-160 under RR-002 C5 in ADR-MCPRE-069 S-09/CO-S1, because it
is a different proposition from the four that landed and from the three NP-160 keeps. Its four
siblings are about what the authoritative STATE is; this is about whether the CALL matches it, and
THM-0129 draws exactly that line: *"Says nothing about the assertion the CALLER presents (ASM-0012),
nor about whether the call matches the state — that is THM-0004."* THM-0004's owner is
`http_profile.admission_currency`, whose evidence class is `proved`; joining a serving-path
integration control to a Verus battery is the probe-class substitution ADR-MCPRE-068 N4 forbids.
Packet at
`verification/reviews/packets/adr069-np-160-np-188-np-189-np-190-ratification-2026-09-20.md`.

## NP-189 — admission is not authorization

**Control:** `mcp-re-proxy/tests/integration_async/admission_currency_serving_test.rs` —
`an_admitted_workload_is_still_refused_by_a_denying_policy`.
**Statement.** *A caller admitted on every axis §7 measures is still refused by a denying policy,
before the backend runs, and the refusal carries the POLICY's token rather than admission's.*
**If false.** The strongest admission statement a deployment can make is read as an application
authority it never granted.
**Likely owner:** none — the nearest unit, `proxy.authorization_capability`, carries no theorem.
**Severity:** `critical`.
**Root relationship.** Split out of NP-160 under RR-002 C5 in ADR-MCPRE-069 S-09/CO-S1. It sits in
the admission carrier and is not an admission proposition: nothing in THM-0129 mentions policy, and
the theorem that does — THM-0040 — is about a PDP DECISION's relation to a request, while this
control drives an ADR-MCPRE-065 Slice 1 evaluator. The unit that holds the Slice 1 serving battery,
`proxy.authorization_capability`, is one of the twenty units no theorem supports, so registering
there would be a re-filing dressed as a discharge. Packet at
`verification/reviews/packets/adr069-np-160-np-188-np-189-np-190-ratification-2026-09-20.md`.

## NP-190 — cross-replica admission-revocation propagation is measured against the declared bound

**Control:** `mcp-re-proxy/tests/admission_propagation_measure_test.rs` —
`a_revocation_reaches_a_sibling_replica_within_the_declared_p_bound`.
**Statement.** *A revocation written to the shared store becomes visible to a replica that performed
it within the declared P bound, and the interval is measured and printed.*
**If false.** The declared propagation bound is a number nobody has ever observed the mechanism
meet.
**Likely owner:** none — a propagation-delay measurement is on an axis no theorem here claims.
**Severity:** `critical`.
**Root relationship.** Split out of NP-160 under RR-002 C5 in ADR-MCPRE-069 S-09/CO-S1, and refused
twice over. THE AXIS: what it asserts is a wall-clock interval against `DECLARED_P_MS`, and
THM-0129 — the only theorem over authoritative admission state — disclaims that axis in two words,
*"AVAILABILITY is not claimed."* Registering it would widen a ratified claim along a
latency/propagation axis, which is the one widening this slice may not make. THE LANE: the control
is `#![cfg(feature = "redis_replay")]` AND returns early with a `SKIP` line when
`MCP_RE_TEST_REDIS_URL` is unset, so in every lane this repository runs by default it reports
success having measured nothing. A registered member that green-passes without executing is the
false green this project has a gate against; it is not evidence and must not be recorded as some.
Packet at
`verification/reviews/packets/adr069-np-160-np-188-np-189-np-190-ratification-2026-09-20.md`.

## NP-191 — enforcing the transport contract does not change which action is authorized

**Control:** `mcp-re-proxy/tests/integration_async/authorization_serving_test.rs` —
`enforcing_the_transport_contract_does_not_change_which_action_is_authorized`.
**Statement.** *Law A-1 as a measurement: with the MCP transport contract enforced a self-
contradictory request is refused before any policy runs, and with it unconstrained the policy sees
the SIGNED BODY's action — never the header's, in either configuration.*
**If false.** Turning an unrelated consistency policy on or off silently changes which action a
deployment authorizes.
**Likely owner:** none — the nearest unit, `proxy.authorization_capability`, carries no theorem.
**Severity:** `critical`.
**Root relationship.** Split out of NP-163 under RR-002 C5 in ADR-MCPRE-069 S-09/CO-S1. The
sentence that looks like its home is THM-0040's — *"the decided operation equals the operation the
SIGNED BODY named"* — and it is not one: THM-0040 is a claim about `PdpDecisionEvaluator::evaluate`
and an authenticated PDP decision, while this control drives an ADR-MCPRE-065 Slice 1 policy with no
decision document at all. The Slice 1 serving battery lives in `proxy.authorization_capability`,
which no theorem supports, so an R1 there closes nothing. Packet at
`verification/reviews/packets/adr069-np-163-np-191-ratification-2026-09-20.md`.

## NP-187 — the legacy and authority identity vocabularies convert field for field

**Controls:** `mcp-re-proxy/src/facades/asserted_identity.rs` (1).
**Statement.** *`IdentityPolicy -> CertificateIdentityPolicy` and
`CertificateIdentitySource -> IdentitySource` are enumerated in both directions and neither
drops nor reassigns a case.*
**If false.** A deployment that configured URI SANs is pointed at another certificate field
by the conversion, before the interpreter is ever asked — the silent downgrade THM-0024's
consequence names, arriving one step upstream of everything THM-0024 quantifies over.
**Likely owner:** none, and the gap is structural rather than accidental. THM-0024 takes the
policy as an INPUT: *"Interpretation is total and deterministic over the interpreted field
set and the policy."* Every clause of its statement is conditioned on *the field the policy
configures*, so a conversion that produces the WRONG policy satisfies the theorem exactly
and violates the deployment's intent. THM-0023 is about the value, not the field.

This is the sharpest thing this slice measured that it could not land: a critical-shaped
premise sitting immediately above a `critical` theorem, unclaimed because the theorem begins
after it.
**Packet:** `verification/reviews/packets/adr069-np-145-np-186-np-187-ratification-2026-09-20.md`.
**Severity:** `high`.

## NP-192 — the bearer credential is left in no second place after it is read

**Control:** `mcp-re-proxy/src/gcp_kms_keysource.rs` — `tests::the_access_token_is_moved_out_of_the_parsed_document`.
**Carrier:** `take_access_token`, asserted over the parsed `serde_json::Value` after the read.
**Statement.** *The access token is MOVED out of the parsed metadata response, so the document is left holding no copy of it — reading it out by cloning would leave the `Value`'s own owned `String` to drop unscrubbed.*
**If false.** A second copy of a credential that authorizes Cloud KMS `asymmetricSign` on the root key sits in freed heap for the process lifetime, where a core dump or a heap-reading defect reaches it. The credential still works; nothing observable changes; and that is what makes it a residency defect rather than a lifetime one.
**Likely owner:** none, and the reason is a scope sentence rather than an omission. THM-0117 governs this exact file and this exact function's caller, and its scope is *"THE LIFETIME, NOT THE CREDENTIAL'S POWER."* — where a copy of the credential RESIDES is neither. Its companion clause, *"NOT A CLAIM ABOUT THE ISSUER."*, points the same way: everything the theorem establishes is about reading an answer, not about what is left behind afterwards. `proxy.aws_sts_credentials`, the theorem's own owner unit, has no counterpart control, so there is not even a twin to argue from.
**Root relationship.** A premise of the proxy units above it. No theorem in this tree states a memory-residency property for secret material.
**Packet:** `verification/reviews/packets/adr069-np-192-ratification-2026-09-20.md`.
**Severity:** `high`.

## NP-193 — an IRSA deployment's misconfiguration is refused at the earliest point and named

**Controls:** `mcp-re-proxy/tests/aws_irsa_web_identity_test.rs` (3).
**Statement.** *A pod that is not under IRSA is told WHICH variable is missing, one at a time, rather than being handed a generic failure; an empty `AWS_ROLE_ARN` is refused at construction rather than posted as a blank role; and an STS rejection fails closed carrying the status, the role it was refused for and the provider's own code.*
**If false.** A deployment misconfiguration presents as an opaque signing failure at the first request instead of a named refusal at startup, and the operator debugging it cannot tell an unbound role from an absent token mount from a genuine STS outage.
**Likely owner:** none. Two of the three are excluded by THM-0117's scope in terms: *"Nothing here is about what the credential is permitted to do, which role it assumes, or whether the assumed role is least-privileged."* A blank role and a rejection naming the role are both about the role. The third is operator-facing prose about the process environment, and the theorem states no rendering clause at all — its nearest control, `each_missing_credential_field_is_named`, is about the STS response document and not about a deployment's variables.
**Root relationship.** The composition above the component propositions this campaign recorded. This is the same axis as NP-123's OFF-line prose and NP-145's rendering agreement, both of which this campaign referred, and it is referred for the same reason: what a refusal TELLS an operator is an operator-facing product promise, not a decomposition of the security claim the refusal enforces.
**Packet:** `verification/reviews/packets/adr069-np-193-ratification-2026-09-20.md`.
**Severity:** `high`.

## NP-194 — a root rotation is carried by a signed manifest over roots no human created

**Control:** `mcp-re-proxy/tests/integration_async/root_authority_manifest_test.rs` — `root_rotation_via_signed_manifest_with_auto_provisioned_roots`.
**Carrier:** `common::run_rotation_scenario`, driven by an `InMemoryTestRootAuthorityProvider` and an org manifest-signing key.
**Statement.** *A root-authority PROVIDER mints the successor root on the fly with no human or console step; an org-signed trust-anchor manifest carries the rotation A → A+B → B and then A's revocation; credentials verify and reject exactly per that manifest; and a rolled-back manifest is refused.*
**If false.** Either the rotation needs a human to create a root — which is the operational failure the auto-provisioning path exists to remove, and the point at which a root's private material passes through somebody's hands — or the document governing which roots are trusted can be replaced by an older one, so a revocation is undone by replaying the manifest that predates it.
**Likely owner:** none, and it is a different authority from NP-159's, which is why it is split out of it. NP-159 is about which roots a verifier ADMITS at each instant; this is about the higher authority that decides the set — an org key a serving proxy cannot forge, a version floor, and a provider that mints roots. THM-0057 states the document half — *"Anchors are released only from a manifest whose signature verified under a trusted signer kid that the signature itself covers"* — but its scope stops at the document: *"Establishes what the document says and for how long."* It says nothing about a provider that creates the root the document then names, and its owner's paths are in `mcp-re-client-core`, so this `mcp-re-proxy` integration target is outside the lane that would run it.
**Root relationship.** The composition above the component propositions this campaign recorded.
**Packet:** `verification/reviews/packets/adr069-np-159-np-194-ratification-2026-09-20.md`.
**Severity:** `critical`.

## NP-195 — an unbound deployment says not-claimed rather than asserting a channel binding

**Control:** `mcp-re-proxy/src/authorization/request.rs::an_unbound_deployment_says_not_claimed_rather_than_asserting_a_binding`.
**Statement.** *An authorization request composed on a deployment that binds no channel
carries NO channel binding, rather than a value a policy could read as one.*
**If false.** A policy conditioned on the channel a request arrived over is handed a binding
the deployment never established, so a condition an operator wrote to be restrictive is
satisfied by a deployment that cannot satisfy it.
**Likely owner:** none.
**Root relationship.** Split out of NP-132 under RR-002 C5 in ADR-MCPRE-069 S-11. It is not
the refusal-token proposition NP-132 states, and THM-0040 — the theorem over the file's own
unit — excludes the subject by name in its scope: *"It is authorization, and not admission,
authentication, channel binding or transport identity."* That is an exclusion of the topic,
not a silence about it, so no decomposition of THM-0040 reaches it.
**Severity:** `high`.
**Packet:** `verification/reviews/packets/adr069-np-132-np-195-np-196-ratification-2026-09-20.md`.

## NP-196 — the authorization-authority seam is populated separately from the request-signer seam

**Control:** `mcp-re-proxy/src/authorization/pdp/policy.rs::a_resolver_that_trusts_nobody_is_a_deployment_that_authorizes_nothing`.
**Statement.** *A `PdpDecisionPolicy` whose authority resolver answers for no kid is a
deployment that authorizes nothing: the authorization-authority seam is not populated by
whatever the request-signer seam happens to trust.*
**If false.** A deployment that enrolled no authorization authority silently inherits the
request-signer trust set, so a key trusted to SIGN a request becomes a key trusted to ISSUE
the decision that authorizes it — the two seams collapsed into one.
**Likely owner:** none.
**Root relationship.** Split out of NP-132 under RR-002 C5 in ADR-MCPRE-069 S-11. THM-0039
is about a decision that verified *"under the key the AUTHORIZATION trust seam resolved"* and
says in its scope *"It does not establish that the authority SHOULD be trusted — only that
the seam answered for that kid, which is the deployment's configuration speaking rather than
this claim."* THM-0040 consumes that and states relevance. Neither states that the seam is
populated separately from the signer's, which is what this control is about, and it is a
different question from every refusal token NP-132 enumerates.
**Severity:** `high`.
**Packet:** `verification/reviews/packets/adr069-np-132-np-195-np-196-ratification-2026-09-20.md`.

## NP-197 — the dormant L1 fast reject is never fresh and evicts FIFO

**Control:** `mcp-re-proxy/src/async_replay/l1_fast_reject.rs::l1_fast_reject_never_fresh_and_evicts_fifo`.
**Statement.** *`L1FastRejectStore` never answers `Fresh` — it refuses or defers, never
admits — and it evicts in FIFO order.*
**If false.** A tier fronted by an L1 that could answer `Fresh` would admit a nonce the
authoritative store never saw, which is an unrecorded nonce and therefore a replayable one.
**Likely owner:** none.
**Root relationship.** Split out of NP-146 under RR-002 C5 in ADR-MCPRE-069 S-11. THM-0105
excludes it by name and explains the exclusion: *"NOTHING ABOUT THE DORMANT L1.
`L1FastRejectStore` is defined and DORMANT — `app.rs` installs the L2 directly on every
backend, nothing outside `async_replay_test` constructs an L1, and no configuration surface
selects one."* It adds *"The L1's own never-`Fresh` invariant stays a documented property of
dormant code, claimed by nothing."* This record is that documented property, held where the register
can see it, and it stays a proposition for exactly as long as the code stays dormant.
**Severity:** `high`.
**Packet:** `verification/reviews/packets/adr069-np-146-np-197-ratification-2026-09-20.md`.
