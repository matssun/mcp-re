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

**Covers:** `semantic_altitude_gate.py`, `lifecycle_purity_gate.py`.
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

**What would move a control out.** A demonstration that a violation admits, emits or signs
something the system does not today. `semantic_altitude_gate` is the likelier of the two:
if a sibling field is ever READ on a path that decides anything, the proposition stops being
about shape and the disposition becomes `new-proposition`.

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
`doc#verified_request::VerifiedMcpRequest`.
**Recorded:** 2026-09-19, ADR-MCPRE-069 Phase 069-B batch 8.

Four `compile_fail` examples over three items, each a hostile construction the type system
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
**Carrier:** the `p256` dependency edge, the SCITT receipt verifier's modules, and
`mcp-re-core`'s `ensure_ed25519_alg`.
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

**Control:** `scripts/owned_worker_gate.py`.
**Carrier:** `managed_worker/mod.rs` and every library source in the workspace, the
`sdk/python` and `sdk/typescript` native bindings included.
**Statement.** *No production source outside `managed_worker` starts an OS thread except at
the reviewed sites, so every long-lived worker's lifetime is represented by an owned value.*
**If false.** A bare `thread::spawn` whose `JoinHandle` is dropped outlives every value it
was conceptually part of: nothing can stop it and nothing can observe that it stopped. This
is the historical defect, not a hypothetical — startup had four, each looping on a SIGTERM
flag no error path sets, so a `run` that failed after the first spawn returned `Err` with
threads still reading files and minting keys. The fourth was found by accident, days after a
survey that swept one file and concluded there were three.
**Likely owner:** a new unit over `managed_worker`.
**Root relationship.** ADR-MCPRE-056 §9. Bears on the lifecycle roots — a recorded terminal
`Stopped` that leaves threads minting keys is the thing THM-0012 is about — without being
what THM-0012 states.
**Severity:** `high`.
**What the control does NOT establish, and the record says so:** that no detached runtime
worker exists. A helper that wraps the spawn, a type alias, a `tokio::spawn`, or a thread
started inside a dependency all pass it. The real enforcement is that runtime-owned work goes
through `WorkerSet`; the gate makes the common bypass loud. Any ratification inherits that
limit rather than quietly dropping it.

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

## NP-009 — the shipped adapter's end-to-end composition, and the lane that does not run it

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

**Controls:** `sdk/typescript/test/parity.test.ts` (3), `sdk/python/tests/test_parity.py` (3).
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

## NP-019 — the correlation store's peek and take split

**Controls:** `sdk/python/tests/test_correlation.py::TestRecordAndTake::test_peek_does_not_consume`,
`::test_take_consumes_the_outstanding_request`.
**Carrier:** `correlation.py`'s `peek` and `take`.
**Statement.** *Peeking an outstanding request never retires it, and taking it retires it
exactly once.*
**If false.** Either a peek retires an entry — so a legitimate answer that arrives
afterwards is refused as unbound — or a take does not, so one reply can be answered twice.
Both are reachable by a peer that controls when replies arrive.
**Likely owner:** `sdk_python.correlation_lifecycle`. It was tempting to register
`test_take_consumes_the_outstanding_request` there alone, as the mechanism of its
outstanding-entry clause, and that is exactly the half-registration ADR-069 D2 is about: the
proposition is the SPLIT, and half of it is not a weaker version of it but a different claim.
The proxy side holds the same proposition whole —
`proxy.continuation_correlation_store` registers
`peek_does_not_consume_and_consume_is_one_shot` as one control — which is the form this
should take.
**Root relationship.** Under THM-0094.
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

`mcp-re-proxy/src/cli.rs` holds **142 controls and is in no unit's `paths`.** It is the
single largest unclaimed carrier in the repository, and its controls are not incidental:
*a zero timeout is refused because it disables the slow-loris defense*, *attested ingress
without pinned mTLS fails closed*, *the default build rejects the AWS KMS key source*, *a
plaintext KMS endpoint to a remote host is refused*, *an argv PKCS#11 PIN is refused with
the replacement named*.

**It is invisible to the adjacent authority as well.** `scripts/unit_closure_gate.py`
registers files the module tree REACHES from a measured unit; `cli.rs` is declared by a
crate root no unit names, so it is not reached, and its production half is outside that
register too. That is ADR-MCPRE-061's question and is referred there rather than answered
here — but it is worth recording that two registers disagree about nothing, because neither
can see this file.

**Why these are propositions and not registrations.** The `config_state::*` units are
carefully scoped to a CLASSIFIER at its own API — `proxy.cross_machine_legality` says so in
terms: *"Every relation reads classified owner states rather than RAW REQUEST FIELDS."* The
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

**Controls:** `mcp-re-proxy/src/cli.rs` (11).
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

**Controls:** `mcp-re-proxy/src/cli.rs` (30).
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

## NP-028 — admission is off unless an argv names a complete enforcing configuration

**Controls:** `mcp-re-proxy/src/cli.rs` (12).
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

**Controls:** `mcp-re-proxy/src/cli.rs` (20).
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

**Controls:** `mcp-re-proxy/src/cli.rs` (11).
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

**Controls:** `mcp-re-proxy/src/cli.rs` (14).
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

**Controls:** `mcp-re-proxy/src/cli.rs` (9).
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

**Controls:** `mcp-re-proxy/src/cli.rs` (4).
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

**Controls:** `mcp-re-proxy/src/cli.rs` (6).
**Carrier:** `mcp-re-proxy/src/cli.rs` — the argv boundary.
**Likely owner:** none. Its `config_state::*` neighbour owns the CLASSIFICATION of the same subject and explicitly does not own raw request fields.
**Root relationship:** THM-0077 — *no deployment serves a posture nobody selected* — is the root above this family, and the command line is where a posture is selected.
**Severity:** `high`.

*The serving target an argv names binds something: an empty or missing target
URI is refused, a target that binds nothing is refused at the validation boundary, an inner
HTTP URL is present and has no empty segment, repeated and comma-separated URLs accumulate,
and a fleet-wide target does not erase the per-core default.* If false, the proxy serves an
endpoint nobody named, or silently drops one an operator did name.

## NP-036 — the shared production-half definition is exact

**Controls:** `mcp-re-test-paths/src/rust_source.rs` (13),
`mcp-re-test-paths/src/rust_source/brace_scan.rs` (6).
**Carrier:** `mcp-re-test-paths`'s `production_half` and its brace scanner.
**Statement.** *A brace inside a string, a char literal, a nested block comment or a raw
string does not close a `#[cfg(test)]` region; a raw string closes only on its own hash
count; an identifier ending in `r` opens none; a lifetime is not a char literal; line
numbers survive the elision; a trailing test module does not end the scan; and a file with
no tests is wholly production.*
**If false.** Every consumer of `production_half` measures a different corpus from the one
it says it measured — `scripts/module_size_gate.py`'s production-line count, the guards that
scan production text, and `conformance.verdict_vocabulary_scope`'s measured scope. This is
not hypothetical: the rule's own documentation records that counting "lines before the first
test module" discarded production code below the tests and measured `trust_plane.rs` at 134
lines when it is 690.
**Likely owner:** `conformance.verdict_vocabulary_scope` names these files in its `paths`,
so its fingerprint already moves when they change — **and it cannot claim these controls.**
It is a `measured` unit, and ADR-MCPRE-068 §4.1 gives a measured unit one apparatus slot,
`measurement_control`, whose meaning is *the demonstration that the number can still MOVE*.
MSR-0001 carries such a control. These are a different thing: a scanner that is wrong in a
fixed way still moves. **The `measured` class has no slot for apparatus CORRECTNESS**, and
that is the finding, not a reason to file these anywhere convenient.
**Root relationship.** Beneath the measured unit rather than beside it: the scope of a
measurement is a premise of the measurement, and this is the scope's own correctness.
**Severity:** `high`.
**What ratification would probably look like:** a `tested` sibling unit over the apparatus,
which the measured unit depends on — not a widening of the measured unit, and not a
`measurement_control` this is not.

## NP-037 — a guard's inputs resolve, or the guard fails loudly

**Controls:** `mcp-re-test-paths/src/lib.rs` (4), `src/source_trees.rs` (3),
`src/traceability_sources.rs` (2).
**Carrier:** `mcp-re-test-paths`'s binary/fixture resolver and its three declaration tables.
**Statement.** *An unknown key is refused rather than resolved to an empty path; no key is
declared twice; no binary key is also a source fallback; and every declared fallback,
sentinel and witness names a file that exists.*
**If false.** A guard resolves its input to an empty path, walks nothing, finds nothing and
reports a clean tree. That is the exact false-green class this repository has already
measured twice — a `tests/` glob that silently exempted a crate from the srcs gate for a
whole campaign, and an empty join that read as a clean tree — and the resolver is where the
first of those enters.
**Likely owner:** none. The resolver is in no unit's `paths`; the tables it holds decide
what several guards see.
**Root relationship.** Not under a product root. It is a premise of the guards, in the same
place NP-036 sits.
**Severity:** `high`.

## NP-038 — a revoked root's resolver is not obtainable

**Control:** `mcp-re-client-core` `doc#delegated_trust::DelegatedResponseTrust` — two
`compile_fail` examples.
**Carrier:** `mcp-re-client-core/src/delegated_trust/mod.rs`'s `TrustedIssuerSet`.
**Statement.** *`TrustedIssuerSet` hands out no response resolver and exposes no raw
lifecycle lookup, so the pairing that made verifying under a REVOKED root possible — a
resolver beside a foreign or empty revocation source, composed through
`CompositeResponseTrust` — is not expressible. What remains public is `resolve_issuer`,
which fails closed on a revoked issuer without consulting the caller's revocation half at
all.*
**If false.** A client verifies a response under a root that has been revoked, because the
two halves of the trust answer were obtained separately and only one of them knew about the
revocation. The file's own documentation says it: *two doors had to close, not one.*
**Likely owner:** `client.trust_manifest_lifecycle` names this file in its `paths` and owns
*which credential identifiers are revoked*. That is the FACT; this is the
unconstructibility of a pairing that would route around it — a different and stronger
claim, and registering the examples against the revocation clause would make that unit's
evidence cover a seal its statement does not assert.
**Root relationship.** Under the client response-trust roots.
**Severity:** `critical`.
**This is ADR-MCPRE-069 §2.1's own named instance.** That section predicted these two
examples exist and are claimed by nothing, and used them to argue the first census was
structurally blind to a whole control kind. They are still unclaimed on main.
**And the ratification is NOT a doctest registration.** ND-010 records why a
`compile_fail` example cannot attribute its refusal on the pinned stable toolchain. The
form this should take is a `structural://` probe pair, exactly as ADR-MCPRE-068 Phase 0B
did for the http-profile items: one probe per door, each naming the rustc error code the
boundary earns — `E0599` for the withdrawn resolver and `E0624` for the `pub(crate)`
lifecycle lookup — rather than a `test://` URI over an example that passes on any
compile error at all.

---

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

## NP-048 — the retention store enforces the record contract at the storage boundary

**Controls:** `mcp-re-proxy/src/transparency/durability.rs::only_the_signed_headers_are_retained`,
`::a_record_without_the_schema_token_is_refused`,
`::a_retained_exchange_comes_back_byte_identical`,
`mcp-re-proxy/src/transparency/retained_archive.rs::an_object_that_is_not_a_retained_record_is_refused`.
**Carrier:** `transparency/durability.rs` and `transparency/retained_archive.rs`.
**Statement.** *What the store writes and what the archive accepts obey the retained-record
contract: only the headers the signature base names are retained, a record without the
schema token is refused, a retained exchange comes back byte-identical, and an object that
is not a retained record is refused at the archive.*
**If false.** The record contract holds where a record is ENCODED and not where it is
STORED — so a live credential reaches the store, or a record the encoder would refuse is
read back as one.
**Likely owner:** `proxy.retained_record_content` states this contract, **and it cannot
claim these controls.** `verify --manifests` refuses a `lib#` selector whose module is not
under that unit's `paths`, for a reason this campaign agrees with: *an in-crate test whose
source the unit does not measure can be rewritten under the same name without moving the
fingerprint.* Widening its `paths` to reach `durability.rs` would pull the whole
retention-commitment machinery into a unit about record CONTENT.
**Root relationship.** The storage-boundary twin of `proxy.retained_record_content`, the
same shape as NP-045 one unit over — and the second mechanically impossible reattribution
this campaign has measured. Both come from the same place: **a unit's battery can only
select controls inside the source it measures, in the project it measures it in.**
**Severity:** `high`.

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

---

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

## NP-049 — the replay configuration classifier

**Controls:** `config_state/replay.rs`.
**Statement.** *Every legal replay state form is classified and accepted; each state names every locator it cannot start without and the feature that could establish it; a shared store with no declared tier, a sub-strict tier, a wait-quorum tier that waits for no acknowledgement and no declared tier at all each name NO state; a locator belonging to the other state is refused; the planned store is the validated locator; the tier is DERIVED from the state rather than stored beside it; and the withdrawn alias names its replacement rather than being reinterpreted.*
**If false.** A fleet starts on a replay store it cannot reach, or on a durability tier weaker than the one it recorded — and the tier stored beside the state is the shape that lets the two disagree. The withdrawn-alias clause is the sharper one: an alias silently reinterpreted is an operator's old configuration meaning something new.
**Likely owner:** none. Its five sibling classifiers are units; this one is not.
**Root relationship.** Under THM-0077 — *no deployment serves a posture nobody selected* — with the command-line family (NP-025 … NP-035) one layer above it.
**Severity:** `critical`.

## NP-050 — the delegated-signing configuration classifier

**Controls:** `config_state/delegated_signing.rs`.
**Statement.** *Every fact a delegated-signing request resolves is present and non-empty however it was produced — a whitespace-minted fact is refused like an empty one, and a one-character fact is not refused by the emptiness guard; a TTL above the ceiling, an overlap outside the rotor range and an overlap outside the TTL are refused or resolve no window; an absent trust epoch names no posture; an explicit value overrides the fallback; the issuer-kid fallback is required only where the resolution reads it; and the two defaults are resolved by this owner.*
**If false.** A replica signs under a delegated credential whose window, rotor range or issuer identity was defaulted into existence rather than declared — and the whitespace arm is the one that has bitten elsewhere: a value that looks present and resolves to nothing.
**Likely owner:** none. Its five sibling classifiers are units; this one is not.
**Root relationship.** Under THM-0077 — *no deployment serves a posture nobody selected* — with the command-line family (NP-025 … NP-035) one layer above it.
**Severity:** `critical`.

## NP-051 — the transport, crl and identity-source classifier

**Controls:** `config_state/transport.rs`.
**Statement.** *Every legal CRL state form and both binding states are classified and accepted; a cadence with no list to re-read and a CRL list holding an empty path are refused; a ZERO cadence is an unbounded reloader and not a disabled one; only an EXACT transport binding becomes a state and every other kind is refused aloud; attested ingress is refused BY NAME rather than passed over; the deprecated identity source names no state; and the identity field names the state while the form decides whether there is one.*
**If false.** A listener runs with a revocation list it never re-reads, or with a transport binding weaker than exact that was read as acceptable, or with an attested-ingress setting silently ignored. 'Refused aloud' and 'refused by name' are the clauses: a setting passed over is indistinguishable from one honoured.
**Likely owner:** none. Its five sibling classifiers are units; this one is not.
**Root relationship.** Under THM-0077 — *no deployment serves a posture nobody selected* — with the command-line family (NP-025 … NP-035) one layer above it.
**Severity:** `critical`.

## NP-052 — the channel credential custody classifier

**Controls:** `config_state/channel_credential_custody.rs and channel_key_material.rs`.
**Statement.** *Both roles answer the custody question with ONE semantic fact; a file key is the exported state and carries the key it exports; the exported state cannot start without that key; the delegated state does not want it; any backend's selector names the same state and records itself; a channel mechanism that does not exist drives the same consumer; and a key object projects its own locator and no neighbours.*
**If false.** The two roles disagree about whether the channel credential is exported, so one plane protects material the other has already written to disk. 'One semantic fact' is the whole claim: two answers to a custody question is how a key ends up somewhere nobody meant.
**Likely owner:** none. Its five sibling classifiers are units; this one is not.
**Root relationship.** Under THM-0077 — *no deployment serves a posture nobody selected* — with the command-line family (NP-025 … NP-035) one layer above it.
**Severity:** `critical`.

## NP-053 — the freshness-window classifier

**Controls:** `config_state/freshness.rs`.
**Statement.** *A skew outside the bound resolves no window; an overflowing expiry saturates rather than wrapping; retention never ends before the verifier stops accepting; the two projections are derived from the same skew; and the public constructor validates too.*
**If false.** An expiry that wraps is an unbounded acceptance window, and retention ending before the verifier stops accepting is evidence discarded while it is still being relied on. 'The public constructor validates too' is the seal arm: without it the invariant is remembered at one construction site.
**Likely owner:** none. Its five sibling classifiers are units; this one is not.
**Root relationship.** Under THM-0077 — *no deployment serves a posture nobody selected* — with the command-line family (NP-025 … NP-035) one layer above it.
**Severity:** `high`.

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
**Likely owner:** none. Its five sibling classifiers are units; this one is not.
**Root relationship.** Under THM-0077 — *no deployment serves a posture nobody selected* — with the command-line family (NP-025 … NP-035) one layer above it.
**Severity:** `critical`.

## NP-056 — the evidence-retention classifier

**Controls:** `config_state/evidence.rs`.
**Statement.** *Every legal state form is classified; retention is selected by its OWN locator; the ON state carries the directory that selected it; and only the trusted context asserts something configuration cannot check.*
**If false.** A deployment retains evidence somewhere other than where the operator pointed, or reads as retaining when it is not. The last clause is the boundary: what configuration can check and what only a trusted context can assert are different facts, and collapsing them is how a configuration claim becomes an assurance claim.
**Likely owner:** none. Its five sibling classifiers are units; this one is not.
**Root relationship.** Under THM-0077 — *no deployment serves a posture nobody selected* — with the command-line family (NP-025 … NP-035) one layer above it.
**Severity:** `high`.

## NP-057 — the in-flight limit classifier

**Controls:** `config_state/in_flight_limit.rs`.
**Statement.** *Saying nothing resolves to the bounded default; an absent limit is DISTINGUISHABLE from one that equals the default; a stated basis is carried through unchanged; and exactly one projection answers for every basis.*
**If false.** The in-flight ceiling is unbounded because silence was read as a choice, or an operator's explicit choice is indistinguishable from silence — the provenance collapse this repository has ruled on, in the one setting that bounds concurrent work.
**Likely owner:** none. Its five sibling classifiers are units; this one is not.
**Root relationship.** Under THM-0077 — *no deployment serves a posture nobody selected* — with the command-line family (NP-025 … NP-035) one layer above it.
**Severity:** `medium`.

## NP-058 — the mcp transport contract classifier

**Controls:** `config_state/mcp_transport_contract.rs`.
**Statement.** *Every legal state form is classified; the ABSENT contract is a state and not a defect; the enforced state carries the set that selected it; and an unusual accepted set is classified rather than refused.*
**If false.** A deployment enforces a transport contract it did not select, or refuses a legal one as malformed. 'Absent is a state' is the clause that keeps an unset contract from reading as a bug in the classifier.
**Likely owner:** none. Its five sibling classifiers are units; this one is not.
**Root relationship.** Under THM-0077 — *no deployment serves a posture nobody selected* — with the command-line family (NP-025 … NP-035) one layer above it.
**Severity:** `high`.

## NP-059 — the topology classifier

**Controls:** `config_state/topology.rs`.
**Statement.** *The default deployment is a single node; zero is a DEFERRAL and not a count; the runtime projection spells auto as zero; and the topology and the shard request do not constrain each other.*
**If false.** A fleet-shaped deployment runs single-node, or a zero core count is read as a count of zero rather than as 'decide at runtime' — and the two-machine independence clause is what keeps a shard request from silently deciding the topology.
**Likely owner:** none. Its five sibling classifiers are units; this one is not.
**Root relationship.** Under THM-0077 — *no deployment serves a posture nobody selected* — with the command-line family (NP-025 … NP-035) one layer above it.
**Severity:** `medium`.

## NP-060 — the validation boundary is total and names what it refused

**Controls:** `config_state/validation/* , config_state/mod.rs and config_state/trust_document.rs`.
**Statement.** *Every required coordinate is refused when empty HOWEVER the request was built, and a whitespace coordinate is refused like an empty one; a target URI that would disable the reconstruction check is refused; the inventory IS the file rather than a list beside it; a machine with no clauses contributes nothing to the violation list; the internal error names the machine that recognised nothing; a refusal names the flag; and the state carries what the planes would otherwise re-derive.*
**If false.** A required coordinate reaches a plane empty because the request was built the other way, or an operator gets a refusal that does not say what to change. 'The inventory IS the file' is the anti-drift clause: a hand-maintained list of what must be validated is a list that goes stale.
**Likely owner:** none. Its five sibling classifiers are units; this one is not.
**Root relationship.** Under THM-0077 — *no deployment serves a posture nobody selected* — with the command-line family (NP-025 … NP-035) one layer above it.
**Severity:** `high`.

## NP-061 — a configuration machine decides only its own subject

**Controls:** `config_state/continuation_control.rs`.
**Statement.** *The continuation-control machine does not read the replay tier.*
**If false.** One configuration machine re-derives another's decision from raw fields, so two owners answer the same question and can disagree. `proxy.cross_machine_legality` states exactly this shape — 'every relation reads classified owner states rather than raw request fields', with `the_trust_epoch_posture_is_not_re_derived_here` as its registered control — and it CANNOT claim this one: its paths are `cross_machine.rs` alone, and `verify --manifests` refuses a `lib#` selector whose module the unit does not measure. The third mechanically impossible reattribution this campaign has measured.
**Likely owner:** none. Its five sibling classifiers are units; this one is not.
**Root relationship.** Under THM-0077 — *no deployment serves a posture nobody selected* — with the command-line family (NP-025 … NP-035) one layer above it.
**Severity:** `high`.

## NP-062 — the CRL index answers revocation exactly

**Controls:** `mcp-re-proxy/src/client_revocation.rs` (12).
**Carrier:** the client-revocation index and its snapshot.
**Statement.** *A listed serial is revoked and an unlisted one is good, with zero padding
normalised; a CRL revokes only leaves of its own CA and says nothing about another; an
uncovered issuer is UNKNOWN and refused; a malformed CRL is refused rather than skipped; an
expired CRL refuses its issuer rather than admitting it, and a stale one certifies nothing
but still revokes; two CRLs for one issuer union their serials and keep the earliest
nextUpdate; an empty index admits everything; unknown status is refused with no policy input
that could admit it; and the snapshot swaps atomically, with a poisoned lock still yielding
the last good index and still accepting a swap.*
**If false.** A revoked client certificate is admitted — by a CRL that was skipped because it
was malformed, by an issuer nobody covered being read as good, by an expired list being
trusted, or by a serial that did not match because of its padding. Each of those is a
different route to the same outcome, which is why the clauses are enumerated rather than
summarised.
**Likely owner:** `proxy.client_certificate_posture` states that every production verifier
*denies unknown revocation status, enforces revocation over the full chain and enforces CRL
expiration*, and `proxy.client_revocation_currency` states that a set of CRLs is installable
only inside its own nextUpdate window. **Neither can claim these controls**: their `paths`
are the `tls_plane` and `tls_listener_state` files, and `client_revocation.rs` — the index
those propositions are ABOUT — is in neither. The fourth mechanically impossible
reattribution this campaign has measured, and the first where TWO units state the
proposition and neither owns the carrier.
**Root relationship.** Under the client-certificate roots.
**Severity:** `critical`.
**The stale/expired pair is the clause worth reading twice.** *A stale CRL certifies nothing
but still revokes*, and *an expired CRL refuses its issuer rather than admitting it*. Those
are opposite directions on purpose: age must never turn a revocation into an admission, and
must never turn an absence of evidence into one either.

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

**Controls:** `mcp-re-proxy/src/materialized_runtime.rs` (11).
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

## NP-068 — a plan carries what it was given, not what it found

**Controls:** `mcp-re-proxy/src/startup_plan.rs` (10).
**Statement.** *Each startup plan carries the decision it was handed: the signing plan
carries the epoch it was GIVEN and not one it found; the continuation plan carries its own
endpoint verbatim; the channel plan carries the classified custody and the credential window;
the epoch plan normalises the key ONCE; the issuer kid in the credential is the one that was
planned, falling back to the server key id only where the resolution reads it; the audience
scope defaults to the response audience and is overridable; both consumers of the epoch hold
ONE decision; each CRL posture is projected as its own variant; and the paths accessor
answers which FILES, not which posture.*
**If false.** The plan re-derives a decision an owner already made, so two answers to one
question exist and can diverge — which is the defect `proxy.cross_machine_legality` states
for relations, arriving one layer later in the planner. "Normalises the key once" and "both
consumers hold one decision" are the same rule stated twice because the planner has two ways
to break it.
**Likely owner:** none. `startup_plan.rs` is in no unit's `paths`.
**Severity:** `critical`.

## NP-069 — planning refuses a state that skipped the parser, and contacts nothing

**Controls:** `mcp-re-proxy/src/startup_plan.rs` (17).
**Statement.** *A tier that reached the planner without passing the parser is refused for
whatever it is missing — a linearizable tier without an endpoint, a shared Redis tier
without a URL, a shared tier without a durability tier — and a request with no durable replay
configuration fails closed; the withdrawn alias is refused rather than reinterpreted; each
declaration is made by its own owner (continuation on its own locator and not the replay
tier, admission independently of replay, only the Redis tier declaring a need, only the
networked push state planning an epoch source), the requirement being the OR of every
contributor; the build refusal is stated once and names both consequences; the assertion arm
is refused at the boundary and the both-set arm agrees with the gate on an unreachable
input; a deployable configuration reads the verified peer certificate; and PLANNING A
NETWORKED TIER CONTACTS NOTHING.*
**If false.** A deployment is planned around a state no classifier ever accepted — the
"skipped the parser" route is the one a programmatic configuration takes — or planning
reaches the network, so a startup that should have failed on configuration instead hangs on
a socket.
**Likely owner:** none.
**Severity:** `critical`.

## NP-070 — the per-core pool ceiling saturates and is raised only when it must be

**Controls:** `mcp-re-proxy/src/startup_plan.rs` (4).
**Statement.** *A ceiling that would overflow SATURATES rather than wrapping; both bounds
reach the pool through the gate's per-core ceiling; the pool is raised only when the fleet
ceiling exceeds its default; and a total that does not divide evenly yields the aggregate the
gate admits.*
**If false.** A wrapping ceiling is an unbounded pool — the arithmetic-semantics failure this
repository has a lint for — reached from an operator-supplied number.
**Likely owner:** none. `proxy.admission_configuration_state` classifies the ceilings; this
is what the planner does with them.
**Severity:** `high`.

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

**Controls:** `transport/ingress/v1.rs` (10), `transport/ingress/v2.rs` (14),
`transport/ingress/mod.rs` (1), across both frozen formats.
**Statement.** *An accepted ingress assertion carries a signature that verifies under a
KNOWN key id, over a length-prefixed and unambiguous preimage, binds to the hash of the
request in hand, is inside its window — stale and implausibly-future rejected, a future
expiry accepted — and, on v2, names this audience and a trusted ingress identity; a
tampered field, a malformed framing, a malformed identity shape, a malformed enum
discriminant and a cross-request binding are each rejected; recorded-facts admission fails
closed; the wire form round-trips through parse; and the two frozen formats have DISJOINT
PREIMAGES.*
**If false.** A peer replays one request's ingress assertion onto another — the
cross-request arm — or an assertion signed for one audience is accepted by another
deployment, and the proxy believes a hop it never verified. The disjoint-preimages clause is
the cross-format version of the same attack: one format's signature must not verify as the
other's.
**Likely owner:** none. NP-033 is the CONFIGURATION side — attested ingress configured whole
or not at all; this is the verification the configuration turns on.
**Root relationship.** Under the peer-identity roots.
**Severity:** `critical`.
**"Length-prefixed and unambiguous" is a proposition about the preimage and not about the
signature**, and it is registered here because it is what makes every other clause mean
what it says: a preimage two different messages can produce makes a valid signature evidence
for the wrong one.

## NP-074 — each ingress format publishes the guarantee it actually gives

**Controls:** `transport/ingress/v1.rs::lb_assertion_guarantee_is_not_end_to_end_mtls`,
`transport/ingress/v2.rs::v2_guarantee_is_attested_delegation_not_end_to_end`.
**Statement.** *The guarantee each ingress format publishes is what it gives: v1's LB
assertion is not end-to-end mTLS, and v2's is attested delegation and not end-to-end.*
**If false.** A deployment reads an ingress assertion as end-to-end channel evidence and
stops requiring the thing that would have been end-to-end. This is NP-063's shape at a
different layer — a mechanism publishing a guarantee it does not have — and it is separated
from NP-073 because verification and publication are different authorities: an assertion can
verify perfectly and still be described as more than it is.
**Likely owner:** none.
**Severity:** `critical`.

## NP-075 — the transport binding is exact match, and no policy can manufacture it

**Controls:** `transport/mod.rs` (7).
**Statement.** *The installable binding is EXACT MATCH; it binds a channel peer and a
request actor that name ONE principal and refuses two different ones; an absent channel peer
fails closed; a permissive policy cannot manufacture the binding fact; the composite actor
id is NOT the binding coordinate; and a static provider yields its identity ignoring the
request.*
**If false.** The proxy treats a request as bound to the channel it arrived on when the two
name different principals — the substitution the binding exists to prevent — or a permissive
policy produces the binding fact without any correspondence being checked. "A permissive
policy cannot MANUFACTURE the fact" is the seal clause: the fact is produced by the
correspondence, not by the policy that decides whether it is required.
**Likely owner:** none. `proxy.certificate_identity` owns what the INTERPRETER decides about
a certificate field; this is what the binding does with the identity once interpreted, in
`transport/`, which that unit does not measure.
**Severity:** `critical`.

## NP-076 — an asserted identity is a bounded, printable, non-empty value

**Controls:** `transport/mod.rs` (4).
**Statement.** *An asserted identity accepts a well-formed value and trims it, and rejects
an empty one, an oversized one, and one carrying control characters.*
**If false.** A peer-supplied identity carrying control characters reaches a log, an audit
record or a comparison — and an unbounded one is a memory cost a peer chooses.
**Likely owner:** none.
**Severity:** `high`.

## NP-077 — a routing header is well-formed and singular, or the request fails closed

**Controls:** `transport/mod.rs` (6).
**Statement.** *An absent routing header passes and a well-formed one passes; a duplicate, an
empty and a malformed one each FAIL CLOSED; and request-header parsing skips the request
line and is case-insensitive.*
**If false.** Two routing headers disagree and the proxy picks one — the header-smuggling
shape — or a malformed header is ignored rather than refused. The absent/present pair is what
keeps "fails closed" from meaning "refuses everything".
**Likely owner:** none.
**Severity:** `critical`.

## NP-078 — a certificate identity is readable only through its projections

**Controls:** `transport/identity.rs` (2).
**Statement.** *A certificate that does not carry the configured field yields NOTHING, and
the projections are the only way to read an identity from one.*
**If false.** A consumer reads a certificate field directly and gets an identity the
interpreter would have refused — the fallback `proxy.certificate_identity` exists to make
impossible, arriving through a second reader instead of through the interpreter.
**Likely owner:** `proxy.certificate_identity` states exactly this (*no fallback to another
field*) and `proxy.certificate_identity_authority_boundary` seals the pairing. Neither can
claim these controls: both units' `paths` are `communication_assurance/*` files, and
`transport/identity.rs` is in neither. The fifth mechanically impossible reattribution this
campaign has measured.
**Severity:** `critical`.

---

## The conformance claim surface — NP-079 through NP-086

`mcp-re-conformance/` holds 97 unclaimed controls across seventeen test files, and **two
units**. Conformance is what MCP-RE tells an auditor it implements, so these controls are
the evidence behind a product-facing claim surface — the same subject NP-008 approaches
from the gate side, arriving here as the claims themselves.

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
compatibility. Both directions are one proposition for the same reason NP-019's peek/take
split is: half of it is a different claim, not a weaker one.
**Severity:** `high`.

## NP-083 — the audit vocabulary is frozen and minted in one place

**Controls:** `audit_vocabulary_guard_test.rs` (7).
**Statement.** *Every audit token is a wire code or a fixed event type; event types do not
collide with frozen wire codes; the success and key-lifecycle event sets are EXACTLY their
allowlists; no producer outside the Core mints a wire token; there is no authorization
hash-mismatch audit reason; and the guard's inputs are non-empty.*
**If false.** An audit record carries a token that means one thing to its producer and
another to its reader, or a producer outside the frozen taxonomy mints one — which makes the
vocabulary a convention rather than a contract.
**Likely owner:** `conformance.verdict_vocabulary_scope` measures HOW MANY files decide what
a verdict token says, and its argv claims three of this file's ten controls. The other seven
are about what the tokens ARE, which that measurement does not say. A `measured` unit has no
battery to hold them, which is NP-036's finding arriving from the other side.
**Severity:** `high`.
**`guard_inputs_are_non_empty` is registered here rather than dispositioned as apparatus**,
because it is this proposition's anti-vacuity arm: a guard over an empty input set reports a
clean vocabulary.

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

**Controls:** `mcp-re-http-profile/src/block.rs` (11).
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

## NP-088 — the body is signed as written, or refused

**Controls:** `mcp-re-http-profile/src/body/mod.rs` (14),
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

## NP-091 — the MCP transport contract is agreed and enforced on the wire

**Controls:** `mcp-re-http-profile/tests/mcp_transport_headers_test.rs`, `mcp-re-http-profile/src/mcp_transport/mod.rs`, `mcp-re-http-profile/src/mcp_transport/agreement.rs`.
**Statement.** *The transport headers a peer may send and must send are a closed, agreed set: the accepted contract is the one both sides named, a header outside it is refused rather than ignored, and what the agreement records is what the exchange is held to.*
**If false.** A peer negotiates one transport contract and is held to another, so a header that decides framing or session identity is honoured under an agreement that never admitted it.
**Likely owner:** none. The `http_profile.*` units that measure these files are each about what their own verdict means.
**Severity:** `critical`.

## NP-092 — a result is classified once, and never read as terminal by default

**Controls:** `mcp-re-http-profile/src/result_class.rs`.
**Statement.** *The recognised set is complete — input-required and absent; a body with no result member is terminal; a near-miss discriminator, an unparseable body, and an input-required reply without a usable state are each REFUSED and not read as terminal; a non-string or unadvertised result type is unrecognized, and unrecognized is not terminal; a terminal reply has no continuation state and an input-required one yields its state.*
**If false.** A continuation is consumed as a completed call. Every clause names a different way to arrive there, and the repeated 'not read as terminal' is the point: the default on doubt must not be the one that ends the exchange.
**Likely owner:** none. The `http_profile.*` units that measure these files are each about what their own verdict means.
**Severity:** `critical`.

## NP-093 — a response envelope is a JSON-RPC response or it is refused

**Controls:** `mcp-re-http-profile/src/envelope/response.rs`.
**Statement.** *The version is exactly 2.0; a response carrying both result and error, or neither, is refused; a non-object body, a non-object result, a malformed error member and an unparseable body are each refused; a JSON-RPC error is a VALID response and not a malformed one; an ordinary result response validates; and an arbitrary application payload inside result is not inspected.*
**If false.** A malformed envelope is interpreted rather than refused — or, in the other direction, a legitimate JSON-RPC error is treated as malformed, which turns a peer's honest refusal into a transport fault. The non-inspection clause is the boundary: the profile validates the envelope and does not read the application's payload.
**Likely owner:** none. The `http_profile.*` units that measure these files are each about what their own verdict means.
**Severity:** `high`.

## NP-094 — a refusal carries its own provenance and is read only after verification

**Controls:** `mcp-re-http-profile/src/rejection/mod.rs`, `mcp-re-http-profile/src/error/core_projection.rs`, `mcp-re-http-profile/src/error.rs`.
**Statement.** *A wire code is read ONLY AFTER the signature verifies, an unsigned rejection is untrusted, a bound rejection verifies and exposes its code, an ordinary rejection body gains no new fields, and the indeterminate rejection states that a retry is unsafe; projection preserves the ratified group count and maps each failure class to its precise code, the derived token is the projected verdict's own, absent and malformed evidence are different verdicts, an outage does not project onto an actor-binding failure and is not an untrusted key, and omission and tampering are different failures.*
**If false.** A refusal an attacker wrote is read as one the peer signed, or two failures with different causes are reported as one — which is how 'the key is untrusted' and 'the network was down' become the same alarm.
**Likely owner:** none. The `http_profile.*` units that measure these files are each about what their own verdict means.
**Severity:** `critical`.

## NP-095 — delegation verifies the chain it was given

**Controls:** `mcp-re-http-profile/src/delegation/mod.rs`, `mcp-re-http-profile/src/delegation/verify.rs`, `mcp-re-http-profile/tests/delegation_e2e_test.rs`.
**Statement.** *The delegated credential chain presented is the one verified, end to end.*
**If false.** A delegated signature is accepted under a chain that was not the one presented.
**Likely owner:** none. The `http_profile.*` units that measure these files are each about what their own verdict means.
**Severity:** `critical`.

## NP-096 — a PDP decision carries exactly the claims it was issued with

**Controls:** `mcp-re-http-profile/src/pdp_decision/claims.rs`, `mcp-re-http-profile/src/pdp_decision/issue.rs`, `mcp-re-http-profile/src/pdp_decision/mod.rs`, `mcp-re-http-profile/src/pdp_decision/verify.rs`.
**Statement.** *The claims a decision carries are the ones it was issued with, and verification reads no others.*
**If false.** An authorization decision is honoured for claims nobody issued it for.
**Likely owner:** none. The `http_profile.*` units that measure these files are each about what their own verdict means.
**Severity:** `critical`.

## NP-097 — the SCITT value types parse only their own shapes

**Controls:** `mcp-re-http-profile/src/scitt/retained.rs`, `mcp-re-http-profile/src/scitt/cose_key/mod.rs`, `mcp-re-http-profile/src/scitt/merkle.rs`, `mcp-re-http-profile/src/scitt/receipt/mod.rs`, `mcp-re-http-profile/src/scitt/statement/mod.rs`.
**Statement.** *Each SCITT value — retained record, COSE key, Merkle node, receipt, statement — parses its own shape and refuses another's.*
**If false.** One SCITT structure is read as another, so an inclusion proof or a key is interpreted under the wrong shape.
**Likely owner:** none. The `http_profile.*` units that measure these files are each about what their own verdict means.
**Severity:** `high`.

## NP-098 — the cryptographic floor refuses what it cannot state exactly

**Controls:** `mcp-re-http-profile/src/verify/floor/sf_dictionary.rs`, `mcp-re-http-profile/src/verify/floor/signature_input.rs`, `mcp-re-http-profile/src/verify/floor/signature_parameters.rs`, `mcp-re-http-profile/src/verify/bound_request.rs`, `mcp-re-http-profile/tests/proof_path_test.rs`, `mcp-re-http-profile/tests/algorithm_confusion_test.rs`.
**Statement.** *An empty dictionary member and dictionary-member spacing are REFUSED, NOT normalised or ignored; alternate signature-input spellings are refused rather than normalised, while a space inside a quoted parameter value is kept; negative zero is not an SF integer; a request with no signature-input has no handle; and the proof path admits no algorithm the header did not name.*
**If false.** A verifier normalises an input into something that verifies, so two different wire forms produce one base — the parser-differential attack again, at the floor rather than at the surface. 'Refused, not normalised' is the same clause NP-088 makes about the body, at the other end of the exchange.
**Likely owner:** none. The `http_profile.*` units that measure these files are each about what their own verdict means.
**Severity:** `critical`.

## NP-099 — each verifier product states what it established, without an Option

**Controls:** `mcp-re-http-profile/src/verified_request/mod.rs`, `mcp-re-http-profile/src/verified_response/bound.rs`, `mcp-re-http-profile/src/verified_response/facts.rs`, `mcp-re-http-profile/src/verified_response/unbound.rs`.
**Statement.** *A full product states its audience, a bound one its binding and a delegated one its issuer WITHOUT AN OPTION; a floor product carries the slot trust resolved it in; a seam-authorized floor projects the signer it resolved; the shared facts carry who signed and no authorization; bound and unbound facts are not the same type; an agreement records both handles and not only the verdict; and the unbound products carry no request binding and no trust-seam resolution TO MISREAD.*
**If false.** A product admits two proof strengths in one type, so a consumer reads an absent fact as a weaker establishment rather than as a different product. The repository has ruled on this exact shape: one Verified type, one proof strength, and an Option documented 'None on the minimal path' is a type admitting two.
**Likely owner:** none. The `http_profile.*` units that measure these files are each about what their own verdict means.
**Severity:** `critical`.

## NP-100 — the evidence handle is domain-separated and derived, never a bare digest

**Controls:** `mcp-re-http-profile/src/evidence.rs`, `mcp-re-http-profile/src/context.rs`, `mcp-re-http-profile/src/digest.rs`, `mcp-re-http-profile/src/artifact.rs`, `mcp-re-http-profile/src/policy.rs`, `mcp-re-http-profile/src/replay.rs`, `mcp-re-http-profile/src/authoritative_admission/record/currentness.rs`.
**Statement.** *A handle is split-form and deterministic, is NOT a bare digest of the base, differs when the base differs, cannot confuse a label with an input, and separates roles by domain over IDENTICAL BYTES; the proxy's own meta keys are stripped and application meta preserved, with a meta of only proxy keys removed entirely and a strip without meta a no-op; a digest round-trips, a tampered body fails closed, and an absent sha-256 member of a present header is malformed.*
**If false.** Two different roles over the same bytes produce the same handle, so evidence for one is evidence for the other — which is NP-087's injectivity failure at the handle rather than at the actor. 'Not a bare digest of the base' is what makes the domain separation structural instead of conventional.
**Likely owner:** none. The `http_profile.*` units that measure these files are each about what their own verdict means.
**Severity:** `critical`.

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

## NP-103 — dispatch admits only what verified

**Controls:** `mcp-re-http-profile/tests/dispatch_test.rs`.
**Statement.** *What reaches dispatch is what verification admitted, with nothing re-derived between.*
**If false.** An unverified request reaches the backend, or a verified one is dispatched under facts the verifier did not establish.
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

---

## The small crates — NP-106 through NP-113

Seventy-six controls outside `mcp-re-proxy`. Nine REGISTER — seven into
`client.binding_spec_refusal`'s own file, and two that are the ANTI-VACUITY arm of
`client.transport_server_identity`: they show that the declared fault injector is what makes
an untrusted or wrong-identity server certificate accepted, so the rejections that unit
claims are the real verifier's and not an artefact of a test that never presented a bad
certificate.

The rest are eight propositions, and three of them are premises of everything above
them.

## NP-106 — the Core's Ed25519 primitive is exact and total

**Controls:** `mcp-re-core/src/crypto.rs`.
**Statement.** *`ensure_ed25519_alg` accepts the supported algorithm and rejects an unknown one with the caller's supplied error; sign-then-verify round-trips and the signature is deterministic for a fixed seed; a wrong key, a wrong-length signature, a tampered preimage and a malformed base64 signature each fail; a malformed key — in b64url or in bytes — maps to actor-binding-failed and the response variant maps to response-sig-invalid; a verification key round-trips through bytes and b64url; and the raw primitive verifies with no algorithm plumbing at all.*
**If false.** The one primitive every signature in the system rests on accepts something it should not, or reports a key problem as a signature problem. The error-mapping clauses are why they are enumerated: a malformed key and a bad signature are different facts, and an alarm that cannot tell them apart sends the operator to the wrong place. `ensure_ed25519_alg_rejects_unknown_alg_with_supplied_error` is also NP-002's other half — the refusal that keeps ES256 out of MCP-RE's own signing.
**Likely owner:** none.
**Severity:** `critical`.

## NP-107 — base64url is the exact encoding, in both directions

**Controls:** `mcp-re-core/src/encoding.rs`.
**Statement.** *Encoding uses the URL-safe alphabet and emits NO padding; decoding rejects a non-alphabet character and rejects padding; an empty input decodes to empty; arbitrary bytes round-trip; and a known answer is reproduced.*
**If false.** Two spellings of one value both decode, so a comparison over the encoded form does not mean what a comparison over the bytes would. Rejecting padding is the clause that makes the encoded form canonical rather than merely decodable.
**Likely owner:** none.
**Severity:** `high`.

## NP-108 — the error taxonomy is frozen, exhaustive and duplicate-free

**Controls:** `mcp-re-core/src/error.rs`, `mcp-re-core/src/ids.rs`.
**Statement.** *`ALL_ERRORS` is duplicate-free and the wire-code list is EXHAUSTIVE; errors compare by value; every frozen wire string renders exactly — the full taxonomy, the delegation strings, the draft-02 strings, the http-profile signed-rejection strings, and renamed-and-kept variants; the http-profile codes are distinct from the folds they replace; a draft-02 missing binding is distinct from a draft-01 missing hash; and the profile-agnostic constants are frozen.*
**If false.** A wire token means one thing to MCP-RE and another to a peer, or two distinct failures render the same string. Exhaustiveness is what makes the taxonomy a contract: a variant nobody listed renders nothing, and nothing is what a reader cannot distinguish from a token they do not know.
**Likely owner:** none.
**Severity:** `critical`.

## NP-109 — the admitted time era is bounded and its formatter is total

**Controls:** `mcp-re-core/src/time/mod.rs`.
**Statement.** *The admitted era round-trips through the formatter; the lowest and highest admitted instants are the boundaries; a five-digit year is REFUSED; and the fixed-digit fields are total outside the parser's widths.*
**If false.** An instant outside the era formats to something a peer parses as a different time — the five-digit year is the concrete case — or the formatter is partial and a legal instant has no representation.
**Likely owner:** none.
**Severity:** `high`.

## NP-110 — the Core stays pure

**Controls:** `mcp-re-core/tests/firewall_test.rs`.
**Statement.** *`mcp-re-core` depends on no networking, no async runtime, no filesystem and nothing up-stack.*
**If false.** The layer every signature rests on acquires a dependency that can read a file, open a socket or block — and the argument that a Core verdict is a function of its inputs stops being true. This is the crate's whole architectural premise, measured as one control and claimed by nothing.
**Likely owner:** none.
**Severity:** `critical`.

## NP-111 — a verified reply's disposition is the one the receipt states

**Controls:** `mcp-re-client-proxy/src/proxy.rs`, `mcp-re-client-core/src/response.rs`.
**Statement.** *A JSON-RPC error reply is carried through and NOT flattened to a null result; a verified error reply is classified as a failed call and not a success; a reply that is not a JSON-RPC response fails closed and an unparseable verified reply is a VERIFICATION failure rather than a bad request; an input-required reply and an unrecognized result type are never terminal; a verified rejection carries its execution contract to the local client and an UNSTATED contract produces no invented disposition; a post-dispatch rejection carries its execution and retry contract; a retention failure is readable as such; an out-of-range skew cannot widen the credential window; an ordinary result still rebuilds; the proxy-owned meta is stripped from the plain reply; and the reply carries the id THE PROXY SIGNED rather than the one the server echoed.*
**If false.** The application is told the call succeeded, or failed, or did not run, on the strength of something the receipt did not say. `an_unstated_contract_is_not_a_did_not_run_verdict` and `an_unstated_contract_produces_no_invented_disposition` are the same rule in two crates: silence is not a verdict.
**Likely owner:** none.
**Severity:** `critical`.

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

## NP-114 — a KMS access token is fetched once, reused honestly, and never extended

**Controls:** `mcp-re-proxy/src/gcp_kms_keysource.rs`.
**Statement.** *A token response yields the credential and its lifetime and an empty or absent access token is refused; a STATED expiry is never extended by the reuse floor and an unestablishable lifetime is reported as a fact rather than read as a stated one; an unreadable `expires_in` is reused briefly rather than refetched every call, including when every clock read differs; concurrent callers perform ONE metadata fetch between them and a failed fetch is not repeated by every waiter; a 401 discards the token and retries once, a persistent 401 stops costing a refetch per call, a 403 does NOT discard a valid token, and only a refusal with a token to discard costs a second call; the failure cool-off expires, a success clears it, a backwards clock step does not extend it, and it must outlast the network timeout as the unknown-expiry floor must outlast the refresh margin; invalidating a token another thread already replaced is a no-op and invalidating the source forces a re-fetch; a poisoned token lock still serves tokens; the access token is MOVED out of the parsed document; and two token sources share neither a cache nor a flight.*
**If false.** The response signer cannot sign — because a 403 threw away a good token, because a persistent 401 turned every call into a metadata fetch, or because a cool-off outlived its own reason — or it signs with a credential past its stated expiry because a reuse floor extended it. `proxy.gcp_kms_adapter` states what the SIGNER does; this is how it gets the credential to do it, and it is a different authority with twenty-three controls and no claim.
**Likely owner:** none.
**Severity:** `critical`.

## NP-115 — the delegated TLS signer offers Ed25519 and nothing else

**Controls:** `mcp-re-proxy/src/delegated_tls.rs`.
**Statement.** *The handshake offers Ed25519 ONLY; the signer scheme is Ed25519 and the signature is 64 bytes; and a wrong-length signature fails closed.*
**If false.** The TLS handshake negotiates a scheme the remote signer does not implement, or accepts a signature of the wrong length as a valid one. This is NP-002's containment argument at the handshake: the set of algorithms offered is the set that can be used.
**Likely owner:** none.
**Severity:** `critical`.

## NP-116 — channel peer resolution yields the identity the relationship authenticated as

**Controls:** `mcp-re-proxy/src/tls.rs`.
**Statement.** *Direct TLS resolves the identity the relationship AUTHENTICATED AS; each relationship resolves its own peer's identity and a resumed one resolves the same identity as a full handshake; a leaf without the configured field and an absent acceptance each resolve NO identity; an issuer in the accepted chain never becomes the transport identity; and an LB-assertion deployment resolves no transport identity at all.*
**If false.** The proxy attributes a request to a peer that did not authenticate as that peer — by promoting an issuer out of the chain, by resolving an identity from a resumed session that differs from the handshake's, or by producing a transport identity in a deployment where the channel is terminated in front of it. The last is the sharpest: under an LB assertion there IS no transport identity, and producing one would let NP-074's guarantee be read as end-to-end.
**Likely owner:** none.
**Severity:** `critical`.

## NP-117 — every deployment classifies to exactly one currency policy, read at call time

**Controls:** `mcp-re-proxy/src/tls.rs`.
**Statement.** *Every deployment classifies to EXACTLY ONE currency policy, and the policy reads the index in force AT THE TIME OF THE CALL.*
**If false.** Two policies are applicable and which one applies depends on the reader, or a call is decided against an index that has since been replaced — so a revocation that landed before the call is not in force for it.
**Likely owner:** none.
**Severity:** `high`.

## NP-118 — a trust snapshot swaps atomically and a held one never changes

**Controls:** `mcp-re-proxy/src/reloading_trust.rs`.
**Statement.** *A reader never observes a snapshot built from two different reads; a snapshot a reader already holds is unaffected by later swaps; the shared handle observes the swap; a swapped store revokes WITHOUT A RESTART; and every edit moves the resolver and the signer set TOGETHER.*
**If false.** A request is decided against half of one trust document and half of another. `proxy.trust_resolution_window` says it takes the materialized snapshot AS AN INPUT AUTHORITY — this is the premise that makes that legitimate, and nothing claimed it.
**Likely owner:** none.
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

**Controls:** `mcp-re-proxy/src/replay_tier.rs`.
**Statement.** *Every tier has a non-empty guarantee and NO TIER CLAIMS UNCONDITIONAL; a tier promising wait supplies its wait parameters and wait-quorum parsing extracts the quorum and timeout; the async tier's claim ceiling is not linearizable; the strict production minimum is wait-quorum or stronger; parsing round-trips the simple tiers and refuses unknown and malformed ones; the wire names are the semantic ADR names; and the startup audit line carries the backend, tier and guarantee and NO NONCE.*
**If false.** A deployment publishes a replay guarantee it does not have, or an async tier is read as linearizable. This is NP-063's proposition for the other tier vocabulary, and the two are recorded separately because they are two vocabularies with two ceilings — the audit-line clause differs too: no key material there, no NONCE here.
**Likely owner:** none.
**Severity:** `high`.

## NP-122 — the handshake quota opens on quota failures only, and never shortens

**Controls:** `mcp-re-proxy/src/handshake_quota.rs`.
**Statement.** *ONLY quota failures open the window; a throttled signature stops calling the signer for the cooldown; a successful probe reopens the path AT ONCE and does not clear a window armed later; only one handshake probes at the cooldown boundary; a straggler cannot SHORTEN the window; a slow throttled call still opens a live window; the window is never shorter than the network timeout; and a poisoned window lock still signs.*
**If false.** A remote signer under quota pressure is hammered by every handshake — or, in the other direction, an unrelated failure opens a cooldown and the listener stops signing for a reason that was never quota. 'A straggler cannot shorten the window' is the race: a late reply from before the window must not end it.
**Likely owner:** none.
**Severity:** `high`.

## NP-123 — a serving capability is ON with an artifact or OFF with an explanation

**Controls:** `mcp-re-proxy/src/serving_capabilities.rs`.
**Statement.** *An ON posture ALWAYS carries an artifact and an OFF posture never does; every OFF line tells the operator what to do about it; evidence retention attaches a store only for a NAMED directory and an unopenable retention directory refuses startup NAMING THE FLAG; the security-audit posture follows the classified audit state; and the verified-context carrier is attached only for a trusted inner channel.*
**If false.** A capability reports ON while carrying nothing, so the transcript says a protection is active that is not. The OFF-line clause is NP-004's operator problem solved from the other side: not merely that a seam states its posture, but that the statement is actionable.
**Likely owner:** none.
**Severity:** `high`.

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

## NP-126 — a client CRL is loaded or the listener fails closed, and it must fall out of force

**Controls:** `mcp-re-proxy/src/client_crl_publication.rs`.
**Statement.** *A missing client-CRL file FAILS CLOSED; no CRL paths loads an empty vector; a CRL that states its nextUpdate is accepted; and a CRL that NEVER FALLS OUT OF FORCE is refused.*
**If false.** A listener starts with a revocation list it could not read and believes it is enforcing revocation — or with one that never expires, so a stale list is trusted forever. 'Never falls out of force is refused' is the clause: a CRL without an expiry is not a permanent CRL, it is an unbounded one.
**Likely owner:** none.
**Severity:** `critical`.

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

