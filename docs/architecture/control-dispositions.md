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

