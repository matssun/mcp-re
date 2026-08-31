<!-- SPDX-License-Identifier: Apache-2.0 -->
# Consolidated owner specification-review packet — ADR-MCPRE-059 §28

*Generated — `python3 tools/verification/review-packet`. Every field is read from
`verification/policy/*.toml` and from the records in `verification/reviews/specification/`,
so this file cannot state a claim the registry does not hold, cannot miss one it does, and
shrinks by itself as records are written. Regenerate rather than edit.*

**Status: AWAITING OWNER REVIEW.** Nothing in this packet has a specification-review
record, and none was self-authored. The ratification of 2026-08-31 was of the theorem
ARCHITECTURE — the root set, the decomposition rulings, the owner-altitude rule and the
closure order — not of these statements. A record inferred from it would record an event
that did not happen, which is why the graph reports every claim below as
`SPECIFICATION REVIEW UNREVIEWED` and why root completeness is what it is.

Grouped by permanent system root, each root followed by its `depends_on` closure in
dependency order. A theorem appearing under more than one root is stated once, at its
first appearance, and cross-referenced afterwards. Theorems that already carry an
independent record — THM-0001 to THM-0042 — are NAMED in each closure and not restated:
this campaign did not reopen any of them, so re-reviewing them here would ask for a
decision that has been taken.

**Where the *lowest honest proposition* argument lives.** In each theorem's **Scope**,
which is where the registry keeps it: every scope says what the claim does NOT establish,
which neighbouring theorem owns that instead, and — for the claims resting on source-text
controls — why the property is EVIDENCE rather than unconstructibility. Copying that
argument into a second field would create two places for it to disagree, which is the
failure `_DUPLICATED_AUTHORITY` exists to prevent. Read the Scope as the justification.

**Deviations from the ratified architecture** are collected in one section at the end
rather than scattered per theorem, because there are six and each is a decision the owner
may want to read against the others.


---

## Root THM-0074 — No unearned dispatch

Owner: `proxy.dispatch_commitment`

Independently reviewed already, and not reopened: THM-0015, THM-0014, THM-0001, THM-0007, THM-0008, THM-0034, THM-0031, THM-0029, THM-0024, THM-0023, THM-0028, THM-0030, THM-0033, THM-0032, THM-0003, THM-0004, THM-0005, THM-0006, THM-0040, THM-0039, THM-0009, THM-0010, THM-0037, THM-0035.

### THM-0074 — No unearned dispatch

* **Kind:** root
* **Owner:** `proxy.dispatch_commitment`
* **Depends on:** THM-0015, THM-0051, THM-0050, THM-0034, THM-0003, THM-0004, THM-0005, THM-0006, THM-0053, THM-0040, THM-0052, THM-0009, THM-0043, THM-0045, THM-0066, THM-0079, THM-0080, THM-0083
* **Support:** unit://proxy.dispatch_commitment — 4 declared symbol(s), lane(s): test; unit://proxy.exchange_lifecycle — 31 declared symbol(s), lane(s): mutation, test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** If the serving path invokes the backend for an inbound request, every pre-dispatch security obligation selected by the validated deployment was first established by its owning authority from the inputs that obligation is defined to consult — request and exchange evidence and, where required, authoritative validated or materialized state — and the downstream pipeline consumed the earned product of that establishment for the same relevant request, actor, subject and exchange.

**Security consequence.** A caller cannot reach the backend by omitting evidence, by presenting evidence for a different exchange, by presenting a fact the deployment did not select the authority for, by handing the pipeline a security value it constructed itself, or by having some other exchange's establishment succeed.

**Scope.**

> It ends at the invocation: what the backend does once dispatched is the application's. Obligations a deployment did NOT select are outside it by construction — this is a claim about the selected set, not a claim that the set is right. It says nothing about liveness: that a valid request IS served is not claimed, and the complement of this implication is THM-0078, not "some other path".
>
> Request-carried evidence does not stand in for authoritative state. Admission currency is stated against the state the enforcement point holds, and actor resolution against the MATERIALIZED trust authority (THM-0066), because an obligation defined over validated state is not discharged by anything the request carries.
>

### THM-0051 — The pipeline holds, at dispatch, the verification product of this very exchange

* **Kind:** relation
* **Owner:** `proxy.dispatch_commitment`
* **Depends on:** THM-0015, THM-0047
* **Support:** unit://proxy.dispatch_commitment — 4 declared symbol(s), lane(s): test; unit://http_profile.verifier_result_separation — 3 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** The verified request the serving path carries from the verification stage to the dispatch, and to every stage between them, is the product that stage's verification of THIS inbound message returned — not a product of another exchange, not one reconstructed downstream, and not one a caller supplied.

**Security consequence.** A caller cannot reach the backend by having some other exchange's verification succeed, and no stage between verification and dispatch can substitute a value for the one the verifier produced.

**Scope.**

> Possession provenance across the serving pipeline. It does not restate what the verification established (THM-0015) or that the products are type-separated (THM-0047); it is the joint those two explicitly exclude.
>
> The mechanism is a self-tested source-text gate, `scripts/serving_product_provenance_gate.py`: the assembly calls the verification stage exactly once and builds exactly one carrier, the stage hands its product to `ExchangeProgress::establish` so the machine learns it ran, the carrier has no public field, and no production module of `mcp-re-proxy` constructs the product. That is EVIDENCE and not unconstructibility, and the reason it cannot be a type is recorded rather than worked around: `VerifiedMcpRequest` keeps PUBLIC fields because the Verus obligation on `prepare_http_dispatch` reads `verified.request_block` as a field so the prover can relate the obligation to the value, and `#[verifier::external_type_specification]` refuses a non-public field. A proved postcondition outranks a seal. So this claim holds for the serving path of this crate and says nothing about a product another crate fabricates.
>

### THM-0047 — The verifier's assurance products are not substitutable

* **Kind:** owner-local
* **Owner:** `http_profile.verifier_result_separation`
* **Depends on:** — (leaf)
* **Support:** unit://http_profile.verifier_result_separation — 3 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** The products the verifier operations return are distinct types whose representations are private to their own modules, so a product that establishes a weaker proposition cannot be passed where a stronger one is required: a floor-verified request is not a full-profile verified request, a bound response is not an unbound one, and a delegated response is not a trust-seam one.

**Security consequence.** A serving path cannot satisfy a consumer that requires a full-profile verification by handing it a value that only cleared the cryptographic floor, and the substitution is a compile error rather than a silently weaker check.

**Scope.**

> Type separation only. It does not establish that the value a consumer holds was produced by the operation whose type it has for THAT consumer's exchange — possession provenance is a proposition about the caller and is registered against the serving composition. It establishes nothing about what any of the operations verify.
>

### THM-0050 — Distinct verification keys cannot feasibly be made to share a keyid

* **Kind:** relation
* **Owner:** `http_profile.keyid`
* **Depends on:** THM-0055
* **Support:** unit://http_profile.keyid — 6 declared symbol(s), lane(s): test
* **Assumptions:** ASM-0037
* **Review requirement:** Owner security-specification review; re-review on any change to the keyid digest algorithm

**Statement.** Under the accepted SHA-256 collision-resistance premise (ASM-0037), no computationally feasible adversary can cause two distinct enrolled verification keys with distinct canonical RFC 7638 JWK representations to resolve to the same keyid, so resolving a keyid through the trust seam selects at most one key against any adversary the premise covers.

**Security consequence.** A signer cannot be brought to acceptance under a keyid that resolves to another party's key, which is what would let one enrolled actor's signature be attributed to another.

**Scope.**

> Computational selector injectivity only, and deliberately not a mathematical one. SHA-256 is not injective — it maps an unbounded domain onto 256 bits, so colliding keys EXIST. What is claimed is that none can be exhibited by an adversary the premise covers, which is the strongest true form of this proposition and the form ASM-0037 states.
>
> The claim decomposes into exactly two halves. THM-0055 is the MCP-RE-owned half, established: distinct admitted verification keys have distinct canonical thumbprint preimages, and the digest encoding merges nothing. ASM-0037 is the primitive half, owner-approved and scoped to this unit and `boundary.crypto_primitives`. Neither ASM-0028 nor ASM-0023 was widened to reach it: second-preimage resistance and collision resistance are different propositions, and ASM-0023's declining to assume the construction's separation properties stands unchanged.
>
> It does not establish that the seam answers for any particular keyid, that the key it returns is trusted for its slot, or that the enrolment set is correct.
>

### THM-0055 — The keyid derivation introduces no collisions of its own

* **Kind:** owner-local
* **Owner:** `http_profile.keyid`
* **Depends on:** — (leaf)
* **Support:** unit://http_profile.keyid — 6 declared symbol(s), lane(s): test
* **Assumptions:** ASM-0037
* **Review requirement:** Owner security-specification review

**Statement.** `canonical_ed25519_jwk` embeds its operand verbatim between a fixed prefix and a fixed suffix, so the operand is recoverable from the form and distinct operands never share one — for any operand, including one carrying JSON metacharacters. The keyid's base64url-no-pad encoding is injective over the fixed 32-byte width of a SHA-256 output.

**Security consequence.** Two distinct verification keys cannot be given the same keyid by anything this project wrote: not by a canonicalization that reorders or drops a member, not by an operand chosen to nest structure inside the JWK, and not by an encoding that merges digests.

**Scope.**

> Everything except the digest. It says nothing about whether SHA-256 maps two distinct canonical forms to one value, which is the remaining premise of selector injectivity (THM-0050) and is a property of the primitive. It establishes nothing about the trust seam, about which keys are enrolled, or about whether a resolved key is trusted for its slot.
>

### THM-0053 — A presented admission assertion is authentic, in its window, and for this audience

* **Kind:** owner-local
* **Owner:** `http_profile.admission_assertion`
* **Depends on:** — (leaf)
* **Support:** unit://http_profile.admission_assertion — 7 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** The admission assertion an enforcement point acts on verified under a key resolved for its issuer through the trust seam, carries the required credential type and algorithm, names this profile and an audience this enforcement point answers to, and the instant of the call lies inside both its own [nbf, exp] window and the verifier's own staleness budget.

**Security consequence.** An admission verdict cannot rest on an assertion another party minted, on one carrying a different credential profile, on one whose validity window has passed or has not begun, or on one issued to a different enforcement point and replayed here.

**Scope.**

> Assertion authenticity only. It does not restate verdict integrity (THM-0003), anti-rollback (THM-0004), presenter binding (THM-0006) or the degraded-admission opt-in (THM-0005), all of which characterize what the verdict SAYS once the assertion is believed.
>
> Its relationship to ASM-0012 is the point of registering it separately. That assumption makes `verify_admission_assertion` opaque to the currency theorem — no `ensures` at all, so it can neither weaken nor be relied on inside the Verus cone — and its own review requirement names a separate unit for assertion validity as the discharge rather than an `ensures` added there. `http_profile.admission_assertion` is that unit, and nothing here is inside the proof cone: this is a test-lane claim, and the reason it can exist at all is that the currency proof never depended on it.
>
> It says nothing about whether the ISSUER should be trusted — that is the trust seam's, and a kid never introduces trust — nor about the authoritative state the verdict is checked against, which is THM-0007's and the currency unit's.
>

### THM-0052 — A dispatched body was released by the decision a configured policy produced

* **Kind:** relation
* **Owner:** `proxy.dispatch_commitment`
* **Depends on:** THM-0045, THM-0040, THM-0056
* **Support:** unit://proxy.dispatch_commitment — 4 declared symbol(s), lane(s): test; unit://proxy.pdp_decision_relation — 16 declared symbol(s), lane(s): mutation, test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** On a deployment where an authorization policy is configured, the `AuthorizationPosture` that released the body reaching the backend was produced by that policy's evaluation of this request's verified facts — `NoPolicyConfigured` is reachable at the dispatch only on a deployment that configured no policy.

**Security consequence.** A serving path cannot bypass a configured policy by releasing the body under the posture that claims nothing, which is the one gap the sealed body type leaves open: possession proves a decision was taken, and this proves it was the one the deployment selected.

**Scope.**

> It does not restate the seal (THM-0045), the decision relation (THM-0040) or the operation's own selection (THM-0056). It establishes nothing about the policy's own correctness, and nothing about deployments that configure no policy, which are entitled to serve while claiming nothing.
>
> The structural half — that the serving path names no `AuthorizationPosture` variant, that the authority builds them in exactly one operation, and that the assembly calls `release` exactly once — is held by `scripts/authorization_provenance_gate.py` clauses 4, 7 and 10, a self-tested source-text gate. That is EVIDENCE, not unconstructibility: `NoPolicyConfigured` is a public variant, and a body released under a synthesized one is byte-for-byte the body a real decision would have released, so no type can refuse it. Deleting the gate leaves the bypass constructible.
>

### THM-0045 — The backend is reached only by consuming a fully assembled pre-dispatch commitment

* **Kind:** relation
* **Owner:** `proxy.dispatch_commitment`
* **Depends on:** THM-0040
* **Support:** unit://proxy.dispatch_commitment — 4 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** The inner dispatch consumes a `ReadyForDispatch`, whose representation and constructor take each pre-dispatch prerequisite by value: an `AuthorizedRequestBody`, a `SigningWindow` snapshotted before the backend runs, and a `RetentionDisposition` that is either `NotConfigured` or a taken `Reserved`. `AuthorizedRequestBody` is sealed with exactly one producer, `AuthorizationPosture::release`. Crossing is one-way: `dispatched` consumes the ready state and yields a `DispatchedExchange`, so no caller holds both.

**Security consequence.** A serving path that skipped the authorization decision, the signing-window snapshot or the retention reservation has nothing to hand the dispatch — the failure is a compile error at the dispatch line, not a proxy that quietly serves unjudged requests or discovers a missing credential after the tool has already run. And a post-dispatch failure cannot be answered as though the backend had not run, because the value that would say so is gone.

**Scope.**

> It establishes that the decision was TAKEN, never that a policy permitted: `NoPolicyConfigured` releases a body too, because a deployment with no policy is entitled to serve while claiming nothing. It does not establish that the posture released was the one a configured policy produced — that proposition is registered separately and is open. It says nothing about what the verifier established, and nothing about the retention record's contents.
>

### THM-0056 — The posture that claims nothing is produced only where no policy is configured

* **Kind:** owner-local
* **Owner:** `proxy.authorization_posture`
* **Depends on:** — (leaf)
* **Support:** unit://proxy.authorization_posture — 10 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** `authorize` returns `AuthorizationPosture::NoPolicyConfigured` exactly when the deployment attached no evaluator, and `AuthorizationPosture::Authorized` only from a grant an evaluator actually returned, carrying the request the decision was taken over and that decision whole. An evaluator that denies, and one that could not complete, are the `Err` half and never a posture. The action coordinate is read whether or not a policy is configured, so enabling one cannot change which requests are well-formed enough to serve.

**Security consequence.** A record cannot report *no policy is deployed* as *a policy permitted this*, and an authorized posture cannot be assembled from an attribution taken from one decision and evidence taken from another — the pairing this type exists to be evidence of.

**Scope.**

> A claim about the operation, not about the serving path: it does not establish that the posture the dispatch consumed is the one this operation returned, which is THM-0052. It establishes nothing about the policy mechanism's own correctness, and nothing about which evaluator a deployment attached.
>

### THM-0043 — The exchange relation is decided everywhere and the execution threshold partitions it

* **Kind:** owner-local
* **Owner:** `proxy.exchange_lifecycle`
* **Depends on:** — (leaf)
* **Support:** unit://proxy.exchange_lifecycle — 31 declared symbol(s), lane(s): mutation, test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** Every (ExchangeState, ExchangeEvent) pair is either explicitly legal or explicitly rejected by `transition`; no event moves a terminal state; the pipeline order is a directed path whose only branches are the notification arm and the open-leg/terminal split; and no state at or past the execution threshold can reach a pre-dispatch terminal. An advance the relation does not admit latches an anomaly in every build, release included, rather than being ignored or panicking.

**Security consequence.** A serving path cannot reach the backend from a state the relation does not admit, cannot reach a pre-dispatch refusal terminal after the backend has been handed the request, and cannot silently drive the machine off the legal path — a disagreement between the model and the code is recorded, and every consequence derived afterwards is derived from a machine that says so.

**Scope.**

> Establishes the relation and the latch. It does not establish that the serving path drives this machine, that a given stage advances it, or that any particular refusal site is inside the lifecycle — those are propositions about the caller and are registered against the serving composition, not here. It establishes nothing about what any stage verified.
>

### THM-0066 — The serving PEP resolves actors through the deployment's materialized trust authority

* **Kind:** relation
* **Owner:** `proxy.serving_trust_seam`
* **Depends on:** THM-0037
* **Support:** unit://proxy.serving_trust_seam — 12 declared symbol(s), lane(s): test; unit://proxy.trust_plan — 4 declared symbol(s), lane(s): mutation, test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** The composition root builds the serving actor resolver exactly once, from the reloading signer directory's snapshot and the deployment's revocation-tier resolver. That seam resolves every Request-slot keyid through the tier on every request rather than through a map captured at process start; an unknown kid is a definitive negative, a store outage is reported as unavailable rather than as a binding failure, and every non-active outcome — revoked, not found, malformed, unavailable — yields no actor. The Response slot answers only for this deployment's own issuer kid.

**Security consequence.** A key revoked in the trust store stops verifying at the instant the tier says so rather than at the next restart, and an operational failure of the tier is never softened into an allow. A deployment cannot announce one revocation tier at startup and run another on the data plane — the defect ADR-MCPS-021 recorded, in which the resolver chain was constructed, its guarantee printed, and then dropped.

**Scope.**

> Where the seam comes from and what it consults. It does not establish that the tier's own answer is correct, that the trust document is authentic, or that the resolved key is the right one for the signer — those are the tier's and the trust owner's. The composition half is held by source controls over `app.rs`, because `ActorResolver` is a closure seam: anything producing that signature is an inhabitant, so privacy buys nothing and the controls are EVIDENCE rather than unconstructibility.
>

### THM-0079 — Distinct signed exchanges have distinct replay keys

* **Kind:** owner-local
* **Owner:** `http_profile.replay_key`
* **Depends on:** — (leaf)
* **Support:** unit://http_profile.replay_key — 4 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** The replay five-tuple — profile id, signature label, actor id, audience hash, nonce — is pre-serialized onto the core cache's three slots with a separator that cannot appear in any component, so equality of the composite slots holds exactly when the full five-tuple is equal; every component discriminates; and a key admitted once is reported as a replay thereafter.

**Security consequence.** Evidence produced under a different profile, a different signature role, a different actor or a different audience can never satisfy a replay check meant for another, and the same signed exchange cannot be admitted twice against the same cache.

**Scope.**

> The KEY and the cache's decision over it. It does not establish that the cache is consulted on every path reaching dispatch, that a distributed backend's insert is atomic, or that the retention window outlives the signature's own validity — those are the replay plane's and are not stated here. Freshness admission itself is THM-0001.
>

### THM-0080 — Serving derives peer identity only from the credential the mechanism accepted

* **Kind:** relation
* **Owner:** `proxy.serving_identity_provenance`
* **Depends on:** THM-0031, THM-0033
* **Support:** unit://proxy.serving_identity_provenance — 4 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** Neither direct-TLS serving path reconstructs peer identity or credential currency from certificate representation: each asks its authority exactly once, through a resolver whose signature admits its predecessor and the options and nothing else, so an acceptance from one relationship cannot be paired with an identity derived from another credential.

**Security consequence.** A served request cannot be attributed to an identity read out of a certificate the communication mechanism did not accept for THIS relationship — the composition ADR-MCPRE-064 Slice 2 forbids, and the one no behavioural control notices, because each still measures a true thing about a correctly-composed value.

**Scope.**

> The ROUTE, and recorded as evidence rather than as unconstructibility — a measurement correction against the proposal packet, which had this as STRUCTURAL. Under the deletion test it is not: the historical extractor is a published API with its own X.509 conformance suite over real DER, so it cannot be removed to make the wrong call unavailable, and deleting the controls leaves a second identity route compiling. What can be held is that the SERVING PATHS do not take it, which is a call-site fact.
>
> The third conjunct is the load-bearing one. The mechanism that forbids the wrong composition is the ABSENCE OF A PARAMETER through which a second credential could enter — a property of a signature, and a signature is exactly what a future edit widens first. "Just pass the leaf too, we already have it" reintroduces the defect without touching a single check.
>
> Measured twice at different widths. The battery holds the route inside this crate and pins that its own rules still detect each regression; `scripts/serving_identity_provenance_gate.py` carries two further clauses over the same subject — the historical facade's exemption, and the `online_ocsp` residue, which ADR-MCPRE-064 Slice 3 deliberately did not migrate and which is allowed only while its feature gate stands.
>
> It does not restate THM-0031, which says the resolved identity is RIGHT; this says only where it may come from.
>

### THM-0083 — What a request is, is decided once, before anything reads it for meaning

* **Kind:** owner-local
* **Owner:** `http_profile.request_envelope`
* **Depends on:** — (leaf)
* **Support:** unit://http_profile.request_envelope — 11 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** A body reaching the serving path is refused unless it is a legal JSON-RPC 2.0 request, and the outstanding id that selects its terminal is established by that one validation, ahead of every stage that reads the body for meaning; no production serving code reads the id again, and a reply is correlated to it by value AND by type, with a null id correlating to nothing.

**Security consequence.** A body cannot be dispatched as a request and acknowledged as a notification — the tool runs and the caller is answered under a receipt that claims nothing ran. Nor can a document that is not an MCP message burn a nonce, spend a human approval, or write a durable retention marker on its own behalf, because the shape is decided before any of those happen.

**Scope.**

> Found by the missing-edge pass rather than by inspecting the registry: R1 quantifies over the pre-dispatch obligations a validated deployment selects, and this is one — it gates the continuation stage, the forwarded body and the choice of terminal — yet no node in the tree stated it. The authority, its contract and its battery all already existed; what did not exist was the claim. The same shape as the replay omission THM-0079 closed.
>
> Two halves. The VOCABULARY half is the owner's own: which bodies are messages, which answers correlate, and the two ways a correlation could be faked — a null id, and a reply that is also a request. The SINGLE-DECISION half is a source-text property of the serving path, and is evidence rather than unconstructibility: `outstanding_id` is a published API with legitimate callers on the client side and in the response validator, so it cannot be deleted to make a second read unavailable; what is held is that the serving path does not ask the same document twice, and that it carries the decided value to its terminal.
>
> It does not establish that the METHOD named is one this deployment serves, which is authorization's, nor anything about the body's application payload, which the profile deliberately does not inspect.
>


---

## Root THM-0078 — Refusal is terminal, and no refusal-side effect reads as success

Owner: `proxy.exchange_lifecycle`

Stated above under an earlier root: THM-0043, THM-0045.

Independently reviewed already, and not reopened: THM-0040, THM-0039.

### THM-0078 — Refusal is terminal, and no refusal-side effect reads as success

* **Kind:** root
* **Owner:** `proxy.exchange_lifecycle`
* **Depends on:** THM-0043, THM-0044, THM-0046, THM-0045, THM-0063, THM-0069, THM-0081
* **Support:** unit://proxy.exchange_lifecycle — 31 declared symbol(s), lane(s): mutation, test; unit://proxy.refusal_provenance — 12 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** If an inbound exchange fails to establish a required pre-dispatch obligation, it reaches a declared refusal terminal — or a declared pre-exchange transport refusal — before backend dispatch. It cannot fall through into a success-path dispatch or a success response. Any refusal-side effect, including signed refusal evidence, audit and retention records, cleanup and continuation retirement, is authorized by the refusal and lifecycle state it was reached from, and none of them can be read as success.

**Security consequence.** The complement of THM-0074 is not "some other path": it is a refusal that is recorded, that cannot reach the dispatch, and whose own effects cannot be mistaken for the effects of a served request — including the case that motivated the exchange machine, where an approval is spent and the refusal must not read as an ordinary retry.

**Scope.**

> It forbids a SUCCESS-PATH effect, not any effect at all. The serving architecture emits signed refusal evidence and performs audit, retention, cleanup and continuation retirement on the refusal side, and those are legitimate. This and THM-0074 are two separate safety implications and never a biconditional: stating them as one would make this a liveness claim, which it is not.
>

### THM-0044 — An exchange's retry consequence never under-reports what may have happened

* **Kind:** relation
* **Owner:** `proxy.exchange_lifecycle`
* **Depends on:** THM-0043
* **Support:** unit://proxy.exchange_lifecycle — 31 declared symbol(s), lane(s): mutation, test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** `ExchangeProgress::retry_semantics` is monotone along every legal path and reports `NotRetrySafe` whenever an anomaly is latched or the backend was dispatched, and `RequiresNewElicitation` whenever a continuation approval was consumed and the backend was not. `Consumed` latches, so no later observation can report a spent approval as unspent; the backend projection is derived from the exchange state rather than asserted beside it, so the two cannot disagree.

**Security consequence.** A client cannot be told that nothing executed when the backend may have run, and cannot be told an ordinary retry is available after a human's one-shot approval was destroyed — the combination that leaves the retry's fresh nonce admitted and the answer refused as already-answered, with the approval gone.

**Scope.**

> A claim about the machine's derivation, not about the wire. It does not establish that the serving path maps a consequence onto a particular HTTP status, that a client acts on it, or that any effect was in fact performed. It establishes nothing about the truth of the observations fed to it — only that no observation can move the consequence backward.
>

### THM-0046 — A refusal carries which authority reached it, over a closed set, unrendered

* **Kind:** owner-local
* **Owner:** `proxy.refusal_provenance`
* **Depends on:** — (leaf)
* **Support:** unit://proxy.refusal_provenance — 12 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** Every `Refusal` carries a `RefusalCause` rather than a rendered token, and `RefusalCause` is closed over exactly the two authorities on this path — a Core verification verdict, in whichever of Core's own producers reached it, and the ADR-MCPRE-065 authorization boundary, held whole so its two arms stay distinguishable. `PolicyError` has no route into the Core taxonomy anywhere in the workspace. Rendering to a wire code happens only at the presentation boundary, and the signing posture is independent of the cause.

**Security consequence.** An authorization refusal cannot arrive at the audit boundary wearing Core's provenance, a foreign taxonomy cannot reach a record's reason field unnoticed, and "no policy verdict was reached" cannot be recorded as "a policy denied" — the three collapses a pre-rendered token made unrecoverable.

**Scope.**

> Establishes the vocabulary and its provenance. It does not establish that every production refusal site is inside the exchange lifecycle, that the audit record is written, or that the refusal is signed — those are propositions about the serving path and the response-emission authority. It does not establish that Core's own verdicts are correct.
>

### THM-0063 — A signed response never advertises validity its credential does not authorize

* **Kind:** relation
* **Owner:** `proxy.response_signing`
* **Depends on:** THM-0062
* **Support:** unit://proxy.response_signing — 8 declared symbol(s), lane(s): test; unit://proxy.delegated_signing_credential — 15 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** `SigningWindow` keeps `expires` private and no constructor accepts one: every window is derived as the earlier of the configured TTL from `now` and the credential's own `exp`, with saturating arithmetic so an absurd configured TTL cannot wrap past it. A credential already past its bound yields a window claiming no future validity rather than one running backwards. The same owner opens every window this deployment signs under, reply and refusal alike, and a refusal signs under the snapshot its own exchange took.

**Security consequence.** A client cannot be given a receipt asserting validity beyond the moment its credential stops authorizing signatures — a window the verifier refuses as soon as the credential's own closes, which the client would learn about only by failing. And a refusal minted late in an exchange cannot advertise more validity for having been reached by a different path.

**Scope.**

> The advertised window, not the signature. It does not establish that a credential existed (THM-0062) or what the signature covers (THM-0065). Where no valid credential exists the receipt is UNSIGNED, and what such a receipt may still state is a separate conjunct of this unit rather than part of this claim.
>

### THM-0062 — A response-signing credential exists only while a valid delegated key does

* **Kind:** owner-local
* **Owner:** `proxy.delegated_signing_credential`
* **Depends on:** — (leaf)
* **Support:** unit://proxy.delegated_signing_credential — 15 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** The response signer publishes a credential snapshot only from a successful rotation, and yields none before the first rotation, past the published key's expiry, after a fail-closed issuance has retired the snapshot, after a terminal retirement — including for a mint that lands afterwards — and when its snapshot lock is poisoned. An issuance failure serves the still-valid key and then fails closed at its expiry rather than extending it, and the retry schedule never sleeps past a still-valid key.

**Security consequence.** A response cannot be signed under a credential the deployment no longer holds, under one whose window has closed, or after the signer has been retired — and there is no longer-lived or root credential to fall back to, because no such mode exists. What a caller gets instead is an unsigned last-resort receipt, which it can tell from a signature.

**Scope.**

> The credential's existence, not its content: it does not establish that the credential chains to the deployment's root, that its scope is right, or that a verifier will accept it. It says nothing about what is signed under it, which is THM-0063 and THM-0065.
>

### THM-0069 — A security record states each authority's outcome in that authority's own coordinate

* **Kind:** relation
* **Owner:** `proxy.audit_record_coordinates`
* **Depends on:** THM-0046
* **Support:** unit://proxy.audit_record_coordinates — 8 declared symbol(s), lane(s): test; unit://proxy.refusal_provenance — 12 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** Every request record states an authorization outcome — not configured, authorized, or refused — and a response record carries none, because there is nothing after the dispatch for a policy to have decided. The Core verdict and the authorization verdict occupy separate coordinates on one record and neither can be read as the other: an unconfigured deployment is not rendered as an authorized one, a policy denial's token goes in the authorization coordinate, the two authorization refusal arms stay distinguishable, and the arm reached before any policy ran imports no policy vocabulary at all.

**Security consequence.** A reader of the record cannot be shown *a policy permitted this* where none was deployed, cannot mistake a request that reached no policy verdict for one a policy denied, and cannot be left unable to tell whether a policy was consulted — the collapse a single rendered `reason` string produced, and which the type system prevented while the record restored.

**Scope.**

> What a record MAY say, not that the vocabulary is total over the outcomes that occur — that is the open proposition below, and it is an ADR-MCPS-035 decision rather than a registry edit. It does not establish that the record was delivered (THM-0070), and it establishes nothing about the truth of either authority's verdict.
>

### THM-0081 — Every production refusal is inside the exchange lifecycle

* **Kind:** relation
* **Owner:** `proxy.refusal_site_totality`
* **Depends on:** THM-0043, THM-0046
* **Support:** unit://proxy.refusal_site_totality — 6 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** Every refusal a production serving path can reach is minted from a `Refusal` a stage named and served through the exchange machine's derived disposition, or is one of the transport frame's four enumerated pre-exchange replies, each reached before an exchange exists — there is no third kind, and no exit answers from source position.

**Security consequence.** No refusal can state a retry contract the exchange machine did not derive, which is how an exit reached after a human's approval was spent came to report an ordinary retry — the defect the machine exists to remove, closed at the sites the machine cannot see.

**Scope.**

> The SITE SET, and nothing about which cause any site chooses. THM-0043 establishes that the transition relation is decided everywhere and THM-0046 that a refusal carries which authority reached it; neither says every SITE is inside the lifecycle, and an exit answering from source position would satisfy both.
>
> Four facts, together total over the exits a served request can take: the serving subtree mints no answer outside `served`; every `Err` arm of `handle` returns the binding its stage produced; the answers given outside the exchange are exactly the transport frame's, minted in its own three files and each reached ahead of the handler; and `disposition` derives the retry contract from `retry_semantics()` with no wildcard arm.
>
> The outside set is FOUR replies, not one, and the correction came from the measurement rather than from the packet: the channel/routing refusal is a served response, while the malformed message, the oversized body and the shed are built at the hyper type and would have been invisible to a control that only counted the first. All four are pre-handler, and the shed's 503 is retry-safe on its own terms — the body is never read, so nothing ran.
>
> One exit answers AFTER the exchange has decided and is named rather than absorbed: `served_to_hyper`'s fallback, taken when a decided answer cannot be framed at all. It is recorded because it is the single place an exchange's derived answer can be replaced, and the claim made about it is narrow and measured — it answers an empty 500, which asserts nothing about retry, and never a status clients retry.
>
> Source-text evidence, and recorded as evidence rather than as unconstructibility. `ServedHttpResponse` is a wire frame with public fields, as the async fleet, the blocking harness and external embedders all construct one — privacy would buy nothing, so deleting the battery leaves an out-of-lifecycle exit compiling. The third fact is measured at two widths: the battery names the transport frame's files inside this crate, and `scripts/refusal_provenance_gate.py` clause 12c holds the served mint to one call site across the whole workspace, so no other crate can acquire one.
>
> The blocking mTLS harness is out of scope and by its own module documentation is not an MCP-RE serving path: it frames every reply as a literal 200, so it carries no RFC 9421 evidence and cannot serve a signed refusal at all.
>


---

## Root THM-0075 — No unearned response attribution

Owner: `proxy.response_signing`

Stated above under an earlier root: THM-0062, THM-0063.

Independently reviewed already, and not reopened: THM-0021, THM-0001, THM-0022.

### THM-0075 — No unearned response attribution

* **Kind:** root
* **Owner:** `proxy.response_signing`
* **Depends on:** THM-0062, THM-0063, THM-0065, THM-0022, THM-0082
* **Support:** unit://proxy.response_signing — 8 declared symbol(s), lane(s): test; unit://http_profile.response_emission_binding — 8 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** Whenever MCP-RE emits signed response or refusal evidence, the signature is produced by the response-signing capability materialized for that deployment under the supported delegation model; bound evidence is bound to the exact request it answers, and evidence produced before a request can be established is explicitly unbound and cannot be interpreted as bound.

**Security consequence.** A response cannot be attributed to the trust root directly, cannot be signed by a credential the deployment does not hold or no longer holds, cannot advertise validity its credential does not authorize, and a pre-parse receipt cannot be replayed as an answer to a request.

**Scope.**

> SECURITY-BEARING SIGNED evidence only. Unsigned transport and error responses exist — a last-resort receipt is emitted when no valid credential does — and they are outside this claim, which is why it does not say every response carries evidence. It does not establish that a client accepts the response, which is THM-0076 and a different proposition on the other side of the same exchange.
>

### THM-0065 — An emitted bound response signature binds the request it answers

* **Kind:** relation
* **Owner:** `http_profile.response_emission_binding`
* **Depends on:** THM-0021, THM-0022
* **Support:** unit://http_profile.response_emission_binding — 8 declared symbol(s), lane(s): test; unit://http_profile.verifier_results — 73 declared symbol(s), lane(s): mutation, test
* **Assumptions:** ASM-0027, ASM-0028, ASM-0029
* **Review requirement:** Owner security-specification review

**Statement.** A response this proxy signs in the bound form carries a signature whose `;req` components resolved against the request being answered, and a response evidence block whose request-evidence handle is over that same request. Signing and verification agree end to end: a response minted for one exchange does not verify as the answer to another, at the evidence block or at the cryptographic floor, and two requests differing only in one signed parameter have different handles.

**Security consequence.** A response cannot be lifted from one exchange and presented as the answer to another, and a `;req` splice cannot be repaired by reconstructing the block — the floor refuses it independently.

**Scope.**

> The bound form only: an unbound emission carries no binding by construction, and that a verifier can never read one as bound is THM-0022 on the verification side. It does not establish which credential the signature was made under (THM-0062, THM-0063), and it says nothing about responses this proxy does not sign.
>

### THM-0082 — The serving path signs under the credential source materialization produced

* **Kind:** relation
* **Owner:** `proxy.signing_credential_provenance`
* **Depends on:** THM-0062, THM-0064, THM-0073
* **Support:** unit://proxy.signing_credential_provenance — 4 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** The response-signing authority the serving path holds was built by the composition root from the custody state the deployment validated: the root opens one key source through the materializer, opens the role-separation witness once, constructs no key source of its own, and installs the signing plane from that same source.

**Security consequence.** A deployment cannot announce one signing custody at startup and sign with another on the data plane — the same shape as the resolver defect ADR-MCPS-021 recorded on the trust side, where the chain was constructed, its guarantee printed, and then dropped. Every signature would still verify and every startup line would still be true; the two facts would simply be about different keys.

**Scope.**

> The counterpart of THM-0066 on the signing side, and the composition half THM-0073's seal cannot reach. THM-0062 establishes what the credential source yields and when it yields nothing; THM-0064 establishes what a custody selection asserts about exposure; THM-0073 establishes that a source obtained through the materializer kept its two roles apart. None of them says the root USED the materializer — `FileKeySource` and the KMS adapters are public constructors, as external embedders need, so a root that opened one beside it would compile.
>
> Evidence, not unconstructibility, and for that exact reason. The measurement is over the composition root's own source, the shape `serving_trust_seam_test` uses for the resolver: delete it and the old defect compiles again. It says nothing about what the signing plane does with the source once installed, which is `proxy.response_signing`'s.
>

### THM-0064 — A non-exporting custody selection keeps the private key off this process

* **Kind:** owner-local
* **Owner:** `proxy.custody_exposure`
* **Depends on:** — (leaf)
* **Support:** unit://proxy.custody_exposure — 13 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** The custody owner classifies each legal selection into exactly one state carrying the material that made it inhabitable, and projects a single semantic fact — `PrivateKeyExposure` — that is `NonExporting` for the device- and service-held states and `ProcessReadable` only for the state that loads a seed. A state missing a parameter it cannot start without is not built, and a state carries no neighbour's material.

**Security consequence.** Where a deployment selects non-exporting custody, nothing that can read this process's memory or its seed file can obtain the signing key — the process can ask for a signature and never for the key. And a consumer asking whether the key may be read here cannot get a different answer by asking which mechanism it is, because the projection names none.

**Scope.**

> CONDITIONAL on the deployment's own selection: it establishes nothing about a deployment that selects file custody, which is `ProcessReadable` and honestly says so. It establishes what the classified STATE asserts, not that the remote signer implementation honours it — that a KMS does not export a key is the provider's property, outside this boundary. It does not establish that response signing and channel signing use different keys.
>

### THM-0073 — Serving materialization refuses a deployment whose two signing roles are one key

* **Kind:** relation
* **Owner:** `proxy.signing_role_separation`
* **Depends on:** THM-0049
* **Support:** unit://proxy.signing_role_separation — 7 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** Serving materialization cannot succeed when the response-signing role and the channel-signing role resolve to the same cryptographic signing-key identity: the composition root obtains its key source only as the product of a comparison over the two materialized public keys, and that comparison refuses before any server starts.

**Security consequence.** A party able to obtain a TLS handshake signature cannot thereby obtain a response attribution, and vice versa — the two roles stay separately attributable, which is the whole content of calling them two roles.

**Scope.**

> Over the MATERIALIZED identities, and that is the substance of the claim rather than an implementation note. A comparison of mechanism LOCATORS would establish nothing: an ARN, a key id and an alias are three names for one AWS key, a PKCS#11 label is scoped to a token, and a filesystem path resolves through symlinks — two locators that differ can be one key, and a check comparing them would report a separation that does not exist while looking exactly like one that does. So both roles are asked for their public verification key after materialization and compared as `Ed25519PublicKeyValue`, the canonical RFC 8410 identity this crate already owns. No AWS-, GCP- or PKCS#11-specific equality semantics were invented.
>
> UNCONDITIONAL, and deliberately not conditioned on a policy input. The ratified wording is "where policy requires the roles to be distinct"; measurement found no supported deployment for which sharing is desirable, and inventing a one-valued policy knob to make the condition expressible would fabricate an input that selects nothing. Every deployment is held to it, so the conditional is satisfied everywhere rather than left as a dormant branch.
>
> It is load-bearing rather than a construction-site convention, which is what moved it here. `MaterializedSigningRoles` holds the source privately and `establish` is its only producer, so a serving path cannot hold a key source that did not come through the comparison — deleting the call does not leave a path that skips it, it leaves one that does not compile. What that does NOT settle is whether the composition root uses the materializer at all: `FileKeySource` and the KMS adapters are public constructors that external embedders need, and THM-0082 is what measures the root.
>
> The owner moved from `proxy.cross_machine_legality`, and had to: a request-level classifier reads locators, and the decisive fact here exists only once both backends have answered. X2a (THM-0049) states the adjacent relation — that the channel key object lives in a backend the deployment already reaches — and is not this claim.
>
> A channel credential whose public key is not a canonical Ed25519 key yields no comparison, and that is a statement rather than a gap: the response role's key always is one, so the two cannot be equal. It claims nothing about whether either key is the RIGHT one, about custody, about exposure, or about the chain being trusted.
>

### THM-0049 — Every illegal cross-owner configuration combination is refused at layer A

* **Kind:** owner-local
* **Owner:** `proxy.cross_machine_legality`
* **Depends on:** — (leaf)
* **Support:** unit://proxy.cross_machine_legality — 5 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** The cross-machine pass reads classified owner states and validated request selections, never raw fields a machine already classified, and refuses every relation it declares — the channel key object living in a backend the deployment does not reach, a revocation deny list no configured profile will read, and a trust-epoch posture incompatible with delegated signing. Each refusal is unconditional in the classifier rather than conditional on a caller having asked.

**Security consequence.** An operator cannot obtain a weaker posture by supplying a combination of individually legal selections that no machine alone can refuse — a PKCS#11 channel key under a KMS signing source, silently doing nothing while the operator believes the handshake key is device-resident.

**Scope.**

> Establishes refusal by the classifier. It does not establish that the illegal combination is unrepresentable — `DeploymentRequest` can hold one, which is why the refusal is a check the classifier performs and not a structural fact. It does not establish that the classifier is consulted on every startup path.
>


---

## Root THM-0076 — A client accepts only an answer to its own request, under a signer it trusts

Owner: `client.response_acceptance`

Independently reviewed already, and not reopened: THM-0016, THM-0021, THM-0001, THM-0019, THM-0020, THM-0022.

### THM-0076 — A client accepts only an answer to its own request, under a signer it trusts

* **Kind:** root
* **Owner:** `client.response_acceptance`
* **Depends on:** THM-0058, THM-0059, THM-0057, THM-0060, THM-0061
* **Support:** unit://client.response_acceptance — 20 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** If `mcp-re-client-core` returns a response as verified, then that response was signed under a signer this client's current trust configuration authorizes in the Response slot, over a signature base that resolved against the request this client sent; a response that could not be bound is never reported as a success; and what the client may conclude about whether the work ran is what the receipt states, never what its silence might be read as.

**Security consequence.** An application cannot be handed, as this call's answer, a response from another exchange, from another signer, from a signer whose authorization has been retired, or one that verified only in the unbound form — and cannot be led to repeat a side effect by reading silence as *it did not run*.

**Scope.**

> The consumer side, kept apart from THM-0075 because a deployment may run either side alone and producer attribution and consumer acceptance are different propositions. It does not establish that the deployment was right to trust an anchor, and it does not establish that the expectation was built from the request this client sent: `ResponseExpectation::new` is public for the FFI bindings, so that pairing is a caller obligation and sealing past the seam would be theatre.
>

### THM-0058 — A client accepts a response only under a signer its trust configuration authorizes

* **Kind:** relation
* **Owner:** `client.response_acceptance`
* **Depends on:** THM-0016, THM-0019, THM-0057
* **Support:** unit://client.response_acceptance — 20 declared symbol(s), lane(s): test; unit://client.trust_manifest_lifecycle — 16 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** A response this client reports as verified was signed under a credential chaining to a root issuer the current trust picture resolves for the Response slot; where the route pins an issuer, a credential chaining to any other trusted anchor fails closed; and a credential whose issuer kid, delegated kid or jti the trust authority reports revoked resolves nothing, on both the success and the rejection path. A response carrying no credential is refused rather than read as a direct-root answer.

**Security consequence.** An application cannot be handed a response signed by a party this deployment never authorized for the Response slot, by one whose authorization has been retired, or by the trust root directly — the mode this project does not support and therefore must not accept.

**Scope.**

> Signer authorization only. It does not establish that the response answers THIS request, which is the binding disposition (THM-0059), and it does not restate the underlying signature and `;req` facts, which are stated over the profile verifier (THM-0016, THM-0019, THM-0021). It says nothing about whether the deployment was right to trust the anchor.
>

### THM-0057 — A client's trust anchors are the ones the current signed manifest published

* **Kind:** owner-local
* **Owner:** `client.trust_manifest_lifecycle`
* **Depends on:** — (leaf)
* **Support:** unit://client.trust_manifest_lifecycle — 16 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** Anchors are released only from a manifest whose signature verified under a trusted signer kid that the signature itself covers, whose profile is this one, and whose version is not below the monotone floor — a floor that rises on load and cannot be read as zero when it cannot be read at all. The manifest's own deadline travels with the anchors it published and outranks every root inside it, so an expired document resolves nothing, and the revocation half is carried by the same authority as the resolution half.

**Security consequence.** A client cannot be moved back onto a superseded trust picture by replaying an older signed manifest, cannot be given anchors by a document nobody trusted signed, and cannot keep resolving roots from a document whose lifetime has passed — including when the floor's own storage fails, where anchors are withheld rather than released against an unknown floor.

**Scope.**

> Establishes what the document says and for how long. It does not establish that a response verified under one of these anchors is an answer to this request (THM-0058, THM-0059), that the publisher's key management is sound, or that a revocation list is complete — only that an identifier it names cannot resolve.
>

### THM-0059 — An unbound receipt is never a success and never another request's answer

* **Kind:** relation
* **Owner:** `client.response_acceptance`
* **Depends on:** THM-0020, THM-0022
* **Support:** unit://client.response_acceptance — 20 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** A response verified without a request binding is reported as unbound and is never classified as a success, and there is no path on which a failed bound verification is retried as an unbound one. A preflight receipt is accepted as being about this call only when it commits to the digest of the bytes this client sent; one about another request, and one about no request at all, answer nothing.

**Security consequence.** A pre-parse receipt cannot be replayed as the answer to a request, and a response that could not be bound cannot be presented to an application as this call's result by falling back to the weaker check.

**Scope.**

> The disposition, not the signer (THM-0058). The unbound receipt's binding is a BYTE binding: two transmissions of identical request bytes share it, so it is not an instance binding, and the client discloses it to the caller as unbound rather than claiming otherwise.
>

### THM-0060 — The client's clock skew is bounded at construction and read once

* **Kind:** owner-local
* **Owner:** `client.delegation_policy_seal`
* **Depends on:** — (leaf)
* **Support:** unit://client.delegation_policy_seal — 3 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** `DelegationPolicy` clamps the configured clock skew to the profile's bound when it is constructed and keeps the result in a private field, so no inhabitant carries an unbounded tolerance; a negative configured skew narrows to zero rather than moving the window backwards; and both freshness windows read that one bounded number through the policy's single projection.

**Security consequence.** An operator cannot widen a client's acceptance window past the profile bound by configuration, and the credential window and the signature window cannot disagree about the tolerance they applied — the disagreement that lets a credential be accepted outside the window its own signature was admitted under.

**Scope.**

> The bound and its single reading. It does not establish that the profile's bound is itself appropriate, and it establishes nothing about what either window checks beyond the tolerance it applies.
>

### THM-0061 — A receipt that says nothing is not a receipt that says nothing ran

* **Kind:** owner-local
* **Owner:** `client.execution_contract`
* **Depends on:** — (leaf)
* **Support:** unit://client.execution_contract — 7 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** `ExecutionStatus::Unstated` and `ExecutionStatus::NotExecuted` are distinct inhabitants, and a rejection body carrying no execution contract yields the silent one rather than a guess. An unrecognized value is carried as unrecognized and never read as a known one, a spent elicitation is reported as requiring a new one rather than as an ordinary failure, and a failed retention obligation survives beside whatever the execution status says. The wire code and the contract are read in one parse.

**Security consequence.** A client cannot repeat a side effect by reading the server's silence as *it did not run*, cannot retry an exchange whose human approval was already spent, and cannot be told a call is recorded when the deployment's audit store has no record of it.

**Scope.**

> What the receipt SAYS, and what a client may conclude from it. It does not establish that the server's statement is true — that is the serving path's exchange machine (THM-0044) — and it establishes nothing about the transport failures on which no receipt arrives at all.
>


---

## Root THM-0077 — No deployment serves a posture nobody selected

Owner: `proxy.trust_composition_root`

Stated above under an earlier root: THM-0049, THM-0073, THM-0064, THM-0066.

Independently reviewed already, and not reopened: THM-0038, THM-0035, THM-0037, THM-0036, THM-0005, THM-0013.

### THM-0077 — No deployment serves a posture nobody selected

* **Kind:** root
* **Owner:** `proxy.trust_composition_root`
* **Depends on:** THM-0067, THM-0038, THM-0036, THM-0005, THM-0013, THM-0048, THM-0049, THM-0054, THM-0073, THM-0064, THM-0066
* **Support:** unit://proxy.trust_composition_root — 3 declared symbol(s), lane(s): test; unit://proxy.cross_machine_legality — 5 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** Every security capability held by the serving runtime is derived from validated semantic owner state. Illegal, unsupported or internally contradictory deployment postures cannot be silently reinterpreted into a weaker posture during materialization or serving.

**Security consequence.** An operator cannot obtain a weaker security posture by supplying a combination nobody validated, and a serving component cannot disagree with the owner about what was configured.

**Scope.**

> SECURITY POSTURE, not liveness and not permanent runtime availability. A runtime dependency may later fail and cause refusal or loss of availability; that does not violate this claim. What it forbids is a SILENT weakening of the selected policy — an unavailable tier failing closed is inside the claim, an unavailable tier being softened into an allow is not.
>

### THM-0067 — The composition root re-reads no owner's security semantics from the request

* **Kind:** owner-local
* **Owner:** `proxy.trust_composition_root`
* **Depends on:** — (leaf)
* **Support:** unit://proxy.trust_composition_root — 3 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** Every field the composition root still reads directly from the validated deployment request is a pinned ordinary parameter — one whose value changing, with every owner state unchanged, cannot change a security-sensitive decision or effect — and each is recorded with the sentence saying why. The inventory is checked against the file it describes in both directions, so a new raw read fails and a field that acquired an owner must leave the list.

**Security consequence.** After layer A classifies a deployment, no post-validation consumer can reach back past an owner for a security decision the owner already made — which is how two components come to disagree about what was configured, with neither of them wrong locally.

**Scope.**

> The general claim over ALL owners; THM-0038 is its trust specialization and states in addition that the root passes trust as owner projections. It does not establish that the owners' own classifications are right, and it says nothing about consumers other than the root — a plane reaching back for a posture is a different failure with its own control.
>
> It is a source-text inventory, not a type: `ValidatedDeployment::config()` is legitimately readable, because the root builds things out of it. What is decidable is WHICH fields, and the list only means anything while adding to it costs a written reason.
>

### THM-0048 — Every listener obtains its whole security posture through one listener state

* **Kind:** owner-local
* **Owner:** `proxy.tls_listener_state`
* **Depends on:** — (leaf)
* **Support:** unit://proxy.tls_listener_state — 25 declared symbol(s), lane(s): mutation, test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** Every MCP-RE construction path obtains a listener's trust anchors, epoch-bound session store, signing budget and client-certificate verifier through one `TlsListenerSecurityState`; the terms cannot be supplied to it independently. The epoch is a function of the anchor set alone, a rebuild that republishes the same trust keeps the resumption cache while a rebuild with withdrawn trust advances the epoch and stops resumption, and no configuration this owner builds can resume outside the store.

**Security consequence.** A withdrawn trust anchor cannot be survived by a resumed session, and a listener cannot be assembled with anchors from one source and a session store or signing budget from another — the pairing that lets a session outlive the trust that admitted it.

**Scope.**

> Establishes that the terms travel together and that the epoch tracks the anchors. It does not establish that the client-certificate verifier denies unknown revocation status: that is a property of one construction site over a foreign trait object, not of any type this owner holds, and it is registered separately as an open proposition. It says nothing about the handshake's own correctness.
>

### THM-0054 — Every production listener denies unknown client revocation status

* **Kind:** relation
* **Owner:** `proxy.tls_listener_state`
* **Depends on:** THM-0048
* **Support:** unit://proxy.tls_listener_state — 25 declared symbol(s), lane(s): mutation, test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** Every client-certificate verifier a production MCP-RE listener uses denies unknown revocation status, enforces revocation over the full chain, and enforces CRL expiration, with no configuration or argument that can relax any of the three.

**Security consequence.** A client whose revocation status cannot be determined — because the CRL is stale, absent for its issuer, or does not cover its position in the chain — cannot complete a handshake, so a revoked credential cannot be admitted by the checking silently failing open.

**Scope.**

> A proposition about every production CONSTRUCTION SITE, not a property of a type this project owns: the verifier is a foreign `dyn` trait object and rustls ships both a permissive policy and a builder method that selects it, so nothing here can make a permissive inhabitant unconstructible. Recorded as evidence accordingly.
>
> Two halves, and both are now measured. The BEHAVIOURAL half drives real handshakes: a revoked client denied, a stale CRL denying even a client it does not revoke, and — the case the other two leave open — a client whose status the configured CRLs CANNOT determine, denied. The first two are cases where revocation checking ran and answered; only the third is the unknown-status decision itself, and it is what separates failing closed from admitting a credential that may have been withdrawn. The SOURCE half pins the site set: one production producer, no `allow_unknown_revocation_status` anywhere, `enforce_revocation_expiration` positively stated, and no parameter through which a caller could choose the posture.
>
> The one other `ClientCertVerifier` implementation in the crate is named rather than filtered out: it is behind `fault_accept_any_client`, a feature that exists to break the control deliberately and prove it is live, and the control asserts it stays behind that gate.
>
> It does not establish that the CRLs a deployment loads are current or complete, and it establishes nothing about the per-request revocation check, which is a separate authority holding the same invariant.
>


---

## Root THM-0012 — The lifecycle record cannot claim a shutdown that did not happen

Owner: `proxy.runtime_lifecycle`

Independently reviewed already, and not reopened: THM-0012.


---

## Root THM-0072 — A verified receipt proves registration on the service this deployment pinned

Owner: `http_profile.scitt_receipt_offline`

Independently reviewed already, and not reopened: THM-0041.

### THM-0072 — A verified receipt proves registration on the service this deployment pinned

* **Kind:** root
* **Owner:** `http_profile.scitt_receipt_offline`
* **Depends on:** THM-0041, THM-0068
* **Support:** unit://http_profile.scitt_receipt_offline — 24 declared symbol(s), lane(s): mutation, test; unit://http_profile.scitt_service_pin — 3 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** A receipt this deployment verifies offline proves the Signed Statement was registered on the transparency service whose key, leaf profile and position profile came from the pin document the deployment resolved — not merely on some service whose key was supplied to the call.

**Security consequence.** An auditor cannot be shown a receipt from a log this deployment never pinned, and cannot be shown one that satisfies a position profile the pinned service never declared.

**Scope.**

> It composes the two facts and adds nothing: offline verification against a resolved service (THM-0041) and the provenance of a pinned one (THM-0068). It carries both scopes forward unchanged — nothing about the service being honest, its log append-only, or an entry unique, and nothing about whether the retained evidence is what the statement describes, which is THM-0042 and is a separate promise because no authority owns the conjunction.
>

### THM-0068 — A pinned transparency service is one operator-reviewed document, or it is not a pin

* **Kind:** owner-local
* **Owner:** `http_profile.scitt_service_pin`
* **Depends on:** — (leaf)
* **Support:** unit://http_profile.scitt_service_pin — 3 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** `ResolvedTransparencyService::pinned` takes its verification key, leaf profile and position profile from a single `ScittServiceTrustPin`, so all three came from one document an operator wrote and reviewed. A malformed pin document never becomes a pin, and an illegal one is refused at deserialization rather than carried into a resolver that would answer from it.

**Security consequence.** A receipt cannot be verified against a service whose key came from one place and whose profile expectations came from another — the pairing that lets a receipt satisfy a position profile the pinned service never declared.

**Scope.**

> It establishes the PROVENANCE of a pinned service, not that a deployment pinned one. `verify_receipt_offline` takes the service as a `Fn(&str) -> Option<ResolvedTransparencyService>` seam, and `stated` is a legitimate second provenance — the in-process prototype log is one, with no pin to resolve from. Against a seam a private field only forces a constructor taking the same arguments with the same absence of checking, so what these fields buy is that every producer is NAMED, not that the illegal pairing is unconstructible. Whether a given deployment's resolver is backed by a pin is deployment wiring and is not established here.
>


---

## Root THM-0042 — Retained evidence is the evidence the statement was made about

Owner: `http_profile.scitt_retained_correspondence`

Independently reviewed already, and not reopened: THM-0042.


---

## Root THM-0071 — Every reachable refusal has a typed provenance in its own authority's coordinate

Owner: `proxy.audit_record_coordinates`

Stated above under an earlier root: THM-0069, THM-0046, THM-0081, THM-0043.

### THM-0071 — Every reachable refusal has a typed provenance in its own authority's coordinate

* **Kind:** root
* **Owner:** `proxy.audit_record_coordinates`
* **Depends on:** THM-0069, THM-0046, THM-0081, THM-0070
* **Support:** unit://proxy.audit_record_coordinates — 8 declared symbol(s), lane(s): test; unit://proxy.refusal_provenance — 12 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** Every outcome a served exchange can reach has a typed refusal provenance, and every authority that reached an outcome is represented in that authority's own record coordinate: no refusal becomes silent, and no authority's vocabulary is recorded as another authority's verdict.

**Security consequence.** An auditor reading the record cannot be shown silence where a refusal occurred, and cannot be shown a token that attributes a refusal to an authority that never ran.

**Scope.**

> TOTALITY over the typed coordinates, which is a different proposition from the one this id carried while ADR-MCPRE-066 was open. It is not a claim that one vocabulary covers the other, and it needs no new one: the algebra ADR-MCPRE-066 decided is that the Core verdict and the authorization verdict are SEPARATELY TYPED coordinates on one record, and its slices implemented it. `PolicyError -> &'static str -> Core reason` no longer exists as a route, so the union that was previously asked to be total is not the object of this claim.
>
> Four established facts compose it, and each closes one way an outcome could escape:
>
> * every SITE is inside the lifecycle or is the one declared pre-exchange refusal (THM-0081) — nothing answers from source position, so there is no outcome outside the algebra; * every refusal carries WHICH authority reached it, held whole (THM-0046), over a `RefusalCause` closed by construction over exactly Core and Authorization; * the two coordinates cannot be read as each other on a record (THM-0069), and a request record always states an authorization outcome while a response record has none to carry; * `CoreVerdict::error` is total over its three producers and `RefusalCause::core_verdict` returns `None` for exactly one cause — an authorization policy decided — which is a STATEMENT that Core reached nothing, not an omission; * the record STREAM is honest about what reached it (THM-0070). Added by the missing-edge pass while assembling the review packet, which found THM-0070 reachable from no root: a refusal that is correctly typed and then silently dropped by the sink is silent, so a totality claim about the record needs delivery to report its losses.
>
> It does not establish that the right cause is chosen at any given site, nor that the frozen public tokens are individually well-named. Both are the owning units' controls, and neither is a totality property.
>
> If a reachable refusal outcome is ever found that the typed record cannot represent, that outcome is a finding against this claim and not a reason to widen a vocabulary.
>

### THM-0070 — The record stream is honest about what reached it

* **Kind:** owner-local
* **Owner:** `proxy.audit_delivery`
* **Depends on:** — (leaf)
* **Support:** unit://proxy.audit_delivery — 9 declared symbol(s), lane(s): test
* **Assumptions:** none
* **Review requirement:** Owner security-specification review

**Statement.** Every emitted record carries a sequence number and the collector preserves emission order. A full queue drops rather than blocking the caller, the drop count is reported without a following record to carry it, an unattributed flood cannot consume the headroom an attributed record needs, and concurrent offers at the ceiling admit only the remaining slots. A drain that timed out is a distinct outcome from one that completed, and the outcome that is unknown is its own case.

**Security consequence.** An auditor cannot be shown a record stream that silently lost entries: a gap is visible in the sequence and a drop is counted and reported. An unattributed caller cannot suppress the records of an attributed one by flooding the queue. And a shutdown whose drain timed out cannot be read as one that emptied the queue — the difference between *these are all the records* and *these are the records that got out*.

**Scope.**

> Delivery integrity, not content (THM-0069) and not durability: the sink is in-process, so a record that was emitted may still be lost with the process. It establishes nothing about whether a record SHOULD have been written for a given outcome, which is the totality proposition below.
>


---

## Theorems outside every declared root closure

None.

## Deviations from the ratified architecture

Six, each stated as a decision rather than a note.

**1. THM-0073 is UNCONDITIONAL.** The ruling's target wording was *where policy requires
the roles to be distinct*. Measurement found no supported deployment for which sharing a
key between the response-signing and channel-signing roles is desirable, and a one-valued
policy input invented to make the condition expressible would be an input that selects
nothing. Every deployment is held to it, so the ratified conditional is satisfied
everywhere rather than left as a dormant branch. If a deployment that legitimately shares
one key exists, this is the deviation to reverse.

**2. THM-0081's outside set is FOUR replies, not one.** The proposal said *one declared
pre-exchange transport refusal*. The measurement found four: the channel/routing refusal
is a served response, while the malformed message, the oversized body and the shed are
built at the hyper type and would have been invisible to a control that counted only the
first. All four are pre-handler. A FIFTH exit was found and is named rather than absorbed:
`served_to_hyper`'s framing fallback answers after the exchange has decided, and the claim
made about it is narrow and measured — an empty 500, which advertises no retry.

**3. THM-0053 got its own unit rather than joining the currency unit.** ASM-0012 declares
the assertion verifier OPAQUE to the currency theorem and its review requirement names a
separate unit as the discharge. `http_profile.admission_assertion` overlaps
`http_profile.admission_currency`'s paths deliberately: they are two authorities in one
file, and the registry already said so.

**4. THM-0073's owner MOVED** from `proxy.cross_machine_legality`, as the ruling
anticipated it might: a request-level classifier reads locators, and the decisive fact
exists only once both backends have answered. The new owner is a materialization relation.

**5. Two production changes were made**, both implied by the ratified architecture rather
than new design. `build_key_source` now returns `MaterializedSigningRoles` — the source is
opened privately and leaves the module only through the role comparison — and
`refusal_provenance_gate.py` gained clause 12. ADR-MCPRE-067 §10 is clarified in
`docs/architecture/components/cli-and-materialization.md` §11; the ADR's own text in the
discussion thread has NOT been edited, because that is an outward-facing publish.

**6. Two missing edges were found and closed, and one gap was found and left open.**
THM-0083 (what a request IS, decided once) was absent from the whole tree though R1
quantifies over it; THM-0070 was reachable from no root though R5c's totality needs it.
Both are now edges. Nothing was invented to make the graph look complete.

## Assumption register

| id | scope | mechanism |
|---|---|---|
| ASM-0001 | unit://core.time_rfc3339 | verus:external_body |
| ASM-0002 | unit://core.time_rfc3339 | verus:assume_specification |
| ASM-0003 | unit://core.time_rfc3339 | verus:assume_specification |
| ASM-0004 | unit://core.time_rfc3339 | verus:external_type_specification |
| ASM-0005 | unit://http_profile.freshness_window | verus:assume_specification |
| ASM-0006 | unit://http_profile.freshness_window | verus:assume_specification |
| ASM-0007 | unit://http_profile.freshness_window | verus:external_body |
| ASM-0008 | unit://http_profile.freshness_window | verus:external_body |
| ASM-0009 | unit://http_profile.freshness_window | verus:external_body |
| ASM-0010 | unit://http_profile.freshness_window | verus:assume_specification |
| ASM-0011 | unit://http_profile.admission_currency | verus:external_body |
| ASM-0012 | unit://http_profile.admission_currency | verus:external_body |
| ASM-0013 | unit://http_profile.admission_currency | verus:external_type_specification |
| ASM-0014 | unit://http_profile.admission_currency | verus:assume_specification |
| ASM-0015 |  | none |
| ASM-0018 | unit://http_profile.artifact_typing | verus:external_body |
| ASM-0019 | unit://http_profile.artifact_typing | verus:external_body |
| ASM-0020 | unit://http_profile.artifact_typing | verus:assume_specification |
| ASM-0021 | unit://http_profile.continuation_unbypassability | verus:external_body |
| ASM-0022 |  | none |
| ASM-0023 | unit://http_profile.continuation_binding | verus:external_body |
| ASM-0024 | unit://http_profile.admission_currency, unit://http_profile.artifact_typing, unit://http_profile.continuation_binding, unit://http_profile.continuation_unbypassability, unit://http_profile.freshness_window | verus:uninterp |
| ASM-0025 | unit://http_profile.admission_currency, unit://http_profile.artifact_typing, unit://http_profile.continuation_binding, unit://http_profile.continuation_unbypassability, unit://http_profile.freshness_window | verus:uninterp |
| ASM-0026 | unit://http_profile.admission_currency, unit://http_profile.artifact_typing, unit://http_profile.continuation_binding, unit://http_profile.continuation_unbypassability, unit://http_profile.freshness_window | verus:uninterp |
| ASM-0027 | unit://http_profile.verifier_results | none:trusted-primitive |
| ASM-0028 | unit://http_profile.verifier_results | none:trusted-primitive |
| ASM-0029 | unit://http_profile.verifier_results | none:trusted-seam |
| ASM-0030 | unit://proxy.certificate_identity | foreign-dependency |
| ASM-0031 | unit://proxy.ed25519_public_key | foreign-dependency |
| ASM-0032 | unit://proxy.credential_key_correspondence | foreign-dependency |
| ASM-0033 | unit://proxy.channel_associated_credential | foreign-dependency |
| ASM-0034 | unit://proxy.channel_associated_identity | foreign-dependency |
| ASM-0035 | unit://proxy.mechanism_verified_credential | foreign-dependency |
| ASM-0036 | unit://proxy.authenticated_relationship_peer | foreign-dependency |
| ASM-0037 | unit://http_profile.keyid, boundary://boundary.crypto_primitives | none:trusted-primitive |

