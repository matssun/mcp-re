<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- GENERATED FILE — DO NOT EDIT.
     Regenerate with: tools/verification/generate-views
     Gated by:        tools/verification/check-generated
     Derived from:
       verification/policy/theorems.toml
       verification/policy/verification.toml
       verification/policy/assumptions.toml
-->

# Security theorem index

Every claim MCP-RE states, with its owner and the review units that support it.
Support is STRUCTURAL — that a unit exists and is named, not that its evidence is
fresh. Whether a claim is established is the conjunction `tools/verification/review`
derives, and it is not shown here because this view cannot see the attestations.

| id | title | owner | supported by | lifecycle |
|---|---|---|---|---|
| THM-0001 | Admitted request parameters imply a current freshness window | http_profile.freshness_window | unit://http_profile.freshness_window | live |
| THM-0002 | RFC 3339 parsing is total and range-bounded | core.time_rfc3339 | unit://core.time_rfc3339 | live |
| THM-0003 | Admission verdict integrity | http_profile.admission_currency | unit://http_profile.admission_currency | live |
| THM-0004 | Admission anti-rollback | http_profile.admission_currency | unit://http_profile.admission_currency | live |
| THM-0005 | Degraded admission requires deployment opt-in | http_profile.admission_currency | unit://http_profile.admission_currency | live |
| THM-0006 | Presenter binding | http_profile.admission_currency | unit://http_profile.admission_currency | live |
| THM-0007 | A typed artifact verifier admits only its own type | http_profile.artifact_typing | unit://http_profile.artifact_typing | live |
| THM-0008 | No untyped artifact binding leaves the verifier as verified | http_profile.artifact_typing | unit://http_profile.artifact_typing | live |
| THM-0009 | A presented continuation cannot bypass verification | http_profile.continuation_unbypassability | unit://http_profile.continuation_unbypassability | live |
| THM-0010 | Continuation handles match their presented inputs in role | http_profile.continuation_binding | unit://http_profile.continuation_binding | live |
| THM-0012 | The lifecycle record cannot claim a shutdown that did not happen | proxy.runtime_lifecycle | unit://proxy.runtime_lifecycle | live |
| THM-0013 | No validated deployment enables online OCSP client-certificate revocation | proxy.online_ocsp_reachability | unit://proxy.online_ocsp_reachability | live |
| THM-0014 | A successful request-floor verification establishes the cryptographic floor | http_profile.verifier_results | unit://http_profile.freshness_window, unit://http_profile.verifier_results | live |
| THM-0015 | A successful full-profile request verification establishes audience and artifact binding | http_profile.verifier_results | unit://http_profile.artifact_typing, unit://http_profile.verifier_results | live |
| THM-0016 | A successful bound response-floor verification establishes binding to the supplied request | http_profile.verifier_results | unit://http_profile.freshness_window, unit://http_profile.verifier_results | live |
| THM-0017 | A successful unbound response-floor verification establishes no request binding at all | http_profile.verifier_results | unit://http_profile.freshness_window, unit://http_profile.verifier_results | live |
| THM-0018 | A successful full bound response verification establishes block agreement with the expected handle | http_profile.verifier_results | unit://http_profile.verifier_results | live |
| THM-0019 | A successful delegated bound response verification establishes an accepted credential chain | http_profile.verifier_results | unit://http_profile.verifier_results | live |
| THM-0020 | A successful delegated unbound response verification establishes a chain and never a binding | http_profile.verifier_results | unit://http_profile.verifier_results | live |

## Claims in full

### THM-0001 — Admitted request parameters imply a current freshness window

**Statement.** Every signature-parameter set the verifier admits satisfies created - skew <= now, now < expires + skew, created < expires, and a lifetime within the policy maximum, for the skew the verifier policy yields.

**Security consequence.** A request cannot be admitted on freshness evidence that has expired, that is dated ahead of the verifier, or that declares a lifetime longer than the policy permits.

**Scope — what this does NOT establish.** Establishes freshness admission only. It does not establish signature validity, issuer authority, admission currency, or replay uniqueness. The window is stated relative to skew_of(policy), an opaque accessor: the theorem holds for whatever skew the deployment configures and does not establish that the configured skew is bounded or sane.

**Review requirement.** Owner security-specification review

### THM-0002 — RFC 3339 parsing is total and range-bounded

**Statement.** parse_rfc3339_utc terminates without panicking on arbitrary input, and every timestamp it accepts denotes an instant within the representable civil range [-62167219200, 253402387199].

**Security consequence.** A timestamp in an evidence artifact can neither crash the verifier nor denote an instant the rest of the system cannot represent.

**Scope — what this does NOT establish.** The two halves are established differently and a reviewer must not look for one conjunct. The range half is the postcondition. Totality is discharged by the absence of a precondition together with the prover's panic-freedom obligation, not by an ensures clause. The theorem says nothing about which grammar variants are accepted beyond that what is accepted is in range.

**Review requirement.** Owner security-specification review

### THM-0003 — Admission verdict integrity

**Statement.** Every admission verdict returned as Ok has status Admitted and carries the generation of the binding that was checked.

**Security consequence.** A policy enforcement point cannot act on a verdict that describes a different call than the one it checked.

**Scope — what this does NOT establish.** Does not establish authenticity, issuer trust, audience validity, assertion freshness, or validity of the assertion's [nbf, exp] window; verify_admission_assertion is outside this proof cone under ASM-0012. Does not establish that the admitted actor is the presenter of the call (see the presenter-binding claim, which this contract does not state).

**Review requirement.** Owner security-specification review

### THM-0004 — Admission anti-rollback

**Statement.** A non-degraded Ok verdict implies the authoritative admission state was reachable, its generation equals the binding's generation, and its status is Admitted.

**Security consequence.** A workload whose admission has been superseded or revoked cannot buy a call with an assertion that has not yet expired.

**Scope — what this does NOT establish.** Says nothing about the degraded path, and nothing about the assertion's authenticity or freshness (ASM-0012). Currency is generation equality against the state the enforcement point holds; the theorem does not establish that that state is itself current. It also does not establish that the state handed in is the state FOR THIS WORKLOAD. `AuthoritativeAdmission` carries a generation and a status and no workload identity, so the proof quantifies over whatever record the caller supplied. Generations are small integers and collide across workloads by construction. The security consequence above therefore rests on a caller obligation this claim does not discharge: the enforcement point must look the record up under the very `binding.admission_id` that was checked. The serving path satisfies it today at `http_profile_serve.rs:600`, which passes `&binding.admission_id` to `AsyncAdmissionSource::current`; nothing in the type forbids a future caller from deriving that id from a header, a session field, or a cache instead.

**Review requirement.** Owner security-specification review

### THM-0005 — Degraded admission requires deployment opt-in

**Statement.** A degraded Ok verdict implies the authoritative admission state was unreachable and the deployment policy explicitly allows degraded mode.

**Security consequence.** No default deployment can reach a degraded admission; serving on a last-known snapshot is always a choice someone made.

**Scope — what this does NOT establish.** Establishes the opt-in, not the bound. That a degraded verdict is confined to the propagation window P is enforced in the body and is not a conjunct of this contract. Says nothing about assertion authenticity or freshness (ASM-0012).

**Review requirement.** Owner security-specification review

### THM-0006 — Presenter binding

**Statement.** A successful admission implies the admitted actor named by the assertion is the presenter of this call — the actor the verifier resolved from the request signature.

**Security consequence.** An assertion describing some admitted workload cannot authorize a different presenter merely because the workload itself is admissible. Without it the assertion is a bearer token: anyone whose key the enforcement point resolves could copy an admitted peer's assertion into their own evidence block, derive the matching binding, and pass the gate.

**Scope — what this does NOT establish.** Establishes that the actor named in the assertion equals the presenter argument. It does not establish that the presenter argument is itself correctly resolved from the request signature, which is the caller's obligation. Does not establish authenticity, issuer trust, audience validity, assertion freshness, or validity of the assertion's [nbf, exp] window; verify_admission_assertion is outside this proof cone under ASM-0012.

**Review requirement.** Owner security-specification review

### THM-0007 — A typed artifact verifier admits only its own type

**Statement.** Each typed OAuth verifier returns Ok only for a binding whose artifact_type is the one that verifier is for and whose binding_type is the opaque-digest form.

**Security consequence.** A binding of one artifact type cannot be verified by the verifier for another, so a credential form cannot be laundered through the wrong check.

**Scope — what this does NOT establish.** Does not establish that the digest matches the presented credential: the comparison's meaning is a statement about SHA-256 and is outside this proof cone under ASM-0018. "Verified" here means correctly typed and in opaque-digest form.

**Review requirement.** Owner security-specification review

### THM-0008 — No untyped artifact binding leaves the verifier as verified

**Statement.** A binding reported verified is in the opaque-digest form and is one of the three OAuth artifact types. The four registry types with no typed verifier can never be reported verified.

**Security consequence.** A caller cannot silently treat an artifact type nothing can verify as though it had been verified.

**Scope — what this does NOT establish.** Structural over the type dispatch, and inherits THM-0007's exclusion: it does not establish that any digest matched its credential (ASM-0018).

**Review requirement.** Owner security-specification review

**Depends on.** THM-0007

### THM-0009 — A presented continuation cannot bypass verification

**Statement.** If dispatch preparation returns Ok for a request whose evidence block carries a continuation, the returned continuation-verified flag is true: the pair (continuation present, not verified) is not a state any successful preparation can produce.

**Security consequence.** A continuation cannot be carried through dispatch on the strength of being present in the request.

**Scope — what this does NOT establish.** Establishes that the check ran, not what it guarantees; what a verified continuation binds is THM-0010, which this claim consumes. continuation_verified is an informational WITNESS propagated in DispatchOutcome, not a control value: downstream consumption is not required for enforcement, because the unsafe combination is unreachable on a successful preparation path. The authority is the successful return under this postcondition, not the boolean, which merely exposes part of that fact. A reader who greps for consumers, finds none, and concludes the check is unwired has read it backwards.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0010

### THM-0010 — Continuation handles match their presented inputs in role

**Statement.** An accepted continuation's three handles are the labeled digests of the three presented inputs, each under its own role label.

**Security consequence.** A response-role evidence handle cannot be presented in the request role, so the three positions of a continuation cannot be permuted.

**Scope — what this does NOT establish.** Assumes only that the labeled digest IS A FUNCTION of (label, bytes) — ASM-0023. It does NOT establish collision-resistant separation between roles; that obligation stays at boundary.crypto_primitives and is not discharged here.

**Review requirement.** Owner security-specification review

### THM-0012 — The lifecycle record cannot claim a shutdown that did not happen

**Statement.** Every state has a unique predecessor under the transition relation and apply is the only mutator, leaving the state unchanged on an illegal event. So a recorded terminal Stopped implies every event of the path Configured -> Validated -> Planned -> Materializing -> Materialized -> Serving -> Draining -> Transitioning -> Reclaiming -> Stopped was applied, in order.

**Security consequence.** A runtime that never bound a listener cannot be recorded as a clean drained shutdown, so the two terminal states remain distinguishable in an audit record.

**Scope — what this does NOT establish.** Establishes what the RECORD can say. It does not establish that any request was refused. RuntimeState::admits_requests is a DESCRIPTIVE value, not a control: no production path consumes it, and the recorded state is never Serving while a request is in flight, because the serving events are applied only after serve_fleet returns Ok — so a consumer reading it during serving would read Materialized and refuse everything. What actually confines requests to the serving interval is resource ownership: the listener exists only inside the serve_fleet call. That the events are applied only on a proven Ok is the materialized-runtime owner's obligation, not this unit's. FailedToStart is currently unreachable from Materialized, so a serve that never bound is recorded as Materialized — the record is silent about the failure rather than wrong about it. Evidence is test:// only: the uniqueness-of-path argument is a match a reviewer reads, not a proof a prover checked.

**Review requirement.** Owner security-specification review

### THM-0013 — No validated deployment enables online OCSP client-certificate revocation

**Statement.** Every DeploymentRequest whose client_ocsp is Require is refused by the legality boundary, in every build and independently of the online_ocsp feature. Every ValidatedDeployment therefore carries client_ocsp = Off, and the serving path is handed no OCSP checker.

**Security consequence.** A successfully validated MCP-RE deployment cannot advertise or rely upon online OCSP enforcement on the production async serving path. An operator who asks for it is refused at startup rather than served by a plane that performs no responder round trip.

**Scope — what this does NOT establish.** Establishes reachability and legality only. It does NOT establish the correctness of the retained RFC 6960 implementation in ocsp.rs, of the blocking-path OCSP checker, of responder trust-chain validation, of the endpoint/SSRF network policy, or of any future async OCSP implementation. It says what no deployment can turn on, not that what is turned off would be correct if turned on.

**Review requirement.** Owner security-specification review

### THM-0014 — A successful request-floor verification establishes the cryptographic floor

**Statement.** If `Verifier::verify_request_floor` returns Ok, then for the request supplied: the covered `Content-Digest` agreed with the body, the RFC 9421 signature verified over the reconstructed signature base under an algorithm the verifier's policy accepts, the signature parameters were admitted as current, and the presented keyid was resolved through the trust seam for the Request slot.

**Security consequence.** An attacker cannot obtain a floor-verified request by tampering with the body, by presenting a signature under an algorithm the deployment does not accept, by replaying expired parameters, or by presenting a key the seam vouches for only in the Response slot.

**Scope — what this does NOT establish.** This theorem characterizes values successfully returned by `verify_request_floor`. It does not establish that an arbitrary externally constructed `CryptographicFloorVerifiedRequest` was produced by that operation. It establishes NOTHING about audience or target equality, artifact binding, replay, admission, continuation semantics, or dispatch authorization: those are the full-profile and dispatch claims. It says the seam ANSWERED for the Request slot, not that the deployment was right to trust that actor (ASM-0029). It rests on a test battery, not on a postcondition over this operation.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0001

### THM-0015 — A successful full-profile request verification establishes audience and artifact binding

**Statement.** If `Verifier::verify_request` returns Ok, then the request-floor proposition holds for the same request, and in addition: the request evidence block parsed and validated under the profile tag, its audience tuple equalled the verifier's own and agreed with the request's `@target-uri`, and every artifact binding the block declared was resolved to credential material and verified.

**Security consequence.** A request signed for a different audience, route or target cannot be admitted at this boundary, and a declared artifact binding cannot be skipped by withholding the material it commits to — an unobtainable credential fails closed rather than being ignored.

**Scope — what this does NOT establish.** This theorem characterizes values successfully returned by `verify_request`. It does not establish that an arbitrary externally constructed `VerifiedMcpRequest` was produced by that operation. It establishes nothing about replay admission, admission-assertion currency, continuation binding or dispatch authorization; a full-profile request is not an admitted one. It does not establish that the artifact material the caller supplied is the credential the peer actually holds — only that the binding verified against what was supplied.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0007, THM-0008, THM-0014

### THM-0016 — A successful bound response-floor verification establishes binding to the supplied request

**Statement.** If `Verifier::verify_bound_response_floor` returns Ok, then for the response supplied: the covered `Content-Digest` agreed with the body, the signature parameters were admitted as current, the presented keyid was resolved through the trust seam for the Response slot, and the RFC 9421 signature verified over a base whose `;req` components were resolved against the concrete request supplied to the call.

**Security consequence.** A response signed for a different request cannot be presented as the answer to this one: splicing changes the signature base, so no valid signature covers it.

**Scope — what this does NOT establish.** This theorem characterizes values successfully returned by `verify_bound_response_floor`. It does not establish that an arbitrary externally constructed `CryptographicFloorVerifiedBoundResponse` was produced by that operation. It says the response is bound to the request the CALLER SUPPLIED. It establishes nothing about that request — not that it was authenticated, not that it was full-profile verified, not that it is the request this peer sent. It reads no response evidence block, so it establishes no `server_signer` correspondence and no request-evidence comparison.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0001

### THM-0017 — A successful unbound response-floor verification establishes no request binding at all

**Statement.** If `Verifier::verify_unbound_response_floor` returns Ok, then for the response supplied: the covered `Content-Digest` agreed with the body, the signature parameters were admitted as current, the presented keyid was resolved through the trust seam for the Response slot, and the signature verified over a base covering ONLY response components — a `;req` component is refused as malformed, because no request exists to resolve it against.

**Security consequence.** A receipt emitted before a request could be parsed can still be attributed to a trusted server signer, and it cannot smuggle in a request binding: a `;req` component makes the message malformed rather than admitting an unresolvable reference.

**Scope — what this does NOT establish.** This theorem characterizes values successfully returned by `verify_unbound_response_floor`. It does not establish that an arbitrary externally constructed `CryptographicFloorVerifiedUnboundResponse` was produced by that operation. It establishes NO relationship to any request, and must never be read as a weaker form of THM-0016. A caller that needs an answer to a specific request gets nothing from this claim. Any `request_evidence` the response body carries is diagnostic and is outside this claim entirely. It reads no response evidence block.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0001

### THM-0018 — A successful full bound response verification establishes block agreement with the expected handle

**Statement.** If `Verifier::verify_bound_response` returns Ok, then the bound response-floor proposition holds for the same response and request, and in addition: the response evidence block parsed and validated under the profile tag, the `server_signer` identity it declared is the identity the signature was accepted under, and the `request_evidence` handle it carried equals the handle supplied by the caller.

**Security consequence.** A response cannot declare a server signer it did not sign as, and cannot claim to answer a request whose evidence handle differs from the one the caller is holding — a semantic check on top of the cryptographic `;req` binding, reported as its own refusal.

**Scope — what this does NOT establish.** This theorem characterizes values successfully returned by `verify_bound_response`. It does not establish that an arbitrary externally constructed `VerifiedMcpResponse` was produced by that operation. It establishes nothing about the PROVENANCE of the expected handle: the caller supplies it, and a caller that supplies a handle from the wrong exchange gets a verified response bound to the wrong request. It makes no delegation claim — the signer was resolved through the trust seam, and whether a credential chain authorized it is THM-0019.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0016

### THM-0019 — A successful delegated bound response verification establishes an accepted credential chain

**Statement.** If `Verifier::verify_delegated_bound_response` returns Ok, then the full bound response proposition holds for the same response and request, and in addition: the response carried an inline delegation credential, that credential verified as a chain to a root issuer key the trust seam resolved for the Response slot, the credential was accepted under the supplied expectations, the response signature verified under the credential's confirmed key, and the keyid the signature was accepted under is the delegated kid the credential and the block both name.

**Security consequence.** A response signed directly by the root, or by a key with no chain to a trusted issuer, cannot be accepted where delegation is required; and a credential cannot be lifted onto a response signed by a different key, because the delegated kid must match on three sides.

**Scope — what this does NOT establish.** This theorem characterizes values successfully returned by `verify_delegated_bound_response`. It does not establish that an arbitrary externally constructed `VerifiedDelegatedMcpResponse` was produced by that operation. The expectations are SUPPLIED, not proved current or sane by this unit: the accepted epoch set, the verifier audiences, the expected audience-scope hash and the credential clock-skew tolerance all come from the caller, and this claim says the credential satisfied them, not that they were the right ones. Revocation is likewise a caller-supplied predicate. It establishes nothing about the provenance of the expected request-evidence handle (THM-0018).

**Review requirement.** Owner security-specification review

**Depends on.** THM-0018

### THM-0020 — A successful delegated unbound response verification establishes a chain and never a binding

**Statement.** If `Verifier::verify_delegated_unbound_response` returns Ok, then the unbound response-floor proposition holds for the same response, and in addition: the response carried an inline delegation credential which verified as a chain to a root issuer key the trust seam resolved for the Response slot and was accepted under the supplied expectations, the response signature verified under the credential's confirmed key, and the keyid it was accepted under is the delegated kid the credential and the block both name.

**Security consequence.** A preflight or pre-parse rejection receipt cannot be forged by an unsigned or directly root-signed response: delegation stays required on the path where there is no request to bind to, which is the path with the least other evidence.

**Scope — what this does NOT establish.** This theorem characterizes values successfully returned by `verify_delegated_unbound_response`. It does not establish that an arbitrary externally constructed `VerifiedDelegatedUnboundResponse` was produced by that operation. It NEVER implies request binding and must not inherit THM-0018 or THM-0019 by analogy: a receipt that satisfies this claim is not an answer to any particular request, and a consumer that needs one must obtain it elsewhere. As in THM-0019 the expectations are supplied rather than proved current. The block's `request_evidence`, if present, is diagnostic and outside this claim.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0017
