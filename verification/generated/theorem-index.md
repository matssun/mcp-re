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
| THM-0016 | A successful bound response-floor verification establishes trust-seam authorization of the signer | http_profile.verifier_results | unit://http_profile.freshness_window, unit://http_profile.verifier_results | live |
| THM-0017 | A successful unbound response-floor verification establishes trust-seam authorization and no request binding | http_profile.verifier_results | unit://http_profile.freshness_window, unit://http_profile.verifier_results | live |
| THM-0018 | A successful full bound response verification establishes block agreement with the expected handle | http_profile.verifier_results | unit://http_profile.verifier_results | live |
| THM-0019 | A successful delegated bound response verification establishes an accepted credential chain | http_profile.verifier_results | unit://http_profile.verifier_results | live |
| THM-0020 | A successful delegated unbound response verification establishes a chain and never a binding | http_profile.verifier_results | unit://http_profile.verifier_results | live |
| THM-0021 | A successful bound-response verification establishes the shared cryptographic and request-binding facts | http_profile.verifier_results | unit://http_profile.freshness_window, unit://http_profile.verifier_results | live |
| THM-0022 | A successful unbound-response verification establishes the shared facts and no request binding at all | http_profile.verifier_results | unit://http_profile.freshness_window, unit://http_profile.verifier_results | live |
| THM-0023 | Every peer identity value is well-formed, whatever evidence produced it | proxy.peer_identity_value | unit://proxy.peer_identity_value | live |
| THM-0024 | Certificate identity interpretation reads the configured field and refuses rather than falling back | proxy.certificate_identity | unit://proxy.certificate_identity | live |
| THM-0025 | Every canonical Ed25519 public key value is the canonical RFC 8410 encoding of its own point | proxy.ed25519_public_key | unit://proxy.ed25519_public_key | live |
| THM-0026 | Credential/key correspondence relates two independently interpreted keys and attributes every refusal to the side that failed | proxy.credential_key_correspondence | unit://proxy.credential_key_correspondence | live |
| THM-0027 | A delegated resolver's existence proves its credential and signer corresponded | proxy.delegated_resolver_materialization | unit://proxy.delegated_resolver_materialization | live |
| THM-0028 | Channel-associated certificate credential evidence originates only from an established relationship's mechanism report | proxy.channel_associated_credential | unit://proxy.channel_associated_credential | live |
| THM-0029 | A channel-associated peer identity is interpreted from the leaf of that relationship's own credential | proxy.channel_associated_identity | unit://proxy.channel_associated_identity | live |
| THM-0030 | Verified-credential evidence records the mechanism's own acceptance and the path it was reached on | proxy.mechanism_verified_credential | unit://proxy.mechanism_verified_credential | live |
| THM-0031 | An authenticated relationship peer's identity is read from the leaf of the very credential the mechanism accepted for that relationship | proxy.authenticated_relationship_peer | unit://proxy.authenticated_relationship_peer | live |
| THM-0032 | Per-request credential currency is decided from the credential the mechanism accepted, and reports which of its five facts refused | proxy.credential_currency | unit://proxy.credential_currency | live |
| THM-0033 | A current authenticated peer's currency is evaluated against the credential that same peer authenticated with | proxy.current_authenticated_peer | unit://proxy.current_authenticated_peer | live |
| THM-0034 | A request is bound to its relationship by relating the authenticated peer to the resolved actor's SUBJECT, never to the composite actor id | proxy.request_peer_binding | unit://proxy.request_peer_binding | live |
| THM-0035 | A successfully classified trust-revocation state carries the witnesses its own state form requires | proxy.trust_configuration_state | unit://proxy.trust_configuration_state | live |
| THM-0036 | A networked trust-epoch source is handed over as a paired locator and key, or not at all | proxy.trust_configuration_state | unit://proxy.trust_configuration_state | live |
| THM-0037 | A trust plan's reload cadence is a projection of the revocation posture, never a second value | proxy.trust_plan | unit://proxy.trust_plan | live |
| THM-0038 | The composition root consumes trust as owner projections and re-reads no trust field from the request | proxy.trust_composition_root | unit://proxy.trust_composition_root | live |

## Claims in full

### THM-0001 — Admitted request parameters imply a current freshness window

**Statement.** Every signature-parameter set the verifier admits satisfies created - skew <= now, now < expires + skew, created < expires, and a lifetime within the policy maximum, for the skew the verifier policy yields.

**Security consequence.** A request cannot be admitted on freshness evidence that has expired, that is dated ahead of the verifier, or that declares a lifetime longer than the policy permits.

**Scope — what this does NOT establish.** Establishes freshness admission only. It does not establish signature validity, issuer authority, admission currency, or replay uniqueness. The window is stated relative to skew_of(policy), an opaque accessor: the theorem holds for whatever skew the deployment configures and does not establish that the configured skew is bounded or sane.

**Review requirement.** Owner security-specification review

### THM-0002 — RFC 3339 parsing is total and range-bounded

**Statement.** parse_rfc3339_utc terminates without panicking on arbitrary input, and every timestamp it accepts denotes an instant within the parser's ADMITTED four-digit civil range 0000-01-01T00:00:00Z through 9999-12-31T23:59:59Z, that is [-62167219200, 253402300799]. Both bounds are TIGHT: each is attained by an accepted timestamp, so neither can be narrowed. RFC 3339 defines the era as 0000AD through 9999AD; MCP-RE admits a stricter UTC-only four-digit-year subset of it, and the grammar's four-digit year together with the refusal of leap seconds is what makes 9999-12-31T23:59:59Z the maximum value the function can return.

**Security consequence.** A timestamp in an evidence artifact can neither crash the verifier nor denote an instant the rest of the system cannot represent.

**Scope — what this does NOT establish.** The two halves are established differently and a reviewer must not look for one conjunct. The range half is the postcondition. Totality is discharged by the absence of a precondition together with the prover's panic-freedom obligation, not by an ensures clause. The theorem says nothing about which grammar variants are accepted beyond that what is accepted is in range. It does not establish that every instant in the range is REACHABLE by some accepted timestamp — only that nothing outside it is. The two endpoints specifically are reachable, and are pinned by boundary controls at their exact Unix seconds, but the claim is containment. It says nothing about the inverse direction: that format_rfc3339_utc round-trips a value in this range is a different proposition with its own evidence.

**Review requirement.** Owner security-specification review

### THM-0003 — Admission verdict integrity

**Statement.** Every admission verdict returned as Ok has status Admitted and carries the generation of the binding that was checked.

**Security consequence.** A policy enforcement point cannot act on a verdict that describes a different call than the one it checked.

**Scope — what this does NOT establish.** Does not establish authenticity, issuer trust, audience validity, assertion freshness, or validity of the assertion's [nbf, exp] window; verify_admission_assertion is outside this proof cone under ASM-0012. Does not establish that the admitted actor is the presenter of the call (see the presenter-binding claim, which this contract does not state).

**Review requirement.** Owner security-specification review

### THM-0004 — Admission anti-rollback

**Statement.** A non-degraded Ok verdict implies the authoritative admission state was reachable, its generation equals the binding's generation, and its status is Admitted.

**Security consequence.** A workload whose admission has been superseded or revoked cannot buy a call with an assertion that has not yet expired.

**Scope — what this does NOT establish.** Says nothing about the degraded path, and nothing about the assertion's authenticity or freshness (ASM-0012). Currency is generation equality against the state the enforcement point holds; the theorem does not establish that that state is itself current. It also does not establish that the state handed in is the state FOR THIS WORKLOAD. `AuthoritativeAdmission` carries a generation and a status and no workload identity, so the proof quantifies over whatever record the caller supplied. Generations are small integers and collide across workloads by construction. The security consequence above therefore rests on a caller obligation this claim does not discharge: the enforcement point must look the record up under the very `binding.admission_id` that was checked. The serving path satisfies it today at `admission_enforcer.rs:121`, which passes `&binding.admission_id` to `AsyncAdmissionSource::current`; nothing in the type forbids a future caller from deriving that id from a header, a session field, or a cache instead.

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

**Security consequence.** A request signed for a different audience, route or target cannot be successfully returned as a full-profile verified request, and a declared artifact binding cannot be skipped by withholding the material it commits to — an unobtainable credential fails closed rather than being ignored.

**Scope — what this does NOT establish.** This theorem characterizes values successfully returned by `verify_request`. It does not establish that an arbitrary externally constructed `VerifiedMcpRequest` was produced by that operation. It establishes nothing about replay admission, admission-assertion currency, continuation binding or dispatch authorization; a full-profile request is not an admitted one — which is why the consequence above is phrased over what this operation returns rather than over what a deployment admits. It does not establish that the artifact material the caller supplied is the credential the peer actually holds — only that the binding verified against what was supplied.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0007, THM-0008, THM-0014

### THM-0016 — A successful bound response-floor verification establishes trust-seam authorization of the signer

**Statement.** If `Verifier::verify_bound_response_floor` returns Ok, then the shared bound-response proposition holds for the same response and request, and in addition: the presented keyid was resolved through the trust seam for the Response slot, and the actor the seam returned IS the accepted signer — the signature verified under the key the seam supplied.

**Security consequence.** A response cannot be attributed to a server signer this deployment's trust store does not vouch for in the Response slot, and a request-signer key presented on a response is refused rather than silently accepted in the wrong role.

**Scope — what this does NOT establish.** This theorem characterizes values successfully returned by `verify_bound_response_floor`. It does not establish that an arbitrary externally constructed `CryptographicFloorVerifiedBoundResponse` was produced by that operation. It says the seam ANSWERED for this keyid in the Response slot, not that the deployment was right to trust that actor, and not that the key the seam returned is the key it should have returned (ASM-0029). It reads no response evidence block, so it establishes no `server_signer` correspondence and no request-evidence comparison. It makes NO delegation claim, and the delegated products do not carry this proposition: on that path the seam is queried for the credential's ROOT ISSUER and the signing key appears in no trust map at all.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0021

### THM-0017 — A successful unbound response-floor verification establishes trust-seam authorization and no request binding

**Statement.** If `Verifier::verify_unbound_response_floor` returns Ok, then the shared unbound-response proposition holds for the same response, and in addition: the presented keyid was resolved through the trust seam for the Response slot, and the actor the seam returned IS the accepted signer.

**Security consequence.** A receipt emitted before a request could be parsed can still be attributed to a trusted server signer — and only to one the seam vouches for in the Response slot.

**Scope — what this does NOT establish.** This theorem characterizes values successfully returned by `verify_unbound_response_floor`. It does not establish that an arbitrary externally constructed `CryptographicFloorVerifiedUnboundResponse` was produced by that operation. It inherits every exclusion of THM-0022 — no request relationship of any kind — and the ASM-0029 boundary of THM-0016. It makes no delegation claim: a delegated receipt is authorized by a credential and never reaches this type.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0022

### THM-0018 — A successful full bound response verification establishes block agreement with the expected handle

**Statement.** If `Verifier::verify_bound_response` returns Ok, then the trust-seam-authorized bound response-floor proposition holds for the same response and request, and in addition: the response evidence block parsed and validated under the profile tag, the `server_signer` identity it declared carries the keyid the signature was accepted under, and the `request_evidence` handle it carried equals the handle supplied by the caller.

**Security consequence.** A response cannot declare a server signer it did not sign as, and cannot claim to answer a request whose evidence handle differs from the one the caller is holding — a semantic check on top of the cryptographic `;req` binding, reported as its own refusal.

**Scope — what this does NOT establish.** This theorem characterizes values successfully returned by `verify_bound_response`. It does not establish that an arbitrary externally constructed `VerifiedMcpResponse` was produced by that operation. **The two request inputs are unrelated by this claim.** The operation receives a concrete request, against which the `;req` components are resolved, and separately a `RequestEvidence` handle, against which the block's handle is compared. Nothing here establishes that the handle was derived from that request. A caller may supply request A and handle B; a successful verification then establishes cryptographic binding to A and semantic equality to B, and NOT that A and B denote the same exchange. Relating them is the caller's obligation — a server passes `verified_request.evidence()` for the request it just verified, a client the handle it kept from signing the request it just sent — and a caller that supplies a handle from the wrong exchange gets a verified response bound to the wrong request. Only the KEYID of the declared `server_signer` was compared. The block's `role`, `trust_domain` and `subject` are its own claim, checked against nothing here. It makes no delegation claim. The signer was resolved through the trust seam, and whether a credential chain authorized one is THM-0019 — a different proposition over a different product, not a strengthening of this one.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0016

### THM-0019 — A successful delegated bound response verification establishes an accepted credential chain

**Statement.** If `Verifier::verify_delegated_bound_response` returns Ok, then the shared bound-response proposition holds for the same response and request, and in addition: the response evidence block parsed and validated under the profile tag; it carried an inline delegation credential; that credential verified as a chain to a root issuer key the trust seam resolved for the Response slot and was accepted under the supplied expectations; the keyid the signature was accepted under is the delegated kid that the credential confirms and the block declares; and the `request_evidence` handle the block carried equals the handle supplied by the caller.

**Security consequence.** A response signed directly by the root, or by a key with no chain to a trusted issuer, cannot be accepted where delegation is required; a credential cannot be lifted onto a response signed by a different key, because the delegated kid must match on three sides; and the response cannot claim to answer a request whose evidence handle differs from the one the caller is holding.

**Scope — what this does NOT establish.** This theorem characterizes values successfully returned by `verify_delegated_bound_response`. It does not establish that an arbitrary externally constructed `VerifiedDelegatedMcpResponse` was produced by that operation. **It does NOT establish THM-0016 or THM-0018, and does not depend on them.** Those claims say the presented signing keyid was resolved through the trust seam; on this path it was not, and no trust map contains it. The seam was queried for the credential's ROOT ISSUER kid, and what authorizes the signing key is the chain. That is why the product carries the shared `BoundResponseSignatureFacts` rather than a `CryptographicFloorVerifiedBoundResponse`: a nested seam-authorized product here would be a value whose documented meaning is false. Reading upward is likewise blocked: `AcceptedResponseSigner` records who signed, not that anyone vouched for the key directly. A consumer whose reasoning needs a trust-store entry for the SIGNING key gets nothing from this claim. The expectations are SUPPLIED, not proved current or sane by this unit: the accepted epoch set, the verifier audiences, the expected audience-scope hash and the credential clock-skew tolerance all come from the caller, and this claim says the credential satisfied them, not that they were the right ones. Revocation is likewise a caller-supplied predicate. The two request inputs are unrelated by this claim in exactly the sense THM-0018 states: the `;req` binding is to the concrete request supplied, the handle comparison is to the handle supplied, and nothing here relates them.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0021

### THM-0020 — A successful delegated unbound response verification establishes a chain and never a binding

**Statement.** If `Verifier::verify_delegated_unbound_response` returns Ok, then the shared unbound-response proposition holds for the same response, and in addition: the response evidence block parsed and validated under the profile tag; it carried an inline delegation credential; that credential verified as a chain to a root issuer key the trust seam resolved for the Response slot and was accepted under the supplied expectations; and the keyid the signature was accepted under is the delegated kid that the credential confirms and the block declares.

**Security consequence.** A preflight or pre-parse rejection receipt cannot be forged by an unsigned or directly root-signed response: delegation stays required on the path where there is no request to bind to, which is the path with the least other evidence.

**Scope — what this does NOT establish.** This theorem characterizes values successfully returned by `verify_delegated_unbound_response`. It does not establish that an arbitrary externally constructed `VerifiedDelegatedUnboundResponse` was produced by that operation. It NEVER implies request binding and must not inherit THM-0018 or THM-0019 by analogy: a receipt that satisfies this claim is not an answer to any particular request, and a consumer that needs one must obtain it elsewhere. The block's `request_evidence`, if present, is diagnostic and outside this claim. **It does NOT establish THM-0017, and does not depend on it**, for the reason THM-0019 does not establish THM-0016: the seam answered for the credential's root issuer, not for the signing key. As in THM-0019 the expectations are supplied rather than proved current.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0022

### THM-0021 — A successful bound-response verification establishes the shared cryptographic and request-binding facts

**Statement.** If any of `Verifier::verify_bound_response_floor`, `Verifier::verify_bound_response` or `Verifier::verify_delegated_bound_response` returns Ok, then for the response supplied: the covered `Content-Digest` agreed with the body, the signature parameters were admitted as current under an algorithm the verifier's policy accepts, and the RFC 9421 signature verified over a base whose `;req` components were resolved against the concrete request supplied to the call, under the verification key of the accepted signer the operation returns.

**Security consequence.** A response signed for a different request cannot be presented as the answer to this one: splicing changes the signature base, so no valid signature covers it. A tampered body breaks the covered digest. Both hold on EITHER authorization path, so a deployment moving from trust-store to delegated response signing does not have to re-establish them.

**Scope — what this does NOT establish.** It says WHO the signature was accepted under and never WHY that signer is acceptable. `AcceptedResponseSigner` deliberately carries no slot resolution and no credential: trust-seam authorization (THM-0016) and delegation-chain authorization (THM-0019) are different propositions, and neither may be inferred from this one. It reads no response evidence block, so it establishes no `server_signer` correspondence and no request-evidence comparison. It says the response is bound to the request the CALLER SUPPLIED; it establishes nothing about that request — not that it was authenticated, not that it was full-profile verified, not that it is the request this peer sent. It characterizes values successfully returned by those three operations. It does not establish that an arbitrary externally constructed `BoundResponseSignatureFacts` was produced by one of them.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0001

### THM-0022 — A successful unbound-response verification establishes the shared facts and no request binding at all

**Statement.** If either `Verifier::verify_unbound_response_floor` or `Verifier::verify_delegated_unbound_response` returns Ok, then for the response supplied: the covered `Content-Digest` agreed with the body, the signature parameters were admitted as current under an algorithm the verifier's policy accepts, and the signature verified over a base covering ONLY response components under the verification key of the accepted signer the operation returns — a `;req` component is refused as malformed, because no request exists to resolve it against.

**Security consequence.** A receipt emitted before a request could be parsed can still be attributed to a signer, and it cannot smuggle in a request binding: a `;req` component makes the message malformed rather than admitting an unresolvable reference.

**Scope — what this does NOT establish.** As with THM-0021, it says WHO the signature was accepted under and never WHY. Trust-seam authorization is THM-0017 and delegation-chain authorization is THM-0020. It establishes NO relationship to any request, and must never be read as a weaker form of THM-0021. A caller that needs an answer to a specific request gets nothing from it. Any `request_evidence` the response body carries is diagnostic and is outside this claim entirely. It reads no response evidence block. It characterizes values successfully returned by those two operations, not arbitrary externally constructed `UnboundResponseSignatureFacts`.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0001

### THM-0023 — Every peer identity value is well-formed, whatever evidence produced it

**Statement.** Every inhabitant of PeerIdentityValue is a non-empty, length-bounded string free of control characters, and equals the trimmed form of the candidate it was interpreted from. The type's representation is private and its only constructor is fallible, so this is a property of the type rather than of any call site: no sequence of operations available to a caller produces an inhabitant that violates it.

**Security consequence.** An issuer that mints a SAN holding a CR/LF or a megabyte of padding, and a downstream that injects the same shape into a trusted-ingress header, are refused by the same rule. Neither can put a log-injection or header-smuggling payload into the value a transport binding compares or an audit record carries, and neither provenance can drift into a weaker definition of well-formed than the other.

**Scope — what this does NOT establish.** Well-formedness only. It says nothing about who the identity denotes, whether the identity was authenticated, trusted, admitted, or authorized, or which evidence produced it — provenance is carried by the evidence product that wraps the value, not by the value. It bounds LENGTH, not content: a well-formed value may be an attacker-chosen string, and the theorem is not a claim that the value is meaningful, resolvable, or issued to anyone. The claim is over inhabitants of the type. Callers that reimplement the rules instead of constructing the type are outside it — which is why the trusted-ingress facade delegating rather than reimplementing is part of this unit's battery.

**Review requirement.** Owner security-specification review

### THM-0024 — Certificate identity interpretation reads the configured field and refuses rather than falling back

**Statement.** If interpreting certificate-chain evidence under an identity-selection policy returns Ok, then: the returned source equals the field the policy configures; the returned value is the PeerIdentityValue interpretation of the FIRST value the leaf presents in that field; and the value satisfies THM-0023. If it returns Err, no other field and no later value of the configured field was read. The five refusals are distinguishable: no leaf was presented, the leaf could not be interpreted as a certificate, the representation carrying the configured field could not be interpreted, the configured field was absent, or the configured field's first value was not a well-formed identity — the last carrying which value rule it broke. Present-but-uninterpretable is never reported as absent, and the refusal names the first rule that failed under the precedence readability -> presence -> identity-value validity. Interpretation is total and deterministic over the interpreted field set and the policy.

**Security consequence.** An issuer or peer cannot choose which identity the proxy binds to by controlling a field the deployment did not configure, and cannot choose it by making the authoritative value unusable: neither a present DNS SAN under a URI-SAN policy nor a valid second URI SAN behind a malformed first one is ever read. A deployment that configured URI SANs cannot be silently downgraded to a legacy Common Name.

**Scope — what this does NOT establish.** It establishes IDENTITY EVIDENCE and nothing above it. It does not establish that the certificate chain is trusted, that it is unrevoked, that it is fresh, that the peer is authenticated, that the relationship is admitted, that any action is authorized, or that a channel to that peer exists. Holding the product is not a weaker form of any of those, and none of them may be inferred from it. The claim divides at the parser boundary. The selector half is over an interpreted field set — an ordinary Rust value — and is what the battery and any future proof reach. That the field set faithfully reports what the DER encodes is ASM-0030, an assumed foreign dependency, NOT part of this claim: a wrong parser yields a faithful interpretation of the wrong fields and this theorem still holds. It characterizes values successfully returned by the interpretation operation. It says nothing about arbitrary possession of a CertificatePeerIdentityEvidence value, whose construction closure is the module boundary rather than a proved postcondition. "First value" is a property of the presented order. The claim assumes the field set preserves that order and does not establish it of any other producer. The refusals are distinguishable but not equally consequential: every one of them refuses, so nothing is admitted on any of them. What the distinction establishes is which fact a refusal RECORDS — an operator, an audit trail and a test can tell a peer that presented nothing from one whose issuer minted a broken field. It is a claim about faithful reporting, not about admission.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0023

### THM-0025 — Every canonical Ed25519 public key value is the canonical RFC 8410 encoding of its own point

**Statement.** Every inhabitant of Ed25519PublicKeyValue was interpreted from bytes that are exactly the canonical RFC 8410 Ed25519 SubjectPublicKeyInfo encoding — the fixed twelve-byte id-Ed25519 header followed by exactly thirty-two key bytes — and its projected point is those thirty-two bytes. Acceptance is decided by that exact match alone. The general SubjectPublicKeyInfo parse runs only after the match has already failed, and only to choose which of three refusals to report, so no parser behaviour can turn a refusal into an acceptance. The encoding direction is the inverse of the interpreting one: interpreting the encoding of a point yields a value whose point is that point.

**Security consequence.** A provider configured with a key of another algorithm — an RSA or NIST P-curve KMS key, a token key of the wrong type — cannot be used as an Ed25519 key anywhere in the proxy, and cannot become one by being re-encoded. Every provider that writes a SubjectPublicKeyInfo and every consumer that reads one is held to a single definition of the encoding, so a mismatch between two providers' idea of it cannot arise.

**Scope — what this does NOT establish.** It is about the ENCODING, not about the key. It does not establish that the thirty-two bytes are a valid curve point, that anyone holds the private half, that the key is trusted, current, or authorized, or that any signature made with it verifies. The refusal taxonomy is a claim about faithful reporting, not about admission: all three refusals refuse. Which one is reported rests on ASM-0031, an assumed foreign parser, and that assumption is contained to reporting precisely because acceptance never consults it. It says nothing about non-canonical encodings other than that they are refused — in particular it does not claim they are invalid keys, only that this system does not accept them.

**Review requirement.** Owner security-specification review

### THM-0026 — Credential/key correspondence relates two independently interpreted keys and attributes every refusal to the side that failed

**Statement.** If establishing credential/key correspondence returns Ok, then: the credential's leaf presented a public key satisfying THM-0025; the signer exported a public key satisfying THM-0025; those two keys are equal; and the returned facts carry that one key. If it returns Err, the refusal names which authority failed — the credential side, the signing-key side, or the relation. The relation itself can refuse only with a mismatch: an absent credential, an unreadable credential, an unreachable signer and a key of the wrong profile are all refused by the adapter that owns them, before the relation is reached, and the relation is never handed a key that failed the profile rule.

**Security consequence.** A delegated TLS listener cannot be built whose signer signs for a key other than the one its certificate presents, and cannot be built on a signer or a credential whose key is of another algorithm — including the algorithm-confusion case where a key of another algorithm carries the credential's public point in its trailing bytes. The failure is refused before any server starts rather than surfacing as an opaque handshake failure, and an operator is told which half of the deployment to look at.

**Scope — what this does NOT establish.** Correspondence only. It does not establish that the credential chain is trusted, valid now, or unrevoked; that the signer may serve; that the signer holds the private half of the key it exported; that a listener has signing budget; or that any channel exists. A signer whose key corresponds to an untrusted, expired, revoked certificate satisfies this theorem. It characterizes a successful return of the named operation, not possession of the facts value. Equality of keys is equality of the thirty-two interpreted bytes. It is not a claim that two equal points are the same KEY MATERIAL in any custody sense, and it establishes nothing about the private halves. The two sides rest on foreign parsing differently, and a reviewer must not read one containment onto the other. That the credential's leaf presented THIS SubjectPublicKeyInfo is ASM-0032, an assumed premise on the ACCEPTING path: a certificate parser reporting the wrong bytes would let correspondence hold against a key the credential does not present. Which refusal is reported, on either side, rests on ASM-0031 through THM-0025, and that one cannot affect acceptance because acceptance never consults it. The signing side needs no equivalent assumption, because the claim is deliberately about the key the signer EXPORTED. It does not establish that the signer holds the private half, so nothing here depends on the export being an honest report of what the device can sign with.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0025

### THM-0027 — A delegated resolver's existence proves its credential and signer corresponded

**Statement.** Every DelegatedCertResolver produced by MCP-RE was produced by DelegatedCertResolver::materialize, which establishes credential/key correspondence (THM-0026) over the very credential chain and signer it then moves into the resolver, and retains the resulting facts as a private construction witness. The construction closure is what carries the claim. The assembling constructor is private and requires a CredentialKeyCorrespondenceFacts value that no caller can produce, so there is no path from independently supplied credential and signer material to a resolver that skips the relation — and no window in which a caller holds facts about one pair and material from another, because the facts are never returned to a caller at all. The listener's handshake-signature budget is installed unchanged and is not derived from the credential.

**Security consequence.** An embedder cannot construct MCP-RE's correspondence-assured delegated resolver from a certificate and a signer whose exported public key differs from the certificate's leaf public key. Such a mismatch is refused before the resolver exists, rather than surfacing as an opaque handshake failure after the server has already started. Before this, that pairing was enforced only by the function MCP-RE happened to call first, while a public constructor took the two operands independently — so the unsafe combination was reachable. This theorem makes NO claim that future signing operations use the private key corresponding to that exported public key. A signer that exports one key and later signs with another is not excluded by it: correspondence relates two public keys at construction time, and nothing here constrains what the device does afterwards.

**Scope — what this does NOT establish.** It is a claim about CONSTRUCTION, and only about resolvers this crate produces. It does not establish that the certificate is trusted, current or unrevoked, that the signer is authorized or holds the private half of the key it exported, that any handshake will succeed, that the peer is admitted, or that a channel exists. It says nothing whatsoever about an arbitrary `ResolvesServerCert` supplied to `TlsListenerSecurityState::build_delegated_resolver_config`. That escape hatch exists for custody arrangements MCP-RE does not model, validates no credential of its own, and is deliberately outside this claim — a resolver reaching the serving path through it carries no correspondence guarantee, and the two operations must not be read as making the same promise. The witness is not projected, so no consumer can read the facts back out; the claim is that the value could not exist without them, not that it exposes them.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0026

### THM-0028 — Channel-associated certificate credential evidence originates only from an established relationship's mechanism report

**Statement.** This is a claim about ORIGIN, not about simultaneous lifetime. The value owns its credential bytes and is `Clone`, so it may outlive the relationship it came from; what cannot happen is that it came from anywhere else. Every ChannelAssociatedCertificateCredentialEvidence inhabitant produced by this crate's production configuration originates from an inhabitant produced by communication_assurance::channel_associated_credential::rustls_adapter::associated_credential for a connection the establishment mechanism reported as established — that is, as no longer handshaking. Cloning preserves that provenance and cannot introduce a new credential or relationship origin. The originating inhabitant carries the non-empty credential chain the mechanism reported for that same connection. The producer boundary is a CALL-SITE fact, and privacy alone does not establish it. The constructor is private to the owning module, and the mechanism adapter is a CHILD of that module rather than a sibling of it. But Rust privacy is the defining module and its descendants, so what privacy bounds is a SET of modules that could call the constructor, not a single one. What makes this claim true is the narrower fact that in the production configuration the only production call site is the descendant mechanism adapter rustls_adapter::associated_credential. Privacy bounds who could; the call sites say who does, and only the conjunction is the claim. The owner's `#[cfg(test)]` module deliberately constructs synthetic inhabitants directly, from chains no connection ever reported, because the refusal at construction has to be exercised. Those test-only inhabitants are outside this theorem's scope, and they are why it is scoped to the production configuration rather than quantified over every inhabitant the crate can build. An earlier draft said the adapter reaches the constructor and nothing else in the crate does; those two constructions are counterexamples to it. A `pub(super)` constructor would still not do, for the reason the call-site framing makes plain: it widens the set privacy admits to every module of `communication_assurance`, present and future, at exactly the point where this product's whole semantic content is provenance — and a future production call site added inside that set would falsify the claim without touching this file. The historical `TransportIdentity` — public fields, a total constructor — is the shape at the other end of that scale. Establishment is a predecessor, not a decision made here. Each serving path calls the adapter after its own successful-establishment boundary: the async path after `TlsAcceptor::accept` has succeeded, the blocking path after the request read that drives the rustls handshake to completion. Because a `ServerConnection` exists before its handshake and therefore proves nothing, the adapter asks the mechanism rather than trusting the type, and declines to speak while the mechanism says establishment has not completed.

**Security consequence.** Possession of this evidence is a fact about a relationship that existed, not a string someone chose. Downstream authorities that consume a peer credential can be given a value whose provenance is structural, instead of the historical situation in which the supposedly-verified transport identity could be manufactured by any caller and nothing downstream could tell a manufactured one from a channel-derived one. The claim is deliberately weaker than the sentence the old control flow implied. It does NOT say the credential was freshly verified during this establishment: a resumed relationship restores its stored chain verbatim and re-runs neither chain building, nor the CRL consultation, nor the validity window, and resumed relationships are legal here. Both paths were measured to associate byte-identical evidence, so the association proposition is the same one on each; the verification facts they do not share are recovered per request by other authorities, which is why this product must not appear to carry them.

**Scope — what this does NOT establish.** It is a claim about CONSTRUCTION, and only about values this crate produces. It does not establish that the credential is trusted, current, unrevoked, or issued by a configured anchor; that it has been interpreted as any identity; that the peer is admitted or authorized; or that the credential is bound to the actor that signed any request. Nor does it say the relationship still exists. Holding the evidence proves where it came from, not that anything is still connected — a value may be cloned and outlive its connection, and a consumer needing currency must establish that separately. It says nothing about what the establishment mechanism did internally. That the mechanism reports establishment honestly, and reports the credential it actually associated, is ASM-0033 — a premise, not a result, and the reason the controls drive real handshakes instead of synthesising a chain. Two refusals exist and neither is a legal domain state: an incomplete establishment and an established relationship carrying no credential are mechanism-boundary inconsistencies. Characterization measured that a peer presenting no certificate is refused DURING establishment by the mandatory client-certificate verifier every serving config is built with, so there is no established relationship for a credential to be missing from. The `fault_accept_any_client` fault-injection build deliberately breaks that verifier; the refusal keeps that build failing closed at this authority too.

**Review requirement.** Owner security-specification review

### THM-0029 — A channel-associated peer identity is interpreted from the leaf of that relationship's own credential

**Statement.** This is a claim about the COMPOSITION, not about either half of it. Both premises are stated elsewhere and neither is strengthened here: THM-0024 says what interpreting a certificate's configured identity field yields, and THM-0028 says where a channel-associated credential comes from. Every ChannelAssociatedCertificatePeerIdentityEvidence inhabitant originates from an inhabitant produced by communication_assurance::channel_associated_identity::interpret_associated_identity — a free function taking a &ChannelAssociatedCertificateCredentialEvidence and a CertificateIdentityPolicy, and nothing else — from some channel-associated certificate credential evidence C and some identity-selection policy P, and its value and source are exactly what interpreting the FIRST certificate of C's associated chain under P returned. Cloning preserves that provenance and cannot introduce a new credential or identity origin. No other certificate can be the source of that identity. The derivation's whole parameter list is a credential and a policy: there is no parameter through which a separately obtained certificate, or a separately obtained identity product, could enter, so pairing credential A with an identity read from certificate B is unconstructible rather than merely untaken. The representation is private to the deriving module, and the owning authority exposes only the free interpret_associated_identity operation taking the predecessor credential and identity-selection policy, so that operation is the only producer; a sibling authority attempting the struct literal fails with E0451. The deriving module is communication_assurance::channel_associated_identity, a SIBLING of the credential authority rather than a module inside it, and that placement is load-bearing in the other direction: inside, it would be a descendant of the credential's module and would therefore reach the private constructor THM-0028 claims only the mechanism adapter can reach — measured, that layout compiled a call to it. It consumes the owner's named `pub(super)` leaf projection instead. A consumer's placement is part of its predecessor's seal. The refusal algebra is the leaf-level one, which has no absence state. The predecessor guarantees a non-empty chain, so *no certificate was presented* is not a state this derivation's input can be in, and the type does not advertise it.

**Security consequence.** An identity that a consumer receives with a relationship cannot have been read out of a different peer's certificate. The composition this replaces — a caller holding relationship credential A and, separately, identity evidence interpreted from certificate B, and pairing them — is the shape in which two individually true facts state a false relation, and nothing downstream could detect it, because the only record of which certificate an identity came from is the pairing itself. It also refuses the intermediate. A chain carries certificates that signed the peer as well as the peer's own; reading identity from anything but the leaf would let an issuer choose the identity the proxy binds to.

**Scope — what this does NOT establish.** It is NOT authentication, and the type is deliberately not named as though it were. THM-0028 establishes no trust, currency, revocation status, or anchor membership for the credential, and THM-0024 establishes only what a certificate representation denotes. Two deliberately weaker facts do not compose into a stronger one: nothing here establishes that the peer is authenticated, that the relationship is admitted, that any action is authorized, or that the identity is bound to the actor that signed any request. Naming the product Authenticated would require a premise that does not exist. Nor does it say the relationship still exists. The product may be cloned and outlive the connection its credential came from — it inherits that limit from THM-0028 rather than repairing it. It says nothing about the establishment mechanism or the X.509 parser. Those premises are ASM-0033 and ASM-0030, and they stay under the theorems that own them: this claim consumes semantic products, so a wrong parser yields a faithful linkage of the wrong fields and this theorem still holds. One premise IS this claim's own. That element 0 of the reported chain is the peer's own credential rather than an issuer's is ASM-0034, a documented and measured property of the mechanism's reporting order — and not something ASM-0033 supplies, since *the mechanism reports the credential it associated* is true under any ordering. Reading the FIRST certificate is what this theorem says; that the first certificate is the PEER'S is what ASM-0034 assumes.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0024, THM-0028

### THM-0030 — Verified-credential evidence records the mechanism's own acceptance and the path it was reached on

**Statement.** This is a claim about RELAY and ORIGIN. It does not say the credential is trusted, current, or unrevoked; it says the mechanism accepted it, and on which path. Every MechanismVerifiedCredentialEvidence inhabitant produced by this crate's production configuration originates from an inhabitant produced by communication_assurance::mechanism_verified_credential::rustls_adapter::verified_credential from ONE connection, carrying that connection's channel-associated credential evidence (THM-0028) and the establishment path the mechanism reported for that same connection. Cloning preserves that provenance. The two components cannot be mismatched, because there is no operation that accepts them separately: the derivation's whole parameter list is a connection, and both facts are read from it in one call. A caller cannot pair a credential with another relationship's path. The path is reported, never inferred. `Full` and `FullWithHelloRetryRequest` are a full handshake; `Resumed` is a resumed session; a relationship for which the mechanism reports no path at all is refused rather than defaulted, because guessing the full-handshake reading would invent the strongest verification fact from a report the mechanism declined to make. The producer boundary is a call-site fact scoped to the production configuration, as in THM-0028: the representation and constructor are private to the owning module, its one production call site is the descendant mechanism adapter, and the owner's test module is the other member of the set privacy admits.

**Security consequence.** A consumer that needs *the configured verifier ran during THIS establishment* can tell, instead of inferring it from the existence of a connection. That inference is currently unavoidable and silently wrong on every resumed session: rustls re-runs neither chain building, nor CRL consultation, nor the validity window when it restores a stored session, so a consumer treating every established relationship as freshly verified believes work happened that did not. Equally, a consumer that does NOT need freshness cannot be misled into thinking a resumed acceptance is defective. It rests on an earlier full handshake plus an unchanged anchor set, which is a different fact, not a weaker one.

**Scope — what this does NOT establish.** It is NOT authentication, and nothing here may be read as trust. It does not establish that the credential is currently valid, unrevoked, within a configured lifetime, or issued under a policy — those are recovered per request by a different authority, and only where a ceiling or CRLs are configured. It does not establish any identity, admission, or authorization, and it does not say the relationship still exists. It deliberately does NOT carry the anchor epoch. The epoch does not reach the serving path; the only one an adapter could read there is the listener's current epoch, while the acceptance described happened at an earlier handshake, so carrying it would be the L-5 pairing this architecture forbids. What makes a resumed acceptance admissible is the ADR-MCPRE-055 epoch gate inside the session store, owned and measured by tls_listener_state::resumption_acceptance — this claim consumes that conclusion and does not restate it. The mechanism premises stay where they are owned: that the reported credential is the one associated is ASM-0033 under THM-0028, and that the reported PATH is faithful, with the store honouring its own refusal, is ASM-0035 here. Acceptance itself is a predecessor, not a decision. Every supported production build refuses an unverified peer during establishment, so the refusals this authority carries are mechanism-boundary inconsistencies rather than legal domain states.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0028

### THM-0031 — An authenticated relationship peer's identity is read from the leaf of the very credential the mechanism accepted for that relationship

**Statement.** This is a claim about the COMPOSITION, and about the ONE word it adds. Neither premise is strengthened: THM-0030 says the mechanism accepted a credential for a relationship and on which path, and THM-0029 says which identity a channel-associated credential's leaf denotes under a configured policy. Every AuthenticatedRelationshipPeerFacts inhabitant originates from an inhabitant produced by communication_assurance::authenticated_relationship_peer::authenticate_relationship_peer — a free function taking a MechanismVerifiedCredentialEvidence by value and a CertificateIdentityPolicy, and nothing else — from some acceptance V and some policy P. Its identity and source are exactly what interpreting the leaf of V's OWN channel-associated credential under P returned, and its establishment path is exactly V's. Cloning preserves that provenance. The two facts cannot be about different credentials. The derivation's whole parameter list is an acceptance and a policy: there is no parameter through which a separately obtained identity product, credential, or certificate could enter, so pairing the acceptance of relationship A with an identity read from relationship B's credential is unconstructible rather than merely untaken. That both predecessors ultimately arose from *a* connection establishes nothing — the defect this excludes is precisely two honest products of two DIFFERENT connections, and a runtime fingerprint comparison would have left the caller doing the pairing. The representation is private to the deriving module, so the derivation is the only producer; a sibling authority attempting the struct literal fails with E0451 — measured. The deriving module is a SIBLING of both predecessors rather than a module inside either, and that placement is load-bearing in the other direction: inside mechanism_verified_credential it would be a descendant and would reach the private `accept` constructor THM-0030 claims only the mechanism adapter reaches; inside channel_associated_credential it would reach `associate` and falsify THM-0028 the same way. A consumer's placement is part of its predecessor's seal. The refusal algebra is the leaf interpreter's, unchanged. Nothing new can fail: the acceptance is already in hand and is not re-decided, and the only fallible step is reading the configured field from the accepted credential's leaf.

**Security consequence.** This is the first product a consumer may read as *the peer of this relationship is this identity*, and the first whose name says so. Before it, a consumer wanting that sentence had to write it itself by holding an acceptance and an identity side by side — which is the composition this authority makes unconstructible, and whose failure mode is a request bound to an identity that authenticated on some other connection. The establishment path survives the composition. A consumer that needs *the configured verifier ran during THIS establishment* can still tell, so authentication inherited across a resumption is not silently reported as freshly verified.

**Scope — what this does NOT establish.** It does NOT establish currency. Whether the accepted credential is still within its validity window, still unrevoked, and within a configured lifetime ceiling is a different authority answering *is it still good now* — recovered per request, and only where a ceiling or CRLs are configured. It does not establish admission, authorization, channel binding, or that this peer is the actor that signed any particular request. It does not say the relationship still exists. The word *authenticated* rests on ASM-0036: that mechanism acceptance entailed a proof binding the peer to the credential — current control of its private key via CertificateVerify on a full handshake, and possession of resumption secret material derived from an earlier authenticated handshake on a resumed one, which is continuity rather than a fresh key proof. That premise is this unit's own and is not supplied by ASM-0033 or ASM-0035, which speak to what the mechanism REPORTS rather than to what acceptance required of the peer. The mechanism and parser premises stay where they are owned, and the chain-ordering premise stays under THM-0029: this claim consumes those conclusions and restates none of them.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0029, THM-0030

### THM-0032 — Per-request credential currency is decided from the credential the mechanism accepted, and reports which of its five facts refused

**Statement.** This is a claim about a PREDICATE AT AN INSTANT and about the ALGEBRA of its refusal. It does not say the credential is trusted or that the peer is authenticated; it says what the deployment's configured controls concluded about that credential at a named moment. Every CurrentCredentialFacts inhabitant originates from an inhabitant produced by communication_assurance::credential_currency::evaluation::evaluate_credential_currency — a free function taking an Option<&MechanismVerifiedCredentialEvidence>, a CredentialCurrencyPolicy and an instant, and nothing else — and carries that acceptance, that instant, and the controls the policy actually applied. There is no chain parameter and no certificate parameter: the chain evaluated is projected from the acceptance inside the operation, so the facts reported cannot be about another relationship's certificates. The chain-form worker is private to the authority, and publishing it would be a second entrance letting a caller evaluate certificates no relationship ever presented. The ADMITTED SET IS UNCHANGED from the implementation this replaces. What is new is that the five facts production computed and discarded are now distinguishable, and that the STRENGTH ASYMMETRY between them is preserved rather than repaired: leaf validity window runs whenever ANY control is configured — never fused to the ceiling leaf span ceiling only where a ceiling is configured leaf revocation `admits`: an empty index admits, otherwise Revoked AND Unknown refuse issuer validity window self-issued certificates exempt; unparseable refused issuer revocation EXPLICIT `Revoked` only — `Unknown` admits The issuer/leaf revocation asymmetry is deliberate and is carried, not corrected: whether a chain reaches a CRL-covered issuer is a path-building question the handshake settled, and re-deciding it from the certificates a peer chose to send would refuse chains a full handshake admitted. The outcome has THREE states, not two. A deployment configuring neither a ceiling nor CRLs evaluates nothing — production returns before parsing — so `NotEvaluated` is distinct from `Current`. A two-state answer would report an unexamined credential as unobjectionable, which is the same sentence as *checked, and fine*, and the credential of a peer holding a keep-alive connection open past its notAfter is exactly the credential that reaches that state. The policy is a TOTAL classification of deployment state with no `Option` and four variants, so *evaluating with nothing configured* cannot be written. The revocation index it carries is the SNAPSHOT in force for the request, not the atomic cell: the leaf check and the issuer check therefore cannot read two different indexes across a reload.

**Security consequence.** A revocation published after a handshake, and an expiry that falls during one, reach a peer that already holds a connection — rustls runs client authentication on a full handshake only, and the ADR-MCPRE-055 trust epoch digests the anchor set rather than the CRLs, so nothing else does. That property is production's and is preserved; what this adds is that the reason is no longer discarded. Before it, all seven refusals arrived as one `mcp-re.transport_binding_failed`, so an operator could not tell an expired credential from a revoked one from an absent one, and no downstream authority could branch on the difference. A weakening that swapped one refusal for another — reporting an expired credential as over-long, or an unreadable issuer as an unreadable credential — was invisible to every control that could only assert *something refused*.

**Scope — what this does NOT establish.** It establishes NO identity and NO authentication: it consumes the acceptance, not the authenticated peer, precisely so that a deployment deriving no transport identity at all (`IdentityStrategy::LbAssertion`) keeps having its credential examined. An authority gated on authentication would silently stop checking currency in exactly that deployment. It does not establish admission, authorization, or binding to a request actor. It says nothing about online OCSP, which is a separate existing path over the same chain and is deliberately unmigrated — the last raw-chain projection in the serving path is its consumer. It is a claim about an INSTANT. The product carries the instant it was evaluated at, and says nothing about the next request on the same connection. The parser premise is ASM-0030 under the adapter that owns it; the mechanism premises stay under THM-0028 and THM-0030. This claim consumes their conclusions and restates none of them.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0028, THM-0030

### THM-0033 — A current authenticated peer's currency is evaluated against the credential that same peer authenticated with

**Statement.** This is a claim about the COMPOSITION, the third application of the ADR-MCPRE-063 L-5 rule. Neither premise is strengthened: THM-0031 says what an authenticated relationship peer is, and THM-0032 says what a currency evaluation concluded about an accepted credential. Every CurrentAuthenticatedRelationshipPeerFacts inhabitant originates from an inhabitant produced by communication_assurance::current_authenticated_peer::current_authenticated_peer — a free function taking an AuthenticatedRelationshipPeerFacts by value, a CredentialCurrencyPolicy and an instant, and nothing else. Its identity, identity source and establishment path are exactly that peer's, and its evaluated instant and applied controls are exactly what evaluating the currency of THAT PEER'S OWN acceptance returned. The two facts cannot be about different credentials. The derivation's whole parameter list is a peer, a policy and an instant: there is no parameter through which a separately obtained currency product, credential, chain or certificate could enter, so pairing the authentication of relationship A with the currency of relationship B is unconstructible rather than merely untaken. That both facts concern *a* relationship establishes nothing, because it does not establish the same one, and a proxy holds many at once. No fingerprint and no linkage token were introduced: the relation is structural, so there is nothing to compare. The peer's own acceptance is reached through a named `pub(super)` projection on the predecessor. Projecting is not constructing — the predecessor's constructor stays private to its module, so THM-0031's producer boundary is untouched. `NotEvaluated` is a REFUSAL here and a legitimate outcome one level down. This type's proposition contains the words *still acceptable*, and an unexamined credential has not earned them; the currency authority's proposition is *what did the configured controls conclude*, for which the truthful answer in that deployment is that none was reached. That difference is between the two TYPES and says nothing about what a deployment may serve: the serving path consumes the currency authority directly and keeps admitting an unexamined credential exactly as before. The establishment path is projected through and never flattened. A resumed relationship whose credential is current is authenticated earlier, carried forward, and acceptable now — three facts, and reporting the first as fresh is the sentence ADR-MCPRE-055 forbids.

**Security consequence.** This is the first product a consumer may read as *the peer of this relationship is this identity, and its credential is still good*. Before it, a consumer wanting that sentence had to hold an authentication and a currency verdict side by side and assert the relation itself — the composition this authority makes unconstructible, and whose failure mode is a request served under a peer whose credential was revoked on another connection.

**Scope — what this does NOT establish.** It does not establish admission, authorization, channel binding, or that this peer is the actor that signed any request. It does not say the relationship still exists, and it is a claim about the instant it carries rather than about the next request. It has NO production caller in this slice, exactly as Slice 5 of ADR-MCPRE-063 and Slice 2 of this ADR had none when they were built. The serving path consumes the currency authority directly, because currency must keep being evaluated where no transport identity is derived at all.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0031, THM-0032

### THM-0034 — A request is bound to its relationship by relating the authenticated peer to the resolved actor's SUBJECT, never to the composite actor id

**Statement.** This is a claim about a BINARY RELATION and about the COORDINATE it is taken over. Neither operand is strengthened: THM-0031/THM-0033 say what an authenticated channel peer is, and the request verifier and trust seam say what a resolved actor is. Every RequestPeerBindingFacts inhabitant originates from an inhabitant produced by communication_assurance::request_peer_binding::bind_request_to_peer — a free function taking an AuthenticatedChannelPeer and a VerifiedRequestSubject, and nothing else — whose two operands compared EQUAL on the peer's identity value and the subject. Cloning preserves that. The coordinate is `ActorIdentity.subject`, and NOT `ActorIdentity::actor_id()`. The composite is the injective `role:trust_domain:subject:keyid` join, and it is the canonical coordinate for replay keys, audit records and trusted-key identity. Binding over it is a category error with two measurable costs, and both are controls: requiring `keyid` couples TLS certificate issuance to every signing-key rotation, and requiring `trust_domain` asserts a channel-side fact the channel never established. Nothing is weakened by taking the subject alone. The role, the trust domain, the signing key and the signer slot are established by the request verifier and the trust seam BEFORE this relation runs, and remain facts owned by those authorities. A key not trusted for a subject fails at request verification and is never rescued here; a key the resolver DOES trust for that subject is not overturned here because the credential rotated. Neither operand can be fabricated, which is what makes the relation worth taking. The channel peer descends from a mechanism adapter's acceptance over a real handshake (THM-0028, THM-0030, THM-0031). The subject's representation and constructor are private to the binding module and its one producer is the request adapter, a CHILD of that module — so a caller cannot assert a subject any more than it can assert a peer. The historical operand, `TransportIdentity`, was a public struct with public fields and a total constructor, and the one control where the old comparison passed built its input from `actor_id()` so the comparison could not fail. An ABSENT channel peer refuses. A configured binding claims every served request is bound, and an absence does not satisfy that claim. This is a BINARY COMPOSITION, not an ADR-MCPRE-063 L-5 substitution. The two operands are genuinely independent — one from a TLS relationship, one from a request signature — and their concerning the same principal is the CONCLUSION rather than a premise, as in the Slice-2 credential/key correspondence.

**Security consequence.** This is the fact a deployment means by *end-to-end mTLS*: the party that signed the request is the party that authenticated the channel it arrived over. Before it, the comparison could not succeed for a certificate naming the principal, and the only way to make it pass was to mint the escaped composite into the SAN — which is what the demo fixtures did, so the tests were green while the model was wrong. Its failure mode under the old coordinate was not an open door but a closed one plus a distorted provisioning scheme: certificates had to serialize the request verifier's internal trust record, and every signing-key rotation invalidated the fleet's certificates.

**Scope — what this does NOT establish.** It is NOT admission and NOT authorization: that a request and a channel are the same principal says nothing about what that principal may do. It is not a cross-namespace mapping. Exact-subject equality is the only relation here. A deployment needing `(trust-domain X, subject Y) <-> SPIFFE Z` gets an explicit mapped-binding authority producing its own fact — not a looser reading of this one, and not the removed `MappedBinding`, which could not honestly produce a same-principal fact. It is not RFC 8705 `x5t#S256`. That binds a request artifact to certificate BYTES; a signer can commit to the thumbprint of a certificate whose key it does not hold, so it does not establish principal equality. Production supplies no mTLS artifact material to the verifier today. It says nothing about the credential's currency beyond what the channel operand carries, and the binding reports which of the two assurances that was rather than flattening them.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0031, THM-0033

### THM-0035 — A successfully classified trust-revocation state carries the witnesses its own state form requires

**Statement.** If `config_state::trust_revocation::classify_and_validate` returns a state, then for the deployment supplied: the state form was reachable under the request, and every witness that form's Required column names is HELD BY THE STATE rather than left in the request beside it. Three of the four forms require a reload cadence, so those three cannot be constructed without one. `BoundedCache` carries the cadence as an `Option` because its column makes the cadence optional, and the ABSENCE is itself a sub-posture rather than a missing value. The state is the only route to these facts. There is no public constructor that takes the witnesses directly, so possessing the state means the classification ran.

**Security consequence.** Planning cannot project "read the document once at startup" from a tier whose whole claim is that the store is re-read. That projection would silently contradict the revocation posture an operator selected: a key removed from the trust document would keep resolving until every replica restarted, while the deployment reported the tier that promises otherwise. A zero cadence — a spinning reloader — is refused in every state form rather than in the parser alone, so a programmatically built request cannot reach it either.

**Scope — what this does NOT establish.** It says NOTHING about the trust document itself: not that the locator names an existing file, not that the file is readable, not that it parses, and not that it holds any key this deployment would trust. Those are observations, and they belong to materialization. It does not establish that the cadence is HONOURED at runtime — only that the state carries one and that the value is legal. Whether a reloader actually re-reads on that cadence is the trust plane's, and is outside this claim. It is not a claim about revocation REACHING a peer. A cadence bounds how stale the local document may be; it says nothing about propagation to other replicas, which is the epoch mechanism's concern (THM-0036) and is separately unproved end to end.

**Review requirement.** Owner security-specification review

### THM-0036 — A networked trust-epoch source is handed over as a paired locator and key, or not at all

**Statement.** If `TrustRevocationState::epoch_source` returns a source, then for the state supplied: both the counter's locator and the key holding it are present, both were validated together, and both are projected together by `EpochSource`. Neither half is separately reachable. `EpochSource` borrows the state and exposes `url()` and `key()`; there is no path that yields one without the other, and no public constructor that assembles one from parts. The key is resolved against its default HERE, once. Two consumers — the trust cache and delegated signing — read the same resolved value rather than each defaulting for itself.

**Security consequence.** A counter read from the right store under the wrong key reports an epoch that never advances: a revocation channel that silently stops revoking while reporting itself configured. Pairing the two makes that combination unconstructible rather than merely unlikely. Two consumers defaulting the key independently agreed only because they happened to spell the same fallback. Nothing made them, and a deployment could have had its trust cache watching one key while delegated signing minted under another.

**Scope — what this does NOT establish.** It does not establish that the counter EXISTS at that locator, that the store is reachable, that the key holds a number, or that anything ever increments it. The source is a validated request fact, not an observation. It does not establish that a build can USE the source. A configured Redis epoch source in a build without the `redis_replay` feature is refused at planning by `TrustEpochPlan::unsupported_by_build`, which is a layer-B fact and outside this claim. It says nothing about propagation LATENCY, nor that an operator's increment reaches every replica within any bound.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0035

### THM-0037 — A trust plan's reload cadence is a projection of the revocation posture, never a second value

**Statement.** For every `TrustPlan`, `reload()` is DERIVED from the plan's own revocation state on demand. This is a structural claim about the representation, and the operative fact is an ABSENCE: `TrustPlan` has no reload field. There is nothing to set, nothing to copy, and no constructor, builder or projection through which a caller could supply a cadence beside a state that disagrees with it. Deleting a check elsewhere cannot bring a contradictory inhabitant into existence, because the contradictory inhabitant is not representable. The plan likewise cannot become the authority for the two values it is HANDED — the response issuer kid and the shared epoch mechanism. Both are constructor arguments, and a plan built with a value the configuration does not name carries that value, which is only possible because nothing inside re-derives them (CF-09).

**Security consequence.** A stored copy is a second value that can disagree with the first, and this one had already drifted: a test fixture named a 30-second reload beside a state carrying 5. A consumer reading the copy would act on a cadence the revocation posture never authorized — reporting a tier that promises frequent re-reads while re-reading on someone else's schedule. Because the plan cannot re-derive the issuer kid, a deployment cannot be told it is chaining to one issuer while another is excluded from the request-signer set.

**Scope — what this does NOT establish.** It does not establish that any reload HAPPENS, on that cadence or at all. `reload()` reports what the posture decided; performing it is the trust plane's, and a plane that never re-reads would not violate this claim. It does not establish anything about the trust document — see THM-0035's scope. A plan holds a locator; it does not know whether the locator names a file. It does not establish that the epoch mechanism it carries WORKS, only that the plan did not invent it.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0035

### THM-0038 — The composition root consumes trust as owner projections and re-reads no trust field from the request

**Statement.** After layer A has classified a deployment, the composition root reads from `ValidatedDeployment::config()` only fields on a pinned inventory of ORDINARY validated parameters — ones whose value, changing while every owner state stays unchanged, cannot change a security-sensitive decision or effect. No trust field is on that inventory. The trust locator, the revocation tier, the reload cadence and the epoch coordinates all left it when they acquired owners, so trust reaches materialization only as `TrustDocumentSource`, `TrustRevocationState` and the `TrustPlan` that composes them. The evidence is a source-text inventory checked against the file it describes, and its own detection is part of what is measured: the guard includes a control that a NEW raw read would fail it. A rule that cannot detect the thing it forbids passes vacuously.

**Security consequence.** The original request stops being a semantic authority once it has been classified. Without this, a consumer could re-derive a trust posture from the raw request and reach a different answer than the one layer A established — the same fact with two authorities, which is what CF-09 exists to prevent — and the disagreement would be invisible because both readings would look principled.

**Scope — what this does NOT establish.** It is narrow in three ways, and each matters. It claims nothing else about `app.rs`. The composition root has other responsibilities and this theorem reaches none of them; it is a statement about trust consumption only. It is a SOURCE-TEXT property, not a runtime one. It establishes which fields the root reads in the code as written, not that any particular execution took a particular value. A raw read introduced through an alias, a helper in another file, or a macro is outside what the guard measures. It does not establish that PLANES do not reach back — that is a different failure with its own control (`plane_config_reachback_test`), because the root is entitled to read the request and a plane is not. And it establishes nothing about the trust document's existence or contents.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0035, THM-0037
