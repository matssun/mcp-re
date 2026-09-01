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

## System roots

The claims MCP-RE makes at its boundary. Proof-tree completeness is derived over
these and reported by `tools/verification/review`; this view cannot see whether
any of them is closed.

| root | claim |
|---|---|
| THM-0074 | No unearned dispatch |
| THM-0078 | Refusal is terminal, and no refusal-side effect reads as success |
| THM-0075 | No unearned response attribution |
| THM-0076 | A client accepts only an answer to its own request, under a signer it trusts |
| THM-0077 | No deployment serves a posture nobody selected |
| THM-0091 | The sidecar signs only for a request its ingress policy admitted |
| THM-0012 | The lifecycle record cannot claim a shutdown that did not happen |
| THM-0072 | A verified receipt proves registration on the service this deployment pinned |
| THM-0042 | Retained evidence is the evidence the statement was made about |
| THM-0071 | Every reachable in-exchange refusal has a typed provenance that reaches the record |

| id | title | owner | supported by | lifecycle |
|---|---|---|---|---|
| THM-0001 | Admitted request parameters imply a current freshness window | http_profile.freshness_window | unit://http_profile.freshness_window | live |
| THM-0002 | RFC 3339 parsing is total and range-bounded | core.time_rfc3339 | unit://core.time_rfc3339 | live |
| THM-0003 | Admission verdict integrity | http_profile.admission_currency | unit://http_profile.admission_currency | live |
| THM-0004 | Admission anti-rollback | http_profile.admission_currency | unit://http_profile.admission_currency | live |
| THM-0005 | Degraded admission requires deployment opt-in | http_profile.admission_currency | unit://http_profile.admission_currency | live |
| THM-0006 | Presenter binding | http_profile.admission_currency | unit://http_profile.admission_currency | live |
| THM-0007 | A typed artifact verifier admits only its own type | http_profile.artifact_typing | unit://http_profile.artifact_typing | live |
| THM-0008 | No untyped artifact binding leaves the verifier as verified | http_profile.artifact_verification_boundary | unit://http_profile.artifact_verification_boundary | live |
| THM-0009 | A presented continuation cannot bypass verification | http_profile.continuation_unbypassability | unit://http_profile.continuation_unbypassability | live |
| THM-0010 | Continuation handles match their presented inputs in role | http_profile.continuation_binding | unit://http_profile.continuation_binding | live |
| THM-0012 | The lifecycle record cannot claim a shutdown that did not happen | proxy.runtime_lifecycle | unit://proxy.runtime_lifecycle | live |
| THM-0013 | No validated deployment enables online OCSP client-certificate revocation | proxy.online_ocsp_reachability | unit://proxy.online_ocsp_reachability | live |
| THM-0014 | A successful request-floor verification establishes the cryptographic floor | http_profile.verifier_results | unit://http_profile.freshness_window, unit://http_profile.verifier_results | live |
| THM-0015 | A successful full-profile request verification establishes audience and artifact binding | http_profile.verifier_results | unit://http_profile.artifact_verification_boundary, unit://http_profile.verifier_results | live |
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
| THM-0039 | An accepted PDP decision was authenticated under a key the trust seam resolved | http_profile.pdp_decision_authentication | unit://http_profile.pdp_decision_authentication | live |
| THM-0040 | An authorized request was permitted by a decision about that very request | proxy.pdp_decision_relation | unit://proxy.pdp_decision_relation | live |
| THM-0041 | An offline-verified receipt proves registration, and its root was never supplied | http_profile.scitt_receipt_offline | unit://http_profile.scitt_receipt_offline | live |
| THM-0042 | Retained evidence is the evidence the statement was made about | http_profile.scitt_retained_correspondence | unit://conformance.retained_corpus, unit://http_profile.scitt_retained_correspondence, unit://http_profile.submitted_hop_identity | live |
| THM-0043 | The exchange relation is decided everywhere and the execution threshold partitions it | proxy.exchange_lifecycle | unit://proxy.exchange_lifecycle | live |
| THM-0044 | An exchange's retry consequence never under-reports what may have happened | proxy.exchange_lifecycle | unit://proxy.exchange_lifecycle | live |
| THM-0045 | The backend is reached only by consuming a fully assembled pre-dispatch commitment | proxy.dispatch_commitment | unit://proxy.dispatch_commitment | live |
| THM-0046 | A refusal carries which authority reached it, over a closed set, unrendered | proxy.refusal_provenance | unit://proxy.refusal_provenance | live |
| THM-0047 | The verifier's assurance products are not substitutable | http_profile.verifier_result_separation | unit://http_profile.verifier_result_separation | live |
| THM-0048 | Every listener obtains its whole security posture through one listener state | proxy.tls_listener_state | unit://proxy.tls_listener_state | live |
| THM-0049 | Every illegal cross-owner configuration combination is refused at layer A | proxy.cross_machine_legality | unit://proxy.cross_machine_legality | live |
| THM-0050 | Distinct verification keys cannot feasibly be made to share a keyid | http_profile.keyid_selector | unit://http_profile.keyid_selector | live |
| THM-0051 | The pipeline holds, at dispatch, the verification product of this very exchange | proxy.dispatch_commitment | unit://http_profile.verifier_result_separation, unit://proxy.dispatch_commitment | live |
| THM-0052 | A dispatched body was released by the decision a configured policy produced | proxy.dispatch_commitment | unit://proxy.dispatch_commitment, unit://proxy.pdp_decision_relation | live |
| THM-0053 | A presented admission assertion is authentic, in its window, and for this audience | http_profile.admission_assertion | unit://http_profile.admission_assertion | live |
| THM-0054 | Every production listener denies unknown client revocation status | proxy.tls_listener_state | unit://proxy.tls_listener_state | live |
| THM-0055 | The keyid derivation introduces no collisions of its own | http_profile.keyid | unit://http_profile.keyid | live |
| THM-0056 | The posture that claims nothing is produced only where no policy is configured | proxy.authorization_posture | unit://proxy.authorization_posture | live |
| THM-0057 | A client's trust anchors are the ones the current signed manifest published | client.trust_manifest_lifecycle | unit://client.trust_manifest_lifecycle | live |
| THM-0058 | A client accepts a response only under a signer its trust configuration authorizes | client.response_acceptance | unit://client.response_acceptance, unit://client.trust_manifest_lifecycle | live |
| THM-0059 | An unbound receipt is never a success and never another request's answer | client.response_acceptance | unit://client.response_acceptance | live |
| THM-0060 | The client's clock skew is bounded at construction and read once | client.delegation_policy_seal | unit://client.delegation_policy_seal | live |
| THM-0061 | A receipt that says nothing is not a receipt that says nothing ran | client.execution_contract | unit://client.execution_contract | live |
| THM-0062 | A response-signing credential exists only while a valid delegated key does | proxy.delegated_signing_credential | unit://proxy.delegated_signing_credential | live |
| THM-0063 | A signed response never advertises validity its credential does not authorize | proxy.response_signing | unit://proxy.delegated_signing_credential, unit://proxy.response_signing | live |
| THM-0064 | A non-exporting custody selection keeps the private key off this process | proxy.custody_exposure | unit://proxy.custody_exposure | live |
| THM-0065 | An emitted bound response signature binds the request it answers | http_profile.response_emission_binding | unit://http_profile.response_emission_binding, unit://http_profile.verifier_results | live |
| THM-0066 | The serving PEP resolves actors through the deployment's materialized trust authority | proxy.serving_trust_seam | unit://proxy.serving_trust_seam, unit://proxy.trust_plan | live |
| THM-0067 | The composition root re-reads no owner's security semantics from the request | proxy.trust_composition_root | unit://proxy.trust_composition_root | live |
| THM-0068 | A pinned transparency service is one operator-reviewed document, or it is not a pin | http_profile.scitt_service_pin | unit://http_profile.scitt_service_pin | live |
| THM-0069 | A security record states each authority's outcome in that authority's own coordinate | proxy.audit_record_coordinates | unit://proxy.audit_record_coordinates, unit://proxy.refusal_provenance | live |
| THM-0070 | The record stream is honest about what reached it | proxy.audit_delivery | unit://proxy.audit_delivery | live |
| THM-0071 | Every reachable in-exchange refusal has a typed provenance that reaches the record | proxy.audit_record_coordinates | unit://proxy.audit_record_coordinates, unit://proxy.refusal_provenance | live |
| THM-0072 | A verified receipt proves registration on the service this deployment pinned | http_profile.scitt_receipt_offline | unit://http_profile.scitt_receipt_offline, unit://http_profile.scitt_service_pin | live |
| THM-0073 | Serving materialization refuses a deployment whose two signing roles are one key | proxy.signing_role_separation | unit://proxy.signing_role_separation | live |
| THM-0074 | No unearned dispatch | proxy.dispatch_commitment | unit://proxy.dispatch_commitment, unit://proxy.exchange_lifecycle | live |
| THM-0075 | No unearned response attribution | proxy.response_signing | unit://http_profile.response_emission_binding, unit://proxy.response_signing | live |
| THM-0076 | A client accepts only an answer to its own request, under a signer it trusts | client.response_acceptance | unit://client.response_acceptance | live |
| THM-0077 | No deployment serves a posture nobody selected | proxy.trust_composition_root | unit://proxy.cross_machine_legality, unit://proxy.trust_composition_root | live |
| THM-0078 | Refusal is terminal, and no refusal-side effect reads as success | proxy.exchange_lifecycle | unit://proxy.exchange_lifecycle, unit://proxy.refusal_provenance | live |
| THM-0079 | Distinct signed exchanges have distinct replay keys | http_profile.replay_key | unit://http_profile.replay_key | live |
| THM-0080 | Serving derives peer identity only from the credential the mechanism accepted | proxy.serving_identity_provenance | unit://proxy.serving_identity_provenance | live |
| THM-0081 | Every production refusal is inside the exchange lifecycle | proxy.refusal_site_totality | unit://proxy.refusal_site_totality | live |
| THM-0082 | The serving path signs under the credential source materialization produced | proxy.signing_credential_provenance | unit://proxy.signing_credential_provenance | live |
| THM-0083 | What a request is, is decided once, before anything reads it for meaning | http_profile.request_envelope | unit://http_profile.request_envelope, unit://proxy.outstanding_id_provenance | live |
| THM-0084 | The shipped client proxy verifies against the request it sent | client.proxy_request_correspondence | unit://client.proxy_request_correspondence | live |
| THM-0085 | Every exchange-owned refusal reaches the audit boundary, typed, before it is answered | proxy.refusal_audit_emission | unit://proxy.refusal_audit_emission | live |
| THM-0086 | The established replay tier is the selected one, and never a weaker substitute | proxy.replay_materialization | unit://proxy.replay_materialization | live |
| THM-0087 | A continuation entry is reachable only by the actor the verifier resolved | proxy.continuation_correlation_store | unit://proxy.continuation_correlation_store | live |
| THM-0088 | A retention artefact reads as a crossing only for an exchange that crossed | proxy.retention_commitment | unit://proxy.retention_commitment | live |
| THM-0089 | A KMS or STS endpoint reaches the authority its text names | proxy.kms_endpoint_authority | unit://proxy.kms_endpoint_authority | live |
| THM-0091 | The sidecar signs only for a request its ingress policy admitted | client.local_ingress_authority | unit://client.local_ingress_authority | live |
| THM-0092 | A request whose replay state was not established does not dispatch | proxy.replay_admission_gate | unit://proxy.replay_admission_gate | live |
| THM-0093 | An answer leg that needs a continuation does not proceed unbound | proxy.continuation_leg_binding | unit://proxy.continuation_leg_binding | live |

## Claims in full

### THM-0001 — Admitted request parameters imply a current freshness window

**Statement.** Every signature-parameter set the verifier admits satisfies created - skew <= now, now < expires + skew, created < expires, and a lifetime within the policy maximum, for the skew the verifier policy yields.

**Security consequence.** A request cannot be admitted on freshness evidence that has expired, that is dated ahead of the verifier, or that declares a lifetime longer than the policy permits.

**Scope — what this does NOT establish.** Establishes freshness admission only. It does not establish signature validity, issuer authority, admission currency, or replay uniqueness. The window is stated relative to skew_of(policy), an opaque accessor: the theorem holds for whatever skew the deployment configures and does not establish that the configured skew is bounded or sane.

**Review requirement.** Owner security-specification review

### THM-0002 — RFC 3339 parsing is total and range-bounded

**Statement.** parse_rfc3339_utc terminates without panicking on arbitrary input, and every timestamp it accepts denotes an instant within the parser's ADMITTED four-digit civil range 0000-01-01T00:00:00Z through 9999-12-31T23:59:59Z, that is [-62167219200, 253402300799]. Both bounds are TIGHT: each is attained by an accepted timestamp, so neither can be narrowed. RFC 3339 defines the era as 0000AD through 9999AD; MCP-RE admits a stricter UTC-only four-digit-year subset of it, and the grammar's four-digit year together with the refusal of leap seconds is what makes 9999-12-31T23:59:59Z the maximum value the function can return.

**Security consequence.** A timestamp in an evidence artifact can neither crash the verifier nor denote an instant the rest of the system cannot represent.

**Scope — what this does NOT establish.** The two halves are established differently and a reviewer must not look for one conjunct. The range half is the postcondition. Totality is discharged by the absence of a precondition together with the prover's panic-freedom obligation, not by an ensures clause. The theorem says nothing about which grammar variants are accepted beyond that what is accepted is in range. It does not establish that every instant in the range is REACHABLE by some accepted timestamp — only that nothing outside it is. The two endpoints specifically are reachable, and are pinned by boundary controls at their exact Unix seconds, but the claim is containment. It says nothing about the inverse direction: that unix_to_rfc3339_utc round-trips a value in this range is a different proposition with its own evidence.

**Review requirement.** Owner security-specification review

### THM-0003 — Admission verdict integrity

**Statement.** Every admission verdict returned as Ok has status Admitted and carries the generation of the binding that was checked.

**Security consequence.** A policy enforcement point cannot act on a verdict that describes a different call than the one it checked.

**Scope — what this does NOT establish.** Does not establish authenticity, issuer trust, audience validity, assertion freshness, or validity of the assertion's [nbf, exp] window; verify_admission_assertion is outside this proof cone under ASM-0012. Does not establish that the admitted actor is the presenter of the call (see the presenter-binding claim, which this contract does not state).

**Review requirement.** Owner security-specification review

### THM-0004 — Admission anti-rollback

**Statement.** A non-degraded Ok verdict implies the authoritative admission state was reachable, that state is ABOUT the workload the call is bound to — its `admission_id` equals the binding's, which the earlier binding/assertion comparison has already equated with the verified assertion's — and at that workload its generation equals the binding's generation and its status is Admitted. The three conjuncts are ordered, and the order is the claim. Generation equality and `Admitted` are properties OF a subject; asserted about an unnamed record they are satisfied by any workload that happens to sit at the same number, and a generation is a per-workload counter, so that is the ordinary case rather than a contrived one.

**Security consequence.** A workload whose admission has been superseded or revoked cannot buy a call with an assertion that has not yet expired, and cannot buy one with ANOTHER WORKLOAD'S authoritative state either — not even a state at the same generation, still admitted, and in every other respect a well-formed answer.

**Scope — what this does NOT establish.** Says nothing about the degraded path, and nothing about the assertion's authenticity or freshness (ASM-0012). Currency is generation equality against the state the enforcement point holds; the theorem does not establish that that state is itself current, nor that the authority behind it is the right authority to trust. The subject conjunct is a claim about the VERDICT, not a caller obligation. It was one: the state carried a generation and a status and no workload identity, so the proof quantified over whatever record the caller supplied, and the security consequence rested on every enforcement point remembering to look the record up under the `binding.admission_id` it had just checked. Every one of them did. That is what a remembered convention looks like, and the R-SEAL test asks whether the check could be deleted and still leave an invalid value unconstructible: it could not, because there was no check — there was nothing to compare. `AuthoritativeAdmission` now carries its subject, and `AuthoritativeAdmission::new` — which cannot be called without naming the workload — is its only construction anywhere the value is consumed. The seal is `#[non_exhaustive]` rather than private fields, and here that binds every actual consumer: all of them are in `mcp-re-proxy`, where the struct literal is refused outright. The fields stay public because Verus does not accept an `external_type_specification` over a datatype with non-public ones, and the postcondition carrying the subject conjunct is this theorem's primary evidence; reading a field cannot produce an illegal value, and construction is what is closed. So the id in the value is the id the adapter looked up: the Redis source builds it from the key it read the record under and files a published record under the record's own subject, and the in-memory source keys its map by the same. There is no longer a pair of operands that could disagree. The claim remains about ONE enforcement decision. It does not establish that the store's key is the workload's true name, nor that a compromised authority publishes true records — those are the authority's propositions, not this one's.

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

**Statement.** If `enforce_full_profile_bindings` returns Ok for an `HttpRequestEvidenceBlock`, then every `ArtifactBinding` that block declared matched one of MCP-RE's explicitly supported typed verification branches and satisfied that branch's required binding form. The supported branches are exactly two: * the OAuth typed-verifier family, reached through `artifact::verify_artifact_binding` for `OauthDpop`, `OauthMtls` and `OauthRar`, each in the `OpaqueDigest` form and against resolved credential material; * `PdpDecision` in the `OpaqueDigest` form, reached through `pdp_decision::verify_pdp_decision_binding` and only when the block carries the decision document the binding commits to. Every other `ArtifactType`, and every binding form outside the branch that admits it — a `ReferenceDigest` entry included — is refused. A `PdpDecision` binding whose block carries no decision has no supported branch and is refused with the rest.

**Security consequence.** An artifact type that nothing supports cannot be laundered into a verified result: it is refused, not skipped, and not reported verified by a branch built for a different type. A caller therefore cannot silently treat an unsupported artifact type as though it had been verified, and adding a registry type does not quietly widen what verification concludes.

**Scope — what this does NOT establish.** Structural over the dispatch relation, and inherits THM-0007's exclusion: it does not establish that any digest matched its credential (ASM-0018), nor that the supplied material is the credential the peer actually holds. It says which branch a verified binding took; it says nothing about what a decision document AUTHORIZES. Digest correspondence is one link — authority trust, actor and action relation, validity and an explicit Allow are separate propositions with their own owner (ADR-MCPRE-065), and none of them is claimed here. The cardinality of the supported set is a fact of the current implementation, not the spine of the claim: the proposition is the closed selection, so adding a typed verifier obliges a re-measurement rather than making the sentence false by arithmetic.

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

**Statement.** Every DeploymentRequest whose `peer_revocation.online` is `OnlineRevocationEvidenceRequest::Required` is refused by the legality boundary, in every build and independently of the online_ocsp feature. Every ValidatedDeployment therefore carries `peer_revocation.online == OnlineRevocationEvidenceRequest::NotRequired`, and the serving path is handed no OCSP checker. The refusal is over the SELECTION, not over any responder parameter it carries: an `OcspResponderRequest` travels inside `Required`, so every deployment that names a responder is already refused by the selection that holds it.

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

**Statement.** If `Verifier::verify_request` returns Ok, then the request-floor proposition holds for the same request, and in addition: the request evidence block parsed and validated under the profile tag, its audience tuple equalled the verifier's own and agreed with the request's `@target-uri`, and every artifact binding the block declared was verified through the supported typed verification branch for its artifact type (THM-0008) — against the credential material resolved for that binding, or, for the carried authorization-decision form, against the decision document the block itself carried.

**Security consequence.** A request signed for a different audience, route or target cannot be successfully returned as a full-profile verified request, and a declared artifact binding cannot be skipped by withholding the evidence it commits to — an unobtainable credential, and an artifact type with no supported typed verification branch, both fail closed rather than being ignored.

**Scope — what this does NOT establish.** This theorem characterizes values successfully returned by `verify_request`. It does not establish that an arbitrary externally constructed `VerifiedMcpRequest` was produced by that operation. It establishes nothing about replay admission, admission-assertion currency, continuation binding or dispatch authorization; a full-profile request is not an admitted one — which is why the consequence above is phrased over what this operation returns rather than over what a deployment admits. It does not establish that the artifact material the caller supplied is the credential the peer actually holds — only that the binding verified against what was supplied. A verified `pdp-decision` binding establishes that the block carried the exact decision document its digest committed to. It establishes nothing about what that document AUTHORIZES: authority trust, the actor and action relations, validity and an explicit Allow are the authorization owner's propositions (ADR-MCPRE-065), not this one's.

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

**Statement.** If `Verifier::verify_bound_response` returns Ok, then the trust-seam-authorized bound response-floor proposition holds for the same response and request, and in addition: the response evidence block parsed and validated under the profile tag, the `server_signer` identity it declared carries the keyid the signature was accepted under, and the `request_evidence` handle it carried equals the handle OF THAT SAME REQUEST — the digest of the signature base the request's own `Signature-Input` describes, derived here from the request the `;req` components were resolved against.

**Security consequence.** A response cannot declare a server signer it did not sign as, and cannot claim to answer a request other than the one it is being verified against. The handle it advertises and the request the `;req` binding covers are the same exchange by construction rather than by an agreement between two operands — a semantic check on top of the cryptographic `;req` binding, reported as its own refusal.

**Scope — what this does NOT establish.** This theorem characterizes values successfully returned by `verify_bound_response`. It does not establish that an arbitrary externally constructed `VerifiedMcpResponse` was produced by that operation. **There is ONE request input.** The operation used to receive two — a concrete request, against which the `;req` components are resolved, and separately a `RequestEvidence` handle, against which the block's handle is compared — with nothing relating them. A caller could supply request A and handle B, and a success then established cryptographic binding to A and semantic equality with B and NOT that A and B denote the same exchange. Both callers did relate them, and that was the problem: a convention held at two call sites, which a third would not have violated visibly. The handle is a function of the request, so it is DERIVED at the boundary and the second operand is gone. `request A + handle B` is not refused; it is unconstructible, because there is nowhere to put B. What the derivation reconstructs is the signature base the request's `Signature-Input` describes — no signature is checked and no trust resolved there, because the handle of a request is a fact about its bytes; a request whose signature does not verify is refused by the floor above. Only the KEYID of the declared `server_signer` was compared. The block's `role`, `trust_domain` and `subject` are its own claim, checked against nothing here. It makes no delegation claim. The signer was resolved through the trust seam, and whether a credential chain authorized one is THM-0019 — a different proposition over a different product, not a strengthening of this one.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0016

### THM-0019 — A successful delegated bound response verification establishes an accepted credential chain

**Statement.** If `Verifier::verify_delegated_bound_response` returns Ok, then the shared bound-response proposition holds for the same response and request, and in addition: the response evidence block parsed and validated under the profile tag; it carried an inline delegation credential; that credential verified as a chain to a root issuer key the trust seam resolved for the Response slot and was accepted under the supplied expectations; the keyid the signature was accepted under is the delegated kid that the credential confirms and the block declares; and the `request_evidence` handle the block carried equals the handle OF THE SAME REQUEST the `;req` components were resolved against, derived from it here.

**Security consequence.** A response signed directly by the root, or by a key with no chain to a trusted issuer, cannot be accepted where delegation is required; a credential cannot be lifted onto a response signed by a different key, because the delegated kid must match on three sides; and the response cannot claim to answer a request other than the one it is being verified against.

**Scope — what this does NOT establish.** This theorem characterizes values successfully returned by `verify_delegated_bound_response`. It does not establish that an arbitrary externally constructed `VerifiedDelegatedMcpResponse` was produced by that operation. **It does NOT establish THM-0016 or THM-0018, and does not depend on them.** Those claims say the presented signing keyid was resolved through the trust seam; on this path it was not, and no trust map contains it. The seam was queried for the credential's ROOT ISSUER kid, and what authorizes the signing key is the chain. That is why the product carries the shared `BoundResponseSignatureFacts` rather than a `CryptographicFloorVerifiedBoundResponse`: a nested seam-authorized product here would be a value whose documented meaning is false. Reading upward is likewise blocked: `AcceptedResponseSigner` records who signed, not that anyone vouched for the key directly. A consumer whose reasoning needs a trust-store entry for the SIGNING key gets nothing from this claim. The expectations are SUPPLIED, not proved current or sane by this unit: the accepted epoch set, the verifier audiences, the expected audience-scope hash and the credential clock-skew tolerance all come from the caller, and this claim says the credential satisfied them, not that they were the right ones. Revocation is likewise a caller-supplied predicate. There is ONE request input, in exactly the sense THM-0018 states: the `;req` binding and the handle comparison are both about the request supplied, because the handle is derived from it rather than accepted beside it.

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

**Scope — what this does NOT establish.** It does not establish admission, authorization, channel binding, or that this peer is the actor that signed any request. It does not say the relationship still exists, and it is a claim about the instant it carries rather than about the next request. It is a claim about the COMPOSITION PRODUCT, not about serving. `tls::resolve_channel_peer` is the production caller: it applies this authority on the channel-credential serving path, propagates a currency refusal out as the transport-boundary refusal, and carries a successful product on as `AuthenticatedChannelPeer::Current`. So the derivation is a CONTROL — refusing here refuses the request — and the successful facts are the WITNESS, the earned product a consumer may read. What the consumer then does with that product is outside this claim. Whether a request is admitted, authorized, or bound to this peer is decided by other authorities with their own propositions; this theorem establishes only that the product, where one exists, is about one credential and one peer. The serving path also consumes the currency authority DIRECTLY on the arm where no transport identity is derived at all — currency must still be evaluated there — and that arm produces no inhabitant of this type and is outside the claim.

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

### THM-0039 — An accepted PDP decision was authenticated under a key the trust seam resolved

**Statement.** If `verify_authorization_decision` returns Ok, then the presented document is a well-formed compact JWS; its protected header carries the profile's `typ` and `alg` and no others; the header's kid and the claims' issuer kid are the same kid; the signature verified under the key the AUTHORIZATION trust seam resolved for that kid; the claims name this evidence profile; the claims' audience contains one of this enforcement point's own audiences; `now` lies inside `[nbf - skew, exp + skew)` with `exp` strictly after `nbf`; the decision was not issued in the future beyond the skew; and its age does not exceed this deployment's own decision-age cap. A `Deny` decision satisfies all of this and returns Ok. It is a statement the authority made, and refusing it here would make *the authority denied* indistinguishable from *the evidence was unusable*.

**Security consequence.** A kid never introduces trust: a decision signed by an issuer this deployment did not configure for AUTHORIZATION is refused rather than resolved, so a workload credential cannot become a policy authority by naming itself one. A decision issued for another evidence profile or another enforcement point cannot be replayed here. And the staleness bound is the VERIFIER'S: how long a decision lives is the issuer's choice, how long this PEP will act on one is not.

**Scope — what this does NOT establish.** It establishes nothing whatsoever about the request in hand. A decision may be perfectly authentic and be about a different actor, a different operation or a different target; relevance is THM-0040 and is a separate proposition over a separate authority, exactly as `verify_admission_assertion` is separate from `check_admission`. It does not establish that the authority SHOULD be trusted — only that the seam answered for that kid, which is the deployment's configuration speaking rather than this claim. It says nothing about the decision's correspondence to the signed request evidence: that the carried document is the one the binding committed to is THM-0008's dispatch relation and THM-0015's artifact conjunct, established before this function is reached. Ed25519 verification is taken as an opaque decision procedure, and this claim says nothing about what a valid signature means cryptographically.

**Review requirement.** Owner security-specification review

### THM-0040 — An authorized request was permitted by a decision about that very request

**Statement.** If `PdpDecisionEvaluator::evaluate` returns Ok for an `AuthorizationRequest`, then THM-0039 holds for the decision it consumed, and in addition: the decision's declared actor scope equals the scope this deployment accepts; the decided actor's trust domain and subject equal the request's VERIFIED actor's, and under credential scope its keyid does too; the decided operation equals the operation the SIGNED BODY named; the decided target and the signed target agree as typed values, where a decision naming no target matches only a not-applicable one and an absent signed target matches neither; and the decision's own outcome is `Permit`. The Permit conjunct is LAST and is not implied by the others. Everything before it establishes that this decision is ABOUT this request; only the decision itself says whether the request may proceed.

**Security consequence.** **A decision is not a bearer token.** Without the actor relation, anyone whose key the enforcement point resolves — a lower-privilege tenant, a compromised sibling workload, anything that read one authorized request body or one request log — could copy an authorized peer's decision into their own signed evidence block and be authorized by it. The gate would then establish *some principal was permitted this action*, never *this caller was*. The action relation is the same argument one axis over: a decision for `tools/list` cannot authorize `tools/call`, and a decision naming no tool cannot authorize a call that names one. Both operands are VERIFIED facts — the actor the request verification resolved and the operation the signed body named — rather than strings reconstructed from a header, a session field or a log.

**Scope — what this does NOT establish.** It is authorization, and not admission, authentication, channel binding or transport identity. It does not establish that the actor coordinates on the request were correctly resolved: that is the verified-request family's claim, and this one consumes it. It says nothing about what happens after the grant, nor about whether the policy the authority applied was the right policy — an authority that permits everything satisfies this theorem completely. Nor does it establish that a refusal is reported faithfully to an operator; the refusal algebra is tested and deliberately carries no theorem, because its vocabulary has no production reader today. The reference binding form produces no authorization at all and is outside this claim: it is never a candidate, so it cannot be selected and then rejected.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0039

### THM-0041 — An offline-verified receipt proves registration, and its root was never supplied

**Statement.** If `verify_receipt_offline` returns Ok, then: the Signed Statement's own COSE `Sig_structure` verified under a key resolved for its issuer kid, so the statement is attributed to the party that actually signed it and to no other; the statement carries the RFC 9943 §6.1 CWT claims in its PROTECTED header, with `iss` equal to the signing kid, `sub` equal to the MCP-RE statement subject and the MCP-RE statement content type, so no other `COSE_Sign1` the same key produces can be read as MCP-RE call evidence; the receipt parsed as an RFC 9942 §5.2.1 receipt; running the RFC 9162 §2.1.3.2 inclusion algorithm over the statement's leaf hash at the receipt's leaf index and tree size produced a root that, for an ATTACHED receipt, equals the root the receipt commits to and, for a DETACHED one, IS the payload the transparency-service signature was checked against; the transparency service's signature verified under a key resolved for its kid; where the pinned profile binds the position, the commitment the service SIGNED equals the one recomputed over that derived root; and both signatures were attempted only under an algorithm the protected header names and the resolved key agrees with, out of EdDSA and ES256 and nothing else. No network was contacted.

**Security consequence.** The root is DERIVED from the statement under verification and never supplied by the caller, on either payload form. A receipt cannot be made to verify by handing in a convenient root, and on the detached form a wrong fold produces a different `Sig_structure`, so the signature simply fails rather than being compared against something the caller chose. An auditor can therefore check that a record existed without trusting the log to replay honestly and without contacting it. Attribution is part of that: possession of a parsed `SignedStatement` proves nothing — `SignedStatement::from_cose` deliberately parses without verifying — and it is THIS operation, over the exact signed bytes, that makes the issuer claim true. Algorithm confusion is refused rather than attempted.

**Scope — what this does NOT establish.** It establishes registration on A SERVICE whose key was resolved. It does NOT establish that the service is honest, that its log is append-only, that the entry is unique, or anything about the log's current state — this is offline verification, and none of those properties is checkable without the log. It says nothing about the CALL the statement describes: that the retained evidence is the evidence the statement was made about is THM-0042, a separate proposition over a separate authority. The two RFC 9162 implementations in this tree stay two on purpose. `prototype` builds a tree and `merkle` verifies a path, and they are an independent cross-check; this claim is over the verification side alone and must not be read as a claim about the builder. `PrototypeTransparencyService` is a public compatibility surface, test/conformance support and a build-side oracle, and is NOT a production security product — no consequence here depends on it. `ReceiptPositionProfile::Bound` is exercised as conformance evidence and is NOT a selectable production configuration. A theorem about code this claim covers does not make a deployment posture supported.

**Review requirement.** Owner security-specification review

### THM-0042 — Retained evidence is the evidence the statement was made about

**Statement.** If `verify_retained_evidence` returns Ok, then the commitment carried by the statement equals the commitment recomputed from the presented reconstruction together with its optional binding and verified-context commitments. So the presented reconstruction is the one that statement committed to, and the `ChainLabel` the commitment embeds is the label of THAT reconstruction — including, when it is incomplete, which hop was missing and why. The equality is over EVERY field the commitment carries, and `submitted_commitment` is one of them. It is the only field that reaches the hops AFTER the verified prefix: every other identity field is derived from that prefix, so on an Incomplete record the unverified tail contributes to none of them. A statement that carries no submission identity therefore cannot bind one, and Ok is not returned for it — neither for a retained record that claims one, nor for a retained record that claims none. Both are the same record: one whose tail this comparison does not reach, and for which Ok would report a binding it does not have.

**Security consequence.** Retained evidence cannot be swapped under a receipt, and a truncated call cannot become COMPLETE: the label is inside what the commitment covers, so a record that says complete and a record that says incomplete-because-hop-3-was-unverifiable are different commitments, and presenting the first for the second fails here. Nor can the unverified tail of an Incomplete record be substituted. An archivist holding a statement about `[h0, h1, h2-tampered]` cannot present `[h0, h1, h2']`: the verified prefix, the shape digest and the `incomplete:1:<reason>` label all still match, and only the submission identity separates them. And a record that identifies no submission is refused rather than reported as bound on the strength of its prefix — the archivist is exactly who would benefit from the weaker answer being indistinguishable from the stronger one. This theorem establishes NO CONFIDENTIALITY. The receipt does not itself carry the retained call bytes, and that is all: it is not unlinkability, not resistance to inference from the digests, and not resistance to guessing a low-entropy reconstruction and confirming it against the commitment.

**Scope — what this does NOT establish.** Correspondence only. It does not establish that the retained bytes are THEMSELVES valid evidence, that the call described ever happened, or that the reconstruction is complete — only that whatever was reconstructed is what was committed to. It says nothing about a record that carries no submission identity beyond that such a record is refused. The `s01` interop corpus is one: its retained artifact records handles rather than the submitted messages, so the digest is not reproducible from it at all, and the conformance vector is demoted in place — it evidences receipt, statement and key-pin interoperation, and does NOT evidence this claim. It stays as it is: that no MCP-RE code produced it is the whole value of that vector, and regenerating it would destroy a real interop claim to fix a different one. The corpus that DOES evidence this claim is `conformance.retained_corpus` — a signed multi-hop exchange this implementation produced, whose statement binds to the verified call its retained messages reproduce. It is the only place the verdict is reached over an artifact on disk rather than over a value a test constructed, and its own controls keep it from being a happy path: a tampered byte and a truncation stop corresponding, and the committed bytes are compared against a fresh generation rather than assumed. It does not establish registration: whether any transparency service ever saw the statement is THM-0041. Nor does it establish that the commitment function is collision-resistant; the digest is an opaque primitive here.

**Review requirement.** Owner security-specification review

### THM-0043 — The exchange relation is decided everywhere and the execution threshold partitions it

**Statement.** Every (ExchangeState, ExchangeEvent) pair is either explicitly legal or explicitly rejected by `transition`; no event moves a terminal state; the pipeline order is a directed path whose only branches are the notification arm and the open-leg/terminal split; and no state at or past the execution threshold can reach a pre-dispatch terminal. An advance the relation does not admit latches an anomaly in every build, release included, rather than being ignored or panicking.

**Security consequence.** A serving path cannot reach the backend from a state the relation does not admit, cannot reach a pre-dispatch refusal terminal after the backend has been handed the request, and cannot silently drive the machine off the legal path — a disagreement between the model and the code is recorded, and every consequence derived afterwards is derived from a machine that says so.

**Scope — what this does NOT establish.** Establishes the relation and the latch. It does not establish that the serving path drives this machine, that a given stage advances it, or that any particular refusal site is inside the lifecycle — those are propositions about the caller and are registered against the serving composition, not here. It establishes nothing about what any stage verified.

**Review requirement.** Owner security-specification review

### THM-0044 — An exchange's retry consequence never under-reports what may have happened

**Statement.** `ExchangeProgress::retry_semantics` is monotone along every legal path and reports `NotRetrySafe` whenever an anomaly is latched or the backend was dispatched, and `RequiresNewElicitation` whenever a continuation approval was consumed and the backend was not. `Consumed` latches, so no later observation can report a spent approval as unspent; the backend projection is derived from the exchange state rather than asserted beside it, so the two cannot disagree.

**Security consequence.** A client cannot be told that nothing executed when the backend may have run, and cannot be told an ordinary retry is available after a human's one-shot approval was destroyed — the combination that leaves the retry's fresh nonce admitted and the answer refused as already-answered, with the approval gone.

**Scope — what this does NOT establish.** A claim about the machine's derivation, not about the wire. It does not establish that the serving path maps a consequence onto a particular HTTP status, that a client acts on it, or that any effect was in fact performed. It establishes nothing about the truth of the observations fed to it — only that no observation can move the consequence backward.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0043

### THM-0045 — The backend is reached only by consuming a fully assembled pre-dispatch commitment

**Statement.** Transmitting to the backend consumes a `ReadyForDispatch`, whose representation and constructor take each pre-dispatch prerequisite by value: a `PreparedInnerDispatch` holding the inner plane's real dispatch capability, a `SigningWindow` snapshotted before the backend runs, and a `RetentionDisposition` that is either `NotConfigured` or a `DispatchCommitted` whose crossing the store has already made durable. The serving path obtains a `PreparedInnerDispatch` only from `InnerPlane::prepare`, which takes an `AuthorizedRequestBody` by value, and that type is sealed with exactly one producer, `AuthorizationPosture::release`. Crossing is one-way and the transmission happens INSIDE it: `dispatch` consumes the ready state, consumes the capability, and yields a `DispatchedExchange`, so no caller holds both and none can transmit twice from one set of prerequisites.

**Security consequence.** A serving path that skipped the authorization decision, the signing-window snapshot or the retention reservation has nothing to hand the dispatch — the failure is a compile error at the dispatch line, not a proxy that quietly serves unjudged requests or discovers a missing credential after the tool has already run. And a post-dispatch failure cannot be answered as though the backend had not run, because the value that would say so is gone. The capability is HELD rather than predicted, so the last pre-dispatch prerequisite is not a forecast that the plane will still admit the call when asked to run it. A saturated or fully-ejected inner plane is therefore refused where refusing is free, and the outcome type a committed dispatch resolves to has no case meaning nothing was transmitted.

**Scope — what this does NOT establish.** It establishes that the decision was TAKEN, never that a policy permitted: `NoPolicyConfigured` releases a body too, because a deployment with no policy is entitled to serve while claiming nothing. It does not establish that the posture released was the one a configured policy produced — that proposition is registered separately and is open. It says nothing about what the verifier established, and nothing about the retention record's contents. `AsyncInnerServer` is a seam, so possession of a `PreparedInnerDispatch` is a fact about the SERVING PATH — which obtains one only through `InnerPlane::prepare` — and not a theorem about every implementation of the trait. What the seam's own contract adds is narrower and is the part that is checked: an implementation cannot report, from a committed dispatch, that nothing was transmitted.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0040

### THM-0046 — A refusal carries which authority reached it, over a closed set, unrendered

**Statement.** Every `Refusal` carries a `RefusalCause` rather than a rendered token, and `RefusalCause` is closed over exactly the two authorities on this path — a Core verification verdict, in whichever of Core's own producers reached it, and the ADR-MCPRE-065 authorization boundary, held whole so its two arms stay distinguishable. `PolicyError` has no route into the Core taxonomy anywhere in the workspace. Rendering to a wire code happens only at the presentation boundary, and the signing posture is independent of the cause.

**Security consequence.** An authorization refusal cannot arrive at the audit boundary wearing Core's provenance, a foreign taxonomy cannot reach a record's reason field unnoticed, and "no policy verdict was reached" cannot be recorded as "a policy denied" — the three collapses a pre-rendered token made unrecoverable.

**Scope — what this does NOT establish.** Establishes the vocabulary and its provenance. The closed set is the two AUDIT-VOCABULARY authorities represented at this boundary — the Core-owned verdict vocabulary and the Authorization-owned verdict vocabulary — and the claim is that a refusal arriving here carries which of those two reached it, whole. It is NOT a claim that only two semantic authorities participated in the exchange: admission, the transport binding, the continuation plane and the replay tier all decide things, and each reaches this boundary through one of the two vocabularies rather than by adding a third. It does not establish that every production refusal site is inside the exchange lifecycle, that the audit record is written, or that the refusal is signed — those are propositions about the serving path and the response-emission authority. It does not establish that Core's own verdicts are correct.

**Review requirement.** Owner security-specification review

### THM-0047 — The verifier's assurance products are not substitutable

**Statement.** The products the verifier operations return are distinct types whose representations are private to their own modules, so a product that establishes a weaker proposition cannot be passed where a stronger one is required: a floor-verified request is not a full-profile verified request, a bound response is not an unbound one, and a delegated response is not a trust-seam one.

**Security consequence.** A serving path cannot satisfy a consumer that requires a full-profile verification by handing it a value that only cleared the cryptographic floor, and the substitution is a compile error rather than a silently weaker check.

**Scope — what this does NOT establish.** Type separation only. It does not establish that the value a consumer holds was produced by the operation whose type it has for THAT consumer's exchange — possession provenance is a proposition about the caller and is registered against the serving composition. It establishes nothing about what any of the operations verify.

**Review requirement.** Owner security-specification review

### THM-0048 — Every listener obtains its whole security posture through one listener state

**Statement.** Every MCP-RE construction path obtains a listener's trust anchors, epoch-bound session store, signing budget and client-certificate verifier through one `TlsListenerSecurityState`; the terms cannot be supplied to it independently. The epoch is a function of the anchor set alone, a rebuild that republishes the same trust keeps the resumption cache while a rebuild with withdrawn trust advances the epoch and stops resumption, and no configuration this owner builds can resume outside the store.

**Security consequence.** A withdrawn trust anchor cannot be survived by a resumed session, and a listener cannot be assembled with anchors from one source and a session store or signing budget from another — the pairing that lets a session outlive the trust that admitted it.

**Scope — what this does NOT establish.** Establishes that the terms travel together and that the epoch tracks the anchors. It does not establish that the client-certificate verifier denies unknown revocation status: that is a property of one construction site over a foreign trait object, not of any type this owner holds, and it is registered separately as an open proposition. It says nothing about the handshake's own correctness.

**Review requirement.** Owner security-specification review

### THM-0049 — Every illegal cross-owner configuration combination is refused at layer A

**Statement.** The cross-machine pass reads classified owner states and validated request selections, never raw fields a machine already classified, and refuses every relation it declares — the channel key object living in a backend the deployment does not reach, a revocation deny list no configured profile will read, and a trust-epoch posture incompatible with delegated signing. Each refusal is unconditional in the classifier rather than conditional on a caller having asked.

**Security consequence.** An operator cannot obtain a weaker posture by supplying a combination of individually legal selections that no machine alone can refuse — a PKCS#11 channel key under a KMS signing source, silently doing nothing while the operator believes the handshake key is device-resident.

**Scope — what this does NOT establish.** Establishes refusal by the classifier over the relations it actually decides. Two are live — X2a, that a delegated channel key object must name a backend the deployment already reaches, and X6, that a deny list no reachable authorization profile will consult enforces nothing — and those are what a validated deployment is held to. X9 is deliberately a NO-OP and the claim says so rather than implying a refusal. The trust-epoch posture is one decision, made by `TrustRevocationState` and carried in `DeploymentConfigState`, and both the trust plane and the delegated-signing plane consume THAT decision; neither re-derives it and neither asks the other. There is therefore no second decision left for a cross-machine rule to find incompatible. It is written down, empty, because a future rule joining those two machines needs an owner to be added to — not because it refuses anything today. It does not establish that the illegal combination is unrepresentable — `DeploymentRequest` can hold one, which is why the refusal is a check the classifier performs and not a structural fact. It does not establish that the classifier is consulted on every startup path.

**Review requirement.** Owner security-specification review

### THM-0050 — Distinct verification keys cannot feasibly be made to share a keyid

**Statement.** Under the accepted SHA-256 collision-resistance premise (ASM-0037), no computationally feasible adversary can cause two distinct enrolled verification keys with distinct canonical RFC 7638 JWK representations to resolve to the same keyid, so resolving a keyid through the trust seam selects at most one key against any adversary the premise covers.

**Security consequence.** A signer cannot be brought to acceptance under a keyid that resolves to another party's key, which is what would let one enrolled actor's signature be attributed to another.

**Scope — what this does NOT establish.** Computational selector injectivity only, and deliberately not a mathematical one. SHA-256 is not injective — it maps an unbounded domain onto 256 bits, so colliding keys EXIST. What is claimed is that none can be exhibited by an adversary the premise covers, which is the strongest true form of this proposition and the form ASM-0037 states. The claim decomposes into exactly two halves, and the REVIEW UNITS are split along that seam so the halves cannot be confused. THM-0055 is the MCP-RE-owned half and is owned by `http_profile.keyid`, a unit carrying NO primitive assumption: distinct admitted verification keys have distinct canonical thumbprint preimages, and the digest encoding merges nothing. ASM-0037 is the primitive half and is scoped to `http_profile.keyid_selector` — this claim's own unit — and to `boundary.crypto_primitives`. Two units over one file, because there are two propositions with two different trusted bases; a single unit would make collision resistance a premise of THM-0055, which is backwards, since the derivation half is proved without assuming anything about the digest and saying so is most of its value. Neither ASM-0028 nor ASM-0023 was widened to reach it: second-preimage resistance and collision resistance are different propositions, and ASM-0023's declining to assume the construction's separation properties stands unchanged. It does not establish that the seam answers for any particular keyid, that the key it returns is trusted for its slot, or that the enrolment set is correct.

**Review requirement.** Owner security-specification review; re-review on any change to the keyid digest algorithm

**Depends on.** THM-0055

### THM-0051 — The pipeline holds, at dispatch, the verification product of this very exchange

**Statement.** The verified request the serving path carries from the verification stage to the dispatch, and to every stage between them, is the product that stage's verification of THIS inbound message returned — not a product of another exchange, not one reconstructed downstream, and not one a caller supplied.

**Security consequence.** A caller cannot reach the backend by having some other exchange's verification succeed, and no stage between verification and dispatch can substitute a value for the one the verifier produced.

**Scope — what this does NOT establish.** Possession provenance across the serving pipeline. It does not restate what the verification established (THM-0015) or that the products are type-separated (THM-0047); it is the joint those two explicitly exclude. The mechanism is a self-tested source-text gate, `scripts/serving_product_provenance_gate.py`: the assembly calls the verification stage exactly once and builds exactly one carrier, the stage hands its product to `ExchangeProgress::establish` so the machine learns it ran, the carrier has no public field, and no production module of `mcp-re-proxy` constructs the product. That is EVIDENCE and not unconstructibility, and the reason it cannot be a type is recorded rather than worked around: `VerifiedMcpRequest` keeps PUBLIC fields because the Verus obligation on `prepare_http_dispatch` reads `verified.request_block` as a field so the prover can relate the obligation to the value, and `#[verifier::external_type_specification]` refuses a non-public field. A proved postcondition outranks a seal. So this claim holds for the serving path of this crate and says nothing about a product another crate fabricates.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0015, THM-0047

### THM-0052 — A dispatched body was released by the decision a configured policy produced

**Statement.** On a deployment where an authorization policy is configured, the `AuthorizationPosture` that released the body reaching the backend was produced by that policy's evaluation of this request's verified facts — `NoPolicyConfigured` is reachable at the dispatch only on a deployment that configured no policy.

**Security consequence.** A serving path cannot bypass a configured policy by releasing the body under the posture that claims nothing, which is the one gap the sealed body type leaves open: possession proves a decision was taken, and this proves it was the one the deployment selected.

**Scope — what this does NOT establish.** It does not restate the seal (THM-0045), the decision relation (THM-0040) or the operation's own selection (THM-0056). It establishes nothing about the policy's own correctness, and nothing about deployments that configure no policy, which are entitled to serve while claiming nothing. The structural half — that the serving path names no `AuthorizationPosture` variant, that the authority builds them in exactly one operation, and that the assembly calls `release` exactly once — is held by `scripts/authorization_provenance_gate.py` clauses 4, 7 and 10, a self-tested source-text gate. That is EVIDENCE, not unconstructibility: `NoPolicyConfigured` is a public variant, and a body released under a synthesized one is byte-for-byte the body a real decision would have released, so no type can refuse it. Deleting the gate leaves the bypass constructible.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0040, THM-0045, THM-0056

### THM-0053 — A presented admission assertion is authentic, in its window, and for this audience

**Statement.** The admission assertion an enforcement point acts on verified under a key resolved for its issuer through the trust seam, carries the required credential type and algorithm, names this profile and an audience this enforcement point answers to, and the instant of the call lies inside both its own [nbf, exp] window and the verifier's own staleness budget.

**Security consequence.** An admission verdict cannot rest on an assertion another party minted, on one carrying a different credential profile, on one whose validity window has passed or has not begun, or on one issued to a different enforcement point and replayed here.

**Scope — what this does NOT establish.** Assertion authenticity only. It does not restate verdict integrity (THM-0003), anti-rollback (THM-0004), presenter binding (THM-0006) or the degraded-admission opt-in (THM-0005), all of which characterize what the verdict SAYS once the assertion is believed. Its relationship to ASM-0012 is the point of registering it separately. That assumption makes `verify_admission_assertion` opaque to the currency theorem — no `ensures` at all, so it can neither weaken nor be relied on inside the Verus cone — and its own review requirement names a separate unit for assertion validity as the discharge rather than an `ensures` added there. `http_profile.admission_assertion` is that unit, and nothing here is inside the proof cone: this is a test-lane claim, and the reason it can exist at all is that the currency proof never depended on it. It says nothing about whether the ISSUER should be trusted — that is the trust seam's, and a kid never introduces trust — nor about the authoritative state the verdict is checked against, which belongs to the admission currency and anti-rollback owner, principally THM-0004.

**Review requirement.** Owner security-specification review

### THM-0054 — Every production listener denies unknown client revocation status

**Statement.** Every client-certificate verifier a production MCP-RE listener uses denies unknown revocation status, enforces revocation over the full chain, and enforces CRL expiration, with no configuration or argument that can relax any of the three.

**Security consequence.** A client whose revocation status cannot be determined — because the CRL is stale, absent for its issuer, or does not cover its position in the chain — cannot complete a handshake, so a revoked credential cannot be admitted by the checking silently failing open.

**Scope — what this does NOT establish.** A proposition about every production CONSTRUCTION SITE, not a property of a type this project owns: the verifier is a foreign `dyn` trait object and rustls ships both a permissive policy and a builder method that selects it, so nothing here can make a permissive inhabitant unconstructible. Recorded as evidence accordingly. Two halves, and both are now measured. The BEHAVIOURAL half drives real handshakes: a revoked client denied, a stale CRL denying even a client it does not revoke, and — the case the other two leave open — a client whose status the configured CRLs CANNOT determine, denied. The first two are cases where revocation checking ran and answered; only the third is the unknown-status decision itself, and it is what separates failing closed from admitting a credential that may have been withdrawn. The SOURCE half pins the site set: one production producer, no `allow_unknown_revocation_status` anywhere, `enforce_revocation_expiration` positively stated, and no parameter through which a caller could choose the posture. The one other `ClientCertVerifier` implementation in the crate is named rather than filtered out: it is behind `fault_accept_any_client`, a feature that exists to break the control deliberately and prove it is live, and the control asserts it stays behind that gate. It does not establish that the CRLs a deployment loads are current or complete, and it establishes nothing about the per-request revocation check, which is a separate authority holding the same invariant.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0048

### THM-0055 — The keyid derivation introduces no collisions of its own

**Statement.** `canonical_ed25519_jwk` embeds its operand verbatim between a fixed prefix and a fixed suffix, so the operand is recoverable from the form and distinct operands never share one — for any operand, including one carrying JSON metacharacters. The keyid's base64url-no-pad encoding is injective over the fixed 32-byte width of a SHA-256 output.

**Security consequence.** Two distinct verification keys cannot be given the same keyid by anything this project wrote: not by a canonicalization that reorders or drops a member, not by an operand chosen to nest structure inside the JWK, and not by an encoding that merges digests.

**Scope — what this does NOT establish.** Everything except the digest, and it INHERITS NOTHING about the digest either. Its unit, `http_profile.keyid`, carries no assumption at all: every property here is a property of code this project wrote, holding for any operand whatsoever. That is why the selector claim lives in a separate unit — ASM-0037 is scoped to `http_profile.keyid_selector`, so collision resistance is a premise of THM-0050 and of nothing else. It says nothing about whether SHA-256 maps two distinct canonical forms to one value, which is the remaining premise of selector injectivity and is a property of the primitive. It establishes nothing about the trust seam, about which keys are enrolled, or about whether a resolved key is trusted for its slot.

**Review requirement.** Owner security-specification review

### THM-0056 — The posture that claims nothing is produced only where no policy is configured

**Statement.** `authorize` returns `AuthorizationPosture::NoPolicyConfigured` exactly when the deployment attached no evaluator, and `AuthorizationPosture::Authorized` only from a grant an evaluator actually returned, carrying the request the decision was taken over and that decision whole. An evaluator that denies, and one that could not complete, are the `Err` half and never a posture. The action coordinate is read whether or not a policy is configured, so enabling one cannot change which requests are well-formed enough to serve.

**Security consequence.** A record cannot report *no policy is deployed* as *a policy permitted this*, and an authorized posture cannot be assembled from an attribution taken from one decision and evidence taken from another — the pairing this type exists to be evidence of.

**Scope — what this does NOT establish.** A claim about the operation, not about the serving path: it does not establish that the posture the dispatch consumed is the one this operation returned, which is THM-0052. It establishes nothing about the policy mechanism's own correctness, and nothing about which evaluator a deployment attached.

**Review requirement.** Owner security-specification review

### THM-0057 — A client's trust anchors are the ones the current signed manifest published

**Statement.** Anchors are released only from a manifest whose signature verified under a trusted signer kid that the signature itself covers, whose profile is this one, and whose version is not below the monotone floor — a floor that rises on load and cannot be read as zero when it cannot be read at all. The manifest's own deadline travels with the anchors it published and outranks every root inside it, so an expired document resolves nothing, and the revocation half is carried by the same authority as the resolution half.

**Security consequence.** A client cannot be moved back onto a superseded trust picture by replaying an older signed manifest, cannot be given anchors by a document nobody trusted signed, and cannot keep resolving roots from a document whose lifetime has passed — including when the floor's own storage fails, where anchors are withheld rather than released against an unknown floor.

**Scope — what this does NOT establish.** Establishes what the document says and for how long. It does not establish that a response verified under one of these anchors is an answer to this request (THM-0058, THM-0059), that the publisher's key management is sound, or that a revocation list is complete — only that an identifier it names cannot resolve.

**Review requirement.** Owner security-specification review

### THM-0058 — A client accepts a response only under a signer its trust configuration authorizes

**Statement.** A response this client reports as verified was signed under a credential chaining to a root issuer the current trust picture resolves for the Response slot; where the route pins an issuer, a credential chaining to any other trusted anchor fails closed; and a credential whose issuer kid, delegated kid or jti the trust authority reports revoked resolves nothing, on both the success and the rejection path. A response carrying no credential is refused rather than read as a direct-root answer.

**Security consequence.** An application cannot be handed a response signed by a party this deployment never authorized for the Response slot, by one whose authorization has been retired, or by the trust root directly — the mode this project does not support and therefore must not accept.

**Scope — what this does NOT establish.** Signer authorization only. It does not establish that the response answers THIS request, which is the binding disposition (THM-0059), and it does not restate the underlying signature and `;req` facts, which are stated over the profile verifier (THM-0016, THM-0019, THM-0021). It says nothing about whether the deployment was right to trust the anchor.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0016, THM-0019, THM-0057

### THM-0059 — An unbound receipt is never a success and never another request's answer

**Statement.** A response verified without a request binding is reported as unbound and is never classified as a success, and there is no path on which a failed bound verification is retried as an unbound one. A preflight receipt is accepted as being about this call only when it commits to the digest of the bytes this client sent; one about another request, and one about no request at all, answer nothing.

**Security consequence.** A pre-parse receipt cannot be replayed as the answer to a request, and a response that could not be bound cannot be presented to an application as this call's result by falling back to the weaker check.

**Scope — what this does NOT establish.** The disposition, not the signer (THM-0058). The unbound receipt's binding is a BYTE binding: two transmissions of identical request bytes share it, so it is not an instance binding, and the client discloses it to the caller as unbound rather than claiming otherwise.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0020, THM-0022

### THM-0060 — The client's clock skew is bounded at construction and read once

**Statement.** `DelegationPolicy` clamps the configured clock skew to the profile's bound when it is constructed and keeps the result in a private field, so no inhabitant carries an unbounded tolerance; a negative configured skew narrows to zero rather than moving the window backwards; and both freshness windows read that one bounded number through the policy's single projection.

**Security consequence.** An operator cannot widen a client's acceptance window past the profile bound by configuration, and the credential window and the signature window cannot disagree about the tolerance they applied — the disagreement that lets a credential be accepted outside the window its own signature was admitted under.

**Scope — what this does NOT establish.** The bound and its single reading. It does not establish that the profile's bound is itself appropriate, and it establishes nothing about what either window checks beyond the tolerance it applies.

**Review requirement.** Owner security-specification review

### THM-0061 — A receipt that says nothing is not a receipt that says nothing ran

**Statement.** `ExecutionStatus::Unstated` and `ExecutionStatus::NotExecuted` are distinct inhabitants, and a rejection body carrying no execution contract yields the silent one rather than a guess. An unrecognized value is carried as unrecognized and never read as a known one, a spent elicitation is reported as requiring a new one rather than as an ordinary failure, and a failed retention obligation survives beside whatever the execution status says. The wire code and the contract are read in one parse.

**Security consequence.** An explicit failed, unknown or unstated retention or execution result cannot be silently reinterpreted by the client library as successful retention or as known non-execution: what the server declined to claim reaches the caller as a claim the server declined to make. It does NOT establish that the server's statement is TRUE. Whether a call really did or did not run, and whether the evidence really was retained, are the serving-side roots' — this claim is only that the client does not improve on the answer it was given.

**Scope — what this does NOT establish.** What the receipt SAYS, and what a client may conclude from it. It does not establish that the server's statement is true — that is the serving path's exchange machine (THM-0044) — and it establishes nothing about the transport failures on which no receipt arrives at all.

**Review requirement.** Owner security-specification review

### THM-0062 — A response-signing credential exists only while a valid delegated key does

**Statement.** The response signer publishes a credential snapshot only from a successful rotation, and yields none before the first rotation, past the published key's expiry, after a fail-closed issuance has retired the snapshot, after a terminal retirement — including for a mint that lands afterwards — and when its snapshot lock is poisoned. An issuance failure serves the still-valid key and then fails closed at its expiry rather than extending it, and the retry schedule never sleeps past a still-valid key.

**Security consequence.** A response cannot be signed under a credential the deployment no longer holds, under one whose window has closed, or after the signer has been retired — and there is no longer-lived or root credential to fall back to, because no such mode exists. What a caller gets instead is an unsigned last-resort receipt, which it can tell from a signature.

**Scope — what this does NOT establish.** The credential's existence, not its content: it does not establish that the credential chains to the deployment's root, that its scope is right, or that a verifier will accept it. It says nothing about what is signed under it, which is THM-0063 and THM-0065.

**Review requirement.** Owner security-specification review

### THM-0063 — A signed response never advertises validity its credential does not authorize

**Statement.** `SigningWindow` keeps `expires` private and no constructor accepts one: every window is derived as the earlier of the configured TTL from `now` and the credential's own `exp`, with saturating arithmetic so an absurd configured TTL cannot wrap past it. A credential already past its bound yields a window claiming no future validity rather than one running backwards. The same owner opens every window this deployment signs under, reply and refusal alike, and a refusal signs under the snapshot its own exchange took.

**Security consequence.** A client cannot be given a receipt asserting validity beyond the moment its credential stops authorizing signatures — a window the verifier refuses as soon as the credential's own closes, which the client would learn about only by failing. And a refusal minted late in an exchange cannot advertise more validity for having been reached by a different path.

**Scope — what this does NOT establish.** The advertised window, not the signature. It does not establish that a credential existed (THM-0062) or what the signature covers (THM-0065). Where no valid credential exists the receipt is UNSIGNED, and what such a receipt may still state is a separate conjunct of this unit rather than part of this claim.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0062

### THM-0064 — A non-exporting custody selection keeps the private key off this process

**Statement.** The custody owner classifies each legal selection into exactly one state carrying the material that made it inhabitable, and projects a single semantic fact — `PrivateKeyExposure` — that is `NonExporting` for the device- and service-held states and `ProcessReadable` only for the state that loads a seed. A state missing a parameter it cannot start without is not built, and a state carries no neighbour's material.

**Security consequence.** Where a deployment selects non-exporting custody, this authority materializes no process-readable export path for the signing key: what the process receives is a signing CAPABILITY and a public identity, never a private signing seed, so there is no key in memory or on disk for this authority to have leaked. And a consumer asking whether the key may be read here cannot get a different answer by asking which mechanism it is, because the projection names none. It does NOT claim that the external KMS, HSM or token itself honours non-exportability. That is the provider's property, it is outside this boundary, and the scope below says so.

**Scope — what this does NOT establish.** CONDITIONAL on the deployment's own selection: it establishes nothing about a deployment that selects file custody, which is `ProcessReadable` and honestly says so. It establishes what the classified STATE asserts, not that the remote signer implementation honours it — that a KMS does not export a key is the provider's property, outside this boundary. It does not establish that response signing and channel signing use different keys.

**Review requirement.** Owner security-specification review

### THM-0065 — An emitted bound response signature binds the request it answers

**Statement.** A response this proxy signs in the bound form carries a signature whose `;req` components resolved against the request being answered, and a response evidence block whose request-evidence handle is over that same request. Signing and verification agree end to end: a response minted for one exchange does not verify as the answer to another, at the evidence block or at the cryptographic floor, and two requests differing only in one signed parameter have different handles.

**Security consequence.** A response cannot be lifted from one exchange and presented as the answer to another, and a `;req` splice cannot be repaired by reconstructing the block — the floor refuses it independently.

**Scope — what this does NOT establish.** The bound form only: an unbound emission carries no binding by construction, and that a verifier can never read one as bound is THM-0022 on the verification side. It does not establish which credential the signature was made under (THM-0062, THM-0063), and it says nothing about responses this proxy does not sign.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0021, THM-0022

### THM-0066 — The serving PEP resolves actors through the deployment's materialized trust authority

**Statement.** The composition root builds the serving actor resolver exactly once, from the reloading signer directory's snapshot and the deployment's revocation-tier resolver. That seam resolves every Request-slot keyid through the tier on every request rather than through a map captured at process start; an unknown kid is a definitive negative, a store outage is reported as unavailable rather than as a binding failure, and every non-active outcome — revoked, not found, malformed, unavailable — yields no actor. The Response slot answers only for this deployment's own issuer kid.

**Security consequence.** A key revoked in the trust store stops verifying at the instant the tier says so rather than at the next restart, and an operational failure of the tier is never softened into an allow. A deployment cannot announce one revocation tier at startup and run another on the data plane — the defect ADR-MCPS-021 recorded, in which the resolver chain was constructed, its guarantee printed, and then dropped.

**Scope — what this does NOT establish.** Where the seam comes from and what it consults. It does not establish that the tier's own answer is correct, that the trust document is authentic, or that the resolved key is the right one for the signer — those are the tier's and the trust owner's. The composition half is held by source controls over `app.rs`, because `ActorResolver` is a closure seam: anything producing that signature is an inhabitant, so privacy buys nothing and the controls are EVIDENCE rather than unconstructibility.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0037

### THM-0067 — The composition root re-reads no owner's security semantics from the request

**Statement.** Every field the composition root still reads directly from the validated deployment request is a pinned ordinary parameter — one whose value changing, with every owner state unchanged, cannot change a security-sensitive decision or effect — and each is recorded with the sentence saying why. The inventory is checked against the file it describes in both directions, so a new raw read fails and a field that acquired an owner must leave the list.

**Security consequence.** After layer A classifies a deployment, no post-validation consumer can reach back past an owner for a security decision the owner already made — which is how two components come to disagree about what was configured, with neither of them wrong locally.

**Scope — what this does NOT establish.** The general claim over ALL owners; THM-0038 is its trust specialization and states in addition that the root passes trust as owner projections. It does not establish that the owners' own classifications are right, and it says nothing about consumers other than the root — a plane reaching back for a posture is a different failure with its own control. It is a source-text inventory, not a type: `ValidatedDeployment::config()` is legitimately readable, because the root builds things out of it. What is decidable is WHICH fields, and the list only means anything while adding to it costs a written reason.

**Review requirement.** Owner security-specification review

### THM-0068 — A pinned transparency service is one operator-reviewed document, or it is not a pin

**Statement.** `ResolvedTransparencyService::pinned` takes its verification key, leaf profile and position profile from a single `ScittServiceTrustPin`, so all three came from one document an operator wrote and reviewed. A malformed pin document never becomes a pin, and an illegal one is refused at deserialization rather than carried into a resolver that would answer from it.

**Security consequence.** Where a resolver is projected from a `ScittServiceTrustPin`, a receipt cannot be verified against a service whose key came from one place and whose profile expectations came from another — the pairing that lets a receipt satisfy a position profile the pinned service never declared. Conditional on that provenance, deliberately. `ResolvedTransparencyService::stated` is a legitimate second provenance and is retained: the in-process prototype log and the conformance corpus have no pin to resolve from, and deleting it to make this consequence unconditional would remove a supported use to improve the wording of a claim.

**Scope — what this does NOT establish.** It establishes the PROVENANCE of a pinned service, not that a deployment pinned one. `verify_receipt_offline` takes the service as a `Fn(&str) -> Option<ResolvedTransparencyService>` seam, and `stated` is a legitimate second provenance — the in-process prototype log is one, with no pin to resolve from. Against a seam a private field only forces a constructor taking the same arguments with the same absence of checking, so what these fields buy is that every producer is NAMED, not that the illegal pairing is unconstructible. Whether a given deployment's resolver is backed by a pin is deployment wiring and is not established here.

**Review requirement.** Owner security-specification review

### THM-0069 — A security record states each authority's outcome in that authority's own coordinate

**Statement.** Every request record states an authorization outcome — not configured, authorized, or refused — and a response record carries none, because there is nothing after the dispatch for a policy to have decided. The Core verdict and the authorization verdict occupy separate coordinates on one record and neither can be read as the other: an unconfigured deployment is not rendered as an authorized one, a policy denial's token goes in the authorization coordinate, the two authorization refusal arms stay distinguishable, and the arm reached before any policy ran imports no policy vocabulary at all.

**Security consequence.** A reader of the record cannot be shown *a policy permitted this* where none was deployed, cannot mistake a request that reached no policy verdict for one a policy denied, and cannot be left unable to tell whether a policy was consulted — the collapse a single rendered `reason` string produced, and which the type system prevented while the record restored.

**Scope — what this does NOT establish.** What a record MAY say, not that the vocabulary is total over the outcomes that occur — that is THM-0071, which composes this with site totality and delivery. It needs no vocabulary decision: ADR-MCPRE-066 decided the coordinate algebra and its slices implemented it, so the two authorities are separately typed and `PolicyError -> &'static str -> Core reason` is gone as a route. It does not establish that the record was delivered (THM-0070), and it establishes nothing about the truth of either authority's verdict.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0046

### THM-0070 — The record stream is honest about what reached it

**Statement.** Every emitted record carries a sequence number and the collector preserves emission order. A full queue drops rather than blocking the caller, the drop count is reported without a following record to carry it, an unattributed flood cannot consume the headroom an attributed record needs, and concurrent offers at the ceiling admit only the remaining slots. A drain that timed out is a distinct outcome from one that completed, and the outcome that is unknown is its own case.

**Security consequence.** Within the modeled collector lifetime, an auditor cannot be shown a record stream that silently lost entries: a gap is visible in the sequence, a drop is counted and reported, an unattributed caller cannot suppress the records of an attributed one by flooding the queue, and a shutdown whose drain timed out cannot be read as one that emptied the queue. The boundary is explicit and is not durability. Queue loss, drop, ordering and drain-timeout loss are all REPRESENTED. Loss of the process itself is not: the sink is in-process, so records emitted and not yet drained disappear with it, and no claim here survives that.

**Scope — what this does NOT establish.** Delivery integrity, not content (THM-0069) and not durability: the sink is in-process, so a record that was emitted may still be lost with the process. It establishes nothing about whether a record SHOULD have been written for a given outcome, which is the totality proposition below.

**Review requirement.** Owner security-specification review

### THM-0071 — Every reachable in-exchange refusal has a typed provenance that reaches the record

**Statement.** Every relevant IN-EXCHANGE refusal outcome a served exchange can reach carries a typed refusal provenance, that provenance reaches the audit-record emission boundary before the refusal is answered, and it is recorded as the audit-vocabulary authority the refusal carries — with the separately typed authorization coordinate beside it where one applies. No such refusal becomes silent within the modeled audit path, and no authority's vocabulary is recorded as another authority's verdict.

**Security consequence.** Within the modeled in-process audit path, an exchange-owned refusal cannot disappear through projection or through ordinary queue loss without that loss itself being represented, and cannot be recorded as another audit authority's verdict. It does NOT establish durable persistence. If the process itself disappears, records emitted and not yet drained go with it, and nothing here survives that — the boundary is THM-0070's and is carried forward unchanged.

**Scope — what this does NOT establish.** Bounded three ways, and each bound was a correction rather than a caveat. IN-EXCHANGE outcomes, not every outcome. The four pre-exchange transport replies are outside this claim: no exchange exists to own them, there is no exchange record to emit, and bringing them in would need a separate audit requirement that is not claimed here. THM-0081 is what enumerates them. The AUDIT-VOCABULARY authority the refusal carries, not every authority that participated. `RefusalCause` closes over the two vocabularies represented at this boundary — Core-owned and Authorization-owned — and admission, the transport binding, the continuation plane and the replay tier all reach the record through one of those rather than by adding a third. Where an authorization verdict applies it occupies its own coordinate, which is what stops a policy denial being recorded as a Core verdict. Within the MODELED audit path. Durability is THM-0070's boundary and is not widened here. Five established facts compose it, and each closes one way an outcome could escape: every SITE is inside the lifecycle or is an enumerated pre-exchange reply (THM-0081); a refusal carries WHICH authority reached it, held whole (THM-0046); the provenance REACHES the record, typed, before the answer is minted (THM-0085); the two coordinates cannot be read as each other on a record (THM-0069); and the stream is honest about what reached it (THM-0070). It needs no vocabulary decision. ADR-MCPRE-066 decided the coordinate algebra and its slices implemented it, so `PolicyError -> &'static str -> Core reason` no longer exists as a route and the union that was once asked to be total is not the object of this claim. It does not establish that the right cause is chosen at any given site, nor that the frozen public tokens are individually well-named; both are the owning units' controls and neither is a totality property.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0046, THM-0069, THM-0070, THM-0081, THM-0085

### THM-0072 — A verified receipt proves registration on the service this deployment pinned

**Statement.** When offline receipt verification is performed through a resolver PROJECTED FROM a `ScittServiceTrustPin`, a receipt that verifies establishes that the Signed Statement was registered on the transparency service that pin describes — the key it verifies under, its leaf profile and its position profile all came from that one reviewed document, not merely from some service whose key was supplied to the call.

**Security consequence.** Where verification runs through a pin-projected resolver, an auditor cannot be shown a receipt from a log that pin does not describe, and cannot be shown one that satisfies a position profile the pinned service never declared. It says nothing about a verification performed through a `stated` resolver, which is a supported non-pin provenance for prototype and conformance use. `verify_receipt_offline` takes its service through a `Fn(&str) -> Option<ResolvedTransparencyService>` seam, so which provenance backs a given call is deployment wiring — and no production wiring was invented to make this claim unconditional.

**Scope — what this does NOT establish.** It composes the two facts and adds nothing: offline verification against a resolved service (THM-0041) and the provenance of a pinned one (THM-0068). It carries both scopes forward unchanged — nothing about the service being honest, its log append-only, or an entry unique, and nothing about whether the retained evidence is what the statement describes, which is THM-0042 and is a separate promise because no authority owns the conjunction.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0041, THM-0068

### THM-0073 — Serving materialization refuses a deployment whose two signing roles are one key

**Statement.** Serving materialization cannot succeed when the response-signing role and the channel-signing role resolve to the same cryptographic signing-key identity: the composition root obtains its key source only as the product of a comparison over the two materialized public keys, and that comparison refuses before any server starts.

**Security consequence.** The two roles rest on two different private keys, so compromise or possession of ONE private key does not, by key reuse, confer the other role: a party who extracts or coerces the channel key has not thereby obtained the ability to attribute a response, and the reverse. It does NOT claim administrative separation. A cloud IAM principal, an HSM session or an operator credential able to invoke one key may well be authorized to invoke the other; whether the two roles are separately AUTHORIZED is a different proposition with a different owner, and nothing here establishes it.

**Scope — what this does NOT establish.** Over the MATERIALIZED identities, and that is the substance of the claim rather than an implementation note. A comparison of mechanism LOCATORS would establish nothing: an ARN, a key id and an alias are three names for one AWS key, a PKCS#11 label is scoped to a token, and a filesystem path resolves through symlinks — two locators that differ can be one key, and a check comparing them would report a separation that does not exist while looking exactly like one that does. So both roles are asked for their public verification key after materialization and compared as `Ed25519PublicKeyValue`, the canonical RFC 8410 identity this crate already owns. No AWS-, GCP- or PKCS#11-specific equality semantics were invented. UNCONDITIONAL, and deliberately not conditioned on a policy input. The ratified wording is "where policy requires the roles to be distinct"; measurement found no supported deployment for which sharing is desirable, and inventing a one-valued policy knob to make the condition expressible would fabricate an input that selects nothing. Every deployment is held to it, so the conditional is satisfied everywhere rather than left as a dormant branch. It is load-bearing rather than a construction-site convention, which is what moved it here. `MaterializedSigningRoles` holds the source privately and `establish` is its only producer, so a serving path cannot hold a key source that did not come through the comparison — deleting the call does not leave a path that skips it, it leaves one that does not compile. What that does NOT settle is whether the composition root uses the materializer at all: `FileKeySource` and the KMS adapters are public constructors that external embedders need, and THM-0082 is what measures the root. The owner moved from `proxy.cross_machine_legality`, and had to: a request-level classifier reads locators, and the decisive fact here exists only once both backends have answered. X2a (THM-0049) states the adjacent relation — that the channel key object lives in a backend the deployment already reaches — and is not this claim. A channel credential whose public key is not a canonical Ed25519 key yields no comparison, and that is a statement rather than a gap: the response role's key always is one, so the two cannot be equal. Likewise a role that materialized NO key contributes none — the composition root reads both immediately afterwards to build the listener and the delegation, so a deployment where either is unavailable starts no server, and the only executions that arm admits are executions that never serve. TWO PREMISES, both found by the missing-edge pass over this very claim rather than assumed. The comparison is over `raw_point()`, so "different points implies different keys" needs THM-0025: possession of an `Ed25519PublicKeyValue` means it was interpreted from the canonical RFC 8410 encoding and its projected point IS those bytes. Without that the inequality would be about two projections rather than about two keys. And the claim that the LEAF's key is the CHANNEL-SIGNING key is not free either — on the delegated path it is THM-0027, which establishes that a resolver cannot exist over a credential and a signer that do not correspond, which is what makes the served leaf the key that signs the handshake. It claims nothing about whether either key is the RIGHT one, about custody, about exposure, or about the chain being trusted.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0025, THM-0027, THM-0049

### THM-0074 — No unearned dispatch

**Statement.** If the serving path invokes the backend for an inbound request, every pre-dispatch security obligation selected by the validated deployment was first established by its owning authority from the inputs that obligation is defined to consult — request and exchange evidence and, where required, authoritative validated or materialized state — and the downstream pipeline consumed the earned product of that establishment for the same relevant request, actor, subject and exchange.

**Security consequence.** A caller cannot reach the backend by omitting evidence, by presenting evidence for a different exchange, by presenting a fact the deployment did not select the authority for, by handing the pipeline a security value it constructed itself, or by having some other exchange's establishment succeed.

**Scope — what this does NOT establish.** It ends at the invocation: what the backend does once dispatched is the application's. Obligations a deployment did NOT select are outside it by construction — this is a claim about the selected set, not a claim that the set is right. It says nothing about liveness: that a valid request IS served is not claimed, and the complement of this implication is THM-0078, not "some other path". Request-carried evidence does not stand in for authoritative state. Admission currency is stated against the state the enforcement point holds, and actor resolution against the MATERIALIZED trust authority (THM-0066), because an obligation defined over validated state is not discharged by anything the request carries.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0003, THM-0004, THM-0005, THM-0006, THM-0009, THM-0015, THM-0034, THM-0040, THM-0043, THM-0045, THM-0050, THM-0051, THM-0052, THM-0053, THM-0066, THM-0079, THM-0080, THM-0083, THM-0092, THM-0093

### THM-0075 — No unearned response attribution

**Statement.** Whenever MCP-RE emits signed response or refusal evidence, the signature is produced by the response-signing capability materialized for that deployment under the supported delegation model; bound evidence is bound to the exact request it answers, and evidence produced before a request can be established is explicitly unbound and cannot be interpreted as bound.

**Security consequence.** A response cannot be attributed to the trust root directly, cannot be signed by a credential the deployment does not hold or no longer holds, cannot advertise validity its credential does not authorize, and unbound evidence cannot successfully verify through the bound-response path as evidence for a particular request. This is the PRODUCER side. What a client ultimately presents to its caller as an answer is THM-0076 and is a different proposition on the other side of the same exchange.

**Scope — what this does NOT establish.** SECURITY-BEARING SIGNED evidence only. Unsigned transport and error responses exist — a last-resort receipt is emitted when no valid credential does — and they are outside this claim, which is why it does not say every response carries evidence. It does not establish that a client accepts the response, which is THM-0076 and a different proposition on the other side of the same exchange.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0022, THM-0062, THM-0063, THM-0065, THM-0082

### THM-0076 — A client accepts only an answer to its own request, under a signer it trusts

**Statement.** If the shipped MCP-RE client proxy returns a remote response as verified for a call, that response was verified against the request THAT PROXY SENT (THM-0084) and under a signer this client's current trust configuration authorizes in the Response slot; a response that could not be bound is never reported as a success; and what the client may conclude about whether the work ran is what the receipt states, never what its silence might be read as.

**Security consequence.** An application cannot be handed, as this call's answer, a response from another exchange, from another signer, from a signer whose authorization has been retired, or one that verified only in the unbound form — and cannot be led to repeat a side effect by reading silence as *it did not run*.

**Scope — what this does NOT establish.** The consumer side, kept apart from THM-0075 because a deployment may run either side alone and producer attribution and consumer acceptance are different propositions. The system root is the SHIPPED `ClientProxy` path, not an arbitrary caller of the low-level verifier — and the two used to say different things. The statement claimed the response resolved against "the request this client sent" while the scope said the pairing was a caller obligation, which is a contradiction rather than a boundary. THM-0084 removes it by establishing the pairing where the shipped path owns it: `handle` builds one `SignedRequest`, forwards it, and derives the expectation from that same owner. The FFI boundary is unchanged and stays outside. `ResponseExpectation::new` remains public for bindings that rebuilt the request from scalars and hold no `SignedRequest`, and sealing past that seam would be theatre; what THM-0084 says is that the shipped path does not use it. Raw FFI and low-level reconstruction remain outside this system-root guarantee. It does not establish that the deployment was right to trust an anchor.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0057, THM-0058, THM-0059, THM-0060, THM-0061, THM-0084

### THM-0077 — No deployment serves a posture nobody selected

**Statement.** Every security capability held by the serving runtime is derived from validated semantic owner state. Illegal, unsupported or internally contradictory deployment postures cannot be silently reinterpreted into a weaker posture during materialization or serving.

**Security consequence.** An operator cannot obtain a weaker security posture by supplying a combination nobody validated, and a serving component cannot disagree with the owner about what was configured.

**Scope — what this does NOT establish.** SECURITY POSTURE, not liveness and not permanent runtime availability. A runtime dependency may later fail and cause refusal or loss of availability; that does not violate this claim. What it forbids is a SILENT weakening of the selected policy — an unavailable tier failing closed is inside the claim, an unavailable tier being softened into an allow is not.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0005, THM-0013, THM-0036, THM-0038, THM-0048, THM-0049, THM-0054, THM-0064, THM-0066, THM-0067, THM-0073, THM-0086, THM-0089

### THM-0078 — Refusal is terminal, and no refusal-side effect reads as success

**Statement.** If an inbound exchange fails to establish a required pre-dispatch obligation, it reaches a declared refusal terminal before backend dispatch, and cannot fall through into a success-path dispatch or a success response. WHERE AN EXCHANGE EXISTS, every refusal-side effect — signed refusal evidence, audit and retention records, cleanup, continuation retirement — is authorized by the refusal and lifecycle state it was reached from, and none can be read as success. A PRE-EXCHANGE transport reply has no exchange state, and therefore may not claim one: it carries no exchange effect, no execution claim and no lifecycle-derived retry contract, which is the only thing that can honestly be said of a reply reached before an exchange began.

**Security consequence.** The complement of THM-0074 is not "some other path": it is a refusal that cannot reach the dispatch and whose own effects cannot be mistaken for the effects of a served request — including the case that motivated the exchange machine, where an approval is spent and the refusal must not read as an ordinary retry. The two kinds are kept apart because the guarantee differs. An exchange-owned refusal is recorded and its effects are authorized by a lifecycle state. A pre-exchange reply has no such state, so what protects a caller there is that it asserts nothing about execution rather than that its assertion was derived.

**Scope — what this does NOT establish.** It forbids a SUCCESS-PATH effect, not any effect at all. The serving architecture emits signed refusal evidence and performs audit, retention, cleanup and continuation retirement on the refusal side, and those are legitimate. This and THM-0074 are two separate safety implications and never a biconditional: stating them as one would make this a liveness claim, which it is not. The exchange-owned and pre-exchange halves are stated separately rather than unified, because a single sentence would be false about one of them: there is no lifecycle state behind a reply reached before an exchange began, and pretending otherwise is exactly the kind of borrowed authority this tree exists to remove. THM-0081 measures which replies are in the second set.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0043, THM-0044, THM-0045, THM-0046, THM-0063, THM-0069, THM-0081, THM-0088

### THM-0079 — Distinct signed exchanges have distinct replay keys

**Statement.** The replay five-tuple — profile id, signature label, actor id, audience hash, nonce — is pre-serialized onto the core cache's three slots with a separator that cannot appear in any component, so equality of the composite slots holds exactly when the full five-tuple is equal; every component discriminates; and a key admitted once is reported as a replay thereafter.

**Security consequence.** Evidence produced under a different profile, a different signature role, a different actor or a different audience can never satisfy a replay check meant for another, and the same signed exchange cannot be admitted twice against the same cache.

**Scope — what this does NOT establish.** The KEY and the cache's decision over it. It does not establish that the cache is consulted on every path reaching dispatch, that a distributed backend's insert is atomic, or that the retention window outlives the signature's own validity — those are the replay plane's and are not stated here. Freshness admission itself is THM-0001.

**Review requirement.** Owner security-specification review

### THM-0080 — Serving derives peer identity only from the credential the mechanism accepted

**Statement.** Neither direct-TLS serving path reconstructs peer identity or credential currency from certificate representation: each asks its authority exactly once, through a resolver whose signature admits its predecessor and the options and nothing else, so an acceptance from one relationship cannot be paired with an identity derived from another credential.

**Security consequence.** A served request cannot be attributed to an identity read out of a certificate the communication mechanism did not accept for THIS relationship — the composition ADR-MCPRE-064 Slice 2 forbids, and the one no behavioural control notices, because each still measures a true thing about a correctly-composed value.

**Scope — what this does NOT establish.** The ROUTE, and recorded as evidence rather than as unconstructibility — a measurement correction against the proposal packet, which had this as STRUCTURAL. Under the deletion test it is not: the historical extractor is a published API with its own X.509 conformance suite over real DER, so it cannot be removed to make the wrong call unavailable, and deleting the controls leaves a second identity route compiling. What can be held is that the SERVING PATHS do not take it, which is a call-site fact. The third conjunct is the load-bearing one. The mechanism that forbids the wrong composition is the ABSENCE OF A PARAMETER through which a second credential could enter — a property of a signature, and a signature is exactly what a future edit widens first. "Just pass the leaf too, we already have it" reintroduces the defect without touching a single check. Measured twice at different widths. The battery holds the route inside this crate and pins that its own rules still detect each regression; `scripts/serving_identity_provenance_gate.py` carries two further clauses over the same subject — the historical facade's exemption, and the `online_ocsp` residue, which ADR-MCPRE-064 Slice 3 deliberately did not migrate and which is allowed only while its feature gate stands. It does not restate THM-0031, which says the resolved identity is RIGHT; this says only where it may come from.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0031, THM-0033

### THM-0081 — Every production refusal is inside the exchange lifecycle

**Statement.** Every production refusal is either an EXCHANGE-OWNED refusal — minted from a `Refusal` a stage named and served under the exchange machine's derived disposition — or one of the four enumerated PRE-EXCHANGE transport replies, each reached before an exchange exists. There is no third, unclassified refusal path, and no exit answers from source position.

**Security consequence.** For an EXCHANGE-OWNED refusal, no retry contract can be stated that the exchange machine did not derive — which is how an exit reached after a human's approval was spent came to report an ordinary retry, the defect the machine exists to remove, now closed at the sites the machine cannot see. For a PRE-EXCHANGE transport reply the claim is necessarily different, because no exchange exists to derive anything: what is established there is that the reply cannot claim execution or any other exchange effect. The three fail-closed frame replies carry no body and no evidence at all, and the one that does — the channel/routing refusal — is a bare JSON error reached before the handler. The shed's 503 is retry-safe on its own terms because the body is never read, so nothing ran. A single sentence covering both would be false about one of them.

**Scope — what this does NOT establish.** The SITE SET, and nothing about which cause any site chooses. THM-0043 establishes that the transition relation is decided everywhere and THM-0046 that a refusal carries which authority reached it; neither says every SITE is inside the lifecycle, and an exit answering from source position would satisfy both. Four facts, together total over the exits a served request can take: the serving subtree mints no answer outside `served`; every `Err` arm of `handle` returns the binding its stage produced; the answers given outside the exchange are exactly the transport frame's, minted in its own three files and each reached ahead of the handler; and `disposition` derives the retry contract from `retry_semantics()` with no wildcard arm. The outside set is FOUR replies, not one, and the correction came from the measurement rather than from the packet: the channel/routing refusal is a served response, while the malformed message, the oversized body and the shed are built at the hyper type and would have been invisible to a control that only counted the first. All four are pre-handler, and the shed's 503 is retry-safe on its own terms — the body is never read, so nothing ran. One exit answers AFTER the exchange has decided and is named rather than absorbed: `served_to_hyper`'s fallback, taken when a decided answer cannot be framed at all. It is recorded because it is the single place an exchange's derived answer can be replaced, and the claim made about it is narrow and measured — it answers an empty 500, which asserts nothing about retry, and never a status clients retry. Source-text evidence, and recorded as evidence rather than as unconstructibility. `ServedHttpResponse` is a wire frame with public fields, as the async fleet, the blocking harness and external embedders all construct one — privacy would buy nothing, so deleting the battery leaves an out-of-lifecycle exit compiling. The third fact is measured at two widths: the battery names the transport frame's files inside this crate, and `scripts/refusal_provenance_gate.py` clause 12c holds the served mint to one call site across the whole workspace, so no other crate can acquire one. The blocking mTLS harness is out of scope and by its own module documentation is not an MCP-RE serving path: it frames every reply as a literal 200, so it carries no RFC 9421 evidence and cannot serve a signed refusal at all.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0043, THM-0046

### THM-0082 — The serving path signs under the credential source materialization produced

**Statement.** The response-signing authority the serving path holds was built by the composition root from the custody state the deployment validated: the root opens one key source through the materializer, opens the role-separation witness once, constructs no key source of its own, and installs the signing plane from that same source.

**Security consequence.** A deployment cannot announce one signing custody at startup and sign with another on the data plane — the same shape as the resolver defect ADR-MCPS-021 recorded on the trust side, where the chain was constructed, its guarantee printed, and then dropped. Every signature would still verify and every startup line would still be true; the two facts would simply be about different keys.

**Scope — what this does NOT establish.** The counterpart of THM-0066 on the signing side, and the composition half THM-0073's seal cannot reach. THM-0062 establishes what the credential source yields and when it yields nothing; THM-0064 establishes what a custody selection asserts about exposure; THM-0073 establishes that a source obtained through the materializer kept its two roles apart. None of them says the root USED the materializer — `FileKeySource` and the KMS adapters are public constructors, as external embedders need, so a root that opened one beside it would compile. Evidence, not unconstructibility, and for that exact reason. The measurement is over the composition root's own source, the shape `serving_trust_seam_test` uses for the resolver: delete it and the old defect compiles again. It says nothing about what the signing plane does with the source once installed, which is `proxy.response_signing`'s.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0062, THM-0064, THM-0073

### THM-0083 — What a request is, is decided once, before anything reads it for meaning

**Statement.** A body reaching the serving path is refused unless it is a legal JSON-RPC 2.0 request, and the outstanding id that selects its terminal is established by that one validation, ahead of every stage that reads the body for meaning; no production serving code reads the id again, and a reply is correlated to it by value AND by type, with a null id correlating to nothing.

**Security consequence.** A body cannot be dispatched as a request and acknowledged as a notification — the tool runs and the caller is answered under a receipt that claims nothing ran. Nor can a document that is not an MCP message burn a nonce, spend a human approval, or write a durable retention marker on its own behalf, because the shape is decided before any of those happen.

**Scope — what this does NOT establish.** Found by the missing-edge pass rather than by inspecting the registry: R1 quantifies over the pre-dispatch obligations a validated deployment selects, and this is one — it gates the continuation stage, the forwarded body and the choice of terminal — yet no node in the tree stated it. The authority, its contract and its battery all already existed; what did not exist was the claim. The same shape as the replay omission THM-0079 closed. Two halves. The VOCABULARY half is the owner's own: which bodies are messages, which answers correlate, and the two ways a correlation could be faked — a null id, and a reply that is also a request. The SINGLE-DECISION half lives in a second unit, because the two halves are in different Cargo packages and a unit's test lane runs in one — a split the authorities agree with, since the vocabulary is the profile's and the single decision is the serving path's. It is evidence rather than unconstructibility: `outstanding_id` is a published API with legitimate callers on the client side and in the response validator, so it cannot be deleted to make a second read unavailable; what is held is that the serving path does not ask the same document twice, and that it carries the decided value to its terminal. It does not establish that the METHOD named is one this deployment serves, which is authorization's, nor anything about the body's application payload, which the profile deliberately does not inspect.

**Review requirement.** Owner security-specification review

### THM-0084 — The shipped client proxy verifies against the request it sent

**Statement.** In the production `ClientProxy` request/reply path, the `SignedRequest` handed to `RemoteTransport::round_trip` is the same signed-request owner from which the `ResponseExpectation` passed to response verification is derived; on the notification path the acknowledgement verifier receives `signed.request()` from that same owner directly. The response is therefore verified against the request that this proxy sent.

**Security consequence.** A server cannot have an answer accepted by pairing a well-formed response with an expectation describing a request the proxy never sent. The expectation and the sent request are not two values that happen to agree — there is only one, so there is nothing for them to disagree about.

**Scope — what this does NOT establish.** The SHIPPED path, and that is the whole point of registering it. THM-0057 through THM-0061 establish what the client-core verifier does with an expectation and a response; every one of them takes the PAIRING as given, and `client.response_acceptance`'s scope says so explicitly — pairing an expectation with the request it describes is the caller's obligation. For a raw FFI caller that is the honest boundary and it stays there: `ResponseExpectation::new` is public precisely so a binding that rebuilt the request from scalars can supply one, and nothing here narrows that. What this claim says is that the SYSTEM ROOT is not an arbitrary caller — it is `ClientProxy::handle`, and there the obligation is DISCHARGED rather than delegated. Raw FFI and low-level reconstruction remain outside the guarantee. Evidence, not unconstructibility. Both halves take `&SignedRequest`, so no signature can force them to be the same value; what is measured is that `handle` builds one, forwards it, and derives from it, and that the shipped path reconstructs no second request. Deleting the battery leaves the wrong composition compiling. It establishes nothing about whether the response is TRUSTWORTHY — that the signer is authorized, the credential current, the receipt bound — which is THM-0058 through THM-0061.

**Review requirement.** Owner security-specification review

### THM-0085 — Every exchange-owned refusal reaches the audit boundary, typed, before it is answered

**Statement.** Every exchange-owned production refusal served by the MCP-RE serving path passes through one funnel, which dispatches to exactly two emitters; each emitter takes the typed `RefusalCause` and asks it for its Core-verdict and authorization-facet projections rather than rendering one; and each records at the audit boundary BEFORE the refusal response is minted.

**Security consequence.** A refusal cannot be served without the record of it having already been offered to the audit boundary, and cannot be recorded under a token this boundary chose rather than one an authority reached. The ordering matters on its own: recording after the answer leaves a window in which a refusal has been served and no record of it exists, which is the one case an auditor cannot reconstruct afterwards.

**Scope — what this does NOT establish.** The EMISSION joint, and the reason it is a separate claim is that its neighbours all hold without it. THM-0081 establishes that every refusal site is inside the lifecycle, THM-0046 that a refusal carries which authority reached it, THM-0069 what a record may say in each coordinate — and a refusal could satisfy all three, be correctly typed and correctly sited, and simply never be recorded. Measured at the ONE boundary rather than reason by reason. A battery enumerating refusal causes would have to learn about the next one, and the failure mode of a stale enumeration is a clean pass over an unrecorded refusal. EXCHANGE-OWNED refusals only. The four pre-exchange transport replies are outside it: no exchange exists, so there is no exchange record to emit, and THM-0081 is what enumerates them. Bringing them in would require a separate audit requirement, and none is claimed here. It says nothing about DELIVERY once the record reaches the sink — that is THM-0070, and it carries its own durability boundary. Evidence rather than unconstructibility: the emitters are ordinary methods, so deleting the battery leaves a mint-before-record ordering compiling.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0046, THM-0069, THM-0081

### THM-0086 — The established replay tier is the selected one, and never a weaker substitute

**Statement.** The replay tier `replay_plane::materialize` hands to the serving path is the tier the plan selected, paired with the dispatch posture that plan declared. A tier that self-declares the volatile single-process reference posture cannot be handed over at all, and a backend this build does not carry is refused by name rather than substituted.

**Security consequence.** A deployment cannot come up believing it has cross-replica replay protection while holding process-local protection. Replay admission cannot degrade to a weaker store on infrastructure trouble, because there is no reachable path that substitutes one.

**Scope — what this does NOT establish.** CONFIGURATION PROJECTION ONLY. It establishes which tier the serving path holds, not what an acknowledged write to that tier durably establishes — that is a per-mechanism external fact with its own premise, and this claim does not use it. It says nothing about availability: a tier that cannot be established refuses startup, which is inside the claim rather than a violation of it. That the plan itself is a faithful projection of the validated configuration is the planner's fact, reached through THM-0077 rather than asserted here.

**Review requirement.** Owner security-specification review

### THM-0087 — A continuation entry is reachable only by the actor the verifier resolved

**Statement.** The MRTR continuation correlation entry is keyed on the actor the VERIFIER resolved together with the opaque `requestState`, never on anything the request asserts, and a read that does not admit an answer leg does not consume the entry.

**Security consequence.** A second verified actor who knows the open leg's public signature-base digests cannot obtain the victim's retained bases, so it cannot complete a human-approval round trip that was not its own. A refused or transiently-failed read cannot destroy a live approval either.

**Scope — what this does NOT establish.** CONFIGURATION PROJECTION AND REACHABILITY ONLY, and the store is OPPORTUNISTIC: an unavailable shared tier does not refuse startup — the deployment announces its absence and serves, and an answer leg that needs a correlated continuation fails closed at the binding rather than being admitted unbound. So this claim carries no "prevents startup" conjunct, which is where it departs from the shape of its replay sibling. It says nothing about what an acknowledged write durably establishes, and nothing about the continuation binding itself, which is `mcp-re-http-profile`'s.

**Review requirement.** Owner security-specification review

### THM-0088 — A retention artefact reads as a crossing only for an exchange that crossed

**Statement.** The retained-evidence store records an exchange in TWO stages under TWO names. `reserve` publishes `<digest>.reserved`, which carries the request-digest commitment and no part of the request; only `commit_to_dispatch` advances it to `<digest>.pending`, and it advances by RENAMING, so one artefact changes what it asserts rather than two existing independently. The stages are two types whose drop dispositions are opposite. Dropping a `ReservedBeforeDispatch` queues the withdrawal of its marker and returns its admission permit; dropping a `DispatchCommitted` keeps its marker. Neither disposition is a call a path can skip. A publication taken before the exchange may dispatch is WITHDRAWN when its durability barrier does not hold, and the durability of that withdrawal is itself established before the store reports that nothing was published; when it cannot be, the store says so as a distinct fact. A publication taken after the backend acted survives its own failure.

**Security consequence.** A committed-stage marker exists only for an exchange that committed to dispatching, so an auditor reconciling them counts calls that may have run and never calls the boundary refused. Before this, one artefact meant both — accepted at `reserve`, crossed at reconciliation — and no byte on disk separated them, so a saturated inner plane or a refused reservation manufactured indeterminacy for calls that provably never reached a backend. No path leaves one behind by forgetting to release. The withdrawal is a drop, which a refusal, an early return, a panic and a cancelled request future all perform; its predecessor was a call site reachable only from tests. And no marker holds a live credential for a call that has not dispatched. The pre-dispatch artefact carries the digest commitment alone, so a refused exchange leaves no bearer token and no DPoP proof in a store with no expiry — the exposure that a failed reservation could previously make permanent, because no value existed for any release path to consume.

**Scope — what this does NOT establish.** It is about WHEN responsibility was accepted and crossed, never about WHAT the retained record contains. That is `retained_record`'s, and the completed hop still carries the full message including its covered credential headers; the marker's content appears here only as an ABSENCE. A stale reserved-stage marker is permitted and is not a defect this forbids. The withdrawal is queued rather than awaited — `Drop` cannot await — and its unlink is not made durable, so a full queue or a process that dies leaves cleanup debt. What is forbidden is that residue reading as an execution, and it cannot, because it is at the other name. It does not establish that the completion write succeeds, and it claims no atomicity between the store and the backend: they share no transaction, which is why the crossing is recorded BEFORE the dispatch rather than around it. It says nothing about which HTTP refusal each failure earns — that is the serving owner's, under THM-0078.

**Review requirement.** Owner security-specification review

### THM-0089 — A KMS or STS endpoint reaches the authority its text names

**Statement.** An operator-supplied KMS or STS endpoint is accepted only when its literal human-readable representation and the machine interpretation the HTTP client will connect by name the same `host[:port]`. Userinfo, percent- and IDNA-encoded hosts, separators a parser resolves differently, alternate IP spellings a resolver canonicalizes, and non-numeric or non-canonical ports are refused; the plaintext-scheme exception is decided from the host as RESOLVED, after userinfo has been refused. The decision belongs to one owner and is consumed by the command line, the validation boundary, and the AWS-KMS, AWS-STS and GCP-KMS key sources alike — none of them obtains it from another.

**Security consequence.** An endpoint whose spelling names a recognisable authority and whose parse names an attacker's cannot be used to carry the root-key trust bootstrap or, on GCP, a live workload-identity bearer token. `https://cloudkms.googleapis.com@evil.example.com` is not a Google endpoint to the client, and `http://localhost:80@evil.example.com` is not loopback — so the plaintext exception cannot be used to send a bearer token off the machine in the clear, which is the redirection R9-C001 exploited. Because the rule is the owner's rather than each caller's, an embedder reaching a key-source constructor without meeting a parser gets the same decision as an operator on a command line. That is what makes it a property of the endpoint rather than of the entry point.

**Scope — what this does NOT establish.** It ends at the endpoint TEXT. What it establishes is agreement between what a reader sees and what a URL parser resolves — NOT that the address finally connected to is one this deployment would accept. Under a rebinding-capable threat model a name that passes here can still resolve to an address the deployment would refuse; establishing that is the connect-time half owned by `proxy.outbound_destination`, and no credential-bearing egress path consumes it today. This claim must not be read as closing that gap. It says nothing about what a KMS does with a request that reaches it, nothing about key custody or exportability (THM-0064's and THM-0082's), and nothing about whether the provider selected was the right one for the deployment.

**Review requirement.** Owner security-specification review

### THM-0091 — The sidecar signs only for a request its ingress policy admitted

**Statement.** A request that reaches the shipped `mcp-re-client` sidecar outside the deployment-selected listener and HTTP-authority policy cannot cause it to initiate a signed MCP-RE exchange. The listener is where the deployment said: an off-host bind exists only against an explicit operator declaration, and possession of the scope IS that permission — there is no other constructor. The authority set is derived from that scope and never from the flag, so permitting an off-host bind widens the names that reach signing by exactly the listener's own address and by nothing else; a rebound name is refused on an exposed listener as it is on a loopback one. Framing is settled before any header is believed, and the three caller-shape refusals — a present `Origin`, a `Host` that does not name this listener, a body that is not JSON — all run before a single byte is signed. A repeated `Content-Length` or `Host` is refused rather than resolved. EXPLICIT NON-CLAIM. This does not identify or authenticate which local process originated an otherwise admissible request; there is no local-caller authentication and none is offered. The local leg is not confidential. No HTTP `Origin` is authenticated either — its PRESENCE is the refusal, which is a different rule from comparing it against anything. The claim is about ingress authority and reachability, and the word "origin" is not used in any other sense here.

**Security consequence.** The sidecar signs with the agent's key. A web page in the user's browser that could reach the loopback listener — by DNS rebinding, or because the listener answered to any `Host` — would obtain signed, attributed MCP-RE calls under someone else's identity, and every root about what a signature MEANS would remain true while saying nothing about who caused it. The defect this closes was not a missing check but a conflated input. One operator boolean governed two independent facts, so an operator who bound off-host for a documented reason disabled the rebinding guard entirely and was never told, and an operator who set the flag for the bind reason lost the guard silently. Two facts now have two values, and neither can be recombined into the other by a caller: `BindScope` hands out one projection, and `AcceptedHttpAuthority`'s only constructor takes that scope rather than the flag.

**Scope — what this does NOT establish.** It is a NEW ROOT, and independence holds both ways: this sidecar runs against deployments with no MCP-RE proxy, and every other root holds where no sidecar exists. It is deliberately NOT a THM-0076 child — that root's subject is response ACCEPTANCE, and this attack completes before any answer exists. It ends at ADMISSION. What the sidecar then does with an admitted request — that the response it accepts answers the request it sent, that the signer was authorized, that the trust document it resolves anchors from is current — is THM-0084, THM-0057 through THM-0061 and THM-0057's neighbourhood, and none of it is re-derived here. `client.trust_manifest_lifecycle` is deliberately NOT a dependency. The blueprint named it as the source of "what the sidecar is configured to be", and the measurement does not bear that out: admission is decided from the validated local configuration alone, and nothing in the ingress path reads the trust document. An edge would claim support this argument does not use, which is the failure the root set exists to avoid. It says nothing about availability. The exchange deadline is in the closure because a dripping caller must not hold a worker, but a request refused for lateness is refused, not admitted — the claim is one-directional and is not a promise that anything is served.

**Review requirement.** Owner security-specification review

### THM-0092 — A request whose replay state was not established does not dispatch

**Statement.** Under the fleet-strict posture, replay admission refuses before any store side effect when the deployment declares no replay tier, declares one below the strict-production minimum, or wires a store that self-reports the single-process reference class. The atomic admission is the LAST step, and a store that does not answer it refuses the exchange rather than admitting it — reported as an outage, never as a replay. Where the store DOES acknowledge under a tier at or above the strict-production minimum, the nonce is recorded fleet-wide for the request's own retention bound, which is what makes the admission a replay decision rather than a local one. That direction is not local and rests on ASM-0040 or ASM-0041, per mechanism.

**Security consequence.** Replay admission cannot degrade to fail-open on infrastructure trouble. The excluded outcome is not a crash — it is a deployment that believes it has cross-replica replay protection and has process-local protection, serving a replayed request as a fresh one because the store it was supposed to consult was unreachable or was never the store the posture claimed. The outage/replay distinction is part of the claim rather than a diagnostic nicety. A replay verdict says this request was already served, so a caller must not retry; an outage says nothing was established, so a retry is exactly what should happen once the tier is back. Collapsing them gives a caller the opposite advice in one of the two cases.

**Scope — what this does NOT establish.** It is one-directional and is not a liveness claim: it says an unestablished replay state does not dispatch, never that an established one does. The two gates it composes are of different kinds and the claim keeps them apart. The DECLARED tier is the operator's statement, checked here; the store's self-reported durability class is the object's own, checked beneath. A deployment can get the first right and the second wrong, which is why both refuse, and why neither is called a check on the other. Outside fleet-strict the tier gate deliberately does not fire, and this claim says nothing about such a deployment beyond what the core gate beneath still enforces. What an acknowledgement durably established is a FOREIGN fact, registered per mechanism. Nothing here establishes that Redis's replication or etcd's consensus behaves as its premise states, and no umbrella premise stands in for both.

**Review requirement.** Owner security-specification review

**Depends on.** THM-0086

### THM-0093 — An answer leg that needs a continuation does not proceed unbound

**Statement.** Where a request carries a continuation, the retained open-leg bases are read WITHOUT being spent, and every way they can be absent — this deployment runs no store, the request names no `requestState`, the entry was never opened, has expired, or was already answered — yields no binding, so the dispatcher fails closed rather than admitting an unbound continuation. A store that does not ANSWER is refused before admission and named as a deployment fact, not reported as the caller's forged continuation. The spend is the store's atomic consume and has four outcomes, because the store's error is not its negative answer: nothing was at stake, this call spent the approval, the store answered and there was nothing live to spend, or the store did not answer and whether the entry is gone cannot be determined by anything downstream.

**Security consequence.** A signed continuation that cannot be bound to a live approval is never admitted, so a second verified actor cannot complete a human approval round trip that was not its own by presenting a continuation the deployment cannot check. The read is free, so a request about to be refused for an unrelated reason leaves a live approval intact — the refusals above the retirement stay free only because nothing above them spent anything. The four-valued retirement is what keeps a human's approval from being silently destroyed or silently duplicated. "There was definitely nothing to retire" and "the entry may or may not be gone" are different facts about a person's decision, and they warrant different claims about whether an ordinary retry can still succeed.

**Scope — what this does NOT establish.** It is about what a leg may PROCEED on, not about what the deployment has. That the shared continuation tier is opportunistic — its absence announces itself and starts, rather than refusing startup — is THM-0087's scope and is deliberately not restated here. It says nothing about the continuation binding check itself, which is `mcp-re-http-profile`'s and is where a bound-but-wrong continuation is caught, and nothing about what an acknowledged store write durably establishes. The `Indeterminate` retirement is reported, not resolved. Nothing downstream can find out whether the entry was consumed, and this claim does not pretend otherwise — what it establishes is that the outcome is carried as its own case rather than collapsed into one of the other three.

**Review requirement.** Owner security-specification review
