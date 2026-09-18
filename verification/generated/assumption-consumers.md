<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- GENERATED FILE — DO NOT EDIT.
     Regenerate with: tools/verification/generate-views
     Gated by:        tools/verification/check-generated
     Derived from:
       verification/policy/theorems.toml
       verification/policy/verification.toml
       verification/policy/assumptions.toml
       verification/policy/trust-boundaries.toml
-->

# Assumption consumers

What each trusted assumption reaches, derived by following scope → unit →
theorem. An assumption several claims stand on is ONE node, not several
independent results, and this view exists so it cannot read as the latter.

| id | premise class | what is trusted | scoped to units | reaches theorems |
|---|---|---|---|---|
| ASM-0001 | review-obligation | `parse_fixed_digits` returns at most a 4-digit value: n ASCII digits cannot denote more than n digits. | core.time_rfc3339 | THM-0002 |
| ASM-0002 | external-boundary | `u8::is_ascii_digit` is true exactly on 0x30..=0x39. | core.time_rfc3339 | THM-0002 |
| ASM-0003 | external-boundary | `<[T]>::split_last` terminates and returns. | core.time_rfc3339 | THM-0002 |
| ASM-0004 | review-obligation | `McpReError` is nameable in a specification as a plain datatype, without verifying its derived Display impl. | core.time_rfc3339 | THM-0002 |
| ASM-0005 | external-boundary | `i64::saturating_sub` clamps at i64::MIN rather than wrapping. | http_profile.freshness_window | THM-0001, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 |
| ASM-0006 | external-boundary | `i64::saturating_add` clamps at i64::MAX rather than wrapping. | http_profile.freshness_window | THM-0001, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 |
| ASM-0007 | assumed | `VerifierPolicy::max_clock_skew` returns this policy's configured skew. | http_profile.freshness_window | THM-0001, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 |
| ASM-0008 | assumed | `VerifierPolicy::max_signature_validity` returns this policy's configured window bound. | http_profile.freshness_window | THM-0001, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 |
| ASM-0009 | review-obligation | `VerifierPolicy::accepted_algorithm` resolves a wire token to an accepted algorithm, or None. | http_profile.freshness_window | THM-0001, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 |
| ASM-0010 | external-boundary | `Option::<T>::as_deref` is total; nothing is claimed about its result. | http_profile.freshness_window | THM-0001, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 |
| ASM-0011 | review-obligation | `AdmissionBinding::matches_state` decides whether this binding commits to a given admitted-state digest. | http_profile.admission_currency | THM-0003, THM-0004, THM-0005, THM-0006 |
| ASM-0012 | review-obligation | `verify_admission_assertion` is opaque to the currency theorem, and contributes NO postcondition to it. | http_profile.admission_currency | THM-0003, THM-0004, THM-0005, THM-0006 |
| ASM-0013 | review-obligation | `mcp_re_core::VerificationKey` is an opaque datatype; no theorem reads it. | http_profile.admission_currency | THM-0003, THM-0004, THM-0005, THM-0006 |
| ASM-0014 | external-boundary | `#[derive(PartialEq)]` on the fieldless enum `AdmissionStatus` is structural equality. | http_profile.admission_currency | THM-0003, THM-0004, THM-0005, THM-0006 |
| ASM-0015 | _withdrawn_ | RESERVED — withdrawn before use. | _no unit_ | _no theorem_ |
| ASM-0018 | review-obligation | `sha256_b64url` and `compare` are opaque digest primitives; nothing is claimed about the digest. | http_profile.artifact_typing | THM-0007 |
| ASM-0019 | review-obligation | `ArtifactBinding::validate` is opaque; the typing theorem holds whatever it returns. | http_profile.artifact_typing | THM-0007 |
| ASM-0020 | external-boundary | `#[derive(PartialEq)]` on the fieldless enums `ArtifactType` and `BindingType` is structural equality. | http_profile.artifact_typing | THM-0007 |
| ASM-0021 | review-obligation | `ActorIdentity::actor_id` / `ResolvedActor::actor_id` are opaque; NO ensures. | http_profile.continuation_unbypassability | THM-0009 |
| ASM-0022 | _withdrawn_ | WITHDRAWN — discharged by unit://http_profile.continuation_binding. | _no unit_ | _no theorem_ |
| ASM-0023 | review-obligation | `RequestEvidenceDigest::matches_labeled` returning true means this handle's value IS the labeled digest of those bytes under that label. | http_profile.continuation_binding | THM-0010 |
| ASM-0024 | assumed | `labeled_digest(label, bytes)` is a function of its arguments and nothing more. | http_profile.admission_currency, http_profile.artifact_typing, http_profile.continuation_binding, http_profile.continuation_unbypassability, http_profile.freshness_window | THM-0001, THM-0003, THM-0004, THM-0005, THM-0006, THM-0007, THM-0009, THM-0010, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 |
| ASM-0025 | assumed | `skew_of(policy)` is the deployment's configured clock skew, as a function of the policy object. | http_profile.admission_currency, http_profile.artifact_typing, http_profile.continuation_binding, http_profile.continuation_unbypassability, http_profile.freshness_window | THM-0001, THM-0003, THM-0004, THM-0005, THM-0006, THM-0007, THM-0009, THM-0010, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 |
| ASM-0026 | assumed | `validity_of(policy)` is the widest accepted `expires - created`, as a function of the policy object. | http_profile.admission_currency, http_profile.artifact_typing, http_profile.continuation_binding, http_profile.continuation_unbypassability, http_profile.freshness_window | THM-0001, THM-0003, THM-0004, THM-0005, THM-0006, THM-0007, THM-0009, THM-0010, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 |
| ASM-0027 | assumed | Ed25519 verification accepts a signature over a message only if it was produced under the private key corresponding to the verification key supplied. | http_profile.bound_response_seam_result, http_profile.bound_response_shared_facts, http_profile.delegated_bound_result, http_profile.delegated_credential_chain, http_profile.delegated_unbound_result, http_profile.request_floor_result, http_profile.unbound_response_seam_result, http_profile.unbound_response_shared_facts | THM-0014, THM-0016, THM-0017, THM-0019, THM-0020, THM-0021, THM-0022 |
| ASM-0028 | assumed | SHA-256 is second-preimage resistant over the byte strings this profile digests, so digest agreement implies byte agreement. | http_profile.bound_response_full_result, http_profile.bound_response_shared_facts, http_profile.delegated_bound_result, http_profile.request_floor_result, http_profile.request_full_result, http_profile.unbound_response_shared_facts | THM-0014, THM-0015, THM-0018, THM-0019, THM-0021, THM-0022 |
| ASM-0029 | assumed | The trust seam answers its SELECTOR correctly: for a queried (keyid, slot), the `ResolvedActor` it returns carries the identity and verification key this deployment has authorized to sign under that keyid in that slot. | http_profile.bound_response_seam_result, http_profile.delegated_credential_chain, http_profile.request_floor_result, http_profile.unbound_response_seam_result | THM-0014, THM-0016, THM-0017, THM-0019, THM-0020 |
| ASM-0030 | external-boundary | The X.509 parser faithfully reports a leaf's URI SANs, DNS SANs, and subject Common Name, in the order the certificate presents them. | proxy.certificate_identity | THM-0024 |
| ASM-0031 | external-boundary | The X.509 SubjectPublicKeyInfo parser faithfully reports a key's algorithm OID, and refuses what is not a SubjectPublicKeyInfo. | proxy.ed25519_public_key | THM-0025 |
| ASM-0032 | external-boundary | The X.509 certificate parser faithfully reports the leaf certificate's SubjectPublicKeyInfo bytes. | proxy.credential_key_correspondence | THM-0026 |
| ASM-0033 | external-boundary | The TLS establishment mechanism faithfully reports whether a relationship has established, and which peer credential it associated with it. | proxy.channel_associated_credential | THM-0028 |
| ASM-0034 | external-boundary | rustls::ServerConnection::peer_certificates() reports the peer certificate chain in TLS order: element 0 is the peer/end-entity credential, and later elements certify preceding elements. | proxy.channel_associated_identity | THM-0029 |
| ASM-0035 | external-boundary | The TLS establishment mechanism faithfully reports which establishment path a relationship took, and admits a resumed session only where an earlier full handshake accepted the peer under an anchor set that has not changed since. | proxy.mechanism_verified_credential | THM-0030 |
| ASM-0036 | external-boundary | A TLS establishment mechanism accepts a client credential only under proof that binds the peer to it: on a FULL handshake, current control of the credential's private key, proved by CertificateVerify; on a RESUMED handshake, possession of resumption secret material derived from an earlier authenticated handshake — authentication CONTINUITY, not a fresh private-key proof. | proxy.authenticated_relationship_peer | THM-0031 |
| ASM-0037 | assumed | SHA-256 is collision resistant: no computationally feasible adversary exhibits two distinct byte strings sharing a digest. | http_profile.keyid_selector | THM-0050 |
| ASM-0038 | external-boundary | The X.509 parser faithfully reports a certificate's validity instants, the DER encodings of its issuer and subject `Name`, and its serial number. | proxy.credential_currency | THM-0032 |
| ASM-0039 | external-boundary | A `RawEd25519TlsSigner` reports, as `tls_public_key_spki_der`, the SubjectPublicKeyInfo of the very key `sign_tls_ed25519` signs with. | proxy.delegated_resolver_materialization | THM-0027 |
| ASM-0040 | external-boundary | A Redis `WAIT n t` reply of at least `n` means `n` replicas acknowledged the preceding `SET NX PX`, and the tier's declared quorum is the number that survives the failures ADR-MCPS-020 admits for REDIS_WAIT_QUORUM. | proxy.replay_admission_gate | THM-0092 |
| ASM-0041 | external-boundary | An etcd `POST /v3/kv/txn` that succeeds under `compare { target: CREATE, create_revision: 0 }` means the key did not exist at a linearization point and now does, cluster-wide, for the granted lease's TTL. | proxy.replay_admission_gate | THM-0092 |
| ASM-0042 | _withdrawn_ | WITHDRAWN — discharged by unit://sdk_python.exchange_path. | _no unit_ | _no theorem_ |
| ASM-0043 | _withdrawn_ | WITHDRAWN — discharged by unit://sdk_typescript.exchange_path. | _no unit_ | _no theorem_ |
| ASM-0044 | external-boundary | A read of the trust-epoch key over a replica's own connection, issued after an operator's `INCR` on that key was acknowledged, returns a value different from every value that replica read before the `INCR`. | proxy.trust_epoch_source | _no theorem_ |
| ASM-0045 | assumed | Each `Ex…` external type specification declares the same datatype as the profile type it mirrors, so a specification naming the mirror is a specification about the real type. | http_profile.admission_currency, http_profile.artifact_typing, http_profile.continuation_binding, http_profile.continuation_unbypassability, http_profile.freshness_window | THM-0001, THM-0003, THM-0004, THM-0005, THM-0006, THM-0007, THM-0009, THM-0010, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 |
| ASM-0046 | assumed | `ExVerifierPolicy`, `ExProfileAlgorithm` and `ExVerificationKey` are OPAQUE: the prover models each as a datatype with no readable fields. | http_profile.admission_currency, http_profile.artifact_typing, http_profile.continuation_binding, http_profile.continuation_unbypassability, http_profile.freshness_window | THM-0001, THM-0003, THM-0004, THM-0005, THM-0006, THM-0007, THM-0009, THM-0010, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 |
| ASM-0047 | external-boundary | Write access to the `mcp-re:cont:` keyspace of the shared correlation tier is confined to the fleet's own replicas, so an entry found there was written by an open leg of this deployment. | proxy.continuation_correlation_store | THM-0087 |
| ASM-0048 | external-boundary | A Redis `DEL key` reply of 1 means THIS call removed a key that existed, and a `SET key v PX t` keeps the key readable for `t` milliseconds and then not — so the delete count is a one-shot verdict across replicas and the entry's lifetime is bounded. | proxy.continuation_correlation_store | THM-0087 |
| ASM-0049 | assumed | For any two distinct trust-anchor sets this deployment admits across listener replacements, the canonical trust-epoch derivation produces distinct SHA-256 digest values. | proxy.epoch_bound_session_store, proxy.listener_state_assembly | THM-0048, THM-0103 |

19 assumption(s) are reached by more than one theorem.
