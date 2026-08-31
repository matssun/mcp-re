<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- GENERATED FILE — DO NOT EDIT.
     Regenerate with: tools/verification/generate-views
     Gated by:        tools/verification/check-generated
     Derived from:
       verification/policy/theorems.toml
       verification/policy/verification.toml
       verification/policy/assumptions.toml
-->

# Assumption consumers

What each trusted assumption reaches, derived by following scope → unit →
theorem. An assumption several claims stand on is ONE node, not several
independent results, and this view exists so it cannot read as the latter.

| id | what is trusted | scoped to units | reaches theorems |
|---|---|---|---|
| ASM-0001 | `parse_fixed_digits` returns at most a 4-digit value: n ASCII digits cannot denote more than n digits. | core.time_rfc3339 | THM-0002 |
| ASM-0002 | `u8::is_ascii_digit` is true exactly on 0x30..=0x39. | core.time_rfc3339 | THM-0002 |
| ASM-0003 | `<[T]>::split_last` terminates and returns. | core.time_rfc3339 | THM-0002 |
| ASM-0004 | `McpReError` is nameable in a specification as a plain datatype, without verifying its derived Display impl. | core.time_rfc3339 | THM-0002 |
| ASM-0005 | `i64::saturating_sub` clamps at i64::MIN rather than wrapping. | http_profile.freshness_window | THM-0001, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 |
| ASM-0006 | `i64::saturating_add` clamps at i64::MAX rather than wrapping. | http_profile.freshness_window | THM-0001, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 |
| ASM-0007 | `VerifierPolicy::max_clock_skew` returns this policy's configured skew. | http_profile.freshness_window | THM-0001, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 |
| ASM-0008 | `VerifierPolicy::max_signature_validity` returns this policy's configured window bound. | http_profile.freshness_window | THM-0001, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 |
| ASM-0009 | `VerifierPolicy::accepted_algorithm` resolves a wire token to an accepted algorithm, or None. | http_profile.freshness_window | THM-0001, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 |
| ASM-0010 | `Option::<T>::as_deref` is total; nothing is claimed about its result. | http_profile.freshness_window | THM-0001, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 |
| ASM-0011 | `AdmissionBinding::matches_state` decides whether this binding commits to a given admitted-state digest. | http_profile.admission_currency | THM-0003, THM-0004, THM-0005, THM-0006 |
| ASM-0012 | `verify_admission_assertion` is opaque to the currency theorem, and contributes NO postcondition to it. | http_profile.admission_currency | THM-0003, THM-0004, THM-0005, THM-0006 |
| ASM-0013 | `mcp_re_core::VerificationKey` is an opaque datatype; no theorem reads it. | http_profile.admission_currency | THM-0003, THM-0004, THM-0005, THM-0006 |
| ASM-0014 | `#[derive(PartialEq)]` on the fieldless enum `AdmissionStatus` is structural equality. | http_profile.admission_currency | THM-0003, THM-0004, THM-0005, THM-0006 |
| ASM-0015 | RESERVED — withdrawn before use. | _no unit_ | _no theorem_ |
| ASM-0018 | `sha256_b64url` and `compare` are opaque digest primitives; nothing is claimed about the digest. | http_profile.artifact_typing | THM-0007 |
| ASM-0019 | `ArtifactBinding::validate` is opaque; the typing theorem holds whatever it returns. | http_profile.artifact_typing | THM-0007 |
| ASM-0020 | `#[derive(PartialEq)]` on the fieldless enums `ArtifactType` and `BindingType` is structural equality. | http_profile.artifact_typing | THM-0007 |
| ASM-0021 | `ActorIdentity::actor_id` / `ResolvedActor::actor_id` are opaque; NO ensures. | http_profile.continuation_unbypassability | THM-0009 |
| ASM-0022 | WITHDRAWN — discharged by unit://http_profile.continuation_binding. | _no unit_ | _no theorem_ |
| ASM-0023 | `RequestEvidenceDigest::matches_labeled` returning true means this handle's value IS the labeled digest of those bytes under that label. | http_profile.continuation_binding | THM-0010 |
| ASM-0024 | `labeled_digest(label, bytes)` is a function of its arguments and nothing more. | http_profile.admission_currency, http_profile.artifact_typing, http_profile.continuation_binding, http_profile.continuation_unbypassability, http_profile.freshness_window | THM-0001, THM-0003, THM-0004, THM-0005, THM-0006, THM-0007, THM-0009, THM-0010, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 |
| ASM-0025 | `skew_of(policy)` is the deployment's configured clock skew, as a function of the policy object. | http_profile.admission_currency, http_profile.artifact_typing, http_profile.continuation_binding, http_profile.continuation_unbypassability, http_profile.freshness_window | THM-0001, THM-0003, THM-0004, THM-0005, THM-0006, THM-0007, THM-0009, THM-0010, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 |
| ASM-0026 | `validity_of(policy)` is the widest accepted `expires - created`, as a function of the policy object. | http_profile.admission_currency, http_profile.artifact_typing, http_profile.continuation_binding, http_profile.continuation_unbypassability, http_profile.freshness_window | THM-0001, THM-0003, THM-0004, THM-0005, THM-0006, THM-0007, THM-0009, THM-0010, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 |
| ASM-0027 | Ed25519 verification accepts a signature over a message only if it was produced under the private key corresponding to the verification key supplied. | http_profile.verifier_results | THM-0014, THM-0015, THM-0016, THM-0017, THM-0018, THM-0019, THM-0020, THM-0021, THM-0022, THM-0065 |
| ASM-0028 | SHA-256 is second-preimage resistant over the byte strings this profile digests, so digest agreement implies byte agreement. | http_profile.verifier_results | THM-0014, THM-0015, THM-0016, THM-0017, THM-0018, THM-0019, THM-0020, THM-0021, THM-0022, THM-0065 |
| ASM-0029 | The trust seam answers its SELECTOR correctly: for a queried (keyid, slot), the `ResolvedActor` it returns carries the identity and verification key this deployment has authorized to sign under that keyid in that slot. | http_profile.verifier_results | THM-0014, THM-0015, THM-0016, THM-0017, THM-0018, THM-0019, THM-0020, THM-0021, THM-0022, THM-0065 |
| ASM-0030 | The X.509 parser faithfully reports a leaf's URI SANs, DNS SANs, and subject Common Name, in the order the certificate presents them. | proxy.certificate_identity | THM-0024 |
| ASM-0031 | The X.509 SubjectPublicKeyInfo parser faithfully reports a key's algorithm OID, and refuses what is not a SubjectPublicKeyInfo. | proxy.ed25519_public_key | THM-0025 |
| ASM-0032 | The X.509 certificate parser faithfully reports the leaf certificate's SubjectPublicKeyInfo bytes. | proxy.credential_key_correspondence | THM-0026 |
| ASM-0033 | The TLS establishment mechanism faithfully reports whether a relationship has established, and which peer credential it associated with it. | proxy.channel_associated_credential | THM-0028 |
| ASM-0034 | rustls::ServerConnection::peer_certificates() reports the peer certificate chain in TLS order: element 0 is the peer/end-entity credential, and later elements certify preceding elements. | proxy.channel_associated_identity | THM-0029 |
| ASM-0035 | The TLS establishment mechanism faithfully reports which establishment path a relationship took, and admits a resumed session only where an earlier full handshake accepted the peer under an anchor set that has not changed since. | proxy.mechanism_verified_credential | THM-0030 |
| ASM-0036 | A TLS establishment mechanism accepts a client credential only under proof that binds the peer to it: on a FULL handshake, current control of the credential's private key, proved by CertificateVerify; on a RESUMED handshake, possession of resumption secret material derived from an earlier authenticated handshake — authentication CONTINUITY, not a fresh private-key proof. | proxy.authenticated_relationship_peer | THM-0031 |
| ASM-0037 | SHA-256 is collision resistant: no computationally feasible adversary exhibits two distinct byte strings sharing a digest. | http_profile.keyid | THM-0055 |

16 assumption(s) are reached by more than one theorem.
