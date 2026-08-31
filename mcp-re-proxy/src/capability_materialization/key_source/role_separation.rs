// SPDX-License-Identifier: Apache-2.0
//! Whether this deployment's two signing ROLES resolved to the same key.
//!
//! A deployment signs with two capabilities and they answer different questions. The
//! RESPONSE-signing key attributes an answer to this proxy; the CHANNEL-signing key proves
//! possession during the handshake that establishes a relationship. If one key serves both,
//! a party able to obtain a handshake signature has thereby obtained a response
//! attribution, and the two roles stop being separately accountable.
//!
//! # Why the comparison is over the MATERIALIZED identity
//!
//! Not over the mechanism locator. `--aws-kms-key-id` and `--aws-kms-tls-key-id` naming
//! different strings says nothing: an ARN, a key id and an alias are three names for one
//! key, a PKCS#11 label is scoped to a token, and a filesystem path resolves through
//! symlinks. Two locators that differ can be the same key, and a check comparing them would
//! report separation that does not exist while looking exactly like one that does.
//!
//! What cannot alias is the key itself. Both roles are asked for their PUBLIC verification
//! key after materialization — from the KMS, from the token, from the file, from the
//! certificate the deployment serves — and the comparison is over
//! [`Ed25519PublicKeyValue`], the canonical RFC 8410 identity this crate already owns. That
//! is one fact per role, obtained from the backend that holds it, and it is the same fact
//! whichever mechanism produced it.
//!
//! # Why possession is the proof
//!
//! [`MaterializedSigningRoles`] holds the key source privately and
//! [`MaterializedSigningRoles::establish`] is its only producer. A serving path cannot hold
//! a key source that did not come through this comparison, so the separation is not a check
//! a construction site remembered to make — deleting the call does not leave a serving path
//! that skips it, it leaves one that does not compile.
//!
//! # What it does NOT claim
//!
//! Nothing about whether either key is the RIGHT one, about custody, about exposure, or
//! about the certificate chain being trusted. It claims exactly that the two roles are two
//! keys. `ChannelCredentialCustody` owns where the channel key lives and `Custody` owns
//! where the response key lives; this is the relation between what they materialized, and
//! it exists because neither machine can see the other's key.

use crate::communication_assurance::certificate_chain_evidence::CertificateChainEvidence;
use crate::communication_assurance::ed25519_public_key::Ed25519PublicKeyValue;
use crate::key_source::{KeyError, KeySource};

/// A deployment's materialized signing capability, known to keep its two roles apart.
///
/// The representation is private and [`Self::establish`] is the only constructor, so
/// holding one IS the proof that the response-signing key and the channel-signing key are
/// different keys.
pub struct MaterializedSigningRoles {
    source: Box<dyn KeySource + Send + Sync>,
}

/// What a role contributed to the comparison.
///
/// `NoKey` is not a failure and not a skipped check. The relation is over what
/// materialization PRODUCED: a role that produced no key is not a role sharing one, so there
/// is nothing to compare rather than something unchecked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoleIdentity {
    /// The role resolved to a canonical RFC 8410 Ed25519 public key.
    Key(Ed25519PublicKeyValue),
    /// It resolved to no key this comparison can use — the backend did not answer, the
    /// material is not there, or the credential presents a key of another profile. In every
    /// case no collapse between the two roles is representable.
    NoKey,
}

impl MaterializedSigningRoles {
    /// Establish that the materialized roles are distinct, or refuse before serving.
    ///
    /// The only producer. It asks each role for its own public key — the response signer
    /// directly, the channel credential through the leaf of the chain this deployment
    /// serves — and refuses when they are the same key.
    pub(super) fn establish(source: Box<dyn KeySource + Send + Sync>) -> Result<Self, KeyError> {
        let response = response_role_identity(source.as_ref());
        let channel = channel_role_identity(source.as_ref());
        if let (RoleIdentity::Key(response), RoleIdentity::Key(channel)) = (response, channel) {
            if channel.raw_point() == response.raw_point() {
                return Err(KeyError::Malformed(
                    "the response-signing key and the channel-signing key are the same key. \
                     The two roles are separately attributable only while they are separate \
                     keys: a party able to obtain a handshake signature would otherwise have \
                     obtained a response attribution. Configure a distinct key for one of \
                     them."
                        .to_string(),
                ));
            }
        }
        Ok(MaterializedSigningRoles { source })
    }

    /// The key source, for the composition root that materializes the serving path.
    ///
    /// Consuming, so the witness is not left behind to be presented for a second source.
    pub fn into_key_source(self) -> Box<dyn KeySource + Send + Sync> {
        self.source
    }
}

/// The response role's identity: its public verification key, in this crate's canonical
/// form.
///
/// A backend that does not answer yields `NoKey` — see the note on
/// [`channel_role_identity`], which is the same argument on the other side.
///
/// The canonical round trip itself cannot fail: `spki_der_for_point` is the WRITE direction
/// of the same owner that interprets, and its own contract is that interpreting what it
/// produced yields the point back. There is no arm here for that.
fn response_role_identity(source: &(dyn KeySource + Send + Sync)) -> RoleIdentity {
    let Ok(key) = source.response_public_key() else {
        return RoleIdentity::NoKey;
    };
    let spki = Ed25519PublicKeyValue::spki_der_for_point(key.to_bytes());
    match Ed25519PublicKeyValue::interpret_rfc8410_spki(&spki) {
        Ok(value) => RoleIdentity::Key(value),
        Err(_) => unreachable!("the canonical encoder's output is canonical"),
    }
}

/// The channel role's identity: the public key inside the leaf of the credential chain this
/// deployment serves.
///
/// The leaf is the right operand on BOTH custody paths. Under delegated channel custody the
/// resolver already refuses a signer whose key does not match this leaf, and under exported
/// custody the served chain is what the handshake authenticates as. So asking the
/// certificate asks the key that actually signs the handshake, without either path having
/// to expose private material to be compared.
///
/// # Infallible, and why that is not fail-open
///
/// An unreadable, absent or empty credential chain yields `NoKey` rather than a refusal, and
/// the same holds for the response role. This authority owns ONE proposition — *the two
/// roles are two keys* — and whether a backend answers belongs to the owner of that
/// material. Refusing here would give this relation an opinion about a thing it does not
/// own, and would move where an operator is told about it: a deployment with a missing
/// certificate would start reporting the fault as a signing-role collapse.
///
/// It also cannot become a way to SKIP the comparison, because there is no execution in
/// which a role produced no key and serving proceeds. The composition root reads the served
/// chain immediately afterwards to build the listener, and the response public key to build
/// the delegation — so a deployment where either is unavailable starts no server. The only
/// executions this arm admits are executions that never serve.
///
/// That is also what keeps `build_key_source` a construction rather than a probe: a key
/// source has always been buildable without the material being present, and a relation that
/// turned an absent seed file into a role error would have changed what constructibility
/// means.
fn channel_role_identity(source: &(dyn KeySource + Send + Sync)) -> RoleIdentity {
    let Ok(chain) = source.tls_server_cert_chain() else {
        return RoleIdentity::NoKey;
    };
    let Some(leaf) = chain.first() else {
        return RoleIdentity::NoKey;
    };
    match CertificateChainEvidence::from_leaf_der(leaf.as_ref()).interpret_credential_public_key() {
        Ok(evidence) => RoleIdentity::Key(evidence.key()),
        Err(_) => RoleIdentity::NoKey,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_core::VerificationKey;

    #[test]
    fn the_response_identity_round_trips_its_own_point() {
        let (leaf, key) = ed25519_leaf();
        let source = RolesFixture {
            response: key.clone(),
            channel_leaf: leaf,
        };
        assert_eq!(
            response_role_identity(&source),
            RoleIdentity::Key(
                Ed25519PublicKeyValue::interpret_rfc8410_spki(
                    &Ed25519PublicKeyValue::spki_der_for_point(key.to_bytes())
                )
                .expect("canonical")
            )
        );
    }

    #[test]
    fn two_different_keys_have_two_different_identities() {
        let (leaf_a, a) = ed25519_leaf();
        let (leaf_b, b) = ed25519_leaf();
        let ia = response_role_identity(&RolesFixture {
            response: a,
            channel_leaf: leaf_a,
        });
        let ib = response_role_identity(&RolesFixture {
            response: b,
            channel_leaf: leaf_b,
        });
        assert_ne!(
            ia, ib,
            "two distinct keys must not share an identity, or the comparison is vacuous"
        );
    }

    /// A credential whose key is not a canonical Ed25519 key contributes no comparison —
    /// and that is a STATEMENT, because the response role's key always is one, so the two
    /// cannot be equal.
    #[test]
    fn a_non_ed25519_credential_is_incomparable_rather_than_a_failure() {
        let garbage = vec![0x30, 0x03, 0x02, 0x01, 0x00];
        assert!(CertificateChainEvidence::from_leaf_der(&garbage)
            .interpret_credential_public_key()
            .is_err());
    }

    /// A key source whose two roles are whatever the fixture says they are.
    ///
    /// It answers the two questions the relation asks and nothing else: every other method
    /// is unreachable from `establish`, so a fixture that implemented them would be
    /// describing a capability this authority does not consult.
    struct RolesFixture {
        response: VerificationKey,
        channel_leaf: Vec<u8>,
    }

    impl crate::key_source::ResponseSigner for RolesFixture {
        fn sign_response(&self, _preimage: &[u8]) -> Result<String, KeyError> {
            unreachable!("the role relation never signs")
        }
        fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
            Ok(self.response.clone())
        }
    }

    impl KeySource for RolesFixture {
        fn tls_server_cert_chain(
            &self,
        ) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, KeyError> {
            Ok(vec![rustls_pki_types::CertificateDer::from(
                self.channel_leaf.clone(),
            )])
        }
        fn tls_server_key(&self) -> Result<rustls_pki_types::PrivateKeyDer<'static>, KeyError> {
            unreachable!("the role relation never exports a private key")
        }
        fn client_ca_roots(
            &self,
        ) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, KeyError> {
            unreachable!("the role relation never reads the trust anchors")
        }
    }

    /// A self-signed Ed25519 leaf certificate, and the verification key it presents.
    ///
    /// The key is read back out of the CERTIFICATE rather than from the generator, so the
    /// fixture pairs exactly what the relation will read — a fixture that reported the
    /// generator's key would agree with the relation by construction and prove nothing.
    fn ed25519_leaf() -> (Vec<u8>, VerificationKey) {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("keypair");
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        let cert = params.self_signed(&pair).expect("self-signed leaf");
        let der = cert.der().to_vec();
        let key = CertificateChainEvidence::from_leaf_der(&der)
            .interpret_credential_public_key()
            .expect("rcgen emits a canonical Ed25519 SPKI")
            .key();
        let verification =
            VerificationKey::from_bytes(&key.raw_point()).expect("a generated key is a point");
        (der, verification)
    }

    /// THE refusal. One key serving both roles cannot become a serving capability.
    #[test]
    fn a_deployment_whose_two_roles_are_one_key_cannot_be_materialized() {
        let (leaf, channel_key) = ed25519_leaf();
        let source = Box::new(RolesFixture {
            response: channel_key,
            channel_leaf: leaf,
        });
        let refusal = MaterializedSigningRoles::establish(source)
            .err()
            .expect("one key serving both roles must be refused");
        assert!(
            format!("{refusal}").contains("same key"),
            "the refusal must name what is wrong: {refusal}"
        );
    }

    /// Two keys materialize. Without this the refusal above could be unconditional.
    #[test]
    fn two_distinct_roles_materialize() {
        let (leaf, _) = ed25519_leaf();
        let (_, other) = ed25519_leaf();
        let source = Box::new(RolesFixture {
            response: other,
            channel_leaf: leaf,
        });
        assert!(
            MaterializedSigningRoles::establish(source).is_ok(),
            "a deployment holding two different keys must materialize"
        );
    }

    /// A source whose credential chain cannot be READ contributes no comparison, and is not
    /// a refusal.
    ///
    /// Found by CI rather than by design: `build_key_source` did not read the served chain
    /// before this relation existed, so propagating a chain-read failure out of it turned a
    /// missing certificate into a signing-role error and broke a fixture that had never
    /// needed one. The relation owns whether the two roles are two keys; whether a chain is
    /// readable is the credential owner's, and it refuses a moment later — no execution
    /// reaches serving through this arm.
    /// A source built over material that is not on disk contributes no comparison on either
    /// side, and is not a refusal.
    ///
    /// Found by CI rather than by design. `build_key_source` touched no filesystem before
    /// this relation existed — a key source has always been CONSTRUCTIBLE without its
    /// material being present, which is what `file_key_source_is_always_constructible`
    /// asserts — and propagating either read failure out of the relation turned an absent
    /// seed or certificate into a signing-role error and changed what constructibility
    /// means. The relation owns whether the two roles are two keys; whether a backend
    /// answers is that material's owner's, and it refuses a moment later.
    #[test]
    fn a_source_over_absent_material_materializes_on_either_side() {
        /// A source whose two roles answer or refuse independently.
        struct Absent {
            response: Option<VerificationKey>,
            leaf: Option<Vec<u8>>,
        }
        impl crate::key_source::ResponseSigner for Absent {
            fn sign_response(&self, _preimage: &[u8]) -> Result<String, KeyError> {
                unreachable!("the role relation never signs")
            }
            fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
                self.response
                    .clone()
                    .ok_or_else(|| KeyError::NotFound("no seed here".to_string()))
            }
        }
        impl KeySource for Absent {
            fn tls_server_cert_chain(
                &self,
            ) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, KeyError> {
                self.leaf
                    .clone()
                    .map(|der| vec![rustls_pki_types::CertificateDer::from(der)])
                    .ok_or_else(|| KeyError::NotFound("no certificate here".to_string()))
            }
            fn tls_server_key(&self) -> Result<rustls_pki_types::PrivateKeyDer<'static>, KeyError> {
                unreachable!("the role relation never exports a private key")
            }
            fn client_ca_roots(
                &self,
            ) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, KeyError> {
                unreachable!("the role relation never reads the trust anchors")
            }
        }
        let (leaf, key) = ed25519_leaf();
        assert!(
            MaterializedSigningRoles::establish(Box::new(Absent {
                response: Some(key.clone()),
                leaf: None,
            }))
            .is_ok(),
            "an unreadable credential chain must not be reported as a signing-role collapse"
        );
        assert!(
            MaterializedSigningRoles::establish(Box::new(Absent {
                response: None,
                leaf: Some(leaf),
            }))
            .is_ok(),
            "an unreadable response key must not be reported as a signing-role collapse"
        );
    }

    /// A channel credential of another profile is not a collapse, and is not a failure.
    #[test]
    fn an_incomparable_channel_credential_materializes() {
        let (_, response) = ed25519_leaf();
        let source = Box::new(RolesFixture {
            response,
            channel_leaf: vec![0x30, 0x03, 0x02, 0x01, 0x00],
        });
        assert!(
            MaterializedSigningRoles::establish(source).is_ok(),
            "a channel key that cannot BE the response key must not be refused as if it were"
        );
    }
}
