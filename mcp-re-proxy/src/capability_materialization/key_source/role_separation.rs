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

use mcp_re_core::VerificationKey;

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

/// Why the channel role contributes no comparable identity.
///
/// Not a failure. A channel credential whose public key is not a canonical RFC 8410 Ed25519
/// key CANNOT be the response-signing key, which is always one — so separation holds, and
/// it holds for a reason worth naming rather than for an absent comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelIdentity {
    /// The channel credential presents a canonical Ed25519 key.
    Comparable(Ed25519PublicKeyValue),
    /// It presents a key of another profile, so no collapse with the response role is
    /// representable.
    IncomparableProfile,
}

impl MaterializedSigningRoles {
    /// Establish that the materialized roles are distinct, or refuse before serving.
    ///
    /// The only producer. It asks each role for its own public key — the response signer
    /// directly, the channel credential through the leaf of the chain this deployment
    /// serves — and refuses when they are the same key.
    pub(super) fn establish(source: Box<dyn KeySource + Send + Sync>) -> Result<Self, KeyError> {
        let response = response_role_identity(&source.response_public_key()?);
        if let ChannelIdentity::Comparable(channel) = channel_role_identity(source.as_ref())? {
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
/// Total. `spki_der_for_point` is the WRITE direction of the same owner that interprets,
/// and its own contract is that interpreting what it produced yields the point back — so
/// the round trip cannot fail and there is no arm here for a failure that cannot occur.
fn response_role_identity(key: &VerificationKey) -> Ed25519PublicKeyValue {
    let spki = Ed25519PublicKeyValue::spki_der_for_point(key.to_bytes());
    Ed25519PublicKeyValue::interpret_rfc8410_spki(&spki)
        .unwrap_or_else(|_| unreachable!("the canonical encoder's output is canonical"))
}

/// The channel role's identity: the public key inside the leaf of the credential chain this
/// deployment serves.
///
/// The leaf is the right operand on BOTH custody paths. Under delegated channel custody the
/// resolver already refuses a signer whose key does not match this leaf, and under exported
/// custody the served chain is what the handshake authenticates as. So asking the
/// certificate asks the key that actually signs the handshake, without either path having
/// to expose private material to be compared.
fn channel_role_identity(
    source: &(dyn KeySource + Send + Sync),
) -> Result<ChannelIdentity, KeyError> {
    let chain = source.tls_server_cert_chain()?;
    let Some(leaf) = chain.first() else {
        // No credential to serve. Nothing is comparable, and the deployment fails later on
        // its own terms — inventing a refusal here would give this authority an opinion
        // about the chain, which belongs to the credential owner.
        return Ok(ChannelIdentity::IncomparableProfile);
    };
    Ok(
        match CertificateChainEvidence::from_leaf_der(leaf.as_ref())
            .interpret_credential_public_key()
        {
            Ok(evidence) => ChannelIdentity::Comparable(evidence.key()),
            Err(_) => ChannelIdentity::IncomparableProfile,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two distinct 32-byte points, each a valid Ed25519 public key.
    fn two_keys() -> (VerificationKey, VerificationKey) {
        let a = mcp_re_core::SigningKey::from_seed_bytes(&[1u8; 32]);
        let b = mcp_re_core::SigningKey::from_seed_bytes(&[2u8; 32]);
        (a.public_key(), b.public_key())
    }

    #[test]
    fn the_response_identity_round_trips_its_own_point() {
        let (a, _) = two_keys();
        assert_eq!(response_role_identity(&a).raw_point(), a.to_bytes());
    }

    #[test]
    fn two_different_keys_have_two_different_identities() {
        let (a, b) = two_keys();
        assert_ne!(
            response_role_identity(&a).raw_point(),
            response_role_identity(&b).raw_point(),
            "two distinct keys must not share an identity, or the comparison is vacuous"
        );
    }

    /// The same key read twice IS the same identity — the direction the refusal depends on.
    #[test]
    fn one_key_has_one_identity_however_often_it_is_asked() {
        let (a, _) = two_keys();
        assert_eq!(
            response_role_identity(&a).raw_point(),
            response_role_identity(&a).raw_point()
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
