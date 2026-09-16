// SPDX-License-Identifier: Apache-2.0
//! What one signing ROLE resolved to, and what it means when it resolved to nothing.
//!
//! The operand half of [`super::role_separation`]. That module owns the RELATION between the
//! two roles; this one owns what each role contributes to it, which is a different
//! proposition and carries a different argument — the relation's is about accountability,
//! and this one's is about which authority owns an absent backend.

use crate::communication_assurance::certificate_chain_evidence::CertificateChainEvidence;
use crate::communication_assurance::ed25519_public_key::Ed25519PublicKeyValue;
use crate::key_source::KeySource;

/// What a role contributed to the comparison.
///
/// `NoKey` is not a failure and not a skipped check. The relation is over what
/// materialization PRODUCED: a role that produced no key is not a role sharing one, so there
/// is nothing to compare rather than something unchecked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RoleIdentity {
    /// The role resolved to a canonical RFC 8410 Ed25519 public key.
    Key(Ed25519PublicKeyValue),
    /// It resolved to no key this comparison can use — the backend did not answer, the
    /// material is not there, or the credential presents a key of another profile. In every
    /// case no collapse between the two roles is representable.
    NoKey,
}

/// The response role's identity: its public verification key, in this crate's canonical
/// form.
///
/// A backend that does not answer yields `NoKey` — see the note on
/// [`channel_role_identity`], which is the same argument on the other side.
///
/// There is no failure arm for the canonical form, and no panic standing in for one. The
/// value owner's `for_point` is total — a thirty-two-byte point has exactly one canonical
/// RFC 8410 encoding — so the only question here is whether the backend answered.
///
/// It used to write the point out and interpret it back, which manufactured an `Err` arm for
/// an outcome that owner's own contract says cannot occur, and filled it with
/// `unreachable!`. `unreachable!` is not covered by the ADR-MCPRE-061 §6 lints, so it
/// carried no obligation to justify itself while making exactly the kind of claim they
/// exist to hold to account.
pub(super) fn response_role_identity(source: &(dyn KeySource + Send + Sync)) -> RoleIdentity {
    let Ok(key) = source.response_public_key() else {
        return RoleIdentity::NoKey;
    };
    RoleIdentity::Key(Ed25519PublicKeyValue::for_point(key.to_bytes()))
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
pub(super) fn channel_role_identity(source: &(dyn KeySource + Send + Sync)) -> RoleIdentity {
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
pub(super) mod tests {
    use super::*;
    use crate::key_source::KeyError;
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
    pub(in crate::capability_materialization::key_source) struct RolesFixture {
        pub(in crate::capability_materialization::key_source) response: VerificationKey,
        pub(in crate::capability_materialization::key_source) channel_leaf: Vec<u8>,
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
    pub(in crate::capability_materialization::key_source) fn ed25519_leaf(
    ) -> (Vec<u8>, VerificationKey) {
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
}
