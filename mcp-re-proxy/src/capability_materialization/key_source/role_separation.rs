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

use super::role_identity::{channel_role_identity, response_role_identity, RoleIdentity};
use crate::key_source::{KeyError, KeySource};

/// A deployment's materialized signing capability, known not to have collapsed its two
/// roles.
///
/// The representation is private and [`Self::establish`] is the only constructor, so holding
/// one is the proof that the comparison ran and did not find one key serving both roles.
///
/// Read that bound exactly. It is NOT *the two keys are different*: where a role produced no
/// key there was nothing to compare, and [`RoleSeparation::NotCompared`] is that outcome
/// rather than a quiet pass. What possession excludes is the collapse — see
/// [`RoleSeparation`] for why the third value is not the negation of either other.
pub struct MaterializedSigningRoles {
    source: Box<dyn KeySource + Send + Sync>,
}

/// What the comparison of the two roles established.
///
/// Three-valued, because there are three outcomes and the third is not the negation of
/// either other one: a role that produced no key was not compared, and answering that as
/// *the roles are separate* would be this boundary claiming a fact it never obtained. The
/// repository already holds this shape twice, with the argument written out —
/// `AuditDrain::OutcomeUnknown` and `RetentionError::Unresolved`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoleSeparation {
    /// Both roles produced a key, and the keys differ.
    Distinct,
    /// Both roles produced a key, and it is one key. [`MaterializedSigningRoles::establish`]
    /// refuses on this, so it reaches no serving path.
    Collapsed,
    /// At least one role produced no key this comparison can use. No collapse is
    /// representable, and none was ruled out either.
    NotCompared,
}

impl MaterializedSigningRoles {
    /// Establish that the materialized roles are distinct, or refuse before serving.
    ///
    /// The only producer. It asks each role for its own public key — the response signer
    /// directly, the channel credential through the leaf of the chain this deployment
    /// serves — and refuses when they are the same key.
    pub(super) fn establish(source: Box<dyn KeySource + Send + Sync>) -> Result<Self, KeyError> {
        match compare_roles(source.as_ref()) {
            // Compared, and separate. The one outcome that establishes the proposition.
            RoleSeparation::Distinct => Ok(MaterializedSigningRoles { source }),
            // Not compared. Materializing is right and the reason is on
            // [`channel_role_identity`]: whether a backend answered belongs to the owner of
            // that material, which refuses a moment later and names the real fault. Written
            // as its own arm so that decision is one a reader can see being taken, rather
            // than a `_` that also catches whatever outcome is added next.
            RoleSeparation::NotCompared => Ok(MaterializedSigningRoles { source }),
            RoleSeparation::Collapsed => Err(KeyError::Malformed(
                "the response-signing key and the channel-signing key are the same key. The \
                 two roles are separately attributable only while they are separate keys: a \
                 party able to obtain a handshake signature would otherwise have obtained a \
                 response attribution. Configure a distinct key for one of them."
                    .to_string(),
            )),
        }
    }

    /// The key source, for the composition root that materializes the serving path.
    ///
    /// Consuming, so the witness is not left behind to be presented for a second source.
    pub fn into_key_source(self) -> Box<dyn KeySource + Send + Sync> {
        self.source
    }
}

/// What comparing the two roles established.
///
/// A relation rather than a branch inside the constructor, so the constructor states the
/// decision and this states the comparison. It answers with all three outcomes rather than
/// with *collapsed or not*: a boolean here would have to spell "at least one role produced
/// no key" as `false`, which is the same token the compared-and-separate case uses, and the
/// caller could then no longer tell them apart even if it wanted to.
fn compare_roles(source: &(dyn KeySource + Send + Sync)) -> RoleSeparation {
    match (
        response_role_identity(source),
        channel_role_identity(source),
    ) {
        (RoleIdentity::Key(response), RoleIdentity::Key(channel)) => {
            if response.raw_point() == channel.raw_point() {
                RoleSeparation::Collapsed
            } else {
                RoleSeparation::Distinct
            }
        }
        _ => RoleSeparation::NotCompared,
    }
}

#[cfg(test)]
mod tests {
    use super::super::role_identity::tests::ed25519_leaf;
    use super::super::role_identity::tests::RolesFixture;
    use super::*;
    use mcp_re_core::VerificationKey;

    /// The three outcomes are three, and the third is not either other one.
    ///
    /// THE control for this module's shape. `establish` answers `Ok` for both
    /// [`RoleSeparation::Distinct`] and [`RoleSeparation::NotCompared`], so every control
    /// that asserts `is_ok()` passes under an implementation that folds them together — and
    /// a folded pair is a boundary reporting *the roles are separate* about an execution
    /// where nothing was compared. This asserts the relation itself, where the difference
    /// is representable.
    #[test]
    fn a_role_that_produced_no_key_is_not_reported_as_a_separated_one() {
        let (leaf, key) = ed25519_leaf();
        let (other_leaf, _) = ed25519_leaf();
        assert_eq!(
            compare_roles(&RolesFixture {
                response: key.clone(),
                channel_leaf: other_leaf,
            }),
            RoleSeparation::Distinct
        );
        assert_eq!(
            compare_roles(&RolesFixture {
                response: key,
                channel_leaf: leaf,
            }),
            RoleSeparation::Collapsed
        );
        // A channel credential of another profile produced no comparable key. Not a
        // collapse, and — the half a bool cannot say — not a separation either.
        assert_eq!(
            compare_roles(&RolesFixture {
                response: ed25519_leaf().1,
                channel_leaf: vec![0x30, 0x03, 0x02, 0x01, 0x00],
            }),
            RoleSeparation::NotCompared
        );
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
