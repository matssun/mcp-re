// SPDX-License-Identifier: Apache-2.0
//! The credential a communication-establishment mechanism ACCEPTED for a relationship, and
//! the path on which it did — ADR-MCPRE-064, Slice 1.
//!
//! # The proposition
//!
//! Possession of [`MechanismVerifiedCredentialEvidence`] means:
//!
//! > The establishment mechanism accepted this credential for this established
//! > relationship, on this establishment path.
//!
//! Slice 4 established that a credential came from a relationship's mechanism report. It
//! deliberately did not say the mechanism had ACCEPTED it under the configured
//! client-certificate verifier — a distinction that matters because the two are different
//! propositions even though, in every supported production build, no relationship exists
//! without acceptance.
//!
//! # Why the establishment path is carried here and was not carried in Slice 4
//!
//! Slice 4 measured that a full handshake and its resumption associate byte-identical
//! credential evidence, so the association proposition is the same on both paths and the
//! product correctly omitted which one occurred — noting that the distinction "enters the
//! representation when a consumer does". This is that consumer, because for ACCEPTANCE the
//! two paths are not the same proposition:
//!
//! ```text
//! Full     the configured verifier ran in THIS establishment: a path to a configured
//!          anchor, per-certificate validity windows, full-chain revocation with unknown
//!          status denied, CRL expiration enforced
//! Resumed  none of that re-ran. The mechanism restored the stored peer chain verbatim,
//!          and what stands behind the acceptance is the earlier full handshake, admitted
//!          now only because the ADR-MCPRE-055 anchor epoch is unchanged
//! ```
//!
//! Flattening those into one word would be the sentence ADR-MCPRE-055 exists to forbid.
//!
//! # What this authority does NOT carry, and why
//!
//! **Not the anchor epoch.** Characterization measured that the epoch does not reach the
//! serving path: it reaches the session store, which enforces it, and the composition root.
//! The only epoch an adapter here could read is the listener's CURRENT one, while the
//! acceptance being described happened at an earlier handshake — pairing those is the
//! ADR-MCPRE-063 L-5 failure shape exactly, two true facts stating a relation their
//! provenance does not establish. What makes the pairing sound is the store's gate, and
//! that proof lives in the store. The epoch enters this representation when a consumer
//! needs it and can obtain it honestly.
//!
//! **Not trust policy, currency, identity or admission.** Whether the credential is still
//! within its validity window, still unrevoked, and within the configured lifetime ceiling
//! is a different authority answering *is it still good now* — recovered per request, and
//! only where a ceiling or CRLs are configured. Which identity the credential denotes is
//! ADR-MCPRE-063 Slice 5. Neither is implied by acceptance.
//!
//! **Not the word `authenticated`.** That needs a proposition about the peer, composed
//! from this one and an identity fact whose provenance ties it to the same credential.
//! ADR-MCPRE-064 §5 rule 1: a name is a claim.

pub(crate) mod rustls_adapter;

use super::channel_associated_credential::ChannelAssociatedCertificateCredentialEvidence;

/// The credential the establishment mechanism accepted for one relationship, with the path
/// on which the acceptance was reached.
///
/// Sealed: the representation is private to this module and the constructor is private to
/// it, so the only inhabitants are the ones the mechanism adapter — a CHILD of this module,
/// and therefore the one descendant that reaches the constructor — produced from a single
/// connection. Both components come from that one connection in one operation, so no caller
/// can pair a credential with an establishment path it did not have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MechanismVerifiedCredentialEvidence {
    /// The credential this acceptance is about. Slice 4's product, obtained from the same
    /// connection in the same operation rather than accepted from a caller.
    credential: ChannelAssociatedCertificateCredentialEvidence,
    /// How this relationship reached acceptance.
    path: EstablishmentPath,
}

impl MechanismVerifiedCredentialEvidence {
    /// Record that the mechanism accepted `credential` on `path`.
    ///
    /// PRIVATE to this authority: reachable by this module and its descendants — the
    /// mechanism adapter, which is the one PRODUCTION call site, and this module's own
    /// tests. Not `pub(super)`, which would publish construction to every module of
    /// `communication_assurance` and let a neighbour pair any credential with any path.
    fn accept(
        credential: ChannelAssociatedCertificateCredentialEvidence,
        path: EstablishmentPath,
    ) -> Self {
        MechanismVerifiedCredentialEvidence { credential, path }
    }

    /// The credential the mechanism accepted.
    pub fn credential(&self) -> &ChannelAssociatedCertificateCredentialEvidence {
        &self.credential
    }

    /// The path on which acceptance was reached.
    ///
    /// A consumer that needs *verified in this establishment* must branch on this. One that
    /// only needs *accepted at some point under an unchanged anchor set* need not — and the
    /// two are different enough that the product refuses to choose for either.
    pub fn establishment_path(&self) -> EstablishmentPath {
        self.path
    }
}

/// The credential chain of an OPTIONAL association, leaf first — an absent credential is
/// the empty chain.
///
/// A COMPATIBILITY projection with exactly ONE consumer left: the online-OCSP guard, which
/// ADR-MCPRE-064 Slice 3 deliberately did not migrate. Currency and identity both moved to
/// semantic products, so this and its Slice-4 sibling are the whole remaining raw-chain
/// surface of the serving path, and they go when OCSP does.
#[cfg_attr(not(feature = "online_ocsp"), allow(dead_code))]
pub(crate) fn accepted_chain_der(
    accepted: Option<&MechanismVerifiedCredentialEvidence>,
) -> Vec<&[u8]> {
    super::channel_associated_credential::associated_chain_der(
        accepted.map(MechanismVerifiedCredentialEvidence::credential),
    )
}

/// How a relationship reached the acceptance this evidence records.
///
/// Two variants because the mechanism reports two, and because they carry materially
/// different verification facts. Deliberately NOT a boolean named `fresh`: the question a
/// consumer asks is which work the mechanism did, and a boolean would invite the reading
/// that resumed acceptance is a weaker form of the same thing rather than a different fact
/// resting on a different gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstablishmentPath {
    /// The configured client-certificate verifier ran during this establishment.
    FullHandshake,
    /// The mechanism restored a stored session. The configured verifier did NOT run again;
    /// the acceptance stands on the earlier full handshake, and on the anchor epoch being
    /// unchanged since it — a gate owned and measured by `tls_listener_state`, not here.
    ResumedSession,
}

/// Why a mechanism's report could not be turned into verified-credential evidence.
///
/// Like Slice 4's algebra, these are **mechanism-boundary inconsistencies, not legal domain
/// states**. Every supported production establishment path reaches this authority only
/// after the mechanism has both established and accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MechanismVerificationRefusal {
    /// No credential was associated with the relationship, so there is nothing an
    /// acceptance could be about. Carries Slice 4's refusal unchanged rather than
    /// re-deciding it: association is that authority's question.
    NoAssociatedCredential(
        super::channel_associated_credential::ChannelCredentialAssociationRefusal,
    ),
    /// The mechanism reports no establishment path for a relationship it also reports as
    /// established.
    ///
    /// Unreachable through any supported production path: `handshake_kind` is `None` only
    /// before a handshake completes, and the association above already refuses that state.
    /// Refused rather than defaulted, because guessing `FullHandshake` here would invent
    /// the strongest reading of a report the mechanism declined to make.
    EstablishmentPathUnreported,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_establishment_paths_are_distinguishable() {
        // The whole reason this product carries a path: a consumer that needs "the verifier
        // ran in this establishment" must be able to tell, and a product whose two paths
        // compared equal would silently answer yes for both.
        assert_ne!(
            EstablishmentPath::FullHandshake,
            EstablishmentPath::ResumedSession
        );
    }

    #[test]
    fn an_unreported_path_is_not_read_as_a_full_handshake() {
        assert_ne!(
            MechanismVerificationRefusal::EstablishmentPathUnreported,
            MechanismVerificationRefusal::NoAssociatedCredential(
                super::super::channel_associated_credential::ChannelCredentialAssociationRefusal::EstablishmentIncomplete
            ),
            "a mechanism that reported no path and one that reported no credential are \
             different inconsistencies"
        );
    }
}
