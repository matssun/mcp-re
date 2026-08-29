// SPDX-License-Identifier: Apache-2.0
//! What establishes that a peer credential is still current — ADR-MCPRE-067 §7, §10.
//!
//! The durable question is *credential currency*: whether this deployment holds evidence
//! that a peer's credential has not been withdrawn, and what latency bound that evidence
//! carries. CRL and OCSP are two mechanisms that answer it, and they are two mechanisms
//! rather than two spellings of one — a revocation list is a periodically published set a
//! verifier reads locally, and a responder is an authority asked per credential.
//!
//! ```text
//! credential-currency requirement   PeerRevocationRequest
//!         ↓
//! per-mechanism configuration       RevocationListRequest / OnlineRevocationEvidenceRequest
//!         ↓
//! mechanism payload                 the list paths and cadence / OcspResponderRequest
//!         ↓
//! leaf                              tls::load_client_crls / ocsp.rs (RFC 6960)
//! ```
//!
//! **They compose; they are not alternatives.** Nothing about holding a CRL set makes an
//! online check meaningless, or the reverse, so this is a struct of two mechanism
//! configurations and not a tagged union between them. Forcing a union would encode a
//! mutual exclusion the domain does not have (ADR-MCPRE-067 §7 — a tagged union is for
//! alternatives, and only for alternatives).

mod online_evidence;
mod revocation_list;

pub use online_evidence::{OcspResponderRequest, OnlineRevocationEvidenceRequest};
pub use revocation_list::RevocationListRequest;

/// How this deployment establishes that a peer credential is still current.
///
/// Two mechanism configurations, composed. A deployment may configure both, either or
/// neither; neither is a POSTURE — currency then rests on the credential-lifetime ceiling
/// alone, which is a bound rather than an absence.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeerRevocationRequest {
    /// The offline published-list mechanism.
    pub lists: RevocationListRequest,
    /// The online per-credential responder mechanism.
    pub online: OnlineRevocationEvidenceRequest,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Composition, not exclusion: configuring one mechanism says nothing about the other,
    /// and a request can hold both. A tagged union here would have encoded an exclusion
    /// the domain does not have.
    #[test]
    fn the_two_mechanisms_compose_rather_than_excluding_each_other() {
        let both = PeerRevocationRequest {
            lists: RevocationListRequest {
                paths: vec!["/crl.pem".to_string()],
                reload_secs: Some(60),
            },
            online: OnlineRevocationEvidenceRequest::Required(OcspResponderRequest::default()),
        };
        assert!(both.lists.is_configured());
        assert!(both.online.is_required());
    }

    /// Neither is a posture. Currency then rests on the credential-lifetime ceiling, and
    /// that is what the default says rather than leaving the question unasked.
    #[test]
    fn configuring_neither_mechanism_is_a_posture() {
        let neither = PeerRevocationRequest::default();
        assert!(!neither.lists.is_configured());
        assert!(!neither.online.is_required());
    }
}
