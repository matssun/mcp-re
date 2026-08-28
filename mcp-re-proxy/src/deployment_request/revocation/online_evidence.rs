// SPDX-License-Identifier: Apache-2.0
//! The online per-credential revocation-evidence mechanism (OCSP today).

/// Whether this deployment requires online revocation evidence for a peer credential.
///
/// The SEMANTIC selection, named for what it asks rather than for the protocol that
/// answers it: a deployment requires per-credential evidence from an authority, or it does
/// not. The protocol is the payload's, one layer down (ADR-MCPRE-067 §6).
///
/// The responder override travels INSIDE `Required`. It used to be a sibling field, and a
/// responder configured beside "not required" named an authority nothing would ever ask —
/// a boundary clause said so, and now cannot be stated at all (ADR-MCPRE-067 §7).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum OnlineRevocationEvidenceRequest {
    /// No online check. Currency, if any, comes from the published lists and the
    /// credential-lifetime ceiling.
    #[default]
    NotRequired,
    /// Require online evidence at connection time, failing closed on anything but a
    /// verified `Good`.
    ///
    /// This selection is REFUSED by the configuration boundary today, and deliberately:
    /// the production data plane performs no responder round trip, so accepting it would
    /// announce enforcement that does not happen. The variant exists because the request
    /// must be able to state what is being refused.
    Required(OcspResponderRequest),
}

impl OnlineRevocationEvidenceRequest {
    /// Whether online evidence is required.
    pub fn is_required(&self) -> bool {
        matches!(self, OnlineRevocationEvidenceRequest::Required(_))
    }

    /// The responder override, where the selection carries one.
    pub fn responder_override(&self) -> Option<&str> {
        match self {
            OnlineRevocationEvidenceRequest::Required(responder) => responder.url.as_deref(),
            OnlineRevocationEvidenceRequest::NotRequired => None,
        }
    }
}

/// The OCSP mechanism payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OcspResponderRequest {
    /// Overrides the responder named by the credential's AIA extension. `None` uses AIA.
    pub url: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The responder cannot exist beside "not required": naming an authority is something
    /// only the requiring selection can do.
    #[test]
    fn a_responder_cannot_be_named_where_nothing_would_ask_it() {
        assert_eq!(
            OnlineRevocationEvidenceRequest::default().responder_override(),
            None
        );
        let required = OnlineRevocationEvidenceRequest::Required(OcspResponderRequest {
            url: Some("http://ocsp.example".to_string()),
        });
        assert_eq!(required.responder_override(), Some("http://ocsp.example"));
        assert!(required.is_required());
    }

    /// Requiring evidence without overriding the responder is the AIA path, and it is a
    /// complete selection rather than a half-configured one.
    #[test]
    fn requiring_evidence_without_an_override_is_a_complete_selection() {
        let aia = OnlineRevocationEvidenceRequest::Required(OcspResponderRequest::default());
        assert!(aia.is_required());
        assert_eq!(aia.responder_override(), None);
    }
}
