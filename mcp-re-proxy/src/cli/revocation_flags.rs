// SPDX-License-Identifier: Apache-2.0
//! The revocation flags, assembled into the typed request — ADR-MCPRE-067 §16.
//!
//! An operator names the online mode and the responder override with two flat flags. The
//! request has one value: the responder lives inside the requiring selection, because an
//! authority nothing would ask is not a configuration.
//!
//! **One refusal lives here.** A responder beside `--client-ocsp off` was a
//! configuration-boundary clause; the pair cannot be built any more, so the parser — the
//! one place that still sees both — answers it, with the sentence the boundary used to.

use crate::deployment_request::{OcspResponderRequest, OnlineRevocationEvidenceRequest};

/// Whether online revocation evidence is required, and the responder that would answer.
pub(super) fn online_evidence(
    require: bool,
    responder_url: Option<String>,
) -> Result<OnlineRevocationEvidenceRequest, String> {
    if !require {
        if responder_url.is_some() {
            return Err(
                "--ocsp-responder-url has no effect without --client-ocsp require: nothing \
                 consults a responder in this mode, so the deployment would carry a \
                 revocation authority it never asks"
                    .to_string(),
            );
        }
        return Ok(OnlineRevocationEvidenceRequest::NotRequired);
    }
    Ok(OnlineRevocationEvidenceRequest::Required(
        OcspResponderRequest { url: responder_url },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A responder with nothing to ask it is refused where it is still statable.
    #[test]
    fn a_responder_without_the_mode_that_reads_it_is_refused() {
        let err = online_evidence(false, Some("http://ocsp.example".to_string()))
            .expect_err("an authority nothing asks");
        assert!(err.contains("--ocsp-responder-url has no effect"), "{err}");
    }

    /// The negative controls: the mode alone, the mode with a responder, and neither are
    /// all coherent command lines. Without these the assertion above would pass just as
    /// well if every combination were refused.
    #[test]
    fn each_coherent_combination_is_accepted() {
        assert_eq!(
            online_evidence(false, None).expect("neither"),
            OnlineRevocationEvidenceRequest::NotRequired
        );
        let aia = online_evidence(true, None).expect("the mode alone");
        assert!(aia.is_required() && aia.responder_override().is_none());
        let overridden = online_evidence(true, Some("http://ocsp.example".to_string()))
            .expect("the mode and a responder");
        assert_eq!(overridden.responder_override(), Some("http://ocsp.example"));
    }
}
