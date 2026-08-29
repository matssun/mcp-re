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

use crate::deployment_request::{
    OcspResponderRequest, OnlineRevocationEvidenceRequest, PeerRevocationRequest,
    RevocationListRequest,
};

/// The revocation inputs, as they accumulate across the argument list.
#[derive(Default)]
pub(super) struct RevocationFlags {
    list_paths: Vec<String>,
    reload_secs: Option<u64>,
    require_online: bool,
    responder_url: Option<String>,
}

impl RevocationFlags {
    /// Whether this value-taking flag belongs to the family.
    pub(super) fn owns(flag: &str) -> bool {
        matches!(
            flag,
            "--client-crl" | "--client-crl-reload-secs" | "--client-ocsp" | "--ocsp-responder-url"
        )
    }

    /// Read one flag of the family. [`Self::owns`] decided it is one.
    pub(super) fn take(&mut self, flag: &str, value: &str) -> Result<(), String> {
        match flag {
            // #3839: repeatable and/or comma-separated list paths. Splitting is the CLI's
            // encoding; whether a resulting path names a file is the boundary's, so a
            // trailing comma reaches it as the empty path it produced.
            "--client-crl" => self.list_paths.extend(value.split(',').map(str::to_string)),
            // ADR-MCPRE-051 §6 (MCPRE-116): in-process reload cadence, in whole seconds.
            // Whether zero is a cadence is the boundary's question.
            "--client-crl-reload-secs" => {
                self.reload_secs = Some(value.parse().map_err(|_| {
                    "invalid --client-crl-reload-secs (expected a positive integer)".to_string()
                })?)
            }
            "--client-ocsp" => {
                self.require_online = match value {
                    "off" => false,
                    "require" => true,
                    other => return Err(format!("unknown --client-ocsp '{other}' (off|require)")),
                }
            }
            _ => self.responder_url = Some(value.to_string()),
        }
        Ok(())
    }

    /// How this deployment establishes that a peer credential is still current.
    ///
    /// The two mechanisms COMPOSE, so this is a struct of both rather than a choice
    /// between them; only the online half has a selection to assemble.
    pub(super) fn finish(self) -> Result<PeerRevocationRequest, String> {
        Ok(PeerRevocationRequest {
            lists: RevocationListRequest {
                paths: self.list_paths,
                reload_secs: self.reload_secs,
            },
            online: online_evidence(self.require_online, self.responder_url)?,
        })
    }
}

/// Whether online revocation evidence is required, and the responder that would answer.
fn online_evidence(
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
