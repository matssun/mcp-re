// SPDX-License-Identifier: Apache-2.0
//! One fact: **a request that carries a credential reaches only the authority its
//! destination was vetted as.**
//!
//! [`super::VettedDestination`] decides whether a destination may be reached at all. That
//! decision is made once, over one URL. What this owns is the step after it: the client
//! that performs the request, and the guarantee that every request it performs lands on
//! that same authority.
//!
//! # Why the authority is not a parameter
//!
//! The census shape this replaces is uniform across the credential paths: check the
//! endpoint, drop the answer, build `ureq::AgentBuilder::new().build()`, and interpolate
//! the endpoint back into a URL string at each call site. Every part of the check is then
//! a statement someone remembered to write — a later call site that formats its own URL
//! reaches whatever it names, and a redirect reaches whatever the *responder* names.
//!
//! Here a caller names a PATH. It cannot name a host: the join is
//! [`super::url::joined_onto`], where that property is stated and measured, and this type
//! offers no other way to address a request. Naming a path is the whole caller-facing
//! surface, so it is a property of the capability rather than of the strings callers
//! happen to pass.
//!
//! The redirect half is the same fact one hop later, and it comes from
//! [`super::VettedDestination::agent`], which disables redirects for every provenance. A
//! `302 Location:` is an authority nothing vetted, chosen by whoever answered.
//!
//! With redirects disabled `ureq` hands the 3xx back as the response, so a caller sees the
//! VETTED responder's own answer — never a body from the host the redirect named. Each
//! credential caller then fails to parse it as the reply it expected and refuses; none of
//! them treats a status alone as success. Nothing was sent to the second authority, which
//! is the fact this owns; what a caller makes of a redirect body is its own parser's.
//!
//! # What this does NOT decide
//!
//! Whether the destination was legitimate. That belongs to whoever built the
//! [`super::VettedDestination`] — for a KMS/STS endpoint, to
//! [`crate::kms_endpoint_policy::KmsEndpoint`], which is the only producer of one for a
//! credential path that carries the root-key trust bootstrap.

use std::time::Duration;

use super::url::joined_onto;
use super::VettedDestination;

/// An HTTP client bound to ONE vetted authority, for requests that carry a credential.
///
/// # Why the representation is private
///
/// `base` and `agent` are established together, from a destination that had already
/// passed its guard, and neither is meaningful without the other: an agent whose base a
/// caller could rewrite is the bare agent this type exists to replace, and a base whose
/// agent a caller could rewrite is a redirect away from a different host. There is no
/// constructor that takes a URL.
pub struct CredentialEgress {
    /// The vetted destination, with any trailing separator removed so that
    /// [`Self::url_for`] adds exactly one.
    base: String,
    /// Built from the destination's provenance — redirects disabled, and for a
    /// certificate-derived destination the resolved-address vetting installed.
    agent: ureq::Agent,
}

impl CredentialEgress {
    /// The egress capability for `destination`.
    ///
    /// `timeout` is handed to [`VettedDestination::agent`]; each request also sets its
    /// own, which is the one that bounds a call.
    pub(crate) fn to(destination: &VettedDestination, timeout: Duration) -> Self {
        CredentialEgress {
            base: destination.url().trim_end_matches('/').to_string(),
            agent: destination.agent(timeout),
        }
    }

    /// A GET against `path` on the vetted authority.
    ///
    /// Compiled where a credential path reads: the Cloud KMS `getPublicKey` call and the
    /// metadata-server token fetch. A build whose only credential egress posts carries no
    /// method nothing calls.
    #[cfg(feature = "gcp_kms_keysource")]
    pub(crate) fn get(&self, path: &str) -> ureq::Request {
        self.agent.get(&self.url_for(path))
    }

    /// A POST against `path` on the vetted authority.
    pub(crate) fn post(&self, path: &str) -> ureq::Request {
        self.agent.post(&self.url_for(path))
    }

    /// `path` on the vetted authority.
    ///
    /// The join is [`super::url::joined_onto`]'s, which is where the property that no path
    /// can move an authority is stated and measured. Nothing is re-decided here.
    fn url_for(&self, path: &str) -> String {
        joined_onto(&self.base, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The capability addresses THROUGH the join, so a hostile path is a path here too.
    ///
    /// The property itself belongs to `url::joined_onto` and is measured there; what this
    /// control establishes is that this type has not acquired a second way to address a
    /// request. If it ever formats its own URL, this fails.
    #[test]
    fn every_request_is_addressed_on_the_vetted_authority() {
        let destination = VettedDestination::operator_configured("https://cloudkms.googleapis.com")
            .expect("an https URL is an admissible operator destination");
        let egress = CredentialEgress::to(&destination, Duration::from_secs(5));
        for path in [
            "//evil.example.com/v1/x",
            "https://evil.example.com/v1/x",
            "v1/keys",
            "",
        ] {
            let url = egress.url_for(path);
            assert!(
                url.starts_with("https://cloudkms.googleapis.com/"),
                "path {path:?} produced {url:?}"
            );
        }
    }
}
