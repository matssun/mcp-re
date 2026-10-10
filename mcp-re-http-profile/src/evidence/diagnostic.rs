// SPDX-License-Identifier: Apache-2.0
//! What an UNBOUND rejection records about the request it refused: a correlation aid,
//! never a binding.

use super::RequestEvidenceDigest;
use crate::digest::content_digest_sha256;

/// The request reference a preflight-unbound rejection carries in its block's
/// `request_evidence` slot. The request never earned a trustworthy hash, so this is not
/// a role handle and cannot be mistaken for one: its algorithm token names what it is
/// (`sha-256-received`, a digest of the received body, or `none`), and no verifier treats
/// an unbound response's slot as a request binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnboundRequestDiagnostic {
    digest: RequestEvidenceDigest,
}

impl UnboundRequestDiagnostic {
    /// A digest of the body bytes as received, so an operator can correlate.
    pub fn received(body: &[u8]) -> Self {
        UnboundRequestDiagnostic {
            digest: RequestEvidenceDigest {
                digest_alg: "sha-256-received".to_owned(),
                digest_value: content_digest_sha256(body),
            },
        }
    }

    /// Nothing was received that could be referenced.
    pub fn absent() -> Self {
        UnboundRequestDiagnostic {
            digest: RequestEvidenceDigest {
                digest_alg: "none".to_owned(),
                digest_value: String::new(),
            },
        }
    }

    /// The wire form the response block carries.
    pub fn to_digest(&self) -> RequestEvidenceDigest {
        self.digest.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Neither form is shaped like a role handle, so neither can pass as one.
    #[test]
    fn a_diagnostic_is_never_a_well_formed_handle() {
        assert!(!UnboundRequestDiagnostic::received(b"{}")
            .to_digest()
            .is_well_formed());
        assert!(!UnboundRequestDiagnostic::absent()
            .to_digest()
            .is_well_formed());
    }

    #[test]
    fn received_digests_the_body_as_received() {
        let d = UnboundRequestDiagnostic::received(b"{\"a\":1}").to_digest();
        assert_eq!(d.digest_alg, "sha-256-received");
        assert_eq!(d.digest_value, content_digest_sha256(b"{\"a\":1}"));
    }
}
