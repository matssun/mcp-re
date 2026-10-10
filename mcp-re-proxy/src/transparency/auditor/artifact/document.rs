// SPDX-License-Identifier: Apache-2.0
//! The attestation artifact as READ BACK from a file.
//!
//! One fact: **what a file claims**, never what was verified. A verifying parse cannot reach
//! the strength of [`super::AttestationArtifact`]: the correspondence verdict and the reason
//! an audit was incomplete are not in the signed commitment, and the reader holds no pin.
//! Every `claimed_*` value is therefore the file author's assertion — not a derivation and
//! not a verified receipt. A reader that acts on a receipt must re-verify it against the
//! statement and its own pin.

use serde::Deserialize;

use super::AttestedService;
use super::ChainVerdict;
use super::CorrespondenceVerdict;
use super::ATTESTATION_SCHEMA;

/// A receipt and the contract that produced it, exactly as the file asserts them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedRegistration {
    receipt: Vec<u8>,
    protocol: String,
}

impl ClaimedRegistration {
    /// The receipt bytes the file carries. Not verified by reading them back.
    pub fn receipt(&self) -> &[u8] {
        &self.receipt
    }

    /// The contract the file says established the registration.
    pub fn protocol(&self) -> &str {
        &self.protocol
    }
}

/// An attestation artifact read back from a file; every `claimed_*` projection is the file
/// author's assertion, to be re-verified by a reader that acts on it.
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "DocumentWire")]
pub struct AttestationDocument {
    issuer_kid: String,
    issued_at: i64,
    signed_statement: Vec<u8>,
    hops: Vec<String>,
    chain: ChainVerdict,
    correspondence: CorrespondenceVerdict,
    transparency_service: AttestedService,
    registration: Option<ClaimedRegistration>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentWire {
    schema: String,
    issuer_kid: String,
    issued_at: i64,
    signed_statement: String,
    hops: Vec<String>,
    chain: ChainVerdict,
    correspondence: CorrespondenceVerdict,
    transparency_service: AttestedService,
    #[serde(default)]
    receipt: Option<String>,
    #[serde(default)]
    registration_protocol: Option<String>,
}

impl TryFrom<DocumentWire> for AttestationDocument {
    type Error = String;

    fn try_from(wire: DocumentWire) -> Result<Self, String> {
        if wire.schema != ATTESTATION_SCHEMA {
            return Err(format!(
                "schema is {:?}, expected {ATTESTATION_SCHEMA:?}",
                wire.schema,
            ));
        }
        let signed_statement = mcp_re_core::b64url_decode(&wire.signed_statement)
            .map_err(|_| "signed_statement is not base64url".to_owned())?;
        let registration = match (wire.receipt, wire.registration_protocol) {
            (Some(receipt), Some(protocol)) => Some(ClaimedRegistration {
                receipt: mcp_re_core::b64url_decode(&receipt)
                    .map_err(|_| "receipt is not base64url".to_owned())?,
                protocol,
            }),
            (None, None) => None,
            (Some(_), None) => {
                return Err("receipt is present without registration_protocol".to_owned())
            }
            (None, Some(_)) => {
                return Err("registration_protocol is present without receipt".to_owned())
            }
        };
        Ok(Self {
            issuer_kid: wire.issuer_kid,
            issued_at: wire.issued_at,
            signed_statement,
            hops: wire.hops,
            chain: wire.chain,
            correspondence: wire.correspondence,
            transparency_service: wire.transparency_service,
            registration,
        })
    }
}

impl AttestationDocument {
    /// Read a document back, refusing anything this reader cannot use.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| format!("attestation artifact: {e}"))
    }

    /// The `kid` the file attributes the Signed Statement to.
    pub fn issuer_kid(&self) -> &str {
        &self.issuer_kid
    }

    /// The instant the file says the statement was issued at.
    pub fn issued_at(&self) -> i64 {
        self.issued_at
    }

    /// The hops the file says were reconstructed.
    pub fn hops(&self) -> &[String] {
        &self.hops
    }

    /// The EXACT Signed Statement bytes the file carries.
    pub fn signed_statement(&self) -> &[u8] {
        &self.signed_statement
    }

    /// The service the file says this attestation is for.
    pub fn transparency_service(&self) -> &AttestedService {
        &self.transparency_service
    }

    /// Whether the file claims the record is whole.
    pub fn claimed_chain(&self) -> &ChainVerdict {
        &self.chain
    }

    /// Which binding the file claims the issuer's self-check established.
    pub fn claimed_correspondence(&self) -> CorrespondenceVerdict {
        self.correspondence
    }

    /// The registration the file claims, if any.
    pub fn claimed_registration(&self) -> Option<&ClaimedRegistration> {
        self.registration.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(extra: &str) -> Vec<u8> {
        format!(
            r#"{{"schema":"mcp-re-attestation/v1","issuer_kid":"auditor-1",
            "issued_at":1700000100,"signed_statement":"eA","hops":[],
            "chain":{{"label":"complete"}},"correspondence":"bound-to-verified-call",
            "transparency_service":{{"service_identifier":"example-ts","kid":"ts-1"}}{extra}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn a_receipt_without_its_protocol_is_refused() {
        let bytes = document(r#","receipt":"eA""#);
        assert!(AttestationDocument::parse(&bytes).is_err());
    }

    #[test]
    fn a_protocol_without_its_receipt_is_refused() {
        let bytes = document(r#","registration_protocol":"canned""#);
        assert!(AttestationDocument::parse(&bytes).is_err());
    }

    #[test]
    fn a_receipt_and_its_protocol_read_back_together() {
        let bytes = document(r#","receipt":"eA","registration_protocol":"canned""#);
        let read = AttestationDocument::parse(&bytes).expect("parses");
        let claimed = read.claimed_registration().expect("registration");
        assert_eq!(claimed.receipt(), b"x");
        assert_eq!(claimed.protocol(), "canned");
    }
}
