// SPDX-License-Identifier: Apache-2.0
//! The documents one audit run is ASSERTED BY, loaded.
//!
//! One fact: **every input an audit rests on is in hand, before anything is signed.**
//!
//! It is one owner rather than four reads at the composition root because the ORDER
//! matters and the order is not obvious: an unreadable service pin has to fail before a
//! statement is issued, not after. A statement cut for a service whose pin is illegal can
//! never be shown to have been registered with that service, so producing one would be
//! producing an artifact with no possible future — and by then the signing has happened.
//!
//! Holding an `AuditInputs` therefore means the profile is coherent, the trust document
//! parses, the pin is legal and the issuing key loaded. Every one of those is a refusal
//! here, and none of them can be reached from below.

use std::path::Path;

use mcp_re_core::SigningKey;
use mcp_re_http_profile::scitt::ScittServiceTrustPin;

use crate::key_source::signing_key_from_seed_b64url;
use crate::trust_document::TrustDocument;

use super::artifact::AttestedService;
use super::invocation::AuditInvocation;
use super::profile::AuditProfile;

/// Everything an audit is asserted by, checked.
pub(super) struct AuditInputs {
    /// What this auditor asserts about the deployment.
    pub(super) profile: AuditProfile,
    /// The deployment's request-signer trust document.
    pub(super) trust: TrustDocument,
    /// The transparency service this attestation is for.
    pub(super) pin: ScittServiceTrustPin,
    /// The key this auditor issues its Signed Statement under.
    pub(super) issuer: SigningKey,
}

impl AuditInputs {
    /// Load every document `invocation` names, or name the first one that will not do.
    pub(super) fn load(invocation: &AuditInvocation) -> Result<Self, String> {
        let profile = AuditProfile::parse(&read("--audit-profile", &invocation.audit_profile)?)?;
        let trust = TrustDocument::parse(&read("--trust-document", &invocation.trust_document)?)?;
        let pin: ScittServiceTrustPin =
            serde_json::from_slice(&read("--service-trust-pin", &invocation.service_trust_pin)?)
                .map_err(|e| format!("--service-trust-pin: {e}"))?;
        let seed = read("--issuer-key-seed", &invocation.issuer_key_seed)?;
        let seed =
            std::str::from_utf8(&seed).map_err(|_| "--issuer-key-seed: not UTF-8".to_owned())?;
        let issuer = signing_key_from_seed_b64url(seed).map_err(|e| format!("{e:?}"))?;
        Ok(AuditInputs {
            profile,
            trust,
            pin,
            issuer,
        })
    }

    /// The service this attestation names, as the artifact records it.
    ///
    /// Identity only. The pin's KEY is not copied into the artifact: what verifies a
    /// receipt is the pin an operator loads, and an artifact carrying its own copy of a
    /// verification key would invite a reader to check a receipt against a key the
    /// artifact came with.
    pub(super) fn attested_service(&self) -> AttestedService {
        AttestedService {
            service_identifier: self.pin.service_identifier().to_owned(),
            kid: self.pin.kid().to_owned(),
        }
    }
}

/// Read a file, naming what was being read when it failed.
fn read(what: &str, path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{what} {}: {e}", path.display()))
}
