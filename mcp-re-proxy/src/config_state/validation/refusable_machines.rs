// SPDX-License-Identifier: Apache-2.0
//! The machines that can REFUSE, and what they refused.
//!
//! Each answers with the state it recognised, or with `None` and the refusal that explains
//! it — so a `None` here is never an absence, it is a decision already made and already
//! reported. Two of them always name a state and can still refuse a column of it; their
//! refusals travel beside the value.
//!
//! Kept apart from [`super::total_machines`] because the two are different in kind, not
//! just in length: a total machine has nothing to say because its illegal combinations are
//! not representable, and putting the two in one list invites an owner to be moved between
//! them without anyone noticing the claim changed.

use crate::config_state::cross_machine::CrossMachineViolations;
use crate::deployment_request::DeploymentRequest;

use super::machine_violations::MachineViolations;

/// Every machine's own refusals, before the cross-machine pass has run.
///
/// Separate from [`MachineViolations`] because the cross field cannot be filled yet: the
/// relation is asked of the states this pass produces.
pub(super) struct Refusals {
    admission: Vec<String>,
    authorization: Vec<String>,
    channel_binding: Vec<String>,
    continuation_control: Vec<String>,
    crl_revocation: Vec<String>,
    custody: Vec<String>,
    delegated_signing: Vec<String>,
    freshness: Vec<String>,
    replay: Vec<String>,
    trust_document: Vec<String>,
    client_credential_window: Vec<String>,
    server_identity: Vec<String>,
    channel_credential_custody: Vec<String>,
    trust_revocation: Vec<String>,
}

impl Refusals {
    /// Join the cross-machine pass's result, giving the clause list everything it splices.
    pub(super) fn with_cross(self, cross: CrossMachineViolations) -> MachineViolations {
        MachineViolations {
            admission: self.admission,
            authorization: self.authorization,
            channel_binding: self.channel_binding,
            continuation_control: self.continuation_control,
            crl_revocation: self.crl_revocation,
            custody: self.custody,
            delegated_signing: self.delegated_signing,
            freshness: self.freshness,
            replay: self.replay,
            trust_document: self.trust_document,
            client_credential_window: self.client_credential_window,
            server_identity: self.server_identity,
            channel_credential_custody: self.channel_credential_custody,
            trust_revocation: self.trust_revocation,
            cross,
        }
    }
}

/// What the machines that CAN refuse recognised.
///
/// `None` is a refusal already made, never an absence. Two of these — the continuation
/// control and the CRL revocation posture — always name a state and can still refuse a
/// column of it, which is why they are values here and their refusals travel beside them.
pub(super) struct RefusableStates {
    pub(super) admission: Option<crate::config_state::AdmissionState>,
    pub(super) authorization: Option<crate::config_state::AuthorizationState>,
    pub(super) channel_binding: Option<crate::config_state::ChannelBindingState>,
    pub(super) client_credential_window: Option<crate::config_state::ClientCredentialWindow>,
    pub(super) freshness: Option<crate::config_state::FreshnessWindow>,
    pub(super) continuation_control: crate::config_state::ContinuationControlState,
    pub(super) crl_revocation: crate::config_state::CrlRevocationState,
    pub(super) custody: Option<crate::config_state::CustodyState>,
    pub(super) delegated_signing: Option<crate::config_state::DelegatedSigningFacts>,
    pub(super) replay: Option<crate::config_state::ReplayState>,
    pub(super) server_identity: Option<crate::config_state::server_identity::ServerIdentityFacts>,
    pub(super) channel_credential_custody:
        Option<crate::config_state::ChannelCredentialCustodyState>,
    pub(super) trust_document: Option<crate::config_state::TrustDocumentSource>,
    pub(super) trust_revocation: Option<crate::config_state::TrustRevocationState>,
}

/// The machines that can REFUSE: each answers with the state it recognised, or with
/// `None` and the refusal that explains it.
pub(super) fn classify_refusable(config: &DeploymentRequest) -> (RefusableStates, Refusals) {
    use crate::config_state as m;
    let (continuation_control, continuation_violations) =
        m::continuation_control::classify_and_validate(config);
    let (custody, custody_violations) = m::custody::classify_and_validate(config);
    let (delegated_signing, delegated_signing_violations) =
        m::delegated_signing::classify_and_validate(config);
    let (replay, replay_violations) = m::replay::classify_and_validate(config);
    let (channel_credential_custody, channel_custody_violations) =
        m::channel_credential_custody::classify_and_validate(config);
    let (trust_revocation, trust_violations) = m::trust_revocation::classify_and_validate(config);
    let (admission, admission_violations) = m::admission::classify_and_validate(config);
    let (authorization, authorization_violations) = m::authorization::classify_and_validate(config);
    let (channel_binding, binding_violations) = m::transport::classify_and_validate_binding(config);
    let (crl_revocation, crl_violations) = m::transport::classify_and_validate_crl(config);
    let (freshness, freshness_violations) = m::freshness::classify_and_validate(config);
    let (trust_document, trust_document_violations) =
        m::trust_document::classify_and_validate(config);
    let (client_credential_window, credential_window_violations) =
        m::client_credential_window::classify_and_validate(config);
    // This deployment's own actor identity. It takes the RESOLVED issuer kid rather than
    // re-reading the primitives it defaults from, so the keyid on the identity and the kid
    // the credential chains to are one value (CF-10).
    let (server_identity, server_identity_violations) =
        m::server_identity::classify_and_validate(config, delegated_signing.as_ref());
    (
        RefusableStates {
            admission,
            authorization,
            channel_binding,
            client_credential_window,
            freshness,
            continuation_control,
            crl_revocation,
            custody,
            delegated_signing,
            replay,
            server_identity,
            channel_credential_custody,
            trust_document,
            trust_revocation,
        },
        Refusals {
            admission: admission_violations,
            authorization: authorization_violations,
            channel_binding: binding_violations,
            continuation_control: continuation_violations,
            crl_revocation: crl_violations,
            custody: custody_violations,
            delegated_signing: delegated_signing_violations,
            freshness: freshness_violations,
            replay: replay_violations,
            trust_document: trust_document_violations,
            client_credential_window: credential_window_violations,
            server_identity: server_identity_violations,
            channel_credential_custody: channel_custody_violations,
            trust_revocation: trust_violations,
        },
    )
}
