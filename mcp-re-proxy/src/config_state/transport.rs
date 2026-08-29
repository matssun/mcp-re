// SPDX-License-Identifier: Apache-2.0
//! The `ChannelBinding` and `CrlRevocation` machines — `work/CONFIG-STATE-ATLAS.md`
//! §C.5 and §C.6.
//!
//! Two machines in one file because they are two small closed models over the same
//! domain, and separating them into two files would say they are further apart than they
//! are. Neither has parameters beyond the ones named below.
//!
//! ## ChannelBinding — how a request is bound to the channel identity
//!
//! | State | Required | Forbidden | Guards |
//! |---|---|---|---|
//! | `Exact + UriSan` | — | every ingress parameter | — |
//! | `Exact + DnsSan` | — | every ingress parameter | — |
//!
//! `binding` and `identity_source` are **two selectors of one machine**, and the machine is
//! named for what it owns rather than for either of them. `binding` contributes one
//! reachable value today, so the live distinction is carried by `identity_source` — the
//! clearest instance of the atlas's rule that a selector is syntax and a machine is a
//! semantic ownership unit.
//!
//! ## CrlRevocation — offline client-certificate revocation
//!
//! | State | Required | Forbidden | Guards |
//! |---|---|---|---|
//! | `None` | — | a reload cadence | — |
//! | `Static` | at least one CRL path | — | — |
//! | `Reloading` | at least one CRL path, a cadence | — | cadence `> 0` |
//!
//! A zero cadence is not a disabled reloader but an unbounded one: the worker's sleep
//! returns immediately, so it re-reads every CRL, rebuilds the rustls verifier and swaps
//! the serving snapshot in a tight loop, burning a core with no diagnostic.

use std::time::Duration;

use crate::deployment_request::{
    AttestedIngressRequest, DeploymentRequest, PeerIdentityEvidenceRequest,
};
use crate::transport::IdentityPolicy;

/// How a verified request signer is bound to the authenticated channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelBindingState {
    /// Exact match against a URI SAN in the client certificate.
    ExactUriSan,
    /// Exact match against a DNS SAN.
    ExactDnsSan,
}

/// Which client-CRL posture a configuration requests.
///
/// The representation is private to this module and [`classify_and_validate`] is the only
/// producer. A CRL-bearing state carries the files that put it in that state, and the
/// reloading state carries the cadence that distinguishes it from the static one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlRevocationState {
    /// The CRL files. Empty is exactly what "no CRLs" means, so the posture and the set
    /// cannot disagree.
    paths: Vec<String>,
    /// Seconds between re-reads, where the operator asked for them. Layer A holds it above
    /// zero and refuses it beside an empty set (CF-04).
    cadence_secs: Option<u64>,
}

impl CrlRevocationState {
    /// The files to read, empty where the posture reads none.
    ///
    /// For materialization, which loads the same bytes under both CRL-bearing postures.
    pub fn paths(&self) -> &[String] {
        &self.paths
    }

    /// Seconds between re-reads, or `None` when the CRLs are read once at startup.
    pub fn reload_cadence_secs(&self) -> Option<u64> {
        self.cadence_secs
    }

    /// Whether any CRL is consulted at all.
    ///
    /// Revocation rests on the client-certificate lifetime ceiling alone when it is not —
    /// a posture rather than an absence, see [`crate::tls_plane::fleet_crl_bound`].
    pub fn is_enforced(&self) -> bool {
        !self.paths.is_empty()
    }

    /// What the TLS plane must establish for client revocation, as this owner states it.
    ///
    /// The projection replaces a match on the representation performed in planning.
    pub fn client_revocation_plan(&self) -> ClientRevocationPlan {
        ClientRevocationPlan {
            paths: self.paths.clone(),
            cadence_secs: self.cadence_secs,
        }
    }
}

/// What the TLS plane establishes for client revocation.
///
/// Produced only by [`CrlRevocationState::client_revocation_plan`]. The files and the
/// cadence are private and set together, so no consumer can plan a re-read cadence over a
/// set of files the deployment did not configure — the combination CF-04 refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRevocationPlan {
    paths: Vec<String>,
    cadence_secs: Option<u64>,
}

impl ClientRevocationPlan {
    /// The files to read, empty where the posture reads none.
    pub fn paths(&self) -> &[String] {
        &self.paths
    }

    /// Seconds between re-reads, or `None` when the CRLs are read once at startup.
    ///
    /// `Some` is the reloading posture: a revocation published after startup takes effect
    /// within the cadence, on established connections as well as at the handshake. `None`
    /// with files is the static posture, bounded by the CRL's own `nextUpdate` or a
    /// restart. `None` with no files is no CRL at all.
    pub fn reload_cadence_secs(&self) -> Option<u64> {
        self.cadence_secs
    }

    /// Whether any CRL is consulted at all.
    pub fn is_enforced(&self) -> bool {
        !self.paths.is_empty()
    }
}

/// Recognise the channel-binding state, or say why the request names none.
///
/// Unlike most machines this one can fail to classify: `binding` has three variants no
/// deployment can be in, and `identity_source` has a deprecated one. They are input forms,
/// not states, so they produce no member of the model.
fn classify_binding(config: &DeploymentRequest) -> Result<ChannelBindingState, Vec<String>> {
    let form = &config.peer_identity;
    let mut refusals = binding_kind_refusals(form);
    // The identity FIELD is asked of the form that has one. No other form reads a
    // certificate, so under those there is no field to be deprecated — where the old shape
    // had a sibling `identity_source` that every form carried and only one consulted.
    let identity = match form.credential_identity_field() {
        Some(IdentityPolicy::UriSan) => Some(ChannelBindingState::ExactUriSan),
        Some(IdentityPolicy::DnsSan) => Some(ChannelBindingState::ExactDnsSan),
        Some(IdentityPolicy::CnLegacy) => {
            refusals.push(
                "--transport-identity-source cn_legacy is a deprecated, insecure identity \
                 binding; use uri_san or dns_san"
                    .to_string(),
            );
            None
        }
        None => None,
    };
    // The state is the PAIR, so a form that is not the one deployable form cannot reach a
    // state named `Exact*` however the refusal list came out.
    match (identity, refusals.is_empty()) {
        (Some(state), true) => Ok(state),
        _ => Err(refusals),
    }
}

/// Every refusal the peer-identity FORM states about itself.
///
/// Exhaustive over [`PeerIdentityEvidenceRequest`], because the classifier's answer for a
/// form is what decides whether the deployment is in a channel-binding state at all: the
/// channel-credential form is the one the serving path installs a transport binding for, so
/// a form reaching a state without an arm here would name a posture the deployment is not
/// in. A form added to the union has no answer until one is written here.
fn binding_kind_refusals(form: &PeerIdentityEvidenceRequest) -> Vec<String> {
    let mut refusals = Vec::new();
    if let Some(refusal) = undeployable_transport_binding_refusal(form) {
        refusals.push(refusal);
    }
    match form {
        PeerIdentityEvidenceRequest::ChannelCredential(_) => {}
        // Refused by the one decision about whether a mode can be deployed, above.
        PeerIdentityEvidenceRequest::AttestedIngress(_) => {}
        PeerIdentityEvidenceRequest::Unbound => refusals.push(
            "--transport-binding none ignores the mTLS channel identity, decoupling the \
             verified request signer from the authenticated channel; production must bind \
             them (--transport-binding exact)"
                .to_string(),
        ),
        PeerIdentityEvidenceRequest::IngressAssertion(_) => refusals.push(
            "--transport-binding lb-assertion places the load balancer in the trusted \
             computing base (the LB terminates the client mTLS and signs a request-bound \
             assertion); this is request-bound ingress assertion, NOT end-to-end \
             client↔node mTLS; production must bind end-to-end (--transport-binding exact \
             with locally-terminated client mTLS)"
                .to_string(),
        ),
    }
    refusals
}

/// Classify the channel-binding state and check its columns.
///
/// The ingress parameters belong to states the model does not contain, and their coherence
/// is checked by `ingress_assertion_violation` at its own position in the clause list.
pub fn classify_and_validate_binding(
    config: &DeploymentRequest,
) -> (Option<ChannelBindingState>, Vec<String>) {
    match classify_binding(config) {
        Ok(state) => (Some(state), Vec::new()),
        Err(refusals) => (None, refusals),
    }
}

/// Recognise the CRL-revocation state. Total: the two fields name one.
fn classify_crl(config: &DeploymentRequest) -> CrlRevocationState {
    let lists = &config.peer_revocation.lists;
    CrlRevocationState {
        paths: lists.paths.clone(),
        cadence_secs: lists.is_configured().then_some(lists.reload_secs).flatten(),
    }
}

/// Classify the CRL-revocation state and check its columns.
pub fn classify_and_validate_crl(config: &DeploymentRequest) -> (CrlRevocationState, Vec<String>) {
    let state = classify_crl(config);
    let mut violations = Vec::new();
    // Structure of the list itself, before anything that reads a member. Classification
    // asks whether the list is empty, which a list holding `""` is not — so a deployment
    // could reach `Static`/`Reloading`, announce that offline revocation is enforced, and
    // hold one path that names no file. Placed ahead of the cadence clauses because those
    // are about a different field: a member that names nothing is a defect in the control
    // the cadence would be re-reading.
    if state.paths().iter().any(String::is_empty) {
        violations.push(
            "--client-crl contains an empty path: every listed CRL must name a file, or the \
             deployment reports offline revocation as enforced while one of its lists \
             revokes nothing"
                .to_string(),
        );
    }
    if config.peer_revocation.lists.reload_secs == Some(0) {
        violations.push(
            "--client-crl-reload-secs 0 makes the CRL reloader spin: the cadence is the sleep \
             between re-reads, so zero re-reads every CRL and rebuilds the TLS verifier \
             continuously. Set a positive cadence, or omit the flag to load the CRLs once"
                .to_string(),
        );
    }
    // Forbidden on `None`: a cadence names how often to re-read a set that is empty, so its
    // presence states a control the deployment does not have.
    if !state.is_enforced() && config.peer_revocation.lists.reload_secs.is_some() {
        violations.push(
            "--client-crl-reload-secs has no effect without --client-crl: there is no \
             revocation list to re-read, so no revocation is enforced on either cadence"
                .to_string(),
        );
    }
    (state, violations)
}

/// The ceiling on `--max-client-cert-lifetime` (ADR-MCPS-023 §A1, MCPS-57). A
/// lifetime above this cannot honestly be audited as `short_lived_cert`, so the
/// proxy rejects it. Matches the 1h default. Exported so test fixtures mint client
/// certs whose validity window is within the SAME bound the proxy enforces — there
/// is one source of truth, not a hand-picked magic number per fixture.
pub const MAX_CLIENT_CERT_LIFETIME: Duration = Duration::from_secs(3600);

/// The one decision about whether a transport-binding mode can be deployed.
///
/// `Some(diagnostic)` means it cannot. Mode-C attested ingress binds the request hash under
/// the OWNER-SIGNED security boundary, and re-binding it to the RFC 9421 request-evidence
/// digest is not designed yet — not merely unimplemented. Admitting it would require
/// answering what the attestor is authorized to ASSERT versus what it is authorized to
/// AUTHORIZE, and those are different claims:
///
/// > ingress A says "user U asked for operation X"
/// > is NOT
/// > ingress A holds authority "user U may perform X"
///
/// unless policy explicitly delegates that authority to A. Attestation must not become
/// authority by implication. Until that is specified — attestor identity, what bytes the
/// attestation binds, audience enforcement, replay, key rotation and revocation, and how an
/// ingress attestation appears in the evidence chain — the mode is refused deliberately
/// rather than left to whether the dormant builder happens to work.
///
/// Refused, NOT removed: attested ingress is the shape a broker-mediated deployment needs
/// (an enterprise access broker attesting a request it forwarded under an authenticated
/// customer context), so the capability is expected to be designed rather than deleted.
///
/// `--transport-binding lb-assertion` is refused separately, by the unsafe-configuration
/// guard that names why a load balancer in the trusted computing base is unacceptable.
pub(crate) fn undeployable_transport_binding_refusal(
    form: &PeerIdentityEvidenceRequest,
) -> Option<String> {
    matches!(form, PeerIdentityEvidenceRequest::AttestedIngress(_)).then(|| {
        "--transport-binding attested-ingress is not a supported deployment mode: Mode-C \
         attested ingress binds the request under the owner-signed security boundary, and \
         its rebinding onto the RFC 9421 request evidence is not yet specified (what the \
         attestor may assert, what its attestation binds, and how it appears in the \
         evidence chain). Use --binding exact (end-to-end mTLS)."
            .to_string()
    })
}

/// The verification material a peer-identity form needs, checked WITHIN that form.
///
/// Every clause here is internal to one form: a form with no verification key admits
/// nothing, a trusted identity that is the empty string admits everything, and an empty
/// audience binds an assertion to every node that also named none. None of them is a
/// relation to another machine, which is why they live beside the classifier.
///
/// **Five clauses are gone and their absence is the result.** They said that a value
/// belonged to a form the deployment had not selected — `--ingress-identity has no effect
/// without --transport-binding attested-ingress` and its four siblings. Each form now
/// carries only its own material, so there is no configuration left for them to examine
/// (ADR-MCPRE-067 §7). The command line can still name a stray flag, and the CLI adapter
/// answers that.
///
/// A sixth is gone for a different reason: the pinned-channel acknowledgement is a REQUIRED
/// member of [`AttestedIngressRequest`], so a Mode-C request without one cannot be built at
/// all rather than being refused after the fact.
fn ingress_assertion_refusal(form: &PeerIdentityEvidenceRequest) -> Option<String> {
    match form {
        PeerIdentityEvidenceRequest::ChannelCredential(_)
        | PeerIdentityEvidenceRequest::Unbound => None,
        PeerIdentityEvidenceRequest::IngressAssertion(assertion) => {
            // A form with no trusted key can never verify an assertion — it would reject
            // every request while reporting that request-bound ingress is in force.
            if assertion.verification_keys.is_empty() {
                return Some(
                    "--transport-binding lb-assertion requires at least one --ingress-lb-key \
                     <keyid>:<base64url-ed25519-pub> (the trusted LB verification key)"
                        .to_string(),
                );
            }
            verification_keys_refusal("--ingress-lb-key", "LB key", &assertion.verification_keys)
        }
        PeerIdentityEvidenceRequest::AttestedIngress(attested) => {
            attested_ingress_refusal(attested)
        }
    }
}

/// Mode C is strict-ADMITTED but ONLY when fully configured: attestor keys, trusted ingress
/// identities, and the expected audience. The pinned-channel acknowledgement is not checked
/// here because it cannot be absent.
fn attested_ingress_refusal(attested: &AttestedIngressRequest) -> Option<String> {
    if attested.attestor_keys.is_empty() {
        return Some(
            "--transport-binding attested-ingress requires at least one \
             --ingress-attestor-key <keyid>:<base64url-ed25519-pub> (the trusted \
             ingress-attestor verification key)"
                .to_string(),
        );
    }
    // A form with no trusted ingress identity would reject every assertion.
    if attested.identities.is_empty() {
        return Some(
            "--transport-binding attested-ingress requires at least one \
             --ingress-identity <id> (a trusted ingress identity)"
                .to_string(),
        );
    }
    // The witness exists, then the witness means something. A trusted identity that is the
    // empty string matches a v2 assertion whose `ingress_identity` states nothing, turning
    // the trusted set into a hole.
    if attested.identities.iter().any(|id| id.trim().is_empty()) {
        return Some(
            "--ingress-identity is empty: an empty trusted identity matches an assertion \
             that names none, so the trusted set would admit rather than restrict"
                .to_string(),
        );
    }
    // The audience binds a v2 assertion to this node's route. Two clauses used to live
    // here — one for an absent audience and one for an empty one — and the absent case is
    // gone: the audience is a MEMBER of the form, so a Mode-C request always carries one.
    // What survives is the clause about what it says, because an empty audience binds an
    // assertion to every node that also named none.
    if attested.audience.trim().is_empty() {
        return Some(
            "--ingress-audience is empty: the audience binds a v2 assertion to this \
             node's route, and an empty one binds it to every node that also set none"
                .to_string(),
        );
    }
    verification_keys_refusal(
        "--ingress-attestor-key",
        "attestor key",
        &attested.attestor_keys,
    )
}

/// Each configured key must be a valid base64url 32-byte Ed25519 public key, and key ids
/// must be unique — a malformed key or duplicate id is a misconfiguration, refused before
/// serving rather than at the first request.
///
/// One function for both forms because it is one rule about one kind of material, and the
/// flag names it quotes are diagnostics rather than semantics.
fn verification_keys_refusal(flag: &str, what: &str, keys: &[(String, String)]) -> Option<String> {
    let mut seen_ids: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for (key_id, key_b64) in keys {
        if !seen_ids.insert(key_id.as_str()) {
            return Some(format!(
                "duplicate {flag} id '{key_id}' (each {what} id must be unique)"
            ));
        }
        if mcp_re_core::VerificationKey::from_b64url(key_b64).is_err() {
            return Some(format!(
                "invalid {flag} '{key_id}': the body must be a base64url-no-pad 32-byte \
                 Ed25519 public key"
            ));
        }
    }
    None
}

/// Peer-identity coherence, read off a [`DeploymentRequest`], because the clauses decide
/// whether an operator can believe a request-binding ingress control is in force, and that
/// belief is no more true when the config was built in code.
pub(crate) fn ingress_assertion_violation(config: &DeploymentRequest) -> Option<String> {
    ingress_assertion_refusal(&config.peer_identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;

    fn binding(
        mutate: impl FnOnce(&mut DeploymentRequest),
    ) -> (Option<ChannelBindingState>, Vec<String>) {
        let mut config = legal_config();
        mutate(&mut config);
        classify_and_validate_binding(&config)
    }

    /// A state this machine must recognise, and how to request it.
    type Form = ((Vec<String>, Option<u64>), fn(&mut DeploymentRequest));

    fn crl(mutate: impl FnOnce(&mut DeploymentRequest)) -> (CrlRevocationState, Vec<String>) {
        let mut config = legal_config();
        mutate(&mut config);
        classify_and_validate_crl(&config)
    }

    #[test]
    fn both_binding_states_are_classified_and_accepted() {
        for (source, expected) in [
            (IdentityPolicy::UriSan, ChannelBindingState::ExactUriSan),
            (IdentityPolicy::DnsSan, ChannelBindingState::ExactDnsSan),
        ] {
            let (state, violations) = binding(|c| {
                c.peer_identity = PeerIdentityEvidenceRequest::channel_credential(source)
            });
            assert_eq!(state, Some(expected));
            assert!(
                violations.is_empty(),
                "{expected:?} refused: {violations:?}"
            );
        }
    }

    /// A Mode-C form, fully configured. Written as a literal so the acknowledgement is
    /// visible: there is no way to name this form without stating it.
    fn attested_form() -> PeerIdentityEvidenceRequest {
        PeerIdentityEvidenceRequest::AttestedIngress(AttestedIngressRequest {
            asserted_identity_kind: IdentityPolicy::UriSan,
            attestor_keys: vec![("attestor-1".to_string(), "k".to_string())],
            identities: vec!["ingress-1".to_string()],
            audience: "https://mcp.example.com/mcp".to_string(),
            pinned_channel: crate::deployment_request::PinnedChannelAcknowledgement::acknowledged(),
        })
    }

    /// Every form. The match is the exhaustiveness witness: a form added to the union stops
    /// this list compiling, so no test below can enumerate a stale variant set.
    fn every_form() -> Vec<PeerIdentityEvidenceRequest> {
        let forms = vec![
            PeerIdentityEvidenceRequest::Unbound,
            PeerIdentityEvidenceRequest::default(),
            PeerIdentityEvidenceRequest::IngressAssertion(
                crate::deployment_request::IngressAssertionRequest {
                    verification_keys: vec![("lb-1".to_string(), "k".to_string())],
                },
            ),
            attested_form(),
        ];
        for form in &forms {
            match form {
                PeerIdentityEvidenceRequest::Unbound
                | PeerIdentityEvidenceRequest::ChannelCredential(_)
                | PeerIdentityEvidenceRequest::IngressAssertion(_)
                | PeerIdentityEvidenceRequest::AttestedIngress(_) => {}
            }
        }
        forms
    }

    /// One machine: the identity FIELD names which state, and the form decides whether
    /// there is one. The field is asked of the form that has one, so the other forms are
    /// not carrying a value nothing reads.
    #[test]
    fn the_identity_field_names_the_state_and_the_form_decides_whether_there_is_one() {
        let uri = binding(|c| {
            c.peer_identity =
                PeerIdentityEvidenceRequest::channel_credential(IdentityPolicy::UriSan);
        })
        .0;
        let dns = binding(|c| {
            c.peer_identity =
                PeerIdentityEvidenceRequest::channel_credential(IdentityPolicy::DnsSan);
        })
        .0;
        assert_eq!(uri, Some(ChannelBindingState::ExactUriSan));
        assert_eq!(dns, Some(ChannelBindingState::ExactDnsSan));
        assert_ne!(uri, dns, "the same form, two states");
        for form in every_form()
            .into_iter()
            .filter(|form| form.credential_identity_field().is_none())
        {
            let named = form.flag_value();
            let (state, _) = binding(|c| c.peer_identity = form);
            assert_eq!(state, None, "{named} named a state it cannot inhabit");
        }
    }

    /// The `Exact` half of the state names, positively: only the kind the serving path
    /// installs a transport binding for reaches a state, and every other kind is refused
    /// with a diagnostic rather than passed over.
    #[test]
    fn only_exact_binding_becomes_a_state_and_every_other_kind_is_refused_aloud() {
        for form in every_form() {
            let named = form.flag_value();
            let is_credential = form.credential_identity_field().is_some();
            let (state, violations) = binding(|c| c.peer_identity = form);
            if is_credential {
                assert_eq!(state, Some(ChannelBindingState::ExactUriSan));
                assert!(violations.is_empty(), "exact refused: {violations:?}");
            } else {
                assert!(state.is_none(), "{named} became a validated state");
                assert!(
                    !violations.is_empty(),
                    "{named} named no state and said nothing about why"
                );
            }
        }
    }

    /// Attested ingress is refused by name. It is the one mode whose refusal is a decision
    /// about what an attestor may assert versus authorize, so losing it silently would put
    /// a deployment in a mode nothing else in the file rejects.
    #[test]
    fn attested_ingress_is_refused_by_name_rather_than_passed_over() {
        let (state, violations) = binding(|c| c.peer_identity = attested_form());
        assert!(state.is_none(), "attested ingress became a validated state");
        assert!(
            violations
                .iter()
                .any(|v| v.contains("attested-ingress is not a supported deployment mode")),
            "{violations:?}"
        );
    }

    #[test]
    fn the_deprecated_identity_source_names_no_state() {
        let (state, violations) = binding(|c| {
            c.peer_identity =
                PeerIdentityEvidenceRequest::channel_credential(IdentityPolicy::CnLegacy);
        });
        assert!(state.is_none());
        assert!(
            violations.iter().any(|v| v.contains("cn_legacy")),
            "{violations:?}"
        );
    }

    #[test]
    fn every_legal_crl_state_form_is_classified_and_accepted() {
        let cases: Vec<Form> = vec![
            ((Vec::new(), None), |_| {}),
            (
                (vec!["/crl.pem".to_string()], None),
                |c: &mut DeploymentRequest| {
                    c.peer_revocation.lists.paths = vec!["/crl.pem".to_string()];
                },
            ),
            (
                (vec!["/crl.pem".to_string()], Some(300)),
                |c: &mut DeploymentRequest| {
                    c.peer_revocation.lists.paths = vec!["/crl.pem".to_string()];
                    c.peer_revocation.lists.reload_secs = Some(300);
                },
            ),
        ];
        for ((paths, cadence), mutate) in cases {
            let (state, violations) = crl(mutate);
            assert_eq!(state.paths(), paths.as_slice());
            assert_eq!(state.reload_cadence_secs(), cadence);
            assert_eq!(state.is_enforced(), !paths.is_empty());
            assert!(
                violations.is_empty(),
                "{paths:?}/{cadence:?} refused: {violations:?}"
            );
        }
    }

    /// G5. A list holding `""` is not an empty list, so it classified as a configured
    /// control while naming no file.
    ///
    /// The parser rejects an empty comma segment, but `client_crl_paths` is a public field:
    /// this mutates the REQUEST, so no parser participates. The positive half is
    /// `every_legal_crl_state_form_is_classified_and_accepted`, which drives the same guard
    /// with a real path and asserts nothing is reported.
    #[test]
    fn a_crl_list_holding_an_empty_path_is_refused() {
        for paths in [
            vec![String::new()],
            vec!["/crl.pem".to_string(), String::new()],
        ] {
            let (state, violations) = crl(|c| c.peer_revocation.lists.paths = paths.clone());
            assert!(
                state.is_enforced(),
                "{paths:?} classified as no CRL control at all, which would hide the defect"
            );
            assert!(
                violations.iter().any(|v| v.contains("empty path")),
                "{paths:?}: not refused — {violations:?}"
            );
        }
    }

    #[test]
    fn a_zero_cadence_is_an_unbounded_reloader_not_a_disabled_one() {
        let (_, violations) = crl(|c| {
            c.peer_revocation.lists.paths = vec!["/crl.pem".to_string()];
            c.peer_revocation.lists.reload_secs = Some(0);
        });
        assert!(
            violations.iter().any(|v| v.contains("spin")),
            "{violations:?}"
        );
    }

    #[test]
    fn a_cadence_with_no_list_to_re_read_is_refused() {
        let (state, violations) = crl(|c| c.peer_revocation.lists.reload_secs = Some(300));
        assert!(!state.is_enforced());
        assert!(
            violations
                .iter()
                .any(|v| v.contains("has no effect without --client-crl")),
            "{violations:?}"
        );
    }
}
