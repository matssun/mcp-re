// SPDX-License-Identifier: Apache-2.0
//! The classified legal deployment state — layer A of `work/CONFIG-STATE-ATLAS.md`.
//!
//! `DeploymentRequest` describes a *requested* deployment. Not every combination of its fields
//! describes a deployment that could exist, and the atlas is the closed model of the ones
//! that can: twelve machines, each with its own states, a set of guard-only owners that
//! have invariants without a mode choice, and a small set of relations between them. This
//! module is that model as code — one classifier/validator per owner, and one value
//! carrying what they recognised.
//!
//! **Three layers, and this is only the first.** Layer A asks whether the request is
//! internally coherent; it touches no filesystem, no network, and no cargo feature. Layer
//! B asks whether *this executable* can establish the request, and layer C whether the
//! world cooperated. Both belong to materialization. `key_source = env` is a coherent
//! request in a binary that cannot serve it: the plan succeeds and materialization
//! refuses, which is `PlanDecision != RuntimeEvidence` working rather than failing.
//!
//! **The classification is a value, not a step (CF-10).** A validator that recognises
//! `PushNetworked`, checks it, and discards the answer leaves planning to re-derive the
//! same fact from the same fields — two derivations of one deployment fact, free to
//! disagree. So validation returns a [`DeploymentConfigState`], and that is what the plane
//! plans project from.
//!
//! **Layer A must not discard evidence intrinsic to the state it just established.** The
//! same argument that makes the classification a value applies to what proving it
//! produced. Deciding that a deployment is `SharedRedis` *is* deciding that its Redis URL
//! is present; a state that keeps only the verdict leaves planning to fetch the URL back
//! out of the broad request and assert `expect("layer A guarantees this")` — the proof
//! erased and then recovered, one layer along, from a representation weak enough to still
//! say `None`.
//!
//! So a semantic owner retains the facts that constitute its invariant. Two shapes, because
//! the atlas has two kinds of owner:
//!
//! - A **state-owning machine** carries its classified state together with the witnesses
//!   intrinsic to inhabiting it. A `Reloading` CRL state without its cadence does not
//!   describe a deployment, so the cadence travels with the state that required it.
//! - A **guard-only owner** has no mode choice and therefore no state enum, but still owns
//!   invariants and resolved values. `DelegatedSigning` is unconditional (ADR-MCPRE-052 is
//!   the only response-signing mode) and still owns the §7 trust-epoch requirement and the
//!   two defaulting rules for the issuer kid and the audience hash. A resolved default is
//!   owned at the layer that owns the rule; downstream there is no knowledge that a
//!   default ever existed.
//!
//! **Two limits keep this from becoming a second `DeploymentRequest`.** A generic deployment
//! parameter stays in `DeploymentRequest` — validated, but not evidence for inhabiting any particular
//! state; `max_clock_skew`, `bind` and the limits are checked and stay put. And a fact
//! already encoded by a variant is *derived*, never stored beside it: `SharedRedis` names
//! the tier, so carrying a tier field too would create two authorities free to disagree,
//! and the impossible pairing becomes representable again.
//!
//! **This is not a normalized plan either.** Consumer-specific shaping is still planning's
//! job. The progression is `DeploymentRequest` (requested values) → `DeploymentConfigState` (semantic
//! state plus its own evidence) → `Plan` (one consumer's intent), and each stage means
//! strictly more than the last — without any of them saying "the previous stage promised
//! this".

pub mod admission;
pub mod authorization;
pub mod channel_credential_custody;
pub mod channel_key_material;
pub mod client_credential_window;
pub mod continuation_control;
pub mod credential_currency_bound;
pub(crate) mod cross_machine;
pub mod custody;
pub mod delegated_signing;
pub mod evidence;
pub mod freshness;
pub mod in_flight_limit;
pub mod key_file_access;
pub(crate) mod kms_endpoint;
pub mod mcp_transport_contract;
pub mod replay;
pub mod server_identity;
pub mod topology;
pub mod transport;
pub mod trust_document;
pub mod trust_revocation;
pub mod validation;

pub use admission::{AdmissionAvailability, AdmissionPosture, AdmissionState, EnforcedAdmission};
pub use authorization::{AuthorizationState, EnforcedAuthorization};
pub use channel_credential_custody::ChannelCredentialCustodyState;
pub use channel_key_material::ChannelKeyMaterial;
pub use client_credential_window::ClientCredentialWindow;
pub use continuation_control::ContinuationControlState;
pub use credential_currency_bound::{credential_currency_bound, CredentialCurrencyBound};
pub use custody::{AwsCredentialMode, CustodyMaterial, CustodyState, PrivateKeyExposure};
pub use delegated_signing::DelegatedSigningFacts;
pub use evidence::{AuditState, RetentionState, VerifiedContextState};
pub use freshness::FreshnessWindow;
pub use in_flight_limit::{InFlightLimitBasis, InFlightLimitRequest};
pub use key_file_access::KeyFileAccessPolicy;
pub use mcp_transport_contract::McpTransportContractState;
pub use replay::ReplayState;
pub use topology::{DeploymentTopology, ShardTopologyRequest};
pub use transport::{ChannelBindingState, CrlRevocationState};
pub use trust_document::TrustDocumentSource;
pub use trust_revocation::TrustRevocationState;

/// What layer A recognised: each machine's state, and each guard-only owner's facts.
///
/// Built only by a successful validation, so holding one is evidence that every owner here
/// was checked against its own required/optional/forbidden/guard columns and that the
/// cross-machine relations hold between them.
///
/// It grows one field per owner as the atlas is implemented; an owner that is not here yet
/// is one whose legality still lives in the residual clause list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentConfigState {
    /// The recognised states themselves. One field rather than a copy of every field in
    /// [`RecognisedStates`]: the two shapes were identical, and a state added to one had to
    /// be transcribed into the other twice — a per-machine cost that bought nothing, since
    /// the only difference between them was ever the claim attached, not the contents.
    /// Private, so the `pub(crate)` fields of the inner value stay unreachable from here.
    states: RecognisedStates,
}

/// The recognised states, as one argument, so adding a machine is a change in one place
/// rather than in every signature between the validator and the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecognisedStates {
    pub(crate) admission: AdmissionState,
    pub(crate) authorization: AuthorizationState,
    pub(crate) audit: AuditState,
    pub(crate) channel_binding: ChannelBindingState,
    pub(crate) client_credential_window: ClientCredentialWindow,
    pub(crate) continuation_control: ContinuationControlState,
    pub(crate) crl_revocation: CrlRevocationState,
    pub(crate) custody: CustodyState,
    pub(crate) delegated_signing: DelegatedSigningFacts,
    pub(crate) freshness: FreshnessWindow,
    pub(crate) in_flight_limit: InFlightLimitBasis,
    pub(crate) key_file_access: KeyFileAccessPolicy,
    pub(crate) mcp_transport_contract: McpTransportContractState,
    pub(crate) replay: ReplayState,
    pub(crate) retention: RetentionState,
    pub(crate) server_identity: server_identity::ServerIdentityFacts,
    pub(crate) shard_topology: ShardTopologyRequest,
    pub(crate) channel_credential_custody: ChannelCredentialCustodyState,
    pub(crate) topology: DeploymentTopology,
    pub(crate) trust_document: TrustDocumentSource,
    pub(crate) trust_revocation: TrustRevocationState,
    pub(crate) verified_context: VerifiedContextState,
}

impl DeploymentConfigState {
    /// Assemble the classified state. Crate-private: the only legitimate producer is the
    /// validation boundary, because the value's meaning is "these states were checked".
    pub(crate) fn new(states: RecognisedStates) -> Self {
        Self { states }
    }

    /// Whether a workload admission gate applies, how strictly, and — when it does — the
    /// authority and shared record it was found inhabitable by.
    pub fn admission(&self) -> &AdmissionState {
        &self.states.admission
    }

    /// Which authorization authority this deployment installs, and the decision profile it
    /// accepts when it installs one.
    pub fn authorization(&self) -> &AuthorizationState {
        &self.states.authorization
    }

    /// Where the per-request security record goes.
    pub fn audit(&self) -> AuditState {
        self.states.audit
    }

    /// How a verified request signer is bound to the authenticated channel.
    pub fn channel_binding(&self) -> ChannelBindingState {
        self.states.channel_binding
    }

    /// Offline client-certificate revocation.
    pub fn crl_revocation(&self) -> &CrlRevocationState {
        &self.states.crl_revocation
    }

    /// Whether exchanges are retained for later SCITT statements.
    pub fn retention(&self) -> &RetentionState {
        &self.states.retention
    }

    /// What the PEP asserts to the inner server about the caller.
    pub fn verified_context(&self) -> VerifiedContextState {
        self.states.verified_context
    }

    /// Whether multi-round-trip flows resolve across replicas, and nothing about replay:
    /// the two were one field until CF-12 and are two facts.
    pub fn continuation_control(&self) -> &ContinuationControlState {
        &self.states.continuation_control
    }

    /// Where admitted nonces live. Both variants are shared — a node-local replay store is
    /// not a state a deployment can be in.
    pub fn replay(&self) -> &ReplayState {
        &self.states.replay
    }

    /// Which basis the admission limit is expressed in, with the default already applied.
    ///
    /// A resolved fact rather than a posture: the control is on in both variants, and the
    /// two differ only in the altitude the operator stated it at.
    /// The accepted temporal uncertainty, and what each mechanism derives from it.
    ///
    /// One fact with two consumers: the RFC 9421 acceptance window and the replay retention
    /// horizon. They read projections of the same value rather than the same raw field.
    pub fn freshness(&self) -> FreshnessWindow {
        self.states.freshness
    }

    pub fn in_flight_limit(&self) -> InFlightLimitBasis {
        self.states.in_flight_limit
    }

    /// Whether the MCP transport/version contract is asserted, and for which versions.
    pub fn mcp_transport_contract(&self) -> &McpTransportContractState {
        &self.states.mcp_transport_contract
    }

    /// Where the response-signing key lives.
    pub fn custody(&self) -> &CustodyState {
        &self.states.custody
    }

    /// What was established about delegated response signing — the epoch every credential
    /// is minted under, and the two values whose defaulting rule this layer owns.
    pub fn delegated_signing(&self) -> &DelegatedSigningFacts {
        &self.states.delegated_signing
    }

    /// This deployment's own actor identity, derived once.
    ///
    /// Consumers take it rather than assembling one from `trust_domain`, `server_signer`
    /// and a `"server"` literal — which is what two of them used to do.
    pub fn server_identity(&self) -> &server_identity::ServerIdentityFacts {
        &self.states.server_identity
    }

    /// Whether the TLS handshake key can leave the device it lives on.
    pub fn channel_credential_custody(&self) -> &ChannelCredentialCustodyState {
        &self.states.channel_credential_custody
    }

    /// Whether this deployment is one node or one replica of several.
    pub fn topology(&self) -> DeploymentTopology {
        self.states.topology
    }

    /// The serving-shard shape as the operator stated it. Not a count: the host resolves
    /// `Auto` into one.
    pub fn shard_topology(&self) -> ShardTopologyRequest {
        self.states.shard_topology
    }

    /// Which key-file permission postures this deployment accepts.
    ///
    /// The policy answers whether a posture is refused; composition never receives the
    /// flag and re-derives the rule around it.
    pub fn key_file_access(&self) -> KeyFileAccessPolicy {
        self.states.key_file_access
    }

    /// How long a client credential authorizes traffic, and how long one connection may
    /// serve on a single handshake — one fact, because the second is what makes the first
    /// a statement about requests.
    pub fn client_credential_window(&self) -> ClientCredentialWindow {
        self.states.client_credential_window
    }

    /// Which document the request-signer set is read from.
    ///
    /// The locator's own authority, so a plan pairs a revocation posture with a document
    /// both owners recognised rather than with whatever string reached the plan.
    pub fn trust_document(&self) -> &TrustDocumentSource {
        &self.states.trust_document
    }

    /// The trust-revocation state — the authority both `TrustPlan` and `SigningPlan`
    /// consume rather than each re-deriving from `trust_epoch_redis_url` (CF-09).
    pub fn trust_revocation(&self) -> &TrustRevocationState {
        &self.states.trust_revocation
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::cli;
    use crate::deployment_request::DeploymentRequest;

    /// The same configuration with the linearizable replay state requested.
    ///
    /// Built by mutating the accepted request and re-classifying, because the replay state
    /// is only obtainable from its own validator — which is what makes possessing one mean
    /// its locators were checked.
    pub(crate) fn legal_linearizable_config() -> DeploymentRequest {
        let mut config = legal_config();
        config.replay.store = None;
        config.replay.durability = Some(crate::replay_tier::ReplayDurabilityTier::Linearizable);
        config.replay.store = Some(crate::deployment_request::ReplayStoreRequest::etcd(
            "http://127.0.0.1:2379",
        ));
        config
    }

    /// The replay plan a linearizable deployment produces.
    ///
    /// Projected from a classified state rather than built as a literal, so a test holds
    /// only plans a configuration could actually reach. The literals these replaced could
    /// name a store paired with any tier at all, including tiers `classify` refuses.
    pub(crate) fn linearizable_replay_plan() -> super::replay::ReplayPlan {
        super::replay::classify_and_validate(&legal_linearizable_config())
            .0
            .expect("the linearizable fixture names a CP store endpoint")
            .materialization_plan()
    }

    /// The replay plan a quorum-Redis deployment produces.
    pub(crate) fn redis_replay_plan() -> super::replay::ReplayPlan {
        super::replay::classify_and_validate(&legal_config())
            .0
            .expect("the accepted fixture names a redis replay store")
            .materialization_plan()
    }

    /// The same configuration with a shared continuation store requested.
    pub(crate) fn shared_continuation_config() -> DeploymentRequest {
        let mut config = legal_config();
        config.continuation_control.shared = Some(
            crate::deployment_request::SharedStoreRequest::redis("redis://127.0.0.1:6379"),
        );
        config
    }

    /// The same configuration with admission enforced under a named authority.
    pub(crate) fn enforcing_admission_config() -> DeploymentRequest {
        let mut config = legal_config();
        config.admission = crate::deployment_request::AdmissionRequest::Required(
            crate::deployment_request::AdmissionGateRequest {
                authority_kid: "authority-1".to_string(),
                authority_pubkey_b64url: mcp_re_core::SigningKey::from_seed_bytes(&[7u8; 32])
                    .public_key()
                    .to_b64url(),
                store: crate::deployment_request::SharedStoreRequest::redis(
                    "redis://127.0.0.1:6379",
                ),
                availability: crate::deployment_request::AdmissionAvailabilityRequest::FailClosed,
            },
        );
        config
    }

    /// The same configuration declaring a served MCP protocol version.
    pub(crate) fn versioned_transport_config() -> DeploymentRequest {
        let mut config = legal_config();
        config.mcp_protocol_versions = vec!["2026-07-28".to_string()];
        config
    }

    /// The retention state a deployment configured with this directory reaches.
    pub(crate) fn retention_at(directory: String) -> super::RetentionState {
        let mut config = legal_config();
        config.retained_evidence_dir = Some(directory);
        super::evidence::classify(&config).1
    }

    /// The trust-revocation state a deployment with these settings reaches.
    ///
    /// Built through the classifier, so a test names a posture a configuration could
    /// actually request rather than assembling one from parts.
    pub(crate) fn revocation_posture(
        tier: crate::revocation_tier::RevocationTier,
        reload_secs: Option<u64>,
        epoch: Option<(&str, &str)>,
    ) -> super::TrustRevocationState {
        let mut config = legal_config();
        config.revocation_tier = tier;
        config.trust_reload_secs = reload_secs;
        config.trust_epoch.source = epoch.map(|(url, key)| {
            crate::deployment_request::TrustEpochSource::redis(url, Some(key.to_string()))
        });
        super::trust_revocation::classify_and_validate(&config)
            .0
            .expect("the requested revocation posture is legal")
    }

    /// The credential window a deployment with this lifetime and connection age reaches.
    ///
    /// Through the classifier, so a test cannot hold a window whose connection age outlives
    /// its certificate — which is the pairing the owner exists to make unconstructible.
    pub(crate) fn credential_window(
        cert_lifetime_secs: u64,
        connection_age_secs: u64,
    ) -> super::ClientCredentialWindow {
        let mut config = legal_config();
        config.max_client_cert_lifetime = Some(std::time::Duration::from_secs(cert_lifetime_secs));
        config.limits.max_connection_age =
            Some(std::time::Duration::from_secs(connection_age_secs));
        super::client_credential_window::classify_and_validate(&config)
            .0
            .expect("the fixture names a legal credential window")
    }

    /// The trust plan a deployment in this posture projects.
    ///
    /// Through the boundary and then through `TrustPlan::from_validated`, so the plan's
    /// revocation posture, its derived reload cadence and its document all come from ONE
    /// accepted deployment. The literal this replaced could pair any state with any
    /// cadence, and did: it named a 30s reload beside a state carrying 5s.
    pub(crate) fn trust_plan(
        tier: crate::revocation_tier::RevocationTier,
        reload_secs: Option<u64>,
        epoch: Option<(&str, &str)>,
    ) -> crate::startup_plan::TrustPlan {
        let mut config = legal_config();
        config.revocation_tier = tier;
        config.trust_reload_secs = reload_secs;
        config.trust_epoch.source = epoch.map(|(url, key)| {
            crate::deployment_request::TrustEpochSource::redis(url, Some(key.to_string()))
        });
        let validated = super::validation::ValidatedDeployment::try_from(config)
            .expect("the requested trust posture is a legal deployment");
        let epoch_plan = crate::startup_plan::TrustEpochPlan::from_validated(&validated);
        crate::startup_plan::TrustPlan::from_validated(
            &validated,
            "response-kid".to_string(),
            epoch_plan,
        )
    }

    /// The CRL state a deployment with these files and cadence reaches.
    /// The freshness window a deployment with this skew resolves.
    ///
    /// Through the classifier, so a test cannot hold a window outside the §5.1 bound.
    pub(crate) fn freshness(max_clock_skew: i64) -> super::FreshnessWindow {
        let mut config = legal_config();
        config.max_clock_skew = max_clock_skew;
        super::freshness::classify_and_validate(&config)
            .0
            .expect("the fixture skew is within the bound")
    }

    pub(crate) fn crl_posture(
        paths: &[&str],
        cadence_secs: Option<u64>,
    ) -> super::CrlRevocationState {
        let mut config = legal_config();
        config.peer_revocation.lists.paths = paths.iter().map(|p| p.to_string()).collect();
        config.peer_revocation.lists.reload_secs = cadence_secs;
        super::transport::classify_and_validate_crl(&config).0
    }

    /// The client-revocation plan such a deployment projects.
    pub(crate) fn crl_plan(
        paths: &[&str],
        cadence_secs: Option<u64>,
    ) -> super::transport::ClientRevocationPlan {
        crl_posture(paths, cadence_secs).client_revocation_plan()
    }

    /// The TLS-custody state a deployment delegating the handshake key to a PKCS#11 token
    /// reaches.
    pub(crate) fn channel_custody_delegated_pkcs11(
        key_label: &str,
    ) -> super::ChannelCredentialCustodyState {
        let mut config = legal_config();
        config.channel_credential.key = crate::deployment_request::ChannelKeyRequest::Delegated(
            crate::deployment_request::DelegatedChannelKeyRequest::Pkcs11(
                crate::deployment_request::Pkcs11ChannelKeyRequest {
                    key_label: key_label.to_string(),
                },
            ),
        );
        super::channel_credential_custody::classify_and_validate(&config)
            .0
            .expect("a delegated PKCS#11 TLS key names a state")
    }

    /// The TLS-custody state a deployment reading the handshake key from a file reaches.
    pub(crate) fn channel_custody_exported(key_path: &str) -> super::ChannelCredentialCustodyState {
        let mut config = legal_config();
        config.channel_credential.key = crate::deployment_request::ChannelKeyRequest::ExportedFile(
            crate::deployment_request::ExportedChannelKeyRequest {
                key_path: key_path.to_string(),
            },
        );
        super::channel_credential_custody::classify_and_validate(&config)
            .0
            .expect("an exported TLS key names a state")
    }

    /// The custody state a deployment holding the signing key on a PKCS#11 token reaches.
    pub(crate) fn custody_pkcs11() -> super::CustodyState {
        let mut config = legal_config();
        config.response_signing.source = crate::deployment_request::SigningSourceRequest::Pkcs11(
            crate::deployment_request::Pkcs11SigningSourceRequest {
                module: Some("/lib/softhsm.so".to_string()),
                pin_file: Some("/pin".to_string()),
                token_label: Some("token".to_string()),
                key_label: Some("signing".to_string()),
            },
        );
        super::custody::classify_and_validate(&config)
            .0
            .expect("a complete PKCS#11 custody configuration names a state")
    }

    /// A configuration the parser accepts, for a machine's tests to mutate.
    ///
    /// From `parse_args` rather than a struct literal so that a test which expects a
    /// refusal is measuring the mutation it made, not a defect it inherited.
    pub(crate) fn legal_config() -> DeploymentRequest {
        let argv: Vec<String> = [
            "--bind",
            "127.0.0.1:8443",
            "--audience",
            "did:example:server-1",
            "--server-signer",
            "did:example:server-1",
            "--server-key-id",
            "server-key-1",
            "--signing-key-seed",
            "/seed",
            "--tls-cert",
            "/cert",
            "--tls-key",
            "/key",
            "--client-ca",
            "/ca",
            "--trust",
            "/trust.json",
            "--inner-http-url",
            "http://127.0.0.1:8080/mcp",
            "--target-uri",
            "https://mcp.example.com/mcp",
            "--delegated-trust-epoch",
            "epoch-min",
            "--trust-domain",
            "mcp.example.com",
            "--replay-redis-url",
            "redis://127.0.0.1:6379",
            "--replay-durability-tier",
            "redis-wait-quorum:1:100",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        cli::parse_args(&argv).expect("the baseline parses")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_state_carries_what_the_planes_would_otherwise_re_derive() {
        let state = DeploymentConfigState::new(RecognisedStates {
            admission:
                admission::classify_and_validate(&test_support::enforcing_admission_config())
                    .0
                    .expect("the enforcing fixture names an admission authority"),
            authorization: authorization::classify_and_validate(&test_support::legal_config())
                .0
                .expect("the legal fixture installs no authorization authority"),
            audit: AuditState::Stderr,
            channel_binding: ChannelBindingState::ExactUriSan,
            freshness: freshness::classify_and_validate(&test_support::legal_config())
                .0
                .expect("the legal fixture names a bounded freshness window"),
            server_identity: crate::config_state::server_identity::classify_and_validate(
                &crate::config_state::test_support::legal_config(),
                crate::config_state::delegated_signing::classify_and_validate(
                    &crate::config_state::test_support::legal_config(),
                )
                .0
                .as_ref(),
            )
            .0
            .expect("the legal fixture has an identity"),
            key_file_access: key_file_access::classify(&test_support::legal_config()),
            topology: topology::classify(&test_support::legal_config()).0,
            shard_topology: topology::classify(&test_support::legal_config()).1,
            in_flight_limit: InFlightLimitBasis::PerCore {
                requests: std::num::NonZeroUsize::new(256).expect("non-zero"),
            },
            continuation_control: continuation_control::classify_and_validate(
                &test_support::shared_continuation_config(),
            )
            .0,
            crl_revocation: test_support::crl_posture(&["/crl.pem"], Some(300)),
            client_credential_window: client_credential_window::classify_and_validate(
                &test_support::legal_config(),
            )
            .0
            .expect("the legal fixture names a bounded credential window"),
            trust_document: trust_document::classify_and_validate(&test_support::legal_config())
                .0
                .expect("the legal fixture names a trust document"),
            custody: test_support::custody_pkcs11(),
            mcp_transport_contract: mcp_transport_contract::classify(
                &test_support::versioned_transport_config(),
            ),
            delegated_signing: delegated_signing::classify_and_validate(
                &test_support::legal_config(),
            )
            .0
            .expect("the legal fixture names a trust epoch"),
            replay: replay::classify_and_validate(&test_support::legal_linearizable_config())
                .0
                .expect("the linearizable fixture names a CP store endpoint"),
            retention: test_support::retention_at("/var/lib/mcp-re/evidence".to_string()),
            channel_credential_custody: test_support::channel_custody_delegated_pkcs11("tls"),
            trust_revocation: test_support::revocation_posture(
                crate::revocation_tier::RevocationTier::Push { t_secs: 30 },
                Some(5),
                Some(("redis://127.0.0.1:6379", "mcp-re:trust:epoch")),
            ),
            verified_context: VerifiedContextState::Trusted,
        });
        assert!(state.trust_revocation().has_networked_epoch());
        assert_eq!(state.custody().exposure(), PrivateKeyExposure::NonExporting);
        assert_eq!(
            state.channel_credential_custody().exposure(),
            PrivateKeyExposure::NonExporting
        );
        // CF-12's negative control, at the level of the value itself: a linearizable
        // replay store and a shared continuation store are independently expressible.
        assert_eq!(
            state.replay().durability_tier(),
            crate::replay_tier::ReplayDurabilityTier::Linearizable
        );
        assert!(state.continuation_control().is_shared());
        // Every machine the atlas names is represented exactly once, including the ones
        // that cannot be misconfigured: the value states the whole posture, not the part
        // that needed checking.
        assert!(state.admission().is_enforced());
        assert_eq!(state.audit(), AuditState::Stderr);
        assert_eq!(state.channel_binding(), ChannelBindingState::ExactUriSan);
        assert_eq!(state.crl_revocation().reload_cadence_secs(), Some(300));
        assert!(state.retention().is_on());
        assert!(state.verified_context().asserts_inner_channel_isolation());
    }
}
