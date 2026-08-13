// SPDX-License-Identifier: Apache-2.0
//! The classified legal deployment state — layer A of `work/CONFIG-STATE-ATLAS.md`.
//!
//! `Config` describes a *requested* deployment. Not every combination of its fields
//! describes a deployment that could exist, and the atlas is the closed model of the ones
//! that can: eleven machines, each with its own states, a set of guard-only owners that
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
//! **Two limits keep this from becoming a second `Config`.** A generic deployment
//! parameter stays in `Config` — validated, but not evidence for inhabiting any particular
//! state; `max_clock_skew`, `bind` and the limits are checked and stay put. And a fact
//! already encoded by a variant is *derived*, never stored beside it: `SharedRedis` names
//! the tier, so carrying a tier field too would create two authorities free to disagree,
//! and the impossible pairing becomes representable again.
//!
//! **This is not a normalized plan either.** Consumer-specific shaping is still planning's
//! job. The progression is `Config` (requested values) → `DeploymentConfigState` (semantic
//! state plus its own evidence) → `Plan` (one consumer's intent), and each stage means
//! strictly more than the last — without any of them saying "the previous stage promised
//! this".

pub mod admission;
pub mod continuation_control;
pub(crate) mod cross_machine;
pub mod custody;
pub mod delegated_signing;
pub mod evidence;
pub mod replay;
pub mod tls_custody;
pub mod transport;
pub mod trust_revocation;

pub use admission::AdmissionState;
pub use continuation_control::ContinuationControlState;
pub use custody::CustodyState;
pub use delegated_signing::DelegatedSigningFacts;
pub use evidence::{AuditState, RetentionState, VerifiedContextState};
pub use replay::ReplayState;
pub use tls_custody::TlsCustodyState;
pub use transport::{ChannelBindingState, CrlRevocationState};
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
    admission: AdmissionState,
    audit: AuditState,
    channel_binding: ChannelBindingState,
    continuation_control: ContinuationControlState,
    crl_revocation: CrlRevocationState,
    custody: CustodyState,
    delegated_signing: DelegatedSigningFacts,
    replay: ReplayState,
    retention: RetentionState,
    tls_custody: TlsCustodyState,
    trust_revocation: TrustRevocationState,
    verified_context: VerifiedContextState,
}

/// The recognised states, as one argument, so adding a machine is a change in one place
/// rather than in every signature between the validator and the value.
pub(crate) struct RecognisedStates {
    pub(crate) admission: AdmissionState,
    pub(crate) audit: AuditState,
    pub(crate) channel_binding: ChannelBindingState,
    pub(crate) continuation_control: ContinuationControlState,
    pub(crate) crl_revocation: CrlRevocationState,
    pub(crate) custody: CustodyState,
    pub(crate) delegated_signing: DelegatedSigningFacts,
    pub(crate) replay: ReplayState,
    pub(crate) retention: RetentionState,
    pub(crate) tls_custody: TlsCustodyState,
    pub(crate) trust_revocation: TrustRevocationState,
    pub(crate) verified_context: VerifiedContextState,
}

impl DeploymentConfigState {
    /// Assemble the classified state. Crate-private: the only legitimate producer is the
    /// validation boundary, because the value's meaning is "these states were checked".
    pub(crate) fn new(states: RecognisedStates) -> Self {
        let RecognisedStates {
            admission,
            audit,
            channel_binding,
            continuation_control,
            crl_revocation,
            custody,
            delegated_signing,
            replay,
            retention,
            tls_custody,
            trust_revocation,
            verified_context,
        } = states;
        Self {
            admission,
            audit,
            channel_binding,
            continuation_control,
            crl_revocation,
            custody,
            delegated_signing,
            replay,
            retention,
            tls_custody,
            trust_revocation,
            verified_context,
        }
    }

    /// Whether a workload admission gate applies, and how strictly.
    pub fn admission(&self) -> AdmissionState {
        self.admission
    }

    /// Where the per-request security record goes.
    pub fn audit(&self) -> AuditState {
        self.audit
    }

    /// How a verified request signer is bound to the authenticated channel.
    pub fn channel_binding(&self) -> ChannelBindingState {
        self.channel_binding
    }

    /// Offline client-certificate revocation.
    pub fn crl_revocation(&self) -> &CrlRevocationState {
        &self.crl_revocation
    }

    /// Whether exchanges are retained for later SCITT statements.
    pub fn retention(&self) -> RetentionState {
        self.retention
    }

    /// What the PEP asserts to the inner server about the caller.
    pub fn verified_context(&self) -> VerifiedContextState {
        self.verified_context
    }

    /// Whether multi-round-trip flows resolve across replicas, and nothing about replay:
    /// the two were one field until CF-12 and are two facts.
    pub fn continuation_control(&self) -> &ContinuationControlState {
        &self.continuation_control
    }

    /// Where admitted nonces live. Both variants are shared — a node-local replay store is
    /// not a state a deployment can be in.
    pub fn replay(&self) -> &ReplayState {
        &self.replay
    }

    /// Where the response-signing key lives.
    pub fn custody(&self) -> CustodyState {
        self.custody
    }

    /// What was established about delegated response signing — the epoch every credential
    /// is minted under, and the two values whose defaulting rule this layer owns.
    pub fn delegated_signing(&self) -> &DelegatedSigningFacts {
        &self.delegated_signing
    }

    /// Whether the TLS handshake key can leave the device it lives on.
    pub fn tls_custody(&self) -> TlsCustodyState {
        self.tls_custody
    }

    /// The trust-revocation state — the authority both `TrustPlan` and `SigningPlan`
    /// consume rather than each re-deriving from `trust_epoch_redis_url` (CF-09).
    pub fn trust_revocation(&self) -> &TrustRevocationState {
        &self.trust_revocation
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::cli::{self, Config};

    /// A configuration the parser accepts, for a machine's tests to mutate.
    ///
    /// From `parse_args` rather than a struct literal so that a test which expects a
    /// refusal is measuring the mutation it made, not a defect it inherited.
    pub(crate) fn legal_config() -> Config {
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
            "--replay-cache",
            "shared",
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
            admission: AdmissionState::Required,
            audit: AuditState::Stderr,
            channel_binding: ChannelBindingState::ExactUriSan,
            continuation_control: ContinuationControlState::Redis {
                endpoint: "redis://127.0.0.1:6379".to_string(),
            },
            crl_revocation: CrlRevocationState::Reloading {
                paths: vec!["/crl.pem".to_string()],
                cadence_secs: 300,
            },
            custody: CustodyState::Pkcs11,
            delegated_signing: delegated_signing::classify_and_validate(
                &test_support::legal_config(),
            )
            .0
            .expect("the legal fixture names a trust epoch"),
            replay: ReplayState::SharedLinearizable {
                endpoint: "http://127.0.0.1:2379".to_string(),
            },
            retention: RetentionState::On,
            tls_custody: TlsCustodyState::Delegated,
            trust_revocation: TrustRevocationState::PushNetworked {
                t_secs: 30,
                reload_secs: 5,
                epoch_url: "redis://127.0.0.1:6379".to_string(),
                epoch_key: "mcp-re:trust:epoch".to_string(),
            },
            verified_context: VerifiedContextState::Trusted,
        });
        assert!(state.trust_revocation().has_networked_epoch());
        assert!(state.custody().is_non_exporting_device());
        assert!(state.tls_custody().is_delegated());
        // CF-12's negative control, at the level of the value itself: a linearizable
        // replay store and a shared continuation store are independently expressible.
        assert!(matches!(
            state.replay(),
            ReplayState::SharedLinearizable { .. }
        ));
        assert!(state.continuation_control().is_shared());
        // Every machine the atlas names is represented exactly once, including the ones
        // that cannot be misconfigured: the value states the whole posture, not the part
        // that needed checking.
        assert!(state.admission().is_enforced());
        assert_eq!(state.audit(), AuditState::Stderr);
        assert_eq!(state.channel_binding(), ChannelBindingState::ExactUriSan);
        assert!(matches!(
            state.crl_revocation(),
            CrlRevocationState::Reloading { .. }
        ));
        assert_eq!(state.retention(), RetentionState::On);
        assert!(state.verified_context().asserts_inner_channel_isolation());
    }
}
