// SPDX-License-Identifier: Apache-2.0
//! The classified legal deployment state — layer A of `work/CONFIG-STATE-ATLAS.md`.
//!
//! `Config` describes a *requested* deployment. Not every combination of its fields
//! describes a deployment that could exist, and the atlas is the closed model of the ones
//! that can: eleven machines, each with its own states, and a small set of relations
//! between them. This module is that model as code — one classifier/validator per machine, and one
//! value carrying what they recognised.
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
//! **Semantic classification is not a normalized plan.** The state enums stay small: they
//! name which state was requested and hold nothing else. The cadence, the URL and the key
//! stay in the validated `Config`, where the owning machine checked them against that
//! state's four columns. Planning reads the pair and produces the plan.

pub mod admission;
pub mod continuation_control;
pub(crate) mod cross_machine;
pub mod custody;
pub mod evidence;
pub mod replay;
pub mod tls_custody;
pub mod transport;
pub mod trust_revocation;

pub use admission::AdmissionState;
pub use continuation_control::ContinuationControlState;
pub use custody::CustodyState;
pub use evidence::{AuditState, RetentionState, VerifiedContextState};
pub use replay::ReplayState;
pub use tls_custody::TlsCustodyState;
pub use transport::{ChannelBindingState, CrlRevocationState};
pub use trust_revocation::TrustRevocationState;

/// Which state each configuration machine was recognised to be in.
///
/// Built only by a successful validation, so holding one is evidence that every state
/// here was checked against its own required/optional/forbidden/guard columns and that
/// the cross-machine relations hold between them.
///
/// It grows one field per machine as the atlas's machines are implemented; a machine that
/// is not here yet is one whose legality still lives in the residual clause list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentConfigState {
    admission: AdmissionState,
    audit: AuditState,
    channel_binding: ChannelBindingState,
    continuation_control: ContinuationControlState,
    crl_revocation: CrlRevocationState,
    custody: CustodyState,
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
    pub fn crl_revocation(&self) -> CrlRevocationState {
        self.crl_revocation
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
            continuation_control: ContinuationControlState::Redis,
            crl_revocation: CrlRevocationState::Reloading,
            custody: CustodyState::Pkcs11,
            replay: ReplayState::SharedLinearizable,
            retention: RetentionState::On,
            tls_custody: TlsCustodyState::Delegated,
            trust_revocation: TrustRevocationState::PushNetworked { t_secs: 30 },
            verified_context: VerifiedContextState::Trusted,
        });
        assert!(state.trust_revocation().has_networked_epoch());
        assert!(state.custody().is_non_exporting_device());
        assert!(state.tls_custody().is_delegated());
        // CF-12's negative control, at the level of the value itself: a linearizable
        // replay store and a shared continuation store are independently expressible.
        assert_eq!(state.replay(), &ReplayState::SharedLinearizable);
        assert!(state.continuation_control().is_shared());
        // Every machine the atlas names is represented exactly once, including the ones
        // that cannot be misconfigured: the value states the whole posture, not the part
        // that needed checking.
        assert!(state.admission().is_enforced());
        assert_eq!(state.audit(), AuditState::Stderr);
        assert_eq!(state.channel_binding(), ChannelBindingState::ExactUriSan);
        assert_eq!(state.crl_revocation(), CrlRevocationState::Reloading);
        assert_eq!(state.retention(), RetentionState::On);
        assert!(state.verified_context().asserts_inner_channel_isolation());
    }
}
