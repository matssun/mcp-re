// SPDX-License-Identifier: Apache-2.0
//! The `Audit`, `Retention` and `VerifiedContext` machines —
//! `work/CONFIG-STATE-ATLAS.md` §C.6.
//!
//! Three two-state machines over what a deployment records and what it asserts. They share
//! a file because each is a single selector with no parameters and no guards; giving each
//! its own file would imply a structure that is not there.
//!
//! None of them can be misconfigured — every state form is legal and none has a required,
//! forbidden or numeric column. **That is the finding, not an omission.** Classifying them
//! anyway is what makes `DeploymentConfigState` a complete statement about the deployment
//! rather than a record of the parts that happened to need checking, and it is why a later
//! stage can read the posture off the classification instead of re-reading the field.

use crate::cli::{AuditSinkKind, Config, VerifiedContextKind};

/// Where the per-request security record goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditState {
    /// No per-request attribution is written.
    None,
    /// One structured record per decision, on the diagnostic channel.
    Stderr,
}

/// Whether full request and response messages are retained for later SCITT statements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionState {
    /// Nothing is retained; the request path is unchanged.
    Off,
    /// Exchanges are retained to a directory — a data-retention decision, so it is named
    /// rather than derived from another flag.
    On,
}

/// What the PEP asserts to the inner server about the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedContextState {
    /// The stripped body is forwarded with no verified context.
    Disabled,
    /// The PEP's verified context is written into the forwarded body. Selecting this
    /// ASSERTS that nothing but this PEP can reach the inner server: the carrier is
    /// unsigned, so the channel is the only thing making it trustworthy, and no
    /// configuration check can confirm that property.
    Trusted,
}

impl VerifiedContextState {
    /// Whether the deployment asserts an unverifiable property of the inner channel.
    pub fn asserts_inner_channel_isolation(&self) -> bool {
        matches!(self, Self::Trusted)
    }
}

/// Classify the evidence machines. Each is total, and none has columns to check.
pub fn classify(config: &Config) -> (AuditState, RetentionState, VerifiedContextState) {
    let audit = match config.audit_sink {
        AuditSinkKind::None => AuditState::None,
        AuditSinkKind::Stderr => AuditState::Stderr,
    };
    let retention = if config.retained_evidence_dir.is_some() {
        RetentionState::On
    } else {
        RetentionState::Off
    };
    let verified_context = match config.verified_context {
        VerifiedContextKind::Disabled => VerifiedContextState::Disabled,
        VerifiedContextKind::Trusted => VerifiedContextState::Trusted,
    };
    (audit, retention, verified_context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;

    fn states(
        mutate: impl FnOnce(&mut Config),
    ) -> (AuditState, RetentionState, VerifiedContextState) {
        let mut config = legal_config();
        mutate(&mut config);
        classify(&config)
    }

    #[test]
    fn every_legal_state_form_is_classified() {
        assert_eq!(
            states(|c| {
                c.audit_sink = AuditSinkKind::None;
                c.retained_evidence_dir = None;
                c.verified_context = VerifiedContextKind::Disabled;
            }),
            (
                AuditState::None,
                RetentionState::Off,
                VerifiedContextState::Disabled
            )
        );
        assert_eq!(
            states(|c| {
                c.audit_sink = AuditSinkKind::Stderr;
                c.retained_evidence_dir = Some("/evidence".to_string());
                c.verified_context = VerifiedContextKind::Trusted;
            }),
            (
                AuditState::Stderr,
                RetentionState::On,
                VerifiedContextState::Trusted
            )
        );
    }

    /// Retention is presence-selected, so the locator IS the selector: there is no separate
    /// on/off flag that could disagree with the directory.
    #[test]
    fn retention_is_selected_by_its_own_locator() {
        assert_eq!(
            states(|c| c.retained_evidence_dir = None).1,
            RetentionState::Off
        );
        assert_eq!(
            states(|c| c.retained_evidence_dir = Some("/evidence".to_string())).1,
            RetentionState::On
        );
    }

    #[test]
    fn only_the_trusted_context_asserts_something_configuration_cannot_check() {
        assert!(!VerifiedContextState::Disabled.asserts_inner_channel_isolation());
        assert!(VerifiedContextState::Trusted.asserts_inner_channel_isolation());
    }
}
