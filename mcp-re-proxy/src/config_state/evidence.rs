// SPDX-License-Identifier: Apache-2.0
//! The `Audit`, `Retention` and `VerifiedContext` machines —
//! `work/CONFIG-STATE-ATLAS.md` §C.6.
//!
//! Three two-state machines over what a deployment records and what it asserts. They share
//! a file because each is a single selector with no guards; giving each its own file would
//! imply a structure that is not there. `Audit` and `VerifiedContext` are selectors whose
//! field IS the state; `Retention` additionally carries the directory whose presence
//! selects it.
//!
//! None of them can be misconfigured — every state form is legal and none has a required,
//! forbidden or numeric column. **That is the finding, not an omission.** Classifying them
//! anyway is what makes `DeploymentConfigState` a complete statement about the deployment
//! rather than a record of the parts that happened to need checking, and it is why a later
//! stage can read the posture off the classification instead of re-reading the field.

use crate::deployment_request::{AuditSinkKind, DeploymentRequest, VerifiedContextKind};

/// Where the per-request security record goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditState {
    /// No per-request attribution is written.
    None,
    /// One structured record per decision, on the diagnostic channel.
    Stderr,
}

/// Whether full request and response messages are retained for later SCITT statements.
///
/// `On` carries the directory that put it in that state. Without it the classification is
/// a verdict whose evidence was thrown away: establishing retention would have to ask
/// `retained_evidence_dir.is_some()` a second time, from a representation still able to
/// say `None`, having already been told the answer.
/// The representation is private to this module and [`classify`] is the only producer, so
/// a consumer cannot name a retention directory this deployment did not configure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionState {
    /// Where retained exchanges are written, or `None` when nothing is retained. Its
    /// presence is what selects the retaining state, so the state that retains carries it.
    directory: Option<String>,
}

impl RetentionState {
    /// Where retained exchanges are written, or `None` when the request path is unchanged.
    ///
    /// The projection a consumer reads instead of the representation: retention is ON
    /// exactly when there is a directory, so the posture and the path are one answer and
    /// cannot be reported inconsistently.
    pub fn directory(&self) -> Option<&str> {
        self.directory.as_deref()
    }

    /// Whether exchanges are retained at all.
    pub fn is_on(&self) -> bool {
        self.directory.is_some()
    }

    /// The non-retaining state, for a consumer that must name the posture it is testing.
    pub fn off() -> Self {
        RetentionState { directory: None }
    }
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
pub fn classify(config: &DeploymentRequest) -> (AuditState, RetentionState, VerifiedContextState) {
    let audit = match config.audit_sink {
        AuditSinkKind::None => AuditState::None,
        AuditSinkKind::Stderr => AuditState::Stderr,
    };
    let retention = match &config.retained_evidence_dir {
        Some(directory) => RetentionState {
            directory: Some(directory.clone()),
        },
        None => RetentionState::off(),
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
        mutate: impl FnOnce(&mut DeploymentRequest),
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
                RetentionState::off(),
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
                RetentionState {
                    directory: Some("/evidence".to_string())
                },
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
            RetentionState::off()
        );
        assert_eq!(
            states(|c| c.retained_evidence_dir = Some("/evidence".to_string()))
                .1
                .directory(),
            Some("/evidence")
        );
    }

    /// The state carries the directory that selected it, so establishing retention has no
    /// second question to ask. Asserted with a path the default fixture does not name.
    #[test]
    fn the_on_state_carries_the_directory_that_selected_it() {
        let state = states(|c| c.retained_evidence_dir = Some("/srv/evidence-7".to_string())).1;
        let directory = state
            .directory()
            .expect("a named directory selects the retaining state");
        assert_eq!(directory, "/srv/evidence-7");
    }

    #[test]
    fn only_the_trusted_context_asserts_something_configuration_cannot_check() {
        assert!(!VerifiedContextState::Disabled.asserts_inner_channel_isolation());
        assert!(VerifiedContextState::Trusted.asserts_inner_channel_isolation());
    }
}
