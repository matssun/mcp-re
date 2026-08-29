// SPDX-License-Identifier: Apache-2.0
//! What this deployment records, and what it forwards about a verified request.

use crate::deployment_request::{AuditSinkKind, VerifiedContextKind};

/// The audit inputs, as they accumulate across the argument list.
#[derive(Default)]
pub(super) struct AuditFlags {
    sink: Option<AuditSinkKind>,
    retained_evidence_dir: Option<String>,
    verified_context: Option<VerifiedContextKind>,
}

/// What one deployment records.
pub(super) struct AuditSurface {
    pub(super) sink: AuditSinkKind,
    pub(super) retained_evidence_dir: Option<String>,
    pub(super) verified_context: VerifiedContextKind,
}

impl AuditFlags {
    /// Whether this value-taking flag belongs to the family.
    pub(super) fn owns(flag: &str) -> bool {
        matches!(
            flag,
            "--audit-sink" | "--retained-evidence-dir" | "--verified-context-carrier"
        )
    }

    /// Read one flag of the family. [`Self::owns`] decided it is one.
    pub(super) fn take(&mut self, flag: &str, value: &str) -> Result<(), String> {
        match flag {
            "--audit-sink" => {
                self.sink = Some(match value {
                    "none" => AuditSinkKind::None,
                    "stderr" => AuditSinkKind::Stderr,
                    other => {
                        return Err(format!("--audit-sink must be none|stderr, got {other:?}"))
                    }
                })
            }
            // ADR-MCPS-035: the per-request security record. Without this the emission
            // points exist and nothing consumes them, so a deployment has no per-request
            // attribution at all.
            "--retained-evidence-dir" => self.retained_evidence_dir = Some(value.to_string()),
            // #415 rev 2 §10: the verified-context carrier. `trusted` asserts that nothing
            // but this PEP can reach the inner server — the carrier is unsigned, so that
            // assertion is the entire basis for the inner server trusting it, and nothing
            // here can check it.
            _ => {
                self.verified_context = Some(match value {
                    "disabled" => VerifiedContextKind::Disabled,
                    "trusted" => VerifiedContextKind::Trusted,
                    other => {
                        return Err(format!(
                            "--verified-context-carrier must be disabled|trusted, got {other:?}"
                        ))
                    }
                })
            }
        }
        Ok(())
    }

    /// What this deployment records. Both selections have a default, and the defaults are
    /// the safe ones: the record is ON unless a deployment names the opposite, and the
    /// unsigned carrier is OFF unless it does.
    pub(super) fn finish(self) -> AuditSurface {
        AuditSurface {
            sink: self.sink.unwrap_or(AuditSinkKind::Stderr),
            retained_evidence_dir: self.retained_evidence_dir,
            verified_context: self
                .verified_context
                .unwrap_or(VerifiedContextKind::Disabled),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defaults are the safe ones, and they are what an absent flag means.
    #[test]
    fn the_defaults_record_and_forward_nothing_unsigned() {
        let surface = AuditFlags::default().finish();
        assert_eq!(surface.sink, AuditSinkKind::Stderr);
        assert_eq!(surface.verified_context, VerifiedContextKind::Disabled);
        assert_eq!(surface.retained_evidence_dir, None);
    }

    /// Each selection is read, and an unknown value is refused rather than defaulted.
    #[test]
    fn an_unknown_selection_is_refused_rather_than_defaulted() {
        let mut flags = AuditFlags::default();
        assert!(flags.take("--audit-sink", "syslog").is_err());
        assert!(flags.take("--verified-context-carrier", "maybe").is_err());
        flags.take("--audit-sink", "none").expect("a known sink");
        flags
            .take("--verified-context-carrier", "trusted")
            .expect("a known carrier");
        let surface = flags.finish();
        assert_eq!(surface.sink, AuditSinkKind::None);
        assert_eq!(surface.verified_context, VerifiedContextKind::Trusted);
    }
}
