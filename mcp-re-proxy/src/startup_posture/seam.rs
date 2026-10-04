// SPDX-License-Identifier: Apache-2.0
//! The optional capabilities a startup transcript must account for.

/// An optional capability whose presence or absence changes what this deployment
/// enforces, stores or attributes.
///
/// A seam belongs here when an operator can be surprised by it being off. Capabilities
/// that are always on, and configuration that only tunes an always-on capability, do
/// not — this is the set of *questions a transcript reader can have*, not an inventory
/// of flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seam {
    /// ADR-MCPS-035: the per-request accepted/rejected/signed attribution record.
    SecurityAuditRecord,
    /// ADR-MCPRE-054: retention of the full request and response of accepted calls.
    EvidenceRetention,
    /// #415 §10: whether the PEP writes its resolved actor into the forwarded body.
    VerifiedContextCarrier,
    /// §4.1: required MCP transport headers and `Mcp-Name` / `params.name` agreement.
    McpTransportContract,
    /// #4030: online OCSP client-certificate revocation.
    OnlineOcspClientRevocation,
    /// ADR-MCPS-047: the shared store that makes multi-round-trip flows cross-replica.
    MrtrContinuationStore,
    /// MCPRE-493 §7: the admission-currency gate over the shared authoritative record.
    AdmissionCurrency,
    /// ADR-MCPRE-065: the authorization authority this deployment decides MAY-ACT with.
    Authorization,
}

impl Seam {
    /// Every seam, in no particular order — `assert_complete` checks membership, and
    /// the transcript order is the decision order at the call sites.
    pub const ALL: &'static [Seam] = &[
        Seam::SecurityAuditRecord,
        Seam::EvidenceRetention,
        Seam::VerifiedContextCarrier,
        Seam::McpTransportContract,
        Seam::OnlineOcspClientRevocation,
        Seam::MrtrContinuationStore,
        Seam::AdmissionCurrency,
        Seam::Authorization,
    ];
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::Seam;

    /// The successor of `seam` in declaration order. Every variant needs an arm here or
    /// this module does not compile, and the natural arm for a new variant links it into
    /// the walk the test compares against `Seam::ALL`.
    fn after(seam: Option<Seam>) -> Option<Seam> {
        match seam {
            None => Some(Seam::SecurityAuditRecord),
            Some(Seam::SecurityAuditRecord) => Some(Seam::EvidenceRetention),
            Some(Seam::EvidenceRetention) => Some(Seam::VerifiedContextCarrier),
            Some(Seam::VerifiedContextCarrier) => Some(Seam::McpTransportContract),
            Some(Seam::McpTransportContract) => Some(Seam::OnlineOcspClientRevocation),
            Some(Seam::OnlineOcspClientRevocation) => Some(Seam::MrtrContinuationStore),
            Some(Seam::MrtrContinuationStore) => Some(Seam::AdmissionCurrency),
            Some(Seam::AdmissionCurrency) => Some(Seam::Authorization),
            Some(Seam::Authorization) => None,
        }
    }

    /// `assert_complete` checks membership against `ALL`, so a seam missing from it is a
    /// capability a deployment can install without the transcript ever mentioning it.
    #[test]
    fn every_seam_is_in_the_set_the_transcript_is_checked_against() {
        let mut walked = Vec::new();
        let mut cursor = after(None);
        while let Some(seam) = cursor {
            assert!(walked.len() < 64, "the walk over Seam does not terminate");
            walked.push(seam);
            cursor = after(Some(seam));
        }
        for seam in &walked {
            assert!(Seam::ALL.contains(seam), "{seam:?} is not in Seam::ALL");
        }
        for seam in Seam::ALL {
            assert!(walked.contains(seam), "{seam:?} is not reached by the walk");
        }
        assert_eq!(walked.len(), Seam::ALL.len());
        for (i, seam) in walked.iter().enumerate() {
            assert!(!walked[..i].contains(seam), "{seam:?} repeats in the walk");
        }
    }
}
