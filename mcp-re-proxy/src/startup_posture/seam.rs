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

    /// `assert_complete` checks membership against `ALL`, so a seam missing from it is a
    /// capability a deployment can install without the transcript ever mentioning it.
    #[test]
    fn every_seam_is_in_the_set_the_transcript_is_checked_against() {
        for seam in [
            Seam::SecurityAuditRecord,
            Seam::EvidenceRetention,
            Seam::VerifiedContextCarrier,
            Seam::McpTransportContract,
            Seam::OnlineOcspClientRevocation,
            Seam::MrtrContinuationStore,
            Seam::AdmissionCurrency,
            Seam::Authorization,
        ] {
            assert!(Seam::ALL.contains(&seam), "{seam:?} is not in Seam::ALL");
        }
    }
}
