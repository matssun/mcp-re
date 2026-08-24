// SPDX-License-Identifier: Apache-2.0
//! What a deployment asked of a credential, and what an evaluation actually applied.
//!
//! Two types, and they are two because they answer different questions at different times:
//! the policy is a deployment decision made before any request arrives, and the controls
//! are a property of a completed evaluation. They coincide on every success, and that
//! coincidence is a theorem about the evaluator rather than an identity between the types —
//! the same separation `CertificateIdentityPolicy` and `CertificateIdentitySource` keep one
//! authority over.

use std::sync::Arc;
use std::time::Duration;

use crate::client_revocation::ClientRevocationIndex;

/// The per-request currency controls a deployment configured.
///
/// A TOTAL classification of the deployment state, with no `Option` and no illegal
/// combination: every deployment is exactly one of these four, and *evaluating with nothing
/// configured* — the state two `Option`s would admit — cannot be written.
///
/// The revocation index is the SNAPSHOT in force for this request, not the atomic cell it
/// was loaded from. The cell is reloaded behind the serving path; a policy holding the cell
/// would let two checks in one request read two different indexes.
#[derive(Debug, Clone)]
pub enum CredentialCurrencyPolicy {
    /// Neither control is configured, so currency is NOT evaluated — see the module
    /// documentation for what that costs.
    NotEvaluated,
    /// A maximum certificate span, and no CRLs.
    Ceiling(Duration),
    /// CRLs, and no span ceiling.
    Revocation(Arc<ClientRevocationIndex>),
    /// Both.
    CeilingAndRevocation(Duration, Arc<ClientRevocationIndex>),
}

impl CredentialCurrencyPolicy {
    /// The configured maximum certificate span, if any.
    pub(crate) fn ceiling(&self) -> Option<Duration> {
        match self {
            CredentialCurrencyPolicy::Ceiling(ceiling)
            | CredentialCurrencyPolicy::CeilingAndRevocation(ceiling, _) => Some(*ceiling),
            CredentialCurrencyPolicy::NotEvaluated | CredentialCurrencyPolicy::Revocation(_) => {
                None
            }
        }
    }

    /// The revocation index in force, if any.
    pub(crate) fn revocation(&self) -> Option<&ClientRevocationIndex> {
        match self {
            CredentialCurrencyPolicy::Revocation(index)
            | CredentialCurrencyPolicy::CeilingAndRevocation(_, index) => Some(index),
            CredentialCurrencyPolicy::NotEvaluated | CredentialCurrencyPolicy::Ceiling(_) => None,
        }
    }

    /// Which controls this policy applies, or `None` where it applies none.
    ///
    /// The validity window is not listed because it is not optional: it runs whenever ANY
    /// control is configured. Fusing it to the ceiling once made a CRL-only deployment stop
    /// re-checking expiry at all.
    pub(crate) fn controls(&self) -> Option<CurrencyControls> {
        match self {
            CredentialCurrencyPolicy::NotEvaluated => None,
            CredentialCurrencyPolicy::Ceiling(_) => Some(CurrencyControls::Lifetime),
            CredentialCurrencyPolicy::Revocation(_) => Some(CurrencyControls::Revocation),
            CredentialCurrencyPolicy::CeilingAndRevocation(_, _) => {
                Some(CurrencyControls::LifetimeAndRevocation)
            }
        }
    }
}

/// Which optional controls an evaluation applied, carried by its result so a consumer can
/// tell a revocation-checked admission from a span-checked one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurrencyControls {
    /// The span ceiling, plus the always-on validity window.
    Lifetime,
    /// Revocation, plus the always-on validity window.
    Revocation,
    /// Both, plus the always-on validity window.
    LifetimeAndRevocation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_policy_states_exactly_which_controls_it_applies() {
        // A conversion that dropped a case would silently stop applying a control while
        // still reporting the deployment as evaluated, so all four are enumerated.
        let ceiling = Duration::from_secs(3600);
        let index = || Arc::new(ClientRevocationIndex::empty());

        let none = CredentialCurrencyPolicy::NotEvaluated;
        assert_eq!(none.controls(), None);
        assert_eq!(none.ceiling(), None);
        assert!(none.revocation().is_none());

        let only_ceiling = CredentialCurrencyPolicy::Ceiling(ceiling);
        assert_eq!(only_ceiling.controls(), Some(CurrencyControls::Lifetime));
        assert_eq!(only_ceiling.ceiling(), Some(ceiling));
        assert!(only_ceiling.revocation().is_none());

        let only_crl = CredentialCurrencyPolicy::Revocation(index());
        assert_eq!(only_crl.controls(), Some(CurrencyControls::Revocation));
        assert_eq!(only_crl.ceiling(), None);
        assert!(only_crl.revocation().is_some());

        let both = CredentialCurrencyPolicy::CeilingAndRevocation(ceiling, index());
        assert_eq!(
            both.controls(),
            Some(CurrencyControls::LifetimeAndRevocation)
        );
        assert_eq!(both.ceiling(), Some(ceiling));
        assert!(both.revocation().is_some());
    }

    #[test]
    fn only_the_unevaluated_policy_applies_no_controls() {
        // `controls()` returning `None` is what the evaluator reads as "nobody asked". A
        // policy that configured something and answered `None` here would silently skip
        // every check while reporting a deployment as unexamined.
        let configured = [
            CredentialCurrencyPolicy::Ceiling(Duration::from_secs(1)),
            CredentialCurrencyPolicy::Revocation(Arc::new(ClientRevocationIndex::empty())),
            CredentialCurrencyPolicy::CeilingAndRevocation(
                Duration::from_secs(1),
                Arc::new(ClientRevocationIndex::empty()),
            ),
        ];
        for policy in configured {
            assert!(
                policy.controls().is_some(),
                "{policy:?} configures a control"
            );
        }
    }
}
