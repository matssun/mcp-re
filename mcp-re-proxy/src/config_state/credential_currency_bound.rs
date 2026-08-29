// SPDX-License-Identifier: Apache-2.0
//! What bounds the exposure of a WITHDRAWN peer credential — ADR-MCPRE-067 §5.
//!
//! The semantic posture between the revocation mechanisms and the claim an operator reads.
//! Its question — *how long can a credential that has been withdrawn keep being served on*
//! — is answered by whichever mechanisms a deployment configured, and it survives every one
//! of them being replaced: a mechanism that re-reads a published set on a cadence gives the
//! cadence as the bound whether that set is an X.509 CRL or something not yet invented.
//!
//! Rendering it is a separate job, and a mechanism-specific one: `tls_plane::fleet_crl_bound`
//! turns this posture into the sentence a fleet operator reads, and names CRLs because
//! CRLs are what the sentence tells them to configure.

use crate::config_state::client_credential_window::ClientCredentialWindow;
use crate::config_state::transport::ClientRevocationPlan;

/// What bounds the exposure of a withdrawn peer credential.
///
/// Total over the configured mechanisms, and never zero-window: every arm names something
/// that actually bounds the exposure, so a posture cannot fall through to another's number.
/// A new mechanism adds an arm, and every consumer stops compiling until it states what
/// that mechanism bounds — which is the property this fact most needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialCurrencyBound {
    /// Nothing re-checks a credential after it is accepted, so the credential's own
    /// lifetime is the whole bound.
    CredentialLifetime {
        /// The exposure window, in seconds.
        window_secs: u64,
    },
    /// A published revocation set is re-read on a cadence, and the cadence IS the bound —
    /// per request on established connections as well as at the handshake.
    PublicationRefresh {
        /// Seconds between re-reads.
        cadence_secs: u64,
    },
    /// A published revocation set is read once. The bound is the set's own next-publication
    /// window, or a restart.
    PublicationValidity,
}

/// The bound the configured mechanisms give this deployment.
///
/// Composed from the owners' own projections rather than from their representations: the
/// revocation plan says whether a set is consulted and how often, the credential window
/// says how long a credential authorizes traffic, and this states the relation between
/// them (R-COMPOSE).
pub fn credential_currency_bound(
    revocation: &ClientRevocationPlan,
    window: &ClientCredentialWindow,
) -> CredentialCurrencyBound {
    if !revocation.is_enforced() {
        return CredentialCurrencyBound::CredentialLifetime {
            window_secs: window.exposure_window().as_secs(),
        };
    }
    match revocation.reload_cadence_secs() {
        Some(cadence_secs) => CredentialCurrencyBound::PublicationRefresh { cadence_secs },
        None => CredentialCurrencyBound::PublicationValidity,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::{credential_window, crl_plan};

    /// The three postures, and each names its own bound. The point of the type is that no
    /// posture can borrow another's number.
    #[test]
    fn every_posture_names_what_actually_bounds_the_exposure() {
        let window = credential_window(3600, 300);
        assert_eq!(
            credential_currency_bound(&crl_plan(&[], None), &window),
            CredentialCurrencyBound::CredentialLifetime {
                window_secs: window.exposure_window().as_secs()
            }
        );
        assert_eq!(
            credential_currency_bound(&crl_plan(&["/crl.pem"], Some(60)), &window),
            CredentialCurrencyBound::PublicationRefresh { cadence_secs: 60 }
        );
        assert_eq!(
            credential_currency_bound(&crl_plan(&["/crl.pem"], None), &window),
            CredentialCurrencyBound::PublicationValidity
        );
    }

    /// The replacement negative control: a revocation mechanism this repository does not
    /// have produces one of the same postures, and the consumer of the posture — the thing
    /// that reports a number to an operator — is unchanged.
    #[test]
    fn a_mechanism_that_does_not_exist_produces_the_same_posture() {
        enum HypotheticalMechanism {
            SignedStatusFeed { poll_secs: u64 },
        }
        impl HypotheticalMechanism {
            fn bound(&self) -> CredentialCurrencyBound {
                match self {
                    HypotheticalMechanism::SignedStatusFeed { poll_secs } => {
                        CredentialCurrencyBound::PublicationRefresh {
                            cadence_secs: *poll_secs,
                        }
                    }
                }
            }
        }
        /// The consumer: it reads a bound and names no mechanism.
        fn is_bounded_by_a_refresh(bound: CredentialCurrencyBound) -> bool {
            matches!(bound, CredentialCurrencyBound::PublicationRefresh { .. })
        }
        assert!(is_bounded_by_a_refresh(credential_currency_bound(
            &crl_plan(&["/crl.pem"], Some(60)),
            &credential_window(3600, 300),
        )));
        assert!(is_bounded_by_a_refresh(
            HypotheticalMechanism::SignedStatusFeed { poll_secs: 30 }.bound()
        ));
    }
}
