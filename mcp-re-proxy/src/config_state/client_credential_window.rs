// SPDX-License-Identifier: Apache-2.0
//! How long a client credential authorizes a connection, as one owned fact.
//!
//! Two durations decide the same thing, and only together:
//!
//! ```text
//!     --max-client-cert-lifetime ──┐
//!                                  ├──▶ ClientCredentialWindow ──▶ exposure window
//!     --max-connection-age-secs ───┘
//! ```
//!
//! Mode A's revocation posture IS the short-lived certificate: with no online OCSP, a
//! compromised client certificate stays usable until it expires, so the proxy bounds the
//! lifetime and then bounds how long one connection may live on a single handshake. The
//! second bound is what makes the first a statement about REQUESTS rather than about
//! handshakes — the certificate is checked when the connection is established, so a peer
//! that never reconnects is never re-checked.
//!
//! # The relation, over the values the deployment actually chose
//!
//! > A connection may not outlive the credential that authenticated it.
//!
//! That sentence was already in the codebase, as relation X5's refusal text. It was not
//! what X5 checked. X5 compared the connection age against the ceiling CONSTANT, so a
//! deployment naming `--max-client-cert-lifetime 600 --max-connection-age-secs 3000` was
//! accepted, and a connection outlived its credential by forty minutes while the startup
//! transcript reported an exposure window of 600s. Both halves were separately bounded,
//! and nothing related them.
//!
//! This owner states the relation over the chosen values, and construction enforces it.
//! Possessing a `ClientCredentialWindow` is the statement that a connection cannot outlive
//! the credential — with no trailing clause about which validator ran.
//!
//! # Why `Duration` and not `Option<Duration>`
//!
//! Disabling either bound is refused, so `None` is a request the boundary rejects rather
//! than a posture a deployment can be in. Holding non-optional durations is what makes the
//! plane's `unbounded` and `none` rendering arms unreachable — they were only ever printed
//! for a configuration that never starts.

use std::time::Duration;

use crate::config_state::transport::MAX_CLIENT_CERT_LIFETIME;
use crate::deployment_request::DeploymentRequest;

/// The window within which a client credential authorizes traffic.
///
/// The representation is private to this module and both bounds are non-optional, so an
/// inhabitant means: enforcement is on for both, the lifetime is within the project
/// ceiling, and the connection age does not exceed the lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientCredentialWindow {
    cert_lifetime: Duration,
    connection_age: Duration,
}

impl ClientCredentialWindow {
    /// The only public constructor, and it performs every check.
    ///
    /// `None` when enforcement is disabled on either side, when the lifetime exceeds the
    /// ceiling, or when a connection could outlive the credential. Construction validates,
    /// so the guarantee travels with the value rather than with the classifier that
    /// usually produces it.
    pub fn new(cert_lifetime: Duration, connection_age: Duration) -> Option<Self> {
        if cert_lifetime.is_zero() || connection_age.is_zero() {
            return None;
        }
        if cert_lifetime > MAX_CLIENT_CERT_LIFETIME {
            return None;
        }
        if connection_age > cert_lifetime {
            return None;
        }
        Some(Self {
            cert_lifetime,
            connection_age,
        })
    }

    /// The bounded client-certificate lifetime.
    pub fn cert_lifetime(&self) -> Duration {
        self.cert_lifetime
    }

    /// How long one connection may serve requests on a single handshake.
    pub fn connection_age(&self) -> Duration {
        self.connection_age
    }

    /// The operator-facing exposure window: how long a compromised client credential can
    /// still be used.
    ///
    /// It is the certificate lifetime, and it is honest ONLY because the connection age is
    /// bounded by it — which this value guarantees rather than assumes. Named as its own
    /// projection so the audit line asks for the claim instead of picking one of two
    /// durations and hoping it is the right one.
    pub fn exposure_window(&self) -> Duration {
        self.cert_lifetime
    }
}

/// Resolve the window, or say which half of it the deployment broke.
///
/// Both guards moved here — the lifetime's from the validation residue, the connection
/// age's from cross-machine relation X5 — because they were two statements about one fact.
/// Each refusal still names the flag an operator can act on, and the relation names both.
pub fn classify_and_validate(
    config: &DeploymentRequest,
) -> (Option<ClientCredentialWindow>, Vec<String>) {
    let mut violations = Vec::new();
    let lifetime = match config.max_client_cert_lifetime {
        None => {
            violations.push(
                "--max-client-cert-lifetime none/0 disables client-cert lifetime enforcement; \
                 set a bounded lifetime (default 1h)"
                    .to_string(),
            );
            None
        }
        Some(lifetime) if lifetime > MAX_CLIENT_CERT_LIFETIME => {
            violations.push(format!(
                "--max-client-cert-lifetime {}s exceeds the ceiling of {}s: Mode-A's \
                 revocation posture is short-lived certificates, so a longer lifetime cannot be \
                 audited as short_lived_cert; set a lifetime <= {}s",
                lifetime.as_secs(),
                MAX_CLIENT_CERT_LIFETIME.as_secs(),
                MAX_CLIENT_CERT_LIFETIME.as_secs(),
            ));
            None
        }
        Some(lifetime) => Some(lifetime),
    };
    let age = match config.limits.max_connection_age {
        None => {
            violations.push(
                "--max-connection-age-secs 0 disables the connection-age bound: the client \
                 certificate is validated only at the handshake, so a peer that never \
                 reconnects is never re-checked against an expiry or a reloaded CRL. Set a \
                 bounded age (default 300s)"
                    .to_string(),
            );
            None
        }
        Some(age) => Some(age),
    };

    // The relation, asked of the two values the deployment chose. Only reachable when both
    // halves are individually legal — a deployment that disabled one is already refused,
    // and adding "and they disagree" to that would name a remedy the boundary also refuses.
    let (Some(lifetime), Some(age)) = (lifetime, age) else {
        return (None, violations);
    };
    let Some(window) = ClientCredentialWindow::new(lifetime, age) else {
        violations.push(format!(
            "--max-connection-age-secs {}s exceeds --max-client-cert-lifetime {}s: a \
             connection would outlive the credential that authenticated it, because the \
             client certificate is checked at the handshake and never again on that \
             connection",
            age.as_secs(),
            lifetime.as_secs(),
        ));
        return (None, violations);
    };
    (Some(window), violations)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(lifetime_secs: u64, age_secs: u64) -> (Option<ClientCredentialWindow>, Vec<String>) {
        let mut config = crate::config_state::test_support::legal_config();
        config.max_client_cert_lifetime = Some(Duration::from_secs(lifetime_secs));
        config.limits.max_connection_age = Some(Duration::from_secs(age_secs));
        classify_and_validate(&config)
    }

    /// THE invariant, and the defect that motivated the owner.
    ///
    /// Before this, both bounds were checked against the CONSTANT ceiling and never against
    /// each other, so this exact deployment was accepted: a connection lived forty minutes
    /// past the expiry of the certificate that authenticated it, while the startup
    /// transcript reported `exposure_window=600s`.
    #[test]
    fn a_connection_may_not_outlive_the_credential_that_authenticated_it() {
        let (window, violations) = window(600, 3000);
        assert!(window.is_none(), "the pair must not resolve a window");
        assert!(
            violations
                .iter()
                .any(|v| v.contains("would outlive the credential")),
            "got: {violations:?}"
        );
    }

    /// The relation holds at the boundary as well as at the edges.
    #[test]
    fn an_age_equal_to_the_lifetime_is_the_last_legal_pair() {
        assert!(window(600, 600).0.is_some(), "equal is not longer");
        assert!(window(600, 601).0.is_none(), "one second longer is longer");
    }

    /// The two projections come from one owned pair, so the exposure window cannot be
    /// reported from a lifetime the connection age contradicts.
    #[test]
    fn the_exposure_window_is_the_lifetime_the_connection_age_respects() {
        let w = window(3600, 300).0.expect("the default posture resolves");
        assert_eq!(w.cert_lifetime(), Duration::from_secs(3600));
        assert_eq!(w.connection_age(), Duration::from_secs(300));
        assert_eq!(w.exposure_window(), w.cert_lifetime());
        assert!(w.connection_age() <= w.exposure_window());
    }

    /// Disabling either half resolves no window, and each refusal names its own flag.
    #[test]
    fn disabling_either_bound_resolves_no_window() {
        let mut config = crate::config_state::test_support::legal_config();
        config.max_client_cert_lifetime = None;
        let (w, v) = classify_and_validate(&config);
        assert!(w.is_none());
        assert!(v.iter().any(|m| m.contains("--max-client-cert-lifetime")));

        let mut config = crate::config_state::test_support::legal_config();
        config.limits.max_connection_age = None;
        let (w, v) = classify_and_validate(&config);
        assert!(w.is_none());
        assert!(v.iter().any(|m| m.contains("--max-connection-age-secs")));
    }

    /// A lifetime past the ceiling resolves no window, and the relation is not also
    /// reported — an operator meets one clause per defect.
    #[test]
    fn a_lifetime_past_the_ceiling_resolves_no_window() {
        let (w, v) = window(MAX_CLIENT_CERT_LIFETIME.as_secs() + 1, 300);
        assert!(w.is_none());
        assert!(v.iter().any(|m| m.contains("exceeds the ceiling")));
        assert!(
            !v.iter().any(|m| m.contains("would outlive")),
            "the relation is unanswerable while a half is illegal: {v:?}"
        );
    }

    /// The public constructor carries every check, so no crate can hold a window whose
    /// connection age outlives its credential.
    #[test]
    fn the_public_constructor_validates_too() {
        assert!(
            ClientCredentialWindow::new(Duration::from_secs(600), Duration::from_secs(3000))
                .is_none()
        );
        assert!(ClientCredentialWindow::new(
            MAX_CLIENT_CERT_LIFETIME + Duration::from_secs(1),
            Duration::from_secs(300)
        )
        .is_none());
        assert!(
            ClientCredentialWindow::new(Duration::from_secs(0), Duration::from_secs(0)).is_none()
        );
        assert!(
            ClientCredentialWindow::new(Duration::from_secs(600), Duration::from_secs(300))
                .is_some()
        );
    }
}
