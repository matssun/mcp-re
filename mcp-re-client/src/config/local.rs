// SPDX-License-Identifier: Apache-2.0
//! The local, plain-MCP leg of the sidecar, as the operator writes it.
//!
//! Its own file because it is the document half of a pair: this is what an operator
//! states, and [`super::BindScope`] is what the deployment may then do with it. Keeping
//! the two next to each other is what makes it visible that `allow_non_loopback` answers
//! ONE of the questions here and not two — it used to answer both, silently.

use std::net::SocketAddr;

use serde::Deserialize;
use serde::Serialize;

/// The local, plain-MCP leg.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalConfig {
    /// Where to accept plain MCP. Loopback unless `allow_non_loopback` says otherwise.
    pub bind: SocketAddr,
    /// Admit a NON-loopback bind address.
    ///
    /// The local leg is unauthenticated by construction — that is the point of the
    /// sidecar, the local client speaks ordinary MCP and holds no key. So anything that
    /// can reach this socket gets requests signed with this client's key, under this
    /// client's identity, against every configured route. On loopback that set is
    /// "processes on this host"; on `0.0.0.0` it is the network.
    ///
    /// Defaulting to refuse costs an operator one field in the one deployment that
    /// genuinely fronts this with its own authenticated hop, and costs nothing in the
    /// far more common one where `0.0.0.0` was copied from the server's config.
    ///
    /// It governs the BIND and nothing else — see [`BindScope`].
    #[serde(default)]
    pub allow_non_loopback: bool,
    /// How long a signed request stays fresh, seconds (RFC 9421 `expires - created`).
    #[serde(default = "default_request_lifetime")]
    pub request_lifetime_secs: i64,
    /// The route to use for a request whose path is not `/route/<id>`, for clients that
    /// POST to a fixed path. Absent means every request must name its route.
    #[serde(default)]
    pub default_route: Option<String>,
    /// How many local requests may be in flight at once. Beyond it the listener answers
    /// 503 rather than spawning without bound.
    #[serde(default = "default_max_in_flight")]
    pub max_in_flight: usize,
}

fn default_max_in_flight() -> usize {
    64
}

fn default_request_lifetime() -> i64 {
    60
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_bounds_have_defaults_and_the_security_switch_does_not_default_open() {
        let local: LocalConfig =
            serde_json::from_str(r#"{"bind":"127.0.0.1:8640"}"#).expect("a minimal document");
        assert_eq!(local.request_lifetime_secs, 60);
        assert_eq!(local.max_in_flight, 64);
        assert!(
            !local.allow_non_loopback,
            "an unstated off-host declaration is a refusal, never a permission",
        );
        assert_eq!(local.default_route, None);
    }

    /// A misspelled security switch must never read as "off" while the operator believes
    /// it is on — which is what `deny_unknown_fields` is here for.
    #[test]
    fn a_misspelled_field_is_a_startup_failure_not_a_silent_default() {
        let misspelled = r#"{"bind":"127.0.0.1:8640","allow_nonloopback":true}"#;
        assert!(serde_json::from_str::<LocalConfig>(misspelled).is_err());
    }

    #[test]
    fn a_bind_that_is_not_an_address_is_refused_by_the_type() {
        assert!(serde_json::from_str::<LocalConfig>(r#"{"bind":"localhost"}"#).is_err());
    }
}
