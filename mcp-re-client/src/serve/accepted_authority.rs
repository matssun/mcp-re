// SPDX-License-Identifier: Apache-2.0
//! Which HTTP authority names may reach the signing key.
//!
//! The half of the browser guard `Origin` does not cover. A page served from
//! `rebound.evil.example`, whose name resolves to `127.0.0.1`, is SAME-origin to the
//! browser and therefore sends no `Origin` at all — but it does send that name as `Host`,
//! and a name it does not control is what it cannot forge.
//!
//! # Why this is not a boolean
//!
//! It was one: `allow_any_host`, wired from `local.allow_non_loopback`. That made a
//! decision about WHERE THE LISTENER IS EXPOSED also decide WHO MAY REACH IT, so an
//! operator who bound off-host for a documented reason turned the rebinding guard off
//! without being told, and every deployment that did so was reachable from any browser
//! page that could resolve a name to its address.
//!
//! The authority set is derived from [`BindScope`] instead — the value that already
//! decides the first fact — and it widens by exactly the listener's own address, never to
//! everything. A caller cannot construct one from the flag, because the constructor does
//! not take the flag.
//!
//! # What it does not claim
//!
//! Nothing about WHO sent an admissible request. There is no local-caller authentication
//! here and none is offered: this decides reachability, not identity. `Origin` is not
//! authenticated either — its mere presence is a refusal, which is a different rule and
//! lives with the other head checks.

use std::net::SocketAddr;

use crate::config::BindScope;

use super::guards::is_loopback_host;

/// The authority names a request may present to reach this listener.
///
/// Private representation with one constructor: the only way to obtain one is from a
/// `BindScope`, so "off-host, therefore any host" is not an inference anything can make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedHttpAuthority {
    /// The listener's own address, when it is not on loopback. `None` means the loopback
    /// literals are the whole set.
    exposed: Option<SocketAddr>,
}

impl AcceptedHttpAuthority {
    /// The names that reach the listener this scope describes.
    pub fn for_listener(scope: &BindScope) -> Self {
        Self {
            exposed: scope.exposed_authority(),
        }
    }

    /// Whether a `Host` header names this listener.
    ///
    /// The loopback literals always, because that is how the local MCP clients spell the
    /// sidecar and no page can claim one as its own name. An exposed listener additionally
    /// answers to its own address — and to nothing else, which is the property a
    /// rebound name fails on a deployment that binds off-host just as it does on loopback.
    pub fn admits(&self, host: &str) -> bool {
        if is_loopback_host(host) {
            return true;
        }
        let Some(address) = self.exposed else {
            return false;
        };
        let host = host.trim();
        // Both spellings of one authority: with the port, and without it. A `Host` naming
        // a DIFFERENT port is a different authority and is not admitted.
        host.eq_ignore_ascii_case(&address.to_string())
            || host.eq_ignore_ascii_case(&address.ip().to_string())
            || bracketed_ipv6(&address).is_some_and(|bare| host.eq_ignore_ascii_case(&bare))
    }
}

/// An IPv6 listener's address without its port, in the bracketed form a `Host` carries.
fn bracketed_ipv6(address: &SocketAddr) -> Option<String> {
    match address {
        SocketAddr::V6(v6) => Some(format!("[{}]", v6.ip())),
        SocketAddr::V4(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(text: &str, declared: bool) -> BindScope {
        BindScope::decide(text.parse().expect("an address"), declared).expect("a legal bind")
    }

    #[test]
    fn a_loopback_listener_answers_to_the_loopback_names_only() {
        let authority = AcceptedHttpAuthority::for_listener(&scope("127.0.0.1:8640", false));
        for host in ["127.0.0.1", "127.0.0.1:8640", "localhost", "[::1]:8640"] {
            assert!(authority.admits(host), "{host} names this host");
        }
        for host in [
            "rebound.evil.example",
            "rebound.evil.example:8640",
            "198.51.100.7",
        ] {
            assert!(
                !authority.admits(host),
                "{host} must not reach the signing key"
            );
        }
    }

    /// THE PROPERTY THAT WAS LOST. `allow_non_loopback` used to disable this check
    /// outright, so a page that could resolve a name to the listener's address obtained
    /// signed, attributed calls under the agent's identity. An exposed listener now
    /// refuses a rebound name exactly as a loopback one does.
    #[test]
    fn an_exposed_listener_still_refuses_a_rebound_name() {
        let authority = AcceptedHttpAuthority::for_listener(&scope("198.51.100.7:8640", true));
        for host in [
            "rebound.evil.example",
            "rebound.evil.example:8640",
            "sidecar.internal",
            "198.51.100.8",
            "198.51.100.7:9",
        ] {
            assert!(
                !authority.admits(host),
                "{host} must not reach the signing key"
            );
        }
    }

    /// The mirror. Without it the control above is satisfied by an authority that admits
    /// nothing, which would break every deployment that legitimately binds off-host.
    #[test]
    fn an_exposed_listener_answers_to_its_own_address() {
        let authority = AcceptedHttpAuthority::for_listener(&scope("198.51.100.7:8640", true));
        for host in ["198.51.100.7", "198.51.100.7:8640", "127.0.0.1"] {
            assert!(authority.admits(host), "{host} names this listener");
        }
    }

    #[test]
    fn an_exposed_ipv6_listener_answers_to_its_bracketed_literal() {
        let authority = AcceptedHttpAuthority::for_listener(&scope("[2001:db8::1]:8640", true));
        for host in ["[2001:db8::1]", "[2001:db8::1]:8640", "[::1]"] {
            assert!(authority.admits(host), "{host} names this listener");
        }
        assert!(!authority.admits("[2001:db8::2]"));
    }
}
