// SPDX-License-Identifier: Apache-2.0
//! Where this sidecar's listener is exposed — and nothing else.
//!
//! Its own authority because one operator input used to govern two independent facts.
//! `local.allow_non_loopback` was wired straight through to `allow_any_host`, so:
//!
//!   * an operator who legitimately binds off-host thereby disabled the `Host`-authority
//!     guard entirely, and a DNS-rebound page reached the signing key on a deployment that
//!     had never asked for that;
//!   * an operator who set the flag for the BIND reason lost the rebinding guard silently,
//!     because nothing in the field's name or documentation said it did two things.
//!
//! Two facts, so two values. This one answers *where is the listener exposed*. Which HTTP
//! authority names may reach signing is a different question with a different answer, and
//! it is [`crate::serve::AcceptedHttpAuthority`]'s — derived from this value, never from
//! the flag, so the conflation cannot be rebuilt by a caller.
//!
//! The refusal lives in the constructor rather than beside it. A `BindScope` in hand means
//! the bind was permitted: there is no way to obtain one for an off-host address the
//! operator did not ask for, and no check elsewhere that could be deleted to change that.

use std::net::SocketAddr;

use super::err;
use super::ConfigError;

/// A listener address the deployment is permitted to bind.
///
/// The representation is private and there is one constructor, so possession is the proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindScope {
    address: SocketAddr,
    /// True only for an address off this host, which [`BindScope::decide`] admits only
    /// against an explicit operator declaration.
    exposed: bool,
}

impl BindScope {
    /// Decide the scope, refusing an off-host bind the operator did not ask for.
    pub fn decide(address: SocketAddr, allow_non_loopback: bool) -> Result<Self, ConfigError> {
        let exposed = !address.ip().is_loopback();
        if exposed && !allow_non_loopback {
            return Err(err(format!(
                "local.bind {address} is not a loopback address. The local leg is \
                 unauthenticated, so binding it off-host offers this client's signing \
                 key as a service to the network. Set local.allow_non_loopback if that \
                 is genuinely intended."
            )));
        }
        Ok(Self { address, exposed })
    }

    /// The address a `Host` header may legitimately name BESIDES the loopback literals,
    /// or `None` when the listener is on loopback and nothing else can name it.
    ///
    /// The one projection the authority policy needs. Deliberately not `address()` plus
    /// `is_exposed()`: handing out both would let a caller recombine them into the
    /// "off-host, therefore any host" inference this type exists to remove.
    pub fn exposed_authority(&self) -> Option<SocketAddr> {
        self.exposed.then_some(self.address)
    }

    /// The address to listen on.
    pub fn listen_address(&self) -> SocketAddr {
        self.address
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_off_host_bind_needs_the_operators_declaration() {
        let exposed: SocketAddr = "0.0.0.0:8640".parse().expect("an address");
        assert!(BindScope::decide(exposed, false).is_err());
        assert!(BindScope::decide(exposed, true).is_ok());
    }

    #[test]
    fn a_loopback_bind_needs_nothing_and_the_flag_does_not_change_it() {
        for text in ["127.0.0.1:8640", "[::1]:8640"] {
            let address: SocketAddr = text.parse().expect("an address");
            for declared in [false, true] {
                let scope = BindScope::decide(address, declared).expect("loopback is admitted");
                assert_eq!(
                    scope.exposed_authority(),
                    None,
                    "{text} names this host, so nothing else may name the listener \
                     — and the declaration is about the BIND, not about who may reach it",
                );
            }
        }
    }

    /// The conflation, stated as the property that removes it: a permitted off-host bind
    /// widens the authority set by exactly ONE address, not to everything.
    #[test]
    fn an_exposed_bind_names_one_further_authority_and_no_more() {
        let address: SocketAddr = "198.51.100.7:8640".parse().expect("an address");
        let scope = BindScope::decide(address, true).expect("declared");
        assert_eq!(scope.exposed_authority(), Some(address));
        assert_eq!(scope.listen_address(), address);
    }
}
