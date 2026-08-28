// SPDX-License-Identifier: Apache-2.0
//! Connecting only to an address the guard has seen.
//!
//! One fact: **every address a connection is made to has passed
//! [`resolved_ip_is_public`](super::address::resolved_ip_is_public).**
//!
//! # The window this closes
//!
//! [`super::url`]'s host guard inspects a STRING. It blocks a literal private IP and the
//! loopback name; it cannot defend a hostile PUBLIC hostname that RESOLVES to an internal
//! address at fetch time — an attacker rebinds `evil.test` to `169.254.169.254` between the
//! guard and the connect. Pinning the connectable set to vetted addresses removes the TOCTOU
//! window entirely rather than narrowing it.
//!
//! It **fails closed on the whole resolve** if ANY address is non-public. Partial filtering
//! would let a rebinding race pick the internal address out of a mixed answer, so an
//! attacker returning one internal and one public address gets nothing.

use std::net::SocketAddr;

use super::address::resolved_ip_is_public;

/// The DNS resolution seam ([`VettingResolver`] vets whatever this returns). The
/// production implementation defers to the OS resolver via `std`'s
/// `ToSocketAddrs`; tests inject a fixed-address implementation to exercise the
/// rebinding-rejection path WITHOUT real DNS.
pub(super) trait BaseResolver: Send + Sync {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<SocketAddr>>;
}

/// The production base resolver: the OS resolver, exactly as `ureq`'s default
/// `StdResolver` would use. The vetting wrapper is what makes it safe.
pub(super) struct StdBaseResolver;

impl BaseResolver for StdBaseResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
        use std::net::ToSocketAddrs;
        netloc.to_socket_addrs().map(|iter| iter.collect())
    }
}

/// A `ureq` [`Resolver`](ureq::Resolver) that closes the DNS-rebinding hole (#128).
///
/// `pub(super)` because [`super::VettedDestination`] installs it; nothing outside this
/// authority chooses whether a fetch is vetted.
///
/// `ureq` connects to whatever a resolver returns; by pinning that set to ONLY
/// addresses that pass [`resolved_ip_is_public`] — and FAILING CLOSED (an
/// `io::Error`, which surfaces as `OcspError::Http` → `Unknown` → deny under
/// hard-fail) the instant ANY resolved address is non-public — there is no
/// TOCTOU window in which a hostile public hostname can be re-resolved to an
/// internal IP between the syntactic guard and the connect. Reuses the existing
/// public-IP predicates (it does NOT duplicate or relax them). Consistent with
/// the ADR-MCPS-018 lean-sync (blocking `ureq`) firewall: synchronous, no async
/// runtime, no extra network round-trip beyond the resolve itself.
pub(super) struct VettingResolver {
    base: Box<dyn BaseResolver>,
}

impl VettingResolver {
    /// The production resolver: OS resolution, every address vetted.
    pub(super) fn std() -> Self {
        Self {
            base: Box::new(StdBaseResolver),
        }
    }

    /// Resolve `netloc` and return ONLY the vetted addresses, or an error if the
    /// host did not resolve or ANY resolved address is non-public (fail closed).
    fn resolve_vetted(&self, netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
        let addrs = self.base.resolve(netloc)?;
        if addrs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "outbound host did not resolve to any address",
            ));
        }
        // Fail CLOSED on the WHOLE resolve if any address is non-public: an
        // attacker who returns one internal + one public address must not be able
        // to have the internal one connected to, and partial filtering would let a
        // rebinding race pick the internal address. Reject the lot.
        if let Some(bad) = addrs.iter().find(|sa| !resolved_ip_is_public(&sa.ip())) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "outbound host resolved to a non-public address ({}); \
                     refusing to connect (SSRF / DNS-rebinding guard, issue #128)",
                    bad.ip()
                ),
            ));
        }
        Ok(addrs)
    }
}

impl ureq::Resolver for VettingResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
        self.resolve_vetted(netloc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DNS-rebinding regression (#128): a hostile PUBLIC hostname that passes the
    /// syntactic AIA guard but RESOLVES to an internal address at fetch time must be
    /// rejected at resolve/connect time by [`super::VettingResolver`], which
    /// re-applies the public-IP predicates to the RESOLVED address and fails CLOSED.
    /// A fixed-address base resolver is injected (the test seam) so no real DNS is
    /// used: each internal target (`127.0.0.1` loopback, `169.254.169.254` cloud
    /// metadata) must yield an `Err`, while a public address must yield `Ok`.
    ///
    /// WITHOUT the guard (`VettingResolver` returning the addresses unfiltered) the
    /// internal cases would return `Ok` and `ureq` would connect to the internal IP —
    /// the very SSRF the fix closes; this asserts they are rejected instead.
    #[test]
    fn vetting_resolver_rejects_rebinding_to_internal_addresses() {
        use std::net::SocketAddr;

        /// A base resolver that ignores the hostname and returns a fixed address —
        /// the injectable seam standing in for a hostile/rebinding DNS answer.
        struct FixedResolver(SocketAddr);
        impl BaseResolver for FixedResolver {
            fn resolve(&self, _netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
                Ok(vec![self.0])
            }
        }
        fn resolver_for(addr: &str) -> VettingResolver {
            VettingResolver {
                base: Box::new(FixedResolver(addr.parse().expect("test addr"))),
            }
        }

        // Loopback — the public hostname "rebinds" to 127.0.0.1.
        assert!(
            resolver_for("127.0.0.1:80")
                .resolve_vetted("ocsp.evil.test:80")
                .is_err(),
            "a host resolving to 127.0.0.1 must be REJECTED at resolve time"
        );
        // Cloud metadata endpoint — the classic rebinding SSRF target.
        assert!(
            resolver_for("169.254.169.254:80")
                .resolve_vetted("ocsp.evil.test:80")
                .is_err(),
            "a host resolving to 169.254.169.254 must be REJECTED at resolve time"
        );
        // IPv6 loopback, for completeness.
        assert!(
            resolver_for("[::1]:80")
                .resolve_vetted("ocsp.evil.test:80")
                .is_err(),
            "a host resolving to ::1 must be REJECTED at resolve time"
        );
        // Positive control: a genuinely public resolved address is admitted, so the
        // resolver does not over-block legitimate responders.
        let ok = resolver_for("93.184.216.34:80").resolve_vetted("ocsp.example.com:80");
        assert!(
            ok.is_ok(),
            "a host resolving to a public address must be admitted"
        );
        assert_eq!(
            ok.unwrap(),
            vec!["93.184.216.34:80".parse::<SocketAddr>().unwrap()],
            "the vetted public address is pinned and returned for connect"
        );
        // Mixed answer: a public + an internal address must fail CLOSED on the whole
        // resolve (no partial filtering that a rebinding race could exploit).
        struct PairResolver;
        impl BaseResolver for PairResolver {
            fn resolve(&self, _netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
                Ok(vec![
                    "93.184.216.34:80".parse().unwrap(),
                    "169.254.169.254:80".parse().unwrap(),
                ])
            }
        }
        assert!(
            VettingResolver {
                base: Box::new(PairResolver)
            }
            .resolve_vetted("ocsp.evil.test:80")
            .is_err(),
            "a mixed public+internal resolve must fail CLOSED, not connect to the public half"
        );
    }
}
