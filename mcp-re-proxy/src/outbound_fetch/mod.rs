// SPDX-License-Identifier: Apache-2.0
//! Where this proxy is allowed to reach out to, and how hard the guard is.
//!
//! One fact: **a destination has passed the guard its PROVENANCE requires.** That is the
//! whole authority, and nothing in it is specific to RFC 6960 — it was found inside
//! `ocsp.rs` by the EX-006 census, which named it as *"a 336-line outbound-fetch network
//! policy … nothing about it is specific to RFC 6960. Any future outbound fetch this proxy
//! performs needs it, and it is currently reachable only through a module compiled out of
//! the default build by a feature gate that has nothing to do with it."* It is compiled
//! unconditionally now.
//!
//! # Provenance decides the guard, and the TYPE decides the provenance
//!
//! ```text
//! certificate-derived destination
//!     → attacker-influenced
//!     → scheme allowlist + private-address protection + resolved-address vetting
//!
//! operator-configured destination
//!     → trusted configuration
//!     → scheme allowlist
//! ```
//!
//! The two are **two constructors**, not one constructor and a flag. A caller cannot assert
//! that a certificate's URL is operator-configured, cannot obtain a destination without
//! passing the guard its constructor applies, and cannot turn resolved-address vetting off
//! for one it built as certificate-derived — because it never holds the switch.
//! [`VettedDestination::agent`] hands out the configured HTTP client rather than a boolean
//! for the caller to act on, so the connect-time half of the guard travels with the value
//! that earned it.
//!
//! The asymmetry is deliberate and is the operator's to have: an operator may legitimately
//! run a responder on an internal address, and a certificate may not name one. What neither
//! may do is name a scheme outside `http`/`https` — that floor is applied to both.
//!
//! # The subordinate owners
//!
//! ```text
//! outbound_fetch          a destination has passed the guard its provenance requires
//!   ├─ url                the scheme and host a URL names
//!   ├─ address            whether an address or host is outside our own network
//!   └─ resolver           every address connected to has passed the address guard
//! ```

mod address;
mod resolver;
mod url;

use std::time::Duration;

use self::resolver::VettingResolver;

/// A destination this proxy may fetch from, and the provenance that decided how it was
/// checked.
///
/// # Why the representation is private
///
/// The census (EX-006) found the guard applied by a caller that matched on a `Copy` enum
/// three lines from the fetch — correct, and correct only because those three lines are
/// adjacent. Here there is no way to obtain the value without the check, and no way to
/// obtain the fetch capability without the value: [`agent`](Self::agent) installs the
/// vetting resolver from the provenance this destination was BUILT with.
#[derive(Debug, Clone)]
pub struct VettedDestination {
    url: String,
    provenance: Provenance,
}

/// Where a destination came from, which is what decides the guard it had to pass.
///
/// Private: it is not an input. It is recorded by whichever constructor ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provenance {
    /// Read out of a certificate — ATTACKER-INFLUENCED.
    CertificateDerived,
    /// Configured by the operator — trusted configuration.
    OperatorConfigured,
}

impl VettedDestination {
    /// A destination read out of a certificate, or `None` if it does not pass the full
    /// guard.
    ///
    /// The full guard is the scheme allowlist AND the literal-private-address block: a
    /// hostile leaf otherwise points a serving thread at `file:///etc/passwd`, the cloud
    /// metadata endpoint `169.254.169.254`, `127.0.0.1`, `::1`, `10/8`, `172.16/12`,
    /// `192.168/16`, or an `inet_aton` spelling of any of them.
    ///
    /// `None` is a REFUSAL, and every caller must treat it as one. It is deliberately not a
    /// weaker destination.
    pub fn certificate_derived(url: impl Into<String>) -> Option<Self> {
        let url = url.into();
        (url::scheme_is_allowed(&url)
            && url::host_of(&url).is_some_and(|h| address::host_is_public(&h)))
        .then_some(VettedDestination {
            url,
            provenance: Provenance::CertificateDerived,
        })
    }

    /// A destination the operator configured, or `None` if its scheme is not allowed.
    ///
    /// Scheme only. An operator may legitimately point at a responder on an internal
    /// address; that is a deployment decision they are entitled to make, and it is the one
    /// difference between the two provenances.
    pub fn operator_configured(url: impl Into<String>) -> Option<Self> {
        let url = url.into();
        url::scheme_is_allowed(&url).then_some(VettedDestination {
            url,
            provenance: Provenance::OperatorConfigured,
        })
    }

    /// The destination URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// An HTTP agent configured for THIS destination's provenance.
    ///
    /// A capability, not a flag. Redirects are disabled for every provenance — a revocation
    /// fetch has no legitimate need to chase a `302 Location: http://169.254.169.254/`, and
    /// the first URL is the only one any guard saw. The resolved-address vetting is
    /// installed only for a certificate-derived destination, for the same reason the
    /// literal-address block is.
    pub fn agent(&self, _timeout: Duration) -> ureq::Agent {
        let builder = ureq::AgentBuilder::new().redirects(0);
        let builder = match self.provenance {
            Provenance::CertificateDerived => builder.resolver(VettingResolver::std()),
            Provenance::OperatorConfigured => builder,
        };
        builder.build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The AIA guard (cert-derived, attacker-influenced) blocks disallowed schemes
    /// AND every private/loopback/link-local/unspecified/multicast literal IP.
    #[test]
    fn aia_guard_blocks_schemes_and_private_ranges() {
        // Disallowed schemes.
        for url in [
            "file:///etc/passwd",
            "gopher://evil/",
            "ftp://host/x",
            "ldap://host/",
            "data:text/plain,x",
            "not-a-url",
            "",
        ] {
            assert!(
                VettedDestination::certificate_derived(url).is_none(),
                "{url:?} has a disallowed/absent scheme and must be blocked"
            );
        }
        // Private / loopback / link-local / unspecified / multicast literals.
        for url in [
            "http://127.0.0.1/",
            "http://[::1]/",
            "http://169.254.169.254/latest/meta-data/", // cloud metadata
            "http://10.0.0.5/",
            "http://172.16.0.1/",
            "http://192.168.1.1/",
            "http://0.0.0.0/",
            "http://[::]/",
            "http://localhost/",
            "http://224.0.0.1/", // multicast
            "http://[fe80::1]/", // IPv6 link-local
            "http://[fc00::1]/", // IPv6 unique-local
        ] {
            assert!(
                VettedDestination::certificate_derived(url).is_none(),
                "{url:?} resolves to a non-public address and must be blocked"
            );
        }
    }

    /// Positive control: a NORMAL public-hostname http AIA URL passes the guard
    /// (so the guard does not over-block legitimate responders). The fetch itself
    /// then fails (no responder listening), but as Err(Http) — proving the URL was
    /// accepted by the guard and the path PROCEEDED to the network, not rejected
    /// pre-fetch as Ok(Unknown).
    #[test]
    fn aia_guard_accepts_normal_public_url() {
        assert!(
            VettedDestination::certificate_derived("http://ocsp.example.com/").is_some(),
            "a normal public http responder URL must pass the AIA SSRF guard"
        );
        assert!(
            VettedDestination::certificate_derived("https://ocsp.digicert.com").is_some(),
            "a normal public https responder URL must pass the AIA SSRF guard"
        );
    }

    /// Issue #26: the SSRF guard must block NON-dotted-decimal IP encodings that
    /// `inet_aton(3)` (and thus the OS resolver / HTTP client) resolves to the same
    /// internal addresses — octal, hex, 32-bit integer, and short forms. Without
    /// canonicalization these slip past the dotted-decimal block as "hostnames".
    #[test]
    fn aia_guard_blocks_alternate_ip_encodings() {
        for url in [
            // 127.0.0.1 (loopback) in every alternate encoding.
            "http://0177.0.0.1/", // octal first octet
            "http://0x7f.0.0.1/", // hex first octet
            "http://0x7f000001/", // single hex 32-bit
            "http://2130706433/", // single decimal 32-bit
            "http://127.1/",      // short form (a.b)
            "http://127.0.1/",    // short form (a.b.c)
            // 169.254.169.254 (cloud metadata) alternate encodings.
            "http://2852039166/",          // decimal 32-bit
            "http://0xa9fea9fe/",          // hex 32-bit
            "http://0251.0376.0251.0376/", // all-octal dotted
            // 10.0.0.5 (RFC1918) as a 32-bit integer.
            "http://167772165/",
            // 0.0.0.0 (unspecified) as integer.
            "http://0/",
        ] {
            assert!(
                VettedDestination::certificate_derived(url).is_none(),
                "{url:?} canonicalizes to a non-public IP and must be blocked"
            );
        }
    }

    /// Positive control: a PUBLIC address in an alternate encoding must STILL be
    /// allowed (the canonicalization must not over-block), and a genuine hostname
    /// that merely looks numeric-ish is treated as a name, not mis-parsed.
    #[test]
    fn aia_guard_allows_public_alternate_encodings_and_hostnames() {
        // 8.8.8.8 (public) as hex 32-bit and octal dotted — must pass.
        assert!(VettedDestination::certificate_derived("http://0x08080808/").is_some());
        // 8.8.8.8 in all-octal dotted form.
        assert!(VettedDestination::certificate_derived("http://010.010.010.010/").is_some());
        // A real hostname (non-numeric labels) is permitted at this layer.
        assert!(VettedDestination::certificate_derived("http://ocsp.example.com/").is_some());
    }

    /// Stage-2 audit regression: a syntactically malformed host — trailing dot,
    /// leading dot, doubled dot, or empty — produces an empty DNS label that std's
    /// `IpAddr`/`inet_aton` parsers reject, so before the empty-label guard it fell
    /// through to the "treat as hostname → permit" branch. The OS resolver, however,
    /// STRIPS a trailing root dot, so `169.254.169.254.` / `127.0.0.1.` reach the
    /// internal address. All such forms must now be blocked. A legitimate trailing-
    /// dot FQDN is rejected too — an accepted hardening tradeoff for a revocation
    /// fetcher (responder URLs do not need the root-dot form).
    #[test]
    fn aia_guard_blocks_malformed_empty_label_hosts() {
        for url in [
            "http://169.254.169.254./latest/meta-data/", // trailing-dot metadata bypass
            "http://127.0.0.1./",                        // trailing-dot loopback bypass
            "http://127.0.0.1../",                       // doubled trailing dot
            "http://.169.254.169.254/",                  // leading dot
            "http://example..com/",                      // doubled interior dot
            "http://.../",                               // all-empty labels
        ] {
            assert!(
                VettedDestination::certificate_derived(url).is_none(),
                "{url:?} has an empty DNS label and must be blocked (not normalized)"
            );
        }
        // The malformed-host rejection is at the host layer, so it holds for the bare
        // host too (the guard is what `aia_responder_url_is_safe` calls after host
        // extraction).
        assert!(!address::host_is_public("169.254.169.254."));
        assert!(!address::host_is_public("127.0.0.1."));
        assert!(!address::host_is_public("a..b"));
        assert!(!address::host_is_public(""));
        // A normal hostname (no empty label) still passes the host layer.
        assert!(address::host_is_public("ocsp.example.com"));
    }

    /// The scheme allowlist (applied to BOTH cert AIA and operator override) admits
    /// only http/https. The operator override is scheme-checked but NOT subject to
    /// the private-IP block, so an operator-chosen internal responder still passes
    /// the scheme gate.
    #[test]
    fn operator_override_scheme_checked_not_ip_blocked() {
        assert!(VettedDestination::operator_configured("http://ocsp.internal/").is_some());
        assert!(VettedDestination::operator_configured("https://ocsp.internal/").is_some());
        assert!(VettedDestination::operator_configured("file:///etc/passwd").is_none());
        assert!(VettedDestination::operator_configured("gopher://x/").is_none());
        // An operator override pointing at an internal/private host passes the
        // scheme gate (the private-IP block does NOT apply to the override).
        assert!(VettedDestination::operator_configured("http://10.0.0.5:8080/ocsp").is_some());
        assert!(VettedDestination::operator_configured("http://localhost:8080/ocsp").is_some());
        // But the AIA (cert) guard WOULD block that same private host.
        assert!(VettedDestination::certificate_derived("http://10.0.0.5:8080/ocsp").is_none());
    }
}
