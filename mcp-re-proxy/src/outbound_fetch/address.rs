// SPDX-License-Identifier: Apache-2.0
//! Which addresses this proxy may reach out to.
//!
//! One fact: **whether an address or a host names something outside the deployment's own
//! network.** Nothing here knows what OCSP is; every predicate is about IP space.
//!
//! # Why an `inet_aton` canonicalizer sits beside `std`'s parser
//!
//! An attacker-influenced host may encode an IPv4 address in a form `std`'s STRICT parser
//! rejects but `inet_aton(3)` — and therefore the OS resolver and the HTTP client at fetch
//! time — accepts: octal `0177.0.0.1`, hex `0x7f.0.0.1`, the 32-bit integer `2130706433`,
//! the short form `127.1`. Without canonicalizing these they slip past the dotted-decimal
//! block as if they were hostnames, and the fetch still reaches the internal address. The
//! guard has to see what the RESOLVER will see, not what `std` will parse.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

/// Whether an IPv4 literal is a PUBLIC (fetchable) address — i.e. NOT loopback
/// (127/8), private (10/8, 172.16/12, 192.168/16), link-local (169.254/16,
/// covering the 169.254.169.254 cloud-metadata endpoint), unspecified (0.0.0.0),
/// broadcast (255.255.255.255), or multicast (224/4). Pure.
pub(super) fn ipv4_is_public(v4: &Ipv4Addr) -> bool {
    !(v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast())
}

/// Whether an IPv6 literal is a PUBLIC (fetchable) address — i.e. NOT loopback
/// (::1), unspecified (::), link-local (fe80::/10), multicast (ff00::/8), or
/// unique-local (fc00::/7). IPv4-mapped/compatible embeddings are unwrapped and
/// re-checked against the IPv4 rules so `::ffff:127.0.0.1` cannot bypass the guard.
/// Pure.
pub(super) fn ipv6_is_public(v6: &Ipv6Addr) -> bool {
    if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
        return false;
    }
    // Unwrap an IPv4-mapped/compatible address and apply the IPv4 rules to it.
    if let Some(v4) = v6.to_ipv4() {
        return ipv4_is_public(&v4);
    }
    let segs = v6.segments();
    // Link-local fe80::/10.
    if (segs[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    // Unique-local fc00::/7 (fc00:: and fd00::).
    if (segs[0] & 0xfe00) == 0xfc00 {
        return false;
    }
    true
}

/// Whether a RESOLVED IP address is a public (fetchable) address, reusing the
/// SAME predicates the literal-IP guard applies. The single chokepoint through
/// which every resolved OCSP-fetch address must pass (see [`VettingResolver`]);
/// it must never be weakened independently of `ipv4_is_public`/`ipv6_is_public`.
pub fn resolved_ip_is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => ipv4_is_public(v4),
        IpAddr::V6(v6) => ipv6_is_public(v6),
    }
}

/// Whether `host` is safe to fetch from for an attacker-influenced URL: it is NOT
/// syntactically malformed (no empty DNS label / trailing or doubled dot), NOT a
/// literal non-public IP, and NOT the loopback name `localhost`. A literal IP is
/// rejected when it is loopback, link-local, private (RFC 1918 / IPv6 ULA),
/// unspecified, or multicast. A non-literal hostname (other than `localhost`) is
/// permitted at this layer. Pure (no DNS).
pub(super) fn host_is_public(host: &str) -> bool {
    use IpAddr;
    // A trailing dot (`169.254.169.254.`), a leading dot, or a doubled dot
    // (`a..b`) produces an EMPTY DNS label. std's `IpAddr` and the `inet_aton`
    // canonicalizer below both REJECT such a string, so without this guard it
    // falls through to the "treat as a real hostname → permit" branch — yet the
    // OS resolver STRIPS a trailing root dot and resolves `169.254.169.254.` to
    // the metadata IP, and `127.0.0.1.` to loopback. Reject any host with an
    // empty label (and the empty host) OUTRIGHT rather than normalizing it: a
    // syntactically malformed host is never a legitimate public responder.
    if host.is_empty() || host.split('.').any(str::is_empty) {
        return false;
    }
    // The loopback hostname is the most common non-literal SSRF target — block it.
    if host.eq_ignore_ascii_case("localhost") {
        return false;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => return ipv4_is_public(&v4),
        Ok(IpAddr::V6(v6)) => return ipv6_is_public(&v6),
        // Not a STRICT dotted-decimal / canonical IPv6 literal — fall through.
        Err(_) => {}
    }
    // SSRF hardening (#26): an attacker-influenced host may encode an IPv4 address
    // in a non-dotted-decimal form that std's strict parser REJECTS but
    // `inet_aton(3)` — and therefore the OS resolver / HTTP client at fetch time —
    // ACCEPTS: octal (`0177.0.0.1`), hex (`0x7f.0.0.1`), a 32-bit integer
    // (`2130706433`), or short forms (`127.1`). Without canonicalizing these they
    // would slip past the dotted-decimal block as if they were hostnames and the
    // fetch would still reach the internal address. Canonicalize and re-check; only
    // a host that is NOT any IPv4 encoding is treated as a real hostname.
    if let Some(v4) = parse_inet_aton_ipv4(host) {
        return ipv4_is_public(&v4);
    }
    true
}

/// Parse an IPv4 address in the LOOSE `inet_aton(3)` forms that std's strict
/// parser rejects but the OS resolver / HTTP clients accept (issue #26 SSRF
/// guard). Each of 1–4 dot-separated parts may be decimal, octal (leading `0`), or
/// hexadecimal (leading `0x`/`0X`); with fewer than 4 parts the final part is a
/// wider field that absorbs the remaining low-order bytes (`a`; `a.b`; `a.b.c`).
/// Returns the canonical address, or `None` if `host` is not such a form (e.g. a
/// real hostname). Pure.
fn parse_inet_aton_ipv4(host: &str) -> Option<Ipv4Addr> {
    if host.is_empty() {
        return None;
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() > 4 {
        return None;
    }
    let vals: Vec<u64> = parts
        .iter()
        .map(|p| parse_inet_aton_part(p))
        .collect::<Option<Vec<u64>>>()?;
    // A slice pattern rather than a length plus indexing: the ARITY and the field widths
    // are one fact, not two related by an `n` that has to stay in step. Each arm states
    // both — every part except the last is a single byte, and the last is a "rest" field
    // whose width is what the earlier parts did not cover — and no arm can index past its
    // own binding.
    let addr: u32 = match *vals.as_slice() {
        [rest] => u32::try_from(rest).ok()?,
        [a, rest] if a <= 0xff => {
            (u32::try_from(a).ok()? << 24)
                | u32::try_from(rest).ok().filter(|r| *r <= 0x00ff_ffff)?
        }
        [a, b, rest] if a <= 0xff && b <= 0xff => {
            (u32::try_from(a).ok()? << 24)
                | (u32::try_from(b).ok()? << 16)
                | u32::try_from(rest).ok().filter(|r| *r <= 0x0000_ffff)?
        }
        [a, b, c, rest] if a <= 0xff && b <= 0xff && c <= 0xff => {
            (u32::try_from(a).ok()? << 24)
                | (u32::try_from(b).ok()? << 16)
                | (u32::try_from(c).ok()? << 8)
                | u32::try_from(rest).ok().filter(|r| *r <= 0x0000_00ff)?
        }
        _ => return None,
    };
    Some(Ipv4Addr::from(addr))
}

/// Parse one `inet_aton(3)` numeric part: hex (`0x..`), octal (leading `0`), or
/// decimal. Returns `None` for an empty or non-numeric part (so a real hostname
/// label like `ocsp` makes the whole parse fail and the host is treated as a name).
fn parse_inet_aton_part(part: &str) -> Option<u64> {
    let (radix, digits) =
        if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
            (16, hex)
        } else if part.len() > 1 && part.starts_with('0') {
            (8, &part[1..])
        } else {
            (10, part)
        };
    if digits.is_empty() {
        return None;
    }
    // Reject any non-digit (incl. a leading sign) up front: `from_str_radix`
    // tolerates a leading `+`, which `inet_aton` does not.
    if !digits.bytes().all(|b| (b as char).is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit-level proof that the loose parser canonicalizes each encoding to the
    /// SAME address the dotted-decimal form denotes.
    #[test]
    fn inet_aton_parser_canonicalizes_each_encoding() {
        use std::net::Ipv4Addr;
        let loopback = Ipv4Addr::new(127, 0, 0, 1);
        for form in [
            "0177.0.0.1",
            "0x7f.0.0.1",
            "0x7f000001",
            "2130706433",
            "127.1",
            "127.0.1",
        ] {
            assert_eq!(
                parse_inet_aton_ipv4(form),
                Some(loopback),
                "{form:?} must canonicalize to 127.0.0.1"
            );
        }
        assert_eq!(
            parse_inet_aton_ipv4("2852039166"),
            Some(Ipv4Addr::new(169, 254, 169, 254)),
            "the cloud-metadata integer must canonicalize correctly"
        );
        // Non-IP hostnames and malformed numeric forms are NOT parsed as IPs.
        assert_eq!(parse_inet_aton_ipv4("ocsp.example.com"), None);
        assert_eq!(parse_inet_aton_ipv4("0x"), None); // empty hex digits
        assert_eq!(parse_inet_aton_ipv4("256.0.0.1"), None); // octet overflow
        assert_eq!(parse_inet_aton_ipv4("1.2.3.4.5"), None); // too many parts
        assert_eq!(parse_inet_aton_ipv4("4294967296"), None); // > u32::MAX
    }
}
