// SPDX-License-Identifier: Apache-2.0
//! Reading a destination URL, minimally and without trusting it.
//!
//! One fact: **the scheme and the host a URL names.**
//!
//! Parsing is intentionally minimal — no URL crate — because what this needs is the two
//! coordinates the guard is about, and a fuller parser would be a larger surface accepting
//! an attacker's string.

/// Whether `url`'s scheme is on the outbound allowlist (`http` or `https`).
///
/// This is the floor applied to EVERY destination, whatever its provenance — so a
/// `file://`, `gopher://`, `ldap://`, `data:` … URL can never be fetched, and an operator
/// cannot configure one either. Parsing is intentionally minimal (no URL crate dependency): the scheme
/// is the ASCII run before the first `:`, compared case-insensitively. Pure.
pub(super) fn scheme_is_allowed(url: &str) -> bool {
    match url.split_once(':') {
        Some((scheme, _rest)) => {
            scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
        }
        None => false,
    }
}

/// Extract the host component (without port, without brackets for IPv6) from an
/// `http`/`https` URL, using minimal parsing (no URL crate). Returns `None` if no
/// authority is present. The authority is the run between `//` and the first `/`,
/// `?`, or `#`; userinfo (`user@`) and the `:port` suffix are stripped; an IPv6
/// literal in `[...]` is returned without its brackets. Pure.
pub(super) fn host_of(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://")?.1;
    // Authority ends at the first path/query/fragment delimiter.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Drop any userinfo (everything up to and including the last '@').
    let hostport = match authority.rsplit_once('@') {
        Some((_userinfo, hp)) => hp,
        None => authority,
    };
    if hostport.is_empty() {
        return None;
    }
    // IPv6 literal: `[addr]` or `[addr]:port`.
    if let Some(rest) = hostport.strip_prefix('[') {
        let close = rest.find(']')?;
        return Some(rest[..close].to_string());
    }
    // host or host:port — the host is everything before the first ':'.
    let host = hostport.split(':').next().unwrap_or(hostport);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}
