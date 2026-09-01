// SPDX-License-Identifier: Apache-2.0
//! Reading a destination URL, minimally and without trusting it.
//!
//! One fact: **which parts of a URL name its authority.** The scheme and host it names,
//! and where the authority it names ENDS — the same question asked three ways, and the
//! reason a path can never be a host here.
//!
//! Parsing is intentionally minimal — no URL crate — because what this needs is the
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

/// `path` joined onto `base`, on the authority `base` names and no other.
///
/// The authority of a URL runs from `://` to the first `/`, `?` or `#` (RFC 3986); a
/// parser may end it earlier — a `\` is a path separator for http(s) URLs, and tab/CR/LF
/// are stripped before parsing — but never later. So a join that guarantees a `/` between
/// the base's authority and everything the caller supplied puts the caller's string
/// entirely inside the path, whatever it spells.
///
/// The authority is `base`'s because `base` is a prefix of the result and a `/` follows it
/// — not because of the trims. The trims are about the PATH being well formed: an endpoint
/// written with a trailing slash would otherwise build `//v1/…`, which Cloud KMS does not
/// serve, and the same doubling appears from the other side when a caller writes a leading
/// one. A join that dropped `base` — which is what every call site did while it addressed
/// requests by full URL — is what would move the authority. Pure.
// Compiled unconditionally, consumed only where an HTTP client is linked. The property it
// carries — that no path moves an authority — is the one every credential-bearing request
// rests on, and a build that compiles it only under the backend features measures it only
// there: the default `cargo test -p mcp-re-proxy --lib` lane is what this unit's evidence
// resolves in, and a symbol that lane cannot run is not evidence for it. The unused warning
// in a build with no HTTP client is the cost of keeping the measurement where the claim is.
#[allow(dead_code)]
pub(super) fn joined_onto(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The load-bearing property of the join: NO path moves the authority.
    ///
    /// Each entry is a spelling that names a different host when it is concatenated onto a
    /// base without this discipline, or when a client is handed it as a whole URL.
    #[test]
    fn no_path_can_move_the_authority_it_is_joined_onto() {
        for base in [
            "https://cloudkms.googleapis.com",
            "https://cloudkms.googleapis.com/",
            "https://cloudkms.googleapis.com//",
        ] {
            for path in [
                "//evil.example.com/v1/x",
                "///evil.example.com/v1/x",
                "https://evil.example.com/v1/x",
                "http://evil.example.com/",
                "@evil.example.com/v1/x",
                "\\evil.example.com/v1/x",
                "\tevil.example.com/",
                "%2F%2Fevil.example.com/",
                "..//evil.example.com/",
                "",
                "/",
            ] {
                let url = joined_onto(base, path);
                assert_eq!(
                    host_of(&url).as_deref(),
                    Some("cloudkms.googleapis.com"),
                    "base {base:?} + path {path:?} produced {url:?}"
                );
            }
        }
    }

    /// Positive control: the join is a join. A guard that discarded the path would satisfy
    /// the property above and serve no request.
    #[test]
    fn the_path_survives_the_join_with_exactly_one_separator() {
        assert_eq!(
            joined_onto("https://kms.example.com", "v1/keys"),
            "https://kms.example.com/v1/keys"
        );
        assert_eq!(
            joined_onto("https://kms.example.com/", "/v1/keys"),
            "https://kms.example.com/v1/keys"
        );
        assert_eq!(
            joined_onto("https://kms.example.com", ""),
            "https://kms.example.com/"
        );
        // A base PATH is a prefix, not an authority: it survives, and it is why the rule
        // above admits an endpoint carrying one.
        assert_eq!(
            joined_onto("http://localhost:8443/kms/", "v1/keys"),
            "http://localhost:8443/kms/v1/keys"
        );
    }

    /// The two reading directions agree on where the authority ends, which is what makes
    /// the join safe to state in terms of the first `/`.
    #[test]
    fn the_host_read_back_is_the_one_the_base_named() {
        assert_eq!(
            host_of("https://a.example.com/x").as_deref(),
            Some("a.example.com")
        );
        assert_eq!(
            host_of("https://a.example.com").as_deref(),
            Some("a.example.com")
        );
        assert!(scheme_is_allowed("https://a.example.com"));
        assert!(!scheme_is_allowed("file:///etc/passwd"));
    }
}
