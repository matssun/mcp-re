// SPDX-License-Identifier: Apache-2.0
//! What a browser cannot do, stated as two predicates.
//!
//! "Processes on this host" does not describe a browser. A web page the user visits can
//! issue cross-origin `POST`s to `127.0.0.1`, and a page served from a name that resolves
//! to `127.0.0.1` (DNS rebinding) is treated by the browser as SAME-origin, so it does not
//! even send an `Origin`. Either way the sidecar would sign and send the attacker''s tool
//! call under this client''s identity, mTLS certificate and authorization bindings, and the
//! remote server would see perfectly valid RFC 9421 evidence. That the page cannot read the
//! reply is no comfort: the side effect is the payload.
//!
//! Three checks close it and a local MCP client passes all three without knowing they
//! exist. The `Origin` refusal needs no predicate — its mere PRESENCE identifies the caller,
//! and there is no origin that should be able to drive this signing key. The other two are
//! here.

/// Whether a `Host` header names this host by an address no name can be rebound to.
///
/// Only the literals: `localhost` resolves through the same resolver a rebinding
/// attack controls, but browsers refuse to let a page claim it as its own name, and the
/// upstream MCP clients spell the local leg that way. An IPv6 literal arrives bracketed.
pub(super) fn is_loopback_host(host: &str) -> bool {
    let host = host.rsplit_once(':').map_or(host, |(head, port)| {
        // Only a trailing `:<port>` is stripped — a bare IPv6 literal is full of colons
        // and must not be truncated into something that happens to parse.
        if port.bytes().all(|b| b.is_ascii_digit()) && !port.is_empty() {
            head
        } else {
            host
        }
    });
    let host = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

/// Whether a `Content-Type` names JSON. Parameters (`; charset=utf-8`) are allowed;
/// the media type itself is not negotiable.
pub(super) fn is_json_content_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("application/json")
}

#[cfg(test)]
mod tests {
    use super::*;
    /// A rebound name resolving to 127.0.0.1 is same-origin to the browser, so `Host`
    /// is the only thing that separates it from a genuine local caller.
    #[test]
    fn only_loopback_literals_and_localhost_are_accepted_hosts() {
        for host in [
            "127.0.0.1",
            "127.0.0.1:8640",
            "127.5.6.7",
            "localhost",
            "LOCALHOST:8640",
            "[::1]",
            "[::1]:8640",
        ] {
            assert!(is_loopback_host(host), "{host} names this host");
        }
        for host in [
            "rebound.evil.example",
            "rebound.evil.example:8640",
            "192.0.2.1",
            "10.0.0.1:8640",
            "localhost.evil.example",
            "",
        ] {
            assert!(!is_loopback_host(host), "{host} must not pass the guard");
        }
    }

    /// A CORS-"simple" POST cannot set a JSON content type without a preflight this
    /// listener never answers, so requiring one removes the no-preflight path.
    #[test]
    fn only_json_content_types_are_accepted() {
        assert!(is_json_content_type("application/json"));
        assert!(is_json_content_type("Application/JSON; charset=utf-8"));
        for value in [
            "text/plain",
            "text/plain;charset=UTF-8",
            "application/x-www-form-urlencoded",
            "multipart/form-data; boundary=x",
            "application/json-patch+json",
            "",
        ] {
            assert!(!is_json_content_type(value), "{value} must be refused");
        }
    }
}
