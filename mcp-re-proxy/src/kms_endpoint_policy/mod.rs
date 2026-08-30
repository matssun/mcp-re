// SPDX-License-Identifier: Apache-2.0
//! Whether an operator-supplied KMS/STS endpoint may be used at all.
//!
//! This is a security policy, not a parsing concern. The rule it answers — may this
//! endpoint carry the root-key trust bootstrap, and on GCP a live workload-identity
//! bearer token — has the same meaning whether the value arrived on a command line, in
//! a config a validation pass is checking, or as a public struct field an embedder set
//! before reaching a key-source constructor.
//!
//! It therefore owns the rule rather than any of those callers owning it. The command
//! line and the validation boundary CONSUME this decision; so do the AWS KMS, AWS STS
//! and GCP KMS key sources, which an embedder can reach without meeting a parser at
//! all. None of them depends on another to obtain it.
//!
//! # The invariant
//!
//! > An endpoint authority is accepted only when its literal human-readable
//! > representation and the machine interpretation used by the client agree. Alternate
//! > host and port spellings that change the effective authority are refused.
//!
//! One rule, several subordinate predicates. `127.1` (an alternate IP representation a
//! parser rewrites to `127.0.0.1`) and `:0443` (a port canonicalisation that reaches
//! 443) are the same threat: text that names one endpoint to a reader and another to
//! the client. They are enforced by [`check_host`] and [`check_port`] respectively,
//! because they are different predicates — not because they are different concerns.
//!
//! The reasoning lives here rather than being restated in each check, so that reviewing
//! the rule means reading one argument and then confirming each predicate enforces its
//! share of it.

use std::str::FromStr;

mod authority;
use authority::split_authority;

/// The `host[:port]` a request to `value` will actually reach — or why `value` may not be
/// used as a KMS/STS endpoint at all.
///
/// These overrides carry the ROOT-KEY trust bootstrap: `getPublicKey` fetches the
/// `spki_der`/verify key that the verify-before-return guardrail is measured against, and
/// on GCP every request also carries a live workload-identity bearer token. An unvalidated
/// override therefore hands a replayable credential to whatever host is named and lets a
/// substituted endpoint supply an attacker-chosen root signing key that every local
/// fail-closed check then passes self-consistently.
///
/// So the authority must be a LITERAL `host[:port]` — text a URL parser reads the same way
/// a reader does. `ureq` resolves a request URL with `url::Url::parse` and connects to its
/// `host_str()`, which reads `https://cloudkms.googleapis.com@evil.example.com` as host
/// `evil.example.com` with the recognisable half demoted to userinfo, and reads
/// `http://localhost:80@evil.example.com` the same way — so userinfo (`@`) is refused, and
/// so is any host carrying percent- or IDNA-encoding or a separator a parser resolves
/// differently (`\`, a tab, a stray `%`), all of which name one host to a reader and
/// another to the parser. The port must be numeric.
///
/// Scheme: `https://` always; `http://` ONLY to loopback — decided from the host below,
/// i.e. AFTER userinfo has been refused, because `http://localhost:80@evil.example.com`
/// otherwise reads as loopback while the plaintext bearer token leaves the machine. The
/// loopback exception is what keeps the LocalStack / KMS-emulator lane working.
///
/// Applied at parse for a command line, at the validation boundary via
/// [`kms_endpoint_refusals`] for any config, and again at key-source construction
/// (`UreqGcpClient::new`, `aws_kms_keysource::authority_of`,
/// `WebIdentityConfig::from_env`), since the endpoint fields are public and an embedder
/// reaches key-source construction without meeting a parser.
pub(crate) fn kms_endpoint_authority(value: &str) -> Result<String, String> {
    let (plaintext, rest) = if let Some(rest) = value.strip_prefix("https://") {
        (false, rest)
    } else if let Some(rest) = value.strip_prefix("http://") {
        (true, rest)
    } else {
        return Err(format!(
            "must be an absolute https:// URL (got {value:?}); this endpoint carries the \
             root-key trust bootstrap and, on GCP, a live bearer token"
        ));
    };
    // RFC 3986: the authority ends at the first `/`, `?` or `#`. A URL parser may end it
    // EARLIER (a `\` is a path separator for http(s) URLs, and tab/CR/LF are stripped
    // before parsing), never later — so the host it picks is always inside this span, and
    // rejecting the span's contents rejects the parser's host too.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err(format!("has no host: {value:?}"));
    }
    // A query or fragment is not part of an endpoint, and it does not survive the way the
    // GCP client builds its URLs: `{base}/v1/{name}:asymmetricSign` on a base carrying `?`
    // puts the whole operation path inside the query string. A trailing PATH is allowed —
    // an emulator legitimately serves the API under one.
    if let Some(bad) = rest.chars().find(|c| matches!(c, '?' | '#')) {
        return Err(format!(
            "must be a bare scheme://host[:port][/path] endpoint; {bad:?} in {value:?} is a \
             query or fragment, which is not part of an authority and is not carried through \
             the per-operation URLs built from it"
        ));
    }
    if authority.contains('@') {
        return Err(format!(
            "authority {authority:?} carries userinfo, and a URL parser reads the host as the \
             text AFTER the '@' — so {value:?} sends the root-key bootstrap, and on GCP a live \
             bearer token, to a host other than the one it appears to name"
        ));
    }
    let (host, port) = split_host_port(authority, value)?;
    if plaintext && !names_this_machine(host) {
        return Err(format!(
            "may only use http:// for a loopback emulator (localhost, 127.0.0.0/8, [::1]); \
             got host {host:?}. A plaintext endpoint exfiltrates the KMS credential and lets a \
             substituted host supply the root verify key"
        ));
    }
    if let Some(port) = port {
        Ok(format!("{host}:{port}"))
    } else {
        Ok(host.to_string())
    }
}

/// Does `host` provably name THIS machine, so a plaintext credential sent to it cannot
/// leave it?
///
/// Decided from the parsed address, not from a spelling, so the canonicalisations a URL
/// parser performs do not change the answer: `url` reads `[0:0:0:0:0:0:0:1]` as `[::1]` and
/// lowercases `LOCALHOST`, and every address in 127.0.0.0/8 is loopback under RFC 1122, not
/// just `127.0.0.1`.
///
/// The IPv4 shorthands a URL parser also accepts — `127.1`, `0x7f.1` — are NOT recognised
/// here, so they are refused rather than admitted as loopback. That is the safe direction
/// (a refusal), and no operator writes an emulator endpoint that way.
fn names_this_machine(host: &str) -> bool {
    if let Some(literal) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return std::net::Ipv6Addr::from_str(literal).is_ok_and(|address| address.is_loopback());
    }
    if let Ok(address) = std::net::Ipv4Addr::from_str(host) {
        return address.is_loopback();
    }
    host.eq_ignore_ascii_case("localhost")
}

/// Split a `host[:port]` authority, refusing anything that is not a literal host.
///
/// The three steps below are the module invariant applied to the three places an
/// authority can diverge: where the host ends, what the host is, and what the port is.
fn split_host_port<'a>(
    authority: &'a str,
    value: &str,
) -> Result<(&'a str, Option<&'a str>), String> {
    let (host, port) = split_authority(authority, value)?;
    check_host(host, value)?;
    if let Some(port) = port {
        check_port(port, value)?;
    }
    Ok((host, port))
}

/// Whether the host names the machine a reader thinks it names.
///
/// A bracketed host's contents must parse as an address — `[foo-bar]` and `[gggg::1]` are
/// bracket-shaped but are not IPv6 literals, and `url::Url::parse` refuses both. Admitting
/// them here would only move the failure to the first request.
///
/// The unbracketed host is held to letters, digits, `.`, `-` and `_`. That is every
/// character a URL parser reads back as the text itself AND that a resolver can answer
/// for: `_` is admitted because internal DNS names carry it and `url` reads it verbatim.
/// The remaining printable ASCII that `url` also reads verbatim — ``! " $ & ' ( ) * + , ; =
/// ` { } ~`` — is refused as defence in depth: none of it can appear in a name
/// `getaddrinfo` will resolve, so refusing it costs no reachable endpoint. Everything else
/// is refused because a parser does NOT read it as written: `# / ? @ \` move the host,
/// and `% : < > [ ] ^ |` make `url` fail outright.
fn check_host(host: &str, value: &str) -> Result<(), String> {
    if let Some(literal) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        if std::net::Ipv6Addr::from_str(literal).is_err() {
            return Err(format!(
                "host {host:?} is bracket-shaped but is not an IPv6 address, which a URL parser \
                 refuses outright: {value:?}"
            ));
        }
        return Ok(());
    }
    if host.is_empty() {
        return Err(format!("has no host: {value:?}"));
    }
    if let Some(bad) = host
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')))
    {
        return Err(format!(
            "host {host:?} is not a literal name or IP address ({bad:?} is percent-, IDNA- \
             or separator-encoding, which a URL parser resolves to a DIFFERENT host than \
             the text reads, or a character no resolver can answer for): {value:?}"
        ));
    }
    // A URL parser reads a host whose LAST label is a NUMBER as an IPv4 address rather
    // than a name, and then rewrites it: `0x7f.1`, `127.1` and `2130706433` all resolve
    // to 127.0.0.1, and `1.1` to 1.0.0.1. Character-legal, but the address reached is
    // not the text. So a host of that shape is admitted only when it already IS a plain
    // dotted quad, where the two agree. No DNS name is affected — a top-level label
    // cannot be all-numeric, and `url` errors on one that is.
    let last_label = host
        .rsplit('.')
        .find(|label| !label.is_empty())
        .unwrap_or("");
    let read_as_an_address = last_label.chars().all(|c| c.is_ascii_digit())
        || last_label.starts_with("0x")
        || last_label.starts_with("0X");
    if read_as_an_address && std::net::Ipv4Addr::from_str(host).is_err() {
        return Err(format!(
            "host {host:?} ends in a number, so a URL parser reads it as an IPv4 ADDRESS \
             and rewrites it (0x7f.1 and 127.1 both become 127.0.0.1); write the dotted \
             quad the request will actually reach: {value:?}"
        ));
    }
    Ok(())
}

/// Whether the port reached is the port written.
///
/// A TCP port is a u16. "all digits" is not the same rule: `:65536` and `:99999999` are
/// all digits, and `url::Url::parse` refuses both — so admitting them would be a genuine
/// disagreement about whether the endpoint is usable at all. A leading zero is refused for
/// the narrower reason that `:0443` parses to 443, making the text and the port reached
/// differ.
fn check_port(port: &str, value: &str) -> Result<(), String> {
    // Digits ONLY, checked before parsing: `u16::from_str` accepts a leading `+`, so
    // `:+443` would parse to 443 while `url::Url::parse` refuses it outright.
    if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!(
            "port {port:?} is not a number, and a URL parser refuses it outright: \
             {value:?}"
        ));
    }
    if port.len() > 1 && port.starts_with('0') {
        return Err(format!(
            "port {port:?} has a leading zero, so the text and the port a URL parser \
             reads differ: {value:?}"
        ));
    }
    if port.parse::<u16>().is_err() {
        return Err(format!(
            "port {port:?} is not a TCP port number (0-65535), and a URL parser refuses \
             it outright: {value:?}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// The host allowlist is a deliberate line, so it is pinned character by character.
    ///
    /// `_` is ADMITTED: internal DNS names carry it and `url::Url::parse` reads it back as
    /// the text itself, so refusing it would have been pure capability loss. The other
    /// printable ASCII `url` also reads verbatim is refused as defence in depth — none of
    /// it can appear in a name a resolver will answer for, so no reachable endpoint is
    /// lost. Measured against url 2.5.8, the crate ureq 2.12.1 links.
    #[test]
    fn the_host_allowlist_is_exactly_the_characters_a_resolver_can_answer_for() {
        assert!(
            super::kms_endpoint_authority("https://kms_internal.example:8443").is_ok(),
            "an underscore is read verbatim by a URL parser and appears in internal DNS names"
        );
        assert!(
            super::kms_endpoint_authority("http://kms_local:4566").is_err(),
            "but the loopback rule still applies to it"
        );
        // Refused, and url reads each of these VERBATIM — a named, accepted capability
        // loss, not an oversight: none can appear in a name `getaddrinfo` resolves.
        for c in [
            '!', '"', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', '`', '{', '}', '~',
        ] {
            assert!(
                super::kms_endpoint_authority(&format!("https://kms{c}internal.example")).is_err(),
                "{c:?} must be refused"
            );
        }
        // Refused because a URL parser does NOT read them as written: these MOVE the host
        // (verified: url resolves each to a host other than the text before the character).
        for c in ['#', '/', '?', '@', '\\'] {
            let hostile = format!("https://kms{c}internal.example");
            // `/`, `?` and `#` end the authority, so the refusal is about what is left.
            assert!(
                super::kms_endpoint_authority(&hostile).is_err()
                    || super::kms_endpoint_authority(&hostile).as_deref() == Ok("kms"),
                "{c:?} must never yield an authority other than the text before it"
            );
        }
        // Refused, and url fails outright on them too.
        for c in ['%', '<', '>', '^', '|'] {
            assert!(
                super::kms_endpoint_authority(&format!("https://kms{c}internal.example")).is_err(),
                "{c:?} must be refused"
            );
        }
    }

    /// A bracket-shaped host must be a real IPv6 literal.
    ///
    /// `[foo-bar]`, `[1]` and `[gggg::1]` pass a character allowlist but `url::Url::parse`
    /// refuses all three, so admitting them would only move the failure to the first
    /// request — and it would leave the gate disagreeing with the parser about what the
    /// host even is, which is the property this whole check exists to hold.
    #[test]
    fn a_bracketed_host_must_be_an_ipv6_literal() {
        for hostile in [
            "https://[foo-bar]",
            "https://[1]",
            "https://[gggg::1]",
            "https://[]",
            "https://[::1",
            "https://[::1]junk",
            "http://[fe80::1%25eth0]",
        ] {
            assert!(
                super::kms_endpoint_authority(hostile).is_err(),
                "{hostile} is not an IPv6 endpoint and must be refused"
            );
        }
        // POSITIVE CONTROL: the real IPv6 spellings, including the canonicalisations a URL
        // parser performs. `[0:0:0:0:0:0:0:1]` IS ::1, so the loopback rule must see it.
        for allowed in [
            "https://[2001:db8::1]",
            "https://[2001:db8::1]:8443",
            "https://[::ffff:192.168.0.1]",
            "http://[::1]",
            "http://[::1]:4566",
            "http://[0:0:0:0:0:0:0:1]:4566",
        ] {
            assert!(
                super::kms_endpoint_authority(allowed).is_ok(),
                "{allowed} is a real IPv6 endpoint and must be accepted: {:?}",
                super::kms_endpoint_authority(allowed).err()
            );
        }
    }

    /// A host whose last label is a NUMBER is read by a URL parser as an IPv4 address and
    /// rewritten, so the text is not the host reached — `0x7f.1`, `127.1` and `2130706433`
    /// all become 127.0.0.1, `1.1` becomes 1.0.0.1. Admitted only as a plain dotted quad,
    /// where the two agree.
    #[test]
    fn a_host_that_ends_in_a_number_must_already_be_the_address_it_resolves_to() {
        for rewritten in [
            "https://0x7f.1",
            "https://127.1",
            "https://2130706433",
            "https://1.1",
            "https://0x01010101",
            "https://kms.example.1",
            "http://127.1:4566",
        ] {
            assert!(
                super::kms_endpoint_authority(rewritten).is_err(),
                "{rewritten} is rewritten by a URL parser and must be refused"
            );
        }
        // POSITIVE CONTROL: dotted quads and ordinary names are untouched. A DNS name is
        // never affected — a top-level label cannot be all-numeric.
        for allowed in [
            "https://10.0.0.5:8443",
            "https://192.168.0.1",
            "http://127.0.0.1:4566",
            "https://kms.us-east-1.amazonaws.com",
            "https://vpce-0abc123-xy1z.kms.us-east-1.vpce.amazonaws.com",
            "https://kms-2.example.com",
        ] {
            assert!(
                super::kms_endpoint_authority(allowed).is_ok(),
                "{allowed} must be accepted: {:?}",
                super::kms_endpoint_authority(allowed).err()
            );
        }
    }

    /// A port is a u16, not "some digits".
    ///
    /// `:65536` and `:99999999` are all-digit and `url::Url::parse` refuses both, so an
    /// all-digit rule admitted endpoints no request could ever be made to — a real
    /// disagreement with the parser, in the direction of accepting the unusable. A leading
    /// zero is refused for the narrower reason that `:0443` reaches port 443 while the text
    /// says otherwise.
    #[test]
    fn a_port_must_be_a_tcp_port_number() {
        for bad in [
            "https://kms.example.com:65536",
            "https://kms.example.com:99999999",
            "https://kms.example.com:0443",
            "https://kms.example.com:00",
            // `u16::from_str` accepts a leading sign; `url::Url::parse` refuses both.
            "https://kms.example.com:+443",
            "https://kms.example.com:-443",
            "https://kms.example.com:",
            "http://127.0.0.1:65536",
        ] {
            assert!(
                super::kms_endpoint_authority(bad).is_err(),
                "{bad} is not a usable endpoint and must be refused"
            );
        }
        for good in [
            "https://kms.example.com:65535",
            "https://kms.example.com:443",
            "https://kms.example.com:8443",
            "http://127.0.0.1:4566",
            "http://[::1]:1",
        ] {
            assert!(
                super::kms_endpoint_authority(good).is_ok(),
                "{good} names a real port and must be accepted: {:?}",
                super::kms_endpoint_authority(good).err()
            );
        }
    }

    /// The plaintext exception is decided from the parsed address, so a spelling a URL
    /// parser canonicalises does not change the answer — and every address in 127.0.0.0/8
    /// is loopback, not just `127.0.0.1`.
    #[test]
    fn the_plaintext_exception_follows_the_address_not_the_spelling() {
        for loopback in [
            "http://127.0.0.1:4566",
            "http://127.0.0.2:4566",
            "http://127.255.255.254",
            "http://LOCALHOST:4566",
            "http://[0:0:0:0:0:0:0:1]",
        ] {
            assert!(
                super::kms_endpoint_authority(loopback).is_ok(),
                "{loopback} provably names this machine and must be accepted: {:?}",
                super::kms_endpoint_authority(loopback).err()
            );
        }
        for off_machine in [
            "http://128.0.0.1",
            "http://10.0.0.5:8443",
            "http://[fe80::1]",
            "http://[2001:db8::1]",
            "http://localhost.attacker.example",
            // The IPv4 shorthands url reads as 127.0.0.1 are refused, not admitted: a
            // refusal is the safe direction and no operator writes an emulator this way.
            "http://127.1",
            "http://0x7f.1",
        ] {
            assert!(
                super::kms_endpoint_authority(off_machine).is_err(),
                "{off_machine} does not provably name this machine and must be refused"
            );
        }
    }

    /// The authority the AWS SigV4 `Host` header is built from is the one a URL parser will
    /// connect to, including the port.
    #[test]
    fn the_authority_returned_is_the_host_and_port_that_will_be_reached() {
        for (endpoint, authority) in [
            (
                "https://kms.us-east-1.amazonaws.com",
                "kms.us-east-1.amazonaws.com",
            ),
            (
                "https://kms.us-east-1.amazonaws.com/",
                "kms.us-east-1.amazonaws.com",
            ),
            ("http://localhost:4566/", "localhost:4566"),
            ("http://[::1]:4566", "[::1]:4566"),
            ("http://[::1]", "[::1]"),
        ] {
            assert_eq!(
                super::kms_endpoint_authority(endpoint).expect("admissible"),
                authority
            );
        }
    }

    // --- the subordinate predicates, exercised directly -------------------------------
    //
    // The cases above reach these through `kms_endpoint_authority`, which is the contract
    // callers depend on. These reach each predicate on its own, so a refusal that stops
    // firing is attributed to the check that owns it rather than surfacing as one opaque
    // failure of the whole rule. Each carries its negative control: the admitted case
    // sitting beside the refused one, so a predicate that started refusing everything
    // would fail here rather than look like a stricter policy.

    #[test]
    fn split_authority_divides_on_the_bracket_not_the_first_colon() {
        // The whole reason this is a separate step: `[::1]:4566` contains four colons and
        // only the last one is the port separator.
        assert_eq!(
            super::split_authority("[::1]:4566", "v").expect("admissible"),
            ("[::1]", Some("4566"))
        );
        assert_eq!(
            super::split_authority("[::1]", "v").expect("admissible"),
            ("[::1]", None)
        );
        assert_eq!(
            super::split_authority("host:443", "v").expect("admissible"),
            ("host", Some("443"))
        );
        assert_eq!(
            super::split_authority("host", "v").expect("admissible"),
            ("host", None)
        );
    }

    #[test]
    fn split_authority_refuses_a_bracket_that_does_not_close_or_is_followed_by_junk() {
        assert!(super::split_authority("[::1", "v").is_err());
        assert!(super::split_authority("[::1]x443", "v").is_err());
    }

    #[test]
    fn check_host_refuses_a_bracket_shaped_host_that_is_not_an_address() {
        assert!(super::check_host("[::1]", "v").is_ok());
        assert!(super::check_host("[foo-bar]", "v").is_err());
        assert!(super::check_host("[gggg::1]", "v").is_err());
    }

    #[test]
    fn check_host_refuses_a_host_a_parser_would_rewrite_to_a_different_address() {
        // The `127.1` half of the module invariant: character-legal, but the address
        // reached is not the text. A plain dotted quad is admitted because there the two
        // agree, and a name is admitted because a parser does not rewrite it.
        assert!(super::check_host("127.0.0.1", "v").is_ok());
        assert!(super::check_host("kms.example.internal", "v").is_ok());
        assert!(super::check_host("127.1", "v").is_err());
        assert!(super::check_host("0x7f.1", "v").is_err());
        assert!(super::check_host("2130706433", "v").is_err());
    }

    #[test]
    fn check_port_refuses_a_port_whose_text_and_value_differ() {
        // The `:0443` half of the same invariant.
        assert!(super::check_port("443", "v").is_ok());
        assert!(super::check_port("0", "v").is_ok());
        assert!(super::check_port("0443", "v").is_err());
        assert!(super::check_port("+443", "v").is_err());
        assert!(super::check_port("65536", "v").is_err());
        assert!(super::check_port("", "v").is_err());
    }
}
