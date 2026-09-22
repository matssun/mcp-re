// SPDX-License-Identifier: Apache-2.0
//! The locator projection — see the crate root for the authority this implements.

use std::fmt;

/// What is rendered when the input cannot be decomposed at all: the input is not echoed,
/// so nothing about its contents — including whether it held a credential — is published.
const UNPARSEABLE: &str = "<unparseable>";

/// What is rendered when the input is a reference with no authority component. It names
/// the shape, and, like [`UNPARSEABLE`], says nothing about the contents.
const NO_AUTHORITY: &str = "<no-authority>";

/// One operator-configured locator as an operator may see it: scheme, host and port, with
/// every credential-bearing component removed and its removal reported.
///
/// A shape this cannot decompose is NAMED rather than echoed, because echoing is exactly
/// what must not happen to an unparsed string — a credential-bearing value that fails a
/// deployment's own `://` shape check (`mats:hunter2@host:6379`) reaches the violation
/// message by that route and no other.
pub struct RedactedLocator(String);

impl RedactedLocator {
    /// Render `raw` for a human-readable line. Infallible on purpose: this is a projection
    /// for human eyes, and a locator a deployment REFUSES must still be nameable in the
    /// message an operator reads while diagnosing that refusal.
    pub fn of(raw: &str) -> Self {
        Self(project(raw))
    }
}

impl fmt::Display for RedactedLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The projection itself: scheme and routing coordinates, plus what was removed.
///
/// Fail-closed at every step — each `return` below names a shape rather than describing
/// it, so no branch can reach the rendered text carrying input.
fn project(raw: &str) -> String {
    let Some((scheme, rest)) = raw.split_once("://") else {
        // A path-absolute reference has no authority and is a recognisable shape; anything
        // else without a scheme delimiter is exactly the credential-bearing form
        // (`user:pass@host:port`) that a locator-shape refusal fires on.
        if raw.starts_with('/') {
            return NO_AUTHORITY.to_string();
        }
        return UNPARSEABLE.to_string();
    };
    if !is_scheme(scheme) {
        return UNPARSEABLE.to_string();
    }
    // RFC 3986: the authority ends at the first `/`, `?` or `#`.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return NO_AUTHORITY.to_string();
    }
    // The userinfo runs to the LAST `@`, which is where a URL parser reads the host from.
    let (userinfo_present, host_port) = match authority.rsplit_once('@') {
        Some((_userinfo, after_at)) => (true, after_at),
        None => (false, authority),
    };
    let Some(coordinates) = routing_coordinates(host_port) else {
        return UNPARSEABLE.to_string();
    };
    // `authority` is a prefix of `rest` by construction, so this is a char boundary.
    let tail = rest.get(authority.len()..).unwrap_or("");
    format!(
        "{scheme}://{coordinates}{}",
        removed(userinfo_present, tail)
    )
}

/// Whether `scheme` is an RFC 3986 scheme, which is the only form echoed verbatim.
fn is_scheme(scheme: &str) -> bool {
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// The `host[:port]` a request would reach, or `None` when it cannot be established.
///
/// The host is the one component echoed, so it is held to the characters a name or an
/// address is written with. Anything else — percent-encoding, a separator a parser
/// resolves differently, a non-numeric port — is not confidently a routing coordinate,
/// and the caller names the whole locator instead of publishing it.
fn routing_coordinates(host_port: &str) -> Option<String> {
    if let Some(after_bracket) = host_port.strip_prefix('[') {
        let (literal, after) = after_bracket.split_once(']')?;
        let ipv6 = !literal.is_empty()
            && literal
                .chars()
                .all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '.'));
        if !ipv6 {
            return None;
        }
        return Some(format!("[{literal}]{}", port_suffix(after)?));
    }
    let (host, port) = match host_port.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (host_port, None),
    };
    let named = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    if !named {
        return None;
    }
    match port {
        None => Some(host.to_string()),
        Some(port) if is_port(port) => Some(format!("{host}:{port}")),
        Some(_) => None,
    }
}

/// The text after an IPv6 literal's closing bracket, as a renderable port suffix.
fn port_suffix(after: &str) -> Option<String> {
    if after.is_empty() {
        return Some(String::new());
    }
    let port = after.strip_prefix(':')?;
    is_port(port).then(|| format!(":{port}"))
}

/// Whether `port` is a TCP port written as itself: digits only, and in range.
fn is_port(port: &str) -> bool {
    !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) && port.parse::<u16>().is_ok()
}

/// What was removed, in a stable order, naming each component and never its contents.
///
/// `tail` is everything after the authority. A path made only of `/` carried nothing, so
/// it is not reported as removed; every other non-empty path was material an operator
/// configured and must be told is missing from this line.
fn removed(userinfo_present: bool, tail: &str) -> String {
    let (before_fragment, fragment) = match tail.split_once('#') {
        Some((before, fragment)) => (before, Some(fragment)),
        None => (tail, None),
    };
    let (path, query) = match before_fragment.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (before_fragment, None),
    };
    let mut components = Vec::new();
    if userinfo_present {
        components.push("userinfo removed");
    }
    if path.chars().any(|c| c != '/') {
        components.push("path removed");
    }
    if query.is_some() {
        components.push("query removed");
    }
    if fragment.is_some() {
        components.push("fragment removed");
    }
    if components.is_empty() {
        return String::new();
    }
    format!(" ({})", components.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// LOAD-BEARING: the reason this type exists. A password in the authority must not
    /// reach the rendered text under any component of the projection.
    #[test]
    fn userinfo_never_reaches_the_rendered_locator() {
        let rendered =
            RedactedLocator::of("https://alice:hunter2@backend.internal/mcp").to_string();
        assert!(
            !rendered.contains("hunter2") && !rendered.contains("alice"),
            "credentials survived the projection: {rendered}"
        );
        assert_eq!(
            rendered,
            "https://backend.internal (userinfo removed, path removed)"
        );
    }

    /// The second half of the same control: not one component of the configured string may
    /// be reassembled from the line, and the complete string may not appear in it.
    #[test]
    fn the_complete_configured_locator_never_appears_in_the_rendering() {
        const CONFIGURED: &str = "https://alice:hunter2@backend.internal/mcp";
        let rendered = RedactedLocator::of(CONFIGURED).to_string();
        assert!(
            !rendered.contains(CONFIGURED),
            "the complete configured locator was echoed: {rendered}"
        );
        assert!(
            !rendered.contains('@') && !rendered.contains("/mcp"),
            "a credential-bearing component survived: {rendered}"
        );
    }

    /// LOAD-BEARING: a credential does not have to sit in the userinfo. A token in query
    /// material is a configured credential too, and nothing here proves a query safe.
    #[test]
    fn a_credential_in_query_material_never_reaches_the_rendering() {
        let rendered = RedactedLocator::of("http://h:2379/?token=s3cr3t").to_string();
        assert!(
            !rendered.contains("s3cr3t") && !rendered.contains("token"),
            "query material reached the diagnostic: {rendered}"
        );
        assert_eq!(rendered, "http://h:2379 (query removed)");
    }

    /// LOAD-BEARING: the path is credential-bearing material too — a bearer token carried
    /// as a path segment is exactly the shape a rendered path publishes.
    #[test]
    fn a_path_is_removed_and_its_removal_is_reported() {
        let rendered = RedactedLocator::of("https://vault.internal/v1/token/s3cr3t").to_string();
        assert!(
            !rendered.contains("s3cr3t") && !rendered.contains("token"),
            "a path segment reached the diagnostic: {rendered}"
        );
        assert_eq!(rendered, "https://vault.internal (path removed)");
    }

    /// The markers report WHICH component was removed, never WHAT it held — so a locator
    /// whose removed components are conspicuous secrets renders the same markers as one
    /// whose removed components are ordinary.
    #[test]
    fn the_removal_markers_do_not_carry_what_was_removed() {
        let secret =
            RedactedLocator::of("https://u:p@h:8443/hunter2?k=hunter2#hunter2").to_string();
        assert!(
            !secret.contains("hunter2"),
            "a marker carried its contents: {secret}"
        );
        assert_eq!(
            secret,
            "https://h:8443 (userinfo removed, path removed, query removed, fragment removed)"
        );
        let ordinary = RedactedLocator::of("https://u:p@h:8443/mcp?a=b#c").to_string();
        assert_eq!(secret, ordinary, "the markers must not vary with contents");
    }

    /// LOAD-BEARING: this is the exact leak. A credential-bearing value with no `://` is
    /// precisely what every locator-shape violation fires on, so the rendering of THIS
    /// shape is what stands between a typo and a password in the startup diagnostic. It
    /// must be named, never echoed.
    #[test]
    fn a_scheme_less_credential_bearing_locator_is_named_not_echoed() {
        let rendered = RedactedLocator::of("mats:hunter2@host:6379").to_string();
        assert!(
            !rendered.contains("hunter2"),
            "the password reached the diagnostic: {rendered}"
        );
        assert!(
            !rendered.contains('@'),
            "no userinfo delimiter may survive: {rendered}"
        );
        assert_eq!(rendered, "<unparseable>");
    }

    /// POSITIVE CONTROL: the projection removed material, not usefulness. A normal
    /// credential-free locator still shows the coordinates an operator routes by.
    #[test]
    fn a_credential_free_locator_renders_without_the_marker() {
        assert_eq!(
            RedactedLocator::of("redis://redis.internal:6379").to_string(),
            "redis://redis.internal:6379"
        );
        assert_eq!(
            RedactedLocator::of("http://127.0.0.1:8621").to_string(),
            "http://127.0.0.1:8621"
        );
        assert_eq!(
            RedactedLocator::of("https://backend.internal/").to_string(),
            "https://backend.internal"
        );
        assert_eq!(
            RedactedLocator::of("http://[::1]:2379").to_string(),
            "http://[::1]:2379"
        );
    }

    #[test]
    fn a_shape_the_projection_cannot_decompose_is_named() {
        for named in [
            "not a url at all",
            "",
            "://backend.internal",
            "1https://backend.internal",
            "https://back end.internal",
            "https://backend.internal:80443",
            "https://backend.internal:htt",
            "https://[gggg::1]",
            "https://[::1junk",
        ] {
            assert_eq!(
                RedactedLocator::of(named).to_string(),
                "<unparseable>",
                "{named:?} must be named, not echoed"
            );
        }
        assert_eq!(RedactedLocator::of("/mcp").to_string(), "<no-authority>");
        assert_eq!(
            RedactedLocator::of("https:///mcp").to_string(),
            "<no-authority>"
        );
    }
}
