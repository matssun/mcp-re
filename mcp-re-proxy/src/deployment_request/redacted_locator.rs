// SPDX-License-Identifier: Apache-2.0
//! The one way an operator-supplied URL or locator is rendered for human eyes.
//!
//! Every locator this deployment takes — `--inner-http-url`, `--admission-redis-url`,
//! `--trust-epoch-redis-url`, `--continuation-control-redis-url`, `--replay-redis-url`,
//! `--cpstore-etcd-endpoint`, `--target-uri` — is a string an operator typed, and the
//! authority component of a URL is a place credentials ride along
//! (`https://user:pass@host/path`, `redis://:hunter2@host:6379`). A diagnostic that
//! echoes the configured string therefore publishes the credential into whatever reads
//! the startup output, and it does so on exactly the path where the string was WRONG —
//! which is the path a typo takes.
//!
//! [`RedactedLocator`] owns that rendering. The rendered text is its private
//! representation and its sole constructor performs the redaction, so possession of one
//! means the userinfo is already gone. There is no path from a raw locator to a rendered
//! one that skips the redaction: no `Debug`, no `as_str`, no `From<String>`, no field
//! accessor. A second rendering path is the defect this type exists to remove, and two
//! independently authored redactions are that defect in its most durable form.

use std::fmt;

use hyper::Uri;

/// One operator-supplied locator as an operator may see it: scheme, host, port and path,
/// with any `userinfo` removed and its presence reported instead.
///
/// A shape this cannot decompose is NAMED rather than echoed, because echoing is exactly
/// what must not happen to an unparsed string — a credential-bearing value that fails the
/// deployment's own `://` shape check (`mats:hunter2@host:6379`) reaches the violation
/// message by that route and no other.
pub(crate) struct RedactedLocator(String);

impl RedactedLocator {
    /// Render `raw` for a human-readable line. Infallible on purpose: this is a
    /// projection for human eyes, and a locator the deployment REFUSES must still be
    /// nameable in the message an operator reads while diagnosing that refusal.
    pub(crate) fn of(raw: &str) -> Self {
        let Ok(uri) = raw.parse::<Uri>() else {
            return Self("<unparseable>".to_string());
        };
        let Some(authority) = uri.authority() else {
            return Self("<no-authority>".to_string());
        };
        let scheme = uri.scheme_str().unwrap_or("<no-scheme>");
        let host = authority.host();
        let port = authority
            .port_u16()
            .map_or_else(String::new, |port| format!(":{port}"));
        // `Authority::host` already returns the host alone; the `@` test is what lets the
        // line SAY that credentials were configured, which is the fact an operator needs.
        let userinfo = if authority.as_str().contains('@') {
            " (userinfo redacted)"
        } else {
            ""
        };
        Self(format!("{scheme}://{host}{port}{}{userinfo}", uri.path()))
    }
}

impl fmt::Display for RedactedLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
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
        assert_eq!(rendered, "https://backend.internal/mcp (userinfo redacted)");
    }

    /// LOAD-BEARING: this is the exact leak. A credential-bearing value with no `://` is
    /// precisely what every locator-shape violation in `config_state` fires on, so the
    /// rendering of THIS shape is what stands between a typo and a password in the
    /// startup diagnostic. It must be named, never echoed.
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
    }

    #[test]
    fn a_credential_free_locator_renders_without_the_marker() {
        assert_eq!(
            RedactedLocator::of("redis://redis.internal:6379").to_string(),
            "redis://redis.internal:6379/"
        );
        assert_eq!(
            RedactedLocator::of("http://127.0.0.1:8621/mcp").to_string(),
            "http://127.0.0.1:8621/mcp"
        );
    }

    #[test]
    fn a_shape_the_projection_cannot_decompose_is_named() {
        assert_eq!(
            RedactedLocator::of("not a url at all").to_string(),
            "<unparseable>"
        );
        assert_eq!(RedactedLocator::of("/mcp").to_string(), "<no-authority>");
        assert_eq!(RedactedLocator::of("").to_string(), "<unparseable>");
    }
}
