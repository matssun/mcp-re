//! The operator-facing projection of the request's `inner_http_urls`.
//!
//! `--inner-http-url` is operator-supplied, and a URL's authority component is a place
//! credentials ride along (`https://user:pass@backend.internal/mcp`). The startup line
//! that names the backends must therefore print a *projection* of that field, never the
//! configured string — the same reason [`super::SecretString`] exists next door, applied
//! to a field whose secret is optional and positional rather than whole.
//!
//! The projection is owned by [`RedactedBackendUrls`]: the rendered text is its private
//! representation and its sole constructor performs the redaction, so possession of one
//! means the userinfo is already gone. There is no path from a raw URL list to a
//! rendered one that skips the redaction, and the type carries no `Debug` that would
//! offer a second, unredacted rendering.

use std::fmt;

use hyper::Uri;

/// The inner-backend URL list as an operator may see it: scheme, host, port and path,
/// with any `userinfo` removed and its presence reported instead.
pub(crate) struct RedactedBackendUrls(String);

impl RedactedBackendUrls {
    /// Render `urls` for a log line. Infallible on purpose: this is a projection for
    /// human eyes, and a URL the inner pool will reject must still be *nameable* in the
    /// message an operator reads while diagnosing that rejection.
    pub(crate) fn of(urls: &[String]) -> Self {
        let rendered = urls
            .iter()
            .map(|url| redact_one(url))
            .collect::<Vec<String>>()
            .join(", ");
        Self(format!("[{rendered}]"))
    }
}

impl fmt::Display for RedactedBackendUrls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Reduce one URL to the coordinates that identify a backend, dropping every part that
/// can carry a credential. A shape this cannot decompose is named as such rather than
/// echoed, because echoing is exactly what must not happen to an unparsed string.
fn redact_one(url: &str) -> String {
    let Ok(uri) = url.parse::<Uri>() else {
        return "<unparseable>".to_string();
    };
    let Some(authority) = uri.authority() else {
        return "<no-authority>".to_string();
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
    format!("{scheme}://{host}{port}{}{userinfo}", uri.path())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// LOAD-BEARING: the reason this type exists. A password in the authority must not
    /// reach the rendered text under any component of the projection.
    #[test]
    fn userinfo_never_reaches_the_rendered_text() {
        let rendered =
            RedactedBackendUrls::of(&["https://alice:hunter2@backend.internal/mcp".to_string()])
                .to_string();
        assert!(
            !rendered.contains("hunter2") && !rendered.contains("alice"),
            "credentials survived the projection: {rendered}"
        );
        assert_eq!(
            rendered,
            "[https://backend.internal/mcp (userinfo redacted)]"
        );
    }

    #[test]
    fn a_credential_free_url_renders_without_the_marker() {
        let rendered =
            RedactedBackendUrls::of(&["http://127.0.0.1:8621/mcp".to_string()]).to_string();
        assert_eq!(rendered, "[http://127.0.0.1:8621/mcp]");
    }

    #[test]
    fn every_backend_in_the_list_is_projected() {
        let rendered = RedactedBackendUrls::of(&[
            "http://a.internal:8621/mcp".to_string(),
            "https://bob:s3cr3t@b.internal/mcp".to_string(),
        ])
        .to_string();
        assert!(
            !rendered.contains("s3cr3t"),
            "second URL leaked: {rendered}"
        );
        assert_eq!(
            rendered,
            "[http://a.internal:8621/mcp, https://b.internal/mcp (userinfo redacted)]"
        );
    }

    /// An unusable configuration is named, not echoed: the echo is the leak.
    #[test]
    fn a_shape_the_projection_cannot_decompose_is_named_not_echoed() {
        let rendered = RedactedBackendUrls::of(&["not a url at all".to_string()]).to_string();
        assert_eq!(rendered, "[<unparseable>]");
        let relative = RedactedBackendUrls::of(&["/mcp".to_string()]).to_string();
        assert_eq!(relative, "[<no-authority>]");
    }

    #[test]
    fn an_empty_backend_list_renders_as_an_empty_list() {
        assert_eq!(RedactedBackendUrls::of(&[]).to_string(), "[]");
    }
}
