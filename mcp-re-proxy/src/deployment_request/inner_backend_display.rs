// SPDX-License-Identifier: Apache-2.0
//! The operator-facing projection of the request's `inner_http_urls`.
//!
//! `--inner-http-url` is operator-supplied, and a URL carries credentials in more than
//! one position: userinfo (`https://user:pass@backend.internal/mcp`), a token in query
//! material, a bearer token as a path segment. The startup line that names the backends
//! must therefore print a *projection* of that field, never the configured string — the
//! same reason [`super::SecretString`] exists next door, applied to a field whose secret
//! is optional and positional rather than whole.
//!
//! The list is owned by [`InnerBackendUrls`]: its representation is private, its `Display`
//! and `Debug` both render through [`RedactedBackendUrls`], and the raw strings leave only
//! through [`InnerBackendUrls::expose`]. A request that carries the list can therefore be
//! printed, logged or `{:?}`-formatted without a call site choosing to redact. The rendered
//! form is itself owned by [`RedactedBackendUrls`]: its text is private and its sole
//! constructor performs the redaction.
//!
//! What ONE locator becomes is [`super::RedactedLocator`]'s, not this type's: this is the
//! list projection, and a second hand-written redaction beside that owner would be two
//! renderings of the same fact with one place to get it wrong.

use std::fmt;

use super::RedactedLocator;

/// The configured inner-backend URL list. Every rendering of it is the redacted one.
#[derive(Clone)]
pub struct InnerBackendUrls(Vec<String>);

impl InnerBackendUrls {
    /// The raw configured URLs. Every call site is a place a credential can escape, as with
    /// `SecretString::expose`: use it to build the pool or to inspect shape, never to print.
    pub fn expose(&self) -> &[String] {
        &self.0
    }
}

impl From<Vec<String>> for InnerBackendUrls {
    fn from(urls: Vec<String>) -> Self {
        Self(urls)
    }
}

impl fmt::Display for InnerBackendUrls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&RedactedBackendUrls::of(&self.0), f)
    }
}

impl fmt::Debug for InnerBackendUrls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&RedactedBackendUrls::of(&self.0), f)
    }
}

/// The inner-backend URL list as an operator may see it: scheme, host and port only,
/// with every credential-bearing component removed and its removal reported.
struct RedactedBackendUrls(String);

impl RedactedBackendUrls {
    /// Render `urls` for a log line. Infallible on purpose: this is a projection for
    /// human eyes, and a URL the inner pool will reject must still be *nameable* in the
    /// message an operator reads while diagnosing that rejection.
    fn of(urls: &[String]) -> Self {
        let rendered = urls
            .iter()
            .map(|url| RedactedLocator::of(url).to_string())
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
            "[https://backend.internal (userinfo removed, path removed)]"
        );
    }

    #[test]
    fn a_credential_free_url_renders_without_the_marker() {
        let rendered =
            RedactedBackendUrls::of(&["http://127.0.0.1:8621/mcp".to_string()]).to_string();
        assert_eq!(rendered, "[http://127.0.0.1:8621 (path removed)]");
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
            "[http://a.internal:8621 (path removed), https://b.internal (userinfo removed, \
             path removed)]"
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
    fn the_request_debug_print_carries_no_backend_credential() {
        let urls = InnerBackendUrls::from(vec![
            "https://alice:hunter2@backend.internal/mcp".to_string()
        ]);
        for rendered in [format!("{urls:?}"), format!("{urls}")] {
            assert!(
                !rendered.contains("hunter2") && !rendered.contains("alice"),
                "credentials survived a rendering of the owner: {rendered}"
            );
        }
        assert_eq!(
            urls.expose()[0],
            "https://alice:hunter2@backend.internal/mcp"
        );
    }

    #[test]
    fn an_empty_backend_list_renders_as_an_empty_list() {
        assert_eq!(RedactedBackendUrls::of(&[]).to_string(), "[]");
    }
}
