// SPDX-License-Identifier: Apache-2.0
//! One HTTP EXCHANGE.
//!
//! One fact: **a request went out and this is what came back, or it did not go out.**
//!
//! A seam rather than a call, for two reasons that are not convenience. The protocol above
//! it is a state machine over statuses, media types and a `Location` header, and every one
//! of its refusals is establishable without a socket — so the machine is proved against a
//! service that speaks the protocol and nothing else. And the client that opens the socket
//! is the one part of this subtree that cannot exist in every build, because the default
//! serving closure deliberately links no HTTP client at all.
//!
//! It carries no protocol vocabulary. The types here are `method`, `url`, `headers`,
//! `body` and `status` — what HTTP is — so a successor protocol reuses them unchanged.

/// A request to send.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// The method, uppercase.
    pub method: &'static str,
    /// The absolute URL.
    pub url: String,
    /// Request headers, in the order they are to be sent.
    pub headers: Vec<(String, String)>,
    /// The body, empty for a request that has none.
    pub body: Vec<u8>,
}

/// What came back.
///
/// A non-2xx STATUS is a response, not an error: a `429` and a `403` are answers this
/// protocol reads, and a transport that turned them into failures would delete the
/// distinction between *refused* and *never asked*.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// The status code.
    pub status: u16,
    /// Response headers, lowercased names.
    pub headers: Vec<(String, String)>,
    /// The body, empty when there is none.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// The first value for `name`, which callers pass lowercased.
    pub(super) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Performing one exchange.
///
/// `Err` means the exchange did not complete — a connection that could not be made, a
/// read that failed part-way. It does NOT mean the server said no; that is a status.
pub trait HttpExchange {
    /// Send `request` and return what came back, or why nothing did.
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_lookup_ignores_case_and_takes_the_first() {
        let response = HttpResponse {
            status: 202,
            headers: vec![
                ("Location".to_owned(), "https://ts.example/op/1".to_owned()),
                ("location".to_owned(), "https://ts.example/op/2".to_owned()),
            ],
            body: Vec::new(),
        };
        assert_eq!(response.header("location"), Some("https://ts.example/op/1"));
        assert_eq!(response.header("retry-after"), None);
    }
}
