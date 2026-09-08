// SPDX-License-Identifier: Apache-2.0
//! The socket.
//!
//! One fact: **an exchange with a destination this deployment is allowed to reach.**
//!
//! It owns no protocol. It turns one [`HttpRequest`] into one [`HttpResponse`], and the
//! only judgement it makes is the one it does not make: a non-2xx status is a RESPONSE,
//! carried up with its headers and body, because `429` and `403` are answers the protocol
//! above reads and a transport that raised them would have deleted the difference between
//! *refused* and *never asked*.
//!
//! # Where it is allowed to reach
//!
//! Through [`VettedDestination::operator_configured`], which is the authority this
//! workspace already has for outbound network policy — the scheme allowlist, and the
//! `ureq` agent that carries the provenance's guard. There is no second egress policy
//! here: a registration endpoint is operator configuration, exactly like an OCSP
//! responder or a KMS endpoint, and inventing a parallel one would mean two answers to
//! *where may this process connect*.
//!
//! Redirects are refused by that agent, for every provenance. The first URL is the only
//! one any guard saw.

use std::time::Duration;

use crate::outbound_fetch::VettedDestination;

use super::exchange::HttpExchange;
use super::exchange::HttpRequest;
use super::exchange::HttpResponse;

/// A blocking HTTP transport over the workspace's outbound-network policy.
pub struct UreqExchange {
    /// The service's base destination, which is what passed the operator-configured guard.
    service: VettedDestination,
    /// Per-exchange timeout. The whole-registration bound is the policy's, above.
    timeout: Duration,
}

impl UreqExchange {
    /// A transport for the service at `base_url`, or `None` if its scheme is not allowed.
    ///
    /// `None` is a REFUSAL and every caller must treat it as one. It is deliberately not a
    /// transport that tries anyway.
    pub fn operator_configured(base_url: &str, timeout: Duration) -> Option<Self> {
        VettedDestination::operator_configured(base_url)
            .map(|service| UreqExchange { service, timeout })
    }
}

impl HttpExchange for UreqExchange {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        let agent = self.service.agent(self.timeout);
        let mut call = agent
            .request(request.method, &request.url)
            .timeout(self.timeout);
        for (name, value) in &request.headers {
            call = call.set(name, value);
        }
        let outcome = if request.body.is_empty() {
            call.call()
        } else {
            call.send_bytes(&request.body)
        };
        match outcome {
            Ok(response) => read(response),
            // A STATUS is an answer, not a failure. `ureq` reports every non-2xx as an
            // error; folding that into a transport failure here would make a `403` read
            // as "never asked", which is the one confusion this layer must not create.
            Err(ureq::Error::Status(_, response)) => read(response),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// One `ureq` response as a value, headers lowercased and body read.
fn read(response: ureq::Response) -> Result<HttpResponse, String> {
    let status = response.status();
    let headers: Vec<(String, String)> = response
        .headers_names()
        .iter()
        .filter_map(|name| {
            response
                .header(name)
                .map(|value| (name.to_ascii_lowercase(), value.to_owned()))
        })
        .collect();
    let mut body = Vec::new();
    std::io::Read::read_to_end(&mut response.into_reader(), &mut body)
        .map_err(|e| format!("the response body could not be read: {e}"))?;
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scheme the outbound-network policy does not allow is refused, not attempted.
    #[test]
    fn a_disallowed_scheme_yields_no_transport() {
        for url in [
            "file:///etc/passwd",
            "gopher://ts.example/",
            "not-a-url",
            "",
        ] {
            assert!(
                UreqExchange::operator_configured(url, Duration::from_secs(5)).is_none(),
                "{url:?}",
            );
        }
        assert!(UreqExchange::operator_configured(
            "https://ts.example.test",
            Duration::from_secs(5)
        )
        .is_some(),);
    }

    /// The socket path, against a real listener: a non-2xx STATUS comes back as a
    /// response with its headers and body, not as a transport failure.
    ///
    /// This is the lane the seam above cannot establish. `ureq` reports every non-2xx as
    /// an `Err`, and a transport that passed that through would make a `429` — which the
    /// protocol reads as *come back later* — indistinguishable from a connection that was
    /// never made.
    #[test]
    fn a_status_answer_survives_the_socket_as_a_response() {
        use std::io::Read;
        use std::io::Write;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a listener");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0_u8; 2048];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 429 Too Many Requests\r\n\
                      Retry-After: 30\r\n\
                      Content-Type: application/json\r\n\
                      Content-Length: 2\r\n\r\n{}",
                );
            }
        });

        let exchange = UreqExchange::operator_configured(
            &format!("http://127.0.0.1:{port}"),
            Duration::from_secs(5),
        )
        .expect("a loopback destination is one an operator may configure");
        let response = exchange
            .send(HttpRequest {
                method: "POST",
                url: format!("http://127.0.0.1:{port}/entries"),
                headers: vec![("content-type".to_owned(), "application/cose".to_owned())],
                body: b"statement".to_vec(),
            })
            .expect("a 429 is an answer, not a transport failure");

        assert_eq!(response.status, 429);
        assert_eq!(response.header("retry-after"), Some("30"));
        assert_eq!(response.body, b"{}");
    }

    /// And a real 200 with a body: the octets come back verbatim, lowercased headers and
    /// all, so the protocol above reads what the service actually sent.
    #[test]
    fn a_body_survives_the_socket_verbatim() {
        use std::io::Read;
        use std::io::Write;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a listener");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0_u8; 2048];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\n\
                      Content-Type: application/cose\r\n\
                      Content-Length: 5\r\n\r\n\xd2\x84\x43\xa1\x01",
                );
            }
        });

        let exchange = UreqExchange::operator_configured(
            &format!("http://127.0.0.1:{port}"),
            Duration::from_secs(5),
        )
        .expect("a loopback destination");
        let response = exchange
            .send(HttpRequest {
                method: "GET",
                url: format!("http://127.0.0.1:{port}/operations/1"),
                headers: Vec::new(),
                body: Vec::new(),
            })
            .expect("the exchange completes");

        assert_eq!(response.status, 200);
        assert_eq!(response.header("content-type"), Some("application/cose"));
        assert_eq!(response.body, b"\xd2\x84\x43\xa1\x01");
    }
}
