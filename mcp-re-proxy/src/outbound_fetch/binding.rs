// SPDX-License-Identifier: Apache-2.0
//! Installing this authority's policy into an HTTP client.
//!
//! One fact: **the client a destination hands out enforces the guard that destination
//! passed.** The policy above it — the scheme allowlist, the private-address
//! classification, the `inet_aton` canonicalizer — is unconditional and decides
//! admissibility once. This is the other half, and it is a different thing: a decision
//! already taken becomes a capability that carries it, so that no caller holds a verdict
//! it could act on incorrectly.
//!
//! It lives behind the features that link an HTTP client, for the reason given where they
//! are named. Nothing here decides whether a destination is legitimate.

use std::time::Duration;

use super::resolver::VettingResolver;
use super::{Provenance, VettedDestination};

impl VettedDestination {
    /// An HTTP agent configured for THIS destination's provenance.
    ///
    /// Feature-gated with the resolver it installs, for the reason stated above the
    /// module: the guard is unconditional, binding it to an HTTP client cannot be.
    ///
    /// A capability, not a flag. Redirects are disabled for every provenance — a revocation
    /// fetch has no legitimate need to chase a `302 Location: http://169.254.169.254/`, and
    /// the first URL is the only one any guard saw. The resolved-address vetting is
    /// installed only for a certificate-derived destination, for the same reason the
    /// literal-address block is.
    pub fn agent(&self, _timeout: Duration) -> ureq::Agent {
        let builder = ureq::AgentBuilder::new().redirects(0);
        let builder = match self.provenance {
            Provenance::CertificateDerived => builder.resolver(VettingResolver::std()),
            Provenance::OperatorConfigured => builder,
        };
        builder.build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The client does not chase a `Location:` — for any provenance, and whoever answered.
    ///
    /// A redirect names an authority nothing here vetted, chosen by the responder. On a
    /// credential path that is the whole attack: the guard saw the first URL and no other.
    /// The vetted responder below answers `302` pointing at a second listener; the agent
    /// must hand the redirect back as the response and never connect to the second.
    #[test]
    fn an_agent_does_not_follow_a_redirect_and_never_reaches_the_second_authority() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let elsewhere = TcpListener::bind("127.0.0.1:0").expect("bind the redirect target");
        let elsewhere_port = elsewhere.local_addr().expect("addr").port();
        let reached = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&reached);
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = elsewhere.accept() {
                flag.store(true, Ordering::SeqCst);
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            }
        });

        let responder = TcpListener::bind("127.0.0.1:0").expect("bind the vetted responder");
        let responder_port = responder.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = responder.accept() {
                let mut buf = [0_u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{elsewhere_port}/\r\n\
                         Content-Length: 0\r\n\r\n"
                    )
                    .as_bytes(),
                );
            }
        });

        let destination =
            VettedDestination::operator_configured(format!("http://127.0.0.1:{responder_port}/"))
                .expect("a loopback http destination is one an operator may configure");
        let outcome = destination
            .agent(Duration::from_secs(5))
            .post(destination.url())
            .timeout(Duration::from_secs(5))
            .send_string("");
        assert_eq!(
            outcome.map(|response| response.status()).ok(),
            Some(302),
            "the responder's own redirect must be what the caller sees"
        );
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            !reached.load(Ordering::SeqCst),
            "the authority named by the redirect was connected to"
        );
    }
}
