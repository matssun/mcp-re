// SPDX-License-Identifier: Apache-2.0
//! One accepted connection, from the TCP stream to the last request served over it.
//!
//! Three facts live here, and they are sequential rather than interleaved: getting a peer
//! through the TLS handshake without letting it occupy the core, reading what the handshake
//! established about that peer, and running hyper over the result under the operator's
//! limits.
//!
//! The handshake admission bound is the one that is easy to lose. Under DELEGATED TLS
//! custody the `CertificateVerify` signature is produced by a blocking KMS round trip or a
//! PKCS#11 `C_Sign` inside rustls' SYNCHRONOUS `Signer::sign`, so `acceptor.accept` occupies
//! its worker thread for the whole call and no deadline can preempt it — the future never
//! yields, so the timer never runs. A worker pool is not a bound: a peer needs only as many
//! concurrent connections as there are workers, and it needs no client certificate to do it,
//! because TLS 1.3 signs `CertificateVerify` before the client's `Certificate` is ever seen.

use std::sync::Arc;

use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio_rustls::TlsAcceptor;

use crate::communication_assurance::mechanism_verified_credential::rustls_adapter::verified_credential;
use crate::tls::ServerOptions;

use super::core_admission::CoreAdmission;
use super::http_limits::http_builder;
use super::request::handle_request;
use super::AsyncRequestHandler;

/// Serve ONE accepted TCP connection: handshake it, read what the handshake established,
/// then run every request it carries under the operator's limits.
pub(super) async fn serve_connection<H: AsyncRequestHandler>(
    tcp: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    options: Arc<ServerOptions>,
    handler: Arc<H>,
    admission: CoreAdmission,
) -> std::io::Result<()> {
    let tls = establish_tls(tcp, acceptor, &options, &admission).await?;
    // THE ESTABLISHMENT BOUNDARY (ADR-MCPRE-063 Slice 4). `acceptor.accept` has
    // succeeded, so only now can the mechanism be asked which credential it associated
    // with the relationship. Captured ONCE — the credential is connection-constant and
    // hyper takes ownership of the TLS stream next. A refusal becomes an absent
    // credential and the fail-closed core downstream decides it; both refusals are
    // mechanism-boundary inconsistencies unreachable from this position.
    //
    // The whole chain, not just the leaf: the handshake verifier checks revocation to
    // the trust anchor (`RevocationCheckDepth::Chain`), so a per-request check that
    // stopped at the leaf would keep honouring a peer whose INTERMEDIATE was revoked
    // for as long as it held the connection open.
    // THE ESTABLISHMENT BOUNDARY: `accept` succeeded (ADR-MCPRE-064 Slice 1).
    let peer_credential = Arc::new(verified_credential(tls.get_ref().1).ok());

    // Read before `options` moves into the service closure below.
    let max_connection_age = options.limits.max_connection_age;
    let builder = http_builder(&options);

    let io = TokioIo::new(tls);
    let service = service_fn(move |req: Request<Incoming>| {
        let options = Arc::clone(&options);
        let handler = Arc::clone(&handler);
        let peer_credential = Arc::clone(&peer_credential);
        let admission = admission.clone();
        async move { handle_request(req, options, handler, peer_credential, admission).await }
    });
    // Serve every request on this connection (keep-alive / H2 multiplexed). A
    // connection-level error just ends this task; other connections are unaffected.
    //
    // MAX CONNECTION AGE: the peer's certificate was validated — chain, CRL, validity
    // window — at the handshake and is never re-consulted on an established connection. At
    // the age bound the connection is GRACEFULLY shut down: in-flight requests finish and
    // no new ones are accepted, so a peer that never reconnects is not served indefinitely
    // on one admission decision.
    //
    // This bound alone does not force re-verification. A TLS 1.3 peer that resumes presents
    // a PSK and sends no CertificateVerify, so the reconnection re-runs no chain or CRL
    // check. Resumption tickets are bound to the trust-anchor epoch, so an anchor change
    // invalidates them; a CRL reload does not. Per-request revocation is what holds against
    // a revoked-but-resuming peer.
    let conn = builder.serve_connection(io, service);
    tokio::pin!(conn);
    match max_connection_age {
        None => {
            let _ = conn.await;
        }
        Some(age) => {
            let deadline = tokio::time::sleep(age);
            tokio::pin!(deadline);
            let mut draining = false;
            loop {
                tokio::select! {
                    result = conn.as_mut() => {
                        let _ = result;
                        break;
                    }
                    // `draining` disarms this arm after it fires once: the elapsed
                    // sleep is immediately ready forever, so re-selecting it would
                    // spin instead of letting the graceful close complete.
                    _ = &mut deadline, if !draining => {
                        draining = true;
                        conn.as_mut().graceful_shutdown();
                    }
                }
            }
        }
    }
    Ok(())
}

/// Get one peer through the TLS handshake without letting it occupy the core.
///
/// The admission wait and the handshake itself are bounded differently on purpose. Waiting
/// for the cap is safe in a way the signature is not: that await YIELDS, so
/// `request_deadline` really does preempt it, and a connection that cannot get in before
/// the deadline is dropped rather than queued indefinitely. The handshake's own timeout is
/// applied all the same — it bounds the exported-key path, where the future does yield.
async fn establish_tls(
    tcp: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    options: &ServerOptions,
    admission: &CoreAdmission,
) -> std::io::Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>> {
    let _handshake = match (&admission.handshakes, options.limits.request_deadline) {
        (None, _) => None,
        (Some(semaphore), Some(deadline)) => Some(
            tokio::time::timeout(deadline, Arc::clone(semaphore).acquire_owned())
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "TLS handshake admission deadline",
                    )
                })?
                .map_err(|_| std::io::Error::other("TLS handshake admission closed"))?,
        ),
        (Some(semaphore), None) => Some(
            Arc::clone(semaphore)
                .acquire_owned()
                .await
                .map_err(|_| std::io::Error::other("TLS handshake admission closed"))?,
        ),
    };
    let tls = match options.limits.request_deadline {
        Some(deadline) => tokio::time::timeout(deadline, acceptor.accept(tcp))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake deadline")
            })??,
        None => acceptor.accept(tcp).await?,
    };
    // The permit is released HERE, not at the end of the connection: the bound is on
    // handshakes in progress, and an established connection costs no further device
    // signatures.
    drop(_handshake);
    Ok(tls)
}
