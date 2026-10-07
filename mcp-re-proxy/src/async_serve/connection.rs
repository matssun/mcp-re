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
use crate::communication_assurance::MechanismVerifiedCredentialEvidence;
use crate::tls::ServerOptions;

use super::core_admission::CoreAdmission;
use super::http_limits::{http_builder, idle_bound};
use super::open_connection::OpenConnection;
use super::request::handle_request;
use super::AsyncRequestHandler;

mod activity;
use activity::ConnectionActivity;

/// Serve ONE accepted TCP connection: handshake it, read what the handshake established,
/// then run every request it carries under the operator's limits.
pub(super) async fn serve_connection<H: AsyncRequestHandler>(
    tcp: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    options: Arc<ServerOptions>,
    handler: Arc<H>,
    admission: CoreAdmission,
    open: OpenConnection,
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

    serve_established(tls, options, handler, admission, peer_credential, open).await
}

/// Run hyper over an established stream until the peer, the age bound or the drain ends it.
///
/// Generic over the stream so the close sequence is exercised without a TLS handshake.
async fn serve_established<I, H>(
    stream: I,
    options: Arc<ServerOptions>,
    handler: Arc<H>,
    admission: CoreAdmission,
    peer_credential: Arc<Option<MechanismVerifiedCredentialEvidence>>,
    mut open: OpenConnection,
) -> std::io::Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    H: AsyncRequestHandler,
{
    // Read before `options` moves into the service closure below.
    let max_connection_age = options.client_credential_window.connection_age();
    let drain_grace = options.limits.drain_grace;
    let idle = idle_bound(&options);
    let builder = http_builder(&options);
    let activity = Arc::new(ConnectionActivity::default());

    let io = TokioIo::new(stream);
    let counted = Arc::clone(&activity);
    let service = service_fn(move |req: Request<Incoming>| {
        let options = Arc::clone(&options);
        let handler = Arc::clone(&handler);
        let peer_credential = Arc::clone(&peer_credential);
        let admission = admission.clone();
        let in_flight = counted.begin();
        async move {
            let _in_flight = in_flight;
            handle_request(req, options, handler, peer_credential, admission).await
        }
    });
    // Serve every request on this connection (keep-alive / H2 multiplexed). A
    // connection-level error just ends this task; other connections are unaffected.
    //
    // TWO things end a connection, and both are the same move: a graceful close, so
    // in-flight requests finish and their responses are written and no new request is
    // accepted, followed by a cut once `drain_grace` has passed. A peer that stops reading
    // cannot hold its connection permit past the age bound plus `drain_grace`.
    //
    // MAX CONNECTION AGE: the peer's certificate was validated — chain, CRL, validity
    // window — at the handshake and is never re-consulted on an established connection. At
    // the age bound the connection is shut down, so a peer that never reconnects is not
    // served indefinitely on one admission decision.
    //
    // This bound alone does not force re-verification. A TLS 1.3 peer that resumes presents
    // a PSK and sends no CertificateVerify, so the reconnection re-runs no chain or CRL
    // check. Resumption tickets are bound to the trust-anchor epoch, so an anchor change
    // invalidates them; a CRL reload does not. Per-request revocation is what holds against
    // a revoked-but-resuming peer.
    //
    // IDLE: a connection carrying no request for the idle bound is closed the same way.
    // HTTP/1 already bounds the gap between requests; this is what bounds it on HTTP/2,
    // where a peer answering keep-alive PINGs would otherwise hold its permit to the age.
    //
    // THE DRAIN: on the core's shutdown the connection is shut down the same way, so a
    // kept-alive connection stops admitting requests and one with a reply being written
    // finishes it. The core's drain waits on this task, so it ends after the reply does.
    let conn = builder.serve_connection(io, service);
    tokio::pin!(conn);
    let age = tokio::time::sleep(max_connection_age);
    tokio::pin!(age);
    let idle = async {
        match idle {
            Some(bound) => activity.idle_for(bound).await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        _ = conn.as_mut() => return Ok(()),
        () = &mut age => {}
        () = idle => {}
        () = open.draining() => {}
    }
    conn.as_mut().graceful_shutdown();
    let _ = tokio::time::timeout(drain_grace, conn.as_mut()).await;
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::config_state::ClientCredentialWindow;
    use crate::tls::ServerLimits;

    fn admission(options: &ServerOptions) -> CoreAdmission {
        let pool = crate::async_fleet::CorePool::for_core(
            crate::async_fleet::ShardDepth::stated(2),
            crate::config_state::PrivateKeyExposure::ProcessReadable,
        )
        .expect("an exported key admits every depth");
        CoreAdmission::for_core(options, pool.handshake_bound())
    }

    /// A peer that stops reading holds the connection only until the age bound plus the
    /// grace window; the connection is then cut rather than awaited.
    #[test]
    fn a_stalled_response_write_is_cut_after_the_age_bound_and_the_grace() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let options = Arc::new(ServerOptions {
                limits: ServerLimits {
                    drain_grace: Duration::from_millis(200),
                    ..ServerLimits::default()
                },
                ..ServerOptions::new(
                    ClientCredentialWindow::new(
                        Duration::from_secs(3600),
                        Duration::from_millis(50),
                    )
                    .expect("a legal credential window"),
                )
            });
            let admission = admission(&options);
            let open = OpenConnection::accepted(&admission);
            let handler = Arc::new(|_request| -> super::super::HandlerResponseFuture {
                Box::pin(std::future::pending())
            });
            let (server, mut peer) = tokio::io::duplex(8);
            // The peer sends its request and then never reads; the half stays open.
            let peer_side = async {
                peer.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                    .await
                    .expect("request written");
                std::future::pending::<()>().await;
            };
            let served = tokio::time::timeout(Duration::from_secs(5), async {
                tokio::select! {
                    result = serve_established(
                        server, options, handler, admission, Arc::new(None), open,
                    ) => result,
                    () = peer_side => unreachable!("the peer side never completes"),
                }
            })
            .await;
            assert!(served.is_ok(), "the connection must be cut, not awaited");
        });
    }
}
