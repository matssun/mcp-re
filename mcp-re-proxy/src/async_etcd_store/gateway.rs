//! The transport connector for the configured etcd JSON gateway.
//!
//! One fact lives here: which scheme the connector was built to serve. An `https`
//! endpoint gets a rustls handshake against the native root store (so `SSL_CERT_FILE` /
//! `SSL_CERT_DIR` configure a private CA); an `http` endpoint gets plaintext. A connector
//! never serves a scheme it was not built for, so a plaintext connector is never handed an
//! `https` URI and a TLS connector never downgrades an `http` one. An endpoint the
//! connector could not serve is refused at construction, and no refusal names the
//! endpoint (Owner Ruling 6).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;

use hyper::Uri;
use hyper_util::client::legacy::connect::Connected;
use hyper_util::client::legacy::connect::Connection;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::RootCertStore;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tower_service::Service;

use crate::outbound_fetch::VettedDestination;
use crate::shared_replay::ReplayStoreError;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn refused(stage: &str) -> ReplayStoreError {
    ReplayStoreError::Unavailable {
        details: format!("etcd endpoint refused: {stage}"),
    }
}

/// Connects to the gateway: plaintext when `tls` is `None`, a TLS handshake when it is
/// `Some`.
#[derive(Clone)]
pub(super) struct GatewayConnector {
    http: HttpConnector,
    tls: Option<TlsConnector>,
}

impl GatewayConnector {
    /// The connector for `endpoint`, or a refusal when no request could be served for it.
    ///
    /// The scheme allowlist is [`VettedDestination::operator_configured`]'s; this
    /// function only reads which of the two allowed schemes was configured.
    pub(super) fn for_endpoint(endpoint: &str) -> Result<Self, ReplayStoreError> {
        let destination = VettedDestination::operator_configured(endpoint)
            .ok_or_else(|| refused("scheme is not http or https"))?;
        let uri: Uri = destination
            .url()
            .parse()
            .map_err(|_| refused("not a usable absolute URI"))?;
        if uri.authority().is_none() {
            return Err(refused("not a usable absolute URI"));
        }
        let tls = match uri.scheme_str() {
            Some("https") => Some(tls_connector(native_roots()?)?),
            Some("http") => None,
            _ => return Err(refused("scheme is not http or https")),
        };
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        Ok(GatewayConnector { http, tls })
    }
}

fn native_roots() -> Result<RootCertStore, ReplayStoreError> {
    let mut roots = RootCertStore::empty();
    let (added, _ignored) =
        roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    if added == 0 {
        return Err(refused("no TLS trust roots could be loaded"));
    }
    Ok(roots)
}

fn tls_connector(roots: RootCertStore) -> Result<TlsConnector, ReplayStoreError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| refused("TLS protocol versions unavailable"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// A connected gateway stream: plaintext or TLS.
pub(super) enum GatewayStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl Connection for GatewayStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl AsyncRead for GatewayStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            GatewayStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            GatewayStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for GatewayStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            GatewayStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            GatewayStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            GatewayStream::Plain(s) => Pin::new(s).poll_flush(cx),
            GatewayStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            GatewayStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            GatewayStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl Service<Uri> for GatewayConnector {
    type Response = TokioIo<GatewayStream>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        Box::pin(connect(self.http.clone(), self.tls.clone(), uri))
    }
}

/// One connection to `uri`: TLS exactly when the connector holds a TLS config and the
/// scheme is `https`, plaintext exactly when it holds none and the scheme is `http`.
async fn connect(
    mut http: HttpConnector,
    tls: Option<TlsConnector>,
    uri: Uri,
) -> Result<TokioIo<GatewayStream>, BoxError> {
    // The scheme is checked before any socket opens, so a mismatch writes nothing.
    let tls = match (uri.scheme_str(), tls) {
        (Some("https"), Some(tls)) => Some(tls),
        (Some("http"), None) => None,
        _ => return Err("connector does not serve this scheme".into()),
    };
    let tcp = http.call(uri.clone()).await?.into_inner();
    let Some(tls) = tls else {
        return Ok(TokioIo::new(GatewayStream::Plain(tcp)));
    };
    let host = uri.host().ok_or("uri has no host")?;
    let name = ServerName::try_from(host.trim_matches(['[', ']']).to_owned())?;
    let stream = tls.connect(name, tcp).await?;
    Ok(TokioIo::new(GatewayStream::Tls(Box::new(stream))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::Request;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    use std::io::Read;
    use std::time::Duration;

    fn empty_root_tls() -> TlsConnector {
        tls_connector(RootCertStore::empty()).expect("TLS config over an empty root store")
    }

    fn plaintext() -> GatewayConnector {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        GatewayConnector { http, tls: None }
    }

    #[tokio::test]
    async fn an_https_endpoint_opens_a_tls_handshake_never_plaintext() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let mut first = [0u8; 1];
                if conn.read_exact(&mut first).is_ok() {
                    let _ = tx.send(first[0]);
                }
            }
        });
        let mut connector = plaintext();
        connector.tls = Some(empty_root_tls());
        let client = Client::builder(TokioExecutor::new()).build(connector);
        let req = Request::post(format!("https://127.0.0.1:{port}/v3/kv/txn"))
            .body(Full::new(Bytes::from_static(b"{}")))
            .expect("request");
        let _ = tokio::time::timeout(Duration::from_secs(5), client.request(req)).await;
        let first = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the listener accepted a connection and read a byte");
        assert_eq!(first, 0x16, "the first byte is a TLS handshake record");
    }

    #[tokio::test]
    async fn a_connector_never_serves_a_scheme_it_was_not_built_for() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let https: Uri = format!("https://127.0.0.1:{port}/").parse().expect("uri");
        let http: Uri = format!("http://127.0.0.1:{port}/").parse().expect("uri");
        let mut tls_built = plaintext();
        tls_built.tls = Some(empty_root_tls());
        assert!(plaintext().call(https).await.is_err());
        assert!(tls_built.call(http).await.is_err());
        let accepted = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        assert!(
            accepted.is_err(),
            "a refused scheme must open no connection"
        );
    }

    #[test]
    fn a_scheme_outside_http_and_https_is_refused_at_construction_without_echoing_it() {
        for configured in [
            "ftp://ops:hunter2@etcd.internal:2379",
            "unix:///run/etcd.sock",
        ] {
            let refusal = GatewayConnector::for_endpoint(configured).err();
            let Some(ReplayStoreError::Unavailable { details }) = refusal else {
                panic!("{configured} must be refused");
            };
            for leaked in ["hunter2", "etcd.internal", configured] {
                assert!(
                    !details.contains(leaked),
                    "refusal echoed {leaked}: {details}"
                );
            }
        }
    }
}
