// SPDX-License-Identifier: Apache-2.0
//! `mcp-re-client` — the MCP-RE client-side ambassador, as a deployable artifact.
//!
//! ```text
//! local MCP client  --plain MCP/HTTP-->  mcp-re-client  --RFC 9421 + 9530 over mTLS-->  mcp-re-proxy
//!                   <--plain MCP--------                <--delegated-signed reply------
//! ```
//!
//! The pipeline is `mcp-re-client-proxy`'s and the mTLS leg is `mcp-re-transport`'s.
//! What this crate adds is the part a library cannot hold: process-lifetime state and
//! the wiring that makes ADR-MCPRE-052's trust-anchor lifecycle real in a deployment —
//! a signed manifest loaded against a DURABLE rollback floor, refreshed on a cadence,
//! published into the snapshot every route verifies against.
//!
//! Until this binary existed, `FileManifestFloor` and `load_signed_manifest_with_floor`
//! had no caller outside tests. The floor is durable state a process keeps across
//! restarts; a library can offer one and only a deployable can keep one. So
//! "restart-durable rollback protection" was a property the test suite demonstrated and
//! no deployment had.

pub mod anchors;
pub mod config;
pub mod serve;

use std::sync::Arc;

use mcp_re_client_core::DelegationPolicy;
use mcp_re_client_proxy::route::ClientVerification;
use mcp_re_client_proxy::AnchorSnapshot;
use mcp_re_client_proxy::ClientProxy;
use mcp_re_client_proxy::Route;
use mcp_re_client_proxy::RouteRegistry;
use mcp_re_core::b64url_decode;
use mcp_re_core::b64url_encode;
use mcp_re_core::SigningKey;
use mcp_re_host::NonceSource;
use mcp_re_host::SystemNonceSource;
use mcp_re_host::NONCE_BYTES;
use mcp_re_transport::remote::MtlsRemoteTransport;
use mcp_re_transport::ClientTlsConfig;
use mcp_re_transport::MtlsClient;
use zeroize::Zeroizing;

use crate::anchors::AnchorLoader;
use crate::config::ClientConfig;
use crate::config::ConfigError;

/// A startup failure. Every variant is fatal: the client refuses to run rather than
/// serve with a piece of its security posture missing.
#[derive(Debug)]
pub enum StartupError {
    /// The configuration document could not be used as written.
    Config(ConfigError),
    /// The trust anchors could not be loaded.
    Anchors(crate::anchors::AnchorError),
    /// Key material or a certificate could not be read.
    Material(String),
}

impl std::fmt::Display for StartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartupError::Config(e) => write!(f, "{e}"),
            StartupError::Anchors(e) => write!(f, "{e}"),
            StartupError::Material(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for StartupError {}

/// Read the Ed25519 signing seed: 32 bytes as Base64URL-no-pad text.
///
/// The file bytes and the decoded seed are held in `Zeroizing` so both are scrubbed on
/// drop, and the text is BORROWED from those bytes rather than copied into an owned
/// `String` — a UTF-8 failure on an owned copy would drop the secret unscrubbed.
pub fn read_signing_key(path: &std::path::Path) -> Result<SigningKey, StartupError> {
    let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
        std::fs::read(path)
            .map_err(|e| StartupError::Material(format!("signing key {}: {e}", path.display())))?,
    );
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| StartupError::Material("signing-key seed is not UTF-8".into()))?;
    let seed: Zeroizing<Vec<u8>> = Zeroizing::new(
        b64url_decode(text.trim())
            .map_err(|_| StartupError::Material("signing-key seed is not Base64URL".into()))?,
    );
    if seed.len() != 32 {
        return Err(StartupError::Material(
            "signing-key seed is not 32 bytes".into(),
        ));
    }
    // The fixed-size copy the constructor needs, scrubbed before it leaves scope; the
    // dalek key it produces is itself `ZeroizeOnDrop`.
    let mut fixed: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    fixed.copy_from_slice(&seed);
    Ok(SigningKey::from_seed_bytes(&fixed))
}

/// Warn when key material is readable beyond its owner.
///
/// A warning rather than a refusal, matching the proxy: a deployment that cannot set
/// the mode (a read-only projected secret with a fixed mask) should not be unable to
/// start, but an operator should never find out from an incident that the seed was
/// world-readable.
pub fn warn_if_permissive(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            let mode = metadata.permissions().mode() & 0o077;
            if mode != 0 {
                eprintln!(
                    "WARNING: {} is group/world accessible (mode {:o}); expected 0600",
                    path.display(),
                    metadata.permissions().mode() & 0o777
                );
            }
        }
    }
}

/// The assembled, running-ready client.
pub struct BuiltClient {
    /// The serving context the local listener drives.
    pub context: Arc<serve::ServeContext>,
    /// The anchors every route reads, so a refresh reaches all of them at once.
    pub snapshot: Arc<AnchorSnapshot>,
    /// The loader, handed to the refresher.
    pub loader: AnchorLoader,
    /// The expiry of the manifest that startup accepted.
    pub manifest_expires_at: i64,
    /// The accepted manifest version — the floor, after this start.
    pub manifest_version: u64,
}

/// Build everything from the configuration, loading the trust anchors once.
///
/// The startup load is FAIL-CLOSED: a client that cannot establish which roots it
/// trusts has no basis to verify anything, so it refuses to start rather than serving
/// while it waits for a manifest to appear.
pub fn build(config: &ClientConfig, now: i64) -> Result<BuiltClient, StartupError> {
    // Re-establish the document invariants on whatever was handed in. `from_json`
    // validates what it parses, but this function takes a `&ClientConfig` whose fields
    // are all public, so a caller that constructed or mutated one would otherwise reach
    // the signing pipeline with a config that has never been checked.
    config.validate().map_err(StartupError::Config)?;
    warn_if_permissive(&config.identity.signing_key_seed_path);
    let signing_key = read_signing_key(&config.identity.signing_key_seed_path)?;

    let mut loader = AnchorLoader::new(&config.trust).map_err(StartupError::Anchors)?;
    let loaded = loader.load(now).map_err(StartupError::Anchors)?;
    let snapshot = Arc::new(AnchorSnapshot::new(loaded.issuers));

    let policy = DelegationPolicy::new(
        config.delegation.verifier_audiences.clone(),
        config.delegation.expected_audience_hash.clone(),
        config.delegation.accepted_epochs.clone(),
        config.delegation.max_clock_skew,
    );

    let mut registry = RouteRegistry::new();
    for route in &config.routes {
        registry = registry.register(Route {
            route_id: route.route_id.clone(),
            target_uri: route.target_uri.clone(),
            audience: route.audience.clone(),
            artifact_bindings: route.resolve_bindings().map_err(StartupError::Config)?,
            extra_headers: route.header_pairs(),
            expected_server_keyid: route.expected_server_keyid.clone(),
            // Every route shares the ONE snapshot. A per-route copy would mean a
            // published revocation reaching some routes and not others, which is the
            // opposite of what "revoking an issuer_kid invalidates every descendant
            // immediately" promises.
            verification: ClientVerification::DelegatedAnchored(
                policy.clone(),
                Arc::clone(&snapshot),
            ),
        });
    }

    let transport = build_transport(config)?;
    let proxy = ClientProxy::new(
        registry,
        signing_key,
        config.identity.key_id.clone(),
        Box::new(transport),
    );

    let context = Arc::new(serve::ServeContext {
        proxy,
        default_route: config.local.default_route.clone(),
        request_lifetime_secs: config.local.request_lifetime_secs,
        max_in_flight: config.local.max_in_flight,
        allow_any_host: config.local.allow_non_loopback,
        clock: Box::new(|| {
            use mcp_re_host::Clock;
            mcp_re_host::SystemClock::new().now_unix()
        }),
        nonce: Box::new(next_nonce),
    });

    Ok(BuiltClient {
        context,
        snapshot,
        loader,
        manifest_expires_at: loaded.expires_at,
        manifest_version: loaded.version,
    })
}

/// A fresh RFC 9421 nonce: `NONCE_BYTES` of OS entropy, Base64URL-no-pad.
///
/// 16 bytes encode to 22 characters, which is exactly the emission floor the core
/// enforces — the nonce carries 128 bits and nothing here can shorten it.
pub fn next_nonce() -> String {
    let mut bytes = [0u8; NONCE_BYTES];
    SystemNonceSource::new().fill(&mut bytes);
    b64url_encode(&bytes)
}

fn build_transport(config: &ClientConfig) -> Result<MtlsRemoteTransport, StartupError> {
    let read = |path: &std::path::Path| -> Result<Vec<u8>, StartupError> {
        std::fs::read(path).map_err(|e| StartupError::Material(format!("{}: {e}", path.display())))
    };
    warn_if_permissive(&config.remote.client_key_path);
    let tls = ClientTlsConfig::from_pem(
        &read(&config.remote.client_cert_path)?,
        &read(&config.remote.client_key_path)?,
        &read(&config.remote.server_ca_path)?,
    )
    .map_err(|e| StartupError::Material(format!("client TLS material: {e}")))?;
    let client = MtlsClient::new(tls, &config.remote.expected_server_name)
        .map_err(|e| StartupError::Material(format!("mTLS client: {e}")))?;
    Ok(MtlsRemoteTransport::new(client, config.remote.addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The nonce must clear the core's 128-bit emission floor by construction, not by a
    /// caller remembering to check.
    #[test]
    fn the_nonce_clears_the_128_bit_emission_floor() {
        let nonce = next_nonce();
        assert_eq!(nonce.len(), 22, "16 bytes of entropy, Base64URL-no-pad");
        assert!(nonce.len() >= mcp_re_client_core::MIN_NONCE_CHARS);
        assert_ne!(nonce, next_nonce(), "each call draws fresh entropy");
    }
}
