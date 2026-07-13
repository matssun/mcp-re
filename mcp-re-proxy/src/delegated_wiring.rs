// SPDX-License-Identifier: Apache-2.0
//! Production wiring of ADR-MCPRE-052 delegated response signing into the serving
//! binary (MCPRE-122 phase 2).
//!
//! [`build_delegated_signing`] turns a parsed [`Config`] plus a ROOT issuer into the
//! two halves the serving path runs across the hot/cold boundary (ADR-MCPRE-051 §5):
//!
//! - the shared [`DelegatedServerSigner`] the per-core fleet signs off (hot path);
//! - the [`DelegatedRotor`] a single background owner drives (cold path), where the
//!   root issuer is invoked at issuance/rotation ONLY.
//!
//! The root issuer is any [`ResponseSigner`] — the in-memory File/dev-Env key, or a
//! non-exporting Cloud KMS / PKCS#11 backend. The KMS is thus a *swap of the injected
//! signer*, not a code fork: the same seam the live GCP-KMS proof drives
//! (`gcp_kms_delegated_signing_live_test`). The root signs only the short-lived
//! delegation credential's compact-JWS signing input; the per-request RFC 9421
//! response signing uses the in-memory delegated key the credential binds, so the
//! **root is never on the request path**.

use std::sync::Arc;

use mcp_re_core::b64url_decode;
use mcp_re_core::SigningKey;
use mcp_re_http_profile::issue_delegation_credential_with_signer;
use mcp_re_http_profile::CustodyConfig;
use mcp_re_http_profile::DelegatedSigningCustody;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::PROFILE_TAG;

use crate::cli::Config;
use crate::delegated_server_signer::DelegatedRotor;
use crate::delegated_server_signer::DelegatedServerSigner;
use crate::key_source::ResponseSigner;

/// The root issuer closure the custody drives at issuance/rotation. Boxed so the
/// production rotor has a concrete type regardless of which root signer (KMS/file)
/// backs it. `Send` so the cold-path rotation thread can own it.
pub type BoxedIssuer =
    Box<dyn FnMut(&DelegationHeader, &DelegationClaims) -> Option<String> + Send>;

/// The delegated-key factory the custody calls per issuance/rotation. Boxed for the
/// same reason. `Send` for the rotation thread.
pub type BoxedKeyFactory = Box<dyn FnMut() -> SigningKey + Send>;

/// The concrete production rotor type — a [`DelegatedRotor`] over the boxed issuer /
/// factory, so the serving path and its background rotation thread name one type.
pub type ProdDelegatedRotor = DelegatedRotor<BoxedIssuer, BoxedKeyFactory>;

/// The built delegated-signing wiring: the shared hot-path signer, the cold-path
/// rotor a single owner drives, and the rotation-overlap window `O` the rotor uses to
/// mint a successor before each key's `exp`.
pub struct DelegatedSigningWiring {
    /// The shared, atomically-swappable delegated-key snapshot the fleet signs off.
    /// Install into the proxy via [`crate::HttpProfileProxy::new_delegated`].
    pub signer: Arc<DelegatedServerSigner>,
    /// The cold-path rotor. The caller performs the initial [`DelegatedRotor::rotate`]
    /// (fail-closed at startup if the root cannot issue) and then hands the rotor to a
    /// background thread that rotates within the overlap window.
    pub rotor: ProdDelegatedRotor,
    /// The rotation-overlap window `O` in seconds (`0 < O < T`).
    pub overlap: i64,
}

/// Build the delegated-signing wiring from `config` and a `root_signer` (the ROOT
/// issuer). Fails closed on an invalid custody policy. Does NOT issue the first key
/// or start any thread — the caller drives the initial [`DelegatedRotor::rotate`]
/// (so a startup issuance failure refuses to serve) and spawns the rotation thread.
///
/// `root_signer` signs ONLY the delegation credential's compact-JWS signing input at
/// issuance/rotation (never per response); a transient root failure yields `None`,
/// which the custody state machine treats as a fail-closed issuance.
pub fn build_delegated_signing(
    config: &Config,
    root_signer: impl ResponseSigner + Send + 'static,
) -> Result<DelegatedSigningWiring, String> {
    // The trust epoch is the ADR-MCPRE-052 §7 hard gate; it is required at parse time
    // in delegated-required mode, re-checked here so this builder is safe standalone.
    let trust_epoch = config.delegated_trust_epoch.clone().ok_or(
        "delegated-required response signing requires a trust epoch (--delegated-trust-epoch)",
    )?;
    // `0 < overlap < ttl` so the rotor mints a successor before the predecessor
    // expires (no signing gap). Enforced at parse time, re-checked here.
    if config.delegated_ttl_secs <= 0
        || config.delegated_overlap_secs <= 0
        || config.delegated_overlap_secs >= config.delegated_ttl_secs
    {
        return Err(format!(
            "delegated custody policy invalid: require 0 < overlap ({}) < ttl ({})",
            config.delegated_overlap_secs, config.delegated_ttl_secs
        ));
    }
    // Defaults: the issuer kid the credential chains to is the server key id; the
    // audience-scope hash is the verifier audience. Both are overridable so a
    // deployment can separate the root-key identity / audience-scope from the
    // response audience if its verifiers expect distinct values.
    let issuer_kid = config
        .delegated_issuer_kid
        .clone()
        .unwrap_or_else(|| config.server_key_id.clone());
    let audience_hash = config
        .delegated_audience_hash
        .clone()
        .unwrap_or_else(|| config.audience.clone());

    let cfg = CustodyConfig {
        issuer_kid,
        iss: config.server_signer.clone(),
        profile: PROFILE_TAG.to_string(),
        aud: config.audience.clone(),
        audience_hash,
        trust_epoch,
        server_role: "server".to_string(),
        server_trust_domain: config.trust_domain.clone(),
        server_subject: config.server_signer.clone(),
        ttl: config.delegated_ttl_secs,
        overlap: config.delegated_overlap_secs,
    };

    // ROOT ISSUER: sign the credential's compact-JWS signing input with the root
    // ResponseSigner (KMS/HSM/file), decoding its base64url raw Ed25519 signature to
    // the 64 bytes the JWS carries. Invoked at issuance/rotation ONLY. A transient
    // root failure → `None` → the custody treats it as a fail-closed issuance.
    let issue: BoxedIssuer = Box::new(move |h, c| {
        issue_delegation_credential_with_signer(h, c, |input| {
            let b64 = root_signer
                .sign_response(input)
                .map_err(|_| HttpProfileError::DelegationCredentialInvalid)?;
            b64url_decode(&b64).map_err(|_| HttpProfileError::DelegationCredentialInvalid)
        })
        .ok()
    });

    // DELEGATED-KEY FACTORY: a fresh in-memory Ed25519 key per issuance/rotation,
    // seeded from the OS CSPRNG (`getrandom`). The private key lives only in this
    // process and is replaced every TTL — never exported, never the root.
    let factory: BoxedKeyFactory = Box::new(|| {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("OS CSPRNG for delegated key seed");
        SigningKey::from_seed_bytes(&seed)
    });

    let signer = Arc::new(DelegatedServerSigner::new());
    let custody = DelegatedSigningCustody::new(cfg, issue, factory);
    let rotor = DelegatedRotor::new(custody, Arc::clone(&signer));
    Ok(DelegatedSigningWiring {
        signer,
        rotor,
        overlap: config.delegated_overlap_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_source::KeyError;
    use mcp_re_core::VerificationKey;

    const ROOT_SEED: [u8; 32] = [33u8; 32];
    const NOW: i64 = 1_700_000_100;

    /// Minimal delegated-required config via the real parser (so this exercises the
    /// production flag path too). Paths are placeholders — `build_delegated_signing`
    /// reads config FIELDS, not files.
    fn delegated_config() -> Config {
        let args: Vec<String> = [
            "--bind", "127.0.0.1:8443",
            "--audience", "verifier-1",
            "--server-signer", "did:example:server",
            "--server-key-id", "root-kid",
            "--signing-key-seed", "/dev/null",
            "--tls-cert", "/dev/null",
            "--tls-key", "/dev/null",
            "--client-ca", "/dev/null",
            "--trust", "/dev/null",
            "--inner-http-url", "http://127.0.0.1:9",
            "--target-uri", "https://mcp.example.com/mcp?route=a",
            // A durable replay selection so parse-time unsafe-config checks pass; the
            // path is not opened at parse (this builder reads config fields only).
            "--replay-cache", "file",
            "--replay-path", "/tmp/mcp-re-delegated-wiring-test-replay",
            "--delegated-trust-epoch", "epoch-1",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        crate::cli::parse_args(&args).expect("parse delegated-required config")
    }

    /// A ROOT issuer that always fails — proves fail-closed issuance flows through.
    struct FailingRoot;
    impl ResponseSigner for FailingRoot {
        fn sign_response(&self, _preimage: &[u8]) -> Result<String, KeyError> {
            Err(KeyError::NotFound("root offline".into()))
        }
        fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
            Err(KeyError::NotFound("root offline".into()))
        }
    }

    #[test]
    fn builds_and_first_rotate_publishes_a_snapshot() {
        let config = delegated_config();
        let root = SigningKey::from_seed_bytes(&ROOT_SEED);
        let mut wiring = build_delegated_signing(&config, root).expect("build wiring");
        assert_eq!(wiring.overlap, 60);
        // No key until the first rotate (fail-closed until issuance).
        assert!(wiring.signer.current(NOW).is_none());
        wiring.rotor.rotate(NOW).expect("initial issuance");
        let snap = wiring.signer.current(NOW).expect("a key is published");
        // The delegated kid chains to the configured issuer (root) kid.
        assert_eq!(snap.delegated_kid, "root-kid/delegated/1");
        // The root issuer was touched exactly once (issuance), never per read.
        assert_eq!(wiring.rotor.root_invocations(), 1);
    }

    #[test]
    fn ttl_bounds_the_published_snapshot() {
        let config = delegated_config();
        let root = SigningKey::from_seed_bytes(&ROOT_SEED);
        let mut wiring = build_delegated_signing(&config, root).expect("build wiring");
        wiring.rotor.rotate(NOW).expect("issue");
        // Valid within [nbf, exp); fails closed at exp (ttl = 300 default).
        assert!(wiring.signer.current(NOW + 299).is_some());
        assert!(wiring.signer.current(NOW + 300).is_none());
    }

    #[test]
    fn failing_root_fails_closed_at_first_issuance() {
        let config = delegated_config();
        let mut wiring = build_delegated_signing(&config, FailingRoot).expect("build wiring");
        // The root cannot issue and there is no prior key: rotate fails closed and
        // publishes nothing — the serving path would then refuse to start.
        assert!(wiring.rotor.rotate(NOW).is_err());
        assert!(wiring.signer.current(NOW).is_none());
    }
}
