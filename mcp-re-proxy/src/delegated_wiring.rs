// SPDX-License-Identifier: Apache-2.0
//! Production wiring of ADR-MCPRE-052 delegated response signing into the serving
//! binary (MCPRE-122 phase 2).
//!
//! [`build_delegated_signing`] turns a [`SigningPlan`](crate::startup_plan::SigningPlan)
//! plus a ROOT issuer into the
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
use mcp_re_http_profile::DelegatedSigningCustody;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::HttpProfileError;
use zeroize::Zeroizing;

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

/// Build the delegated-signing wiring from a [`SigningPlan`](crate::startup_plan::SigningPlan)
/// and a `root_signer` (the ROOT issuer). Does NOT issue the first key or start any thread
/// — the caller drives the initial [`DelegatedRotor::rotate`] (so a startup issuance
/// failure refuses to serve) and spawns the rotation thread.
///
/// **Infallible, and that is the change.** It used to take a `DeploymentRequest` and re-decide two
/// things: that a trust epoch is present, and that `0 < overlap < ttl`. Both are layer-A
/// questions, both are boundary clauses now, and answering them here meant a deterministic
/// configuration invalidity was refused after the trust and TLS planes had already
/// established resources. The wiring is handed a policy and builds it.
///
/// `root_signer` signs ONLY the delegation credential's compact-JWS signing input at
/// issuance/rotation (never per response); a transient root failure yields `None`,
/// which the custody state machine treats as a fail-closed issuance.
pub fn build_delegated_signing(
    plan: &crate::startup_plan::SigningPlan,
    root_signer: impl ResponseSigner + Send + 'static,
) -> DelegatedSigningWiring {
    let cfg = plan.custody.clone();
    let overlap = cfg.overlap;

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
    // The seed is held in `Zeroizing` and scrubbed when this closure returns. Every
    // owned temporary holding a raw seed is wrapped this way (see `key_source.rs`); a
    // plain `[u8; 32]` here would leave one unscrubbed copy of a live response-signing
    // seed on the rotation thread's stack per rotation, for the process lifetime —
    // recoverable from a core dump, a swapped page, or a later stack disclosure.
    let factory: BoxedKeyFactory = Box::new(|| {
        let mut seed: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *seed).expect("OS CSPRNG for delegated key seed");
        SigningKey::from_seed_bytes(&seed)
    });

    let signer = Arc::new(DelegatedServerSigner::new());
    let custody = DelegatedSigningCustody::new(cfg, issue, factory);
    let rotor = DelegatedRotor::new(custody, Arc::clone(&signer));
    DelegatedSigningWiring {
        signer,
        rotor,
        overlap,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_source::KeyError;
    use mcp_re_core::VerificationKey;

    const ROOT_SEED: [u8; 32] = [33u8; 32];
    const NOW: i64 = 1_700_000_100;

    /// A minimal delegated plan, projected from a real parsed-and-validated config so
    /// this still exercises the production flag path and the boundary. Paths are
    /// placeholders — nothing here opens a file.
    fn delegated_plan() -> crate::startup_plan::SigningPlan {
        let config = delegated_config();
        let validated =
            crate::cli::ValidatedDeployment::try_from(config).expect("the fixture must validate");
        crate::startup_plan::SigningPlan::from_validated(
            &validated,
            crate::startup_plan::response_issuer_kid(&validated),
            crate::startup_plan::TrustEpochPlan::from_validated(&validated),
        )
    }

    fn delegated_config() -> crate::cli::DeploymentRequest {
        let args: Vec<String> = [
            "--bind",
            "127.0.0.1:8443",
            "--audience",
            "verifier-1",
            "--server-signer",
            "did:example:server",
            "--server-key-id",
            "root-kid",
            "--signing-key-seed",
            "/dev/null",
            "--tls-cert",
            "/dev/null",
            "--tls-key",
            "/dev/null",
            "--client-ca",
            "/dev/null",
            "--trust",
            "/dev/null",
            "--inner-http-url",
            "http://127.0.0.1:9",
            "--target-uri",
            "https://mcp.example.com/mcp?route=a",
            // A durable replay selection so parse-time unsafe-config checks pass; the
            // path is not opened at parse (this builder reads config fields only).
            "--replay-redis-url",
            "redis://127.0.0.1:6379",
            "--replay-durability-tier",
            "redis-wait-quorum:1:100",
            "--delegated-trust-epoch",
            "epoch-1",
            "--trust-domain",
            "mcp.example.com",
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
        let root = SigningKey::from_seed_bytes(&ROOT_SEED);
        let mut wiring = build_delegated_signing(&delegated_plan(), root);
        assert_eq!(wiring.overlap, 60);
        // No key until the first rotate (fail-closed until issuance).
        assert!(wiring.signer.current(NOW).is_none());
        wiring.rotor.rotate(NOW).expect("initial issuance");
        let snap = wiring.signer.current(NOW).expect("a key is published");
        // The delegated kid is the RFC 7638 JWK thumbprint of the published key
        // itself (#415 rev 2 §1.5) — self-describing, so it is checkable against
        // the key without knowing the issuer's minting order. Chaining to the root
        // is asserted by the credential's `issuer_kid`, not by the kid string.
        assert_eq!(
            snap.delegated_kid,
            mcp_re_http_profile::jwk_thumbprint_ed25519(&snap.key.public_key().to_b64url()),
        );
        // The root issuer was touched exactly once (issuance), never per read.
        assert_eq!(wiring.rotor.root_invocations(), 1);
    }

    #[test]
    fn ttl_bounds_the_published_snapshot() {
        let root = SigningKey::from_seed_bytes(&ROOT_SEED);
        let mut wiring = build_delegated_signing(&delegated_plan(), root);
        wiring.rotor.rotate(NOW).expect("issue");
        // Valid within [nbf, exp); fails closed at exp (ttl = 300 default).
        assert!(wiring.signer.current(NOW + 299).is_some());
        assert!(wiring.signer.current(NOW + 300).is_none());
    }

    #[test]
    fn failing_root_fails_closed_at_first_issuance() {
        let mut wiring = build_delegated_signing(&delegated_plan(), FailingRoot);
        // The root cannot issue and there is no prior key: rotate fails closed and
        // publishes nothing — the serving path would then refuse to start.
        assert!(wiring.rotor.rotate(NOW).is_err());
        assert!(wiring.signer.current(NOW).is_none());
    }
}
