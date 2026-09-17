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
use mcp_re_core::verify_ed25519;
use mcp_re_core::SigningKey;
use mcp_re_http_profile::custody::DelegatedKeyWindow;
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
    /// The key lifecycle window this wiring was built from: `T` and `O`, `0 < O < T`.
    ///
    /// The sealed pair rather than the overlap alone. A consumer that reports or schedules
    /// on the overlap needs the TTL it was checked against, and handing back one number
    /// beside a config holding the other is the re-pairing this type exists not to do.
    pub window: DelegatedKeyWindow,
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
    let window = cfg.window;

    // The key the root issuer says it signs under, read ONCE at build. A backend that
    // cannot state its own public key cannot have its issuance checked against anything, and
    // an unverifiable issuer is not one this deployment publishes credentials from.
    let root_public_key = root_signer.response_public_key().ok();

    // ROOT ISSUER: sign the credential's compact-JWS signing input with the root
    // ResponseSigner (KMS/HSM/file), decoding its base64url raw Ed25519 signature to
    // the 64 bytes the JWS carries. Invoked at issuance/rotation ONLY. A transient
    // root failure → `None` → the custody treats it as a fail-closed issuance.
    //
    // The signature is then RE-VERIFIED under the key the root advertises, which is what the
    // response seam next door already does and this one did not. Downstream,
    // `issue_delegation_credential_with_signer` only length-checks the bytes that come back,
    // so before this a root backend wired to the wrong key — or one whose adapter returned
    // the right number of wrong bytes — published a credential every verifier in the fleet
    // rejects, discovered at the next request rather than at the first issuance. Fail-closed
    // here means the current key keeps serving until its own `exp`, which is the outcome the
    // custody state machine already guarantees.
    let issue: BoxedIssuer = Box::new(move |h, c| {
        issue_delegation_credential_with_signer(h, c, |input| {
            let b64 = root_signer
                .sign_response(input)
                .map_err(|_| HttpProfileError::DelegationCredentialInvalid)?;
            let public_key = root_public_key
                .as_ref()
                .ok_or(HttpProfileError::DelegationCredentialInvalid)?;
            verify_ed25519(input, &b64, public_key)
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
    // Class A, in its no-safe-value form. Continuing when the OS declines randomness
    // means minting a response-signing key from the zeroed seed this buffer was
    // initialised with — identical on every replica, reproducible by any reader of this
    // source. Aborting leaves the current credential serving until its own `exp` and then
    // failing closed, which is the outcome this module exists to guarantee.
    #[allow(clippy::expect_used)]
    let factory: BoxedKeyFactory = Box::new(|| {
        let mut seed: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *seed).expect("the OS CSPRNG yields a delegated key seed");
        SigningKey::from_seed_bytes(&seed)
    });

    let signer = Arc::new(DelegatedServerSigner::new());
    let custody = DelegatedSigningCustody::new(cfg, issue, factory);
    let rotor = DelegatedRotor::new(custody, Arc::clone(&signer));
    DelegatedSigningWiring {
        signer,
        rotor,
        window,
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
        let validated = crate::config_state::validation::ValidatedDeployment::try_from(config)
            .expect("the fixture must validate");
        crate::startup_plan::SigningPlan::from_validated(
            &validated,
            crate::startup_plan::response_issuer_kid(&validated),
            crate::startup_plan::TrustEpochPlan::from_validated(&validated),
        )
    }

    fn delegated_config() -> crate::deployment_request::DeploymentRequest {
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
        assert_eq!((wiring.window.ttl(), wiring.window.overlap()), (300, 60));
        // No key until the first rotate (fail-closed until issuance).
        assert!(wiring.signer.current(NOW).is_none());
        wiring.rotor.rotate(NOW).expect("initial issuance");
        let snap = wiring.signer.current(NOW).expect("a key is published");
        // The delegated kid is the RFC 7638 JWK thumbprint of the published key
        // itself (#415 rev 2 §1.5) — self-describing, so it is checkable against
        // the key without knowing the issuer's minting order. Chaining to the root
        // is asserted by the credential's `issuer_kid`, not by the kid string.
        assert_eq!(
            snap.delegated_kid(),
            mcp_re_http_profile::jwk_thumbprint_ed25519(&snap.key().public_key().to_b64url()),
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

    /// A root that signs under a key it does not advertise issues NOTHING.
    ///
    /// The seam's opaque callback is alg-agnostic, so the bytes it returns are not evidence
    /// of anything on their own — and downstream only their LENGTH is checked. A KMS or
    /// PKCS#11 adapter wired to the wrong key therefore produced a credential of exactly the
    /// right shape that every verifier in the fleet rejects, discovered at the next request
    /// rather than at the first issuance.
    ///
    /// The response seam next door has re-verified under its advertised key since #22; this
    /// is the producer half catching up to its own sibling.
    struct RootSigningUnderAnotherKey {
        signing: SigningKey,
        advertised: VerificationKey,
    }
    impl ResponseSigner for RootSigningUnderAnotherKey {
        fn sign_response(&self, preimage: &[u8]) -> Result<String, KeyError> {
            self.signing.sign_response(preimage)
        }
        fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
            Ok(self.advertised.clone())
        }
    }

    #[test]
    fn a_root_signing_under_a_key_it_does_not_advertise_publishes_no_credential() {
        let mismatched = RootSigningUnderAnotherKey {
            signing: SigningKey::from_seed_bytes(&ROOT_SEED),
            advertised: SigningKey::from_seed_bytes(&[34u8; 32]).public_key(),
        };
        let mut wiring = build_delegated_signing(&delegated_plan(), mismatched);

        assert!(
            wiring.rotor.rotate(NOW).is_err(),
            "a signature that does not verify under the advertised key is not an issuance"
        );
        assert!(
            wiring.signer.current(NOW).is_none(),
            "and nothing is published: the fleet never sees a credential it would reject"
        );
    }

    /// The mirror: a root that signs under the key it advertises still issues.
    ///
    /// Without it the refusal above is satisfied by a wiring that refuses every issuance,
    /// which would fail the deployment closed at startup and establish nothing about the
    /// pairing.
    #[test]
    fn a_root_signing_under_its_advertised_key_still_issues() {
        let root = SigningKey::from_seed_bytes(&ROOT_SEED);
        let advertised = root.public_key();
        let matched = RootSigningUnderAnotherKey {
            signing: SigningKey::from_seed_bytes(&ROOT_SEED),
            advertised,
        };
        let mut wiring = build_delegated_signing(&delegated_plan(), matched);
        wiring.rotor.rotate(NOW).expect("issuance");
        assert!(wiring.signer.current(NOW).is_some());
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

/// Delegated-key snapshots for the modules that hold one, minted the way production mints
/// them.
///
/// `#[cfg(test)]`, so it is not a production surface. It exists because
/// [`ActiveDelegatedKey`](mcp_re_http_profile::ActiveDelegatedKey) has no other way in: its
/// representation is private and its only producer derives the window from the credential,
/// so a fixture cannot pair `credential: "cred"` with an `exp` of its choosing — which is
/// exactly the inconsistency the seal exists to make unconstructible, and a test-only
/// constructor would hand straight back.
///
/// So a fixture runs the real state machine over a software root and takes what it
/// published. `exp` is `now + ttl` because that is what an issuance decides it is.
#[cfg(test)]
pub(crate) mod test_support {
    use mcp_re_core::SigningKey;
    use mcp_re_http_profile::custody::DelegatedKeyWindow;
    use mcp_re_http_profile::issue_delegation_credential;
    use mcp_re_http_profile::ActiveDelegatedKey;
    use mcp_re_http_profile::CustodyConfig;
    use mcp_re_http_profile::DelegatedSigningCustody;

    /// The root key every fixture credential chains to, and the `issuer_kid` naming it.
    pub(crate) const ROOT_KID: &str = "test-root-kid";

    /// The custody configuration the fixtures issue under.
    pub(crate) fn cfg(ttl: i64, overlap: i64) -> CustodyConfig {
        CustodyConfig {
            issuer_kid: ROOT_KID.into(),
            iss: "did:example:server".into(),
            profile: "mcp-re-http-v1".into(),
            aud: "verifier-1".into(),
            audience_hash: "aud-scope-1".into(),
            trust_epoch: "epoch-1".into(),
            server_role: "server".into(),
            server_trust_domain: "example.com".into(),
            server_subject: "did:example:server".into(),
            window: DelegatedKeyWindow::of(ttl, overlap).expect("0 < overlap < ttl"),
        }
    }

    /// The credential lifetime every fixture issuance is minted with.
    pub(crate) const FIXTURE_TTL: i64 = 3_600;

    /// A snapshot a real issuance produced, whose credential expires exactly at `exp`.
    ///
    /// `seed` picks the delegated key, so two fixtures are two different keys — and
    /// therefore two different `delegated_kid`s, since a delegated kid is the RFC 7638
    /// thumbprint of the key the credential attests. A fixture can no longer name its own
    /// kid, which is the point: it could not have named one the credential agreed with.
    pub(crate) fn issued_expiring_at(exp: i64, seed: u8) -> ActiveDelegatedKey {
        let root = SigningKey::from_seed_bytes(&[33u8; 32]);
        let mut custody = DelegatedSigningCustody::new(
            cfg(FIXTURE_TTL, FIXTURE_TTL / 6),
            move |h, c| Some(issue_delegation_credential(&root, h, c)),
            move || SigningKey::from_seed_bytes(&[seed; 32]),
        );
        custody
            .ensure_active(exp - FIXTURE_TTL)
            .expect("the software root issues");
        let active = custody.active_snapshot().expect("an issuance published");
        assert_eq!(active.exp(), exp, "the fixture window is the credential's");
        active
    }
}
