//! MCPS-84 (ADR-MCPS-049 W2) — live Redis trust-epoch source.
//!
//! Proves the networked half of the trust-epoch invalidation source against a
//! real Redis: a `TrustEpochSource` over a `RedisEpochReader` reads a shared epoch
//! key and emits a coarse `FlushAll` when an operator advances that epoch on a
//! DIFFERENT connection (`INCR`) — the cross-connection propagation a fleet relies
//! on. The epoch→event logic itself (baseline, steady, error→unhealthy,
//! self-healing) is unit-tested without Redis in `src/trust_epoch.rs`; this proves
//! the Redis reader wiring.
//!
//! Feature-gated on `redis_replay`, skipped when `MCP_RE_TEST_REDIS_URL` is unset
//! (hard-failed under `MCP_RE_REQUIRE_LIVE_INFRA`), mirroring
//! `redis_replay_e2e_test.rs`.
#![cfg(feature = "redis_replay")]

use mcp_re_proxy::trust_epoch::redis_trust_epoch_source;
use mcp_re_proxy::InvalidationChannel;
use mcp_re_proxy::InvalidationEvent;

fn redis_url() -> Option<String> {
    let url = std::env::var("MCP_RE_TEST_REDIS_URL")
        .ok()
        .filter(|u| !u.trim().is_empty());
    if url.is_none() && std::env::var("MCP_RE_REQUIRE_LIVE_INFRA").is_ok_and(|v| !v.is_empty()) {
        panic!("MCP_RE_REQUIRE_LIVE_INFRA is set but MCP_RE_TEST_REDIS_URL is unavailable");
    }
    url
}

fn unique_epoch_key() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("mcp-re:test:trust:epoch:{now}")
}

#[test]
fn epoch_advance_on_redis_is_detected_as_flush_all() {
    let Some(url) = redis_url() else {
        eprintln!(
            "SKIP epoch_advance_on_redis_is_detected_as_flush_all: MCP_RE_TEST_REDIS_URL unset"
        );
        return;
    };
    let key = unique_epoch_key();

    // Admin connection: the "operator" that bumps the trust epoch.
    let mut admin = redis::Client::open(url.as_str())
        .expect("open redis client")
        .get_connection()
        .expect("admin connection");
    // Establish a concrete starting epoch.
    let _: () = redis::cmd("SET")
        .arg(&key)
        .arg(1_i64)
        .query(&mut admin)
        .expect("SET epoch=1");

    // The source is a SEPARATE connection, as a sibling replica would be.
    let source = redis_trust_epoch_source(&url, &key).expect("connect trust-epoch source");

    // First poll establishes the baseline (epoch=1): no flush. `poll_once` is the
    // read; `drain_pending` is the queue the request path takes, and it does no I/O.
    source.poll_once();
    assert!(
        source.drain_pending().is_empty(),
        "baseline poll must not flush"
    );
    assert!(source.is_healthy(), "a successful read is healthy");

    // Operator advances the epoch on the admin connection.
    let _: i64 = redis::cmd("INCR")
        .arg(&key)
        .query(&mut admin)
        .expect("INCR epoch -> 2");

    // The source, on its own connection, detects the advance and flushes.
    source.poll_once();
    assert_eq!(
        source.drain_pending(),
        vec![InvalidationEvent::FlushAll],
        "an epoch advance on another connection must surface as FlushAll"
    );
    // Steady epoch: no further flush.
    source.poll_once();
    assert!(
        source.drain_pending().is_empty(),
        "a steady epoch must not flush again"
    );

    // A second advance flushes again.
    let _: i64 = redis::cmd("INCR")
        .arg(&key)
        .query(&mut admin)
        .expect("INCR epoch -> 3");
    source.poll_once();
    assert_eq!(
        source.drain_pending(),
        vec![InvalidationEvent::FlushAll],
        "a second epoch advance must flush again"
    );

    // An ABSENT key is a read FAILURE, never a live epoch 0: reading it as a baseline
    // left the push kill switch silently inert whenever the key was never created,
    // pointed at the wrong database, or lost to a restore or an eviction.
    let _: () = redis::cmd("DEL")
        .arg(&key)
        .query(&mut admin)
        .expect("DEL epoch key");
    let Err(err) = redis_trust_epoch_source(&url, &key) else {
        panic!("an absent epoch key must fail closed, not read as epoch 0");
    };
    assert!(
        err.contains("does not exist"),
        "the refusal must name the absent key so the operator can seed it: {err}"
    );
}

// ---------------------------------------------------------------------------
// Cross-replica revocation coherence through the FULL serving path
// ---------------------------------------------------------------------------
//
// MCPS-86 (ADR-MCPS-049 W1, proof b). The lane above proves the epoch source
// itself. This one proves the property a fleet actually depends on, through the
// production serving PEP (`HttpProfileProxy`) wired exactly as `app.rs` wires it
// — a Tier-3 `PushInvalidationTrustCache` over the live Redis trust-epoch source,
// adapted by the production `build_actor_resolver`:
//
//   a key revoked in the authoritative store is still served by a SIBLING replica
//   (bounded-`T` staleness — the negative control) until an operator advances the
//   shared trust epoch, at which point the sibling flushes and rejects.
#[cfg(feature = "async_serve")]
mod serving_path {
    use std::collections::HashMap;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    use mcp_re_core::SigningKey;
    use mcp_re_core::TrustResolver;
    use mcp_re_core::TrustResolverError;
    use mcp_re_core::VerificationKey;

    use mcp_re_http_profile::issue_delegation_credential;
    use mcp_re_http_profile::sign_request_full;
    use mcp_re_http_profile::ActorIdentity;
    use mcp_re_http_profile::ArtifactBinding;
    use mcp_re_http_profile::ArtifactType;
    use mcp_re_http_profile::AudienceTuple;
    use mcp_re_http_profile::CustodyConfig;
    use mcp_re_http_profile::DelegatedSigningCustody;
    use mcp_re_http_profile::DelegationClaims;
    use mcp_re_http_profile::DelegationHeader;
    use mcp_re_http_profile::HttpRequest;
    use mcp_re_http_profile::HttpRequestEvidenceBlock;
    use mcp_re_http_profile::PROFILE_TAG;

    use mcp_re_proxy::app::build_actor_resolver;
    use mcp_re_proxy::async_replay::AsyncReplayTier;
    use mcp_re_proxy::async_replay::InMemoryAsyncAtomicReplayStore;
    use mcp_re_proxy::async_serve::ServedHttpRequest;
    use mcp_re_proxy::http_profile_dispatch::ProxyDispatchConfig;
    use mcp_re_proxy::trust_epoch::redis_trust_epoch_source;
    use mcp_re_proxy::trust_epoch::RedisEpochReader;
    use mcp_re_proxy::trust_epoch::SharedEpochChannel;
    use mcp_re_proxy::trust_epoch::TrustEpochSource;
    use mcp_re_proxy::DelegatedRotor;
    use mcp_re_proxy::DelegatedServerSigner;
    use mcp_re_proxy::HttpProfileProxy;
    use mcp_re_proxy::PushInvalidationTrustCache;

    const CLIENT_SEED: [u8; 32] = [11u8; 32];
    const ROOT_SEED: [u8; 32] = [33u8; 32];
    const TARGET: &str = "https://mcp.example.com/mcp?route=a";
    const ACCESS_TOKEN: &str = "access-token-xyz";
    const CLIENT_KEY_ID: &str = "client-key-1";
    const CLIENT_SIGNER: &str = "did:example:agent-1";
    const ROOT_KID: &str = "root-kid";
    const VERIFIER_AUD: &str = "verifier-1";
    /// The Tier-1 bounded window. Long enough that nothing here expires by time —
    /// so the ONLY thing that can revoke within the test is the epoch advance, and
    /// the negative control cannot pass for the wrong reason.
    const T_SECS: i64 = 3_600;

    fn client_key() -> SigningKey {
        SigningKey::from_seed_bytes(&CLIENT_SEED)
    }
    fn root_key() -> SigningKey {
        SigningKey::from_seed_bytes(&ROOT_SEED)
    }
    fn audience() -> AudienceTuple {
        AudienceTuple {
            audience_id: VERIFIER_AUD.into(),
            target_uri: TARGET.into(),
            route: Some("a".into()),
        }
    }
    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64
    }

    /// The AUTHORITATIVE trust store both replicas resolve through. Flipping
    /// `revoked` models an operator revoking the binding in that store — which a
    /// replica only observes once its cache is flushed.
    struct AuthoritativeStore {
        revoked: Arc<AtomicBool>,
    }

    impl TrustResolver for AuthoritativeStore {
        fn resolve(
            &self,
            _signer: &str,
            _key_id: &str,
        ) -> Result<VerificationKey, TrustResolverError> {
            if self.revoked.load(Ordering::SeqCst) {
                return Err(TrustResolverError::Revoked);
            }
            Ok(client_key().public_key())
        }
    }

    /// A replica wired the way `app.rs` wires the production serving path: the
    /// Request slot resolves through a Tier-3 push cache fed by the LIVE Redis
    /// trust-epoch source, on its OWN connection, as a sibling replica would.
    /// The replica plus the handle its epoch POLLER runs on. The poll is off the
    /// request path in production (a blocking Redis GET inline on the async serve path
    /// serialized the whole fleet on one connection), so the test drives it explicitly
    /// where a request used to trigger it.
    struct Replica {
        proxy: HttpProfileProxy,
        epoch: Arc<TrustEpochSource<RedisEpochReader>>,
    }

    fn replica(url: &str, epoch_key: &str, revoked: Arc<AtomicBool>) -> Replica {
        let source =
            Arc::new(redis_trust_epoch_source(url, epoch_key).expect("connect trust-epoch source"));
        let cache = PushInvalidationTrustCache::new(
            Box::new(AuthoritativeStore { revoked }),
            T_SECS,
            T_SECS,
            Box::new(now),
            Box::new(SharedEpochChannel(Arc::clone(&source))),
        );
        let mut client_signers = HashMap::new();
        client_signers.insert(CLIENT_KEY_ID.to_string(), CLIENT_SIGNER.to_string());
        let trust_store = Arc::new(mcp_re_proxy::reloading_trust::ReloadingTrustStore::new(
            mcp_re_core::InMemoryTrustResolver::default(),
            client_signers,
        ));
        let resolve_actor = build_actor_resolver(
            trust_store.signer_directory(),
            Arc::new(cache),
            "example.com".to_string(),
            ROOT_KID.to_string(),
            ActorIdentity {
                role: "server".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:server".into(),
                keyid: ROOT_KID.into(),
            },
            root_key().public_key(),
        );

        let signer = Arc::new(DelegatedServerSigner::new());
        let root = root_key();
        let issue = move |h: &DelegationHeader, c: &DelegationClaims| {
            Some(issue_delegation_credential(&root, h, c))
        };
        let mut n = 100u8;
        let factory = move || {
            n = n.wrapping_add(1);
            SigningKey::from_seed_bytes(&[n; 32])
        };
        let custody = CustodyConfig {
            issuer_kid: ROOT_KID.into(),
            iss: "did:example:server".into(),
            profile: PROFILE_TAG.into(),
            aud: VERIFIER_AUD.into(),
            audience_hash: VERIFIER_AUD.into(),
            trust_epoch: "epoch-1".into(),
            server_role: "server".into(),
            server_trust_domain: "example.com".into(),
            server_subject: "did:example:server".into(),
            ttl: 300,
            overlap: 60,
        };
        let mut rotor = DelegatedRotor::new(
            DelegatedSigningCustody::new(custody, issue, factory),
            Arc::clone(&signer),
        );
        rotor.rotate(now()).expect("issue the first delegated key");

        Replica {
            proxy: HttpProfileProxy::new_delegated(
                resolve_actor,
                audience(),
                AsyncReplayTier::new(Arc::new(InMemoryAsyncAtomicReplayStore::new()), 60),
                ProxyDispatchConfig {
                    fleet_strict: false,
                    tier: None,
                },
                Box::new(|_forwarded: &[u8]| -> Vec<u8> {
                    br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec()
                }),
                300,
                signer,
            ),
            epoch: source,
        }
    }

    fn signed_request(nonce: &str, now: i64) -> HttpRequest {
        let block = HttpRequestEvidenceBlock {
            profile: PROFILE_TAG.into(),
            audience: audience(),
            artifact_bindings: vec![ArtifactBinding::opaque_digest(
                ArtifactType::OauthDpop,
                ACCESS_TOKEN.as_bytes(),
            )],
            continuation: None,
            admission: None,
            admission_assertion: None,
        };
        let mut req = HttpRequest {
            method: "POST".into(),
            target_uri: TARGET.into(),
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
                ("Authorization".into(), format!("Bearer {ACCESS_TOKEN}")),
            ],
            body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#
                .to_vec(),
        };
        sign_request_full(
            &mut req,
            &block,
            &client_key(),
            CLIENT_KEY_ID,
            now - 60,
            now + 240,
            nonce,
        )
        .expect("client signs the RFC 9421 request");
        req
    }

    fn served(req: &HttpRequest) -> ServedHttpRequest {
        ServedHttpRequest {
            method: req.method.clone(),
            target_uri: req.target_uri.clone(),
            headers: req.headers.clone(),
            body: req.body.clone(),
            identity: None,
            assertion: None,
        }
    }

    #[test]
    fn revocation_takes_effect_on_a_sibling_replica_when_the_epoch_advances() {
        let Some(url) = super::redis_url() else {
            eprintln!(
                "SKIP revocation_takes_effect_on_a_sibling_replica_when_the_epoch_advances: \
                 MCP_RE_TEST_REDIS_URL unset"
            );
            return;
        };
        let epoch_key = super::unique_epoch_key();

        let mut admin = redis::Client::open(url.as_str())
            .expect("open redis client")
            .get_connection()
            .expect("admin connection");
        let _: () = redis::cmd("SET")
            .arg(&epoch_key)
            .arg(1_i64)
            .query(&mut admin)
            .expect("SET epoch=1");

        let revoked = Arc::new(AtomicBool::new(false));
        let sibling = replica(&url, &epoch_key, Arc::clone(&revoked));
        // Establish the baseline, exactly as the production poller's first tick does.
        sibling.epoch.poll_once();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let now = now();
            let prefix = format!("epoch-{}-{}", std::process::id(), now);

            // 1. Trust is live: the sibling serves the request.
            let ok = signed_request(&format!("{prefix}-1"), now);
            assert_eq!(
                sibling.proxy.handle(served(&ok), now).await.status,
                200,
                "an unrevoked binding is served"
            );

            // 2. The operator revokes the binding in the AUTHORITATIVE store — but
            //    does NOT advance the epoch. NEGATIVE CONTROL: the sibling has the
            //    key cached within `T`, so it keeps serving. Without this control a
            //    green step 3 would prove nothing about the epoch.
            revoked.store(true, Ordering::SeqCst);
            let stale = signed_request(&format!("{prefix}-2"), now);
            sibling.epoch.poll_once();
            assert_eq!(
                sibling.proxy.handle(served(&stale), now).await.status,
                200,
                "NEGATIVE CONTROL: the sibling serves stale trust until the epoch advances"
            );

            // 3. The operator advances the shared trust epoch on ANOTHER connection.
            let _: i64 = redis::cmd("INCR")
                .arg(&epoch_key)
                .query(&mut admin)
                .expect("INCR epoch -> 2");

            // 4. The sibling's poller observes the advance, the next request flushes,
            //    re-resolves live, and rejects — cross-replica revocation coherence.
            sibling.epoch.poll_once();
            let after = signed_request(&format!("{prefix}-3"), now);
            let status = sibling.proxy.handle(served(&after), now).await.status;
            assert_ne!(
                status, 200,
                "the sibling must reject the revoked binding once the epoch advanced"
            );
            assert_eq!(
                status, 403,
                "a failed actor binding is the signed 403 rejection, not a soft allow"
            );
        });

        let _: () = redis::cmd("DEL")
            .arg(&epoch_key)
            .query(&mut admin)
            .expect("DEL epoch key");
    }
}
