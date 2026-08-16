// SPDX-License-Identifier: Apache-2.0
//! What `ValidatedDeployment` does and does not establish, measured rather than read.
//!
//! `ValidatedDeployment` is meant to mean "this deployment state is legal". The claim is only
//! as strong as the set of relations its constructor actually decides, and this file
//! measures that set from the outside: each case builds a `DeploymentRequest` in code carrying a
//! state `parse_args` refuses, and records whether the boundary refuses it too.
//!
//! This file carried a second test, of relations the parser decided and the boundary did
//! not — cases recorded as ADMITTED, each to be moved into [`refused_at_the_boundary`] when
//! its relation arrived. Every one has now moved, the last being a `--ocsp-responder-url`
//! configured beside a mode that never reads it, so the ledger is closed and its test is
//! gone rather than left standing over nothing.
//!
//! What remains is the positive half of the same measurement: each case below is a state
//! `parse_args` used to be the only thing that refused, and the assertion is that a
//! `DeploymentRequest` built in code — never passing a parser — is refused too.

use mcp_re_proxy::cli;
use mcp_re_proxy::config_state::validation::ValidatedDeployment;
use mcp_re_proxy::deployment_request::DeploymentRequest;

/// The smallest command line that parses under the unconditional strict posture.
///
/// It names `--replay-cache file` because the boundary refuses `memory` and its refusal
/// text recommends `file`. See [`the_recommended_replay_backend_cannot_start`].
fn base() -> DeploymentRequest {
    let argv: Vec<String> = [
        "--bind",
        "127.0.0.1:8443",
        "--audience",
        "did:example:server-1",
        "--server-signer",
        "did:example:server-1",
        "--server-key-id",
        "server-key-1",
        "--signing-key-seed",
        "/seed",
        "--tls-cert",
        "/cert",
        "--tls-key",
        "/key",
        "--client-ca",
        "/ca",
        "--trust",
        "/trust.json",
        "--inner-http-url",
        "http://127.0.0.1:8080/mcp",
        "--target-uri",
        "https://mcp.example.com/mcp",
        "--delegated-trust-epoch",
        "epoch-min",
        "--trust-domain",
        "mcp.example.com",
        "--replay-redis-url",
        "redis://127.0.0.1:6379",
        "--replay-durability-tier",
        "redis-wait-quorum:1:100",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    cli::parse_args(&argv).expect("baseline parses")
}

#[test]
fn the_baseline_is_admitted() {
    assert!(
        ValidatedDeployment::try_from(base()).is_ok(),
        "the baseline must be legal, or every case below measures the wrong thing"
    );
}

/// Relations that have MOVED to the boundary, and the state each one now decides.
///
/// A case arrives here by flipping in the list above. What makes the move meaningful is
/// not the refusal alone but that the boundary now names a state: `TrustRevocation` has
/// four, the epoch source is what splits `Push` into two of them, and a tier that cannot
/// consume one does not merely ignore it.
#[test]
fn refused_at_the_boundary() {
    // ADR-MCPRE-052 §7: the epoch minted into every delegated response-signing credential.
    // A verifier admits only credentials whose epoch is in its accepted set, so there is
    // deliberately no default. Admitted before, and refused instead inside
    // `delegated_wiring` — after the trust and TLS planes had read files and started
    // workers, by a module whose subject is building a signer rather than judging a
    // configuration. Its two siblings (`--delegated-ttl-secs`, `--delegated-overlap-secs`)
    // were already boundary clauses, so one family was split across two layers.
    let mut config = base();
    config.delegated_trust_epoch = None;
    let refusal = ValidatedDeployment::try_from(config)
        .expect_err("delegated signing must not mint under a bare epoch label");
    assert!(refusal.contains("--delegated-trust-epoch"), "{refusal}");

    // The inner plane. Admitted before, and refused instead by the TRUST plane — which
    // meant a configuration naming no inner server was rejected only after trust had read
    // its document and started its workers, by a plane with no stake in the question.
    let mut config = base();
    config.inner_http_urls.clear();
    let refusal =
        ValidatedDeployment::try_from(config).expect_err("a deployment must name an inner server");
    assert!(refusal.contains("--inner-http-url"), "{refusal}");

    // MCPS-84 / atlas X8. Admitted before: the deployment believed a networked trust
    // invalidation was active while no tier consumed it.
    let mut config = base();
    config.trust_epoch_redis_url = Some("redis://127.0.0.1:6379".to_string());
    let refusal =
        ValidatedDeployment::try_from(config).expect_err("an epoch source under a non-Push tier");
    assert!(refusal.contains("--trust-epoch-redis-url"), "{refusal}");

    // Atlas §C.3. `--key-source file` with no seed is the `FileSeed` state missing the one
    // parameter it cannot start without: nothing else in that state supplies the
    // response-signing key.
    let mut config = base();
    config.signing_key_seed = String::new();
    let refusal = ValidatedDeployment::try_from(config).expect_err("a custody state with no key");
    assert!(refusal.contains("--signing-key-seed"), "{refusal}");

    // Atlas §C.1, the Replay machine's forbidden and required columns. A CP-store
    // endpoint on a state whose store is Redis; and a deployment declaring no durability
    // tier, when the tier IS the horizontal replay-safety claim and the only selector.
    for (name, mutate) in [
        (
            "cpstore_etcd_endpoint",
            Box::new(|c: &mut DeploymentRequest| {
                c.cpstore_etcd_endpoint = Some("http://127.0.0.1:2379".to_string())
            }) as Box<dyn FnOnce(&mut DeploymentRequest)>,
        ),
        (
            "replay_durability_tier",
            Box::new(|c: &mut DeploymentRequest| c.replay_durability_tier = None),
        ),
    ] {
        let mut config = base();
        mutate(&mut config);
        assert!(
            ValidatedDeployment::try_from(config).is_err(),
            "{name}: still admitted at the boundary"
        );
    }

    // The deployment's own identity coordinates. Requiredness lived in the parser's
    // `require()`, which rejects an ABSENT flag and says nothing about an EMPTY value —
    // and nothing at all about a config built in code. Nothing downstream dereferences
    // these: they are minted into what the proxy signs and compared by verifiers, so an
    // empty one failed no startup step and simply stopped distinguishing this deployment.
    for (name, mutate) in [
        (
            "trust_domain",
            Box::new(|c: &mut DeploymentRequest| c.trust_domain = String::new())
                as Box<dyn FnOnce(&mut DeploymentRequest)>,
        ),
        (
            "audience",
            Box::new(|c: &mut DeploymentRequest| c.audience = String::new()),
        ),
        (
            "server_signer",
            Box::new(|c: &mut DeploymentRequest| c.server_signer = String::new()),
        ),
        (
            "server_key_id",
            Box::new(|c: &mut DeploymentRequest| c.server_key_id = String::new()),
        ),
        // The locators. These ARE dereferenced at startup, so an empty one always failed
        // eventually — but as an observation about the environment, raised after planes had
        // established resources. That the string names nothing is knowable here
        // (ADR-MCPRE-056 §5.1), and reads as the configuration defect it is.
        (
            "bind",
            Box::new(|c: &mut DeploymentRequest| c.bind = String::new()),
        ),
        (
            "tls_cert",
            Box::new(|c: &mut DeploymentRequest| c.tls_cert = String::new()),
        ),
        (
            "client_ca",
            Box::new(|c: &mut DeploymentRequest| c.client_ca = String::new()),
        ),
        (
            "trust_path",
            Box::new(|c: &mut DeploymentRequest| c.trust_path = String::new()),
        ),
    ] {
        let mut config = base();
        mutate(&mut config);
        assert!(
            ValidatedDeployment::try_from(config).is_err(),
            "{name}: an empty required value is still admitted at the boundary"
        );
    }

    // The numeric ranges the parser bounded and the boundary did not. `max_clock_skew` is
    // the freshness tolerance applied to every verified request AND to the replay
    // `retain_until`, so outside its bound the gate stops bounding anything; it was left to
    // `VerifierPolicy::new`, which is reached after two planes have started.
    for (name, mutate) in [
        (
            "max_clock_skew above the bound",
            Box::new(|c: &mut DeploymentRequest| c.max_clock_skew = 86_400)
                as Box<dyn FnOnce(&mut DeploymentRequest)>,
        ),
        (
            "a negative max_clock_skew",
            Box::new(|c: &mut DeploymentRequest| c.max_clock_skew = -1),
        ),
        (
            "a zero connection ceiling",
            Box::new(|c: &mut DeploymentRequest| c.limits.max_concurrent_connections = 0),
        ),
        (
            "a zero drain window",
            Box::new(|c: &mut DeploymentRequest| {
                c.limits.drain_grace = std::time::Duration::from_secs(0)
            }),
        ),
    ] {
        let mut config = base();
        mutate(&mut config);
        assert!(
            ValidatedDeployment::try_from(config).is_err(),
            "{name}: still admitted at the boundary"
        );
    }

    // The last case to move. A responder URL beside `--client-ocsp off` is not a mode this
    // deployment is in — nothing consults a responder there — so the deployment carried a
    // revocation authority it never asked, and the operator had a configured one to point
    // at. Refused only by the parser until now.
    let mut config = base();
    config.ocsp_responder_url = Some("http://ocsp.example.com".to_string());
    let refusal = ValidatedDeployment::try_from(config)
        .expect_err("a responder no mode reads is a configured authority that answers nothing");
    assert!(refusal.contains("--ocsp-responder-url"), "{refusal}");

    // The same source under the tier that DOES consume it is the legal state, and is
    // recognised as such rather than merely permitted.
    let mut config = base();
    config.revocation_tier = mcp_re_proxy::revocation_tier::RevocationTier::Push { t_secs: 30 };
    config.trust_reload_secs = Some(30);
    config.trust_epoch_redis_url = Some("redis://127.0.0.1:6379".to_string());
    let validated = ValidatedDeployment::try_from(config).expect("push + epoch source is legal");
    assert!(
        validated.state().trust_revocation().has_networked_epoch(),
        "the boundary accepted it without recognising which state it is"
    );
}

/// The boundary refuses `--replay-cache memory` and recommends `--replay-cache file`;
/// `ReplayPlan::from_config` then refuses `file` on the async serving path.
///
/// So the legal-state relation disagrees with itself across two stages: the remedy the
/// boundary names is not a state the next stage will start. This baseline — the shape the
/// parser's own test suite uses as its canonical valid config — is one of them.
#[test]
fn the_recommended_replay_backend_cannot_start() {
    let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let refusal = mcp_re_proxy::app::run(base(), shutdown)
        .expect_err("a config naming absent key material cannot serve");
    // The startup order reaches key material before replay planning, so this is what an
    // operator meets first. Recorded so that a reordering shows up here rather than
    // silently changing which of the two refusals a `file` deployment receives.
    assert!(
        refusal.contains("key material not found"),
        "unexpected first refusal: {refusal}"
    );
}
