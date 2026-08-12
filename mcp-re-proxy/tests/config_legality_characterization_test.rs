// SPDX-License-Identifier: Apache-2.0
//! What `ValidatedConfig` does and does not establish, measured rather than read.
//!
//! `ValidatedConfig` is meant to mean "this deployment state is legal". The claim is only
//! as strong as the set of relations its constructor actually decides, and this file
//! measures that set from the outside: each case builds a `Config` in code carrying a
//! state `parse_args` refuses, and records whether the boundary refuses it too.
//!
//! Every case below is currently ADMITTED. That is the finding, not an accident of the
//! test: the relation is enforced in the argument parser alone, so it holds for a command
//! line and not for the runtime. As each relation moves to the boundary, its case here
//! flips and must be moved into [`refused_at_the_boundary`] — which is what makes this a
//! characterization of the boundary rather than a list of things someone once checked.

use mcp_re_proxy::cli::{self, Config, ValidatedConfig};

/// The smallest command line that parses under the unconditional strict posture.
///
/// It names `--replay-cache file` because the boundary refuses `memory` and its refusal
/// text recommends `file`. See [`the_recommended_replay_backend_cannot_start`].
fn base() -> Config {
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
        "--replay-cache",
        "shared",
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

fn admitted(mutate: impl FnOnce(&mut Config)) -> bool {
    let mut config = base();
    mutate(&mut config);
    ValidatedConfig::try_from(config).is_ok()
}

#[test]
fn the_baseline_is_admitted() {
    assert!(
        ValidatedConfig::try_from(base()).is_ok(),
        "the baseline must be legal, or every case below measures the wrong thing"
    );
}

/// Required identity and path values: present as a flag, unconstrained as a field.
///
/// `require()` in the parser rejects an ABSENT flag. It says nothing about an EMPTY value,
/// and nothing at all about a config built in code. An empty `--audience` or `--trust`
/// is not a cosmetic defect: the audience is half the RFC 9421 dispatch-boundary
/// conjunction, and the trust path is where the request-signer set comes from.
#[test]
fn required_values_are_unconstrained_at_the_boundary() {
    for (name, admitted) in [
        ("bind", admitted(|c| c.bind = String::new())),
        ("audience", admitted(|c| c.audience = String::new())),
        (
            "server_signer",
            admitted(|c| c.server_signer = String::new()),
        ),
        (
            "server_key_id",
            admitted(|c| c.server_key_id = String::new()),
        ),
        ("trust_domain", admitted(|c| c.trust_domain = String::new())),
        ("trust_path", admitted(|c| c.trust_path = String::new())),
        ("client_ca", admitted(|c| c.client_ca = String::new())),
        ("tls_cert", admitted(|c| c.tls_cert = String::new())),
    ] {
        assert!(
            admitted,
            "{name}: now refused at the boundary — move this case"
        );
    }
}

/// Numeric ranges the parser bounds and the boundary does not.
///
/// `max_clock_skew` is the freshness tolerance applied to every verified request and to
/// the replay `retain_until`; the parser holds it to `0..=MAX_CLOCK_SKEW_BOUND` and the
/// boundary accepts a day, or a negative value.
#[test]
fn numeric_ranges_are_unconstrained_at_the_boundary() {
    assert!(admitted(|c| c.max_clock_skew = 86_400));
    assert!(admitted(|c| c.max_clock_skew = -1));
    assert!(admitted(|c| c.limits.max_concurrent_connections = 0));
}

/// Cross-field mode relations the parser decides and the boundary does not.
///
/// These are the state-legality relations proper — each names a control an operator would
/// believe is in force.
#[test]
fn cross_field_relations_are_unenforced_at_the_boundary() {
    // ADR-MCPRE-052 §7: the epoch minted into every delegated response-signing credential.
    // A verifier admits only credentials whose epoch is in its accepted set, so there is
    // deliberately no default — the parser requires it and the boundary does not.
    assert!(admitted(|c| c.delegated_trust_epoch = None));
    // The dangling-OCSP-knob illusion the parser refuses by name.
    assert!(admitted(
        |c| c.ocsp_responder_url = Some("http://ocsp.example.com".to_string())
    ));
}

/// Relations that have MOVED to the boundary, and the state each one now decides.
///
/// A case arrives here by flipping in the list above. What makes the move meaningful is
/// not the refusal alone but that the boundary now names a state: `TrustRevocation` has
/// four, the epoch source is what splits `Push` into two of them, and a tier that cannot
/// consume one does not merely ignore it.
#[test]
fn refused_at_the_boundary() {
    // The inner plane. Admitted before, and refused instead by the TRUST plane — which
    // meant a configuration naming no inner server was rejected only after trust had read
    // its document and started its workers, by a plane with no stake in the question.
    let mut config = base();
    config.inner_http_urls.clear();
    let refusal =
        ValidatedConfig::try_from(config).expect_err("a deployment must name an inner server");
    assert!(refusal.contains("--inner-http-url"), "{refusal}");

    // MCPS-84 / atlas X8. Admitted before: the deployment believed a networked trust
    // invalidation was active while no tier consumed it.
    let mut config = base();
    config.trust_epoch_redis_url = Some("redis://127.0.0.1:6379".to_string());
    let refusal =
        ValidatedConfig::try_from(config).expect_err("an epoch source under a non-Push tier");
    assert!(refusal.contains("--trust-epoch-redis-url"), "{refusal}");

    // Atlas §C.3. `--key-source file` with no seed is the `FileSeed` state missing the one
    // parameter it cannot start without: nothing else in that state supplies the
    // response-signing key.
    let mut config = base();
    config.signing_key_seed = String::new();
    let refusal = ValidatedConfig::try_from(config).expect_err("a custody state with no key");
    assert!(refusal.contains("--signing-key-seed"), "{refusal}");

    // Atlas §C.1, the Replay machine's forbidden and required columns. A CP-store
    // endpoint on a state whose store is Redis; a shared store declaring no durability
    // tier, when the tier IS the horizontal replay-safety claim; and a `--replay-path`
    // for a state no deployment can be in.
    for (name, mutate) in [
        (
            "cpstore_etcd_endpoint",
            Box::new(|c: &mut Config| {
                c.cpstore_etcd_endpoint = Some("http://127.0.0.1:2379".to_string())
            }) as Box<dyn FnOnce(&mut Config)>,
        ),
        (
            "replay_durability_tier",
            Box::new(|c: &mut Config| c.replay_durability_tier = None),
        ),
        (
            "replay_path",
            Box::new(|c: &mut Config| c.replay_path = Some("/replay".to_string())),
        ),
    ] {
        let mut config = base();
        mutate(&mut config);
        assert!(
            ValidatedConfig::try_from(config).is_err(),
            "{name}: still admitted at the boundary"
        );
    }

    // The same source under the tier that DOES consume it is the legal state, and is
    // recognised as such rather than merely permitted.
    let mut config = base();
    config.revocation_tier = mcp_re_proxy::revocation_tier::RevocationTier::Push { t_secs: 30 };
    config.trust_reload_secs = Some(30);
    config.trust_epoch_redis_url = Some("redis://127.0.0.1:6379".to_string());
    let validated = ValidatedConfig::try_from(config).expect("push + epoch source is legal");
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
