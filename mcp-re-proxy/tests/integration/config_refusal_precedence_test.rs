// SPDX-License-Identifier: Apache-2.0
//! The ORDER in which a multiply-illegal configuration is refused.
//!
//! The boundary answers a different question from the state model. The model
//! (`work/CONFIG-STATE-ATLAS.md`) says whether a requested deployment state is legal; it
//! deliberately says nothing about which refusal an operator meets first when several
//! things are wrong at once. That ordering is a property of validation *orchestration*,
//! and it is observable: `unsafe_config_violations` returns every violation, in one fixed
//! source order, and the boundary joins them into the message an operator reads.
//!
//! The reason to pin it before reorganising the boundary: the order would otherwise change
//! as a side effect of which validator happens to be called first — a diagnostic
//! regression with no failing test and no diff that mentions it. With this file in place a
//! reordering has to be written down.
//!
//! Pinning is not endorsement. Some of this order is deliberate and some is the order the
//! clauses were added in; this file records what it IS, so that changing it is a decision.

use mcp_re_proxy::cli::{self, AuthzKind, BindingKind, DeploymentRequest, OcspKind};
use mcp_re_proxy::IdentityPolicy;

/// A legal configuration, from the parser, so every violation below is one this fixture
/// introduces on purpose rather than one the baseline dragged in.
fn legal() -> DeploymentRequest {
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
    cli::parse_args(&argv).expect("the baseline parses")
}

/// A distinguishing fragment per clause, in the order the boundary emits them.
fn keys(violations: &[String]) -> Vec<&'static str> {
    const CLAUSES: &[&str] = &[
        "--client-ocsp",
        "--revocation-list",
        "--authz",
        "TLS signing is delegated XOR exported",
        "--transport-binding lb-assertion places",
        // The deployment's own identity coordinates, then its locators, immediately before
        // `--target-uri` — which is one of them, and was the only one the boundary decided.
        "--trust-domain is empty",
        "--audience is empty",
        "--server-signer is empty",
        "--server-key-id is empty",
        "--bind is empty",
        "--tls-cert is empty",
        "--client-ca is empty",
        "--trust is empty",
        "--target-uri",
        // Ahead of the general `--inner-http-url` key, which it contains: `find` takes the
        // first match, so a more specific fragment has to come first or it is never seen.
        "--inner-http-url contains an empty URL",
        "--inner-http-url",
        "--admission",
        "--aws-kms-endpoint",
        "--gcp-kms-endpoint",
        "--aws-sts-endpoint",
        "--key-source",
        "--ingress-",
        // The structure of the list, before the clauses that read a different field.
        "--client-crl contains an empty path",
        "--client-crl-reload-secs 0",
        "--client-crl-reload-secs has no effect",
        "--delegated-trust-epoch",
        "--delegated-ttl-secs",
        "--delegated-overlap-secs",
        "--max-client-cert-lifetime",
        "--max-connection-age-secs",
        "--revocation-tier live|push requires",
        "--trust-reload-secs 0",
        "--trust-reload-secs",
        // The quantity guards, together and ahead of the timeouts they share a class with:
        // each is a limit that disables the control it bounds.
        "--max-clock-skew",
        "--max-connections 0",
        "--drain-grace-secs 0",
        "--read-timeout-secs",
        "--write-timeout-secs",
        "--request-deadline-secs",
        "--transport-identity-source cn_legacy",
        "--replay-durability-tier",
        "--reverse-proxy-identity-header",
        "--transport-binding none",
    ];
    violations
        .iter()
        .map(|v| {
            CLAUSES
                .iter()
                .copied()
                .find(|c| v.contains(c))
                .unwrap_or_else(|| panic!("unrecognised refusal, add a key for it: {v}"))
        })
        .collect()
}

/// One configuration violating as many independent clauses as can coexist.
///
/// Mutually exclusive states (a `binding` cannot be both `none` and `lb-assertion`) are
/// split across the fixtures below; this one takes the larger share.
#[test]
fn the_boundary_refuses_in_this_order() {
    let mut config = legal();
    config.client_ocsp = OcspKind::Require;
    config.revocation_list_paths = vec!["/deny.json".to_string()];
    config.authz = AuthzKind::Reference;
    config.pkcs11_tls_key_label = Some("tls".to_string()); // with tls_key set: XOR violated
    config.target_uri = String::new();
    config.trust_domain = String::new();
    config.audience = String::new();
    config.server_signer = String::new();
    config.server_key_id = String::new();
    config.bind = String::new();
    config.tls_cert = String::new();
    config.client_ca = String::new();
    config.trust_path = String::new();
    config.inner_http_urls.clear();
    config.max_clock_skew = -1;
    config.limits.max_concurrent_connections = 0;
    config.limits.drain_grace = std::time::Duration::from_secs(0);
    config.client_crl_paths = vec!["/crl.pem".to_string(), String::new()];
    config.client_crl_reload_secs = Some(0);
    config.delegated_trust_epoch = None;
    config.delegated_ttl_secs = 0;
    config.delegated_overlap_secs = 0;
    config.max_client_cert_lifetime = None;
    config.limits.max_connection_age = None;
    config.limits.read_timeout = None;
    config.limits.write_timeout = None;
    config.limits.request_deadline = None;
    config.identity_source = IdentityPolicy::CnLegacy;
    config.replay_durability_tier = None;
    config.binding = BindingKind::None;

    let order = keys(&cli::unsafe_config_violations(&config));
    assert_eq!(
        order,
        vec![
            "--client-ocsp",
            "--revocation-list",
            "--authz",
            "TLS signing is delegated XOR exported",
            // Both moved UP with the `ChannelBinding` machine, from the end of the list to
            // its own position. Deliberate: an undeployable binding kind and a deprecated
            // identity source are statements about whether this deployment exists at all,
            // and an operator should meet them before a limit or a timeout.
            "--transport-binding none",
            "--transport-identity-source cn_legacy",
            // NEW. Requiredness for these lived in the parser's `require()`, which rejects
            // an ABSENT flag and says nothing about an EMPTY value. They sit immediately
            // before `--target-uri` because it is one of them: the coordinates a verifier
            // uses to tell this deployment from another, then the locators that name what
            // it loads. Stated one field at a time — they belong to a machine layer A does
            // not have, and one merged clause would fix its diagnostic order in advance.
            "--trust-domain is empty",
            "--audience is empty",
            "--server-signer is empty",
            "--server-key-id is empty",
            "--bind is empty",
            "--tls-cert is empty",
            "--client-ca is empty",
            "--trust is empty",
            "--target-uri",
            // NEW, and it arrived from the trust plane rather than from nowhere: naming no
            // inner server was previously refused only after trust had read its document
            // and started its workers. It sits beside `--target-uri` because both are
            // required locators the parser checks and the boundary did not.
            "--inner-http-url",
            "--key-source",
            // NEW, and ahead of the cadence clause because it is about a different field:
            // a list member that names no file is a defect in the control the cadence
            // would be re-reading.
            "--client-crl contains an empty path",
            "--client-crl-reload-secs 0",
            "--delegated-trust-epoch",
            "--delegated-ttl-secs",
            "--delegated-overlap-secs",
            "--max-client-cert-lifetime",
            "--max-connection-age-secs",
            // NEW. The quantity guards, grouped with the timeouts they share a class with
            // — a limit that disables the control it bounds — and ahead of them because a
            // skew outside its bound or a zero ceiling is the graver of the two.
            "--max-clock-skew",
            "--max-connections 0",
            "--drain-grace-secs 0",
            "--read-timeout-secs",
            "--write-timeout-secs",
            "--request-deadline-secs",
            "--replay-durability-tier",
        ],
        "the boundary's refusal order changed"
    );
}

/// The clauses the fixture above cannot reach, because they need a state it contradicts.
#[test]
fn the_trust_and_fleet_clauses_keep_their_places() {
    let mut config = legal();
    config.revocation_tier = mcp_re_proxy::revocation_tier::RevocationTier::Live;
    config.trust_reload_secs = None;
    config.fleet = true;
    // The zero-cadence clause shares this position with the missing-cadence clause above —
    // they are the same guard answering two ways, so only one can fire per run and they
    // are pinned together rather than each claiming its own slot.
    config.binding = BindingKind::LbAssertion;
    config.reverse_proxy_identity_header = Some("x-client-id".to_string());

    let order = keys(&cli::unsafe_config_violations(&config));
    assert_eq!(
        order,
        vec![
            // `lb-assertion` is refused twice: because the mode is not deployable, and
            // because its own required keys are absent. The order of the pair INVERTED
            // when the `ChannelBinding` machine took ownership — deliberately, and this is
            // where that is recorded. An operator now learns the mode does not exist
            // before being told which of its parameters are missing, which is the useful
            // way round; previously the undeployability came after every unrelated limit.
            "--transport-binding lb-assertion places",
            "--ingress-",
            "--revocation-tier live|push requires",
            "--reverse-proxy-identity-header",
        ],
        "the boundary's refusal order changed"
    );
}

/// Every violation is reported, not just the first.
///
/// This is the property that makes the order above a diagnostic contract rather than an
/// implementation detail: an operator fixing a configuration sees the whole list, so
/// dropping a clause silently shortens the list rather than changing an error.
#[test]
fn the_boundary_reports_every_violation_not_the_first() {
    let mut config = legal();
    config.authz = AuthzKind::Reference;
    config.identity_source = IdentityPolicy::CnLegacy;
    config.replay_durability_tier = None;

    let refusal = mcp_re_proxy::cli::ValidatedDeployment::try_from(config)
        .expect_err("three violations must refuse");
    for expected in ["--authz", "cn_legacy", "--replay-durability-tier"] {
        assert!(
            refusal.contains(expected),
            "missing {expected} in: {refusal}"
        );
    }
}

/// The zero-cadence refusal occupies the SAME slot as its missing-cadence sibling.
///
/// Both come from the reload-cadence guard, so an operator meets one clause about that
/// flag in one place whichever way they got it wrong. Pinned in its own run because a
/// single configuration cannot provoke both — the cadence is either absent or zero.
#[test]
fn the_zero_cadence_clause_takes_the_cadence_slot() {
    let mut config = legal();
    config.revocation_tier = mcp_re_proxy::revocation_tier::RevocationTier::Live;
    config.trust_reload_secs = Some(0);
    config.fleet = true;
    config.binding = BindingKind::LbAssertion;
    config.reverse_proxy_identity_header = Some("x-client-id".to_string());

    let order = keys(&cli::unsafe_config_violations(&config));
    assert_eq!(
        order,
        vec![
            "--transport-binding lb-assertion places",
            "--ingress-",
            "--trust-reload-secs 0",
            "--reverse-proxy-identity-header",
        ],
        "the boundary's refusal order changed"
    );
}
