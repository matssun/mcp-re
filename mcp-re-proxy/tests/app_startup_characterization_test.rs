// SPDX-License-Identifier: Apache-2.0
//! Characterization of `app::run`'s STARTUP behaviour, in the default test lane.
//!
//! These tests exist to pin what the composition root does today, so the ADR-MCPRE-056
//! restructuring can be shown to preserve it. They are characterization, not
//! specification: an assertion here records observed behaviour and is expected to
//! survive the refactor unchanged.
//!
//! **Why this file exists separately.** Every test that drove `app::run` used to live in
//! `tls_load_harness_bench.rs`, which is gated `#![cfg(feature = "redis_replay")]` and
//! whose Bazel target is tagged `manual`. So the composition root — the single largest
//! and most security-relevant assembly in the proxy — was exercised by neither
//! `cargo test --workspace` nor `bazel test //...`. A startup test that runs in no
//! default lane protects nothing.
//!
//! The cases here deliberately need no Redis, no Docker and no listener: each config is
//! refused BEFORE the serve loop, so the whole file is fast and hermetic.

mod serving_fixtures;
mod startup_transcript;

use serving_fixtures::Material;

/// The flags every case below shares: enough to get through parsing and preflight, with
/// a replay tier that cannot be opened in this build. Startup therefore always reaches
/// the trust plane and always stops at the replay stage, which is what makes these
/// hermetic — no Redis, no Docker, no listener.
fn base_args(m: &Material) -> Vec<String> {
    [
        "--bind",
        "127.0.0.1:0",
        "--audience",
        serving_fixtures::AUDIENCE,
        "--server-signer",
        serving_fixtures::SERVER,
        "--server-key-id",
        serving_fixtures::SERVER_KEY_ID,
        "--delegated-trust-epoch",
        "epoch-1",
        "--signing-key-seed",
        &m.seed_path.to_string_lossy(),
        "--tls-cert",
        &m.server_cert_path.to_string_lossy(),
        "--tls-key",
        &m.server_key_path.to_string_lossy(),
        "--client-ca",
        &m.client_ca_path.to_string_lossy(),
        "--trust",
        &m.trust_path.to_string_lossy(),
        "--target-uri",
        serving_fixtures::TARGET_URI,
        "--trust-domain",
        serving_fixtures::TRUST_DOMAIN,
        "--inner-http-url",
        "http://127.0.0.1:9/mcp",
        "--replay-cache",
        "shared",
        "--replay-redis-url",
        "redis://127.0.0.1:1",
        "--replay-durability-tier",
        "redis-wait-quorum:2:2000",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn with(m: &Material, extra: &[&str]) -> Vec<String> {
    let mut args = base_args(m);
    args.extend(extra.iter().map(|s| s.to_string()));
    args
}

/// The trust plane states its declared revocation tier and its reload posture, in that
/// order, BEFORE the replay tier is opened.
///
/// The order is the point. ADR-MCPRE-056 moves these two statements into a `TrustPlane`
/// materializer and the replay tier into a separate one; a restructuring that let a
/// replay fact be reported before the trust posture would have changed what an operator
/// reads on a failed start, even though every individual line survived.
#[test]
fn the_trust_posture_is_reported_before_the_replay_tier_is_opened() {
    let m = serving_fixtures::write_material();
    let t = startup_transcript::capture(&base_args(&m));

    let tier = startup_transcript::StartupEvent::RevocationTier {
        tier: "BOUNDED_CACHE".to_string(),
        // No --trust-reload-secs: the store itself never changes while this runs.
        store_change_bounded: false,
    };
    let reload = startup_transcript::StartupEvent::TrustReload { active: false };

    assert!(t.has(&tier), "tier not reported:\n{}", t.dump());
    assert!(t.has(&reload), "reload posture not reported:\n{}", t.dump());
    assert!(
        t.emits_in_order(&tier, &reload),
        "the declared tier must precede the reload posture that qualifies it:\n{}",
        t.dump()
    );
    assert!(
        !t.has(&startup_transcript::StartupEvent::FleetServing),
        "this config must never reach the serving state:\n{}",
        t.dump()
    );
}

/// Turning on `--trust-reload-secs` changes BOTH reported facts: the reload becomes
/// active and the tier line stops saying the store can never change. They are two
/// statements about one decision, and the refactor must keep them agreeing.
#[test]
fn enabling_trust_reload_changes_the_tier_line_and_the_reload_line_together() {
    let m = serving_fixtures::write_material();
    let t = startup_transcript::capture(&with(&m, &["--trust-reload-secs", "60"]));

    assert!(
        t.has(&startup_transcript::StartupEvent::TrustReload { active: true }),
        "reload should be ACTIVE:\n{}",
        t.dump()
    );
    assert!(
        t.has(&startup_transcript::StartupEvent::RevocationTier {
            tier: "BOUNDED_CACHE".to_string(),
            store_change_bounded: true,
        }),
        "the tier line must stop reporting an unbounded store-change cadence:\n{}",
        t.dump()
    );
}

/// A push tier with no networked event source says so, immediately after the tier it
/// qualifies — the honesty control that stops a deployment reading a near-zero
/// revocation window it is not actually getting.
///
/// `--trust-reload-secs` is not incidental here: `push` (and `live`) are REFUSED without
/// it, because a tier that states its window in terms of consulting the trust store
/// cannot deliver one while the store is read once at startup. So the qualified-claim
/// posture has two layers, and this pins the inner one.
#[test]
fn a_push_tier_without_an_event_source_is_qualified_where_it_is_declared() {
    let m = serving_fixtures::write_material();
    let t = startup_transcript::capture(&with(
        &m,
        &["--revocation-tier", "push:60", "--trust-reload-secs", "60"],
    ));

    let tier = startup_transcript::StartupEvent::RevocationTier {
        tier: "PUSH".to_string(),
        store_change_bounded: true,
    };
    let caveat = startup_transcript::StartupEvent::PushTierNoEventSource;

    assert!(t.has(&tier), "push tier not reported:\n{}", t.dump());
    assert!(t.has(&caveat), "fallback caveat missing:\n{}", t.dump());
    assert!(
        t.emits_in_order(&tier, &caveat),
        "the caveat must follow the claim it weakens:\n{}",
        t.dump()
    );
}

/// A build without `redis_replay` refuses a shared replay tier BEFORE serving, and says
/// which feature is missing. Pins the exit shape the transcript harness depends on.
#[test]
fn an_unopenable_replay_tier_refuses_startup_and_names_the_missing_feature() {
    let m = serving_fixtures::write_material();
    let t = startup_transcript::capture(&base_args(&m));

    match &t.outcome {
        startup_transcript::Outcome::Exited { success, refused } => {
            assert!(!success, "startup must fail closed:\n{}", t.dump());
            let refused = refused.as_deref().unwrap_or("");
            assert!(
                refused.contains("redis_replay"),
                "the refusal must name the missing feature, got {refused:?}"
            );
        }
        other => panic!("expected an early exit, got {other:?}:\n{}", t.dump()),
    }
}

/// A `Config` that never went through the parser cannot bypass the safety guards.
///
/// `Config` has 76 public fields. Until the validation boundary landed, the hard guards
/// ran only inside `parse_args`, so anything that built a `Config` in code — an
/// embedder, a harness, a bespoke launcher — reached the serving path having run none of
/// them. This mutates a parsed config AFTER parsing, which is the cheapest way to
/// reproduce exactly what such a caller can construct, and asserts `run` refuses it.
///
/// The posture chosen is the disabled client-cert lifetime: with no bound, a stolen
/// certificate authenticates for as long as its issuer allows, which is the revocation
/// posture the whole Mode-A design rests on.
#[test]
fn a_config_that_skipped_the_parser_still_cannot_bypass_the_safety_guards() {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    let m = serving_fixtures::write_material();
    let mut config = mcp_re_proxy::cli::parse_args(&base_args(&m)).expect("the base config parses");

    // `parse_args` would have refused this. Setting it afterwards is not a contrived
    // move — it is the only shape an in-code caller has.
    config.max_client_cert_lifetime = None;

    let err = mcp_re_proxy::app::run(config, Arc::new(AtomicBool::new(true)))
        .expect_err("an unsafe configuration must be refused however it was built");

    assert!(
        err.contains("refuses unsafe configuration"),
        "expected the unsafe-configuration refusal, got: {err}"
    );
    assert!(
        err.contains("--max-client-cert-lifetime"),
        "the refusal must name the offending setting, got: {err}"
    );
}

/// `app::run` refuses configs it cannot build BEFORE serving — the key-source and
/// replay-tier branches that never execute on the happy path. Each returns `Err` early
/// (no listener, no Redis), so this is a fast in-process test that covers the
/// orchestration's fail-closed arms. `shutdown` is pre-flipped: if a case unexpectedly
/// reached the serve loop it would drain at once, so a returned `Ok` still fails the
/// `expect_err`.
///
/// The assertions rely on the aws-kms/gcp-kms/pkcs11 key sources and the linearizable
/// (etcd) tier being ABSENT from the build, so they fail closed at construction. Skipped
/// when any of those backends IS compiled in — with the feature present the source
/// builds (and fails later, for a different reason), so the "not compiled" premise no
/// longer holds.
#[cfg(not(any(
    feature = "aws_kms_keysource",
    feature = "gcp_kms_keysource",
    feature = "pkcs11_keysource",
    feature = "cpstore_etcd"
)))]
#[test]
fn app_run_refuses_unbuildable_key_sources_and_replay_tiers() {
    // Imported here rather than at file scope: the whole test is `cfg`-ed out in the
    // feature lane, and file-scope imports would then be unused — a hard error under
    // the gate's `clippy -D warnings`.
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    use serving_fixtures::write_material;
    use serving_fixtures::AUDIENCE;
    use serving_fixtures::SERVER;
    use serving_fixtures::SERVER_KEY_ID;
    use serving_fixtures::TARGET_URI;
    use serving_fixtures::TRUST_DOMAIN;

    let m = write_material();
    let seed = m.seed_path.to_string_lossy().into_owned();
    let scert = m.server_cert_path.to_string_lossy().into_owned();
    let skey = m.server_key_path.to_string_lossy().into_owned();
    let cca = m.client_ca_path.to_string_lossy().into_owned();
    let trust = m.trust_path.to_string_lossy().into_owned();

    let mk = |case: &[&str]| -> Vec<String> {
        let mut v: Vec<String> = [
            "--bind",
            "127.0.0.1:0",
            "--audience",
            AUDIENCE,
            "--server-signer",
            SERVER,
            "--server-key-id",
            SERVER_KEY_ID,
            // Required since ADR-MCPRE-052 §7: delegated signing is the only response
            // mode, and every credential is minted under a coordinated trust epoch.
            "--delegated-trust-epoch",
            "epoch-1",
            "--signing-key-seed",
            seed.as_str(),
            "--tls-cert",
            &scert,
            "--tls-key",
            &skey,
            "--client-ca",
            &cca,
            "--trust",
            &trust,
            "--target-uri",
            TARGET_URI,
            "--trust-domain",
            TRUST_DOMAIN,
            "--inner-http-url",
            "http://127.0.0.1:9/mcp",
            "--replay-cache",
            "shared",
            "--replay-redis-url",
            "redis://127.0.0.1:1",
            "--replay-durability-tier",
            "redis-wait-quorum:2:2000",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        v.extend(case.iter().map(|s| s.to_string()));
        v
    };
    let app_err = |argv: Vec<String>| -> String {
        let config = mcp_re_proxy::cli::parse_args(&argv).expect("args parse");
        let sd = Arc::new(AtomicBool::new(true));
        mcp_re_proxy::app::run(config, sd).expect_err("config must be refused before serving")
    };

    // Cloud/HSM key sources that are not compiled into this build fail closed.
    assert!(app_err(mk(&[
        "--key-source",
        "aws-kms",
        "--aws-kms-region",
        "r",
        "--aws-kms-key-id",
        "k"
    ]))
    .contains("aws_kms"));
    assert!(app_err(mk(&[
        "--key-source",
        "gcp-kms",
        "--gcp-kms-key-version",
        "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
    ]))
    .contains("gcp_kms"));
    assert!(app_err(mk(&[
        "--key-source",
        "pkcs11",
        "--pkcs11-module",
        "/x.so",
        "--pkcs11-pin-file",
        "/etc/pin",
        "--pkcs11-token-label",
        "t",
        "--pkcs11-key-label",
        "k",
    ]))
    .to_lowercase()
    .contains("pkcs11"));
    // A node-local file replay cache is refused on the per-core async serving plane.
    assert!(app_err(mk(&["--replay-cache", "file", "--replay-path", "/tmp/x"])).contains("file"));
    // The linearizable (CP) tier needs a cpstore_etcd build.
    assert!(app_err(mk(&[
        "--replay-durability-tier",
        "linearizable",
        "--cpstore-etcd-endpoint",
        "http://127.0.0.1:2379",
    ]))
    .contains("cpstore_etcd"));
}
