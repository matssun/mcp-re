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
/// a replay tier that cannot be opened — either because the backend is not compiled into
/// this build, or because nothing answers on `127.0.0.1:1`. Startup therefore always
/// reaches the trust plane and always stops at the replay stage in every cargo lane,
/// which is what makes these hermetic — no Redis, no Docker, no listener.
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

/// A shared replay tier that cannot be opened refuses startup BEFORE serving, and names
/// the reason it could not be opened. Pins the exit shape the transcript harness depends
/// on.
///
/// The refusal is invariant across builds; the reason is not. Without `redis_replay` the
/// backend is not compiled in at all and the refusal names the missing feature. With it
/// compiled in, the same config gets as far as dialling `redis://127.0.0.1:1` and is
/// refused by the connection failure. Asserting one fixed substring would therefore pass
/// in one cargo lane and fail in the other — as it did — so the lanes are distinguished
/// here rather than the test being narrowed to whichever lane it was written in.
#[test]
fn an_unopenable_replay_tier_refuses_startup_and_names_why() {
    // Kept as a `cfg!` value rather than a `#[cfg]` on the test so BOTH lanes assert
    // fail-closed startup; only the diagnostic they expect differs.
    let expected = if cfg!(feature = "redis_replay") {
        "connect redis"
    } else {
        "redis_replay"
    };

    let m = serving_fixtures::write_material();
    let t = startup_transcript::capture(&base_args(&m));

    match &t.outcome {
        startup_transcript::Outcome::Exited { success, refused } => {
            assert!(!success, "startup must fail closed:\n{}", t.dump());
            let refused = refused.as_deref().unwrap_or("");
            assert!(
                refused.contains(expected),
                "the refusal must say why the tier could not be opened, \
                 expected {expected:?}, got {refused:?}"
            );
        }
        other => panic!("expected an early exit, got {other:?}:\n{}", t.dump()),
    }
}

/// Refusal PRECEDENCE, not merely the refusal set (ADR-MCPRE-056 §K1).
///
/// Two independent fallible startup checks are broken at once: the trust store cannot be
/// read, and `--client-crl` names a file that does not exist. Both refuse. The assertion
/// is about WHICH ONE the operator is told about, because that determines the log trail
/// and the remediation path they follow.
///
/// This guards a defect the restructuring nearly introduced. Extracting the TLS block
/// into a plane made it natural to materialize it beside the key material it derives
/// from, which would have moved the CRL checks ahead of the trust store. Same refusal
/// set, same eventual outcome, different first error — and every one of the suite's 2232
/// tests still passed. In a security proxy failure precedence is observable behaviour, so
/// it gets an assertion rather than a convention.
#[test]
fn the_trust_store_is_refused_before_the_client_crls_are_read() {
    let m = serving_fixtures::write_material();
    // Replace the good trust path rather than appending a second `--trust`.
    let args: Vec<String> = base_args(&m)
        .into_iter()
        .scan(false, |replace_next, arg| {
            let out = if *replace_next {
                "/nonexistent/trust".to_string()
            } else {
                arg.clone()
            };
            *replace_next = arg == "--trust";
            Some(out)
        })
        .collect();
    let mut args = args;
    args.extend(["--client-crl".to_string(), "/nonexistent/crl".to_string()]);

    let t = startup_transcript::capture(&args);
    match &t.outcome {
        startup_transcript::Outcome::Exited { success, refused } => {
            assert!(!success, "startup must fail closed:\n{}", t.dump());
            let refused = refused.as_deref().unwrap_or("");
            assert!(
                !refused.contains("CRL") && !refused.contains("crl"),
                "the CRL failure must not preempt the trust failure — reordering \
                 independent fallible checks changes which remediation an operator \
                 follows. Got {refused:?}"
            );
            assert!(
                refused.contains("trust"),
                "expected the trust-store refusal first, got {refused:?}"
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

/// The same bypass, for the posture that says an online revocation check is running.
///
/// `--client-ocsp require` is refused because the check is implemented only on the
/// blocking serve loop, while the production data plane is the per-core async fleet, which
/// performs no OCSP round trip at all. That refusal used to live only in `parse_args`, so
/// a caller building a `Config` in code could set `client_ocsp = Require`, reach the
/// serving path, and have startup announce `ONLINE OCSP client-cert revocation enabled` on
/// a deployment that admits every revoked client certificate.
///
/// The gap was found by writing the OFF branch of the startup posture: stating what an
/// operator should do INSTEAD required knowing whether the ON state was reachable, and it
/// was — but only off the parsed path.
#[test]
fn a_programmatic_config_cannot_claim_an_ocsp_check_the_serving_path_never_makes() {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    let m = serving_fixtures::write_material();
    let mut config = mcp_re_proxy::cli::parse_args(&base_args(&m)).expect("the base config parses");

    // What an in-code caller can write. `parse_args` refuses the flag, so this is the
    // only shape the configuration can take.
    config.client_ocsp = mcp_re_proxy::cli::OcspKind::Require;

    let err = mcp_re_proxy::app::run(config, Arc::new(AtomicBool::new(true)))
        .expect_err("a claim the serving path cannot deliver must be refused however it was built");

    assert!(
        err.contains("refuses unsafe configuration"),
        "expected the unsafe-configuration refusal, got: {err}"
    );
    assert!(
        err.contains("--client-ocsp require cannot be honored"),
        "the refusal must name the offending setting, got: {err}"
    );
}

/// The same bypass again, for a revocation control that nothing enforces.
///
/// `--revocation-list` supplies a policy-layer deny-list consumed only by an authorization
/// profile, and no production profile has landed, so the list would enforce nothing. The
/// parser refuses it — but `revocation_list_paths` is a public field, so a caller building
/// a `Config` in code reached the serving path carrying a revocation control that is never
/// read. An operator would believe a compromised grant was revoked while it kept being
/// authorized.
///
/// Deliberately drives `app::run`, not `parse_args`: a parser test would only exercise the
/// path that was already correct, which is the lesson the `--client-ocsp` case taught.
#[test]
fn a_programmatic_config_cannot_carry_a_deny_list_nothing_enforces() {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    let m = serving_fixtures::write_material();
    let mut config = mcp_re_proxy::cli::parse_args(&base_args(&m)).expect("the base config parses");

    // What an in-code caller can write; `parse_args` refuses the flag, so this is the only
    // shape the configuration can take.
    config.revocation_list_paths = vec!["/tmp/deny-list.json".to_string()];

    let err = mcp_re_proxy::app::run(config, Arc::new(AtomicBool::new(true)))
        .expect_err("a revocation control nothing enforces must be refused however it was built");

    assert!(
        err.contains("refuses unsafe configuration"),
        "expected the unsafe-configuration refusal, got: {err}"
    );
    assert!(
        err.contains("--revocation-list"),
        "the refusal must name the offending setting, got: {err}"
    );
}

/// An unaccepted authorization profile is refused at the VALIDATION boundary.
///
/// Third instance of the family, and the one that was never a bypass: the composition root
/// carried its own copy of this refusal, so a programmatically built `Config` was already
/// caught. What was wrong is that one prohibition was stated twice, in two places, with two
/// different diagnostics — free to drift, and a policy decision sitting in a composition
/// root (ADR-MCPRE-056 §12).
///
/// The composition-root copy is gone, so this test is what keeps the prohibition alive off
/// the parsed path. Without it, deleting the boundary consultation would leave nothing
/// refusing a programmatic `authz = Reference` at all.
#[test]
fn a_programmatic_config_cannot_enable_an_unaccepted_authz_profile() {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    let m = serving_fixtures::write_material();
    let mut config = mcp_re_proxy::cli::parse_args(&base_args(&m)).expect("the base config parses");

    config.authz = mcp_re_proxy::cli::AuthzKind::Reference;

    let err = mcp_re_proxy::app::run(config, Arc::new(AtomicBool::new(true)))
        .expect_err("an unaccepted authorization profile must be refused however it was built");

    assert!(
        err.contains("refuses unsafe configuration"),
        "the refusal must come from the validation boundary, not a later ad-hoc check, \
         got: {err}"
    );
    assert!(
        err.contains("--authz reference"),
        "the refusal must name the offending setting, got: {err}"
    );
}

/// `--transport-binding lb-assertion` is refused by the validation boundary alone.
///
/// The composition root used to refuse it too, in the same `matches!` arm as Mode-C
/// attested ingress. That arm now covers Mode-C only, so this test is what establishes
/// that dropping the duplicate did not drop the prohibition: the boundary refuses
/// lb-assertion on its own, for a `Config` that never met the parser.
///
/// Asserts the boundary's own wrapper rather than merely `is_err()` — with the guard gone,
/// this config would still fail later for an unrelated reason, and a weaker test would
/// report protection that had moved somewhere accidental.
#[test]
fn the_boundary_alone_refuses_an_lb_assertion_binding() {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    let m = serving_fixtures::write_material();
    let mut config = mcp_re_proxy::cli::parse_args(&base_args(&m)).expect("the base config parses");

    config.binding = mcp_re_proxy::cli::BindingKind::LbAssertion;

    let err = mcp_re_proxy::app::run(config, Arc::new(AtomicBool::new(true)))
        .expect_err("lb-assertion binding must be refused however it was built");

    assert!(
        err.contains("refuses unsafe configuration"),
        "the refusal must come from the validation boundary, got: {err}"
    );
    assert!(
        err.contains("lb-assertion"),
        "the refusal must name the offending setting, got: {err}"
    );
}

/// Mode-C attested ingress is refused at the configuration boundary, not later.
///
/// The refusal used to live in `run_validated` and NOWHERE else — a policy decision in a
/// composition root, and the only thing refusing the mode at all. It moved to the boundary
/// once the ruling was made that Mode-C is deliberately non-deployable in v0.16: refused,
/// not removed, because attested ingress is the shape a broker-mediated deployment needs
/// and is expected to be designed rather than deleted.
///
/// The order matters — the ruling came first, then the move. Relocating it earlier would
/// have made the product declaration as a side effect of a refactor.
///
/// Asserts the boundary's own wrapper: with the guard deleted, this config would still fail
/// somewhere downstream, and `is_err()` would report protection that had silently moved.
/// This test does NOT assert anything about the dormant Mode-C internals — the boundary
/// contract is the durable thing.
#[test]
fn mode_c_attested_ingress_is_refused_at_the_configuration_boundary() {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    let m = serving_fixtures::write_material();
    let mut config = mcp_re_proxy::cli::parse_args(&base_args(&m)).expect("the base config parses");

    config.binding = mcp_re_proxy::cli::BindingKind::AttestedIngress;

    let err = mcp_re_proxy::app::run(config, Arc::new(AtomicBool::new(true)))
        .expect_err("a non-deployable transport-binding mode must be refused");

    assert!(
        err.contains("refuses unsafe configuration"),
        "the refusal must come from the validation boundary, not a later ad-hoc check, \
         got: {err}"
    );
    assert!(
        err.contains("attested-ingress"),
        "the refusal must name the offending mode, got: {err}"
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
