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

use crate::serving_fixtures;
use crate::startup_transcript;

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

/// A `DeploymentRequest` that never went through the parser cannot bypass the safety guards.
///
/// `DeploymentRequest` has 76 public fields. Until the validation boundary landed, the hard guards
/// ran only inside `parse_args`, so anything that built a `DeploymentRequest` in code — an
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
/// a caller building a `DeploymentRequest` in code could set `client_ocsp = Require`, reach the
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
/// a `DeploymentRequest` in code reached the serving path carrying a revocation control that is never
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
/// carried its own copy of this refusal, so a programmatically built `DeploymentRequest` was already
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
/// lb-assertion on its own, for a `DeploymentRequest` that never met the parser.
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
    // A file replay cache never reaches a build question: CF-01 made it a LAYER-A
    // refusal, because no build can establish it, so there is no capability to name.
    // Asserted at the boundary rather than through `run`, which it no longer reaches.
    let file_refusal =
        mcp_re_proxy::cli::parse_args(&mk(&["--replay-cache", "file", "--replay-path", "/tmp/x"]))
            .expect_err("file is not a deployment state");
    assert!(
        file_refusal.contains("not a supported deployment state"),
        "{file_refusal}"
    );
    // The linearizable (CP) tier needs a cpstore_etcd build. The Redis replay locator is
    // dropped from the base first: it belongs to the OTHER replay state, and layer A now
    // refuses it beside a linearizable tier (CF-12), which would mask this build refusal.
    let mut linearizable = mk(&[
        "--replay-durability-tier",
        "linearizable",
        "--cpstore-etcd-endpoint",
        "http://127.0.0.1:2379",
    ]);
    let at = linearizable
        .iter()
        .position(|a| a == "--replay-redis-url")
        .expect("the base names a redis replay store");
    linearizable.drain(at..at + 2);
    let refusal = app_err(linearizable);
    assert!(refusal.contains("cpstore_etcd"), "got: {refusal}");
}

/// ADR-MCPRE-058 §8.3 / §16.3 — the delegated-custody knobs, audited as a family.
///
/// # Why these, and why together
///
/// `parse_args` refuses four delegated-custody configurations: a missing trust epoch, a
/// non-positive TTL, a non-positive overlap, and an overlap that meets or exceeds the
/// TTL. Each is an invariant an in-code caller could otherwise walk past, since `DeploymentRequest`
/// has public fields and nothing downstream re-derives them.
///
/// The four are asserted together because the failure they prevent is one failure. A
/// delegated key minted without a trust epoch carries the bare label instead of
/// `<base>#<counter>`, so a restarted replica appears unrevoked to verifiers pinned past
/// an operator `INCR` — the cross-fleet kill switch stops working. A TTL or overlap
/// outside `0 < overlap < ttl` breaks the rotor's successor-before-expiry rule, so
/// signing stops or never starts. Either way the deployment would be serving on custody
/// nobody can revoke or rotate.
///
/// # This used to drive the wiring, and now drives the boundary
///
/// Three of the four were boundary clauses; the trust epoch was refused only inside
/// `delegated_wiring::build_delegated_signing`. So the family was split across two layers
/// — and the epoch half fired late, after the trust and TLS planes had already read files
/// and started workers, from a module whose subject is building a signer rather than
/// judging a configuration.
///
/// With `SigningPlan` the wiring is infallible and all four are checked in one place,
/// before anything is established. That also removed this test's old caveat about not
/// being able to assert through `run`: the boundary is reachable without materializing
/// anything, so what is asserted here is now strictly stronger than what it replaced.
///
/// The broken implementation this catches: dropping one of the four from the boundary on
/// the grounds that the parser already refuses it.
#[test]
fn a_programmatic_config_cannot_carry_delegated_custody_the_rotor_cannot_honour() {
    let m = serving_fixtures::write_material();
    let parsed = mcp_re_proxy::cli::parse_args(&base_args(&m)).expect("the base config parses");

    // Each case is a mutation the parser would have refused, applied afterwards — the
    // only shape an in-code caller has — with the substring the refusal must name.
    #[allow(clippy::type_complexity)]
    let cases: Vec<(
        &str,
        Box<dyn Fn(&mut mcp_re_proxy::cli::DeploymentRequest)>,
        &str,
    )> = vec![
        (
            "no trust epoch",
            Box::new(|c: &mut mcp_re_proxy::cli::DeploymentRequest| c.delegated_trust_epoch = None),
            "trust epoch",
        ),
        (
            "zero ttl",
            Box::new(|c: &mut mcp_re_proxy::cli::DeploymentRequest| c.delegated_ttl_secs = 0),
            "ttl",
        ),
        (
            "negative overlap",
            Box::new(|c: &mut mcp_re_proxy::cli::DeploymentRequest| c.delegated_overlap_secs = -1),
            "overlap",
        ),
        (
            "overlap at the ttl",
            Box::new(|c: &mut mcp_re_proxy::cli::DeploymentRequest| {
                c.delegated_overlap_secs = c.delegated_ttl_secs
            }),
            "overlap",
        ),
    ];

    for (name, mutate, expected) in cases {
        let mut config = parsed.clone();
        mutate(&mut config);
        let err = mcp_re_proxy::cli::ValidatedDeployment::try_from(config).expect_err(&format!(
            "{name}: custody the rotor cannot honour must be refused"
        ));
        assert!(
            err.to_lowercase().contains(expected),
            "{name}: the refusal must name what is wrong; expected {expected:?}, got: {err}"
        );
    }

    // The negative control. Without it every assertion above would also pass against a
    // boundary that refused unconditionally — and one that refuses every delegated
    // configuration is not a stricter proxy, it is a broken one.
    let mut valid = parsed;
    valid.delegated_overlap_secs = valid.delegated_ttl_secs / 2;
    assert!(
        valid.delegated_overlap_secs > 0,
        "the control needs a genuinely valid overlap to be worth anything"
    );
    mcp_re_proxy::cli::ValidatedDeployment::try_from(valid)
        .expect("a valid delegated custody policy must be admitted");
}

/// The fifth member of the parser-only family: contradictory TLS-key custody.
///
/// `validate_tls_signing_exclusivity` refuses a config that asserts BOTH a delegated,
/// non-exporting TLS key and an exported one. Until now it was called from `parse_args`
/// and nowhere else, so a `DeploymentRequest` built in code could assert both and reach the serving
/// path — and nothing downstream would notice, because `build_key_source` dispatches on
/// `key_source` and simply ignores a selector belonging to another source.
///
/// The state it refuses is not an operator typo. It means the TLS handshake key is
/// custodied in a device it is supposed never to leave, while a copy of it also sits in
/// a file on the pod — which is the whole property the delegated custody modes exist to
/// provide, quietly false. That is the "believes no key material lands in the pod while
/// it does" shape the key-file permission work already chased once.
///
/// The broken implementation this catches: reverting the refusal to a parse-time-only
/// check, which is where every other member of this family started.
#[test]
fn a_programmatic_config_cannot_assert_both_delegated_and_exported_tls_custody() {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    let m = serving_fixtures::write_material();
    let parsed = mcp_re_proxy::cli::parse_args(&base_args(&m)).expect("the base config parses");

    // The base config custodies the TLS key in a FILE. Asserting a token-resident TLS
    // key on top of it is the contradiction: the parser would have refused the pair, and
    // setting it afterwards is the only shape an in-code caller has.
    let mut config = parsed.clone();
    assert!(
        !config.tls_key.is_empty(),
        "the fixture must start with an exported TLS key for the contradiction to exist"
    );
    config.pkcs11_tls_key_label = Some("tls-key-on-the-token".to_string());

    let err = mcp_re_proxy::app::run(config, Arc::new(AtomicBool::new(true)))
        .expect_err("contradictory TLS custody must be refused however the config was built");
    assert!(
        err.contains("refuses unsafe configuration"),
        "it must be refused at the validation boundary, got: {err}"
    );
    assert!(
        err.to_lowercase().contains("tls"),
        "the refusal must name the contradiction, got: {err}"
    );

    // Negative control: the SAME config without the contradictory selector must not be
    // refused for TLS custody. Without this, a boundary that refused every config would
    // satisfy the assertion above.
    let err = mcp_re_proxy::app::run(parsed, Arc::new(AtomicBool::new(true)))
        .expect_err("this fixture stops at an environmental step, not a custody one");
    assert!(
        !err.contains("refuses unsafe configuration"),
        "an exported TLS key alone is a supported custody and must not be refused, got: {err}"
    );
}

/// ADR-MCPRE-058 §8.3 — the request-target reconstruction check cannot be disabled by
/// building the config in code.
///
/// `async_serve` refuses to serve when the origin-form of the configured `--target-uri`
/// differs from the one the request arrived at. That comparison is answerable only for an
/// absolute target: `origin_form_of` returns `None` without a `://`, and
/// `target_uri_mismatch` reads that `None` as "no mismatch". A scheme-less target therefore
/// does not weaken the check, it turns it off for every request — and both of those
/// functions documented the shape as something the parser had already guaranteed.
///
/// It had, and only for argv. `target_uri` is a public `DeploymentRequest` field, so this was the
/// sixth member of the parser-only family: an ingress fanning several paths into one
/// process would verify signatures over a `@target-uri` no request arrived at, while the
/// deployment reported the binding as in force.
///
/// Driven through `app::run` rather than the serving path because the boundary is where
/// the refusal belongs — a config this shape must never reach a listener at all.
#[test]
fn a_programmatic_config_cannot_disable_the_request_target_reconstruction_check() {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    let m = serving_fixtures::write_material();
    let parsed = mcp_re_proxy::cli::parse_args(&base_args(&m)).expect("the base config parses");

    for (label, target) in [
        ("scheme-less", "proxy.internal:8600/mcp"),
        ("path-only", "/mcp"),
        ("empty", ""),
    ] {
        let mut config = parsed.clone();
        config.target_uri = target.to_string();

        let err = mcp_re_proxy::app::run(config, Arc::new(AtomicBool::new(true)))
            .expect_err("a target of this shape must be refused however the config was built");
        assert!(
            err.contains("refuses unsafe configuration"),
            "a {label} target must be refused at the validation boundary, got: {err}"
        );
        assert!(
            err.contains("--target-uri"),
            "the refusal must name the flag, got: {err}"
        );
    }

    // Negative control: the same fixture with its absolute target must NOT be refused for
    // this reason. Without it, a boundary that refused every config would satisfy the
    // assertions above.
    let err = mcp_re_proxy::app::run(parsed, Arc::new(AtomicBool::new(true)))
        .expect_err("this fixture stops at an environmental step, not a target-uri one");
    assert!(
        !err.contains("refuses unsafe configuration"),
        "an absolute target is the supported shape and must not be refused, got: {err}"
    );
}

/// R8-C014 / R8-C015 — the KMS/STS endpoint overrides carry the ROOT-KEY trust bootstrap,
/// and the rule that protects them is not a parser rule.
///
/// `validated_kms_endpoint` allows `https://` anywhere and `http://` only to loopback,
/// because the named host supplies the `GetPublicKey`/SPKI that becomes the ROOT verify
/// key — so a substituted endpoint substitutes the root authority and every local
/// fail-closed check then passes self-consistently against the attacker's key — and
/// because the GCP path posts a live workload-identity bearer token to it in the clear.
///
/// All three endpoint fields are public on `DeploymentRequest`. Until the rule reached the validation
/// boundary, a config built in code could name `http://attacker/` and reach key-source
/// construction unrefused.
///
/// R9-C001 extends the case list to the authorities that READ as the intended host and are
/// not it. `ureq` resolves a request URL with `url::Url::parse` and connects to its
/// `host_str()`: `https://cloudkms.googleapis.com@evil.example.com` reaches
/// `evil.example.com`, and `http://localhost:80@evil.example.com` reaches it too — the
/// loopback exception was decided from a host derived BEFORE userinfo was stripped, so
/// plaintext to "loopback" put a live bearer token on the wire to an arbitrary host. The
/// round-8 case list used only bare hosts and passed straight over both.
///
/// The broken implementation this catches: consulting `validated_kms_endpoint` only from
/// the argv match arms, or checking the scheme and the host's emptiness without checking
/// what a URL parser reads the authority as.
#[test]
fn a_programmatic_config_cannot_point_a_root_key_endpoint_at_a_plaintext_host() {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    let m = serving_fixtures::write_material();
    let parsed = mcp_re_proxy::cli::parse_args(&base_args(&m)).expect("the base config parses");

    // (flag, the REASON the refusal must give, mutation). The reason matters: three of
    // these fields are also named by unrelated coherence rules, so asserting only that the
    // flag appears would let a refusal for another cause stand in for this one.
    #[allow(clippy::type_complexity)]
    let cases: Vec<(
        &str,
        &str,
        Box<dyn Fn(&mut mcp_re_proxy::cli::DeploymentRequest)>,
    )> = vec![
        (
            "--aws-kms-endpoint",
            "loopback",
            Box::new(|c: &mut mcp_re_proxy::cli::DeploymentRequest| {
                c.aws_kms_endpoint = Some("http://attacker.example/".to_string())
            }),
        ),
        (
            "--gcp-kms-endpoint",
            "loopback",
            Box::new(|c: &mut mcp_re_proxy::cli::DeploymentRequest| {
                c.gcp_kms_endpoint = Some("http://attacker.example/v1".to_string())
            }),
        ),
        (
            "--aws-kms-endpoint",
            "absolute https:// URL",
            Box::new(|c: &mut mcp_re_proxy::cli::DeploymentRequest| {
                c.aws_kms_endpoint = Some("ftp://kms.internal/".to_string())
            }),
        ),
        (
            "--aws-kms-endpoint",
            "has no host",
            Box::new(|c: &mut mcp_re_proxy::cli::DeploymentRequest| {
                c.aws_kms_endpoint = Some("https://".to_string())
            }),
        ),
        // R9-C001: an authority whose userinfo re-points the request. `url::Url::parse`
        // reads the host of every one of these as `evil.example.com`.
        (
            "--gcp-kms-endpoint",
            "userinfo",
            Box::new(|c: &mut mcp_re_proxy::cli::DeploymentRequest| {
                c.gcp_kms_endpoint =
                    Some("https://cloudkms.googleapis.com@evil.example.com".to_string())
            }),
        ),
        (
            "--gcp-kms-endpoint",
            "userinfo",
            Box::new(|c: &mut mcp_re_proxy::cli::DeploymentRequest| {
                c.gcp_kms_endpoint = Some("http://localhost:80@evil.example.com".to_string())
            }),
        ),
        (
            "--aws-kms-endpoint",
            "userinfo",
            Box::new(|c: &mut mcp_re_proxy::cli::DeploymentRequest| {
                c.aws_kms_endpoint =
                    Some("https://kms.us-east-1.amazonaws.com@evil.example.com".to_string())
            }),
        ),
        (
            "--aws-kms-endpoint",
            "userinfo",
            Box::new(|c: &mut mcp_re_proxy::cli::DeploymentRequest| {
                c.aws_kms_endpoint = Some("http://127.0.0.1:4566@evil.example.com".to_string())
            }),
        ),
        (
            "--aws-sts-endpoint",
            "userinfo",
            Box::new(|c: &mut mcp_re_proxy::cli::DeploymentRequest| {
                c.aws_sts_endpoint =
                    Some("https://sts.eu-north-1.amazonaws.com@evil.example.com".to_string())
            }),
        ),
    ];

    for (flag, reason, mutate) in cases {
        let mut config = parsed.clone();
        mutate(&mut config);
        let err = mcp_re_proxy::app::run(config, Arc::new(AtomicBool::new(true)))
            .expect_err("an unvalidated root-key endpoint must be refused");
        assert!(
            err.contains("refuses unsafe configuration")
                && err.contains(flag)
                && err.contains(reason),
            "the boundary must refuse it, name {flag} and say {reason:?}, got: {err}"
        );
    }

    // The negative controls: the shapes the rule exists to KEEP working — the public
    // hosts, a VPC endpoint, an emulator with a port, and the loopback `http://` lane with
    // and without a port. A boundary that refused every endpoint would satisfy every
    // assertion above, which is how round 8 shipped three fail-closed regressions.
    for allowed in [
        "https://kms.us-east-1.amazonaws.com/",
        "https://cloudkms.googleapis.com",
        "https://vpce-0abc123-xy1z.kms.us-east-1.vpce.amazonaws.com",
        "https://kms.emulator.svc.cluster.local:8443",
        "http://127.0.0.1:4566/",
        "http://localhost:4566",
        "http://[::1]:4566",
        "http://localhost",
    ] {
        let mut config = parsed.clone();
        config.aws_kms_endpoint = Some(allowed.to_string());
        config.gcp_kms_endpoint = Some(allowed.to_string());
        let err = mcp_re_proxy::app::run(config, Arc::new(AtomicBool::new(true)))
            .expect_err("this fixture stops at an environmental step");
        assert!(
            !err.contains("refuses unsafe configuration"),
            "{allowed} is an admissible endpoint and must not be refused, got: {err}"
        );
        // `--aws-sts-endpoint` is refused by an unrelated coherence rule unless
        // `--aws-kms-use-web-identity` is on, so its accept case is asserted against the
        // endpoint decision itself rather than against the whole boundary.
        let mut sts = parsed.clone();
        sts.aws_sts_endpoint = Some(allowed.to_string());
        let err = mcp_re_proxy::app::run(sts, Arc::new(AtomicBool::new(true)))
            .expect_err("this fixture stops at an environmental step");
        assert!(
            !err.contains("userinfo") && !err.contains("loopback"),
            "{allowed} is an admissible --aws-sts-endpoint and must not be refused as one, \
             got: {err}"
        );
    }
}

/// R8-C108 — the custody-coherence and ingress-assertion clauses refuse a state, not a
/// typo, so they belong at the validation boundary too.
///
/// A selector belonging to another key source is silently ignored by `build_key_source`,
/// which dispatches on `key_source` alone; a dangling ingress key is silently ignored by a
/// binding that never reads it. In both cases the operator believes a custody or a
/// request-binding control is in force when nothing enforces it — and neither belief gets
/// truer because the config was built in code rather than parsed.
///
/// The broken implementation this catches: calling `key_source_custody_refusal` and
/// `ingress_assertion_refusal` only from `parse_args`.
#[test]
fn a_programmatic_config_cannot_carry_a_dangling_custody_or_ingress_selector() {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    let m = serving_fixtures::write_material();
    let parsed = mcp_re_proxy::cli::parse_args(&base_args(&m)).expect("the base config parses");

    #[allow(clippy::type_complexity)]
    let cases: Vec<(&str, Box<dyn Fn(&mut mcp_re_proxy::cli::DeploymentRequest)>)> = vec![
        (
            "--gcp-kms-use-metadata",
            Box::new(|c: &mut mcp_re_proxy::cli::DeploymentRequest| c.gcp_kms_use_metadata = true),
        ),
        (
            "--aws-kms-use-web-identity",
            Box::new(|c: &mut mcp_re_proxy::cli::DeploymentRequest| {
                c.aws_kms_use_web_identity = true
            }),
        ),
        (
            "--ingress-lb-key",
            Box::new(|c: &mut mcp_re_proxy::cli::DeploymentRequest| {
                c.ingress_lb_keys = vec![("lb-1".to_string(), "not-a-key".to_string())]
            }),
        ),
        (
            "--ingress-identity",
            Box::new(|c: &mut mcp_re_proxy::cli::DeploymentRequest| {
                c.ingress_identities = vec!["spiffe://x/ingress".to_string()]
            }),
        ),
    ];

    for (flag, mutate) in cases {
        let mut config = parsed.clone();
        mutate(&mut config);
        let err = mcp_re_proxy::app::run(config, Arc::new(AtomicBool::new(true)))
            .expect_err("a dangling custody/ingress selector must be refused");
        assert!(
            err.contains("refuses unsafe configuration") && err.contains(flag),
            "the boundary must refuse it and name {flag}, got: {err}"
        );
    }

    // Negative control: the untouched fixture carries none of these selectors and must
    // not be refused for this reason.
    let err = mcp_re_proxy::app::run(parsed, Arc::new(AtomicBool::new(true)))
        .expect_err("this fixture stops at an environmental step");
    assert!(
        !err.contains("refuses unsafe configuration"),
        "a coherent custody/ingress configuration must not be refused, got: {err}"
    );
}

/// R8-C052 — a zero CRL reload cadence is a spin, not a disabled reloader.
///
/// The cadence IS the sleep between re-reads, so `Some(0)` makes the reload worker re-read
/// every CRL file, rebuild the rustls verifier and swap the serving-config snapshot in a
/// tight loop: one core burned and the snapshot thrashed, with no diagnostic. The parser
/// refuses it; `client_crl_reload_secs` is a public field, so until the boundary refused it
/// too, an embedder or harness got exactly that replica.
///
/// The broken implementation this catches: keeping the zero-cadence refusal in the argv
/// match arm alone.
#[test]
fn a_programmatic_config_cannot_hot_spin_the_crl_reloader() {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    let m = serving_fixtures::write_material();
    let parsed = mcp_re_proxy::cli::parse_args(&base_args(&m)).expect("the base config parses");

    let mut config = parsed.clone();
    config.client_crl_reload_secs = Some(0);
    let err = mcp_re_proxy::app::run(config, Arc::new(AtomicBool::new(true)))
        .expect_err("a zero reload cadence must be refused");
    assert!(
        err.contains("refuses unsafe configuration") && err.contains("--client-crl-reload-secs"),
        "the boundary must refuse it and name the flag, got: {err}"
    );

    // Negative controls: a positive cadence, and no cadence at all (load once), are both
    // supported and must not be refused.
    //
    // The cadence is given a list to re-read. Since the `CrlRevocation` machine landed, a
    // cadence with no CRLs is itself refused — it names how often to re-read an empty set,
    // so it states a revocation control the deployment does not have — and that refusal
    // would mask the property under test here.
    for cadence in [Some(30), None] {
        let mut config = parsed.clone();
        config.client_crl_paths = vec![m.client_ca_path.to_string_lossy().into_owned()];
        config.client_crl_reload_secs = cadence;
        let err = mcp_re_proxy::app::run(config, Arc::new(AtomicBool::new(true)))
            .expect_err("this fixture stops at an environmental step");
        assert!(
            !err.contains("refuses unsafe configuration"),
            "cadence {cadence:?} is supported and must not be refused, got: {err}"
        );
    }
}

/// R8-C098 — the delegated credential's TTL is its exposure window, and it needs a ceiling.
///
/// `exp` is the ONLY thing that ever expires a delegated response-signing credential: an
/// operator advancing the trust epoch does not reach credentials already issued under it,
/// because no verifier reads the counter. So an exfiltrated delegated key stays verifiable
/// for exactly the configured TTL — while every document describing the deployment calls it
/// the SHORT-lived hot-path key. Nothing refused, or even warned about, an arbitrarily long
/// one: parse, the boundary and `delegated_wiring` all checked only `0 < overlap < ttl`.
///
/// The broken implementation this catches: a TTL validated for positivity alone.
#[test]
fn a_programmatic_config_cannot_mint_an_unboundedly_long_lived_delegated_credential() {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    let m = serving_fixtures::write_material();
    let parsed = mcp_re_proxy::cli::parse_args(&base_args(&m)).expect("the base config parses");
    let ceiling = mcp_re_proxy::cli::MAX_DELEGATED_TTL_SECS;

    let mut config = parsed.clone();
    config.delegated_ttl_secs = ceiling + 1;
    config.delegated_overlap_secs = 60;
    let err = mcp_re_proxy::app::run(config, Arc::new(AtomicBool::new(true)))
        .expect_err("a TTL above the ceiling must be refused");
    assert!(
        err.contains("refuses unsafe configuration") && err.contains("--delegated-ttl-secs"),
        "the boundary must refuse it and name the flag, got: {err}"
    );

    // And the rotor's window rule holds at the boundary as well as in the wiring.
    let mut config = parsed.clone();
    config.delegated_overlap_secs = config.delegated_ttl_secs;
    let err = mcp_re_proxy::app::run(config, Arc::new(AtomicBool::new(true)))
        .expect_err("an overlap at the TTL must be refused");
    assert!(
        err.contains("--delegated-overlap-secs"),
        "the refusal must name the overlap, got: {err}"
    );

    // Negative control: a TTL exactly AT the ceiling is admissible. Without it, a boundary
    // that refused every delegated TTL would satisfy the assertions above.
    let mut config = parsed;
    config.delegated_ttl_secs = ceiling;
    config.delegated_overlap_secs = 60;
    let err = mcp_re_proxy::app::run(config, Arc::new(AtomicBool::new(true)))
        .expect_err("this fixture stops at an environmental step");
    assert!(
        !err.contains("refuses unsafe configuration"),
        "a TTL at the ceiling is admissible and must not be refused, got: {err}"
    );
}
