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
