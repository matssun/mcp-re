//! MCPS-010 — object conformance runner, end-to-end against the committed
//! vectors.
//!
//! The committed vectors at `components/mcps/mcps-core/tests/vectors/` are the
//! SINGLE SOURCE OF TRUTH. They are NOT duplicated into this crate: they are
//! embedded at compile time via `include_str!` of the sibling mcps-core package
//! paths (listed as `compile_data` from the `//components/mcps/mcps-core:vectors`
//! filegroup), so the bazel test needs no runfiles and no absolute paths.
//!
//! This re-proves the FULL suite (including the `requires_pipeline` vectors,
//! which MCPS-008 made runnable) through the conformance runner, and adds a
//! negative self-test proving the runner actually checks expected vs actual.

use mcps_conformance::parse_case;
use mcps_conformance::parse_manifest;
use mcps_conformance::run_suite;
use mcps_conformance::ObjectTarget;
use mcps_conformance::VectorCase;

// --- Embedded committed vectors (compile-time, no fs at test time) ----------

const MANIFEST: &str = include_str!("../../mcps-core/tests/vectors/manifest.json");

/// (manifest file name, embedded JSON text). Mirrors mcps-core's `committed()`.
fn embedded() -> Vec<(&'static str, &'static str)> {
    macro_rules! v {
        ($file:literal) => {
            (
                $file,
                include_str!(concat!("../../mcps-core/tests/vectors/", $file)),
            )
        };
    }
    vec![
        v!("v1_valid_request.json"),
        v!("v2_tampered_argument.json"),
        v!("tampered_id.json"),
        v!("v3_valid_response.json"),
        v!("v4_wrong_hash_garbage_sig_response.json"),
        v!("v4b_signed_wrong_hash_response.json"),
        v!("replay_request.json"),
        v!("expired_request.json"),
        v!("wrong_audience_request.json"),
        v!("missing_envelope_request.json"),
        v!("batch.json"),
        v!("security_notification.json"),
        v!("unknown_envelope_field.json"),
        v!("jcs_01_duplicate_key.json"),
        v!("jcs_02_unsafe_integer_id.json"),
        v!("jcs_03_unsafe_integer_arguments.json"),
        v!("jcs_04_non_integer_number.json"),
        v!("jcs_05_exponent_number.json"),
        v!("jcs_06_unpaired_surrogate.json"),
        v!("jcs_07_invalid_utf8.json"),
        v!("jcs_08_large_id_as_string.json"),
    ]
}

/// Load the committed vectors in manifest order from the embedded sources.
fn load_committed() -> Vec<VectorCase> {
    let entries = parse_manifest(MANIFEST).expect("manifest parses");
    let sources = embedded();
    let mut cases = Vec::with_capacity(entries.len());
    for entry in entries {
        let text = sources
            .iter()
            .find(|(file, _)| *file == entry.file)
            .unwrap_or_else(|| panic!("no embedded source for {}", entry.file))
            .1;
        cases.push(parse_case(text).unwrap_or_else(|e| panic!("parse {}: {e}", entry.file)));
    }
    cases
}

#[test]
fn embedded_set_matches_manifest() {
    let entries = parse_manifest(MANIFEST).expect("manifest parses");
    let manifest_files: std::collections::BTreeSet<String> =
        entries.iter().map(|e| e.file.clone()).collect();
    let embedded_files: std::collections::BTreeSet<String> =
        embedded().iter().map(|(f, _)| f.to_string()).collect();
    assert_eq!(
        manifest_files, embedded_files,
        "embedded vector set must match the committed manifest exactly"
    );
}

#[test]
fn object_runner_every_case_actual_equals_expected() {
    let cases = load_committed();
    assert!(!cases.is_empty(), "must load vectors");
    let report = run_suite(&ObjectTarget::new(), &cases);

    // Per-case: actual must equal expected (surfaces the offending case on fail).
    for r in &report.results {
        assert!(
            r.pass,
            "case '{}' (requires_pipeline={}): expected '{}' but got '{}'",
            r.name, r.requires_pipeline, r.expected, r.actual
        );
    }
}

#[test]
fn object_runner_report_is_all_green() {
    let cases = load_committed();
    let total = cases.len();
    let report = run_suite(&ObjectTarget::new(), &cases);
    assert_eq!(report.failed, 0, "no case may fail");
    assert_eq!(report.passed, total, "every case must pass");
    assert_eq!(report.total, total);
    assert!(report.all_passed());
}

#[test]
fn object_runner_covers_pipeline_dependent_vectors() {
    // The requires_pipeline vectors (replay/expired/audience/missing/batch/
    // notification/unknown-field/V4B) are now runnable through the pipeline;
    // confirm they are present AND pass.
    let cases = load_committed();
    let report = run_suite(&ObjectTarget::new(), &cases);
    let pipeline_cases: Vec<&_> = report
        .results
        .iter()
        .filter(|r| r.requires_pipeline)
        .collect();
    assert!(
        pipeline_cases.len() >= 8,
        "expected the full set of pipeline-dependent vectors, found {}",
        pipeline_cases.len()
    );
    for r in pipeline_cases {
        assert!(r.pass, "pipeline-dependent case '{}' must pass", r.name);
    }
}

/// Negative self-test: feed a synthetic case whose `expected` is deliberately
/// WRONG and confirm the runner reports it as failed. Proves the runner truly
/// compares actual vs expected rather than rubber-stamping.
#[test]
fn runner_reports_failure_when_expected_is_wrong() {
    // Start from the real v1 valid request (verifies OK) but assert it should
    // produce an audience error — a lie the runner must catch. (We avoid the
    // replay token here: that token selects the runner's double-submit path,
    // which would make a lone fresh-cache run genuinely replay-detect itself.)
    let v1_text = embedded()
        .into_iter()
        .find(|(f, _)| *f == "v1_valid_request.json")
        .expect("v1 present")
        .1;
    let mut bogus = parse_case(v1_text).expect("parse v1");
    bogus.name = "synthetic_wrong_expected".to_string();
    bogus.expected = "mcps.invalid_audience".to_string();

    // Include a real OK request too so the suite has a green baseline.
    let good = parse_case(v1_text).expect("parse v1 again");

    let report = run_suite(&ObjectTarget::new(), &[good, bogus]);
    assert_eq!(report.failed, 1, "exactly the bogus case must fail");
    assert_eq!(report.passed, 1, "the honest case must pass");

    let bogus_result = report
        .results
        .iter()
        .find(|r| r.name == "synthetic_wrong_expected")
        .expect("bogus result present");
    assert!(!bogus_result.pass, "bogus case must be reported as failed");
    assert_eq!(bogus_result.expected, "mcps.invalid_audience");
    assert_eq!(
        bogus_result.actual, "verify_ok",
        "actual must be the true outcome (verify_ok), not the lie"
    );
}
