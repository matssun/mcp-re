//! MCPS-012 — stdio harness conformance tests.
//!
//! Launches the `mcps_stdio_server` child process and drives the full MCP-S
//! outcome matrix over real stdin/stdout (newline-delimited JSON-RPC):
//! valid-accept, tamper-reject, replay-reject, expiry-reject, wrong-audience-
//! reject, signed-response-verify, and wrong-request-binding-reject. The closing
//! test proves the stdio transport produces the SAME wire token as the
//! in-process object target for the shared request vectors (ADR-MCPS-011
//! transport parity).
//!
//! The server binary is located from `MCPS_STDIO_SERVER` (set by the BUILD
//! target to `$(rlocationpath :mcps_stdio_server)`) resolved against the bazel
//! runfiles root — no runfiles-crate dependency.

use std::path::PathBuf;

use mcps_conformance::now_unix_for_case;
use mcps_conformance::outcome_token;
use mcps_conformance::parse_case;
use mcps_conformance::response_resolver;
use mcps_conformance::ConformanceTarget;
use mcps_conformance::ObjectTarget;
use mcps_conformance::RunContext;
use mcps_conformance::StdioHarness;
use mcps_conformance::VectorCase;
use mcps_core::parse_rfc3339_utc;
use mcps_core::request_hash;
use mcps_core::McpsError;
use serde_json::Value;

// --- Embedded committed request vectors (compile-time; no fs at test time) ---

const V1: &str = include_str!("../../mcps-core/tests/vectors/v1_valid_request.json");
const V2_TAMPERED: &str = include_str!("../../mcps-core/tests/vectors/v2_tampered_argument.json");
const REPLAY: &str = include_str!("../../mcps-core/tests/vectors/replay_request.json");
const EXPIRED: &str = include_str!("../../mcps-core/tests/vectors/expired_request.json");
const WRONG_AUDIENCE: &str =
    include_str!("../../mcps-core/tests/vectors/wrong_audience_request.json");
// MCPS-082 (audit M-12): P182 names these two as well; they must agree
// object == stdio == http like the rest, not be object-only.
const TAMPERED_ID: &str = include_str!("../../mcps-core/tests/vectors/tampered_id.json");
const MISSING_ENVELOPE: &str =
    include_str!("../../mcps-core/tests/vectors/missing_envelope_request.json");

const ISSUED_AT: &str = "2026-05-28T20:00:00Z";

/// Locate the server binary from the `$(rlocationpath)` env, resolved against
/// the runfiles root. Tries `TEST_SRCDIR`, `RUNFILES_DIR`, then the bare path.
fn locate_server() -> PathBuf {
    mcps_test_paths::resolve_runfile("MCPS_STDIO_SERVER")
}

fn harness() -> StdioHarness {
    StdioHarness::new(locate_server())
}

/// `now` 60s after the canonical issued_at — inside the freshness window.
fn now_fresh() -> i64 {
    parse_rfc3339_utc(ISSUED_AT).expect("parse issued_at") + 60
}

/// The serialized request bytes for a vector's `message`.
fn request_bytes(case: &VectorCase) -> Vec<u8> {
    let message = case.message.as_ref().expect("request vector has a message");
    serde_json::to_vec(message).expect("serialize message")
}

/// The locally computed request_hash for a request vector's message.
fn case_request_hash(case: &VectorCase) -> String {
    let message = case.message.as_ref().expect("message");
    // A vector with no signed envelope (e.g. missing_envelope_request) has no
    // request hash; it is rejected before any response binding, so the hash is
    // unused in the outcome. Fall back to a placeholder rather than panicking.
    request_hash(message).unwrap_or_else(|_| "sha256:unused".to_string())
}

#[test]
fn valid_request_over_stdio_verifies_and_binds() {
    let case = parse_case(V1).expect("parse v1");
    let resp = harness()
        .roundtrip(&request_bytes(&case), now_fresh())
        .expect("roundtrip");

    let expected_hash = case_request_hash(&case);
    let token = outcome_token(&resp, &expected_hash, &response_resolver());
    assert_eq!(token, "verify_ok", "signed response must verify and bind");

    // The echoed text round-trips through the transport.
    let value: Value = serde_json::from_slice(&resp).expect("parse response");
    assert_eq!(
        value["result"]["content"][0]["text"].as_str(),
        Some("hello")
    );
}

#[test]
fn tampered_request_over_stdio_is_rejected() {
    let case = parse_case(V1).expect("parse v1");
    let mut value: Value = serde_json::from_slice(&request_bytes(&case)).expect("parse v1 message");
    value["params"]["arguments"]["text"] = Value::String("goodbye".to_string());
    let tampered = serde_json::to_vec(&value).expect("reserialize tampered");

    let resp = harness()
        .roundtrip(&tampered, now_fresh())
        .expect("roundtrip");
    let token = outcome_token(&resp, "sha256:unused", &response_resolver());
    assert_eq!(token, "mcps.invalid_signature");
}

#[test]
fn replayed_request_over_stdio_is_rejected_on_second_submission() {
    let case = parse_case(V1).expect("parse v1");
    let bytes = request_bytes(&case);
    // Two identical submissions to ONE process: the replay cache persists.
    let responses = harness()
        .serve(&[bytes.clone(), bytes], now_fresh())
        .expect("serve twice");
    assert_eq!(responses.len(), 2, "two requests, two responses");

    let first = outcome_token(
        &responses[0],
        &case_request_hash(&case),
        &response_resolver(),
    );
    assert_eq!(first, "verify_ok", "first submission accepted");
    let second = outcome_token(&responses[1], "sha256:unused", &response_resolver());
    assert_eq!(second, "mcps.replay_detected", "second submission replayed");
}

#[test]
fn expired_request_over_stdio_is_rejected() {
    let case = parse_case(EXPIRED).expect("parse expired");
    let now = now_unix_for_case(&case).expect("now for expired");
    let resp = harness()
        .roundtrip(&request_bytes(&case), now)
        .expect("roundtrip");
    let token = outcome_token(&resp, "sha256:unused", &response_resolver());
    assert_eq!(token, "mcps.expired_request");
}

#[test]
fn wrong_audience_over_stdio_is_rejected() {
    let case = parse_case(WRONG_AUDIENCE).expect("parse wrong_audience");
    let resp = harness()
        .roundtrip(&request_bytes(&case), now_fresh())
        .expect("roundtrip");
    let token = outcome_token(&resp, "sha256:unused", &response_resolver());
    assert_eq!(token, "mcps.invalid_audience");
}

#[test]
fn signed_response_bound_to_wrong_request_is_rejected() {
    // A valid request yields a signed response bound to ITS hash; verifying that
    // response against a different request's hash must fail the binding check.
    let case = parse_case(V1).expect("parse v1");
    let resp = harness()
        .roundtrip(&request_bytes(&case), now_fresh())
        .expect("roundtrip");

    let token = outcome_token(
        &resp,
        "sha256:some-other-request-hash",
        &response_resolver(),
    );
    assert_eq!(token, McpsError::ResponseHashMismatch.wire_code());
}

#[test]
fn stdio_matches_object_outcomes_for_shared_request_vectors() {
    let object = ObjectTarget::new();
    let ctx = RunContext {
        canonical_request_hash: None,
    };

    for raw in [
        V1,
        V2_TAMPERED,
        REPLAY,
        EXPIRED,
        WRONG_AUDIENCE,
        TAMPERED_ID,
        MISSING_ENVELOPE,
    ] {
        let case = parse_case(raw).expect("parse vector");

        // Object target's wire token for this vector.
        let object_token = object
            .run_case(&case, &ctx)
            .expect("object run_case")
            .as_token()
            .to_string();

        // stdio transport's wire token for the SAME vector.
        let now = now_unix_for_case(&case).expect("now");
        let bytes = request_bytes(&case);
        let expected_hash = case_request_hash(&case);
        let stdio_token = if case.expected == "mcps.replay_detected" {
            let responses = harness()
                .serve(&[bytes.clone(), bytes], now)
                .expect("serve twice");
            outcome_token(&responses[1], &expected_hash, &response_resolver())
        } else {
            let resp = harness().roundtrip(&bytes, now).expect("roundtrip");
            outcome_token(&resp, &expected_hash, &response_resolver())
        };

        assert_eq!(
            stdio_token, object_token,
            "transport parity: vector '{}' must yield identical tokens (object={object_token}, stdio={stdio_token})",
            case.name
        );
    }
}
