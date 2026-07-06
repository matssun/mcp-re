//! MCPS-013 — Streamable HTTP harness conformance tests.
//!
//! Drives the full MCP-RE outcome matrix over real loopback HTTP and asserts the
//! SAME wire tokens as the stdio harness and the in-process object target — the
//! transport-agnostic headline claim (ADR-MCPS-011). The closing test runs each
//! shared request vector through all three targets (object, stdio, HTTP) and
//! asserts identical outcomes.
//!
//! The stdio comparison launches the `mcp_re_stdio_server` child process, located
//! from `MCP_RE_STDIO_SERVER` ($(rlocationpath)) resolved against the runfiles
//! root — no runfiles-crate dependency.

use std::path::PathBuf;

use mcp_re_conformance::now_unix_for_case;
use mcp_re_conformance::outcome_token;
use mcp_re_conformance::parse_case;
use mcp_re_conformance::response_resolver;
use mcp_re_conformance::ConformanceTarget;
use mcp_re_conformance::HttpHarness;
use mcp_re_conformance::ObjectTarget;
use mcp_re_conformance::RunContext;
use mcp_re_conformance::StdioHarness;
use mcp_re_conformance::VectorCase;
use mcp_re_core::parse_rfc3339_utc;
use mcp_re_core::request_hash;
use mcp_re_core::McpReError;
use serde_json::Value;

const V1: &str = include_str!("../../mcp-re-core/tests/vectors/v1_valid_request.json");
const V2_TAMPERED: &str = include_str!("../../mcp-re-core/tests/vectors/v2_tampered_argument.json");
const REPLAY: &str = include_str!("../../mcp-re-core/tests/vectors/replay_request.json");
const EXPIRED: &str = include_str!("../../mcp-re-core/tests/vectors/expired_request.json");
const WRONG_AUDIENCE: &str =
    include_str!("../../mcp-re-core/tests/vectors/wrong_audience_request.json");
// MCPS-082 (audit M-12): P182 names these two as well; they must agree
// object == stdio == http like the rest, not be object-only.
const TAMPERED_ID: &str = include_str!("../../mcp-re-core/tests/vectors/tampered_id.json");
const MISSING_ENVELOPE: &str =
    include_str!("../../mcp-re-core/tests/vectors/missing_envelope_request.json");

const ISSUED_AT: &str = "2026-05-28T20:00:00Z";

fn locate_server() -> PathBuf {
    mcp_re_test_paths::resolve_runfile("MCP_RE_STDIO_SERVER")
}

fn http() -> HttpHarness {
    HttpHarness::new()
}

fn stdio() -> StdioHarness {
    StdioHarness::new(locate_server())
}

/// `now` 60s after the canonical issued_at — inside the freshness window.
fn now_fresh() -> i64 {
    parse_rfc3339_utc(ISSUED_AT).expect("parse issued_at") + 60
}

fn request_bytes(case: &VectorCase) -> Vec<u8> {
    let message = case.message.as_ref().expect("request vector has a message");
    serde_json::to_vec(message).expect("serialize message")
}

fn case_request_hash(case: &VectorCase) -> String {
    let message = case.message.as_ref().expect("message");
    // A vector with no signed envelope (e.g. missing_envelope_request) has no
    // request hash; it is rejected before any response binding, so the hash is
    // unused in the outcome. Fall back to a placeholder rather than panicking.
    request_hash(message).unwrap_or_else(|_| "sha256:unused".to_string())
}

#[test]
fn valid_request_over_http_verifies_and_binds() {
    let case = parse_case(V1).expect("parse v1");
    let resp = http()
        .roundtrip(&request_bytes(&case), now_fresh())
        .expect("roundtrip");

    let token = outcome_token(&resp, &case_request_hash(&case), &response_resolver());
    assert_eq!(token, "verify_ok", "signed response must verify and bind");

    let value: Value = serde_json::from_slice(&resp).expect("parse response");
    assert_eq!(
        value["result"]["content"][0]["text"].as_str(),
        Some("hello")
    );
}

#[test]
fn tampered_request_over_http_is_rejected() {
    let case = parse_case(V1).expect("parse v1");
    let mut value: Value = serde_json::from_slice(&request_bytes(&case)).expect("parse v1 message");
    value["params"]["arguments"]["text"] = Value::String("goodbye".to_string());
    let tampered = serde_json::to_vec(&value).expect("reserialize tampered");

    let resp = http().roundtrip(&tampered, now_fresh()).expect("roundtrip");
    let token = outcome_token(&resp, "sha256:unused", &response_resolver());
    assert_eq!(token, "mcp-re.invalid_signature");
}

#[test]
fn replayed_request_over_http_is_rejected_on_second_submission() {
    let case = parse_case(V1).expect("parse v1");
    let bytes = request_bytes(&case);
    let responses = http()
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
    assert_eq!(second, "mcp-re.replay_detected", "second submission replayed");
}

#[test]
fn expired_request_over_http_is_rejected() {
    let case = parse_case(EXPIRED).expect("parse expired");
    let now = now_unix_for_case(&case).expect("now for expired");
    let resp = http()
        .roundtrip(&request_bytes(&case), now)
        .expect("roundtrip");
    let token = outcome_token(&resp, "sha256:unused", &response_resolver());
    assert_eq!(token, "mcp-re.expired_request");
}

#[test]
fn wrong_audience_over_http_is_rejected() {
    let case = parse_case(WRONG_AUDIENCE).expect("parse wrong_audience");
    let resp = http()
        .roundtrip(&request_bytes(&case), now_fresh())
        .expect("roundtrip");
    let token = outcome_token(&resp, "sha256:unused", &response_resolver());
    assert_eq!(token, "mcp-re.invalid_audience");
}

#[test]
fn signed_response_bound_to_wrong_request_is_rejected_over_http() {
    let case = parse_case(V1).expect("parse v1");
    let resp = http()
        .roundtrip(&request_bytes(&case), now_fresh())
        .expect("roundtrip");
    let token = outcome_token(
        &resp,
        "sha256:some-other-request-hash",
        &response_resolver(),
    );
    assert_eq!(token, McpReError::ResponseHashMismatch.wire_code());
}

/// Compute one vector's wire token through a transport that exposes `serve`.
fn transport_token(
    serve: impl Fn(&[Vec<u8>], i64) -> Result<Vec<Vec<u8>>, String>,
    case: &VectorCase,
) -> String {
    let now = now_unix_for_case(case).expect("now");
    let bytes = request_bytes(case);
    let expected_hash = case_request_hash(case);
    if case.expected == "mcp-re.replay_detected" {
        let responses = serve(&[bytes.clone(), bytes], now).expect("serve twice");
        outcome_token(&responses[1], &expected_hash, &response_resolver())
    } else {
        let responses = serve(&[bytes], now).expect("serve");
        outcome_token(&responses[0], &expected_hash, &response_resolver())
    }
}

#[test]
fn http_stdio_and_object_agree_for_all_shared_request_vectors() {
    let object = ObjectTarget::new();
    let ctx = RunContext {
        canonical_request_hash: None,
    };
    let http = http();
    let stdio = stdio();

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

        let object_token = object
            .run_case(&case, &ctx)
            .expect("object run_case")
            .as_token()
            .to_string();
        let http_token = transport_token(|r, n| http.serve(r, n), &case);
        let stdio_token = transport_token(|r, n| stdio.serve(r, n), &case);

        assert_eq!(
            http_token, object_token,
            "HTTP must match object for '{}' (object={object_token}, http={http_token})",
            case.name
        );
        assert_eq!(
            stdio_token, object_token,
            "stdio must match object for '{}' (object={object_token}, stdio={stdio_token})",
            case.name
        );
        assert_eq!(
            http_token, stdio_token,
            "HTTP and stdio must be identical for '{}' (http={http_token}, stdio={stdio_token})",
            case.name
        );
    }
}
