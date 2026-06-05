//! MCPS-017 — conformance acceptance.
//!
//! Proves the headline guarantees end-to-end:
//!   1. A native MCP-S server and a sidecar-wrapped ORDINARY server produce
//!      identical Core outcomes for the full request-vector matrix, over BOTH
//!      stdio and Streamable HTTP — i.e. native ≡ sidecar across transports.
//!   2. The model holds no private key: requests are signed by a `HostSigner`
//!      (which exposes no key accessor), and the sidecar-wrapped ordinary server
//!      still accepts them and returns a signed, bound response.
//!
//! The stdio server binary is located from `MCPS_STDIO_SERVER`
//! (`$(rlocationpath)`) resolved against the runfiles root.

use std::path::PathBuf;

use mcps_conformance::now_unix_for_case;
use mcps_conformance::outcome_token;
use mcps_conformance::parse_case;
use mcps_conformance::response_resolver;
use mcps_conformance::ConformanceTarget;
use mcps_conformance::HttpHarness;
use mcps_conformance::ObjectTarget;
use mcps_conformance::RunContext;
use mcps_conformance::ServerKind;
use mcps_conformance::StdioHarness;
use mcps_conformance::VectorCase;
use mcps_core::parse_rfc3339_utc;
use mcps_core::request_hash;
use mcps_core::SigningKey;
use mcps_host::HostSigner;
use serde_json::json;
use serde_json::Value;

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

const SIGNER: &str = "did:example:agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";
const AUTH_HASH: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";

fn locate_server() -> PathBuf {
    // Bazel mode: MCPS_STDIO_SERVER is a runfile-relative path injected by the
    // test target; resolve it under TEST_SRCDIR / RUNFILES_DIR.
    if let Ok(rel) = std::env::var("MCPS_STDIO_SERVER") {
        let mut candidates: Vec<PathBuf> = Vec::new();
        for key in ["TEST_SRCDIR", "RUNFILES_DIR"] {
            if let Ok(root) = std::env::var(key) {
                candidates.push(PathBuf::from(root).join(&rel));
            }
        }
        candidates.push(PathBuf::from(&rel));
        for candidate in &candidates {
            if candidate.exists() {
                return candidate.clone();
            }
        }
        panic!("cannot locate stdio server binary (rel='{rel}'); tried: {candidates:?}");
    }
    // Cargo mode: the `mcps-stdio-server` `[[bin]]` is a same-crate target, so
    // CARGO_BIN_EXE_<name> is set automatically when this integration test is
    // compiled.
    PathBuf::from(env!("CARGO_BIN_EXE_mcps-stdio-server"))
}

fn stdio() -> StdioHarness {
    StdioHarness::new(locate_server())
}

fn request_bytes(case: &VectorCase) -> Vec<u8> {
    serde_json::to_vec(case.message.as_ref().expect("message")).expect("serialize")
}

fn case_request_hash(case: &VectorCase) -> String {
    // A vector with no signed envelope (e.g. missing_envelope_request) has no
    // request hash; it is rejected before any response binding, so the hash is
    // unused in the outcome. Fall back to a placeholder rather than panicking.
    request_hash(case.message.as_ref().expect("message"))
        .unwrap_or_else(|_| "sha256:unused".to_string())
}

/// One vector's wire token through a transport+kind exposed as a `serve` closure.
fn transport_token(
    serve: impl Fn(&[Vec<u8>], i64) -> Result<Vec<Vec<u8>>, String>,
    case: &VectorCase,
) -> String {
    let now = now_unix_for_case(case).expect("now");
    let bytes = request_bytes(case);
    let expected_hash = case_request_hash(case);
    if case.expected == "mcps.replay_detected" {
        let responses = serve(&[bytes.clone(), bytes], now).expect("serve twice");
        outcome_token(&responses[1], &expected_hash, &response_resolver())
    } else {
        let responses = serve(&[bytes], now).expect("serve");
        outcome_token(&responses[0], &expected_hash, &response_resolver())
    }
}

#[test]
fn native_and_sidecar_agree_across_both_transports() {
    let object = ObjectTarget::new();
    let ctx = RunContext {
        canonical_request_hash: None,
    };
    let stdio = stdio();
    let http = HttpHarness::new();

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

        // Four target instantiations: {native, sidecar} × {stdio, HTTP}.
        let combos: [(&str, String); 4] = [
            (
                "stdio-native",
                transport_token(|r, n| stdio.serve_kind(r, n, ServerKind::Native), &case),
            ),
            (
                "stdio-sidecar",
                transport_token(
                    |r, n| stdio.serve_kind(r, n, ServerKind::SidecarWrapped),
                    &case,
                ),
            ),
            (
                "http-native",
                transport_token(|r, n| http.serve_kind(r, n, ServerKind::Native), &case),
            ),
            (
                "http-sidecar",
                transport_token(
                    |r, n| http.serve_kind(r, n, ServerKind::SidecarWrapped),
                    &case,
                ),
            ),
        ];

        for (label, token) in combos {
            assert_eq!(
                token, object_token,
                "{label}: vector '{}' must match the object outcome (object={object_token}, got={token})",
                case.name
            );
        }
    }
}

#[test]
fn model_holds_no_key_yet_sidecar_accepts_host_signed_request() {
    // The HostSigner owns the key; "model logic" here only supplies the tool
    // text. There is deliberately no accessor to read the key off the signer.
    let host = HostSigner::new(SigningKey::from_seed_bytes(&[1u8; 32]), SIGNER, SIGNER_KEY_ID);
    let request = host
        .sign_tool_call(
            &Value::String("req-accept".to_string()),
            "echo",
            json!({ "text": "hello from a keyless model" }),
            ON_BEHALF_OF,
            AUDIENCE,
            AUTH_HASH,
            "nonce-acceptance-0001",
            ISSUED_AT,
            EXPIRES_AT,
        )
        .expect("host signs (model never touches the key)");

    let now = parse_rfc3339_utc(ISSUED_AT).expect("parse") + 60;
    let expected_hash = request_hash(&serde_json::from_slice::<Value>(&request).unwrap())
        .expect("request_hash");

    // The sidecar-wrapped ORDINARY server accepts it over stdio and returns a
    // signed response bound to the request.
    let responses = stdio()
        .serve_kind(&[request], now, ServerKind::SidecarWrapped)
        .expect("sidecar serves");
    let token = outcome_token(&responses[0], &expected_hash, &response_resolver());
    assert_eq!(token, "verify_ok", "sidecar accepts the host-signed request");
}
