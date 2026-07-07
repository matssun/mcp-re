// SPDX-License-Identifier: Apache-2.0
//! HTTP standards-profile conformance corpus (ADR-MCPRE-050, seed Work Item 4).
//!
//! A SEPARATE corpus under `tests/vectors/http-profile/` — the draft-01 and
//! draft-02 corpora stay byte-frozen and untouched (v0.11 grill I.1). Each
//! fixture freezes the COMPLETE signed HTTP message(s) plus, for verifying
//! fixtures, a static oracle: the exact signature-base bytes, the
//! `Content-Digest` value, the Ed25519 signature (deterministic — byte-compare
//! is honest for Ed25519 ONLY), and the split-form `request_evidence` value.
//!
//! Two-sided guard, mirroring the draft-02 corpus:
//!   1. the writer (`write_http_profile_fixtures -- --ignored`) regenerates the
//!      corpus with the project's own implementation (drift guard);
//!   2. the frozen runner verifies every committed fixture black-box and
//!      byte-compares the oracle fields — a third party checks itself against
//!      the frozen bytes, not this project's regenerated opinion (S8/S15).
//!
//! Regenerate: cargo test -p mcp-re-conformance --test http_profile_vectors_test \
//!   write_http_profile_fixtures -- --ignored --exact

use serde::Deserialize;
use serde::Serialize;

use mcp_re_core::SigningKey;
use mcp_re_core::VerificationKey;
use mcp_re_http_profile::sign_request;
use mcp_re_http_profile::sign_response;
use mcp_re_http_profile::verify_request;
use mcp_re_http_profile::verify_response;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;

// Fixed, documented TEST-ONLY seeds; the corpus is deterministic end-to-end.
const CLIENT_SEED: [u8; 32] = [11u8; 32];
const SERVER_SEED: [u8; 32] = [22u8; 32];
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
/// The frozen verification instant every runner uses.
const NOW: i64 = 1_700_000_100;

const CLIENT_KEY_ID: &str = "client-key-1";
const SERVER_KEY_ID: &str = "server-key-1";

// ---------------------------------------------------------------------------
// Fixture schema (`mcp-re-http-profile-conformance/v1`).
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireMessage {
    method: Option<String>,
    target_uri: Option<String>,
    status: Option<u16>,
    headers: Vec<(String, String)>,
    body_utf8: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Oracle {
    /// Exact request signature-base bytes, base64url-no-pad.
    signature_base_b64url: String,
    /// The request `Content-Digest` header value.
    content_digest: String,
    /// The request `Signature` header value (label + byte sequence).
    signature_header: String,
    /// The split-form evidence handle digest value (base64url-no-pad).
    request_evidence_digest_value: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    schema: String,
    name: String,
    /// `request` fixtures verify `request`; `response` fixtures verify
    /// `response` against `request` (the ;req binding source).
    kind: String,
    /// `verify_ok` or the exact frozen `mcp-re.*` wire code observed.
    expected: String,
    request: WireMessage,
    response: Option<WireMessage>,
    oracle: Option<Oracle>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    schema: String,
    verify_at_unix: i64,
    fixtures: Vec<String>,
}

// ---------------------------------------------------------------------------
// Shared material.
// ---------------------------------------------------------------------------

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}

fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&SERVER_SEED)
}

fn resolver() -> impl Fn(&str) -> Option<VerificationKey> {
    move |key_id: &str| match key_id {
        CLIENT_KEY_ID => Some(client_key().public_key()),
        SERVER_KEY_ID => Some(server_key().public_key()),
        _ => None,
    }
}

fn base_request() -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        target_uri: "https://mcp.example.com/mcp".into(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#
            .to_vec(),
    }
}

fn to_wire_request(r: &HttpRequest) -> WireMessage {
    WireMessage {
        method: Some(r.method.clone()),
        target_uri: Some(r.target_uri.clone()),
        status: None,
        headers: r.headers.clone(),
        body_utf8: String::from_utf8(r.body.clone()).expect("test bodies are UTF-8"),
    }
}

fn to_wire_response(r: &HttpResponse) -> WireMessage {
    WireMessage {
        method: None,
        target_uri: None,
        status: Some(r.status),
        headers: r.headers.clone(),
        body_utf8: String::from_utf8(r.body.clone()).expect("test bodies are UTF-8"),
    }
}

fn from_wire_request(w: &WireMessage) -> HttpRequest {
    HttpRequest {
        method: w.method.clone().expect("request fixture has method"),
        target_uri: w.target_uri.clone().expect("request fixture has target_uri"),
        headers: w.headers.clone(),
        body: w.body_utf8.clone().into_bytes(),
    }
}

fn from_wire_response(w: &WireMessage) -> HttpResponse {
    HttpResponse {
        status: w.status.expect("response fixture has status"),
        headers: w.headers.clone(),
        body: w.body_utf8.clone().into_bytes(),
    }
}

/// Locate the committed corpus under BOTH build systems (same dual-mode
/// bridge as the draft-02 corpus; Bazel passes
/// `MCP_RE_HTTP_PROFILE_VECTORS_MANIFEST = $(rlocationpath ...)`).
fn vectors_root() -> std::path::PathBuf {
    if let Ok(rel) = std::env::var("MCP_RE_HTTP_PROFILE_VECTORS_MANIFEST") {
        for key in ["TEST_SRCDIR", "RUNFILES_DIR"] {
            if let Ok(root) = std::env::var(key) {
                let candidate = std::path::Path::new(&root).join(&rel);
                if candidate.exists() {
                    return candidate.parent().expect("manifest has a parent").to_path_buf();
                }
            }
        }
        let candidate = std::path::PathBuf::from(&rel);
        if candidate.exists() {
            return candidate.parent().expect("manifest has a parent").to_path_buf();
        }
        panic!("MCP_RE_HTTP_PROFILE_VECTORS_MANIFEST set but runfile not found (rel={rel})");
    }
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("http-profile")
}

// ---------------------------------------------------------------------------
// Fixture construction (the writer's source of truth).
// ---------------------------------------------------------------------------

fn build_fixtures() -> Vec<Fixture> {
    let mut fixtures = Vec::new();

    // 1. request_valid — with the full static oracle.
    let mut req = base_request();
    let evidence = sign_request(&mut req, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, "vec-nonce-1")
        .expect("signing succeeds");
    let verified = verify_request(&req, &resolver(), NOW).expect("fixture verifies");
    assert_eq!(evidence, verified.evidence, "writer sanity");
    // Reconstruct the exact base the verifier accepted, for the oracle.
    let base = {
        use mcp_re_http_profile::sigbase::signature_base;
        use mcp_re_http_profile::sigbase::SourceMessage;
        use mcp_re_http_profile::CoveredComponent;
        use mcp_re_http_profile::SignatureParams;
        let components: Vec<CoveredComponent> =
            ["@method", "@target-uri", "content-digest", "content-type"]
                .iter()
                .map(|n| CoveredComponent::new(n))
                .collect();
        let params = SignatureParams {
            created: Some(CREATED),
            expires: Some(EXPIRES),
            nonce: Some("vec-nonce-1".into()),
            keyid: Some(CLIENT_KEY_ID.into()),
            alg: Some("ed25519".into()),
            tag: Some("mcp-re-http-v1".into()),
        };
        signature_base(&components, &params, &SourceMessage::Request(&req)).expect("base builds")
    };
    let content_digest = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-digest"))
        .expect("digest header present")
        .1
        .clone();
    let signature_header = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("signature"))
        .expect("signature header present")
        .1
        .clone();
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h01_request_valid".into(),
        kind: "request".into(),
        expected: "verify_ok".into(),
        request: to_wire_request(&req),
        response: None,
        oracle: Some(Oracle {
            signature_base_b64url: mcp_re_core::b64url_encode(&base),
            content_digest,
            signature_header,
            request_evidence_digest_value: evidence.digest_value.clone(),
        }),
    });

    // 2. h02_request_body_tamper — frozen post-tamper message.
    let mut tampered = req.clone();
    tampered.body =
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rm -rf"}}"#.to_vec();
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h02_request_body_tamper".into(),
        kind: "request".into(),
        expected: "mcp-re.invalid_signature".into(),
        request: to_wire_request(&tampered),
        response: None,
        oracle: None,
    });

    // 3. h03_request_missing_covered_component — content-digest stripped from
    //    the covered set after signing.
    let mut stripped = req.clone();
    for h in stripped.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case("signature-input") {
            h.1 = h.1.replace(" \"content-digest\"", "");
        }
    }
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h03_request_missing_covered_component".into(),
        kind: "request".into(),
        expected: "mcp-re.missing_envelope".into(),
        request: to_wire_request(&stripped),
        response: None,
        oracle: None,
    });

    // 4. h04_request_foreign_tag — same evidence under a foreign profile tag.
    let mut foreign = req.clone();
    for h in foreign.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case("signature-input") {
            h.1 = h.1.replace("tag=\"mcp-re-http-v1\"", "tag=\"not-mcp-re\"");
        }
    }
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h04_request_foreign_tag".into(),
        kind: "request".into(),
        expected: "mcp-re.unsupported_version".into(),
        request: to_wire_request(&foreign),
        response: None,
        oracle: None,
    });

    // 5. h05_request_stale_window — expired relative to the frozen NOW.
    let mut stale = base_request();
    sign_request(
        &mut stale,
        &client_key(),
        CLIENT_KEY_ID,
        CREATED - 10_000,
        CREATED - 9_000,
        "vec-nonce-stale",
    )
    .expect("signing succeeds");
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h05_request_stale_window".into(),
        kind: "request".into(),
        expected: "mcp-re.expired_request".into(),
        request: to_wire_request(&stale),
        response: None,
        oracle: None,
    });

    // 6. h06_request_wrong_keyid — untrusted keyid, trust must fail first.
    let mut rogue = base_request();
    sign_request(&mut rogue, &client_key(), "rogue-key-9", CREATED, EXPIRES, "vec-nonce-r")
        .expect("signing succeeds");
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h06_request_wrong_keyid".into(),
        kind: "request".into(),
        expected: "mcp-re.actor_binding_failed".into(),
        request: to_wire_request(&rogue),
        response: None,
        oracle: None,
    });

    // 7. h07_response_valid — full signed exchange.
    let mut rsp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
    };
    sign_response(&mut rsp, &req, &server_key(), SERVER_KEY_ID, CREATED, EXPIRES)
        .expect("response signing succeeds");
    verify_response(&rsp, &req, &resolver(), NOW).expect("fixture verifies");
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h07_response_valid".into(),
        kind: "response".into(),
        expected: "verify_ok".into(),
        request: to_wire_request(&req),
        response: Some(to_wire_response(&rsp)),
        oracle: None,
    });

    // 8. h08_response_splice — a response signed for request B presented as
    //    the answer to request A.
    let mut req_b = base_request();
    req_b.target_uri = "https://mcp.example.com/mcp?route=b".into();
    sign_request(&mut req_b, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, "vec-nonce-2")
        .expect("signing succeeds");
    let mut rsp_b = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
    };
    sign_response(&mut rsp_b, &req_b, &server_key(), SERVER_KEY_ID, CREATED, EXPIRES)
        .expect("response signing succeeds");
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h08_response_splice".into(),
        kind: "response".into(),
        expected: "mcp-re.response_sig_invalid".into(),
        // The splice: request A with B's response.
        request: to_wire_request(&req),
        response: Some(to_wire_response(&rsp_b)),
        oracle: None,
    });

    fixtures
}

// ---------------------------------------------------------------------------
// Writer (regenerates the corpus) — run explicitly with --ignored.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "golden writer: regenerates the committed http-profile corpus"]
fn write_http_profile_fixtures() {
    let root = vectors_root();
    std::fs::create_dir_all(&root).expect("corpus dir");
    let fixtures = build_fixtures();
    let mut names = Vec::new();
    for f in &fixtures {
        let path = root.join(format!("{}.json", f.name));
        std::fs::write(&path, serde_json::to_string_pretty(f).expect("serialize") + "\n")
            .expect("write fixture");
        names.push(format!("{}.json", f.name));
    }
    let manifest = Manifest {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        verify_at_unix: NOW,
        fixtures: names,
    };
    std::fs::write(
        root.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).expect("serialize") + "\n",
    )
    .expect("write manifest");
}

// ---------------------------------------------------------------------------
// Frozen runner: every committed fixture must verify black-box to its
// expected verdict, and oracles must byte-match.
// ---------------------------------------------------------------------------

#[test]
fn frozen_http_profile_corpus_verifies() {
    let root = vectors_root();
    let manifest: Manifest = serde_json::from_slice(
        &std::fs::read(root.join("manifest.json")).expect("committed manifest"),
    )
    .expect("manifest parses");
    assert_eq!(manifest.schema, "mcp-re-http-profile-conformance/v1");
    assert!(!manifest.fixtures.is_empty(), "corpus must not be empty");

    for name in &manifest.fixtures {
        let fixture: Fixture =
            serde_json::from_slice(&std::fs::read(root.join(name)).expect("fixture file"))
                .expect("fixture parses");
        let request = from_wire_request(&fixture.request);
        let observed = match fixture.kind.as_str() {
            "request" => match verify_request(&request, &resolver(), manifest.verify_at_unix) {
                Ok(verified) => {
                    if let Some(oracle) = &fixture.oracle {
                        // Oracle byte-equality (S8: assert bytes, not prints).
                        assert_eq!(
                            verified.evidence.digest_value, oracle.request_evidence_digest_value,
                            "{name}: evidence handle drifted from frozen oracle"
                        );
                        let digest_header = request
                            .headers
                            .iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case("content-digest"))
                            .expect("digest header")
                            .1
                            .clone();
                        assert_eq!(digest_header, oracle.content_digest, "{name}: digest drifted");
                        let sig_header = request
                            .headers
                            .iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case("signature"))
                            .expect("signature header")
                            .1
                            .clone();
                        assert_eq!(sig_header, oracle.signature_header, "{name}: signature drifted");
                    }
                    "verify_ok".to_owned()
                }
                Err(e) => e.wire_code().to_owned(),
            },
            "response" => {
                let response = from_wire_response(fixture.response.as_ref().expect("response"));
                match verify_response(&response, &request, &resolver(), manifest.verify_at_unix) {
                    Ok(()) => "verify_ok".to_owned(),
                    Err(e) => e.wire_code().to_owned(),
                }
            }
            other => panic!("unknown fixture kind {other}"),
        };
        assert_eq!(observed, fixture.expected, "{name}: verdict mismatch");
    }
}

/// Drift guard: regenerating the corpus with the current implementation must
/// reproduce the committed bytes exactly (writer output == frozen files).
#[test]
fn regenerated_fixtures_match_committed_bytes() {
    let root = vectors_root();
    for f in build_fixtures() {
        let committed = std::fs::read_to_string(root.join(format!("{}.json", f.name)))
            .expect("committed fixture");
        let regenerated = serde_json::to_string_pretty(&f).expect("serialize") + "\n";
        assert_eq!(
            regenerated, committed,
            "{}: implementation drifted from the frozen corpus",
            f.name
        );
    }
}
