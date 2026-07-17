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
use mcp_re_http_profile::block::AudienceTuple;
use mcp_re_http_profile::build_signed_rejection;
use mcp_re_http_profile::reconstruct_chain;
use mcp_re_http_profile::sign_accepted_202;
use mcp_re_http_profile::verify_accepted_202;
use mcp_re_http_profile::sign_request;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::sign_response;
use mcp_re_http_profile::sign_response_full;
use mcp_re_http_profile::verify_artifact_binding;
use mcp_re_http_profile::verify_request;
use mcp_re_http_profile::verify_response;
use mcp_re_http_profile::verify_response_bound_full;
use mcp_re_http_profile::verify_signed_rejection;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::ChainLabel;
use mcp_re_http_profile::HttpContinuation;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::IncompleteReason;
use mcp_re_http_profile::RejectionReason;
use mcp_re_http_profile::RequestEvidence;
use mcp_re_http_profile::RequestEvidenceDigest;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::RetainedHop;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifierPolicy;

/// Credentials in artifact fixtures are base64url-no-pad (reusing the core
/// codec so the corpus needs no extra base64 dependency).
fn credential_b64(bytes: &[u8]) -> String {
    mcp_re_core::b64url_encode(bytes)
}

fn base64_std_decode(s: &str) -> Vec<u8> {
    mcp_re_core::b64url_decode(s).expect("fixture credential is base64url")
}

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

/// A frozen artifact-binding check (MCPRE-95). The committed `binding` is the
/// oracle (its `digest_value` is frozen); the runner recomputes the thumbprint
/// from `credential_b64` and checks the verdict. The credential surface (access
/// token / cert DER / canonical RAR details) is standard-base64 here ONLY
/// because a conformance fixture must be self-contained; on the wire it rides in
/// the covered `authorization`/`dpop` header or the mTLS layer, never in
/// evidence — the binding itself carries only the digest.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactCheck {
    binding: serde_json::Value,
    credential_b64: String,
}

/// A frozen MRTR continuation check (MCPRE-97). The committed `continuation`
/// carries the three standards-derived handles; the runner re-presents the
/// three mandated inputs (base64url) and checks the verdict. `request_state`
/// stays opaque but is digest-bound.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContinuationCheck {
    continuation: serde_json::Value,
    previous_request_base_b64: String,
    input_required_response_base_b64: String,
    request_state_b64: String,
}

/// A frozen retained-CHAIN reconstruction check (#416 rev 2 §9/§13, MCPRE-431).
/// Each hop freezes the complete signed request and response; the runner replays
/// them through `reconstruct_chain` and compares the label. `outcomes` classifies
/// each hop's response terminal / input_required — MCP-level semantics the
/// standards profile is deliberately not in the business of reading from a body.
///
/// `expected_label` is `complete`, or `incomplete:<hop>:<reason>` — an incomplete
/// record must name WHICH hop broke it, so the frozen expectation names it too.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainCheck {
    hops: Vec<ChainHop>,
    expected_label: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainHop {
    request: WireMessage,
    response: WireMessage,
}

/// A frozen admission check (#414 §4.3/§5, #415 §7, MCPRE-433). The assertion JWS,
/// the call's binding, and the authoritative admission snapshot are all frozen, so
/// the §7 currency verdict is a deterministic function a third party replays. A
/// `null` authoritative state models the unreachable-authority (degraded) fork.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionCheck {
    assertion_jws: String,
    binding: serde_json::Value,
    /// `[generation, status]` — the PEP's authoritative state, or absent for the
    /// unreachable-authority case.
    authoritative_generation: Option<u64>,
    authoritative_status: Option<String>,
    issuer_public_key_b64url: String,
    allow_degraded_mode: bool,
    degraded_propagation_bound: i64,
}

/// A frozen DELEGATED bodyless-202 check (#424, owner ruling 2026-07-17). Freezes
/// the notification request and the signed 202 (credential in the covered
/// `mcp-re-delegation` header), plus the root key + scope so the delegated
/// verification is deterministic for a third party.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Delegated202Check {
    request: WireMessage,
    response: WireMessage,
    root_public_key_b64url: String,
    root_kid: String,
    verifier_audience: String,
    audience_hash: String,
    epoch: String,
    revoked: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    schema: String,
    name: String,
    /// `request` fixtures verify `request`; `response` fixtures verify
    /// `response` against `request` (the ;req binding source); `artifact`
    /// fixtures verify `artifact_check`; `chain` fixtures reconstruct
    /// `chain_check`.
    kind: String,
    /// `verify_ok` or the exact frozen `mcp-re.*` wire code observed.
    expected: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request: Option<WireMessage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response: Option<WireMessage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    oracle: Option<Oracle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    artifact_check: Option<ArtifactCheck>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    continuation_check: Option<ContinuationCheck>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chain_check: Option<ChainCheck>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    admission_check: Option<AdmissionCheck>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delegated_202_check: Option<Delegated202Check>,
}

/// One manifest entry: the fixture path and the SHA-256 of its exact bytes
/// (#415 rev 2 §12.2).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestEntry {
    file: String,
    /// Lowercase hex SHA-256 over the fixture file's bytes.
    sha256: String,
}

/// The committed corpus index (#415 rev 2 §12.2).
///
/// §12.2: "a tag or branch name alone is insufficient to prove that two reviewers
/// used the same corpus." A filename list is the same problem one level down — it
/// proves which files were MEANT to be there, not what was in them. So every entry
/// carries the SHA-256 of its bytes, and `corpus_digest` commits to the whole set
/// at once.
#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    schema: String,
    verify_at_unix: i64,
    /// SHA-256 over the sorted `path:hash` list — one value that names this exact
    /// corpus. Two reviewers comparing this string are comparing every byte of
    /// every vector, not a tag that can be moved.
    corpus_digest: String,
    fixtures: Vec<ManifestEntry>,
}

/// The §12.2 corpus digest: SHA-256 over the SORTED `<path>:<sha256>\n` list.
///
/// Sorted so the digest is a property of the corpus CONTENT, not of the order the
/// writer happened to emit fixtures in — otherwise reordering the builder would
/// change the published digest while every vector stayed byte-identical, and the
/// digest would be reporting churn instead of drift.
fn corpus_digest(entries: &[ManifestEntry]) -> String {
    let mut lines: Vec<String> = entries
        .iter()
        .map(|e| format!("{}:{}\n", e.file, e.sha256))
        .collect();
    lines.sort();
    hex_sha256(lines.concat().as_bytes())
}

fn hex_sha256(bytes: &[u8]) -> String {
    use sha2::Digest;
    let d = sha2::Sha256::digest(bytes);
    d.iter().map(|b| format!("{b:02x}")).collect()
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

/// Slot-aware trust seam (MCPRE-100): the client key is trusted only for the
/// Request slot, the server key only for the Response slot.
fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    move |key_id: &str, slot: SignerSlot| {
        let (role, key) = match (key_id, slot) {
            (CLIENT_KEY_ID, SignerSlot::Request) => ("client", client_key()),
            (SERVER_KEY_ID, SignerSlot::Response) => ("server", server_key()),
            _ => return None,
        };
        Some(ResolvedActor {
            identity: ActorIdentity {
                role: role.into(),
                trust_domain: "example.com".into(),
                subject: format!("did:example:{role}"),
                keyid: key_id.into(),
            },
            verification_key: key.public_key(),
            slot,
        })
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
        target_uri: w
            .target_uri
            .clone()
            .expect("request fixture has target_uri"),
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
                    return candidate
                        .parent()
                        .expect("manifest has a parent")
                        .to_path_buf();
                }
            }
        }
        let candidate = std::path::PathBuf::from(&rel);
        if candidate.exists() {
            return candidate
                .parent()
                .expect("manifest has a parent")
                .to_path_buf();
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
    let evidence = sign_request(
        &mut req,
        &client_key(),
        CLIENT_KEY_ID,
        CREATED,
        EXPIRES,
        "vec-nonce-1",
    )
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
        request: Some(to_wire_request(&req)),
        response: None,
        oracle: Some(Oracle {
            signature_base_b64url: mcp_re_core::b64url_encode(&base),
            content_digest,
            signature_header,
            request_evidence_digest_value: evidence.digest_value.clone(),
        }),
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
    });

    // 2. h02_request_body_tamper — frozen post-tamper message. The body no
    //    longer matches the signed Content-Digest, so this is a precise digest
    //    mismatch (MCPRE-92), not the old invalid_signature fold.
    let mut tampered = req.clone();
    tampered.body =
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rm -rf"}}"#.to_vec();
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h02_request_body_tamper".into(),
        kind: "request".into(),
        expected: "mcp-re.digest_mismatch".into(),
        request: Some(to_wire_request(&tampered)),
        response: None,
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
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
        request: Some(to_wire_request(&stripped)),
        response: None,
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
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
        request: Some(to_wire_request(&foreign)),
        response: None,
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
    });

    // 4b. h23_request_alg_not_allowlisted — a signature naming an algorithm that
    //     IS in the IANA HTTP Signature Algorithms registry but is NOT in this
    //     verifier's local allowlist (#415 rev 2 §13.1). Registration is not
    //     deployment consent: the allowlist is the agility mechanism, so this is
    //     rejected on POLICY, before any key resolution or crypto — the same
    //     `unsupported_version` a foreign tag earns.
    let mut foreign_alg = req.clone();
    for h in foreign_alg.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case("signature-input") {
            h.1 = h.1.replace("alg=\"ed25519\"", "alg=\"ml-dsa-65\"");
        }
    }
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h23_request_alg_not_allowlisted".into(),
        kind: "request".into(),
        expected: "mcp-re.unsupported_version".into(),
        request: Some(to_wire_request(&foreign_alg)),
        response: None,
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
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
        request: Some(to_wire_request(&stale)),
        response: None,
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
    });

    // 6. h06_request_wrong_keyid — untrusted keyid, trust must fail first.
    let mut rogue = base_request();
    sign_request(
        &mut rogue,
        &client_key(),
        "rogue-key-9",
        CREATED,
        EXPIRES,
        "vec-nonce-r",
    )
    .expect("signing succeeds");
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h06_request_wrong_keyid".into(),
        kind: "request".into(),
        expected: "mcp-re.actor_binding_failed".into(),
        request: Some(to_wire_request(&rogue)),
        response: None,
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
    });

    // 7. h07_response_valid — full signed exchange.
    let mut rsp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
    };
    sign_response(
        &mut rsp,
        &req,
        &server_key(),
        SERVER_KEY_ID,
        CREATED,
        EXPIRES,
    )
    .expect("response signing succeeds");
    verify_response(&rsp, &req, &resolver(), NOW).expect("fixture verifies");
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h07_response_valid".into(),
        kind: "response".into(),
        expected: "verify_ok".into(),
        request: Some(to_wire_request(&req)),
        response: Some(to_wire_response(&rsp)),
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
    });

    // 8. h08_response_splice — a response signed for request B presented as
    //    the answer to request A.
    let mut req_b = base_request();
    req_b.target_uri = "https://mcp.example.com/mcp?route=b".into();
    sign_request(
        &mut req_b,
        &client_key(),
        CLIENT_KEY_ID,
        CREATED,
        EXPIRES,
        "vec-nonce-2",
    )
    .expect("signing succeeds");
    let mut rsp_b = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
    };
    sign_response(
        &mut rsp_b,
        &req_b,
        &server_key(),
        SERVER_KEY_ID,
        CREATED,
        EXPIRES,
    )
    .expect("response signing succeeds");
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h08_response_splice".into(),
        kind: "response".into(),
        expected: "mcp-re.response_sig_invalid".into(),
        // The splice: request A with B's response.
        request: Some(to_wire_request(&req)),
        response: Some(to_wire_response(&rsp_b)),
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
    });

    // ----- artifact-binding fixtures (MCPRE-95) -----
    // The binding carries only a digest; the credential surface is committed
    // alongside ONLY so the fixture is self-contained. Each type has a positive
    // (matching thumbprint) and a negative (a different credential → the
    // artifact_binding_failed code).
    let dpop_token = b"dpop-access-token-abc".to_vec();
    let mtls_cert = b"\x30\x82fake-client-cert-der".to_vec();
    let rar_details = br#"[{"type":"payment_initiation","actions":["initiate"]}]"#.to_vec();

    let artifact_cases: [(&str, ArtifactType, &[u8], bool); 6] = [
        (
            "h09_artifact_dpop_ath_valid",
            ArtifactType::OauthDpop,
            &dpop_token,
            true,
        ),
        (
            "h10_artifact_dpop_ath_mismatch",
            ArtifactType::OauthDpop,
            &dpop_token,
            false,
        ),
        (
            "h11_artifact_mtls_x5t_valid",
            ArtifactType::OauthMtls,
            &mtls_cert,
            true,
        ),
        (
            "h12_artifact_mtls_x5t_mismatch",
            ArtifactType::OauthMtls,
            &mtls_cert,
            false,
        ),
        (
            "h13_artifact_rar_digest_valid",
            ArtifactType::OauthRar,
            &rar_details,
            true,
        ),
        (
            "h14_artifact_rar_digest_mismatch",
            ArtifactType::OauthRar,
            &rar_details,
            false,
        ),
    ];
    for (name, artifact_type, credential, positive) in artifact_cases {
        // The binding always commits to the true credential's thumbprint; the
        // negative presents a DIFFERENT credential at verify time.
        let binding = ArtifactBinding::opaque_digest(artifact_type, credential);
        let presented: Vec<u8> = if positive {
            credential.to_vec()
        } else {
            let mut evil = credential.to_vec();
            evil.extend_from_slice(b"-tampered");
            evil
        };
        fixtures.push(Fixture {
            schema: "mcp-re-http-profile-conformance/v1".into(),
            name: name.into(),
            kind: "artifact".into(),
            expected: if positive {
                "verify_ok".into()
            } else {
                "mcp-re.artifact_binding_failed".into()
            },
            request: None,
            response: None,
            oracle: None,
            artifact_check: Some(ArtifactCheck {
                binding: serde_json::to_value(&binding).expect("binding serializes"),
                credential_b64: credential_b64(&presented),
            }),
            continuation_check: None,
            chain_check: None,
        admission_check: None,
        delegated_202_check: None,
        });
    }

    // ----- MRTR continuation fixtures (MCPRE-97) -----
    // Three standards-derived handles over the mandated inputs. Positive binds
    // its inputs; negatives splice the previous-request base and tamper the
    // opaque requestState — both continuation_binding_failed.
    let prev_base = b"previous-request-signature-base-bytes".to_vec();
    let irr_base = b"input-required-response-signature-base-bytes".to_vec();
    let req_state = b"opaque-request-state-blob".to_vec();
    let continuation = HttpContinuation::build(&prev_base, &irr_base, &req_state);
    let continuation_value = serde_json::to_value(&continuation).expect("continuation serializes");

    // h15 — valid: the client re-presents the exact mandated inputs.
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h15_continuation_valid".into(),
        kind: "continuation".into(),
        expected: "verify_ok".into(),
        request: None,
        response: None,
        oracle: None,
        artifact_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
        continuation_check: Some(ContinuationCheck {
            continuation: continuation_value.clone(),
            previous_request_base_b64: credential_b64(&prev_base),
            input_required_response_base_b64: credential_b64(&irr_base),
            request_state_b64: credential_b64(&req_state),
        }),
    });

    // h16 — splice: a different previous-request base is presented.
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h16_continuation_splice".into(),
        kind: "continuation".into(),
        expected: "mcp-re.continuation_binding_failed".into(),
        request: None,
        response: None,
        oracle: None,
        artifact_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
        continuation_check: Some(ContinuationCheck {
            continuation: continuation_value.clone(),
            previous_request_base_b64: credential_b64(b"a-different-previous-request-base"),
            input_required_response_base_b64: credential_b64(&irr_base),
            request_state_b64: credential_b64(&req_state),
        }),
    });

    // h17 — tampered opaque requestState.
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h17_continuation_request_state_tamper".into(),
        kind: "continuation".into(),
        expected: "mcp-re.continuation_binding_failed".into(),
        request: None,
        response: None,
        oracle: None,
        artifact_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
        continuation_check: Some(ContinuationCheck {
            continuation: continuation_value,
            previous_request_base_b64: credential_b64(&prev_base),
            input_required_response_base_b64: credential_b64(&irr_base),
            request_state_b64: credential_b64(b"opaque-request-state-blob-TAMPERED"),
        }),
    });

    // ----- bodyless / signed-202 fixtures (#415 rev 2 §3.4/§8.1, MCPRE-424) -----
    // The 202 acknowledges a signed one-way notification POST. Its `;req` binding
    // is the ONLY binding it has (no body ⇒ no restated request_evidence), so the
    // negatives below target exactly that and the named-set boundaries.
    let mut note = HttpRequest {
        method: "POST".into(),
        target_uri: "https://mcp.example.com/mcp".into(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_vec(),
    };
    sign_request(&mut note, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, "vec-nonce-note")
        .expect("a notification signs like any request");
    let ack = sign_accepted_202(&note, &server_key(), SERVER_KEY_ID, CREATED, EXPIRES)
        .expect("the PEP signs its acceptance");

    // h34 — positive: a signed 202 bound to its notification.
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h34_bodyless_202_valid".into(),
        kind: "bodyless_202".into(),
        expected: "verify_ok".into(),
        request: Some(to_wire_request(&note)),
        response: Some(to_wire_response(&ack)),
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
    });

    // h35 — content-type present when the named set says it must be absent.
    let mut ack_ct = ack.clone();
    ack_ct.headers.push(("Content-Type".into(), "application/json".into()));
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h35_bodyless_202_content_type_present".into(),
        kind: "bodyless_202".into(),
        expected: "mcp-re.malformed_envelope".into(),
        request: Some(to_wire_request(&note)),
        response: Some(to_wire_response(&ack_ct)),
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
    });

    // h36 — content injected into a message whose digest commits to empty content.
    let mut ack_body = ack.clone();
    ack_body.body = br#"{"cancelled":true}"#.to_vec();
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h36_bodyless_202_content_injected".into(),
        kind: "bodyless_202".into(),
        expected: "mcp-re.malformed_envelope".into(),
        request: Some(to_wire_request(&note)),
        response: Some(to_wire_response(&ack_body)),
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
    });

    // h37 — the splice: A's acknowledgement presented against notification B.
    let mut note_b = HttpRequest {
        method: "POST".into(),
        target_uri: "https://mcp.example.com/mcp".into(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","method":"notifications/cancelled"}"#.to_vec(),
    };
    sign_request(&mut note_b, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, "vec-nonce-note-b")
        .expect("signing succeeds");
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h37_bodyless_202_splice".into(),
        kind: "bodyless_202".into(),
        expected: "mcp-re.response_sig_invalid".into(),
        request: Some(to_wire_request(&note_b)),
        response: Some(to_wire_response(&ack)),
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
    });

    // ----- MCP transport-header fixtures (#415 rev 2 §4.1, MCPRE-425) -----
    // h31 covered-and-matching positive; h32 present-but-uncovered negative;
    // h33 header/body method mismatch negative.
    let mcp_headers = |method_header: &str| -> HttpRequest {
        let mut r = HttpRequest {
            method: "POST".into(),
            target_uri: "https://mcp.example.com/mcp".into(),
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
                ("Mcp-Method".into(), method_header.into()),
                ("Mcp-Name".into(), "read".into()),
            ],
            body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#
                .to_vec(),
        };
        sign_request(&mut r, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, "vec-nonce-mcp")
            .expect("signing succeeds");
        r
    };

    let mcp_ok = mcp_headers("tools/call");
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h31_mcp_headers_covered_valid".into(),
        kind: "request".into(),
        expected: "verify_ok".into(),
        request: Some(to_wire_request(&mcp_ok)),
        response: None,
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
    });

    // h32 — the header rides on the wire but was dropped from the covered set:
    //       an unsigned method claim attached to a signed request.
    let mut mcp_uncovered = mcp_ok.clone();
    for h in mcp_uncovered.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case("signature-input") {
            h.1 = h.1.replace(" \"mcp-method\"", "");
        }
    }
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h32_mcp_method_present_but_uncovered".into(),
        kind: "request".into(),
        expected: "mcp-re.missing_envelope".into(),
        request: Some(to_wire_request(&mcp_uncovered)),
        response: None,
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
    });

    // h33 — the covered header says tools/list, the covered body says tools/call.
    //       The signature is VALID: this is the signer stating two different
    //       methods, and the verifier refuses rather than picking one.
    let mcp_diverged = mcp_headers("tools/list");
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h33_mcp_method_body_divergence".into(),
        kind: "request".into(),
        expected: "mcp-re.malformed_envelope".into(),
        request: Some(to_wire_request(&mcp_diverged)),
        response: None,
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
    });

    // ----- MCP transport CONTRACT fixtures (#415 rev 2 §4.1, MCPRE-425) -----
    // h31-h33 above check header integrity under the default policy. These check
    // the full §4.1 contract — required-header presence, supported-version policy,
    // and header/body agreement — under a strict 2026-07-28 transport policy. The
    // runner replays them with that policy attached.
    let tx_body =
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#.to_vec();
    let tx_sign = |headers: Vec<(&str, &str)>, body: &[u8], nonce: &str| -> HttpRequest {
        let mut hs: Vec<(String, String)> =
            vec![("Content-Type".into(), "application/json".into())];
        for (k, v) in headers {
            hs.push((k.into(), v.into()));
        }
        let mut r = HttpRequest {
            method: "POST".into(),
            target_uri: "https://mcp.example.com/mcp".into(),
            headers: hs,
            body: body.to_vec(),
        };
        sign_request(&mut r, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, nonce)
            .expect("signing succeeds");
        r
    };

    // h38 — fully conforming under the strict contract.
    let tx_ok = tx_sign(
        vec![
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", "read"),
            ("MCP-Protocol-Version", "2026-07-28"),
        ],
        &tx_body,
        "vec-nonce-tx-ok",
    );
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h38_transport_contract_valid".into(),
        kind: "transport_request".into(),
        expected: "verify_ok".into(),
        request: Some(to_wire_request(&tx_ok)),
        response: None,
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
    });

    // h39 — a required header absent (no Mcp-Method) under the strict contract.
    let tx_missing = tx_sign(
        vec![("MCP-Protocol-Version", "2026-07-28")],
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
        "vec-nonce-tx-miss",
    );
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h39_transport_required_header_absent".into(),
        kind: "transport_request".into(),
        expected: "mcp-re.missing_envelope".into(),
        request: Some(to_wire_request(&tx_missing)),
        response: None,
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
    });

    // h40 — an unsupported protocol version (a client's claim is not consent).
    let tx_badver = tx_sign(
        vec![("Mcp-Method", "initialize"), ("MCP-Protocol-Version", "1999-01-01")],
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
        "vec-nonce-tx-ver",
    );
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h40_transport_unsupported_version".into(),
        kind: "transport_request".into(),
        expected: "mcp-re.unsupported_version".into(),
        request: Some(to_wire_request(&tx_badver)),
        response: None,
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
    });

    // h41 — Mcp-Name disagreeing with params.name (the routing header naming a
    //       different tool than the signed body invokes).
    let tx_name = tx_sign(
        vec![
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", "delete"),
            ("MCP-Protocol-Version", "2026-07-28"),
        ],
        &tx_body,
        "vec-nonce-tx-name",
    );
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h41_transport_mcp_name_divergence".into(),
        kind: "transport_request".into(),
        expected: "mcp-re.malformed_envelope".into(),
        request: Some(to_wire_request(&tx_name)),
        response: None,
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
    });

    // ----- delegated bodyless-202 fixtures (#424, owner ruling 2026-07-17) -----
    fixtures.extend(delegated_202_fixtures());

    // ----- admission fixtures (#414 §4.3/§5, #415 §7, MCPRE-433) -----
    // Each freezes the assertion JWS, the call's binding, and the authoritative
    // snapshot, so the §7 currency verdict is deterministic. The load-bearing one
    // (h43) freezes a signed, fresh, "admitted" assertion that is STILL refused
    // because the authoritative generation moved on — a snapshot is not currency.
    fixtures.extend(admission_fixtures());

    // h30 — SSE response on a covered exchange (#415 rev 2 §3.4, MCPRE-423).
    //       The server GENUINELY signs it: the signature is valid and the digest
    //       matches its body. It is rejected purely because a covered exchange is
    //       JSON-mode only — per-event SSE evidence is deferred to a future
    //       companion profile, so a stream here would be signed as a whole while
    //       every event inside went unattested.
    let mut sse_rsp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "text/event-stream".into())],
        body: b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n"
            .to_vec(),
    };
    sign_response(
        &mut sse_rsp,
        &req,
        &server_key(),
        SERVER_KEY_ID,
        CREATED,
        EXPIRES,
    )
    .expect("the server really does sign the stream");
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h30_response_sse_on_covered_exchange".into(),
        kind: "response".into(),
        expected: "mcp-re.serialization_failed".into(),
        request: Some(to_wire_request(&req)),
        response: Some(to_wire_response(&sse_rsp)),
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
    });

    // ----- retained-chain fixtures (#416 rev 2 §9/§13, MCPRE-430/431) -----
    // The continuation fixtures above check ONE handle set in isolation. These
    // check what §9 actually requires: that a whole chain re-links. Each freezes
    // complete signed messages per hop, so a third party replays real evidence
    // rather than this project's opinion of a handle.
    fixtures.extend(chain_fixtures());

    // ----- signed-rejection fixtures (MCPRE-96) -----
    // A rejection is a signed response carrying error.data.mcp_re_error.wire_code.
    // `req` (from h01) is a fully signed request the server binds via ;req.
    let reject_reason = RejectionReason {
        wire_code: "mcp-re.invalid_audience",
        message: "audience did not match this verifier (human text — do not trust)".into(),
    };

    // h18 — bound valid: the trusted wire code surfaces after the signature.
    let bound = build_signed_rejection(
        Some(&req),
        &reject_reason,
        403,
        &server_key(),
        SERVER_KEY_ID,
        CREATED,
        EXPIRES,
    )
    .expect("bound rejection builds");
    verify_signed_rejection(&bound, Some(&req), &resolver(), NOW)
        .expect("bound rejection verifies");
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h18_rejection_bound_valid".into(),
        kind: "rejection".into(),
        expected: "mcp-re.invalid_audience".into(),
        request: Some(to_wire_request(&req)),
        response: Some(to_wire_response(&bound)),
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
    });

    // h19 — unbound valid: no request context, signed response-only.
    let unbound = build_signed_rejection(
        None,
        &reject_reason,
        400,
        &server_key(),
        SERVER_KEY_ID,
        CREATED,
        EXPIRES,
    )
    .expect("unbound rejection builds");
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h19_rejection_unbound_valid".into(),
        kind: "rejection".into(),
        expected: "mcp-re.invalid_audience".into(),
        request: None,
        response: Some(to_wire_response(&unbound)),
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
    });

    // h20 — body tamper: an edited human message breaks Content-Digest.
    let mut tampered_rej = bound.clone();
    tampered_rej.body =
        br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32003,"message":"LIES","data":{"mcp_re_error":{"wire_code":"mcp-re.expired_request"}}}}"#
            .to_vec();
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h20_rejection_body_tamper".into(),
        kind: "rejection".into(),
        expected: "mcp-re.digest_mismatch".into(),
        request: Some(to_wire_request(&req)),
        response: Some(to_wire_response(&tampered_rej)),
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
    });

    // h21 — splice: a rejection bound to `req` presented against a different
    // request fails the ;req-covered signature.
    let mut other_req = base_request();
    other_req.target_uri = "https://mcp.example.com/mcp?route=other".into();
    sign_request(
        &mut other_req,
        &client_key(),
        CLIENT_KEY_ID,
        CREATED,
        EXPIRES,
        "vec-nonce-o",
    )
    .expect("signing succeeds");
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h21_rejection_splice".into(),
        kind: "rejection".into(),
        expected: "mcp-re.response_sig_invalid".into(),
        request: Some(to_wire_request(&other_req)),
        response: Some(to_wire_response(&bound)),
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
    });

    // h22 — unsigned: a bare JSON-RPC error with no signature is untrusted.
    let unsigned = HttpResponse {
        status: 403,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: bound.body.clone(),
    };
    fixtures.push(Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: "h22_rejection_unsigned".into(),
        kind: "rejection".into(),
        expected: "mcp-re.missing_envelope".into(),
        request: Some(to_wire_request(&req)),
        response: Some(to_wire_response(&unsigned)),
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: None,
    });

    fixtures
}

// ---------------------------------------------------------------------------
// Retained-chain fixtures (#416 rev 2 §9/§13).
// ---------------------------------------------------------------------------

/// Third-party KATs committed in this corpus but NOT generated by the writer.
/// Pinned by hash like every other file; replayed by their own harnesses
/// (`rfc9421_cross_verification_test`, `full_profile_parity_test`), not by the
/// fixture runner, because they are not `Fixture`-shaped.
const EXTERNAL_KATS: [&str; 1] = ["external_kat.json"];

const CHAIN_TARGET: &str = "https://mcp.example.com/mcp";
const AWAITING: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required"}}"#;
const DONE: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;

fn chain_audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: "mcp.example.com".into(),
        target_uri: CHAIN_TARGET.into(),
        route: Some("tools/call".into()),
    }
}

fn chain_server_signer() -> ActorIdentity {
    ActorIdentity {
        role: "server".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:server".into(),
        keyid: SERVER_KEY_ID.into(),
    }
}

fn chain_block(continuation: Option<HttpContinuation>) -> HttpRequestEvidenceBlock {
    HttpRequestEvidenceBlock {
        profile: mcp_re_http_profile::PROFILE_TAG.into(),
        audience: chain_audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(ArtifactType::OauthDpop, b"tok")],
        continuation,
        admission: None,
    }
}

fn to_digest(e: &RequestEvidence) -> RequestEvidenceDigest {
    RequestEvidenceDigest {
        digest_alg: e.digest_alg.clone(),
        digest_value: e.digest_value.clone(),
    }
}

/// Sign one hop and return it with the two role-labeled handles the next hop's
/// continuation must name.
fn chain_hop(
    nonce: &str,
    continuation: Option<HttpContinuation>,
    body: &str,
) -> (RetainedHop, RequestEvidence, RequestEvidence) {
    let mut request = HttpRequest {
        method: "POST".into(),
        target_uri: CHAIN_TARGET.into(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#.to_vec(),
    };
    let req_evidence = sign_request_full(
        &mut request,
        &chain_block(continuation),
        &client_key(),
        CLIENT_KEY_ID,
        CREATED,
        EXPIRES,
        nonce,
    )
    .expect("request signs");
    let mut response = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: body.as_bytes().to_vec(),
    };
    sign_response_full(
        &mut response,
        &request,
        &req_evidence,
        &chain_server_signer(),
        &server_key(),
        SERVER_KEY_ID,
        CREATED,
        EXPIRES,
    )
    .expect("response signs");
    let rsp_evidence =
        verify_response_bound_full(&response, &request, &req_evidence, &resolver(), NOW)
            .expect("response verifies")
            .response_signature_base_digest;
    (RetainedHop { request, response }, req_evidence, rsp_evidence)
}

fn to_chain_hop(h: &RetainedHop) -> ChainHop {
    ChainHop {
        request: to_wire_request(&h.request),
        response: to_wire_response(&h.response),
    }
}

fn chain_fixture(name: &str, hops: &[RetainedHop], label: &str) -> Fixture {
    Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: name.into(),
        kind: "chain".into(),
        expected: "verify_ok".into(),
        request: None,
        response: None,
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: Some(ChainCheck {
            hops: hops.iter().map(to_chain_hop).collect(),
            expected_label: label.into(),
        }),
        admission_check: None,
        delegated_202_check: None,
    }
}

/// The full three-hop chain R0→S0→R1→S1→R2→S2 the chain fixtures are cut from.
fn three_hop() -> Vec<RetainedHop> {
    let (h0, r0, s0) = chain_hop("chain-n0", None, AWAITING);
    let (h1, r1, s1) = chain_hop(
        "chain-n1",
        Some(HttpContinuation::from_handles(
            to_digest(&r0),
            to_digest(&s0),
            b"state-0",
        )),
        AWAITING,
    );
    let (h2, _, _) = chain_hop(
        "chain-n2",
        Some(HttpContinuation::from_handles(
            to_digest(&r1),
            to_digest(&s1),
            b"state-1",
        )),
        DONE,
    );
    vec![h0, h1, h2]
}

fn chain_fixtures() -> Vec<Fixture> {
    let full = three_hop();
    let mut out = Vec::new();

    // h24 — multi-hop positive (§13.4 "multi-hop" claim): two consecutive
    // non-terminal turns followed by a terminal one, every hop re-linking.
    out.push(chain_fixture(
        "h24_chain_multi_hop_complete",
        &full,
        
        "complete",
    ));

    // h25 — the missing MIDDLE hop (§9.1/§9.3). Every retained message verifies
    // on its own and S2 is a genuine terminal result; the record is still
    // incomplete, and says so naming hop 1. This is the case §9 exists for.
    out.push(chain_fixture(
        "h25_chain_missing_middle_hop_incomplete",
        &[full[0].clone(), full[2].clone()],
        "incomplete:1:continuation_does_not_link",
    ));

    // h26 — truncated chain (§13.2): the record stops on a turn still awaiting
    // input. Every hop verifies; the call has no ending.
    out.push(chain_fixture(
        "h26_chain_truncated_incomplete",
        &[full[0].clone(), full[1].clone()],
        "incomplete:1:terminal_expected",
    ));

    // h27 — a continuation naming ANOTHER chain's evidence (§13.2 "response from
    // another chain"): well-formed handles that do not describe this record.
    let (o0, _, _) = chain_hop("chain-other0", None, AWAITING);
    let (_, other_r, other_s) = chain_hop("chain-other-src", None, AWAITING);
    let (o1, _, _) = chain_hop(
        "chain-other1",
        Some(HttpContinuation::from_handles(
            to_digest(&other_r),
            to_digest(&other_s),
            b"state-o",
        )),
        DONE,
    );
    out.push(chain_fixture(
        "h27_chain_foreign_continuation_incomplete",
        &[o0, o1],
        "incomplete:1:continuation_does_not_link",
    ));

    // h28 — role substitution (§7.3): the previous RESPONSE handle presented as
    // the previous-REQUEST handle and vice versa. Domain separation makes the
    // lifted handles different values in the wrong role, so re-linking rejects.
    let (s0h, sr0, ss0) = chain_hop("chain-swap0", None, AWAITING);
    let (s1h, _, _) = chain_hop(
        "chain-swap1",
        Some(HttpContinuation::from_handles(
            to_digest(&ss0),
            to_digest(&sr0),
            b"state-s",
        )),
        DONE,
    );
    out.push(chain_fixture(
        "h28_chain_role_swapped_handles_incomplete",
        &[s0h, s1h],
        "incomplete:1:continuation_does_not_link",
    ));

    // h29 — terminal spliced onto a continuation request (§13.2): the chain
    // claims to continue past a turn that already answered terminally.
    let (t0, tr0, ts0) = chain_hop("chain-term0", None, DONE);
    let (t1, _, _) = chain_hop(
        "chain-term1",
        Some(HttpContinuation::from_handles(
            to_digest(&tr0),
            to_digest(&ts0),
            b"state-t",
        )),
        DONE,
    );
    out.push(chain_fixture(
        "h29_chain_terminal_spliced_incomplete",
        &[t0, t1],
        "incomplete:0:non_terminal_expected",
    ));

    out
}

/// The runner's label encoding, mirroring `expected_label` in the fixture.
fn label_token(label: &ChainLabel) -> String {
    match label {
        ChainLabel::Complete => "complete".to_owned(),
        ChainLabel::Incomplete { hop, reason } => {
            let r = match reason {
                IncompleteReason::RequestUnverifiable(_) => "request_unverifiable",
                IncompleteReason::ResponseUnverifiable(_) => "response_unverifiable",
                IncompleteReason::MissingContinuation => "missing_continuation",
                IncompleteReason::ContinuationDoesNotLink => "continuation_does_not_link",
                IncompleteReason::NonTerminalExpected => "non_terminal_expected",
                IncompleteReason::TerminalExpected => "terminal_expected",
                IncompleteReason::EmptyChain => "empty_chain",
            };
            format!("incomplete:{hop}:{r}")
        }
    }
}

// ---------------------------------------------------------------------------
// Delegated bodyless-202 fixtures (#424).
// ---------------------------------------------------------------------------

const D202_ROOT_KID: &str = "root-kid";
const D202_DELEGATED_KID: &str = "delegated-kid-1";
const D202_AUD: &str = "verifier-1";
const D202_AUD_HASH: &str = "aud-scope-1";
const D202_EPOCH: &str = "epoch-1";

fn d202_root() -> SigningKey {
    SigningKey::from_seed_bytes(&[33u8; 32])
}
fn d202_delegated() -> SigningKey {
    SigningKey::from_seed_bytes(&[55u8; 32])
}

fn d202_credential() -> String {
    let d = d202_delegated();
    let header = mcp_re_http_profile::DelegationHeader {
        typ: mcp_re_http_profile::DELEGATION_TYP.into(),
        alg: mcp_re_http_profile::DELEGATION_ALG.into(),
        kid: D202_ROOT_KID.into(),
    };
    let server_signer = ActorIdentity {
        role: "server".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:server".into(),
        keyid: D202_DELEGATED_KID.into(),
    };
    let claims = mcp_re_http_profile::DelegationClaims {
        iss: "did:example:server".into(),
        iat: CREATED,
        nbf: CREATED,
        exp: EXPIRES,
        jti: "evt-202".into(),
        aud: mcp_re_http_profile::Audience::One(D202_AUD.into()),
        mcp_re_profile: mcp_re_http_profile::PROFILE_TAG.into(),
        mcp_re_audience_hash: D202_AUD_HASH.into(),
        mcp_re_server_signer: server_signer.actor_id(),
        mcp_re_key_use: mcp_re_http_profile::KEY_USE_RESPONSE_SIGNING.into(),
        delegated_kid: D202_DELEGATED_KID.into(),
        issuer_kid: D202_ROOT_KID.into(),
        trust_epoch: D202_EPOCH.into(),
        cnf: mcp_re_http_profile::Cnf {
            jwk: mcp_re_http_profile::DelegatedJwk {
                kty: mcp_re_http_profile::JWK_KTY_OKP.into(),
                crv: mcp_re_http_profile::JWK_CRV_ED25519.into(),
                kid: D202_DELEGATED_KID.into(),
                x: d.public_key().to_b64url(),
            },
        },
    };
    mcp_re_http_profile::issue_delegation_credential(&d202_root(), &header, &claims)
}

fn d202_notification() -> HttpRequest {
    let mut r = HttpRequest {
        method: "POST".into(),
        target_uri: "https://mcp.example.com/mcp".into(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_vec(),
    };
    sign_request(&mut r, &client_key(), CLIENT_KEY_ID, CREATED, EXPIRES, "vec-nonce-d202")
        .expect("notification signs");
    r
}

fn d202_check(response: &HttpResponse, note: &HttpRequest, revoked: bool) -> Delegated202Check {
    Delegated202Check {
        request: to_wire_request(note),
        response: to_wire_response(response),
        root_public_key_b64url: d202_root().public_key().to_b64url(),
        root_kid: D202_ROOT_KID.into(),
        verifier_audience: D202_AUD.into(),
        audience_hash: D202_AUD_HASH.into(),
        epoch: D202_EPOCH.into(),
        revoked,
    }
}

fn d202_fixture(name: &str, check: Delegated202Check, expected: &str) -> Fixture {
    Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: name.into(),
        kind: "delegated_202".into(),
        expected: expected.into(),
        request: None,
        response: None,
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: None,
        delegated_202_check: Some(check),
    }
}

fn delegated_202_fixtures() -> Vec<Fixture> {
    let note = d202_notification();
    let ack = mcp_re_http_profile::sign_delegated_accepted_202(
        &note,
        &d202_credential(),
        &d202_delegated(),
        D202_DELEGATED_KID,
        CREATED,
        EXPIRES,
    )
    .expect("PEP delegated-signs the 202");

    let mut out = Vec::new();
    // h47 — positive: a delegated 202 verifying via the credential→root chain.
    out.push(d202_fixture(
        "h47_delegated_202_valid",
        d202_check(&ack, &note, false),
        "verify_ok",
    ));

    // h48 — the credential header stripped from the COVERED set (still on the
    //       wire). An uncovered credential is unprotected — the load-bearing
    //       negative for the whole design.
    let mut uncovered = ack.clone();
    for h in uncovered.headers.iter_mut() {
        if h.0.eq_ignore_ascii_case("signature-input") {
            h.1 = h.1.replace(" \"mcp-re-delegation\"", "");
        }
    }
    out.push(d202_fixture(
        "h48_delegated_202_credential_uncovered",
        d202_check(&uncovered, &note, false),
        "mcp-re.missing_envelope",
    ));

    // h49 — revoked delegated key: the revocation seam is live.
    out.push(d202_fixture(
        "h49_delegated_202_revoked",
        d202_check(&ack, &note, true),
        "mcp-re.delegation_revoked",
    ));

    out
}

// ---------------------------------------------------------------------------
// Admission fixtures (#414 §4.3/§5, #415 §7).
// ---------------------------------------------------------------------------

const ADMISSION_ISSUER_KID: &str = "admission-root-1";

fn admission_root() -> SigningKey {
    SigningKey::from_seed_bytes(&[44u8; 32])
}

fn admission_claims(generation: u64, status: mcp_re_http_profile::AdmissionStatus) -> mcp_re_http_profile::AdmissionClaims {
    use sha2::Digest;
    mcp_re_http_profile::AdmissionClaims {
        iss: "did:example:admission".into(),
        iat: NOW - 10,
        nbf: NOW - 10,
        exp: NOW + 300,
        jti: format!("adm#{generation}"),
        aud: mcp_re_http_profile::Audience::One("mcp.example.com".into()),
        mcp_re_profile: mcp_re_http_profile::PROFILE_TAG.into(),
        mcp_re_admission_id: "workload-7".into(),
        mcp_re_admission_generation: generation,
        mcp_re_admitted_state_digest: mcp_re_core::b64url_encode(&sha2::Sha256::digest(b"admitted-state")),
        mcp_re_admission_status: status,
        issuer_kid: ADMISSION_ISSUER_KID.into(),
    }
}

fn admission_fixture(
    name: &str,
    claims: &mcp_re_http_profile::AdmissionClaims,
    authoritative: Option<(u64, &str)>,
    degraded: Option<i64>,
    expected: &str,
) -> Fixture {
    let jws = mcp_re_http_profile::issue_admission_assertion(claims, |input| {
        mcp_re_core::b64url_decode(&admission_root().sign(input))
            .map_err(|_| mcp_re_http_profile::HttpProfileError::InvalidSignature)
    })
    .expect("issue");
    let binding = mcp_re_http_profile::AdmissionBinding::opaque_from(claims);
    Fixture {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        name: name.into(),
        kind: "admission".into(),
        expected: expected.into(),
        request: None,
        response: None,
        oracle: None,
        artifact_check: None,
        continuation_check: None,
        chain_check: None,
        admission_check: Some(AdmissionCheck {
            assertion_jws: jws,
            binding: serde_json::to_value(&binding).expect("binding serializes"),
            authoritative_generation: authoritative.map(|(g, _)| g),
            authoritative_status: authoritative.map(|(_, s)| s.to_owned()),
            issuer_public_key_b64url: admission_root().public_key().to_b64url(),
            allow_degraded_mode: degraded.is_some(),
            degraded_propagation_bound: degraded.unwrap_or(0),
        }),
        delegated_202_check: None,
    }
}

fn admission_fixtures() -> Vec<Fixture> {
    use mcp_re_http_profile::AdmissionStatus::*;
    vec![
        // h42 — current admitted workload: served.
        admission_fixture("h42_admission_current_admitted", &admission_claims(5, Admitted), Some((5, "admitted")), None, "verify_ok"),
        // h43 — the load-bearing case: a valid, fresh, admitted assertion refused
        //       because the authoritative generation advanced. A snapshot is not currency.
        admission_fixture("h43_admission_stale_generation", &admission_claims(5, Admitted), Some((6, "admitted")), None, "mcp-re.actor_binding_failed"),
        // h44 — revoked after issuance.
        admission_fixture("h44_admission_revoked_after_issuance", &admission_claims(5, Admitted), Some((5, "revoked")), None, "mcp-re.actor_binding_failed"),
        // h45 — authoritative state unreachable, degraded disabled: fail closed.
        admission_fixture("h45_admission_state_unreachable_failclosed", &admission_claims(5, Admitted), None, None, "mcp-re.actor_binding_failed"),
        // h46 — unreachable state within the P bound with degraded enabled: served.
        admission_fixture("h46_admission_degraded_within_bound", &admission_claims(5, Admitted), None, Some(600), "verify_ok"),
    ]
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
    let mut entries = Vec::new();
    for f in &fixtures {
        let file = format!("{}.json", f.name);
        let bytes = serde_json::to_string_pretty(f).expect("serialize") + "\n";
        std::fs::write(root.join(&file), &bytes).expect("write fixture");
        // Hash the bytes actually written — the artifact a third party will read,
        // not the in-memory struct they cannot see.
        entries.push(ManifestEntry {
            sha256: hex_sha256(bytes.as_bytes()),
            file,
        });
    }
    // Pin the external KAT too (#415 rev 2 §12.2 names external KATs explicitly).
    // It is NOT generated here — it is a third-party artifact, a signature produced
    // by python-cryptography independently of ed25519-dalek — which is exactly why
    // it must be pinned: it is the anchor of the cross-verification claim, and if
    // it drifted, that claim would silently change meaning while still passing. The
    // writer hashes it in place and never rewrites it.
    for external in EXTERNAL_KATS {
        let bytes = std::fs::read(root.join(external))
            .unwrap_or_else(|_| panic!("{external}: external KAT must be committed"));
        entries.push(ManifestEntry {
            file: (*external).to_owned(),
            sha256: hex_sha256(&bytes),
        });
    }

    let manifest = Manifest {
        schema: "mcp-re-http-profile-conformance/v1".into(),
        verify_at_unix: NOW,
        corpus_digest: corpus_digest(&entries),
        fixtures: entries,
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

    // §12.2 content pin: the corpus digest must commit to the manifest's own
    // entries. A tampered entry (or an entry added/removed) breaks this before any
    // vector runs — the digest is checked first precisely so a corpus cannot be
    // edited into agreeing with itself.
    assert_eq!(
        corpus_digest(&manifest.fixtures),
        manifest.corpus_digest,
        "corpus digest does not commit to the manifest entries"
    );

    for entry in &manifest.fixtures {
        let name = &entry.file;
        let bytes = std::fs::read(root.join(name)).expect("fixture file");
        // Fail closed BEFORE running: a vector whose bytes do not match the
        // manifest is not a vector, it is an unknown file with a familiar name.
        // Running it would report a verdict about something nobody pinned.
        assert_eq!(
            hex_sha256(&bytes),
            entry.sha256,
            "{name}: fixture bytes do not match the manifest SHA-256"
        );
        // An external KAT is pinned by hash but replayed by its own harness.
        if EXTERNAL_KATS.contains(&name.as_str()) {
            continue;
        }
        let fixture: Fixture = serde_json::from_slice(&bytes).expect("fixture parses");
        let observed = match fixture.kind.as_str() {
            "request" => {
                let request = from_wire_request(fixture.request.as_ref().expect("request"));
                match verify_request(&request, &resolver(), manifest.verify_at_unix) {
                    Ok(verified) => {
                        if let Some(oracle) = &fixture.oracle {
                            // Oracle byte-equality (S8: assert bytes, not prints).
                            assert_eq!(
                                verified.evidence.digest_value,
                                oracle.request_evidence_digest_value,
                                "{name}: evidence handle drifted from frozen oracle"
                            );
                            let digest_header = request
                                .headers
                                .iter()
                                .find(|(k, _)| k.eq_ignore_ascii_case("content-digest"))
                                .expect("digest header")
                                .1
                                .clone();
                            assert_eq!(
                                digest_header, oracle.content_digest,
                                "{name}: digest drifted"
                            );
                            let sig_header = request
                                .headers
                                .iter()
                                .find(|(k, _)| k.eq_ignore_ascii_case("signature"))
                                .expect("signature header")
                                .1
                                .clone();
                            assert_eq!(
                                sig_header, oracle.signature_header,
                                "{name}: signature drifted"
                            );
                        }
                        "verify_ok".to_owned()
                    }
                    Err(e) => e.wire_code().to_owned(),
                }
            }
            "response" => {
                let request = from_wire_request(fixture.request.as_ref().expect("request"));
                let response = from_wire_response(fixture.response.as_ref().expect("response"));
                match verify_response(&response, &request, &resolver(), manifest.verify_at_unix) {
                    Ok(_) => "verify_ok".to_owned(),
                    Err(e) => e.wire_code().to_owned(),
                }
            }
            "artifact" => {
                let check = fixture.artifact_check.as_ref().expect("artifact_check");
                let binding: ArtifactBinding =
                    serde_json::from_value(check.binding.clone()).expect("binding parses");
                let credential = base64_std_decode(&check.credential_b64);
                match verify_artifact_binding(&binding, &credential) {
                    Ok(()) => "verify_ok".to_owned(),
                    Err(e) => e.wire_code().to_owned(),
                }
            }
            "continuation" => {
                let check = fixture
                    .continuation_check
                    .as_ref()
                    .expect("continuation_check");
                let continuation: HttpContinuation =
                    serde_json::from_value(check.continuation.clone())
                        .expect("continuation parses");
                match continuation.verify(
                    &base64_std_decode(&check.previous_request_base_b64),
                    &base64_std_decode(&check.input_required_response_base_b64),
                    &base64_std_decode(&check.request_state_b64),
                ) {
                    Ok(()) => "verify_ok".to_owned(),
                    Err(e) => e.wire_code().to_owned(),
                }
            }
            "bodyless_202" => {
                let request = from_wire_request(fixture.request.as_ref().expect("request"));
                let response = from_wire_response(fixture.response.as_ref().expect("response"));
                match verify_accepted_202(
                    &response,
                    &request,
                    &resolver(),
                    &VerifierPolicy::default(),
                    manifest.verify_at_unix,
                ) {
                    Ok(_) => "verify_ok".to_owned(),
                    Err(e) => e.wire_code().to_owned(),
                }
            }
            "delegated_202" => {
                let check = fixture.delegated_202_check.as_ref().expect("delegated_202_check");
                let request = from_wire_request(&check.request);
                let response = from_wire_response(&check.response);
                let root_key =
                    mcp_re_core::VerificationKey::from_b64url(&check.root_public_key_b64url)
                        .expect("root key parses");
                let root_kid = check.root_kid.clone();
                let resolve = move |kid: &str, slot: SignerSlot| {
                    (kid == root_kid && slot == SignerSlot::Response).then(|| ResolvedActor {
                        identity: ActorIdentity {
                            role: "server".into(),
                            trust_domain: "example.com".into(),
                            subject: "did:example:server".into(),
                            keyid: kid.into(),
                        },
                        verification_key: root_key.clone(),
                        slot,
                    })
                };
                let auds = [check.verifier_audience.as_str()];
                let epochs = [check.epoch.as_str()];
                let expect = mcp_re_http_profile::DelegationExpectations {
                    policy: VerifierPolicy::default(),
                    verifier_audiences: &auds,
                    expected_audience_hash: &check.audience_hash,
                    accepted_epochs: &epochs,
                    max_clock_skew: 60,
                };
                let revoked_kid = check.revoked;
                let is_revoked = move |id: &str| revoked_kid && id == D202_DELEGATED_KID;
                match mcp_re_http_profile::verify_delegated_accepted_202(
                    &response,
                    &request,
                    &resolve,
                    &expect,
                    &is_revoked,
                    manifest.verify_at_unix,
                ) {
                    Ok(_) => "verify_ok".to_owned(),
                    Err(e) => e.wire_code().to_owned(),
                }
            }
            "admission" => {
                let check = fixture.admission_check.as_ref().expect("admission_check");
                let binding: mcp_re_http_profile::AdmissionBinding =
                    serde_json::from_value(check.binding.clone()).expect("binding parses");
                let issuer_key = mcp_re_core::VerificationKey::from_b64url(
                    &check.issuer_public_key_b64url,
                )
                .expect("issuer key parses");
                let authoritative = match (&check.authoritative_generation, &check.authoritative_status) {
                    (Some(g), Some(s)) => Some(mcp_re_http_profile::AuthoritativeAdmission {
                        generation: *g,
                        status: match s.as_str() {
                            "admitted" => mcp_re_http_profile::AdmissionStatus::Admitted,
                            "suspended" => mcp_re_http_profile::AdmissionStatus::Suspended,
                            "revoked" => mcp_re_http_profile::AdmissionStatus::Revoked,
                            other => panic!("{name}: unknown status {other}"),
                        },
                    }),
                    _ => None,
                };
                let policy = mcp_re_http_profile::AdmissionPolicy {
                    allow_degraded_mode: check.allow_degraded_mode,
                    degraded_propagation_bound: check.degraded_propagation_bound,
                    ..mcp_re_http_profile::AdmissionPolicy::default()
                };
                match mcp_re_http_profile::check_admission(
                    &binding,
                    &check.assertion_jws,
                    authoritative.as_ref(),
                    mcp_re_http_profile::PROFILE_TAG,
                    &["mcp.example.com"],
                    &policy,
                    manifest.verify_at_unix,
                    |kid: &str| (kid == ADMISSION_ISSUER_KID).then(|| issuer_key.clone()),
                ) {
                    Ok(_) => "verify_ok".to_owned(),
                    Err(e) => e.wire_code().to_owned(),
                }
            }
            "transport_request" => {
                let request = from_wire_request(fixture.request.as_ref().expect("request"));
                // The strict 2026-07-28 contract these fixtures were built under.
                let policy = VerifierPolicy::default().with_mcp_transport(
                    mcp_re_http_profile::McpTransportPolicy::mcp_2026_07_28(&["2026-07-28"]),
                );
                match mcp_re_http_profile::verify_request_with_policy(
                    &request,
                    &resolver(),
                    &policy,
                    manifest.verify_at_unix,
                ) {
                    Ok(_) => "verify_ok".to_owned(),
                    Err(e) => e.wire_code().to_owned(),
                }
            }
            "chain" => {
                let check = fixture.chain_check.as_ref().expect("chain_check");
                let hops: Vec<RetainedHop> = check
                    .hops
                    .iter()
                    .map(|h| RetainedHop {
                        request: from_wire_request(&h.request),
                        response: from_wire_response(&h.response),
                    })
                    .collect();
                let out = reconstruct_chain(
                    &hops,
                    &resolver(),
                    &VerifierPolicy::default(),
                    manifest.verify_at_unix,
                );
                // The label IS the frozen verdict: an incomplete record must name
                // the hop that broke it, so the comparison covers WHICH hop too.
                assert_eq!(
                    label_token(&out.label),
                    check.expected_label,
                    "{name}: chain label drifted from the frozen expectation"
                );
                "verify_ok".to_owned()
            }
            "rejection" => {
                // A rejection carries request context only when bound.
                let request = fixture.request.as_ref().map(from_wire_request);
                let response = from_wire_response(fixture.response.as_ref().expect("response"));
                match verify_signed_rejection(
                    &response,
                    request.as_ref(),
                    &resolver(),
                    manifest.verify_at_unix,
                ) {
                    // On success the observed verdict IS the trusted wire code
                    // (not just "verify_ok"): the frozen fixture pins the exact
                    // machine signal a client would act on.
                    Ok(verdict) => verdict.wire_code,
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
