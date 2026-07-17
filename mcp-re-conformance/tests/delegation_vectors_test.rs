// SPDX-License-Identifier: Apache-2.0
//! Delegated-signing conformance corpus (ADR-MCPRE-052 §9, MCPRE-122).
//!
//! A SEPARATE frozen corpus under `tests/vectors/delegation-profile/`, sibling to
//! the HTTP-profile corpus (`http_profile_vectors_test.rs`) — the compact-JWS
//! delegation credential + delegated-key RFC 9421 response, verified black-box
//! through the ONE production entry point `verify_delegated_response_full`
//! (ADR-MCPRE-052 §3 steps 1–8). Every §9 vector is a self-contained, frozen
//! request + delegated response + verifier-policy `check`; the runner recomputes
//! the verified request, verifies the delegated response, and asserts the exact
//! frozen `mcp-re.*` verdict.
//!
//! Two-sided guard, mirroring the draft-02 / http-profile corpora:
//!   1. the writer (`write_delegation_fixtures -- --ignored`) regenerates the
//!      corpus with the project's own implementation (drift guard);
//!   2. the frozen runner verifies every committed fixture black-box and asserts
//!      the frozen verdict — a third party checks itself against the frozen bytes,
//!      not this project's regenerated opinion.
//!
//! Cross-verification against an INDEPENDENT JOSE/JWS implementation
//! (`external_delegation_kat.json`, produced by python-cryptography Ed25519) runs
//! in `delegation_cross_verification_test.rs` + `tools/jose_cross_verify.py`
//! (ADR-MCPRE-052 §9; mirrors the RFC 9421 gate, MCPRE-99).
//!
//! Regenerate: cargo test -p mcp-re-conformance --test delegation_vectors_test \
//!   write_delegation_fixtures -- --ignored --exact

use serde::Deserialize;
use serde::Serialize;

use mcp_re_core::SigningKey;
use mcp_re_http_profile::issue_delegation_credential;
use mcp_re_http_profile::sign_delegated_response_full;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::sign_response_full;
use mcp_re_http_profile::verify_delegated_response_full;
use mcp_re_http_profile::verify_request_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::Audience;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::Cnf;
use mcp_re_http_profile::DelegatedJwk;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationExpectations;
use mcp_re_http_profile::DelegationHeader;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::HttpResponse;
use mcp_re_http_profile::RequestEvidence;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::VerifiedHttpRequestEvidence;
use mcp_re_http_profile::DELEGATION_ALG;
use mcp_re_http_profile::DELEGATION_TYP;
use mcp_re_http_profile::JWK_CRV_ED25519;
use mcp_re_http_profile::JWK_KTY_OKP;
use mcp_re_http_profile::KEY_USE_RESPONSE_SIGNING;
use mcp_re_http_profile::PROFILE_TAG;

// Fixed, documented TEST-ONLY seeds; the corpus is deterministic end-to-end
// (Ed25519 is deterministic, so byte-freezing is honest).
const CLIENT_SEED: [u8; 32] = [11u8; 32];
const ROOT_SEED: [u8; 32] = [33u8; 32];
const DELEGATED_SEED: [u8; 32] = [44u8; 32];
const DELEGATED2_SEED: [u8; 32] = [45u8; 32];
const ATTACKER_SEED: [u8; 32] = [99u8; 32];

const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
/// The frozen verification instant every runner uses.
const NOW: i64 = 1_700_000_100;

const CLIENT_KID: &str = "client-key-1";
const ROOT_KID: &str = "root-kid";
const DELEGATED_KID: &str = "root-kid/delegated/1";
const DELEGATED2_KID: &str = "root-kid/delegated/2";
const VERIFIER_AUD: &str = "verifier-1";
const AUD_SCOPE: &str = "aud-scope-1";
const EPOCH: &str = "epoch-1";
const NEXT_EPOCH: &str = "epoch-2";

const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const ACCESS_TOKEN: &str = "access-token-xyz";

// ---------------------------------------------------------------------------
// Fixture schema (`mcp-re-delegation-conformance/v1`).
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

/// The verifier-side deployment policy a fixture pins (ADR-MCPRE-052 §3). The
/// same frozen response can be accepted or rejected depending on this policy
/// (e.g. a valid credential is `audience_mismatch` at a verifier not named in
/// `aud`, or `trust_epoch_stale` once the accepted-epoch set advances).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegationCheck {
    verifier_audiences: Vec<String>,
    expected_audience_hash: String,
    accepted_epochs: Vec<String>,
    max_clock_skew: i64,
    revoked_kids: Vec<String>,
}

impl DelegationCheck {
    /// The nominal in-policy verifier: this audience, this scope, the current
    /// epoch, nothing revoked.
    fn nominal() -> Self {
        DelegationCheck {
            verifier_audiences: vec![VERIFIER_AUD.into()],
            expected_audience_hash: AUD_SCOPE.into(),
            accepted_epochs: vec![EPOCH.into()],
            max_clock_skew: 60,
            revoked_kids: vec![],
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    schema: String,
    name: String,
    /// Always `delegated_response`: verify `response` against `request` through
    /// `verify_delegated_response_full` with the fixture `check` policy.
    kind: String,
    /// `verify_ok` or the exact frozen `mcp-re.*` wire code observed.
    expected: String,
    request: WireMessage,
    response: WireMessage,
    check: DelegationCheck,
}

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    schema: String,
    verify_at_unix: i64,
    /// SHA-256 over the sorted `path:hash` list (#415 rev 2 §12.2) — one value
    /// naming this exact corpus, since a tag or a filename list proves only which
    /// files were MEANT to be there, not what was in them.
    corpus_digest: String,
    fixtures: Vec<ManifestEntry>,
}

/// One manifest entry: the fixture path and the SHA-256 of its exact bytes.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestEntry {
    file: String,
    sha256: String,
}

fn hex_sha256(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The §12.2 corpus digest over the SORTED `<path>:<sha256>` list — sorted so the
/// digest tracks corpus CONTENT, not the writer's emission order.
fn corpus_digest(entries: &[ManifestEntry]) -> String {
    let mut lines: Vec<String> = entries
        .iter()
        .map(|e| format!("{}:{}\n", e.file, e.sha256))
        .collect();
    lines.sort();
    hex_sha256(lines.concat().as_bytes())
}

/// Third-party KATs committed here but NOT generated by the writer: pinned by
/// hash, replayed by their own harness (`delegation_cross_verification_test`).
const EXTERNAL_KATS: [&str; 1] = ["external_delegation_kat.json"];

const SCHEMA: &str = "mcp-re-delegation-conformance/v1";

// ---------------------------------------------------------------------------
// Shared material + trust seam.
// ---------------------------------------------------------------------------

fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
fn root_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ROOT_SEED)
}
fn delegated_key() -> SigningKey {
    SigningKey::from_seed_bytes(&DELEGATED_SEED)
}
fn delegated2_key() -> SigningKey {
    SigningKey::from_seed_bytes(&DELEGATED2_SEED)
}
fn attacker_key() -> SigningKey {
    SigningKey::from_seed_bytes(&ATTACKER_SEED)
}

/// Slot-aware trust seam: the client key for the Request slot, the ROOT key (by
/// its `issuer_kid`) for the Response slot. The DELEGATED keys are never enrolled
/// here — they are authorized by the credential chain alone.
fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    move |key_id: &str, slot: SignerSlot| {
        let (role, key) = match (key_id, slot) {
            (CLIENT_KID, SignerSlot::Request) => ("client", client_key()),
            (ROOT_KID, SignerSlot::Response) => ("server", root_key()),
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

/// A server-signer identity whose `keyid` IS the given delegated-key id.
fn server_signer_for(delegated_kid: &str) -> ActorIdentity {
    ActorIdentity {
        role: "server".into(),
        trust_domain: "example.com".into(),
        subject: "did:example:server".into(),
        keyid: delegated_kid.into(),
    }
}

fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: VERIFIER_AUD.into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    }
}

fn base_request() -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        target_uri: TARGET.into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Authorization".into(), format!("Bearer {ACCESS_TOKEN}")),
        ],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#.to_vec(),
    }
}

fn no_material() -> impl Fn(&ArtifactBinding) -> Option<Vec<u8>> {
    move |_b: &ArtifactBinding| None
}

fn response_body() -> Vec<u8> {
    br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec()
}

fn signed_request() -> (HttpRequest, RequestEvidence) {
    let mut req = base_request();
    let block = HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(
            ArtifactType::OauthDpop,
            ACCESS_TOKEN.as_bytes(),
        )],
        continuation: None,
    };
    let ev = sign_request_full(
        &mut req, &block, &client_key(), CLIENT_KID, CREATED, EXPIRES, "nonce-1",
    )
    .expect("sign request");
    (req, ev)
}

fn recompute_verified_request(req: &HttpRequest) -> VerifiedHttpRequestEvidence {
    verify_request_full(req, &audience(), &no_material(), &resolver(), NOW)
        .expect("frozen request re-verifies")
}

// ---------------------------------------------------------------------------
// Credential minting (the issuer/custody side, root-signed).
// ---------------------------------------------------------------------------

fn good_header() -> DelegationHeader {
    DelegationHeader {
        typ: DELEGATION_TYP.into(),
        alg: DELEGATION_ALG.into(),
        kid: ROOT_KID.into(),
    }
}

/// A nominal, in-every-way-valid claim set binding `delegated` under
/// `delegated_kid`, scoped to this verifier / profile / audience / epoch.
fn good_claims(delegated: &SigningKey, delegated_kid: &str) -> DelegationClaims {
    DelegationClaims {
        iss: "did:example:server".into(),
        iat: CREATED,
        nbf: CREATED,
        exp: EXPIRES,
        jti: "evt-1".into(),
        aud: Audience::One(VERIFIER_AUD.into()),
        mcp_re_profile: PROFILE_TAG.into(),
        mcp_re_audience_hash: AUD_SCOPE.into(),
        mcp_re_server_signer: server_signer_for(delegated_kid).actor_id(),
        mcp_re_key_use: KEY_USE_RESPONSE_SIGNING.into(),
        delegated_kid: delegated_kid.into(),
        issuer_kid: ROOT_KID.into(),
        trust_epoch: EPOCH.into(),
        cnf: Cnf {
            jwk: DelegatedJwk {
                kty: JWK_KTY_OKP.into(),
                crv: JWK_CRV_ED25519.into(),
                kid: delegated_kid.into(),
                x: delegated.public_key().to_b64url(),
            },
        },
    }
}

fn mint(root: &SigningKey, header: &DelegationHeader, claims: &DelegationClaims) -> String {
    issue_delegation_credential(root, header, claims)
}

/// The single canonical valid credential for the primary delegated key.
fn valid_credential() -> String {
    mint(
        &root_key(),
        &good_header(),
        &good_claims(&delegated_key(), DELEGATED_KID),
    )
}

// ---------------------------------------------------------------------------
// Fixture assembly.
// ---------------------------------------------------------------------------

fn wire_request(r: &HttpRequest) -> WireMessage {
    WireMessage {
        method: Some(r.method.clone()),
        target_uri: Some(r.target_uri.clone()),
        status: None,
        headers: r.headers.clone(),
        body_utf8: String::from_utf8(r.body.clone()).expect("utf-8 body"),
    }
}

fn wire_response(r: &HttpResponse) -> WireMessage {
    WireMessage {
        method: None,
        target_uri: None,
        status: Some(r.status),
        headers: r.headers.clone(),
        body_utf8: String::from_utf8(r.body.clone()).expect("utf-8 body"),
    }
}

fn from_wire_request(w: &WireMessage) -> HttpRequest {
    HttpRequest {
        method: w.method.clone().expect("request method"),
        target_uri: w.target_uri.clone().expect("request target_uri"),
        headers: w.headers.clone(),
        body: w.body_utf8.clone().into_bytes(),
    }
}

fn from_wire_response(w: &WireMessage) -> HttpResponse {
    HttpResponse {
        status: w.status.expect("response status"),
        headers: w.headers.clone(),
        body: w.body_utf8.clone().into_bytes(),
    }
}

/// Sign a fresh delegated response embedding `credential`, signed by
/// `delegated_signing_key` under RFC 9421 `keyid`, with the block's
/// `server_signer.keyid == block_signer_kid`.
fn delegated_response(
    req: &HttpRequest,
    ev: &RequestEvidence,
    credential: &str,
    delegated_signing_key: &SigningKey,
    keyid: &str,
    block_signer_kid: &str,
) -> HttpResponse {
    let mut rsp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    };
    sign_delegated_response_full(
        &mut rsp,
        req,
        ev,
        &server_signer_for(block_signer_kid),
        credential,
        delegated_signing_key,
        keyid,
        CREATED,
        EXPIRES,
    )
    .expect("sign delegated response");
    rsp
}

fn fixture(name: &str, expected: &str, req: &WireMessage, rsp: &HttpResponse, check: DelegationCheck) -> Fixture {
    Fixture {
        schema: SCHEMA.into(),
        name: name.into(),
        kind: "delegated_response".into(),
        expected: expected.into(),
        request: WireMessage {
            method: req.method.clone(),
            target_uri: req.target_uri.clone(),
            status: req.status,
            headers: req.headers.clone(),
            body_utf8: req.body_utf8.clone(),
        },
        response: wire_response(rsp),
        check,
    }
}

fn build_fixtures() -> Vec<Fixture> {
    let (req, ev) = signed_request();
    let req_wire = wire_request(&req);
    let mut fx = Vec::new();

    // --- 1. valid → accept -------------------------------------------------
    let valid_rsp = delegated_response(
        &req, &ev, &valid_credential(), &delegated_key(), DELEGATED_KID, DELEGATED_KID,
    );
    fx.push(fixture("d01_valid", "verify_ok", &req_wire, &valid_rsp, DelegationCheck::nominal()));

    // --- 2. credential_expired (exp < now) ---------------------------------
    let mut c = good_claims(&delegated_key(), DELEGATED_KID);
    c.nbf = CREATED - 20_000;
    c.exp = CREATED - 10_000;
    let rsp = delegated_response(&req, &ev, &mint(&root_key(), &good_header(), &c), &delegated_key(), DELEGATED_KID, DELEGATED_KID);
    fx.push(fixture("d02_credential_expired", "mcp-re.delegation_credential_expired", &req_wire, &rsp, DelegationCheck::nominal()));

    // --- 3. not_yet_valid (now < nbf) --------------------------------------
    let mut c = good_claims(&delegated_key(), DELEGATED_KID);
    c.nbf = NOW + 10_000;
    c.exp = NOW + 20_000;
    let rsp = delegated_response(&req, &ev, &mint(&root_key(), &good_header(), &c), &delegated_key(), DELEGATED_KID, DELEGATED_KID);
    fx.push(fixture("d03_not_yet_valid", "mcp-re.delegation_credential_expired", &req_wire, &rsp, DelegationCheck::nominal()));

    // --- 4. key_use_invalid ------------------------------------------------
    let mut c = good_claims(&delegated_key(), DELEGATED_KID);
    c.mcp_re_key_use = "request-signing".into();
    let rsp = delegated_response(&req, &ev, &mint(&root_key(), &good_header(), &c), &delegated_key(), DELEGATED_KID, DELEGATED_KID);
    fx.push(fixture("d04_key_use_invalid", "mcp-re.delegation_key_use_invalid", &req_wire, &rsp, DelegationCheck::nominal()));

    // --- 5. profile_mismatch -----------------------------------------------
    let mut c = good_claims(&delegated_key(), DELEGATED_KID);
    c.mcp_re_profile = "some-other-profile".into();
    let rsp = delegated_response(&req, &ev, &mint(&root_key(), &good_header(), &c), &delegated_key(), DELEGATED_KID, DELEGATED_KID);
    fx.push(fixture("d05_profile_mismatch", "mcp-re.delegation_profile_mismatch", &req_wire, &rsp, DelegationCheck::nominal()));

    // --- 5a. audience_mismatch: verifier not named in `aud` ----------------
    // A VALID credential, rejected because THIS verifier is not in its audience.
    let mut check = DelegationCheck::nominal();
    check.verifier_audiences = vec!["some-other-verifier".into()];
    fx.push(fixture("d06_verifier_not_in_aud", "mcp-re.delegation_audience_mismatch", &req_wire, &valid_rsp, check));

    // --- 5a'. audience_mismatch: credential scoped to a different service ---
    let mut check = DelegationCheck::nominal();
    check.expected_audience_hash = "different-scope".into();
    fx.push(fixture("d07_audience_scope_mismatch", "mcp-re.delegation_audience_mismatch", &req_wire, &valid_rsp, check));

    // --- 5b. trust_epoch_stale ---------------------------------------------
    let mut check = DelegationCheck::nominal();
    check.accepted_epochs = vec![NEXT_EPOCH.into()];
    fx.push(fixture("d08_trust_epoch_stale", "mcp-re.delegation_trust_epoch_stale", &req_wire, &valid_rsp, check));

    // --- 5b'. bounded rollout window accepts the previous epoch ------------
    // Same valid credential (epoch = EPOCH), accepted only because the verifier
    // explicitly runs { current = NEXT_EPOCH, previous = EPOCH }.
    let mut check = DelegationCheck::nominal();
    check.accepted_epochs = vec![NEXT_EPOCH.into(), EPOCH.into()];
    fx.push(fixture("d09_bounded_rollout_previous_epoch", "verify_ok", &req_wire, &valid_rsp, check));

    // --- 5c. delegation required rejects a directly root-signed response ----
    let mut direct = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    };
    sign_response_full(&mut direct, &req, &ev, &server_signer_for(ROOT_KID), &root_key(), ROOT_KID, CREATED, EXPIRES)
        .expect("sign direct-root response");
    fx.push(fixture("d10_required_rejects_direct_root", "mcp-re.delegation_credential_missing", &req_wire, &direct, DelegationCheck::nominal()));

    // --- 6. revoked delegated key ------------------------------------------
    let mut check = DelegationCheck::nominal();
    check.revoked_kids = vec![DELEGATED_KID.into()];
    fx.push(fixture("d11_revoked_delegated_key", "mcp-re.delegation_revoked", &req_wire, &valid_rsp, check));

    // --- 7. substituted key: RFC 9421 keyid ≠ delegated_kid ----------------
    let rsp = delegated_response(&req, &ev, &valid_credential(), &delegated_key(), "some-other-kid", DELEGATED_KID);
    fx.push(fixture("d12_keyid_not_delegated_kid", "mcp-re.delegation_key_mismatch", &req_wire, &rsp, DelegationCheck::nominal()));

    // --- 7'. substituted key: signed by a key other than cnf.jwk -----------
    let rsp = delegated_response(&req, &ev, &valid_credential(), &attacker_key(), DELEGATED_KID, DELEGATED_KID);
    fx.push(fixture("d13_signed_by_non_cnf_key", "mcp-re.delegation_key_mismatch", &req_wire, &rsp, DelegationCheck::nominal()));

    // --- 8. credential stripped from a delegated response ------------------
    let mut stripped = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: response_body(),
    };
    sign_response_full(&mut stripped, &req, &ev, &server_signer_for(DELEGATED_KID), &delegated_key(), DELEGATED_KID, CREATED, EXPIRES)
        .expect("sign credential-less delegated response");
    fx.push(fixture("d14_credential_stripped", "mcp-re.delegation_credential_missing", &req_wire, &stripped, DelegationCheck::nominal()));

    // --- 8'. credential lifted from a DIFFERENT delegated key/server-signer -
    // A trusted-root credential that authorizes DELEGATED2 (and is thus scoped to
    // DELEGATED2's server-signer), swapped onto a response signed by (and whose
    // block names) DELEGATED1. The credential's `mcp_re_server_signer` no longer
    // matches the block's resolved server-signer, so scope binding (§3 step 5)
    // rejects the lifted credential before the step-8 keyid/cnf cross-check.
    let foreign = mint(&root_key(), &good_header(), &good_claims(&delegated2_key(), DELEGATED2_KID));
    let rsp = delegated_response(&req, &ev, &foreign, &delegated_key(), DELEGATED_KID, DELEGATED_KID);
    fx.push(fixture("d15_credential_lifted_wrong_server_signer", "mcp-re.delegation_audience_mismatch", &req_wire, &rsp, DelegationCheck::nominal()));

    // --- 9. issuer_untrusted -----------------------------------------------
    let mut h = good_header();
    h.kid = "untrusted-root".into();
    let mut c = good_claims(&delegated_key(), DELEGATED_KID);
    c.issuer_kid = "untrusted-root".into();
    let rsp = delegated_response(&req, &ev, &mint(&root_key(), &h, &c), &delegated_key(), DELEGATED_KID, DELEGATED_KID);
    fx.push(fixture("d16_issuer_untrusted", "mcp-re.delegation_issuer_untrusted", &req_wire, &rsp, DelegationCheck::nominal()));

    // --- 10. wrong_alg (header alg ≠ EdDSA, incl. `none`) ------------------
    let mut h = good_header();
    h.alg = "none".into();
    let rsp = delegated_response(&req, &ev, &mint(&root_key(), &h, &good_claims(&delegated_key(), DELEGATED_KID)), &delegated_key(), DELEGATED_KID, DELEGATED_KID);
    fx.push(fixture("d17_wrong_alg", "mcp-re.delegation_credential_invalid", &req_wire, &rsp, DelegationCheck::nominal()));

    // --- 10'. forged root signature (claims a trusted issuer_kid) ----------
    let forged = mint(&attacker_key(), &good_header(), &good_claims(&delegated_key(), DELEGATED_KID));
    let rsp = delegated_response(&req, &ev, &forged, &delegated_key(), DELEGATED_KID, DELEGATED_KID);
    fx.push(fixture("d18_forged_root_signature", "mcp-re.delegation_credential_invalid", &req_wire, &rsp, DelegationCheck::nominal()));

    // --- 11. rotation overlap: a response under EITHER successor accepts ----
    // Key A is the primary; key B is a second in-overlap delegated key with its
    // own valid credential. No verification gap across the rotation.
    fx.push(fixture("d19_rotation_overlap_key_a", "verify_ok", &req_wire, &valid_rsp, DelegationCheck::nominal()));
    let cred_b = mint(&root_key(), &good_header(), &good_claims(&delegated2_key(), DELEGATED2_KID));
    let rsp_b = delegated_response(&req, &ev, &cred_b, &delegated2_key(), DELEGATED2_KID, DELEGATED2_KID);
    fx.push(fixture("d20_rotation_overlap_key_b", "verify_ok", &req_wire, &rsp_b, DelegationCheck::nominal()));

    // --- 12. response body tamper (content-digest floor) -------------------
    let mut tampered = valid_rsp_clone(&req, &ev);
    let last = tampered.body.len() - 2;
    tampered.body[last] ^= 0x01;
    fx.push(fixture("d21_body_tamper", "mcp-re.digest_mismatch", &req_wire, &tampered, DelegationCheck::nominal()));

    // --- 12'. response signature-bytes tamper (verify under cnf fails) ------
    let mut sig_tampered = valid_rsp_clone(&req, &ev);
    tamper_response_signature(&mut sig_tampered);
    fx.push(fixture("d22_response_signature_tamper", "mcp-re.delegation_key_mismatch", &req_wire, &sig_tampered, DelegationCheck::nominal()));

    fx
}

/// A fresh copy of the valid delegated response (its own signed bytes) so a
/// post-signing tamper does not disturb the shared `valid_rsp`.
fn valid_rsp_clone(req: &HttpRequest, ev: &RequestEvidence) -> HttpResponse {
    delegated_response(req, ev, &valid_credential(), &delegated_key(), DELEGATED_KID, DELEGATED_KID)
}

/// Flip one base64url character inside the `mcp-re-response` Signature value,
/// keeping it a well-formed header but a wrong signature.
fn tamper_response_signature(rsp: &mut HttpResponse) {
    for (k, v) in rsp.headers.iter_mut() {
        if k.eq_ignore_ascii_case("signature") {
            // value form: mcp-re-response=:<b64>:  — flip a byte inside the b64.
            let bytes = unsafe { v.as_bytes_mut() };
            // Find the ':' that opens the byte-sequence, then mutate a char after.
            if let Some(colon) = bytes.iter().position(|&b| b == b':') {
                let idx = colon + 3;
                if idx < bytes.len() {
                    bytes[idx] = if bytes[idx] == b'A' { b'B' } else { b'A' };
                }
            }
        }
    }
}

/// Locate the committed corpus under BOTH build systems (same dual-mode bridge
/// as the http-profile corpus).
fn vectors_root() -> std::path::PathBuf {
    if let Ok(rel) = std::env::var("MCP_RE_DELEGATION_VECTORS_MANIFEST") {
        for key in ["TEST_SRCDIR", "RUNFILES_DIR"] {
            if let Ok(root) = std::env::var(key) {
                let candidate = std::path::Path::new(&root).join(&rel);
                if candidate.exists() {
                    return candidate.parent().expect("manifest parent").to_path_buf();
                }
            }
        }
        let candidate = std::path::PathBuf::from(&rel);
        if candidate.exists() {
            return candidate.parent().expect("manifest parent").to_path_buf();
        }
        panic!("MCP_RE_DELEGATION_VECTORS_MANIFEST set but runfile not found (rel={rel})");
    }
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("delegation-profile")
}

// ---------------------------------------------------------------------------
// Writer (regenerates the corpus) — run explicitly with --ignored.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "golden writer: regenerates the committed delegation corpus"]
fn write_delegation_fixtures() {
    let root = vectors_root();
    std::fs::create_dir_all(&root).expect("corpus dir");
    let fixtures = build_fixtures();
    let mut entries = Vec::new();
    for f in &fixtures {
        let file = format!("{}.json", f.name);
        let bytes = serde_json::to_string_pretty(f).expect("serialize") + "\n";
        std::fs::write(root.join(&file), &bytes).expect("write fixture");
        // Hash the bytes actually written — the artifact a third party reads.
        entries.push(ManifestEntry {
            sha256: hex_sha256(bytes.as_bytes()),
            file,
        });
    }
    // Pin the external KAT (#415 rev 2 §12.2 names external KATs explicitly). It is
    // a third-party artifact, not generated here — which is precisely why it needs
    // pinning: it anchors the independent cross-verification claim, and silent drift
    // would change what that claim means while still passing.
    for external in EXTERNAL_KATS {
        let bytes = std::fs::read(root.join(external))
            .unwrap_or_else(|_| panic!("{external}: external KAT must be committed"));
        entries.push(ManifestEntry {
            file: (*external).to_owned(),
            sha256: hex_sha256(&bytes),
        });
    }

    let manifest = Manifest {
        schema: SCHEMA.into(),
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
// Frozen runner: every committed fixture verifies black-box to its verdict.
// ---------------------------------------------------------------------------

fn run_fixture(fixture: &Fixture, verify_at: i64) -> String {
    let request = from_wire_request(&fixture.request);
    let response = from_wire_response(&fixture.response);
    let verified_req = recompute_verified_request(&request);

    let auds: Vec<&str> = fixture.check.verifier_audiences.iter().map(String::as_str).collect();
    let epochs: Vec<&str> = fixture.check.accepted_epochs.iter().map(String::as_str).collect();
    let expect = DelegationExpectations {
        policy: mcp_re_http_profile::VerifierPolicy::default(),
        verifier_audiences: &auds,
        expected_audience_hash: &fixture.check.expected_audience_hash,
        accepted_epochs: &epochs,
        max_clock_skew: fixture.check.max_clock_skew,
    };
    let is_revoked = |kid: &str| fixture.check.revoked_kids.iter().any(|r| r == kid);

    match verify_delegated_response_full(
        &response,
        &request,
        &verified_req,
        &resolver(),
        &expect,
        &is_revoked,
        verify_at,
    ) {
        Ok(_) => "verify_ok".to_owned(),
        Err(e) => e.wire_code().to_owned(),
    }
}

#[test]
fn frozen_delegation_corpus_verifies() {
    let root = vectors_root();
    let manifest: Manifest = serde_json::from_slice(
        &std::fs::read(root.join("manifest.json")).expect("committed manifest"),
    )
    .expect("manifest parses");
    assert_eq!(manifest.schema, SCHEMA);
    assert!(!manifest.fixtures.is_empty(), "corpus must not be empty");

    // §12.2: the digest must commit to the manifest's entries, checked before any
    // vector runs so a corpus cannot be edited into agreeing with itself.
    assert_eq!(
        corpus_digest(&manifest.fixtures),
        manifest.corpus_digest,
        "corpus digest does not commit to the manifest entries"
    );

    for entry in &manifest.fixtures {
        let name = &entry.file;
        let bytes = std::fs::read(root.join(name)).expect("fixture file");
        // Fail closed BEFORE running: a fixture whose bytes do not match the
        // manifest is an unknown file with a familiar name.
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
        assert_eq!(fixture.kind, "delegated_response", "{name}: unexpected kind");
        let observed = run_fixture(&fixture, manifest.verify_at_unix);
        assert_eq!(observed, fixture.expected, "{name}: verdict mismatch");
    }
}

/// Drift guard: regenerating the corpus with the current implementation must
/// reproduce the committed bytes exactly (writer output == frozen files).
#[test]
fn regenerated_delegation_fixtures_match_committed_bytes() {
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

/// Sanity: the §9 plan enumerates 12 numbered vectors (several with sub-cases);
/// the corpus must be comprehensive, not a token stub.
#[test]
fn corpus_covers_the_full_taxonomy() {
    let names: std::collections::BTreeSet<String> =
        build_fixtures().into_iter().map(|f| f.name).collect();
    assert!(names.len() >= 22, "corpus shrank below the §9 taxonomy: {}", names.len());
    // Every frozen delegation wire token must appear as an expected verdict at
    // least once (the corpus exercises the whole taxonomy, not a subset).
    let verdicts: std::collections::BTreeSet<String> =
        build_fixtures().into_iter().map(|f| f.expected).collect();
    for token in [
        "mcp-re.delegation_credential_missing",
        "mcp-re.delegation_credential_invalid",
        "mcp-re.delegation_credential_expired",
        "mcp-re.delegation_issuer_untrusted",
        "mcp-re.delegation_profile_mismatch",
        "mcp-re.delegation_audience_mismatch",
        "mcp-re.delegation_key_use_invalid",
        "mcp-re.delegation_trust_epoch_stale",
        "mcp-re.delegation_key_mismatch",
        "mcp-re.delegation_revoked",
    ] {
        assert!(verdicts.contains(token), "corpus never exercises {token}");
    }
}
