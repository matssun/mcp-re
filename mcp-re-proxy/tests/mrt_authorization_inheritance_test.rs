// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPS-024 conformance, vector "No authorization inheritance" (SEP-2322).
//!
//! ADR-024 Decision rule 4: *"Continuation does not bypass authorization. Each leg
//! is independently subject to Phase 5 authorization (ADR-MCPS-013). A later leg
//! MUST NOT inherit an authorization decision from an earlier leg via
//! `requestState`."* The other five ADR-024 vectors are pure per-leg
//! verify_request concerns proven in `mcp-re-core/tests/multi_round_trip_test.rs`
//! (continuation accepted, leg replay rejected, requestState buys no replay
//! exemption, forged requestState breaks the signature, retry safety); this vector
//! is the ONE that lives at the proxy/PEP layer, because authorization is Phase 5
//! (`Proxy::with_policy_enforcement` → `authorize_after_verify`), not Core
//! verification. It is the proxy-layer sibling of the cross-replica MRT proof in
//! `fleet_mrt_replica_switch_e2e_test.rs`.
//!
//! Both directions of "no inheritance" are proven against the real serving path:
//!
//!   1. `revoking_authorization_between_legs_fails_the_continuation_closed` — the
//!      ADR's literal vector wording: leg 1 is authorized and served; the grant is
//!      revoked between legs; the continuation leg (a fresh nonce, echoing the same
//!      opaque `requestState`) is denied `mcp-re.authorization_revoked` and the
//!      inner server is never reached. Authorization is re-evaluated per leg — the
//!      earlier allow is not carried forward.
//!
//!   2. `request_state_confers_no_inherited_authorization` — the mechanism the ADR
//!      names: a continuation leg that echoes leg 1's exact `requestState` but
//!      carries NO authorization block of its own is denied
//!      `mcp-re.authorization_block_missing`. The opaque resume payload transports
//!      no authorization; each leg must present its own.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex;

use mcp_re_core::b64url_encode;
use mcp_re_core::canonicalize;
use mcp_re_core::parse_rfc3339_utc;
use mcp_re_core::request_hash;
use mcp_re_core::sha256_hash_id;
use mcp_re_core::verify_response;
use mcp_re_core::InMemoryTrustResolver;
use mcp_re_core::SigningKey;
use mcp_re_host::HostSigner;
use mcp_re_policy::mint_reference_grant;
use mcp_re_policy::GrantedOperation;
use mcp_re_policy::PolicyEvaluator;
use mcp_re_policy::ReferenceGrantSpec;
use mcp_re_policy::ReferenceProfile;
use mcp_re_policy::RevocationSource;
use mcp_re_policy::RevocationStatus;
use mcp_re_policy::RevocationUnavailable;
use mcp_re_policy::AUTHORIZATION_META_KEY;
use mcp_re_policy::REFERENCE_PROFILE_ID;
use mcp_re_proxy::test_support::block_on_handle;
use mcp_re_proxy::Proxy;
use serde_json::json;
use serde_json::Map;
use serde_json::Value;

const SIGNER: &str = "did:example:agent-1";
const SIGNER_KEY_ID: &str = "key-1";
const SERVER: &str = "did:example:server-1";
const SERVER_KEY_ID: &str = "server-key-1";
const ISSUER: &str = "did:example:authority-1";
const ISSUER_KEY_ID: &str = "authority-key-1";
const AUDIENCE: &str = "did:example:server-1";
const ON_BEHALF_OF: &str = "did:example:user-1";
const ISSUED_AT: &str = "2026-05-28T20:00:00Z";
const EXPIRES_AT: &str = "2026-05-28T20:05:00Z";
const GRANT_NOT_BEFORE: &str = "2026-05-28T20:00:00Z";
const GRANT_EXPIRES_AT: &str = "2026-05-28T21:00:00Z";
const REVOCATION_ID: &str = "rev-mrt-1";
const SKEW: i64 = 300;

// Distinct, equal-length base64url nonces — a continuation leg MUST carry a fresh
// nonce (ADR-024 rule 3); it buys no replay exemption and no authorization.
const NONCE_LEG_1: &str = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA";
const NONCE_LEG_2: &str = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MB";
// The opaque SEP-2322 resume payload the client echoes back to continue — untrusted
// app data (ADR-024: confers neither freshness nor authorization).
const REQUEST_STATE: &str = "eyJzdGVwIjoxfQ";

fn signer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[1u8; 32])
}
fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[2u8; 32])
}
fn issuer_key() -> SigningKey {
    SigningKey::from_seed_bytes(&[42u8; 32])
}
fn now() -> i64 {
    parse_rfc3339_utc(ISSUED_AT).expect("parse issued_at") + 60
}

/// One resolver holding BOTH the request signer key (Core verification) and the
/// grant issuer key (Phase 5 policy) — the proxy reuses one resolver for both.
fn resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SIGNER, SIGNER_KEY_ID, signer_key().public_key());
    r.insert(ISSUER, ISSUER_KEY_ID, issuer_key().public_key());
    r
}
fn server_resolver() -> InMemoryTrustResolver {
    let mut r = InMemoryTrustResolver::new();
    r.insert(SERVER, SERVER_KEY_ID, server_key().public_key());
    r
}

fn host() -> HostSigner {
    HostSigner::new(signer_key(), SIGNER, SIGNER_KEY_ID)
}

/// A revocation source with interior mutability so the test can revoke a grant
/// BETWEEN legs — the point of vector 5. `InMemoryRevocationSource::revoke` takes
/// `&mut self` and is moved into the `Proxy`, so it cannot model a mid-exchange
/// revocation; this shared handle can.
#[derive(Clone, Default)]
struct SharedRevocationSource {
    revoked: Arc<Mutex<BTreeSet<String>>>,
}
impl SharedRevocationSource {
    fn new() -> Self {
        SharedRevocationSource::default()
    }
    /// Revoke `revocation_id` (visible to the proxy that holds a clone).
    fn revoke(&self, revocation_id: &str) {
        self.revoked.lock().unwrap().insert(revocation_id.to_string());
    }
}
impl RevocationSource for SharedRevocationSource {
    fn revocation_status(
        &self,
        revocation_id: &str,
    ) -> Result<RevocationStatus, RevocationUnavailable> {
        if self.revoked.lock().unwrap().contains(revocation_id) {
            Ok(RevocationStatus::Revoked)
        } else {
            Ok(RevocationStatus::NotRevoked)
        }
    }
}

type Calls = Arc<Mutex<Vec<Value>>>;

/// Build a serving proxy with Phase 5 enforcement over the reference profile, whose
/// revocation is driven by the returned shared handle. The inner records every call
/// it receives so a denial can be proven by the inner NEVER being reached.
fn enforcing_proxy(revocation: SharedRevocationSource) -> (Proxy, Calls) {
    let calls: Calls = Arc::new(Mutex::new(Vec::new()));
    let calls_for_inner = Arc::clone(&calls);
    let inner = move |request: &[u8]| -> Vec<u8> {
        let value: Value = serde_json::from_slice(request).expect("inner parses");
        let id = value.get("id").cloned().unwrap_or(Value::Null);
        calls_for_inner.lock().unwrap().push(value);
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": id,
            "result": { "content": [ { "type": "text", "text": "ok" } ] }
        }))
        .expect("serialize inner response")
    };
    let mut evaluator = PolicyEvaluator::new();
    evaluator.register(Box::new(ReferenceProfile::new()));
    let proxy = Proxy::new(
        server_key(),
        SERVER,
        SERVER_KEY_ID,
        Box::new(resolver()),
        AUDIENCE,
        SKEW,
    )
    .with_async_inner(Box::new(inner))
    .with_policy_enforcement(evaluator, Box::new(revocation));
    (proxy, calls)
}

fn grant_spec() -> ReferenceGrantSpec {
    ReferenceGrantSpec {
        issuer: ISSUER.to_string(),
        grantee: SIGNER.to_string(),
        subject: ON_BEHALF_OF.to_string(),
        audience: AUDIENCE.to_string(),
        operations: vec![GrantedOperation {
            method: "tools/call".to_string(),
            tool: "echo".to_string(),
            arguments: None,
        }],
        not_before: GRANT_NOT_BEFORE.to_string(),
        expires_at: GRANT_EXPIRES_AT.to_string(),
        revocation_id: REVOCATION_ID.to_string(),
    }
}

/// Sign a `tools/call echo` leg carrying the opaque `requestState` resume payload,
/// and — when `with_grant` — its own reference-profile authorization block. Each
/// leg is a standalone signed MCP-RE request (ADR-024: a leg, not a session).
fn signed_leg(id: &str, nonce: &str, with_grant: bool) -> Vec<u8> {
    let artifact = mint_reference_grant(&grant_spec(), &issuer_key(), ISSUER_KEY_ID)
        .expect("mint reference grant");
    let authorization_hash = sha256_hash_id(&canonicalize(&artifact).expect("canonicalize grant"));

    let mut params = Map::new();
    params.insert("name".to_string(), json!("echo"));
    params.insert("arguments".to_string(), json!({ "text": "hello" }));
    // The SEP-2322 resume payload rides as an ordinary signed params member.
    params.insert("requestState".to_string(), json!(REQUEST_STATE));
    if with_grant {
        let mut meta = Map::new();
        meta.insert(
            AUTHORIZATION_META_KEY.to_string(),
            json!({ "profile": REFERENCE_PROFILE_ID, "artifact": b64url_encode(&artifact) }),
        );
        params.insert("_meta".to_string(), Value::Object(meta));
    }
    host()
        .sign_request(
            &Value::String(id.to_string()),
            "tools/call",
            params,
            ON_BEHALF_OF,
            AUDIENCE,
            &authorization_hash,
            nonce,
            ISSUED_AT,
            EXPIRES_AT,
        )
        .expect("host signs the leg")
}

fn error_message(bytes: &[u8]) -> String {
    let value: Value = serde_json::from_slice(bytes).expect("parse error response");
    value["error"]["message"]
        .as_str()
        .expect("error message")
        .to_string()
}

/// Vector 5, literal wording: a later leg is independently authorized; revoking the
/// grant BETWEEN legs fails the continuation closed.
#[test]
fn revoking_authorization_between_legs_fails_the_continuation_closed() {
    let revocation = SharedRevocationSource::new();
    let (proxy, calls) = enforcing_proxy(revocation.clone());

    // Leg 1 — an authorized first-round call. It reaches the inner and is served.
    let leg1 = signed_leg("req-1", NONCE_LEG_1, true);
    let expected_hash =
        request_hash(&serde_json::from_slice::<Value>(&leg1).unwrap()).expect("leg-1 request hash");
    let resp1 = block_on_handle(&proxy, &leg1, now());
    assert_eq!(
        calls.lock().unwrap().len(),
        1,
        "leg 1 is authorized and must reach the inner exactly once"
    );
    verify_response(&resp1, &server_resolver(), &expected_hash)
        .expect("leg 1's response verifies and binds");

    // Authorization is revoked mid-exchange (e.g. the user's grant is pulled).
    revocation.revoke(REVOCATION_ID);

    // Leg 2 — the continuation: a fresh nonce, the SAME opaque requestState, the
    // SAME still-structurally-valid grant. It must be re-evaluated per leg and fail
    // closed on the revocation; the earlier allow is NOT inherited.
    let leg2 = signed_leg("req-2", NONCE_LEG_2, true);
    let resp2 = block_on_handle(&proxy, &leg2, now());

    assert_eq!(
        calls.lock().unwrap().len(),
        1,
        "the revoked continuation must NOT reach the inner — still exactly one call"
    );
    assert_eq!(
        error_message(&resp2),
        "mcp-re.authorization_revoked",
        "revoking authorization between legs fails the continuation closed"
    );
}

/// Vector 5, the mechanism the ADR names: `requestState` inherits no authorization.
/// A continuation echoing leg 1's exact resume payload but carrying no authorization
/// block of its own is denied — the opaque payload transports no grant.
#[test]
fn request_state_confers_no_inherited_authorization() {
    let revocation = SharedRevocationSource::new();
    let (proxy, calls) = enforcing_proxy(revocation);

    // Leg 1 — authorized, served, and yields the requestState the client will echo.
    let leg1 = signed_leg("req-1", NONCE_LEG_1, true);
    let resp1 = block_on_handle(&proxy, &leg1, now());
    assert!(
        serde_json::from_slice::<Value>(&resp1).unwrap().get("error").is_none(),
        "leg 1 is authorized and served"
    );
    assert_eq!(calls.lock().unwrap().len(), 1, "leg 1 reaches the inner");

    // Leg 2 — a continuation echoing the SAME requestState but presenting NO
    // authorization block. It cannot ride leg 1's allow via requestState.
    let leg2 = signed_leg("req-2", NONCE_LEG_2, false);
    assert_eq!(
        serde_json::from_slice::<Value>(&leg2).unwrap()["params"]["requestState"],
        json!(REQUEST_STATE),
        "the continuation carries leg 1's opaque resume payload verbatim"
    );
    let resp2 = block_on_handle(&proxy, &leg2, now());

    assert_eq!(
        calls.lock().unwrap().len(),
        1,
        "the unauthorized continuation must NOT reach the inner"
    );
    assert_eq!(
        error_message(&resp2),
        "mcp-re.authorization_block_missing",
        "requestState carries no inherited authorization — the leg needs its own grant"
    );
}
