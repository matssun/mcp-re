// SPDX-License-Identifier: Apache-2.0
//! Method-transparency behavioral guard (ADR-MCPS-030/034), on the RFC 9421 carrier
//! (ADR-MCPRE-050). MCP-RE is method-transparent: the verify verdict is a function
//! of the evidence, NEVER of the JSON-RPC method name. This is the §A "Tool safety"
//! witness (behavioral half of the ADR-MCPS-036 #150 pair).

use mcp_re_core::SigningKey;
use mcp_re_http_profile::sign_request_full;
use mcp_re_http_profile::verify_request_full;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpRequestEvidenceBlock;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;
use mcp_re_http_profile::PROFILE_TAG;

const SEED: [u8; 32] = [11u8; 32];
const NOW: i64 = 1_700_000_100;
const CREATED: i64 = 1_700_000_000;
const EXPIRES: i64 = 1_700_000_300;
const TARGET: &str = "https://mcp.example.com/mcp?route=a";
const TOKEN: &str = "access-token-xyz";
const KID: &str = "client-key-1";

fn key() -> SigningKey {
    SigningKey::from_seed_bytes(&SEED)
}
fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: "verifier-1".into(),
        target_uri: TARGET.into(),
        route: Some("a".into()),
    }
}
fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    move |kid: &str, slot: SignerSlot| match (kid, slot) {
        (KID, SignerSlot::Request) => Some(ResolvedActor {
            identity: ActorIdentity {
                role: "client".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:host-a".into(),
                keyid: KID.into(),
            },
            verification_key: key().public_key(),
            slot,
        }),
        _ => None,
    }
}
fn block() -> HttpRequestEvidenceBlock {
    HttpRequestEvidenceBlock {
        profile: PROFILE_TAG.into(),
        audience: audience(),
        artifact_bindings: vec![ArtifactBinding::opaque_digest(ArtifactType::OauthDpop, TOKEN.as_bytes())],
        continuation: None,
    }
}

/// The verify verdict is ACCEPTED identically for every JSON-RPC method — the
/// evidence, not the method name, decides. A method-name branch would show up as a
/// differing verdict here.
#[test]
fn accepted_verdict_is_identical_across_all_methods() {
    let methods = [
        "tools/call",
        "tools/list",
        "resources/read",
        "resources/list",
        "prompts/get",
        "completion/complete",
        "an/unknown/method",
    ];
    let material = |_b: &ArtifactBinding| None;
    for (i, method) in methods.iter().enumerate() {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{{"name":"x"}}}}"#
        );
        let mut req = HttpRequest {
            method: "POST".into(),
            target_uri: TARGET.into(),
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
                ("Authorization".into(), format!("Bearer {TOKEN}")),
            ],
            body: body.into_bytes(),
        };
        sign_request_full(&mut req, &block(), &key(), KID, CREATED, EXPIRES, &format!("nonce-{i}"))
            .expect("sign");
        let verdict = verify_request_full(&req, &audience(), &material, &resolver(), NOW);
        assert!(
            verdict.is_ok(),
            "method {method:?} must produce the SAME accepted verdict — the verdict is \
             method-transparent (evidence-driven), never method-name-driven"
        );
    }
}
