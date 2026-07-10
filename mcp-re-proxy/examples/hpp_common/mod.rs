// SPDX-License-Identifier: Apache-2.0
//! Shared demo material for the HTTP-profile proof pair (`http_profile_proxy`
//! server + `http_profile_client` driver). NOT a standalone example — it lives in
//! a subdirectory so cargo does not compile it as its own binary; each example
//! pulls it in with `#[path = "hpp_common/mod.rs"] mod hpp_common;`.
//!
//! The identities/keys are DETERMINISTIC demo seeds (same pattern as
//! `tests/http_profile_dispatch_test.rs`) so client and server agree without a
//! shared key file. Addresses/target come from the environment — the launcher
//! resolves them from `config/ports.toml`, so no port literal is baked in here.

use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use mcp_re_core::SigningKey;
use mcp_re_http_profile::ActorIdentity;
use mcp_re_http_profile::AudienceTuple;
use mcp_re_http_profile::ResolvedActor;
use mcp_re_http_profile::SignerSlot;

/// Demo client request-signing seed (Ed25519). Deterministic — proof material.
pub const CLIENT_SEED: [u8; 32] = [11u8; 32];
/// Demo server response-signing seed (Ed25519). Deterministic — proof material.
pub const SERVER_SEED: [u8; 32] = [22u8; 32];
pub const CLIENT_KEY_ID: &str = "client-key-1";
pub const SERVER_KEY_ID: &str = "server-key-1";
pub const TRUST_DOMAIN: &str = "example.com";
pub const CLIENT_SUBJECT: &str = "did:example:host-a";
pub const SERVER_SUBJECT: &str = "did:example:server-1";
pub const AUDIENCE_ID: &str = "verifier-1";
pub const ROUTE: &str = "a";
/// Demo access token bound by the request's OAuth DPoP artifact binding. The
/// evidence block requires at least one artifact binding; DPoP derives its
/// credential from the covered `Authorization: Bearer` header.
pub const ACCESS_TOKEN: &str = "access-token-xyz";

pub fn client_key() -> SigningKey {
    SigningKey::from_seed_bytes(&CLIENT_SEED)
}
pub fn server_key() -> SigningKey {
    SigningKey::from_seed_bytes(&SERVER_SEED)
}

pub fn client_identity() -> ActorIdentity {
    ActorIdentity {
        role: "client".into(),
        trust_domain: TRUST_DOMAIN.into(),
        subject: CLIENT_SUBJECT.into(),
        keyid: CLIENT_KEY_ID.into(),
    }
}

pub fn server_identity() -> ActorIdentity {
    ActorIdentity {
        role: "server".into(),
        trust_domain: TRUST_DOMAIN.into(),
        subject: SERVER_SUBJECT.into(),
        keyid: SERVER_KEY_ID.into(),
    }
}

/// The canonical `@target-uri` (RFC 9421) both sides use verbatim, from
/// `HPP_TARGET` (launcher-supplied, registry-derived). Signing covers this string,
/// so client and server MUST agree on it byte-for-byte.
pub fn target() -> String {
    std::env::var("HPP_TARGET").expect("HPP_TARGET must be set (e.g. http://127.0.0.1:8601/mcp)")
}

/// The verifier's audience tuple. `target_uri` must equal the request
/// `@target-uri` (verify_request_full enforces it).
pub fn audience() -> AudienceTuple {
    AudienceTuple {
        audience_id: AUDIENCE_ID.into(),
        target_uri: target(),
        route: Some(ROUTE.into()),
    }
}

/// The trust seam: the client key is trusted ONLY for the Request slot, the server
/// key ONLY for the Response slot (MCPRE-100 slot discipline). A key presented on
/// the wrong slot resolves to `None` → `actor_binding_failed`.
pub fn resolver() -> impl Fn(&str, SignerSlot) -> Option<ResolvedActor> {
    move |key_id: &str, slot: SignerSlot| match (key_id, slot) {
        (CLIENT_KEY_ID, SignerSlot::Request) => Some(ResolvedActor {
            identity: client_identity(),
            verification_key: client_key().public_key(),
            slot,
        }),
        (SERVER_KEY_ID, SignerSlot::Response) => Some(ResolvedActor {
            identity: server_identity(),
            verification_key: server_key().public_key(),
            slot,
        }),
        _ => None,
    }
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs() as i64
}
