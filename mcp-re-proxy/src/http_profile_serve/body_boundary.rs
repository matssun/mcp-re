// SPDX-License-Identifier: Apache-2.0
//! The PEP's read/write boundary inside the client's JSON-RPC body (#415 rev 2 §10,
//! MCPRE-429, ADR-MCPS-047).
//!
//! One fact, stated here and nowhere else: **the enforcement boundary's interest in the
//! body is confined to named fields, and everything else passes through untouched.**
//! Three named fields exist — `params.requestState`, which the proxy READS to key the
//! correlation store and never interprets; the PEP-owned `_meta` request-evidence block,
//! which it STRIPS because it has just consumed it; and the reserved verified-context
//! `_meta` key, which it WRITES and which a caller may therefore never author.
//!
//! Keeping them together is what makes the §10 guard checkable. The guard is not "strip
//! `_meta`" — that would destroy application data the PEP was asked to pass through — it
//! is "the PEP removes exactly what it owns, then writes exactly what it is entitled to
//! assert". The profile crate joins those halves by TYPE: the write takes a
//! `StrippedBody`, which only the guard produces.
//!
//! [`ForwardedBody`] is sealed: its representation is private, [`ForwardedBody::prepare`]
//! is its only producer, and the bytes are obtained only by
//! [`ForwardedBody::into_bytes_for_inner`], which names a caller's attempt as it hands
//! them over. The seal reaches to that call and stops: what leaves is an ordinary
//! `Vec<u8>`, so "the guard ran" is a fact about this stage, not about the path to the
//! backend.
//!
//! **Fidelity.** The forwarded bytes are a re-serialization under EVERY policy, so the
//! guarantee outside the PEP-owned keys is JSON-value equality and never byte identity.
//! The inner server does not receive the bytes the client's `Content-Digest` covered and
//! cannot re-check a signature over them; no downstream check may assume otherwise.

use mcp_re_http_profile::context::SeededMetaPositions;
use mcp_re_http_profile::context::StrippedBody;
use mcp_re_http_profile::insert_verified_context;
use mcp_re_http_profile::strip_proxy_owned_meta;
use mcp_re_http_profile::HttpProfileError;
use mcp_re_http_profile::VerifiedContext;
use mcp_re_http_profile::VerifiedContextPolicy;
use mcp_re_http_profile::VerifiedMcpRequest;

/// Read `params.requestState` (a string) from a JSON-RPC request body — the opaque
/// MRTR state an answer leg re-presents (ADR-MCPS-047). `None` if the body is not
/// JSON, has no `params.requestState`, or it is not a string.
///
/// The value is read only to KEY the correlation store; it is never interpreted, and
/// what it binds to is settled by digest equality against the retained bases.
///
/// Total where the §10 guard on the same body is fallible, deliberately. The distinction between "no
/// continuation presented" and "one presented in a shape this cannot key on" is not made
/// here and must not be: the caller's own SIGNED evidence block makes it, and the answer
/// leg reads this member only once that block declares a continuation. An unreadable
/// member under a declared continuation therefore yields no key, no bases, and a
/// caller-attributed `continuation_binding_failed` — fail-closed, one stage on.
pub fn extract_request_state(body: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    v.get("params")?
        .get("requestState")?
        .as_str()
        .map(str::to_owned)
}

/// Remove exactly the `_meta` keys the PEP owns, returning the guarded body as the value
/// the write half requires, and refusing a body shape the guard declines to walk.
///
/// Separated from [`ForwardedBody::prepare`] because this half is the §10 guard proper and
/// runs under EVERY policy, so it is the half that must be checkable on its own: that the
/// PEP removes what it owns and leaves what it does not is a property of the request body
/// alone, with no verified request and no policy in it.
fn strip_pep_owned(body: &[u8]) -> Result<StrippedBody, HttpProfileError> {
    // The bytes are re-serialized by the guard, which cannot carry a duplicate member name
    // or a number the f64 carrier alters. That question is asked at the request-envelope
    // boundary, on the original bytes and before admission spends anything, so a body that
    // reaches this function has already answered it — asking again here would be a second
    // opinion on a decision that has an owner, and the one thing it could still change is
    // which stage a refusal is attributed to.
    strip_proxy_owned_meta(body)
}

/// The diagnostic line naming a caller's reserved-key attempt.
///
/// A function rather than an inline `eprintln!` so the line the boundary emits is a value
/// a test can assert on. Two properties it owns: `actor_id` is written through `{:?}`, so
/// no inhabitant of the identity type can forge a second line in the stream that records
/// the attempt; and the position list is truncated, so the line's length is the
/// boundary's choice and not the caller's.
fn seeding_report(actor_id: &str, seeded: &SeededMetaPositions) -> String {
    const NAMED: usize = 8;
    let positions = seeded.positions();
    let shown = positions
        .iter()
        .take(NAMED)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    let unnamed = positions.len().saturating_sub(NAMED);
    let tail = if unnamed == 0 {
        String::new()
    } else {
        format!(" (+{unnamed} more)")
    };
    format!(
        "mcp-re-proxy: warning: request from actor {actor_id:?} seeded the reserved \
         verified-context `_meta` key at {shown}{tail}; stripped before forwarding \
         (the inner server never saw it)"
    )
}

/// The body the inner server receives, and the §10 guard's detection signal.
///
/// Private fields: holding one means the PEP-owned keys have been removed and, under
/// `Trusted`, the PEP's own context has been written. There is no way to assemble the
/// pair from outside this module and no way to read the bytes without the seeded-key
/// attempt being reported.
pub(super) struct ForwardedBody {
    /// The clean JSON-RPC bytes the inner server receives.
    body: Vec<u8>,
    /// Which `_meta` positions the caller had seeded with the reserved verified-context
    /// key. The value was stripped from every one of them; this is the only trace the
    /// attempt leaves, so the boundary names it rather than discarding it — and names the
    /// positions, because the position is the interesting fact about the method.
    seeded: SeededMetaPositions,
}

impl ForwardedBody {
    /// Compose the body forwarded to the inner server.
    ///
    /// Three steps, in this order:
    ///
    /// 0. **Refuse bytes that are not the verified request's own.** Stamping a conclusion
    ///    about one document onto another would hand the inner server a verdict about
    ///    bytes it never sees, and the carrier has no signature for it to notice with.
    ///    [`VerifiedMcpRequest::covers_body`] owns the comparison; this asks it.
    ///
    /// 1. **Strip the PEP-owned `_meta` keys.** The §10 guard, and it runs on EVERY
    ///    request regardless of policy: a caller that could seed the reserved key would
    ///    be asserting its own verified context to a server that trusts the block
    ///    implicitly, and a deployment with the carrier disabled must not be one config
    ///    flip away from forwarding that. Only PEP-owned keys are removed.
    ///
    /// 2. **Write the PEP's own context**, only under an explicitly trusted channel, and
    ///    only into the guarded body step 1 produced — which is a type, not an ordering.
    ///
    /// Returns `Err` if the trusted carrier is enabled and the context could not be
    /// written: under `Trusted` the inner server is entitled to assume the PEP speaks, so
    /// forwarding without the context it expects would be a silent downgrade to an
    /// unauthenticated call that looks ordinary.
    pub(super) fn prepare(
        body: &[u8],
        verified: &VerifiedMcpRequest,
        policy: VerifiedContextPolicy,
        now: i64,
    ) -> Result<Self, HttpProfileError> {
        if !verified.covers_body(body) {
            return Err(HttpProfileError::MalformedEvidence(
                "forwarded body is not the verified request body",
            ));
        }
        let stripped = strip_pep_owned(body)?;
        // The capability, not the selector: `trusted_inner_channel` is the only producer
        // of the value `insert_verified_context` requires, so the write is reachable only
        // from the deployment act that authorized it.
        let body = match policy.trusted_inner_channel() {
            None => stripped.bytes().to_vec(),
            Some(trusted_channel) => {
                let ctx = VerifiedContext::from_verified(verified, now);
                insert_verified_context(&stripped, &ctx, trusted_channel)?
            }
        };
        Ok(Self {
            body,
            seeded: stripped.into_seeded(),
        })
    }

    /// The bytes the inner server receives, naming a caller's reserved-key attempt as they
    /// are handed over.
    ///
    /// The report is not a separate step the assembly must remember: the bytes leave this
    /// type only through here, so an attempt cannot reach the backend path unnamed. SCOPE:
    /// that holds up to this call and no further — what returns is a `Vec<u8>` like any
    /// other, and no later stage carries the fact that the guard ran.
    ///
    /// `actor_id` is the exchange's resolved actor, not a value this call site chooses:
    /// `Exchange::actor_id` is private, assigned once from `resolved_actor().actor_id()`.
    ///
    /// A deliberate attempt to assert one's own authentication context to the inner server
    /// is exactly what this surface exists to detect. The frozen audit vocabulary has no
    /// event for it (ADR-MCPS-035 §3 admits no third success event), so it is named on the
    /// diagnostic channel rather than left with no trace at all.
    pub(super) fn into_bytes_for_inner(self, actor_id: &str) -> Vec<u8> {
        if self.seeded.any() {
            eprintln!("{}", seeding_report(actor_id, &self.seeded));
        }
        self.body
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_core::SigningKey;
    use mcp_re_http_profile::content_digest_sha256;
    use mcp_re_http_profile::ActorIdentity;
    use mcp_re_http_profile::AudienceTuple;
    use mcp_re_http_profile::CryptographicFloorVerifiedRequest;
    use mcp_re_http_profile::HttpRequestEvidenceBlock;
    use mcp_re_http_profile::ResolvedActor;
    use mcp_re_http_profile::SignerSlot;
    use mcp_re_http_profile::VERIFIED_CONTEXT_BLOCK_KEY;

    const NOW: i64 = 1_700_000_100;

    fn audience() -> AudienceTuple {
        AudienceTuple {
            audience_id: "aud".into(),
            target_uri: "https://example.test/mcp".into(),
            route: None,
        }
    }

    /// A verified request that COVERS `body` — the pairing `prepare` now requires.
    fn verified_for(body: &[u8]) -> VerifiedMcpRequest {
        let key = SigningKey::from_seed_bytes(&[7u8; 32]);
        VerifiedMcpRequest {
            floor: CryptographicFloorVerifiedRequest {
                profile_id: "p".into(),
                signature_label: "mcpre".into(),
                resolved_actor: ResolvedActor {
                    identity: ActorIdentity {
                        role: "client".into(),
                        trust_domain: "example.com".into(),
                        subject: "did:example:a".into(),
                        keyid: "k".into(),
                    },
                    verification_key: key.public_key(),
                    slot: SignerSlot::Request,
                },
                evidence: mcp_re_http_profile::RequestRoleEvidence::from_signature_base(b"base"),
                request_signature_base: b"base".to_vec(),
                content_digest: content_digest_sha256(body),
                created: 1_700_000_000,
                expires: 1_700_000_300,
                nonce: "n".into(),
                key_id: "k".into(),
            },
            audience: audience(),
            audience_hash: audience().audience_hash(),
            request_block: HttpRequestEvidenceBlock {
                profile: "p".into(),
                audience: audience(),
                artifact_bindings: Vec::new(),
                continuation: None,
                admission: None,
                admission_assertion: None,
                authorization_decision: None,
            },
        }
    }

    fn seeded_body() -> Vec<u8> {
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read","_meta":{{"{VERIFIED_CONTEXT_BLOCK_KEY}":{{"actor_id":"root-admin"}},"app.keep":"v"}}}}}}"#
        )
        .into_bytes()
    }

    fn prepared(body: &[u8], policy: VerifiedContextPolicy) -> ForwardedBody {
        ForwardedBody::prepare(body, &verified_for(body), policy, NOW)
            .expect("an ordinary verified body prepares")
    }

    #[test]
    fn request_state_is_read_only_as_a_string_under_params() {
        assert_eq!(
            extract_request_state(br#"{"params":{"requestState":"s-1"}}"#),
            Some("s-1".to_owned())
        );
        // Not JSON, no `params`, no `requestState`, and a non-string one all read as
        // absent: the value keys a store, so anything that is not the opaque string the
        // client presented is no key at all.
        assert_eq!(extract_request_state(b"not json"), None);
        assert_eq!(extract_request_state(br#"{"params":{}}"#), None);
        assert_eq!(extract_request_state(br#"{"requestState":"s-1"}"#), None);
        assert_eq!(
            extract_request_state(br#"{"params":{"requestState":7}}"#),
            None
        );
    }

    #[test]
    fn application_meta_survives_the_pep_owned_strip() {
        // The §10 guard is not "delete `_meta`". A boundary that removed the whole block
        // would be destroying data the PEP was asked to pass through, and the difference
        // is only observable on a body carrying an application entry.
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"app.trace":"t-1"}}}"#;
        let stripped = strip_pep_owned(body).expect("a well-formed body strips");
        assert!(
            !stripped.seeded().any(),
            "no reserved key was present, so nothing was attempted"
        );
        let v: serde_json::Value = serde_json::from_slice(stripped.bytes()).expect("json out");
        assert_eq!(
            v["params"]["_meta"]["app.trace"], "t-1",
            "an application `_meta` entry is none of the enforcement boundary's business"
        );
    }

    #[test]
    fn an_unrepresentable_body_is_refused_before_any_reserialization() {
        // A body whose meaning changes under re-serialization never reaches the backend,
        // and the owner of that is the request-envelope boundary, where the refusal is free.
        // Asserted against the owner rather than against this composer, which asks nothing
        // and would otherwise look like a second opinion on the same question.
        assert!(
            mcp_re_http_profile::validate_request_envelope(
                br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"a":1,"a":2}}"#
            )
            .is_err(),
            "a body whose meaning changes under re-serialization never reaches the backend"
        );
    }

    /// A body the guard cannot enumerate the reserved-key positions of is REFUSED here
    /// rather than forwarded. The shapes are already refused by the request-envelope
    /// boundary, before admission spends anything — this is the composer declining to
    /// hand on bytes nobody inspected, whatever reaches it.
    #[test]
    fn a_body_the_guard_cannot_reach_is_refused_rather_than_forwarded() {
        assert!(strip_pep_owned(b"not json").is_err());
        assert!(strip_pep_owned(br#"[{"jsonrpc":"2.0"}]"#).is_err());
        assert!(strip_pep_owned(br#"{"jsonrpc":"2.0","params":"positional"}"#).is_err());
    }

    /// The forwarded bytes name WHICH position was seeded, for every position the guard
    /// reaches, so an operator investigating the attempt gets the attacker's method.
    #[test]
    fn the_seeded_positions_are_named_on_the_forwarded_body() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":[{"_meta":{"se.syncom/mcp-re.verified-context":{"actor_id":"admin"}}}]}"#;
        let stripped = strip_pep_owned(body).expect("a positional params body strips");
        assert_eq!(
            stripped.seeded().positions(),
            vec!["params[0]._meta".to_owned()]
        );
        assert!(stripped.seeded().any());
    }

    // ----- the composer itself, in the lane that compiles it -----

    /// THE guard runs under BOTH policies. A caller-seeded reserved key never reaches the
    /// inner server whether or not the carrier is enabled, and the application's own
    /// `_meta` entry beside it survives either way.
    #[test]
    fn prepare_strips_the_reserved_key_under_every_policy() {
        for policy in [
            VerifiedContextPolicy::Disabled,
            VerifiedContextPolicy::Trusted,
        ] {
            let body = seeded_body();
            let forwarded = prepared(&body, policy).into_bytes_for_inner("actor");
            let text = String::from_utf8(forwarded.clone()).expect("utf-8 out");
            assert!(
                !text.contains("root-admin"),
                "{policy:?}: the caller's forged context reached the inner server"
            );
            let v: serde_json::Value = serde_json::from_slice(&forwarded).expect("json out");
            assert!(v["params"]["_meta"]
                .get(VERIFIED_CONTEXT_BLOCK_KEY)
                .is_none());
            // POSITIVE CONTROL: the application's own entry beside it is untouched.
            assert_eq!(v["params"]["_meta"]["app.keep"], serde_json::json!("v"));
        }
    }

    /// The policy branch: the PEP's own block is written under `Trusted` and under
    /// `Disabled` no block is present at all.
    #[test]
    fn prepare_writes_the_peps_block_only_under_trusted() {
        let body = seeded_body();

        let trusted = prepared(&body, VerifiedContextPolicy::Trusted).into_bytes_for_inner("a");
        let ctx = mcp_re_http_profile::extract_verified_context(&trusted)
            .expect("under Trusted the inner server is handed the PEP's block");
        assert_eq!(ctx.claimed_key_id(), "k");
        assert_ne!(ctx.claimed_actor_id(), "root-admin");

        let disabled = prepared(&body, VerifiedContextPolicy::Disabled).into_bytes_for_inner("a");
        assert!(
            mcp_re_http_profile::extract_verified_context(&disabled).is_err(),
            "with the carrier off the reserved key is gone entirely"
        );
    }

    /// The conclusion is about THESE bytes. A verified request paired with a different
    /// body is refused rather than stamped onto it.
    #[test]
    fn prepare_refuses_a_body_the_verified_request_does_not_cover() {
        let body = seeded_body();
        let other = br#"{"jsonrpc":"2.0","id":2,"method":"tools/call"}"#;
        assert!(
            ForwardedBody::prepare(
                other,
                &verified_for(&body),
                VerifiedContextPolicy::Trusted,
                NOW
            )
            .is_err(),
            "a conclusion about one document must not be stamped onto another"
        );
        // POSITIVE CONTROL: the matching pair still prepares.
        assert!(ForwardedBody::prepare(
            other,
            &verified_for(other),
            VerifiedContextPolicy::Trusted,
            NOW
        )
        .is_ok());
    }

    /// FAIL CLOSED: under `Trusted`, a body whose top-level `_meta` occupies the PEP's
    /// write position makes the composer refuse rather than forward a context-free
    /// request that looks ordinary. Under `Disabled` the same body is forwarded, because
    /// nothing is written.
    #[test]
    fn prepare_fails_closed_under_trusted_when_the_block_cannot_be_written() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","_meta":[1,2]}"#;
        assert!(ForwardedBody::prepare(
            body,
            &verified_for(body),
            VerifiedContextPolicy::Trusted,
            NOW
        )
        .is_err());
        assert!(ForwardedBody::prepare(
            body,
            &verified_for(body),
            VerifiedContextPolicy::Disabled,
            NOW
        )
        .is_ok());
    }

    /// The report a caller's attempt produces is a value, so what the operator's only
    /// trace says is observable: the positions are named, the identity is escaped, and
    /// the line's length is the boundary's choice.
    #[test]
    fn the_seeding_report_names_positions_escapes_the_actor_and_is_bounded() {
        let seeded = strip_pep_owned(&seeded_body())
            .expect("the seeded body strips")
            .into_seeded();
        let line = seeding_report("client:example.com:a:k", &seeded);
        assert!(line.contains("params._meta"), "the position is named");
        assert!(
            line.contains("\"client:example.com:a:k\""),
            "the identity is written through its escaped form"
        );

        // A caller cannot choose the line's length, and cannot forge a second line.
        let many = (0..40)
            .map(|i| format!(r#"{{"_meta":{{"{VERIFIED_CONTEXT_BLOCK_KEY}":{i}}}}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let wide = format!(r#"{{"jsonrpc":"2.0","params":[{many}]}}"#).into_bytes();
        let wide = strip_pep_owned(&wide).expect("strips").into_seeded();
        let line = seeding_report("evil\nmcp-re-proxy: warning: forged", &wide);
        assert!(
            line.contains("(+32 more)"),
            "the position list is truncated"
        );
        assert_eq!(line.lines().count(), 1, "the report is one line");
    }
}
