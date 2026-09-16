// SPDX-License-Identifier: Apache-2.0
//! The continuation correlation KEY: which namespace an open leg is recorded in.
//!
//! Its own module because deriving the key and storing under it are two authorities. This
//! one is a pure function of three public identifiers and holds no state, no I/O and no
//! contract with an implementation; what it decides is the SCOPE a continuation lives in,
//! and that decision is what keeps one actor's approval out of another's reach. The trait
//! next door decides what may be done to an entry once its namespace is settled.
//!
//! Keeping them apart is not tidiness. The properties differ in kind: the store's are about
//! occupancy and atomicity, and are measured against a running tier; these are algebraic
//! properties of an encoding — injectivity over the triple, and domain separation from every
//! other SHA-256 the profile computes — and are measured against nothing but the function.

/// The key prefix for a continuation correlation entry in the shared store.
pub const CONTINUATION_KEY_PREFIX: &str = "mcp-re:cont:";

/// Domain separator, so this digest cannot collide with any other SHA-256 the
/// profile computes over the same bytes.
const CONTINUATION_KEY_DOMAIN: &[u8] = b"mcp-re/continuation-key/v1";

/// Derive the shared-store key for a continuation from the dispatch AUDIENCE, the
/// RESOLVED ACTOR and the opaque `requestState` bytes:
/// `mcp-re:cont:<b64url(SHA-256(domain || len(aud) || aud || len(actor) || actor || state))>`.
///
/// Both legs derive it the same way: the open leg from the state it minted into the reply,
/// the answer leg from the state the client re-presents. Why it is the VERIFIER's actor is
/// the module header's argument and is not restated here.
///
/// The AUDIENCE is in the key as it is in the replay composite key. Without it two
/// MCP-RE deployments — different audiences, different inner backends —
/// pointed at one Redis share a single continuation namespace, and nothing in config
/// or code enforced the assumption that they would not be. An actor trusted by both
/// could then open a leg against one dispatch boundary and answer it against the
/// other. The audience is what makes a signed request valid HERE and nowhere else, so
/// it belongs in any key that crosses a shared store.
///
/// Every boundary between the fields is pinned: `audience_id` and `actor_id` each carry
/// their length, and `request_state` is last, so the remaining bytes are all of it. No
/// tuple can be spelled as a different one by moving a boundary — which is the property;
/// a length prefix on the final field would add nothing to it.
///
/// `actor_id` is `role:trust_domain:subject:keyid`, so the scope is the KEY, not the
/// subject: both legs must be signed with the same key. This is a narrower identity than
/// the replay tier's `principal`, which drops the keyid deliberately
/// (`mcp_re_http_profile::replay`) — the two co-located designs do not use one notion of
/// "the same actor", and the difference is load-bearing in both directions. Here it is
/// what keeps a second key from collecting a human approval it did not ask for; there it
/// is what keeps one subject's rotation from reading as several budgets.
pub fn continuation_key(audience_id: &str, actor_id: &str, request_state: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(CONTINUATION_KEY_DOMAIN);
    hasher.update((audience_id.len() as u64).to_be_bytes());
    hasher.update(audience_id.as_bytes());
    hasher.update((actor_id.len() as u64).to_be_bytes());
    hasher.update(actor_id.as_bytes());
    hasher.update(request_state);
    format!(
        "{CONTINUATION_KEY_PREFIX}{}",
        mcp_re_core::b64url_encode(&hasher.finalize())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dispatch boundary the key is scoped to; a second deployment on the same
    /// shared store has a different one.
    const AUD: &str = "did:example:server-1";
    const ACTOR_A: &str = "client:example.com:did:example:host-a:client-key-1";
    const ACTOR_B: &str = "client:example.com:did:example:host-b:client-key-2";

    /// Two deployments sharing one Redis must not share one continuation namespace.
    /// The audience is what makes a signed request valid at THIS dispatch boundary,
    /// so an actor trusted by both cannot open a leg against one and answer it
    /// against the other.
    #[test]
    fn the_key_is_scoped_to_the_audience() {
        let here = continuation_key(AUD, ACTOR_A, b"state-1");
        let elsewhere = continuation_key("did:example:server-2", ACTOR_A, b"state-1");
        assert_ne!(here, elsewhere);
    }

    #[test]
    fn key_is_stable_and_specific_to_both_inputs() {
        assert_eq!(
            continuation_key(AUD, ACTOR_A, b"abc"),
            continuation_key(AUD, ACTOR_A, b"abc")
        );
        assert_ne!(
            continuation_key(AUD, ACTOR_A, b"abc"),
            continuation_key(AUD, ACTOR_A, b"abd")
        );
        assert_ne!(
            continuation_key(AUD, ACTOR_A, b"abc"),
            continuation_key(AUD, ACTOR_B, b"abc")
        );
        assert!(continuation_key(AUD, ACTOR_A, b"abc").starts_with(CONTINUATION_KEY_PREFIX));
    }

    /// No boundary in the key can be moved — over BOTH of the key's interior boundaries,
    /// which is what the derivation claims.
    ///
    /// The actor/state half is the reachable attack: without `actor_id`'s length prefix
    /// `("ab", "c")` and `("a", "bc")` hash the same bytes, and one actor names another's
    /// entry by spelling the split differently.
    ///
    /// The audience/actor half needs a constructed witness, and the construction is the
    /// point. `("ab", "c")` versus `("a", "bc")` does NOT separate it — the actor prefix
    /// that follows pins that boundary from the right — so the obvious pair passes
    /// whether `audience_id` carries its length or not, and a control written that way
    /// would report a check it never exercised. Moving this boundary means absorbing the
    /// FOLLOWING length prefix into the audience, which is what the pair below does: the
    /// two tuples differ, and their unprefixed encodings are byte-identical.
    #[test]
    fn no_boundary_between_the_keys_fields_can_be_moved() {
        assert_ne!(
            continuation_key(AUD, "ab", b"c"),
            continuation_key(AUD, "a", b"bc")
        );

        // ("A", "X", 0x00*8 ++ "Z") and ("A" ++ len8("X") ++ "X", "", "Z") encode to the
        // same bytes once `audience_id`'s length is dropped: the first tuple's actor
        // prefix becomes part of the second tuple's audience.
        let mut state = vec![0u8; 8];
        state.push(b'Z');
        assert_ne!(
            continuation_key("A", "X", &state),
            continuation_key("A\0\0\0\0\0\0\0\u{1}X", "", b"Z")
        );
    }
}
