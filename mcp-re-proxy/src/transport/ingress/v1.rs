// SPDX-License-Identifier: Apache-2.0
//! Mode B / Tier 3 — the frozen `mcp-re/lb-ingress-assertion/v1` assertion.
//!
//! One frozen wire format and everything that reads it: the domain-separation tag, the
//! length-prefixed preimage, the parser, the verifier and its rejection vocabulary. The
//! format is FROZEN (ADR-MCPS-023 §C1), which is why Mode C is a separate format in
//! [`super::v2`] rather than fields added here.
//!
//! Reachability is the facade's fact, not this module's: see [`super`].

use mcp_re_core::parse_hash_id;
use mcp_re_core::verify_ed25519_with;
use mcp_re_core::McpReError;
use mcp_re_core::VerificationKey;

use super::LbKeyEntry;
use crate::transport::IdentitySource;
use crate::transport::TransportIdentity;

// ---------------------------------------------------------------------------
// Tier 3 (ADR-MCPS-023, future-boundary, issue #71): LB-signed, request-bound
// ingress assertion.
// ---------------------------------------------------------------------------

/// The frozen domain-separation tag prefixed to every Tier-3 assertion preimage.
/// It namespaces the signature so an LB key reused for some other purpose cannot
/// produce bytes that an attacker can re-frame as an MCP-RE ingress assertion. The
/// trailing version byte (`v1`) lets the preimage format evolve without ambiguity.
const LB_ASSERTION_DOMAIN_TAG: &[u8] = b"mcp-re/lb-ingress-assertion/v1";

/// The default freshness window (seconds) for a Tier-3 LB assertion: how far the
/// assertion's `validation_time` may lag behind the node's `now_unix` and still be
/// accepted. Small by design — the LB signs the assertion at the moment it admits
/// the request, so a legitimate assertion reaches the node within seconds.
pub const DEFAULT_LB_ASSERTION_MAX_AGE_SECS: i64 = 30;

/// The parsed fields of a Tier-3 LB-signed ingress assertion (ADR-MCPS-023).
///
/// The assertion ties a **specific MCP-RE request** (by its `request_hash`) to the
/// asserted client identity, signed by the load balancer. Unlike the Tier-2
/// trusted-ingress header — which the node trusts solely over the authenticated
/// LB↔node hop — a Tier-3 assertion lets the node CRYPTOGRAPHICALLY verify that
/// the ingress bound its assertion to the exact request the node holds in hand.
///
/// # Honesty boundary
///
/// This is **request-bound ingress assertion**, NOT end-to-end client↔node
/// binding. The LB still terminates the client's mTLS and re-asserts the client
/// identity; the node verifies the LB's signature and the request binding, not the
/// client's own key. It MUST NOT be presented as equivalent to `end_to_end_mtls`
/// (Tier 1). See [`LbAssertionBinding::GUARANTEE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LbAssertion {
    /// The LB key id naming the verification key that signed this assertion.
    pub key_id: String,
    /// The asserted client identity (e.g. `spiffe://example.org/agent-1`).
    pub asserted_client_identity: String,
    /// The MCP-RE request hash the assertion is bound to, as the
    /// `sha256:<base64url>` hash identifier (MCP_RE_SPEC §3).
    pub request_hash: String,
    /// The LB's assertion time as a Unix timestamp (seconds). Freshness is checked
    /// against the node's `now_unix`.
    pub validation_time: i64,
}

impl LbAssertion {
    /// The deterministic, UNAMBIGUOUS canonical preimage the LB signs and the node
    /// re-derives to verify.
    ///
    /// Encoding is **length-prefixed framing**, NOT delimiter-joining, so no field
    /// value can ever collide with a delimiter to forge a different field split
    /// (the classic `a|b` vs `a` + `|b` ambiguity). The layout is:
    ///
    /// ```text
    /// LB_ASSERTION_DOMAIN_TAG
    /// || len(key_id)                    as u64 big-endian || key_id bytes
    /// || len(asserted_client_identity)  as u64 big-endian || identity bytes
    /// || len(request_hash)              as u64 big-endian || request_hash bytes
    /// || validation_time                as i64 big-endian (fixed 8 bytes)
    /// ```
    ///
    /// Every variable-length field is preceded by its exact byte length, so the
    /// byte stream parses to exactly one field tuple — two distinct field tuples
    /// can never produce the same preimage. The fixed-width integer needs no
    /// length prefix.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(LB_ASSERTION_DOMAIN_TAG);
        for field in [
            self.key_id.as_bytes(),
            self.asserted_client_identity.as_bytes(),
            self.request_hash.as_bytes(),
        ] {
            out.extend_from_slice(&(field.len() as u64).to_be_bytes());
            out.extend_from_slice(field);
        }
        out.extend_from_slice(&self.validation_time.to_be_bytes());
        out
    }
}

/// A node-side verifier for Tier-3 LB-signed, request-bound ingress assertions
/// (ADR-MCPS-023 future boundary, issue #71).
///
/// It holds a small in-proxy trust map of LB verification keys (keyed by key id)
/// and, given a presented assertion + the request hash the node already holds in
/// hand + the current time, yields a VERIFIED [`TransportIdentity`] only after a
/// strict, ordered, fail-closed sequence of checks (see [`Self::verify`]). The
/// resulting identity then flows into the SAME [`TransportBindingPolicy`] the
/// direct-TLS / Tier-2 paths use — this type does the cryptographic request-
/// binding; the binding policy ties the verified identity to the request signer.
///
/// # SECURITY — what this does and does NOT prove
///
/// This is **request-bound ingress assertion**, NOT end-to-end client↔node mTLS.
/// The node verifies the LB's signature over the (identity, request-hash, time)
/// tuple — proving the trusted LB asserted *this* client identity for *this*
/// request — but the client's own key never reaches the node. The LB remains in
/// the trusted computing base. The guarantee MUST NOT be surfaced as equivalent
/// to `end_to_end_mtls` (Tier 1); see [`Self::GUARANTEE`].
#[derive(Debug, Clone)]
pub struct LbAssertionBinding {
    /// Trusted LB verification keys, addressed by key id.
    keys: Vec<LbKeyEntry>,
    /// The identity source reported on the yielded [`TransportIdentity`].
    source: IdentitySource,
    /// Maximum accepted assertion age (seconds) relative to `now_unix`.
    max_age_secs: i64,
}

/// Why a Tier-3 LB assertion was rejected. Every variant fails closed (no identity
/// is yielded). Surfaced for tests and audit; the proxy maps any rejection to
/// [`McpReError::TransportBindingFailed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LbAssertionRejection {
    /// The assertion bytes are malformed (bad framing / not valid UTF-8 / bad
    /// base64) or a field violates the strict asserted-identity shape rules.
    Malformed,
    /// The assertion names a `key_id` not present in the trust map (fail closed —
    /// an unknown LB key is never admitted).
    UnknownKeyId,
    /// The Ed25519 signature does not verify under the named LB key.
    BadSignature,
    /// The assertion's bound `request_hash` does not equal the in-hand request hash
    /// (a cross-request / wrong-hash assertion).
    RequestHashMismatch,
    /// The assertion's `validation_time` is outside the freshness window (too old,
    /// or implausibly far in the future).
    Stale,
}

impl LbAssertionBinding {
    /// The honest Tier-3 guarantee string. Deliberately NOT `end_to_end_mtls`: the
    /// node cryptographically verifies that the trusted ingress bound its assertion
    /// to THIS request, but the client's own key never reaches the node, so this is
    /// request-bound ingress assertion, not end-to-end client↔node channel binding.
    pub const GUARANTEE: &'static str = "request_bound_ingress_assertion";

    /// Build a verifier with no trusted keys yet (every assertion fails closed
    /// until a key is added) and the default freshness window
    /// ([`DEFAULT_LB_ASSERTION_MAX_AGE_SECS`]). `source` is the [`IdentitySource`]
    /// stamped on the yielded identity (mirrors the configured identity policy).
    pub fn new(source: IdentitySource) -> Self {
        LbAssertionBinding {
            keys: Vec::new(),
            source,
            max_age_secs: DEFAULT_LB_ASSERTION_MAX_AGE_SECS,
        }
    }

    /// Override the freshness window (seconds).
    pub fn with_max_age_secs(mut self, max_age_secs: i64) -> Self {
        self.max_age_secs = max_age_secs;
        self
    }

    /// Add a trusted LB verification key addressed by `key_id`. A duplicate
    /// `key_id` REPLACES the prior key for that id (last write wins) so a rotating
    /// deployment cannot end up with two live keys for one id.
    pub fn add_key(&mut self, key_id: impl Into<String>, key: VerificationKey) {
        let key_id = key_id.into();
        self.keys.retain(|entry| entry.key_id != key_id);
        self.keys.push(LbKeyEntry { key_id, key });
    }

    /// Look up a trusted LB verification key by key id.
    fn key_for(&self, key_id: &str) -> Option<&VerificationKey> {
        self.keys
            .iter()
            .find(|entry| entry.key_id == key_id)
            .map(|entry| &entry.key)
    }

    /// Verify a presented Tier-3 assertion against the in-hand request hash and the
    /// current time, yielding the VERIFIED client identity on success.
    ///
    /// Ordered, fail-closed checks (ADR-MCPS-023 future boundary, issue #71):
    /// 1. **Parse** the assertion; malformed framing/shape ⇒ `Malformed`.
    /// 2. **Key lookup** — an unknown `key_id` ⇒ `UnknownKeyId` (fail closed; never
    ///    admit an assertion signed by a key the node does not trust).
    /// 3. **Signature** — Ed25519-verify the LB signature over the length-prefixed
    ///    [`LbAssertion::signing_preimage`]; mismatch ⇒ `BadSignature`.
    /// 4. **Request binding** — the assertion's `request_hash` MUST equal the
    ///    in-hand request hash; mismatch (cross-request / wrong hash) ⇒
    ///    `RequestHashMismatch`.
    /// 5. **Freshness** — `validation_time` MUST be within the window
    ///    `[now - max_age, now + max_age]`; outside ⇒ `Stale`.
    ///
    /// # Replay
    ///
    /// An assertion replayed against a DIFFERENT request fails check 4 (its bound
    /// hash will not match the new request's hash). An assertion replayed against
    /// the SAME request is caught by that request's OWN replay protection
    /// (`verify_request` runs the replay cache BEFORE this binding ever executes),
    /// and additionally ages out of the freshness window (check 5). The assertion
    /// therefore carries no independent nonce — request-hash binding plus freshness
    /// plus the request's replay cache cover it.
    pub fn verify(
        &self,
        assertion_value: &str,
        in_hand_request_hash: &str,
        now_unix: i64,
    ) -> Result<TransportIdentity, LbAssertionRejection> {
        // 1. Parse (framing + strict field shape).
        let (assertion, signature_b64url) = super::v1_wire::parse(assertion_value)?;
        // 2. Key lookup — unknown key id fails closed.
        let key = self
            .key_for(&assertion.key_id)
            .ok_or(LbAssertionRejection::UnknownKeyId)?;
        // 3. Signature over the length-prefixed canonical preimage.
        let preimage = assertion.signing_preimage();
        verify_ed25519_with(
            &preimage,
            &signature_b64url,
            key,
            McpReError::TransportBindingFailed,
        )
        .map_err(|_| LbAssertionRejection::BadSignature)?;
        // 4. Request binding — compare the bound hash to the in-hand hash. Compare
        //    the parsed 32-byte digests so two encodings of the same digest match
        //    and a malformed bound hash fails closed.
        let bound = parse_hash_id(&assertion.request_hash)
            .map_err(|_| LbAssertionRejection::RequestHashMismatch)?;
        let in_hand = parse_hash_id(in_hand_request_hash)
            .map_err(|_| LbAssertionRejection::RequestHashMismatch)?;
        if bound != in_hand {
            return Err(LbAssertionRejection::RequestHashMismatch);
        }
        // 5. Freshness window (symmetric: reject implausibly-future timestamps too).
        let age = now_unix.saturating_sub(assertion.validation_time);
        // Class R: the window is symmetric, so it is stated as one comparison against the
        // magnitude. Negating `max_age_secs` to build the lower edge was the one partial
        // operation between a signature that had just verified and the freshness verdict
        // that admits the assertion — `i64::MIN` has no negation.
        if age.saturating_abs() > self.max_age_secs {
            return Err(LbAssertionRejection::Stale);
        }
        Ok(TransportIdentity::attested_by_verified_ingress(
            assertion.asserted_client_identity,
            self.source,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::ingress::test_support::in_hand_request_hash;
    use crate::transport::ingress::test_support::LB_SEED;
    use mcp_re_core::b64url_encode;
    use mcp_re_core::sha256_hash_id;
    use mcp_re_core::SigningKey;

    /// Mint a wire-form Tier-3 assertion: the five `.`-separated base64url fields
    /// `<key_id>.<identity>.<request_hash>.<validation_time>.<signature>`, signed by
    /// `signer` over the length-prefixed canonical preimage.
    fn mint_assertion(
        signer: &SigningKey,
        key_id: &str,
        identity: &str,
        request_hash: &str,
        validation_time: i64,
    ) -> String {
        let assertion = LbAssertion {
            key_id: key_id.to_string(),
            asserted_client_identity: identity.to_string(),
            request_hash: request_hash.to_string(),
            validation_time,
        };
        let signature = signer.sign(&assertion.signing_preimage());
        format!(
            "{}.{}.{}.{}.{}",
            b64url_encode(key_id.as_bytes()),
            b64url_encode(identity.as_bytes()),
            b64url_encode(request_hash.as_bytes()),
            b64url_encode(&validation_time.to_be_bytes()),
            signature,
        )
    }

    /// A verifier trusting the LB key `lb-1` under the given seed.
    fn binding_with_lb_key(seed: &[u8; 32]) -> LbAssertionBinding {
        let mut binding = LbAssertionBinding::new(IdentitySource::UriSan);
        binding.add_key("lb-1", SigningKey::from_seed_bytes(seed).public_key());
        binding
    }

    #[test]
    fn lb_assertion_bound_to_in_hand_request_is_accepted() {
        let lb = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = binding_with_lb_key(&LB_SEED);
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        let assertion = mint_assertion(&lb, "lb-1", "spiffe://example.org/agent-1", &rh, now);
        // The verified identity is yielded, then binds to the matching signer via
        // the SAME ExactMatchBinding the direct-TLS / Tier-2 paths use.
        let identity = binding
            .verify(&assertion, &rh, now)
            .expect("a valid request-bound assertion must be accepted");
        assert_eq!(
            identity,
            TransportIdentity::attested_by_verified_ingress(
                "spiffe://example.org/agent-1",
                IdentitySource::UriSan
            )
        );
        // The Tier-3 assertion path yields a `TransportIdentity`, not a channel peer: no
        // TLS relationship authenticated anybody here, the LB asserted them. Since
        // ADR-MCPRE-064 Slice 4 the binding relation takes two SEMANTIC products, so this
        // control asserts what the assertion actually established — which identity was
        // verified — rather than running it through a policy that no longer models this
        // ingress. `--transport-binding lb-assertion` is refused by configuration
        // validation, so no deployment reaches the missing composition.
        assert_eq!(identity.value(), "spiffe://example.org/agent-1");
    }

    #[test]
    fn lb_assertion_cross_request_is_rejected() {
        // A valid signature, but the assertion is bound to a DIFFERENT request hash
        // than the one the node holds in hand: cross-request replay must fail.
        let lb = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = binding_with_lb_key(&LB_SEED);
        let now = 1_000_000;
        let other_request_hash = sha256_hash_id(b"a totally different request body");
        let assertion = mint_assertion(
            &lb,
            "lb-1",
            "spiffe://example.org/agent-1",
            &other_request_hash,
            now,
        );
        assert_eq!(
            binding
                .verify(&assertion, &in_hand_request_hash(), now)
                .unwrap_err(),
            LbAssertionRejection::RequestHashMismatch,
            "an assertion bound to another request must not bind to this one"
        );
    }

    #[test]
    fn lb_assertion_wrong_in_hand_hash_is_rejected() {
        // The assertion is internally consistent and bound to request hash A, but
        // the node presents a DIFFERENT in-hand hash B (e.g. the request was
        // tampered after the LB signed): the binding must fail closed.
        let lb = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = binding_with_lb_key(&LB_SEED);
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        let assertion = mint_assertion(&lb, "lb-1", "spiffe://example.org/agent-1", &rh, now);
        let tampered_in_hand = sha256_hash_id(b"node holds a different request");
        assert_eq!(
            binding
                .verify(&assertion, &tampered_in_hand, now)
                .unwrap_err(),
            LbAssertionRejection::RequestHashMismatch
        );
    }

    #[test]
    fn lb_assertion_unknown_key_id_is_rejected() {
        // The assertion names a key id the node's trust map does not contain: fail
        // closed (never admit an assertion signed by an untrusted/unknown key).
        let lb = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = binding_with_lb_key(&LB_SEED); // trusts only "lb-1"
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        let assertion = mint_assertion(
            &lb,
            "lb-99-unknown",
            "spiffe://example.org/agent-1",
            &rh,
            now,
        );
        assert_eq!(
            binding.verify(&assertion, &rh, now).unwrap_err(),
            LbAssertionRejection::UnknownKeyId
        );
    }

    #[test]
    fn lb_assertion_bad_signature_is_rejected() {
        // Signed by a DIFFERENT LB key than the one the node trusts for "lb-1":
        // the signature does not verify under the trusted key → fail closed.
        let attacker = SigningKey::from_seed_bytes(&[7u8; 32]);
        let binding = binding_with_lb_key(&LB_SEED); // trusts the lb-1 == LB_SEED key
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        let assertion = mint_assertion(&attacker, "lb-1", "spiffe://example.org/agent-1", &rh, now);
        assert_eq!(
            binding.verify(&assertion, &rh, now).unwrap_err(),
            LbAssertionRejection::BadSignature
        );
    }

    #[test]
    fn lb_assertion_tampered_identity_breaks_signature() {
        // Take a valid assertion and swap the identity field for a higher-privilege
        // one WITHOUT re-signing. The length-prefixed preimage covers the identity,
        // so the signature no longer verifies → fail closed (no privilege escalation).
        let lb = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = binding_with_lb_key(&LB_SEED);
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        let assertion = mint_assertion(&lb, "lb-1", "spiffe://example.org/agent-1", &rh, now);
        let mut parts: Vec<&str> = assertion.split('.').collect();
        let forged_identity = b64url_encode(b"spiffe://example.org/admin");
        parts[1] = &forged_identity;
        let forged = parts.join(".");
        assert_eq!(
            binding.verify(&forged, &rh, now).unwrap_err(),
            LbAssertionRejection::BadSignature
        );
    }

    #[test]
    fn lb_assertion_stale_is_rejected() {
        // validation_time is far outside the freshness window relative to now.
        let lb = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = binding_with_lb_key(&LB_SEED); // default 30s window
        let signed_at = 1_000_000;
        let rh = in_hand_request_hash();
        let assertion = mint_assertion(&lb, "lb-1", "spiffe://example.org/agent-1", &rh, signed_at);
        // The node evaluates it a full hour later.
        let now = signed_at + 3600;
        assert_eq!(
            binding.verify(&assertion, &rh, now).unwrap_err(),
            LbAssertionRejection::Stale
        );
        // The inclusive boundary (exactly max_age old) is still accepted, proving
        // it is a bounded window and not a blanket rejection.
        let at_bound = signed_at + super::DEFAULT_LB_ASSERTION_MAX_AGE_SECS;
        assert!(binding.verify(&assertion, &rh, at_bound).is_ok());
    }

    #[test]
    fn lb_assertion_implausibly_future_is_rejected() {
        // A timestamp far in the FUTURE (clock-skew / forgery attempt) is also
        // outside the symmetric window → fail closed.
        let lb = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = binding_with_lb_key(&LB_SEED);
        let rh = in_hand_request_hash();
        let signed_at = 1_000_000;
        let assertion = mint_assertion(&lb, "lb-1", "spiffe://example.org/agent-1", &rh, signed_at);
        let now = signed_at - 3600; // assertion claims to be from the future
        assert_eq!(
            binding.verify(&assertion, &rh, now).unwrap_err(),
            LbAssertionRejection::Stale
        );
    }

    #[test]
    fn lb_assertion_malformed_framing_is_rejected() {
        let binding = binding_with_lb_key(&LB_SEED);
        let rh = in_hand_request_hash();
        let now = 1_000_000;
        // Wrong field count.
        assert_eq!(
            binding.verify("only.three.fields", &rh, now).unwrap_err(),
            LbAssertionRejection::Malformed
        );
        // Empty.
        assert_eq!(
            binding.verify("", &rh, now).unwrap_err(),
            LbAssertionRejection::Malformed
        );
        // Non-base64url field.
        assert_eq!(
            binding.verify("!!!.!!!.!!!.!!!.!!!", &rh, now).unwrap_err(),
            LbAssertionRejection::Malformed
        );
    }

    #[test]
    fn lb_assertion_malformed_identity_shape_is_rejected() {
        // A CRLF-laced asserted identity (header-smuggling / log-injection) fails
        // the strict shape check even with an otherwise valid signature.
        let lb = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = binding_with_lb_key(&LB_SEED);
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        let assertion = mint_assertion(&lb, "lb-1", "agent\r\nX-Spoof: evil", &rh, now);
        assert_eq!(
            binding.verify(&assertion, &rh, now).unwrap_err(),
            LbAssertionRejection::Malformed
        );
    }

    #[test]
    fn lb_assertion_signing_preimage_is_length_prefixed_and_unambiguous() {
        // The length-prefixed framing defeats the delimiter-collision class: moving
        // a byte across a field boundary yields a DIFFERENT preimage, so the two
        // distinct field tuples can never share a signature.
        let a = LbAssertion {
            key_id: "lb".to_string(),
            asserted_client_identity: "ab".to_string(),
            request_hash: "c".to_string(),
            validation_time: 1,
        };
        let b = LbAssertion {
            key_id: "lb".to_string(),
            asserted_client_identity: "a".to_string(),
            request_hash: "bc".to_string(),
            validation_time: 1,
        };
        assert_ne!(
            a.signing_preimage(),
            b.signing_preimage(),
            "shifting a byte across a field boundary MUST change the preimage"
        );
        // Domain-separation tag is present and leads the preimage.
        assert!(a
            .signing_preimage()
            .starts_with(b"mcp-re/lb-ingress-assertion/v1"));
    }

    #[test]
    fn lb_assertion_guarantee_is_not_end_to_end_mtls() {
        // HONESTY: the Tier-3 guarantee is request-bound ingress assertion and MUST
        // NOT be surfaced as end-to-end client↔node mTLS (Tier 1).
        assert_eq!(
            LbAssertionBinding::GUARANTEE,
            "request_bound_ingress_assertion"
        );
        assert_ne!(LbAssertionBinding::GUARANTEE, "end_to_end_mtls");
        assert!(
            !LbAssertionBinding::GUARANTEE.contains("end_to_end"),
            "the Tier-3 guarantee must not claim end-to-end binding"
        );
    }
}
