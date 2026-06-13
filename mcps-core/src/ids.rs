//! Frozen string constants for the MCP-S security profile (MCPS_SPEC §1).
//!
//! These strings live inside the signed `_meta` keys and are therefore part of
//! the canonical preimage. They are defined ONCE here and referenced everywhere
//! — no string literals for these values may be scattered elsewhere in the code.

/// The incubation extension identifier (ADR-MCPS-010, reassigned to the
/// `se.syncom` root by ADR-MCPS-027; MCPS_SPEC §1). It appears inside the signed
/// `_meta` keys and is therefore part of the canonical preimage: it may change
/// between draft versions during incubation and freezes at 1.0. Controlled,
/// explicitly NON-official. Also the SEP-2133 `extensions`-map identifier.
pub const EXTENSION_ID: &str = "se.syncom/mcps";

/// `_meta` key under which the request envelope is carried.
pub const REQUEST_META_KEY: &str = "se.syncom/mcps.request";

/// `_meta` key under which the response envelope is carried.
pub const RESPONSE_META_KEY: &str = "se.syncom/mcps.response";

/// `_meta` key under which the (unsigned, local) verified-context sidecar block
/// is carried. Never part of any signed preimage.
pub const VERIFIED_META_KEY: &str = "se.syncom/mcps.verified";

/// The only supported envelope `version` value in this draft. Any other value
/// maps to `mcps.unsupported_version`.
pub const VERSION_DRAFT_01: &str = "draft-01";

/// The only supported signature algorithm. Any other value is treated as a
/// signature failure in v1.
pub const SIG_ALG_ED25519: &str = "Ed25519";

/// Wrapper key under which the proxy preserves a NON-OBJECT inner `result`
/// (scalar/array/null) before signing — see `mcps-proxy` `build_signed_response`
/// (the `json!({ "value": result })` branch). The client-side
/// [`crate::unwrap_verified_result`] strips this wrapper back to the original
/// payload. The two sides MUST agree on this exact key.
pub const RESPONSE_WRAP_VALUE_KEY: &str = "value";

/// Wrapper key under which the proxy preserves an inner ERROR (or any inner
/// response carrying no `result`) before signing — see `mcps-proxy`
/// `build_signed_response` (the `json!({ "inner_error": inner })` branch). The
/// client-side [`crate::unwrap_verified_result`] surfaces this as a real error to
/// the caller. The two sides MUST agree on this exact key.
pub const RESPONSE_WRAP_INNER_ERROR_KEY: &str = "inner_error";

/// W3C Trace Context `_meta` keys that are EXCLUDED from the MCP-S signing
/// preimage (ADR-MCPS-026, the explicit signed/unsigned `_meta` partition).
///
/// These observability fields (`traceparent` / `tracestate` / `baggage`) are
/// legitimately rewritten by middle boxes between signing and verification, so
/// including them in the preimage would break the signature on every tracing hop.
/// They are stripped from the canonical preimage exactly like `signature.value`,
/// on BOTH the signer and verifier side (one shared `signing_preimage`), and MUST
/// NOT influence any security decision. Everything else under `_meta` — including
/// a per-request `protocolVersion` (ADR-MCPS-026 rule 2) and any unknown key — is
/// IN scope and therefore integrity-protected: tampering it fails verification.
pub const OBSERVABILITY_META_KEYS: [&str; 3] = ["traceparent", "tracestate", "baggage"];

#[cfg(test)]
mod tests {
    use super::EXTENSION_ID;
    use super::OBSERVABILITY_META_KEYS;
    use super::REQUEST_META_KEY;
    use super::RESPONSE_META_KEY;
    use super::SIG_ALG_ED25519;
    use super::VERIFIED_META_KEY;
    use super::VERSION_DRAFT_01;

    #[test]
    fn extension_id_is_the_incubation_identifier() {
        assert_eq!(EXTENSION_ID, "se.syncom/mcps");
    }

    #[test]
    fn meta_keys_are_namespaced_under_the_extension_id() {
        assert_eq!(REQUEST_META_KEY, "se.syncom/mcps.request");
        assert_eq!(RESPONSE_META_KEY, "se.syncom/mcps.response");
        assert_eq!(VERIFIED_META_KEY, "se.syncom/mcps.verified");
        for key in [REQUEST_META_KEY, RESPONSE_META_KEY, VERIFIED_META_KEY] {
            assert!(key.starts_with(EXTENSION_ID));
        }
    }

    #[test]
    fn frozen_scalar_constants() {
        assert_eq!(VERSION_DRAFT_01, "draft-01");
        assert_eq!(SIG_ALG_ED25519, "Ed25519");
    }

    #[test]
    fn observability_keys_are_the_w3c_trace_context_set() {
        assert_eq!(
            OBSERVABILITY_META_KEYS,
            ["traceparent", "tracestate", "baggage"]
        );
        // None of the excluded observability keys may collide with the MCP-S
        // envelope keys (which ARE signed).
        for key in OBSERVABILITY_META_KEYS {
            assert_ne!(key, REQUEST_META_KEY);
            assert_ne!(key, RESPONSE_META_KEY);
            assert_ne!(key, VERIFIED_META_KEY);
        }
    }
}
