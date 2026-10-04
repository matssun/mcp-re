// SPDX-License-Identifier: Apache-2.0
//! Frozen, profile-agnostic string constants for the MCP-RE security profile.
//!
//! Defined ONCE here for `mcp-re-core` — no string literals for these values may
//! be scattered across this crate. `EXTENSION_ID` and `DIGEST_ALG_SHA256` hold the
//! extension id and the SHA-256 digest token that the RFC 9421 carrier
//! (ADR-MCPRE-050) also uses; the carrier declares its own copies in
//! `mcp_re_http_profile::ids`, which also holds the carrier's algorithm token
//! `ALG_ED25519`. The carrier signs HTTP messages (RFC 9421 + RFC 9530); no
//! signature rides in a JSON-RPC `_meta` block.

/// The incubation extension identifier (reassigned to the `se.syncom` root by
/// ADR-MCPS-027). Controlled, explicitly NON-official; also the SEP-2133
/// `extensions`-map identifier.
pub const EXTENSION_ID: &str = "se.syncom/mcp-re";

/// The digest algorithm token for authorization/artifact bindings (bare
/// `digest_value`, no prefix). Matches the `sha256:` convention's algorithm name.
pub const DIGEST_ALG_SHA256: &str = "sha256";

#[cfg(test)]
mod tests {
    use super::DIGEST_ALG_SHA256;
    use super::EXTENSION_ID;

    #[test]
    fn frozen_profile_agnostic_constants() {
        assert_eq!(EXTENSION_ID, "se.syncom/mcp-re");
        assert_eq!(DIGEST_ALG_SHA256, "sha256");
    }
}
