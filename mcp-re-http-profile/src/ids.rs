// SPDX-License-Identifier: Apache-2.0
//! Protected identifiers of the HTTP standards profile (ADR-MCPRE-050,
//! v0.11 grill E-1/E-2). These strings are wire vocabulary: changing any of
//! them is a profile change requiring an ADR.

/// The profile id, carried as the RFC 9421 `tag` signature parameter on BOTH
/// request and response signatures (E-1: one profile-id tag, no per-direction
/// tag values).
pub const PROFILE_TAG: &str = "mcp-re-http-v1";

/// The request signature label (the `Signature-Input` / `Signature` dictionary
/// member name).
pub const REQUEST_LABEL: &str = "mcp-re";

/// The response signature label. Rejections are responses and reuse this label
/// (E-2: no third label).
pub const RESPONSE_LABEL: &str = "mcp-re-response";

/// The only signature algorithm of the profile, expressed per the RFC 9421
/// HTTP Signature Algorithms registry (lowercase — the native profile's
/// `Ed25519` token is a different, JCS-envelope identifier).
pub const ALG_ED25519: &str = "ed25519";

/// Digest algorithm token in the split evidence form (matches the draft-02
/// `authorization_binding` convention: `digest_alg` + bare base64url
/// `digest_value`, no prefix form — v0.11 grill E-5).
pub const EVIDENCE_DIGEST_ALG: &str = "sha256";

/// Covered components REQUIRED on every conforming request signature
/// (v0.11 grill B.1). `authorization` and `dpop` are additionally required
/// when the corresponding header is present.
pub const REQUIRED_REQUEST_COMPONENTS: [&str; 4] =
    ["@method", "@target-uri", "content-digest", "content-type"];

/// Response components REQUIRED on every conforming response signature
/// (v0.11 grill C.1, Codex-tightened set including `content-type;req`).
pub const REQUIRED_RESPONSE_COMPONENTS: [&str; 3] = ["@status", "content-digest", "content-type"];

/// Request components a conforming response signature MUST bind via the
/// RFC 9421 `req` parameter.
pub const REQUIRED_RESPONSE_REQ_COMPONENTS: [&str; 4] =
    ["@method", "@target-uri", "content-digest", "content-type"];
