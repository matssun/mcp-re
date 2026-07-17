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
/// HTTP Signature Algorithms registry (lowercase `ed25519`, distinct from the
/// mixed-case `Ed25519` algorithm token used in `mcp-re-core`).
pub const ALG_ED25519: &str = "ed25519";

/// Digest algorithm token in the split evidence form (matches the draft-02
/// `authorization_binding` convention: `digest_alg` + bare base64url
/// `digest_value`, no prefix form — v0.11 grill E-5).
pub const EVIDENCE_DIGEST_ALG: &str = "sha256";

// --- evidence-handle domain separation (#416 rev 2 §7.1/§7.3, MCPRE-430) -----
//
// Every evidence handle is a SHA-256 over a role-labeled preimage:
//
//     SHA-256(<role label> || 0x00 || <mandated input bytes>)
//
// Before this, all three continuation handles and both evidence handles shared
// one derivation, so a handle's ROLE was carried only by which field it sat in.
// §7.3 requires role distinction robust against substitution — a positional
// convention is not that: it holds only as long as every consumer reads the
// right field, which is exactly the assumption an attacker attacks.
//
// With a label per role, a request-role handle and a response-role handle over
// identical bytes are DIFFERENT values, so a handle lifted into the wrong field
// cannot verify — the separation is cryptographic rather than clerical. The
// labels are profile-scoped, so they also separate this profile's handles from
// any future one's.
//
// `0x00` separates label from input unambiguously: the labels are ASCII and can
// never contain a NUL, so no (label, input) pair can collide with another.

/// Role label for a handle over a REQUEST's RFC 9421 signature base.
pub const EVIDENCE_LABEL_REQUEST: &str = "mcp-re-http-v1/request-evidence";

/// Role label for a handle over a RESPONSE's RFC 9421 signature base.
pub const EVIDENCE_LABEL_RESPONSE: &str = "mcp-re-http-v1/response-evidence";

/// Role label for a handle over the opaque MRTR `requestState` bytes. Distinct
/// from both signature-base roles: `requestState` is opaque server data, never a
/// signature base, and must not be substitutable for one.
pub const EVIDENCE_LABEL_REQUEST_STATE: &str = "mcp-re-http-v1/request-state";

/// `_meta` key of the request-side body evidence block (E-3: no new HTTP
/// header fields; MCP evidence rides in the JSON-RPC body, protected because
/// `content-digest` is a covered component). MCPRE-93.
pub const REQUEST_EVIDENCE_BLOCK_KEY: &str = "se.syncom/mcp-re.http.request";

/// `_meta` key of the RESERVED verified-context carrier (#415 rev 2 §10,
/// MCPRE-429): the PEP's verified conclusion handed to the inner server.
///
/// Reserved means exactly that: caller-supplied content at this key is stripped at
/// the enforcement boundary and never forwarded. Unlike every other block in this
/// vocabulary it is NOT evidence — it carries no signature, because the inner
/// server is not meant to evaluate trust independently. It is therefore only
/// meaningful over a channel that the PEP alone can write to.
pub const VERIFIED_CONTEXT_BLOCK_KEY: &str = "se.syncom/mcp-re.verified-context";

/// `_meta` key of the response-side body evidence block (`server_signer`,
/// `request_evidence`). MCPRE-93.
pub const RESPONSE_EVIDENCE_BLOCK_KEY: &str = "se.syncom/mcp-re.http.response";

/// Covered components REQUIRED on every conforming request signature
/// (v0.11 grill B.1). `authorization` and `dpop` are additionally required
/// when the corresponding header is present.
pub const REQUIRED_REQUEST_COMPONENTS: [&str; 4] =
    ["@method", "@target-uri", "content-digest", "content-type"];

// --- MCP transport headers (#415 rev 2 §4.1, MCPRE-425) ---------------------
//
// These are MCP's own transport headers, not MCP-RE inventions (E-3 forbids
// minting new header fields, and this mints none). §4.1 requires covering them
// when the protocol version defines them.
//
// The gap they close is concrete: `Mcp-Method` states, in the clear, which
// JSON-RPC method a request carries. Uncovered, that claim can diverge from the
// signed body — an intermediary reads `tools/list` off the header and routes,
// logs, or authorizes against it while the signed body says `tools/call`. The
// proxy itself never routes on these (ADR-MCPS-025: they are untrusted hints,
// the body is authoritative), but a covered header cannot lie about a signed
// body, which is worth more than a header nobody is allowed to believe.

/// The SEP-2243 routing header naming the JSON-RPC method. Required on every
/// POST from MCP 2026-07-28.
pub const MCP_METHOD_HEADER: &str = "mcp-method";

/// The SEP-2243 routing header naming the tool/resource. Required on every POST
/// from MCP 2026-07-28.
pub const MCP_NAME_HEADER: &str = "mcp-name";

/// The MCP protocol-version header, when the deployment's version defines it.
pub const MCP_PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";

/// Response components REQUIRED on every conforming response signature
/// (v0.11 grill C.1, Codex-tightened set including `content-type;req`).
pub const REQUIRED_RESPONSE_COMPONENTS: [&str; 3] = ["@status", "content-digest", "content-type"];

/// Request components a conforming response signature MUST bind via the
/// RFC 9421 `req` parameter.
pub const REQUIRED_RESPONSE_REQ_COMPONENTS: [&str; 4] =
    ["@method", "@target-uri", "content-digest", "content-type"];

// --- bodyless component sets (#415 rev 2 §3.4/§8.1, MCPRE-424) --------------
//
// NAMED sets, not silent relaxations of the bodied ones. A verifier is told which
// set it is checking and enforces that set exactly; it never "notices" a body is
// absent and drops a requirement. The distinction matters because "no
// content-type because there is no content" and "content-type stripped by an
// attacker" must not be the same observation — under a named set, a bodied
// message missing its content-type still fails, and a bodyless message CARRYING
// one also fails.
//
// `content-digest` is present and REQUIRED on both, computed over empty content.
// A digest of nothing is not ceremony: it is what makes "this message has no
// body" a signed statement rather than an absence. Without it, a stripped body
// and an intentionally empty one would be indistinguishable.

/// Covered components of a bodyless REQUEST (§8.1): no `content-type`, because
/// there is no content to describe.
pub const BODYLESS_REQUEST_COMPONENTS: [&str; 3] = ["@method", "@target-uri", "content-digest"];

/// Covered components of a bodyless RESPONSE (§3.4) — the signed `202 Accepted`
/// acknowledging a client-posted notification or response.
pub const BODYLESS_RESPONSE_COMPONENTS: [&str; 2] = ["@status", "content-digest"];

/// The HTTP status of an accepted one-way notification/response (#418, §3.4).
///
/// A signed 202 states exactly one thing: THE ENFORCEMENT BOUNDARY AUTHENTICATED
/// AND ACCEPTED THIS MESSAGE. It does not state that a requested cancellation
/// completed, that the inner application observed the notification, or that any
/// action was taken. Describing it as more would be precisely the overclaim this
/// protocol exists to avoid.
pub const STATUS_ACCEPTED: u16 = 202;
