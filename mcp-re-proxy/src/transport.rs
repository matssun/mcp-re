//! Transport-binding abstraction (MCPS-024, ADR-MCPS-014).
//!
//! Phase 6 binds the MCP-RE signing identity to the transport channel: an mTLS
//! client certificate proves *which channel* a request arrived on, and the
//! transport-binding policy asserts that channel identity is consistent with the
//! request's verified `signer`. A mismatch — or a required-but-absent verified
//! client identity — fails closed with `mcp-re.transport_binding_failed`.
//!
//! This module is std-only: it defines the identity type, the provider seam, and
//! the binding policy. `mcp-re-core` stays pure — the `transport_binding_failed`
//! code lives in its taxonomy but is emitted here, at the proxy, which is the only
//! component holding the connection.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use mcp_re_core::b64url_decode;
use mcp_re_core::b64url_encode;
use mcp_re_core::parse_hash_id;
use mcp_re_core::verify_ed25519_with;
use mcp_re_core::McpReError;
use mcp_re_core::VerificationKey;

/// Where a verified transport identity was read from in the client certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentitySource {
    /// A URI Subject Alternative Name (SPIFFE-style).
    UriSan,
    /// A DNS Subject Alternative Name.
    DnsSan,
    /// The subject Common Name (last resort).
    CommonName,
}

/// Which certificate field is the AUTHORITATIVE source of the transport identity.
///
/// This is a deployment policy, not a heuristic: the proxy reads exactly the
/// configured field and NEVER silently falls through to a weaker one. If the
/// selected field is absent from the client certificate, identity extraction
/// returns `None` and the (required) transport binding fails closed — a missing
/// URI SAN must never be quietly downgraded to a DNS SAN or a Common Name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IdentityPolicy {
    /// URI Subject Alternative Name (SPIFFE-style). The recommended default:
    /// URI SANs are unambiguous, namespaced, and the SPIFFE/workload-identity
    /// convention.
    #[default]
    UriSan,
    /// DNS Subject Alternative Name. Use only when the deployment's client
    /// identities are genuinely DNS names and this is an explicit choice.
    DnsSan,
    /// Subject Common Name. LEGACY ONLY — the CN is unstructured and deprecated
    /// for identity by the CA/Browser Forum. Selecting it emits a startup
    /// warning; prefer a URI or DNS SAN.
    CnLegacy,
}

/// A verified client identity extracted from a successfully-verified mTLS client
/// certificate (the leaf of the chain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportIdentity {
    /// The identity string (e.g. `spiffe://example.org/agent-1`).
    pub value: String,
    /// Which certificate field it came from.
    pub source: IdentitySource,
}

impl TransportIdentity {
    /// Construct a transport identity.
    pub fn new(value: impl Into<String>, source: IdentitySource) -> Self {
        TransportIdentity {
            value: value.into(),
            source,
        }
    }
}

/// The parsed HTTP request headers of an inbound connection, the only request
/// context a [`TransportBindingProvider`] is given. This is a thin, case-
/// insensitive view over the already-parsed header block — providers never see
/// the socket, the body, or the TLS connection, so a header-reading provider
/// cannot accidentally reach for connection state it must not trust.
///
/// Header names compare ASCII-case-insensitively (per RFC 7230). The FIRST
/// occurrence of a name wins.
#[derive(Debug, Clone, Default)]
pub struct RequestHeaders {
    /// `(lowercased-name, raw-value)` pairs in wire order.
    headers: Vec<(String, String)>,
}

impl RequestHeaders {
    /// Parse an HTTP/1.1 header block (the bytes up to and including the
    /// terminating `\r\n\r\n`, or any prefix of it) into a header view. The
    /// request line (first line) is skipped; malformed lines without a `:` are
    /// ignored. Values are trimmed of surrounding whitespace.
    pub fn parse(header_block: &str) -> Self {
        let mut headers = Vec::new();
        for (index, line) in header_block.lines().enumerate() {
            // Skip the request line (`POST / HTTP/1.1`) and blank lines.
            if index == 0 || line.trim().is_empty() {
                continue;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }
        RequestHeaders { headers }
    }

    /// Construct directly from `(name, value)` pairs (used in tests). Names are
    /// lowercased so lookup stays case-insensitive.
    pub fn from_pairs<I, N, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (N, V)>,
        N: Into<String>,
        V: Into<String>,
    {
        let headers = pairs
            .into_iter()
            .map(|(name, value)| (name.into().to_ascii_lowercase(), value.into()))
            .collect();
        RequestHeaders { headers }
    }

    /// The first value for `name` (case-insensitive), or `None` if absent.
    pub fn first(&self, name: &str) -> Option<&str> {
        let lowered = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(header_name, _)| *header_name == lowered)
            .map(|(_, value)| value.as_str())
    }

    /// The number of values present for `name` (case-insensitive). Used to fail
    /// closed on a duplicated trust header.
    pub fn count(&self, name: &str) -> usize {
        let lowered = name.to_ascii_lowercase();
        self.headers
            .iter()
            .filter(|(header_name, _)| *header_name == lowered)
            .count()
    }
}

/// Produces the verified client identity for an inbound request, or `None` when
/// no identity is available (fail closed: a binding that requires identity then
/// rejects). The request headers are the ONLY context — direct-TLS identity is
/// extracted functionally by the serve loop (see `tls::connection_identity`) and
/// does not go through this trait. `StaticIdentityProvider` ignores the request
/// and is used in tests.
pub trait TransportBindingProvider {
    /// The verified client identity for this request, if any.
    fn verified_identity(&self, request: &RequestHeaders) -> Option<TransportIdentity>;
}

/// A fixed identity (or none). Useful in tests and as a degenerate provider; it
/// ignores the request entirely and always yields the identity it was built with.
#[derive(Debug, Clone, Default)]
pub struct StaticIdentityProvider {
    identity: Option<TransportIdentity>,
}

impl StaticIdentityProvider {
    /// A provider that yields `identity` (or `None`).
    pub fn new(identity: Option<TransportIdentity>) -> Self {
        StaticIdentityProvider { identity }
    }
}

impl TransportBindingProvider for StaticIdentityProvider {
    fn verified_identity(&self, _request: &RequestHeaders) -> Option<TransportIdentity> {
        self.identity.clone()
    }
}

// The trusted-ingress identity vocabulary — `MAX_ASSERTED_IDENTITY_LEN`,
// `AssertedIdentityRejection`, `validate_asserted_identity_value` — is a compatibility
// facade over the peer-identity value owner (ADR-MCPRE-063 Slice 1) and lives in
// `asserted_identity_facade`. Re-exported here so this module's own callers, and the
// crate root, keep their existing paths.
pub use crate::asserted_identity_facade::validate_asserted_identity_value;
pub use crate::asserted_identity_facade::AssertedIdentityRejection;
pub use crate::asserted_identity_facade::MAX_ASSERTED_IDENTITY_LEN;

/// The SEP-2243 transport routing header naming the JSON-RPC method (ADR-MCPS-025).
/// Lowercased for case-insensitive [`RequestHeaders`] lookup.
pub const MCP_METHOD_HEADER: &str = "mcp-method";

/// The SEP-2243 transport routing header naming the tool/resource (ADR-MCPS-025).
/// Lowercased for case-insensitive [`RequestHeaders`] lookup.
pub const MCP_NAME_HEADER: &str = "mcp-name";

/// Why a SEP-2243 routing header was rejected (ADR-MCPS-025).
///
/// Routing headers (`Mcp-Method` / `Mcp-Name`) are untrusted hints: the signed
/// body is authoritative and the proxy never routes on them. But ADR-MCPS-025
/// rule 4 applies the ADR-MCPS-023 strict-header rules to them too — a duplicated
/// or malformed routing header is a header-smuggling / log-injection vector and
/// fails closed at the transport boundary before the handler runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingHeaderRejection {
    /// The header appeared more than once (a downstream-injected duplicate must
    /// not be able to shadow or confuse the first).
    Duplicate {
        /// The offending header name (`mcp-method` / `mcp-name`).
        header: &'static str,
    },
    /// The header's lone value failed the strict shape rules (empty, oversized, or
    /// containing a control character) — see [`validate_asserted_identity_value`].
    Malformed {
        /// The offending header name (`mcp-method` / `mcp-name`).
        header: &'static str,
    },
}

/// Apply the ADR-MCPS-023 strict-header rules to the SEP-2243 routing headers
/// (`Mcp-Method` / `Mcp-Name`) per ADR-MCPS-025 rule 4: each MUST be single-valued
/// and well-formed (non-empty, length-bounded, no control characters). Absent
/// headers pass — they are optional routing hints, not required. Present-but-bad
/// headers fail closed; the proxy never trusts a routing header for any security
/// decision, so this is hygiene (anti-smuggling), not a routing check.
pub fn validate_routing_headers(headers: &RequestHeaders) -> Result<(), RoutingHeaderRejection> {
    for header in [MCP_METHOD_HEADER, MCP_NAME_HEADER] {
        match headers.count(header) {
            0 => continue,
            1 => {
                let value = headers.first(header).unwrap_or("");
                if validate_asserted_identity_value(value).is_err() {
                    return Err(RoutingHeaderRejection::Malformed { header });
                }
            }
            _ => return Err(RoutingHeaderRejection::Duplicate { header }),
        }
    }
    Ok(())
}

/// Decides whether a request's verified `signer` is bound to the transport
/// identity. A failure is always [`McpReError::TransportBindingFailed`].
pub trait TransportBindingPolicy {
    /// `Ok(())` iff `signer` is bound to `identity`; otherwise
    /// [`McpReError::TransportBindingFailed`].
    fn check(&self, signer: &str, identity: Option<&TransportIdentity>) -> Result<(), McpReError>;
}

/// The strongest default: the request `signer` must equal the verified transport
/// identity (the key-holder is the cert-holder). A required identity that is
/// absent fails closed.
#[derive(Debug, Clone, Default)]
pub struct ExactMatchBinding;

impl ExactMatchBinding {
    /// Construct the exact-match policy.
    pub fn new() -> Self {
        ExactMatchBinding
    }
}

impl TransportBindingPolicy for ExactMatchBinding {
    fn check(&self, signer: &str, identity: Option<&TransportIdentity>) -> Result<(), McpReError> {
        match identity {
            Some(identity) if identity.value == signer => Ok(()),
            _ => Err(McpReError::TransportBindingFailed),
        }
    }
}

/// A binding the serving path is permitted to enforce.
///
/// [`TransportBindingPolicy`] is the vocabulary of binding rules; this is the subset the
/// configuration owner recognised. The distinction is the whole point: a
/// `Box<dyn TransportBindingPolicy>` parameter states only that SOME rule will run, and
/// every implementation satisfies it — including one whose `check` returns `Ok(())` for
/// every request, which the serving path cannot distinguish from a binding that held.
///
/// The representation is private and every constructor is `pub(crate)`, so a value of this
/// type exists only where `config_state::transport` recognised a
/// [`ChannelBindingState`](crate::config_state::ChannelBindingState). Possession is
/// therefore the proof that the mode was approved, with no trailing clause about which
/// call site built it.
///
/// `pub(crate)` seals nothing against this crate's own composition root, and normally that
/// makes it the wrong lever. Here it is the right one, because the consumers being excluded
/// are the ones outside the crate: `app.rs` SHOULD build these, and an embedder should not.
pub(crate) struct TransportBinding {
    policy: Box<dyn TransportBindingPolicy + Send + Sync>,
}

impl TransportBinding {
    /// The exact-match binding (Mode A): the request signer must equal the channel identity.
    ///
    /// The one binding any deployment can be in — `BindingKind::Exact` is the only kind
    /// that reaches a channel-binding state. A second deployable mode arrives here as a
    /// second constructor, not as a caller-supplied policy object.
    pub(crate) fn exact_match() -> Self {
        TransportBinding {
            policy: Box::new(ExactMatchBinding::new()),
        }
    }

    /// Apply the binding. The serving path's only projection of the private policy.
    pub(crate) fn check(
        &self,
        signer: &str,
        identity: Option<&TransportIdentity>,
    ) -> Result<(), McpReError> {
        self.policy.check(signer, identity)
    }
}

/// Cross-namespace binding: each `signer` maps to a set of allowed transport
/// identities (e.g. a DID signer permitted over one or more SPIFFE IDs). A signer
/// with no mapping, or an identity outside its set (or absent), fails closed.
///
/// This is a STRICT, EXPLICIT allowlist: matches are by exact string equality
/// only. There are deliberately no wildcards, no globs, and no regular
/// expressions — every permitted `(signer, identity)` pair is enumerated and
/// auditable, and any pair not enumerated is denied. A literal `"*"` is just an
/// ordinary string with no special meaning.
#[derive(Debug, Clone, Default)]
pub struct MappedBinding {
    allowed: BTreeMap<String, BTreeSet<String>>,
}

impl MappedBinding {
    /// An empty mapping (every signer fails closed until permitted).
    pub fn new() -> Self {
        MappedBinding {
            allowed: BTreeMap::new(),
        }
    }

    /// Permit `signer` to arrive over the transport identity `identity`.
    pub fn permit(&mut self, signer: impl Into<String>, identity: impl Into<String>) {
        self.allowed
            .entry(signer.into())
            .or_default()
            .insert(identity.into());
    }
}

impl TransportBindingPolicy for MappedBinding {
    fn check(&self, signer: &str, identity: Option<&TransportIdentity>) -> Result<(), McpReError> {
        let identity = identity.ok_or(McpReError::TransportBindingFailed)?;
        match self.allowed.get(signer) {
            Some(set) if set.contains(&identity.value) => Ok(()),
            _ => Err(McpReError::TransportBindingFailed),
        }
    }
}

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

/// A trusted LB verification key, addressed by its key id, used to verify Tier-3
/// LB-signed assertions. The key id is the opaque label the LB stamps into the
/// assertion's `key_id` field; the node looks the verification key up by it.
#[derive(Debug, Clone)]
struct LbKeyEntry {
    /// The LB key id (matches the assertion's `key_id` field byte-for-byte).
    key_id: String,
    /// The Ed25519 verification (public) key for this key id.
    key: VerificationKey,
}

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

    /// Parse a presented Tier-3 assertion header value into its fields.
    ///
    /// Wire form (single header value): four `.`-separated base64url-no-pad fields
    /// — `key_id . asserted_client_identity . request_hash . validation_time` —
    /// followed by the base64url-no-pad Ed25519 `signature` as a fifth field:
    /// `<key_id>.<identity>.<request_hash>.<validation_time>.<signature>`. Each
    /// textual field is base64url-encoded so it can never contain the `.`
    /// separator; this is a TRANSPORT encoding only — the SIGNATURE preimage is the
    /// length-prefixed [`LbAssertion::signing_preimage`], which is what defeats the
    /// delimiter-collision class. Any framing / decoding / shape violation fails
    /// closed as [`LbAssertionRejection::Malformed`].
    fn parse(value: &str) -> Result<(LbAssertion, String), LbAssertionRejection> {
        let trimmed = value.trim();
        // Bound total length up front (anti-DoS / smuggling), reusing the asserted-
        // identity ceiling generously across the whole assertion.
        if trimmed.is_empty() || trimmed.len() > MAX_ASSERTED_IDENTITY_LEN {
            return Err(LbAssertionRejection::Malformed);
        }
        let parts: Vec<&str> = trimmed.split('.').collect();
        if parts.len() != 5 {
            return Err(LbAssertionRejection::Malformed);
        }
        let key_id = decode_b64url_field(parts[0])?;
        let asserted_client_identity = decode_b64url_field(parts[1])?;
        let request_hash = decode_b64url_field(parts[2])?;
        let validation_time_bytes =
            b64url_decode(parts[3]).map_err(|_| LbAssertionRejection::Malformed)?;
        // Fixed 8-byte big-endian i64.
        let validation_time = i64::from_be_bytes(
            validation_time_bytes
                .as_slice()
                .try_into()
                .map_err(|_| LbAssertionRejection::Malformed)?,
        );
        // The signature is carried as the raw base64url string (verify_ed25519_with
        // decodes + length-checks it); a non-base64url signature fails closed there.
        let signature_b64url = parts[4].to_string();
        if signature_b64url.is_empty() {
            return Err(LbAssertionRejection::Malformed);
        }
        // Strict shape on the asserted identity (length-bound, no control chars,
        // non-empty), mirroring the Tier-2 header path.
        if validate_asserted_identity_value(&asserted_client_identity).is_err() {
            return Err(LbAssertionRejection::Malformed);
        }
        // key_id and request_hash must be non-empty and control-char-free too.
        if key_id.is_empty()
            || request_hash.is_empty()
            || key_id.chars().any(|c| c.is_control())
            || request_hash.chars().any(|c| c.is_control())
        {
            return Err(LbAssertionRejection::Malformed);
        }
        Ok((
            LbAssertion {
                key_id,
                asserted_client_identity,
                request_hash,
                validation_time,
            },
            signature_b64url,
        ))
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
        let (assertion, signature_b64url) = Self::parse(assertion_value)?;
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
        if age > self.max_age_secs || age < -self.max_age_secs {
            return Err(LbAssertionRejection::Stale);
        }
        Ok(TransportIdentity::new(
            assertion.asserted_client_identity,
            self.source,
        ))
    }
}

/// Decode one base64url-no-pad assertion field to a UTF-8 string; any decode or
/// UTF-8 error fails closed as [`LbAssertionRejection::Malformed`].
fn decode_b64url_field(field: &str) -> Result<String, LbAssertionRejection> {
    let bytes = b64url_decode(field).map_err(|_| LbAssertionRejection::Malformed)?;
    String::from_utf8(bytes).map_err(|_| LbAssertionRejection::Malformed)
}

// ---------------------------------------------------------------------------
// Mode C / Tier 4 (ADR-MCPS-023 §C1–C3, v0.10): attested-ingress assertion.
//
// A genuinely NEW frozen format, `mcp-re/lb-ingress-assertion/v2`. It is **not** an
// in-place extension of the frozen Tier-3 v1 assertion above: the v1 preimage is
// frozen (§C1), so binding the additional Mode-C facts requires a new
// domain-separation tag, a new length-prefixed layout, and a new node-side
// verifier order. Mode C is *attested delegation* — explicit opt-in, request-bound
// over a pinned attestor→node channel — and MUST NEVER be surfaced as
// `end_to_end_mtls` (see [`LbAssertionV2Binding::GUARANTEE`]).
//
// Honesty / scope: the v2 verifier is BIND-NOT-INTERPRET (§C3). The node verifies
// the abstract signed-assertion contract — signature, freshness, `request_hash`
// equality, audience/route, ingress identity — and treats the attestor's
// `cert_verification_result` / `revocation_result` as OPAQUE asserted facts it
// records and admits by fail-closed policy. It performs NO certificate-path
// validation and NO CRL-freshness computation of its own; a stale CRL at the
// attestor reaches the node as an explicit [`AttestedRevocation::StaleCrl`]
// verdict, so the node fails closed on staleness without doing CRL math.
// ---------------------------------------------------------------------------

/// The frozen v2 domain-separation tag prefixed to every Mode-C assertion
/// preimage. It is DISTINCT from the v1 tag (`mcp-re/lb-ingress-assertion/v1`): the
/// tag is the first bytes of the preimage, so a v1 verifier and a v2 verifier
/// derive disjoint preimages for identical field values — a signature minted for
/// one format can never be re-framed as the other (cross-version confusion).
const LB_ASSERTION_V2_DOMAIN_TAG: &[u8] = b"mcp-re/lb-ingress-assertion/v2";

/// An anti-DoS ceiling on the total v2 wire-assertion length (bytes). Generous
/// relative to the field set; a legitimate assertion is a few hundred bytes.
const MAX_V2_ASSERTION_WIRE_LEN: usize = 64 * 1024;

/// The attestor's asserted client-certificate verification verdict, carried in a
/// v2 assertion. Mode C is **bind-not-interpret** (ADR-023 §C3): the node RECORDS
/// this fact and admits ONLY [`Verified`](Self::Verified) — it performs no
/// certificate-path validation of its own. Modeled as an explicit enum, never an
/// optional/sentinel field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestedCertVerification {
    /// The attestor reports the load balancer verified the client-certificate
    /// chain.
    Verified,
    /// The attestor reports the client-certificate chain did NOT verify.
    Failed,
}

impl AttestedCertVerification {
    /// The fixed-width discriminant byte used in the signing preimage and the wire
    /// form. Stable across releases — part of the frozen v2 format. `0` is
    /// deliberately unassigned so an all-zero / truncated field fails closed.
    fn discriminant(self) -> u8 {
        match self {
            AttestedCertVerification::Verified => 1,
            AttestedCertVerification::Failed => 2,
        }
    }

    fn from_discriminant(b: u8) -> Option<Self> {
        match b {
            1 => Some(AttestedCertVerification::Verified),
            2 => Some(AttestedCertVerification::Failed),
            _ => None,
        }
    }
}

/// The attestor's asserted certificate-revocation verdict, carried in a v2
/// assertion. Mode C is **bind-not-interpret** (ADR-023 §C3): the node RECORDS this
/// fact and admits ONLY [`Good`](Self::Good) — it performs no CRL-freshness
/// computation of its own. A stale CRL at the attestor surfaces here as an explicit
/// [`StaleCrl`](Self::StaleCrl) verdict, so the node fails closed on staleness
/// WITHOUT itself doing CRL math. Modeled as an explicit enum, never an
/// optional/sentinel field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestedRevocation {
    /// The attestor checked a fresh CRL and the client certificate is not revoked.
    Good,
    /// The attestor found the client certificate revoked.
    Revoked,
    /// The attestor could not determine revocation status (e.g. no CRL available).
    Unknown,
    /// The attestor's CRL was stale (past `nextUpdate`) — freshness could not be
    /// asserted.
    StaleCrl,
}

impl AttestedRevocation {
    /// The fixed-width discriminant byte used in the signing preimage and the wire
    /// form. Stable across releases — part of the frozen v2 format. `0` is
    /// deliberately unassigned so an all-zero / truncated field fails closed.
    fn discriminant(self) -> u8 {
        match self {
            AttestedRevocation::Good => 1,
            AttestedRevocation::Revoked => 2,
            AttestedRevocation::Unknown => 3,
            AttestedRevocation::StaleCrl => 4,
        }
    }

    fn from_discriminant(b: u8) -> Option<Self> {
        match b {
            1 => Some(AttestedRevocation::Good),
            2 => Some(AttestedRevocation::Revoked),
            3 => Some(AttestedRevocation::Unknown),
            4 => Some(AttestedRevocation::StaleCrl),
            _ => None,
        }
    }
}

/// The parsed fields of a Mode-C (`mcp-re/lb-ingress-assertion/v2`) attested-ingress
/// assertion (ADR-MCPS-023 §C1).
///
/// Beyond the four v1 fields it binds the additional Mode-C facts: a distinct
/// ingress identity (the attestor's own identity, separate from the signing
/// `key_id`), the target `audience`/route, the attestor's opaque
/// `cert_verification_result` and `revocation_result` verdicts, the CRL
/// `crl_next_update` (recorded for audit, never compared by the node), and an
/// optional `expires_at` (present only when a validity shorter than the freshness
/// window is genuinely required — §C1).
///
/// # Honesty boundary
///
/// This is **attested delegation**, NOT end-to-end client↔node binding. The
/// load balancer witnesses proof-of-possession and remains in the trusted
/// computing base; the node verifies the attestor's signature and the request
/// binding, not the client's own key. It MUST NOT be presented as equivalent to
/// `end_to_end_mtls`. See [`LbAssertionV2Binding::GUARANTEE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LbAssertionV2 {
    /// The attestor key id naming the verification key that signed this assertion.
    pub key_id: String,
    /// The attestor's own ingress identity, DISTINCT from `key_id`. The node
    /// admits only ingress identities it has been configured to trust
    /// ([`LbAssertionV2Binding::permit_ingress_identity`]).
    pub ingress_identity: String,
    /// The delegated (asserted) client identity.
    pub asserted_client_identity: String,
    /// The MCP-RE request hash the assertion is bound to, as the
    /// `sha256:<base64url>` hash identifier (MCP_RE_SPEC §3).
    pub request_hash: String,
    /// The target audience/route the assertion is scoped to; the node checks it
    /// equals its own configured audience.
    pub audience: String,
    /// The attestor's opaque client-certificate verification verdict (recorded;
    /// admitted only when [`AttestedCertVerification::Verified`]).
    pub cert_verification_result: AttestedCertVerification,
    /// The attestor's opaque revocation verdict (recorded; admitted only when
    /// [`AttestedRevocation::Good`]).
    pub revocation_result: AttestedRevocation,
    /// The attestor's assertion time as a Unix timestamp (seconds). Freshness is
    /// checked against the node's `now_unix`.
    pub validation_time: i64,
    /// The `nextUpdate` of the CRL the attestor consulted, as a Unix timestamp
    /// (seconds). RECORDED for audit only — the node never compares it (§C3).
    pub crl_next_update: i64,
    /// An OPTIONAL absolute expiry (Unix seconds). Present only when a validity
    /// shorter than the freshness window is genuinely required (§C1); when present,
    /// the node rejects the assertion once `now_unix` passes it.
    pub expires_at: Option<i64>,
}

impl LbAssertionV2 {
    /// The deterministic, UNAMBIGUOUS canonical preimage the attestor signs and the
    /// node re-derives to verify.
    ///
    /// Encoding is **length-prefixed framing** (never delimiter-joining), so no
    /// field value can collide with a delimiter to forge a different field split.
    /// The layout is:
    ///
    /// ```text
    /// LB_ASSERTION_V2_DOMAIN_TAG
    /// || len(key_id)                    as u64 big-endian || key_id bytes
    /// || len(ingress_identity)          as u64 big-endian || ingress_identity bytes
    /// || len(asserted_client_identity)  as u64 big-endian || identity bytes
    /// || len(request_hash)              as u64 big-endian || request_hash bytes
    /// || len(audience)                  as u64 big-endian || audience bytes
    /// || cert_verification_result       as 1 fixed byte (discriminant)
    /// || revocation_result              as 1 fixed byte (discriminant)
    /// || validation_time                as i64 big-endian (fixed 8 bytes)
    /// || crl_next_update                as i64 big-endian (fixed 8 bytes)
    /// || expires_at present flag        as 1 fixed byte (0 = absent, 1 = present)
    /// || expires_at                     as i64 big-endian (fixed 8 bytes, ONLY when present)
    /// ```
    ///
    /// The optional `expires_at` is framed by an explicit presence byte, never an
    /// in-band sentinel value, so absence and any concrete timestamp are
    /// unambiguously distinct.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(LB_ASSERTION_V2_DOMAIN_TAG);
        for field in [
            self.key_id.as_bytes(),
            self.ingress_identity.as_bytes(),
            self.asserted_client_identity.as_bytes(),
            self.request_hash.as_bytes(),
            self.audience.as_bytes(),
        ] {
            out.extend_from_slice(&(field.len() as u64).to_be_bytes());
            out.extend_from_slice(field);
        }
        out.push(self.cert_verification_result.discriminant());
        out.push(self.revocation_result.discriminant());
        out.extend_from_slice(&self.validation_time.to_be_bytes());
        out.extend_from_slice(&self.crl_next_update.to_be_bytes());
        match self.expires_at {
            None => out.push(0),
            Some(deadline) => {
                out.push(1);
                out.extend_from_slice(&deadline.to_be_bytes());
            }
        }
        out
    }

    /// Render the transport wire form for this assertion given its `signature`
    /// (base64url-no-pad Ed25519 over [`Self::signing_preimage`]). Symmetric with
    /// [`LbAssertionV2Binding::parse`]; used by the attestor reference and tests.
    ///
    /// Eleven `.`-separated base64url-no-pad fields — every textual/scalar field is
    /// base64url-encoded so it can never contain the `.` separator (a TRANSPORT
    /// encoding only; the SIGNATURE preimage is the length-prefixed
    /// [`Self::signing_preimage`]):
    /// `key_id . ingress_identity . asserted_client_identity . request_hash .
    /// audience . cert_result . revocation_result . validation_time .
    /// crl_next_update . expires_at . signature`.
    pub fn to_wire(&self, signature_b64url: &str) -> String {
        let expires_at_bytes = match self.expires_at {
            None => vec![0u8],
            Some(deadline) => {
                let mut v = vec![1u8];
                v.extend_from_slice(&deadline.to_be_bytes());
                v
            }
        };
        [
            b64url_encode(self.key_id.as_bytes()),
            b64url_encode(self.ingress_identity.as_bytes()),
            b64url_encode(self.asserted_client_identity.as_bytes()),
            b64url_encode(self.request_hash.as_bytes()),
            b64url_encode(self.audience.as_bytes()),
            b64url_encode(&[self.cert_verification_result.discriminant()]),
            b64url_encode(&[self.revocation_result.discriminant()]),
            b64url_encode(&self.validation_time.to_be_bytes()),
            b64url_encode(&self.crl_next_update.to_be_bytes()),
            b64url_encode(&expires_at_bytes),
            signature_b64url.to_string(),
        ]
        .join(".")
    }
}

/// The verified outcome of a Mode-C assertion: the request-bound client identity
/// plus the attestor's recorded facts, which the proxy emits as the three §C2
/// audit trust facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedIngressVerified {
    /// The verified, request-bound delegated client identity (audit
    /// `delegated_client_identity`). Flows into the same [`TransportBindingPolicy`]
    /// the direct-TLS path uses.
    pub client_identity: TransportIdentity,
    /// The attestor's own ingress identity (audit `ingress_internal_hop`).
    pub ingress_identity: String,
    /// The attestor's admitted certificate-verification verdict (recorded).
    pub cert_verification_result: AttestedCertVerification,
    /// The attestor's admitted revocation verdict (recorded).
    pub revocation_result: AttestedRevocation,
    /// The CRL `nextUpdate` the attestor consulted (recorded for audit only).
    pub crl_next_update: i64,
}

/// Why a Mode-C v2 assertion was rejected. Every variant fails closed (no identity
/// is yielded). Surfaced for tests and audit; the proxy maps any rejection to
/// [`McpReError::TransportBindingFailed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LbAssertionV2Rejection {
    /// The assertion bytes are malformed (bad framing / not valid UTF-8 / bad
    /// base64 / bad enum discriminant) or a field violates the strict shape rules.
    Malformed,
    /// The assertion names a `key_id` not present in the trust map (fail closed).
    UnknownKeyId,
    /// The Ed25519 signature does not verify under the named attestor key.
    BadSignature,
    /// `validation_time` is outside the freshness window (too old, or implausibly
    /// far in the future).
    Stale,
    /// The bound `request_hash` does not equal the in-hand request hash.
    RequestHashMismatch,
    /// The assertion's `audience` does not equal the node's configured audience.
    AudienceMismatch,
    /// The assertion's `ingress_identity` is not in the node's trusted set.
    UntrustedIngressIdentity,
    /// The attestor's `cert_verification_result` is not
    /// [`AttestedCertVerification::Verified`].
    CertificateNotVerified,
    /// The attestor's `revocation_result` is [`AttestedRevocation::Revoked`].
    Revoked,
    /// The attestor's `revocation_result` is [`AttestedRevocation::Unknown`].
    RevocationUnknown,
    /// The attestor's `revocation_result` is [`AttestedRevocation::StaleCrl`].
    StaleRevocation,
    /// The assertion carries an `expires_at` and `now_unix` is past it.
    Expired,
}

/// A node-side verifier for Mode-C (`mcp-re/lb-ingress-assertion/v2`) attested-
/// ingress assertions (ADR-MCPS-023 §C1–C3, v0.10).
///
/// It holds a small in-proxy trust map of attestor verification keys (keyed by key
/// id), the node's own expected `audience`, and the set of trusted ingress
/// identities. Given a presented assertion + the in-hand request hash + the
/// current time, it yields a VERIFIED [`AttestedIngressVerified`] only after a
/// strict, ordered, fail-closed sequence of checks (see [`Self::verify`]).
///
/// # SECURITY — what this does and does NOT prove
///
/// This is **attested delegation**, NOT end-to-end client↔node mTLS. The node
/// verifies the attestor's signature over the v2 preimage — proving the trusted
/// attestor bound *this* client identity to *this* request over the pinned channel
/// — but the client's own key never reaches the node, and the load balancer
/// remains in the trusted computing base as the sole proof-of-possession witness.
/// The guarantee MUST NOT be surfaced as `end_to_end_mtls`; see [`Self::GUARANTEE`].
#[derive(Debug, Clone)]
pub struct LbAssertionV2Binding {
    /// Trusted attestor verification keys, addressed by key id.
    keys: Vec<LbKeyEntry>,
    /// The identity source stamped on the yielded client identity.
    source: IdentitySource,
    /// The node's own audience; the assertion's `audience` must equal it.
    expected_audience: String,
    /// The ingress identities the node trusts; an assertion whose
    /// `ingress_identity` is absent fails closed.
    allowed_ingress_identities: BTreeSet<String>,
    /// Maximum accepted assertion age (seconds) relative to `now_unix`.
    max_age_secs: i64,
}

impl LbAssertionV2Binding {
    /// The honest Mode-C guarantee string. Deliberately NOT `end_to_end_mtls`: the
    /// node cryptographically verifies that the trusted attestor bound its
    /// assertion to THIS request over the pinned channel, but the client's own key
    /// never reaches the node and the LB remains in the TCB — attested delegation,
    /// not end-to-end client↔node channel binding.
    pub const GUARANTEE: &'static str = "attested_ingress_delegation";

    /// Build a verifier for the node's `expected_audience` with no trusted keys or
    /// ingress identities yet (every assertion fails closed until both a key and an
    /// ingress identity are added) and the default freshness window
    /// ([`DEFAULT_LB_ASSERTION_MAX_AGE_SECS`]). `source` is the [`IdentitySource`]
    /// stamped on the yielded identity.
    pub fn new(source: IdentitySource, expected_audience: impl Into<String>) -> Self {
        LbAssertionV2Binding {
            keys: Vec::new(),
            source,
            expected_audience: expected_audience.into(),
            allowed_ingress_identities: BTreeSet::new(),
            max_age_secs: DEFAULT_LB_ASSERTION_MAX_AGE_SECS,
        }
    }

    /// Override the freshness window (seconds).
    pub fn with_max_age_secs(mut self, max_age_secs: i64) -> Self {
        self.max_age_secs = max_age_secs;
        self
    }

    /// Add a trusted attestor verification key addressed by `key_id`. A duplicate
    /// `key_id` REPLACES the prior key (last write wins) so a rotating deployment
    /// cannot end up with two live keys for one id.
    pub fn add_key(&mut self, key_id: impl Into<String>, key: VerificationKey) {
        let key_id = key_id.into();
        self.keys.retain(|entry| entry.key_id != key_id);
        self.keys.push(LbKeyEntry { key_id, key });
    }

    /// Trust an ingress identity; an assertion whose `ingress_identity` is not in
    /// this set fails closed ([`LbAssertionV2Rejection::UntrustedIngressIdentity`]).
    pub fn permit_ingress_identity(&mut self, ingress_identity: impl Into<String>) {
        self.allowed_ingress_identities
            .insert(ingress_identity.into());
    }

    /// Look up a trusted attestor verification key by key id.
    fn key_for(&self, key_id: &str) -> Option<&VerificationKey> {
        self.keys
            .iter()
            .find(|entry| entry.key_id == key_id)
            .map(|entry| &entry.key)
    }

    /// Parse a presented v2 assertion header value into its fields + signature.
    ///
    /// Wire form: eleven `.`-separated base64url-no-pad fields (see
    /// [`LbAssertionV2::to_wire`]). Any framing / decoding / shape violation fails
    /// closed as [`LbAssertionV2Rejection::Malformed`].
    fn parse(value: &str) -> Result<(LbAssertionV2, String), LbAssertionV2Rejection> {
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_V2_ASSERTION_WIRE_LEN {
            return Err(LbAssertionV2Rejection::Malformed);
        }
        let parts: Vec<&str> = trimmed.split('.').collect();
        if parts.len() != 11 {
            return Err(LbAssertionV2Rejection::Malformed);
        }
        let key_id = decode_v2_str(parts[0])?;
        let ingress_identity = decode_v2_str(parts[1])?;
        let asserted_client_identity = decode_v2_str(parts[2])?;
        let request_hash = decode_v2_str(parts[3])?;
        let audience = decode_v2_str(parts[4])?;
        let cert_verification_result =
            decode_v2_enum(parts[5], AttestedCertVerification::from_discriminant)?;
        let revocation_result = decode_v2_enum(parts[6], AttestedRevocation::from_discriminant)?;
        let validation_time = decode_v2_i64(parts[7])?;
        let crl_next_update = decode_v2_i64(parts[8])?;
        let expires_at = decode_v2_expires_at(parts[9])?;
        let signature_b64url = parts[10].to_string();
        if signature_b64url.is_empty() {
            return Err(LbAssertionV2Rejection::Malformed);
        }
        // Strict shape on the delegated identity (length-bound, no control chars,
        // non-empty), mirroring the Tier-2/Tier-3 header paths.
        if validate_asserted_identity_value(&asserted_client_identity).is_err() {
            return Err(LbAssertionV2Rejection::Malformed);
        }
        // key_id / ingress_identity / request_hash / audience must be non-empty and
        // control-char-free too.
        for field in [&key_id, &ingress_identity, &request_hash, &audience] {
            if field.is_empty() || field.chars().any(|c| c.is_control()) {
                return Err(LbAssertionV2Rejection::Malformed);
            }
        }
        Ok((
            LbAssertionV2 {
                key_id,
                ingress_identity,
                asserted_client_identity,
                request_hash,
                audience,
                cert_verification_result,
                revocation_result,
                validation_time,
                crl_next_update,
                expires_at,
            },
            signature_b64url,
        ))
    }

    /// Verify a presented Mode-C assertion against the in-hand request hash and the
    /// current time, yielding the VERIFIED [`AttestedIngressVerified`] on success.
    ///
    /// Ordered, fail-closed checks (ADR-MCPS-023 §C3):
    /// 1. **Parse** the assertion; malformed framing/shape ⇒ `Malformed`.
    /// 2. **Key lookup** — an unknown `key_id` ⇒ `UnknownKeyId` (fail closed).
    /// 3. **Signature** — Ed25519-verify over the length-prefixed
    ///    [`LbAssertionV2::signing_preimage`]; mismatch ⇒ `BadSignature`.
    /// 4. **Freshness** — `validation_time` within `[now - max_age, now + max_age]`;
    ///    outside ⇒ `Stale`. An `expires_at` in the past ⇒ `Expired`.
    /// 5. **Request binding** — the assertion's `request_hash` MUST equal the
    ///    in-hand hash; mismatch ⇒ `RequestHashMismatch`.
    /// 6. **Audience/route** — `audience` MUST equal the node's configured
    ///    audience; mismatch ⇒ `AudienceMismatch`.
    /// 7. **Ingress identity** — `ingress_identity` MUST be trusted; else
    ///    `UntrustedIngressIdentity`.
    /// 8. **Recorded-facts admission** — the attestor's opaque verdicts are RECORDED
    ///    and admitted by fail-closed policy (NOT recomputed): `cert_verification_result`
    ///    MUST be `Verified` (else `CertificateNotVerified`) and `revocation_result`
    ///    MUST be `Good` (else `Revoked` / `RevocationUnknown` / `StaleRevocation`).
    ///
    /// # Replay
    ///
    /// As with v1, the assertion carries no independent nonce (§C1): a replay
    /// against a DIFFERENT request fails check 5, and a replay against the SAME
    /// request is caught by that request's own replay cache (which runs before this
    /// binding) and the freshness window (check 4).
    pub fn verify(
        &self,
        assertion_value: &str,
        in_hand_request_hash: &str,
        now_unix: i64,
    ) -> Result<AttestedIngressVerified, LbAssertionV2Rejection> {
        // 1. Parse (framing + strict field shape).
        let (assertion, signature_b64url) = Self::parse(assertion_value)?;
        // 2. Key lookup — unknown key id fails closed.
        let key = self
            .key_for(&assertion.key_id)
            .ok_or(LbAssertionV2Rejection::UnknownKeyId)?;
        // 3. Signature over the length-prefixed canonical preimage.
        let preimage = assertion.signing_preimage();
        verify_ed25519_with(
            &preimage,
            &signature_b64url,
            key,
            McpReError::TransportBindingFailed,
        )
        .map_err(|_| LbAssertionV2Rejection::BadSignature)?;
        // 4. Freshness (symmetric window; reject implausibly-future timestamps too),
        //    plus the optional hard expiry.
        let age = now_unix.saturating_sub(assertion.validation_time);
        if age > self.max_age_secs || age < -self.max_age_secs {
            return Err(LbAssertionV2Rejection::Stale);
        }
        if let Some(deadline) = assertion.expires_at {
            if now_unix > deadline {
                return Err(LbAssertionV2Rejection::Expired);
            }
        }
        // 5. Request binding — compare parsed 32-byte digests so two encodings of
        //    the same digest match and a malformed bound hash fails closed.
        let bound = parse_hash_id(&assertion.request_hash)
            .map_err(|_| LbAssertionV2Rejection::RequestHashMismatch)?;
        let in_hand = parse_hash_id(in_hand_request_hash)
            .map_err(|_| LbAssertionV2Rejection::RequestHashMismatch)?;
        if bound != in_hand {
            return Err(LbAssertionV2Rejection::RequestHashMismatch);
        }
        // 6. Audience/route.
        if assertion.audience != self.expected_audience {
            return Err(LbAssertionV2Rejection::AudienceMismatch);
        }
        // 7. Ingress identity must be trusted.
        if !self
            .allowed_ingress_identities
            .contains(&assertion.ingress_identity)
        {
            return Err(LbAssertionV2Rejection::UntrustedIngressIdentity);
        }
        // 8. Recorded-facts admission (bind-not-interpret): admit only the attestor's
        //    positive verdicts; the node recomputes NEITHER (§C3).
        if assertion.cert_verification_result != AttestedCertVerification::Verified {
            return Err(LbAssertionV2Rejection::CertificateNotVerified);
        }
        match assertion.revocation_result {
            AttestedRevocation::Good => {}
            AttestedRevocation::Revoked => return Err(LbAssertionV2Rejection::Revoked),
            AttestedRevocation::Unknown => return Err(LbAssertionV2Rejection::RevocationUnknown),
            AttestedRevocation::StaleCrl => return Err(LbAssertionV2Rejection::StaleRevocation),
        }
        Ok(AttestedIngressVerified {
            client_identity: TransportIdentity::new(
                assertion.asserted_client_identity,
                self.source,
            ),
            ingress_identity: assertion.ingress_identity,
            cert_verification_result: assertion.cert_verification_result,
            revocation_result: assertion.revocation_result,
            crl_next_update: assertion.crl_next_update,
        })
    }
}

/// Decode one base64url-no-pad v2 field to a UTF-8 string; any decode or UTF-8
/// error fails closed as [`LbAssertionV2Rejection::Malformed`].
fn decode_v2_str(field: &str) -> Result<String, LbAssertionV2Rejection> {
    let bytes = b64url_decode(field).map_err(|_| LbAssertionV2Rejection::Malformed)?;
    String::from_utf8(bytes).map_err(|_| LbAssertionV2Rejection::Malformed)
}

/// Decode a single-byte enum discriminant field via `from_disc`; a wrong length or
/// an unassigned discriminant fails closed as [`LbAssertionV2Rejection::Malformed`].
fn decode_v2_enum<T>(
    field: &str,
    from_disc: fn(u8) -> Option<T>,
) -> Result<T, LbAssertionV2Rejection> {
    let bytes = b64url_decode(field).map_err(|_| LbAssertionV2Rejection::Malformed)?;
    match bytes.as_slice() {
        [b] => from_disc(*b).ok_or(LbAssertionV2Rejection::Malformed),
        _ => Err(LbAssertionV2Rejection::Malformed),
    }
}

/// Decode a fixed 8-byte big-endian `i64` field; a wrong length fails closed as
/// [`LbAssertionV2Rejection::Malformed`].
fn decode_v2_i64(field: &str) -> Result<i64, LbAssertionV2Rejection> {
    let bytes = b64url_decode(field).map_err(|_| LbAssertionV2Rejection::Malformed)?;
    let array: [u8; 8] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| LbAssertionV2Rejection::Malformed)?;
    Ok(i64::from_be_bytes(array))
}

/// Decode the optional-`expires_at` field: a single presence byte `0` (absent) or
/// `1` followed by a fixed 8-byte big-endian `i64` (present). Any other framing —
/// including a stray sentinel — fails closed as [`LbAssertionV2Rejection::Malformed`].
fn decode_v2_expires_at(field: &str) -> Result<Option<i64>, LbAssertionV2Rejection> {
    let bytes = b64url_decode(field).map_err(|_| LbAssertionV2Rejection::Malformed)?;
    match bytes.as_slice() {
        [0] => Ok(None),
        [1, rest @ ..] => {
            let array: [u8; 8] = rest
                .try_into()
                .map_err(|_| LbAssertionV2Rejection::Malformed)?;
            Ok(Some(i64::from_be_bytes(array)))
        }
        _ => Err(LbAssertionV2Rejection::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::AttestedCertVerification;
    use super::AttestedRevocation;
    use super::ExactMatchBinding;
    use super::IdentitySource;
    use super::LbAssertion;
    use super::LbAssertionBinding;
    use super::LbAssertionRejection;
    use super::LbAssertionV2;
    use super::LbAssertionV2Binding;
    use super::LbAssertionV2Rejection;
    use super::MappedBinding;
    use super::RequestHeaders;
    use super::StaticIdentityProvider;
    use super::TransportBinding;
    use super::TransportBindingPolicy;
    use super::TransportBindingProvider;
    use super::TransportIdentity;
    use mcp_re_core::b64url_encode;
    use mcp_re_core::sha256_hash_id;
    use mcp_re_core::McpReError;
    use mcp_re_core::SigningKey;

    fn spiffe(value: &str) -> TransportIdentity {
        TransportIdentity::new(value, IdentitySource::UriSan)
    }

    /// A request carrying a single header.
    fn req_with(name: &str, value: &str) -> RequestHeaders {
        RequestHeaders::from_pairs([(name, value)])
    }

    #[test]
    fn static_provider_yields_its_identity_ignoring_request() {
        let id = spiffe("spiffe://example.org/agent-1");
        let provider = StaticIdentityProvider::new(Some(id.clone()));
        // The request argument is ignored: same identity regardless of headers.
        let empty = RequestHeaders::default();
        let populated = req_with("x-forwarded-client-cert", "URI=spiffe://other");
        assert_eq!(provider.verified_identity(&empty), Some(id.clone()));
        assert_eq!(provider.verified_identity(&populated), Some(id));
        assert_eq!(
            StaticIdentityProvider::new(None).verified_identity(&empty),
            None
        );
    }

    // --- Issue #21 (cluster 2): ADR-MCPS-023 strict rules on the XFCC value -----

    #[test]
    fn request_headers_parse_skips_request_line_and_is_case_insensitive() {
        let block =
            "POST /mcp HTTP/1.1\r\nHost: proxy\r\nX-Forwarded-Client-Cert: URI=spiffe://x\r\n\r\n";
        let headers = RequestHeaders::parse(block);
        assert_eq!(headers.first("host"), Some("proxy"));
        assert_eq!(
            headers.first("X-Forwarded-Client-Cert"),
            Some("URI=spiffe://x")
        );
        assert_eq!(
            headers.first("POST"),
            None,
            "the request line is not a header"
        );
        assert_eq!(headers.count("x-forwarded-client-cert"), 1);
    }

    #[test]
    fn exact_match_binds_equal_signer_and_identity() {
        let policy = ExactMatchBinding::new();
        let id = spiffe("did:example:agent-1");
        assert!(policy.check("did:example:agent-1", Some(&id)).is_ok());
    }

    #[test]
    fn exact_match_rejects_mismatch_and_absence() {
        let policy = ExactMatchBinding::new();
        let id = spiffe("did:example:other");
        assert_eq!(
            policy.check("did:example:agent-1", Some(&id)).unwrap_err(),
            McpReError::TransportBindingFailed
        );
        assert_eq!(
            policy.check("did:example:agent-1", None).unwrap_err(),
            McpReError::TransportBindingFailed
        );
    }

    /// The installable binding enforces the exact-match rule, not merely some rule.
    ///
    /// `TransportBinding` exists to make "a rule ran" and "THE approved rule ran" the same
    /// statement, so its behaviour is pinned here rather than inferred from the policy it
    /// happens to wrap today.
    #[test]
    fn the_installable_binding_is_exact_match() {
        let binding = TransportBinding::exact_match();
        let id = spiffe("did:example:agent-1");
        assert!(binding.check("did:example:agent-1", Some(&id)).is_ok());
        assert_eq!(
            binding.check("did:example:agent-2", Some(&id)).unwrap_err(),
            McpReError::TransportBindingFailed,
            "a signer that is not the channel identity was admitted"
        );
        assert_eq!(
            binding.check("did:example:agent-1", None).unwrap_err(),
            McpReError::TransportBindingFailed,
            "a request with no channel identity at all was admitted"
        );
    }

    /// A permissive policy is expressible, which is exactly why it must not be installable.
    ///
    /// This is the state the seal excludes: an implementation of the public
    /// [`TransportBindingPolicy`] trait that admits every request. Nothing stops an
    /// embedder writing it — the point is that there is no longer a public route from one
    /// of these to the serving path, so `TransportBinding` cannot wrap it.
    #[test]
    fn a_permissive_policy_is_not_what_the_installable_binding_does() {
        struct AdmitEverything;
        impl TransportBindingPolicy for AdmitEverything {
            fn check(&self, _: &str, _: Option<&TransportIdentity>) -> Result<(), McpReError> {
                Ok(())
            }
        }

        let id = spiffe("did:example:agent-1");
        // The negative control: this is what the serving path would do if a caller could
        // supply the rule.
        assert!(AdmitEverything
            .check("did:example:impostor", Some(&id))
            .is_ok());
        assert_eq!(
            TransportBinding::exact_match()
                .check("did:example:impostor", Some(&id))
                .unwrap_err(),
            McpReError::TransportBindingFailed,
            "the installable binding must not behave like the policy the seal excludes"
        );
    }

    #[test]
    fn mapped_binding_honours_the_allow_set() {
        let mut policy = MappedBinding::new();
        policy.permit("did:example:agent-1", "spiffe://example.org/agent-1");
        let ok = spiffe("spiffe://example.org/agent-1");
        assert!(policy.check("did:example:agent-1", Some(&ok)).is_ok());

        // Identity outside the set.
        let bad = spiffe("spiffe://example.org/evil");
        assert_eq!(
            policy.check("did:example:agent-1", Some(&bad)).unwrap_err(),
            McpReError::TransportBindingFailed
        );
        // Signer with no mapping.
        assert_eq!(
            policy.check("did:example:unmapped", Some(&ok)).unwrap_err(),
            McpReError::TransportBindingFailed
        );
        // Absent identity.
        assert_eq!(
            policy.check("did:example:agent-1", None).unwrap_err(),
            McpReError::TransportBindingFailed
        );
    }

    #[test]
    fn mapped_binding_has_no_wildcard_semantics() {
        // A literal "*" is an ordinary string, not a wildcard: permitting "*"
        // for a signer must NOT permit some other concrete identity.
        let mut policy = MappedBinding::new();
        policy.permit("did:example:agent-1", "*");
        let star = spiffe("*");
        assert!(
            policy.check("did:example:agent-1", Some(&star)).is_ok(),
            "the literal '*' identity matches the literal '*' entry"
        );
        let concrete = spiffe("spiffe://example.org/agent-1");
        assert_eq!(
            policy
                .check("did:example:agent-1", Some(&concrete))
                .unwrap_err(),
            McpReError::TransportBindingFailed,
            "'*' must NOT act as a wildcard over concrete identities"
        );
    }

    #[test]
    fn mapped_binding_matches_are_exact_and_case_sensitive() {
        // Matching is byte-exact: no case folding, no trimming, no normalization.
        let mut policy = MappedBinding::new();
        policy.permit("did:example:agent-1", "spiffe://example.org/agent-1");
        let differing_case = spiffe("spiffe://example.org/AGENT-1");
        assert_eq!(
            policy
                .check("did:example:agent-1", Some(&differing_case))
                .unwrap_err(),
            McpReError::TransportBindingFailed,
            "identity match is case-sensitive"
        );
        // Signer is matched exactly too.
        let ok = spiffe("spiffe://example.org/agent-1");
        assert_eq!(
            policy.check("DID:EXAMPLE:AGENT-1", Some(&ok)).unwrap_err(),
            McpReError::TransportBindingFailed,
            "signer match is case-sensitive"
        );
    }

    // ADR-MCPS-023: strict asserted-identity header validation.
    #[test]
    fn asserted_identity_accepts_a_well_formed_value_and_trims() {
        assert_eq!(
            super::validate_asserted_identity_value("  spiffe://example.org/agent-1  "),
            Ok("spiffe://example.org/agent-1")
        );
    }

    #[test]
    fn asserted_identity_rejects_empty() {
        assert_eq!(
            super::validate_asserted_identity_value("   "),
            Err(super::AssertedIdentityRejection::Empty)
        );
    }

    #[test]
    fn asserted_identity_rejects_oversized() {
        let huge = "a".repeat(super::MAX_ASSERTED_IDENTITY_LEN + 1);
        assert_eq!(
            super::validate_asserted_identity_value(&huge),
            Err(super::AssertedIdentityRejection::TooLong)
        );
        // Exactly at the bound is accepted.
        let at_bound = "a".repeat(super::MAX_ASSERTED_IDENTITY_LEN);
        assert!(super::validate_asserted_identity_value(&at_bound).is_ok());
    }

    #[test]
    fn asserted_identity_rejects_control_characters() {
        // CR/LF (header smuggling / log injection), NUL, and a bare control char.
        for bad in [
            "agent\r\nX-Spoof: y",
            "agent\nid",
            "agent\0id",
            "ag\u{7}ent",
        ] {
            assert_eq!(
                super::validate_asserted_identity_value(bad),
                Err(super::AssertedIdentityRejection::Malformed),
                "control characters must fail closed: {bad:?}"
            );
        }
    }

    // ---- ADR-MCPS-025 routing-header hygiene ----------------------------------

    #[test]
    fn routing_headers_absent_pass() {
        // Mcp-Method / Mcp-Name are optional hints; absent is fine.
        let headers = super::RequestHeaders::default();
        assert_eq!(super::validate_routing_headers(&headers), Ok(()));
    }

    #[test]
    fn routing_headers_well_formed_pass() {
        let headers =
            super::RequestHeaders::from_pairs([("Mcp-Method", "tools/call"), ("Mcp-Name", "echo")]);
        assert_eq!(super::validate_routing_headers(&headers), Ok(()));
    }

    #[test]
    fn duplicate_routing_header_fails_closed() {
        let headers = super::RequestHeaders::from_pairs([
            ("Mcp-Method", "tools/call"),
            ("mcp-method", "tools/list"),
        ]);
        assert_eq!(
            super::validate_routing_headers(&headers),
            Err(super::RoutingHeaderRejection::Duplicate {
                header: super::MCP_METHOD_HEADER
            })
        );
    }

    #[test]
    fn malformed_routing_header_fails_closed() {
        // A CRLF-laced routing header is a smuggling vector — fail closed even
        // though the proxy never routes on it.
        let headers = super::RequestHeaders::from_pairs([("Mcp-Name", "echo\r\nX-Spoof: evil")]);
        assert_eq!(
            super::validate_routing_headers(&headers),
            Err(super::RoutingHeaderRejection::Malformed {
                header: super::MCP_NAME_HEADER
            })
        );
    }

    #[test]
    fn empty_routing_header_fails_closed() {
        let headers = super::RequestHeaders::from_pairs([("Mcp-Method", "   ")]);
        assert_eq!(
            super::validate_routing_headers(&headers),
            Err(super::RoutingHeaderRejection::Malformed {
                header: super::MCP_METHOD_HEADER
            })
        );
    }

    // ---- ADR-MCPS-023 Tier 3 (issue #71): LB-signed request-bound assertion ----

    /// A fixed LB signing seed so the minted assertions are reproducible in-test.
    const LB_SEED: [u8; 32] = [42u8; 32];

    /// The request hash the node holds in hand for the request under test.
    fn in_hand_request_hash() -> String {
        sha256_hash_id(br#"{"jsonrpc":"2.0","method":"tools/call","id":1}"#)
    }

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
            TransportIdentity::new("spiffe://example.org/agent-1", IdentitySource::UriSan)
        );
        let policy = ExactMatchBinding::new();
        assert!(
            policy
                .check("spiffe://example.org/agent-1", Some(&identity))
                .is_ok(),
            "the verified Tier-3 identity must bind to its signer"
        );
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

    // -----------------------------------------------------------------------
    // Mode C / v2 attested-ingress assertion (ADR-MCPS-023 §C1–C3, MCPS-60).
    // -----------------------------------------------------------------------

    const V2_INGRESS_ID: &str = "spiffe://example.org/ingress-attestor-1";
    const V2_AUDIENCE: &str = "did:example:server-1";
    const V2_CLIENT: &str = "spiffe://example.org/agent-1";

    /// A canonical, fully-populated valid v2 assertion for the given request hash
    /// and time: cert Verified, revocation Good, no hard expiry.
    fn v2_assertion(request_hash: &str, validation_time: i64) -> LbAssertionV2 {
        LbAssertionV2 {
            key_id: "attestor-1".to_string(),
            ingress_identity: V2_INGRESS_ID.to_string(),
            asserted_client_identity: V2_CLIENT.to_string(),
            request_hash: request_hash.to_string(),
            audience: V2_AUDIENCE.to_string(),
            cert_verification_result: AttestedCertVerification::Verified,
            revocation_result: AttestedRevocation::Good,
            validation_time,
            crl_next_update: validation_time + 86_400,
            expires_at: None,
        }
    }

    /// Sign `assertion` with `signer` and render its wire form.
    fn mint_v2(signer: &SigningKey, assertion: &LbAssertionV2) -> String {
        assertion.to_wire(&signer.sign(&assertion.signing_preimage()))
    }

    /// A v2 verifier trusting attestor key `attestor-1` (under `LB_SEED`), the
    /// canonical audience, and the canonical ingress identity.
    fn v2_binding() -> LbAssertionV2Binding {
        let mut binding = LbAssertionV2Binding::new(IdentitySource::UriSan, V2_AUDIENCE);
        binding.add_key(
            "attestor-1",
            SigningKey::from_seed_bytes(&LB_SEED).public_key(),
        );
        binding.permit_ingress_identity(V2_INGRESS_ID);
        binding
    }

    #[test]
    fn v2_valid_assertion_is_accepted_and_records_facts() {
        let attestor = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = v2_binding();
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        let wire = mint_v2(&attestor, &v2_assertion(&rh, now));
        let verified = binding
            .verify(&wire, &rh, now)
            .expect("a valid Mode-C assertion must be accepted");
        assert_eq!(
            verified.client_identity,
            TransportIdentity::new(V2_CLIENT, IdentitySource::UriSan)
        );
        assert_eq!(verified.ingress_identity, V2_INGRESS_ID);
        assert_eq!(
            verified.cert_verification_result,
            AttestedCertVerification::Verified
        );
        assert_eq!(verified.revocation_result, AttestedRevocation::Good);
        assert_eq!(verified.crl_next_update, now + 86_400);
        // The verified delegated identity binds to its signer via the SAME policy.
        let policy = ExactMatchBinding::new();
        assert!(policy
            .check(V2_CLIENT, Some(&verified.client_identity))
            .is_ok());
    }

    #[test]
    fn v2_to_wire_round_trips_through_parse() {
        let attestor = SigningKey::from_seed_bytes(&LB_SEED);
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        // Exercise the present-`expires_at` path too.
        let mut a = v2_assertion(&rh, now);
        a.expires_at = Some(now + 10);
        let wire = mint_v2(&attestor, &a);
        let (parsed, _sig) = LbAssertionV2Binding::parse(&wire).expect("round-trips");
        assert_eq!(parsed, a);
    }

    #[test]
    fn v2_cross_request_is_rejected() {
        let attestor = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = v2_binding();
        let now = 1_000_000;
        let other = sha256_hash_id(b"a totally different request body");
        let wire = mint_v2(&attestor, &v2_assertion(&other, now));
        assert_eq!(
            binding
                .verify(&wire, &in_hand_request_hash(), now)
                .unwrap_err(),
            LbAssertionV2Rejection::RequestHashMismatch
        );
    }

    #[test]
    fn v2_unknown_key_id_is_rejected() {
        let attestor = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = v2_binding();
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        let mut a = v2_assertion(&rh, now);
        a.key_id = "attestor-UNKNOWN".to_string();
        let wire = mint_v2(&attestor, &a);
        assert_eq!(
            binding.verify(&wire, &rh, now).unwrap_err(),
            LbAssertionV2Rejection::UnknownKeyId
        );
    }

    #[test]
    fn v2_bad_signature_is_rejected() {
        // Signed by a DIFFERENT attestor key than the one the node trusts for the
        // named key id.
        let wrong = SigningKey::from_seed_bytes(&[7u8; 32]);
        let binding = v2_binding();
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        let wire = mint_v2(&wrong, &v2_assertion(&rh, now));
        assert_eq!(
            binding.verify(&wire, &rh, now).unwrap_err(),
            LbAssertionV2Rejection::BadSignature
        );
    }

    #[test]
    fn v2_tampered_field_breaks_signature() {
        // A validly-signed assertion whose recorded revocation verdict is mutated on
        // the wire after signing: the preimage no longer matches ⇒ BadSignature
        // (the attacker cannot flip `revoked`→`good` without the attestor key).
        let attestor = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = v2_binding();
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        let signed = v2_assertion(&rh, now);
        let sig = attestor.sign(&signed.signing_preimage());
        // Re-render with a different revocation byte but the ORIGINAL signature.
        let mut tampered = signed.clone();
        tampered.revocation_result = AttestedRevocation::Revoked;
        let wire = tampered.to_wire(&sig);
        assert_eq!(
            binding.verify(&wire, &rh, now).unwrap_err(),
            LbAssertionV2Rejection::BadSignature
        );
    }

    #[test]
    fn v2_stale_and_future_are_rejected() {
        let attestor = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = v2_binding();
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        // Too old.
        let old = mint_v2(&attestor, &v2_assertion(&rh, now - 10_000));
        assert_eq!(
            binding.verify(&old, &rh, now).unwrap_err(),
            LbAssertionV2Rejection::Stale
        );
        // Implausibly far in the future.
        let future = mint_v2(&attestor, &v2_assertion(&rh, now + 10_000));
        assert_eq!(
            binding.verify(&future, &rh, now).unwrap_err(),
            LbAssertionV2Rejection::Stale
        );
    }

    #[test]
    fn v2_expiry_is_enforced_but_future_expiry_is_accepted() {
        let attestor = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = v2_binding();
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        // expires_at already passed (still within the freshness window) ⇒ Expired.
        let mut expired = v2_assertion(&rh, now);
        expired.expires_at = Some(now - 1);
        assert_eq!(
            binding
                .verify(&mint_v2(&attestor, &expired), &rh, now)
                .unwrap_err(),
            LbAssertionV2Rejection::Expired
        );
        // A future expiry is fine.
        let mut ok = v2_assertion(&rh, now);
        ok.expires_at = Some(now + 5);
        assert!(binding.verify(&mint_v2(&attestor, &ok), &rh, now).is_ok());
    }

    #[test]
    fn v2_audience_mismatch_is_rejected() {
        let attestor = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = v2_binding();
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        let mut a = v2_assertion(&rh, now);
        a.audience = "did:example:some-other-server".to_string();
        assert_eq!(
            binding
                .verify(&mint_v2(&attestor, &a), &rh, now)
                .unwrap_err(),
            LbAssertionV2Rejection::AudienceMismatch
        );
    }

    #[test]
    fn v2_untrusted_ingress_identity_is_rejected() {
        let attestor = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = v2_binding();
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        let mut a = v2_assertion(&rh, now);
        a.ingress_identity = "spiffe://example.org/rogue-ingress".to_string();
        assert_eq!(
            binding
                .verify(&mint_v2(&attestor, &a), &rh, now)
                .unwrap_err(),
            LbAssertionV2Rejection::UntrustedIngressIdentity
        );
    }

    #[test]
    fn v2_recorded_facts_admission_fails_closed() {
        // The attestor's opaque verdicts are admitted by fail-closed policy: only
        // (Verified, Good) passes. Each negative verdict yields a DISTINCT auditable
        // rejection — the offline evidence spine MCPS-62 asserts against these.
        let attestor = SigningKey::from_seed_bytes(&LB_SEED);
        let binding = v2_binding();
        let now = 1_000_000;
        let rh = in_hand_request_hash();

        let mut cert_failed = v2_assertion(&rh, now);
        cert_failed.cert_verification_result = AttestedCertVerification::Failed;
        assert_eq!(
            binding
                .verify(&mint_v2(&attestor, &cert_failed), &rh, now)
                .unwrap_err(),
            LbAssertionV2Rejection::CertificateNotVerified
        );

        for (verdict, expected) in [
            (AttestedRevocation::Revoked, LbAssertionV2Rejection::Revoked),
            (
                AttestedRevocation::Unknown,
                LbAssertionV2Rejection::RevocationUnknown,
            ),
            (
                AttestedRevocation::StaleCrl,
                LbAssertionV2Rejection::StaleRevocation,
            ),
        ] {
            let mut a = v2_assertion(&rh, now);
            a.revocation_result = verdict;
            assert_eq!(
                binding
                    .verify(&mint_v2(&attestor, &a), &rh, now)
                    .unwrap_err(),
                expected,
                "revocation verdict {verdict:?} must fail closed"
            );
        }
    }

    #[test]
    fn v2_malformed_framing_is_rejected() {
        let binding = v2_binding();
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        // Wrong field count (v1's 5-field shape, not v2's 11).
        assert_eq!(
            binding.verify("a.b.c.d.e", &rh, now).unwrap_err(),
            LbAssertionV2Rejection::Malformed
        );
        // Empty.
        assert_eq!(
            binding.verify("", &rh, now).unwrap_err(),
            LbAssertionV2Rejection::Malformed
        );
    }

    #[test]
    fn v2_malformed_enum_discriminant_is_rejected() {
        // A syntactically well-framed wire value whose cert-result field carries an
        // UNASSIGNED discriminant byte fails closed at parse (never silently
        // defaults). Field 5 (0-indexed) is cert_verification_result.
        let attestor = SigningKey::from_seed_bytes(&LB_SEED);
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        let wire = mint_v2(&attestor, &v2_assertion(&rh, now));
        let mut parts: Vec<&str> = wire.split('.').collect();
        let bogus = b64url_encode(&[9u8]); // 9 is unassigned
        parts[5] = &bogus;
        let mutated = parts.join(".");
        assert_eq!(
            v2_binding().verify(&mutated, &rh, now).unwrap_err(),
            LbAssertionV2Rejection::Malformed
        );
    }

    #[test]
    fn v2_domain_tag_differs_from_v1_and_preimage_is_disjoint() {
        // Cross-version confusion guard: for identical shared field values the v1
        // and v2 preimages must be DISJOINT (different domain tag as the leading
        // bytes), so a v1 signature can never be re-framed as a v2 assertion.
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        let v1 = LbAssertion {
            key_id: "k".to_string(),
            asserted_client_identity: V2_CLIENT.to_string(),
            request_hash: rh.clone(),
            validation_time: now,
        };
        let v2 = v2_assertion(&rh, now);
        assert_ne!(v1.signing_preimage(), v2.signing_preimage());
        assert!(v2
            .signing_preimage()
            .starts_with(b"mcp-re/lb-ingress-assertion/v2"));
        assert!(!v2
            .signing_preimage()
            .starts_with(b"mcp-re/lb-ingress-assertion/v1"));
    }

    #[test]
    fn v2_signing_preimage_is_length_prefixed_and_unambiguous() {
        // Moving a byte across the key_id/ingress_identity boundary must change the
        // preimage (length-prefix framing defeats the delimiter-collision class).
        let now = 1_000_000;
        let rh = in_hand_request_hash();
        let mut a = v2_assertion(&rh, now);
        a.key_id = "ab".to_string();
        a.ingress_identity = "cd".to_string();
        let mut b = a.clone();
        b.key_id = "abc".to_string();
        b.ingress_identity = "d".to_string();
        assert_ne!(a.signing_preimage(), b.signing_preimage());
    }

    #[test]
    fn v2_guarantee_is_attested_delegation_not_end_to_end() {
        // HONESTY (§C decision): Mode C is attested delegation and MUST NEVER be
        // surfaced as end-to-end client↔node mTLS.
        assert_eq!(
            LbAssertionV2Binding::GUARANTEE,
            "attested_ingress_delegation"
        );
        assert!(!LbAssertionV2Binding::GUARANTEE.contains("end_to_end"));
    }
}
