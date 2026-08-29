// SPDX-License-Identifier: Apache-2.0
//! Mode C / Tier 4 — the frozen `mcp-re/lb-ingress-assertion/v2` assertion.
//!
//! A genuinely NEW frozen format, not an extension of [`super::v1`]: its own
//! domain-separation tag, its own field layout, its own verifier order and its own
//! rejection vocabulary. The tag is the leading bytes of the preimage, so a v1 signature
//! can never be re-framed as a v2 assertion — the facade holds the test that says so.
//!
//! Reachability is the facade's fact, not this module's: see [`super`].

use std::collections::BTreeSet;

use mcp_re_core::b64url_decode;
use mcp_re_core::b64url_encode;
use mcp_re_core::parse_hash_id;
use mcp_re_core::verify_ed25519_with;
use mcp_re_core::McpReError;
use mcp_re_core::VerificationKey;

use super::v1::DEFAULT_LB_ASSERTION_MAX_AGE_SECS;
use super::LbKeyEntry;
use crate::transport::validate_asserted_identity_value;
use crate::transport::IdentitySource;
use crate::transport::TransportIdentity;

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

/// The EARNED outcome of a Mode-C assertion: the request-bound client identity plus the
/// attestor's recorded facts, which the proxy emits as the three §C2 audit trust facts.
///
/// # Why the representation is private
///
/// The name is the claim. With five public fields, anything that could name the type could
/// build one with `cert_verification_result: Verified` — a `Verified`-shaped value that had
/// verified nothing, which is the defect EX-004 found in `EvidenceCommitment`. Its current
/// unreachability limited the exposure; it did not make the representation sound.
///
/// [`LbAssertionV2Binding::verify`] is now the only producer, and it reaches this
/// construction only after eight checks — framing, audience, attestor key, signature,
/// request binding, freshness, ingress-identity allowlist, and the recorded-facts
/// admission. Two of those are what the projections below can therefore assert without
/// re-reading anything: a value of this type carries
/// [`AttestedCertVerification::Verified`] and [`AttestedRevocation::Good`], because every
/// other verdict returned `Err` before it existed.
///
/// Sealing changes nothing about deployment reachability. Mode C stays refused at Layer-A
/// validation; what changed is that the type now means what it says if it ever is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedIngressVerified {
    /// The verified, request-bound delegated client identity (audit
    /// `delegated_client_identity`). Flows into the same [`TransportBindingPolicy`]
    /// the direct-TLS path uses.
    client_identity: TransportIdentity,
    /// The attestor's own ingress identity (audit `ingress_internal_hop`).
    ingress_identity: String,
    /// The attestor's admitted certificate-verification verdict (recorded).
    cert_verification_result: AttestedCertVerification,
    /// The attestor's admitted revocation verdict (recorded).
    revocation_result: AttestedRevocation,
    /// The CRL `nextUpdate` the attestor consulted (recorded for audit only).
    crl_next_update: i64,
}

impl AttestedIngressVerified {
    /// The client identity the assertion carried.
    pub fn client_identity(&self) -> &TransportIdentity {
        &self.client_identity
    }

    /// The attestor's own ingress identity, for the audit record.
    pub fn ingress_identity(&self) -> &str {
        &self.ingress_identity
    }

    /// The attestor's certificate-verification verdict, as admitted.
    ///
    /// Recorded, never recomputed: this node binds the attestor's statement, it does not
    /// re-derive it (§C3, bind-not-interpret). Only [`AttestedCertVerification::Verified`]
    /// reaches a value of this type at all.
    pub fn cert_verification_result(&self) -> AttestedCertVerification {
        self.cert_verification_result
    }

    /// The attestor's revocation verdict, as admitted. Only
    /// [`AttestedRevocation::Good`] reaches a value of this type.
    pub fn revocation_result(&self) -> AttestedRevocation {
        self.revocation_result
    }

    /// The CRL `nextUpdate` the attestor consulted, for the audit record.
    pub fn crl_next_update(&self) -> i64 {
        self.crl_next_update
    }
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
            client_identity: TransportIdentity::attested_by_verified_ingress(
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
    use super::*;
    use crate::transport::ingress::test_support::in_hand_request_hash;
    use crate::transport::ingress::test_support::LB_SEED;
    use mcp_re_core::sha256_hash_id;
    use mcp_re_core::SigningKey;

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
            TransportIdentity::attested_by_verified_ingress(V2_CLIENT, IdentitySource::UriSan)
        );
        assert_eq!(verified.ingress_identity(), V2_INGRESS_ID);
        assert_eq!(
            verified.cert_verification_result(),
            AttestedCertVerification::Verified
        );
        assert_eq!(verified.revocation_result(), AttestedRevocation::Good);
        assert_eq!(verified.crl_next_update(), now + 86_400);
        // Mode C attests an identity rather than authenticating a TLS peer, so what this
        // pins is the identity the attestation carried. The Slice-4 binding relation takes
        // two semantic products and this path produces neither; Mode C is refused by
        // configuration validation, and rebinding it onto the request evidence is the
        // unspecified work that refusal names.
        assert_eq!(verified.client_identity().value(), V2_CLIENT);
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
