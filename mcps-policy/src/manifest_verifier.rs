//! Signed tool-manifest verifier (issue #3866).
//!
//! Mirrors the [`crate::profile::AuthorizationProfile`] shape — hash-bind →
//! verify-then-decide, with revocation injected as a trait — applied to a signed
//! tool manifest. The verifier is PURE (no I/O, no clock): the caller passes
//! `now_unix`, the [`mcps_core::TrustResolver`], the
//! [`crate::revocation::RevocationSource`], and a mutable
//! [`crate::manifest_pin::ManifestPinStore`].
//!
//! ## Order of checks (fail closed — any failure rejects, never accepts)
//!
//! 1. **Schema-hash binding.** Recompute every tool's
//!    `sha256_hash_id(canonicalize(schema))` and compare against the recorded
//!    `schema_hash` (constant-shape per-field comparison). Mismatch →
//!    [`ManifestError::ManifestSchemaHashMismatch`]. This happens BEFORE trusting
//!    the manifest's identity so a self-inconsistent manifest is rejected even if
//!    well signed.
//! 2. **Identity self-consistency.** The top-level `key_id` and `signature.key_id`
//!    are both inside the signed preimage and MUST agree; a divergence (which the
//!    key resolution would otherwise silently ignore, since it resolves on
//!    `signature.key_id`) → [`ManifestError::ManifestMalformed`].
//! 3. **Signing authority + signature.** Resolve `(signer, signature.key_id)`
//!    through the injected resolver; verify the Ed25519 signature over the
//!    canonical manifest minus `signature.value`. Unknown signer / malformed key →
//!    [`ManifestError::ManifestSignerUnresolved`]; unsupported alg →
//!    [`ManifestError::ManifestUnsupportedAlg`]; bad signature →
//!    [`ManifestError::ManifestSignatureInvalid`].
//! 4. **Revocation.** A revoked `manifest_id` (or the composite `signer#version`) →
//!    [`ManifestError::ManifestRevoked`].
//! 5. **Validity window.** `now` must be within `[issued_at − skew, expires_at +
//!    skew]` (symmetric [`MAX_CLOCK_SKEW_SECS`], matching Core freshness) when
//!    those bounds are present → else [`ManifestError::ManifestExpired`].
//! 6. **Rug-pull pin.** Duplicate tool names within the manifest are rejected
//!    first as [`ManifestError::ManifestMalformed`] (`name` is the pin key, so two
//!    entries for one name are self-contradictory). Then, for each tool,
//!    `(name, version, schema_hash)` is checked against the pin store; a changed
//!    schema under the same `(name, version)` → [`ManifestError::ManifestRugPull`].
//!    The pin store is updated only after ALL earlier checks pass — and the dedup
//!    + read-only pre-check guarantee the commit loop cannot fail mid-iteration, so
//!    a rejected manifest never leaves the store partially mutated (P7-04, #4064).

use std::collections::BTreeSet;

use mcps_core::verify_ed25519_with;
use mcps_core::McpsError;
use mcps_core::TrustResolver;
use mcps_core::SIG_ALG_ED25519;
use serde_json::json;

use crate::manifest::manifest_signing_preimage;
use crate::manifest::ToolManifest;
use crate::manifest_error::ManifestError;
use crate::manifest_pin::ManifestPinStore;
use crate::revocation::RevocationSource;
use crate::revocation::RevocationStatus;

/// The verified `(name, version, schema_hash)` triple exposed per tool after a
/// manifest verifies. Tool versioning is first-class: `version` is part of the
/// tool identity and travels with the schema hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTool {
    /// The tool name.
    pub name: String,
    /// The tool version (identity component).
    pub version: String,
    /// The verified `schema_hash` (recomputed and matched against the manifest).
    pub schema_hash: String,
}

/// M05 (#4076): breadth bound on the number of tools a single signed manifest may
/// carry. A trust-boundary DoS guard — a hostile-but-resolvable manifest with an
/// absurd tool count is rejected before any per-tool work. Chosen deliberately
/// generous: real MCP servers expose tens to low hundreds of tools, so 4096 never
/// constrains a legitimate manifest while capping the work an attacker can force.
pub const MAX_TOOLS: usize = 4096;

/// M05 (#4076): per-tool size bound on the combined `{input, output}` schema, in
/// bytes of its compact JSON serialization. 1 MiB is enormous for a JSON Schema
/// (legitimate schemas are kilobytes), so this never rejects a real tool while
/// bounding the canonicalization/hash work a single tool can force.
pub const MAX_TOOL_SCHEMA_BYTES: usize = 1024 * 1024;

/// M05 (#4076): aggregate size bound across every tool's combined schema, in bytes
/// of compact JSON. Caps total work even when each individual tool is under the
/// per-tool bound. 16 MiB across all tools is far beyond any legitimate manifest.
pub const MAX_TOTAL_SCHEMA_BYTES: usize = 16 * 1024 * 1024;

/// The pure signed tool-manifest verifier. Stateless itself; all mutable state
/// (the pins) is held by the injected [`ManifestPinStore`].
#[derive(Debug, Clone, Default)]
pub struct ManifestVerifier;

impl ManifestVerifier {
    /// Construct the verifier.
    pub fn new() -> Self {
        ManifestVerifier
    }

    /// Verify a signed manifest end to end. On success returns the per-tool
    /// `(name, version, schema_hash)` triples and records/updates the pins; on any
    /// failure returns the precise [`ManifestError`] and leaves the pin store
    /// unchanged.
    pub fn verify(
        &self,
        manifest: &ToolManifest,
        resolver: &dyn TrustResolver,
        revocation: &dyn RevocationSource,
        pins: &mut dyn ManifestPinStore,
        now_unix: i64,
    ) -> Result<Vec<VerifiedTool>, ManifestError> {
        // (0) Breadth/size bounds (M05, #4076). A hostile-but-resolvable signed
        // manifest with an absurd tool count or enormous schema blobs is a DoS at
        // the trust boundary. Reject ManifestMalformed BEFORE any per-tool work
        // (canonicalization, hashing, signature verify) and before the commit loop,
        // consistent with the deny-before-commit contract.
        self.check_size_bounds(manifest)?;

        // (1) Schema-hash binding: recompute every tool's schema_hash and compare.
        self.check_schema_hashes(manifest)?;

        // (1b) Identity self-consistency: the top-level `key_id` and the
        // `signature.key_id` are both inside the signed preimage and MUST agree.
        // The verifier resolves the key on `signature.key_id`; the redundant
        // top-level `key_id` (#85 findings 2+3, #87 finding 3) is otherwise never
        // read, so a mismatched manifest would be silently accepted. Cross-check
        // them and reject ManifestMalformed on divergence — fail closed and remove
        // the silent-mismatch footgun (the field stays in the signed wire shape so
        // existing readers/the documented format are unaffected).
        if manifest.key_id != manifest.signature.key_id {
            return Err(ManifestError::ManifestMalformed);
        }

        // (2) Signing authority + Ed25519 signature over the canonical preimage.
        self.verify_signature(manifest, resolver)?;

        // (3) Revocation (manifest_id OR signer#version). Fail closed and, per
        // M-10 (#3839), distinguish an actual revocation from an UNAVAILABLE
        // revocation source: both deny, but with distinct tokens, and an outage
        // never silently passes as "not revoked". The trait's bool→Result change
        // (#3839, M-10) and this verifier (#3866) landed in parallel; this wires
        // the verifier to the current `revocation_status` API.
        let composite = composite_revocation_id(manifest);
        for id in [manifest.manifest_id.as_str(), composite.as_str()] {
            match revocation.revocation_status(id) {
                Ok(RevocationStatus::NotRevoked) => {}
                Ok(RevocationStatus::Revoked) => return Err(ManifestError::ManifestRevoked),
                Err(_) => return Err(ManifestError::ManifestRevocationUnavailable),
            }
        }

        // (4) Validity window (only enforced where the optional bounds are present).
        check_window(manifest, now_unix)?;

        // (5) Rug-pull pin check. Build the triples first so NO pin is mutated
        // unless every tool passes — preserving "leave the pin store unchanged on
        // reject" for the rug-pull case too (an earlier tool must not be pinned if
        // a later tool is a rug pull).
        let verified: Vec<VerifiedTool> = manifest
            .tools
            .iter()
            .map(|tool| VerifiedTool {
                name: tool.name.clone(),
                version: tool.version.clone(),
                schema_hash: tool.schema_hash.clone(),
            })
            .collect();

        // In-manifest duplicate tool names are malformed: `name` is the pin key, so
        // a manifest asserting two states for one name is self-contradictory. This
        // must be caught BEFORE the commit loop — otherwise the first entry would be
        // recorded and a conflicting second entry would fail `check_and_record`
        // mid-iteration, leaving the store partially mutated (P7-04, #4064). The
        // pre-check below is read-only, so it cannot see an earlier entry of the
        // SAME manifest the way the commit loop's `check_and_record` would; we detect
        // duplicates explicitly here so the pre-check accounts for in-manifest
        // duplicates the same way the commit does.
        let mut seen_names: BTreeSet<&str> = BTreeSet::new();
        for tool in &verified {
            if !seen_names.insert(tool.name.as_str()) {
                return Err(ManifestError::ManifestMalformed);
            }
        }

        for tool in &verified {
            // A read-only pre-check: a rug pull on ANY tool rejects the whole
            // manifest WITHOUT having recorded the others.
            if let Some((pinned_version, pinned_hash)) = pins.pinned(&tool.name) {
                if pinned_version == tool.version && pinned_hash != tool.schema_hash {
                    return Err(ManifestError::ManifestRugPull);
                }
            }
        }

        // All tools clear the dedup + rug-pull gates; now commit the pins. With
        // unique names and every (name, version, schema_hash) already cleared
        // against the pinned state, no `check_and_record` in this loop can fail —
        // so the commit cannot partial-mutate.
        for tool in &verified {
            pins.check_and_record(&tool.name, &tool.version, &tool.schema_hash)?;
        }

        Ok(verified)
    }

    /// Enforce the trust-boundary breadth/size bounds (M05, #4076): reject
    /// [`ManifestError::ManifestMalformed`] when the tool count exceeds
    /// [`MAX_TOOLS`], any single tool's combined `{input, output}` schema exceeds
    /// [`MAX_TOOL_SCHEMA_BYTES`], or the aggregate across all tools exceeds
    /// [`MAX_TOTAL_SCHEMA_BYTES`]. Pure and allocation-light: schema size is the
    /// byte length of the compact JSON serialization (an over-approximation of the
    /// canonical form, which is fine for a generous upper bound). Runs first so a
    /// hostile manifest is capped before any canonicalization/hash/verify work.
    fn check_size_bounds(&self, manifest: &ToolManifest) -> Result<(), ManifestError> {
        if manifest.tools.len() > MAX_TOOLS {
            return Err(ManifestError::ManifestMalformed);
        }
        let mut total: usize = 0;
        for tool in &manifest.tools {
            let combined = json!({ "input": tool.input_schema, "output": tool.output_schema });
            let bytes =
                serde_json::to_vec(&combined).map_err(|_| ManifestError::ManifestMalformed)?;
            let len = bytes.len();
            if len > MAX_TOOL_SCHEMA_BYTES {
                return Err(ManifestError::ManifestMalformed);
            }
            total = total.saturating_add(len);
            if total > MAX_TOTAL_SCHEMA_BYTES {
                return Err(ManifestError::ManifestMalformed);
            }
        }
        Ok(())
    }

    /// Recompute and compare every tool's `schema_hash` (constant-shape: a direct
    /// per-field string comparison; mismatch rejects).
    fn check_schema_hashes(&self, manifest: &ToolManifest) -> Result<(), ManifestError> {
        for tool in &manifest.tools {
            let recomputed = tool.recompute_schema_hash()?;
            if recomputed != tool.schema_hash {
                return Err(ManifestError::ManifestSchemaHashMismatch);
            }
        }
        Ok(())
    }

    /// Resolve the signing authority and verify the Ed25519 signature over the
    /// canonical manifest minus `signature.value`.
    fn verify_signature(
        &self,
        manifest: &ToolManifest,
        resolver: &dyn TrustResolver,
    ) -> Result<(), ManifestError> {
        if manifest.signature.alg != SIG_ALG_ED25519 {
            return Err(ManifestError::ManifestUnsupportedAlg);
        }
        let preimage = manifest_signing_preimage(manifest)?;
        let key = resolver
            .resolve(&manifest.signer, &manifest.signature.key_id)
            .map_err(|_| ManifestError::ManifestSignerUnresolved)?;
        // `verify_ed25519_with` returns its own McpsError sentinel on any failure;
        // we discard it and surface the manifest-layer reject code.
        verify_ed25519_with(
            &preimage,
            &manifest.signature.value,
            &key,
            McpsError::InvalidSignature,
        )
        .map_err(|_| ManifestError::ManifestSignatureInvalid)
    }
}

/// The composite revocation handle binding `(signer, version)`, accepted
/// alongside the `manifest_id` so deployments can revoke either way (issue #3866
/// §4).
///
/// M04 (#4076): a naive `signer#version` concatenation is AMBIGUOUS — if `signer`
/// itself contains `#`, two distinct `(signer, version)` pairs collide to the same
/// handle (`("a#b","c")` and `("a","b#c")` both become `"a#b#c"`), so revoking one
/// silently revokes the other. We length-prefix each component so the encoding is
/// injective: distinct `(signer, version)` pairs ALWAYS map to distinct handles.
/// The handle reads `mcps.manifest.composite.v1:<len(signer)>#<signer><version>`,
/// where `<len(signer)>` is the byte length of `signer` — the only `#` with a
/// structural role is the one terminating the length, and the boundary between
/// `signer` and `version` is fixed by that length, not by scanning for a `#`.
fn composite_revocation_id(manifest: &ToolManifest) -> String {
    format!(
        "mcps.manifest.composite.v1:{}#{}{}",
        manifest.signer.len(),
        manifest.signer,
        manifest.version
    )
}

/// Symmetric clock-skew tolerance (seconds) applied to the manifest validity
/// window, matching Core freshness (MCPS-07 / [`mcps_core::check_freshness`]) and
/// the conformance harnesses' `MAX_CLOCK_SKEW_SECS`. The two trust-boundary time
/// checks (request freshness and manifest validity) MUST tolerate the same skew so
/// a manifest is not spuriously rejected at one boundary while a request issued
/// against the same clock is accepted at the other (#87 finding 2). Five minutes
/// is the standard allowance used throughout the codebase.
pub const MAX_CLOCK_SKEW_SECS: i64 = 300;

/// Validity-window check with a symmetric clock-skew tolerance, mirroring Core
/// freshness ([`mcps_core::check_freshness`]): the effective window is
/// `[issued_at − skew, expires_at + skew]` (both bounds inclusive). When
/// `issued_at` is present, `now` must be >= `issued_at − skew`; when `expires_at`
/// is present, `now` must be <= `expires_at + skew`. Absent bounds impose no
/// limit. `saturating_*` keeps the arithmetic fail-closed at the i64 extremes.
fn check_window(manifest: &ToolManifest, now_unix: i64) -> Result<(), ManifestError> {
    if let Some(issued_at) = manifest.issued_at {
        if now_unix < issued_at.saturating_sub(MAX_CLOCK_SKEW_SECS) {
            return Err(ManifestError::ManifestExpired);
        }
    }
    if let Some(expires_at) = manifest.expires_at {
        if now_unix > expires_at.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return Err(ManifestError::ManifestExpired);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::composite_revocation_id;
    use super::ManifestVerifier;
    use super::MAX_TOOLS;
    use super::MAX_TOOL_SCHEMA_BYTES;
    use crate::manifest::mint_signed_manifest;
    use crate::manifest::ManifestSpec;
    use crate::manifest::ToolSpec;
    use crate::manifest_error::ManifestError;
    use crate::manifest_pin::InMemoryManifestPinStore;
    use crate::manifest_pin::ManifestPinStore;
    use crate::revocation::InMemoryRevocationSource;
    use crate::revocation::RevocationSource;
    use crate::revocation::RevocationStatus;
    use mcps_core::InMemoryTrustResolver;
    use mcps_core::SigningKey;
    use serde_json::json;
    use serde_json::Value;

    const SIGNER: &str = "did:example:server-1";
    const KEY_ID: &str = "server-key-1";
    const NOW: i64 = 1_700_000_500;

    fn signing_key() -> SigningKey {
        SigningKey::from_seed_bytes(&[5u8; 32])
    }

    fn resolver() -> InMemoryTrustResolver {
        let mut r = InMemoryTrustResolver::new();
        r.insert(SIGNER, KEY_ID, signing_key().public_key());
        r
    }

    fn input_schema() -> Value {
        json!({ "type": "object", "properties": { "text": { "type": "string" } } })
    }

    fn spec_with(version: &str, tool_version: &str, tool_input: Value) -> ManifestSpec {
        ManifestSpec {
            signer: SIGNER.to_string(),
            manifest_id: "manifest-1".to_string(),
            version: version.to_string(),
            issued_at: Some(1_700_000_000),
            expires_at: Some(1_800_000_000),
            tools: vec![ToolSpec {
                name: "echo".to_string(),
                version: tool_version.to_string(),
                input_schema: tool_input,
                output_schema: json!({ "type": "string" }),
            }],
        }
    }

    fn default_spec() -> ManifestSpec {
        spec_with("1", "1.0.0", input_schema())
    }

    /// Build a manifest spec carrying an explicit list of `(name, version,
    /// input_schema)` tools (output schema fixed). Lets tests construct
    /// multi-tool and duplicate-name manifests.
    fn spec_with_tools(version: &str, tools: Vec<(&str, &str, Value)>) -> ManifestSpec {
        ManifestSpec {
            signer: SIGNER.to_string(),
            manifest_id: "manifest-1".to_string(),
            version: version.to_string(),
            issued_at: Some(1_700_000_000),
            expires_at: Some(1_800_000_000),
            tools: tools
                .into_iter()
                .map(|(name, tool_version, tool_input)| ToolSpec {
                    name: name.to_string(),
                    version: tool_version.to_string(),
                    input_schema: tool_input,
                    output_schema: json!({ "type": "string" }),
                })
                .collect(),
        }
    }

    #[test]
    fn valid_signed_manifest_verifies_and_pins() {
        let manifest = mint_signed_manifest(&default_spec(), &signing_key(), KEY_ID).unwrap();
        let mut pins = InMemoryManifestPinStore::new();
        let verified = ManifestVerifier::new()
            .verify(
                &manifest,
                &resolver(),
                &InMemoryRevocationSource::new(),
                &mut pins,
                NOW,
            )
            .expect("valid manifest must verify");
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0].name, "echo");
        assert_eq!(verified[0].version, "1.0.0");
        assert_eq!(verified[0].schema_hash, manifest.tools[0].schema_hash);
        // The pin was recorded.
        assert_eq!(
            pins.pinned("echo"),
            Some(("1.0.0".to_string(), manifest.tools[0].schema_hash.clone()))
        );
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let mut manifest = mint_signed_manifest(&default_spec(), &signing_key(), KEY_ID).unwrap();
        // Flip a byte in the signature value (still valid b64url shape).
        let mut bytes = manifest.signature.value.into_bytes();
        bytes[0] = if bytes[0] == b'A' { b'B' } else { b'A' };
        manifest.signature.value = String::from_utf8(bytes).unwrap();
        let mut pins = InMemoryManifestPinStore::new();
        assert_eq!(
            ManifestVerifier::new().verify(
                &manifest,
                &resolver(),
                &InMemoryRevocationSource::new(),
                &mut pins,
                NOW,
            ),
            Err(ManifestError::ManifestSignatureInvalid)
        );
    }

    #[test]
    fn tampered_content_after_signing_is_rejected() {
        let mut manifest = mint_signed_manifest(&default_spec(), &signing_key(), KEY_ID).unwrap();
        // Change the manifest version AFTER signing: signature no longer covers it.
        manifest.version = "evil".to_string();
        let mut pins = InMemoryManifestPinStore::new();
        assert_eq!(
            ManifestVerifier::new().verify(
                &manifest,
                &resolver(),
                &InMemoryRevocationSource::new(),
                &mut pins,
                NOW,
            ),
            Err(ManifestError::ManifestSignatureInvalid)
        );
    }

    #[test]
    fn unknown_signer_is_rejected() {
        let manifest = mint_signed_manifest(&default_spec(), &signing_key(), KEY_ID).unwrap();
        let empty_resolver = InMemoryTrustResolver::new();
        let mut pins = InMemoryManifestPinStore::new();
        assert_eq!(
            ManifestVerifier::new().verify(
                &manifest,
                &empty_resolver,
                &InMemoryRevocationSource::new(),
                &mut pins,
                NOW,
            ),
            Err(ManifestError::ManifestSignerUnresolved)
        );
    }

    #[test]
    fn unsupported_alg_is_rejected() {
        let mut manifest = mint_signed_manifest(&default_spec(), &signing_key(), KEY_ID).unwrap();
        manifest.signature.alg = "RSA".to_string();
        let mut pins = InMemoryManifestPinStore::new();
        assert_eq!(
            ManifestVerifier::new().verify(
                &manifest,
                &resolver(),
                &InMemoryRevocationSource::new(),
                &mut pins,
                NOW,
            ),
            Err(ManifestError::ManifestUnsupportedAlg)
        );
    }

    #[test]
    fn recomputed_schema_hash_mismatch_is_rejected() {
        let mut manifest = mint_signed_manifest(&default_spec(), &signing_key(), KEY_ID).unwrap();
        // Corrupt the recorded schema_hash so it no longer matches the schema.
        manifest.tools[0].schema_hash = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
        let mut pins = InMemoryManifestPinStore::new();
        // Schema-hash binding is checked BEFORE the signature, so this is the
        // reject reason even though the signature is now also stale.
        assert_eq!(
            ManifestVerifier::new().verify(
                &manifest,
                &resolver(),
                &InMemoryRevocationSource::new(),
                &mut pins,
                NOW,
            ),
            Err(ManifestError::ManifestSchemaHashMismatch)
        );
    }

    #[test]
    fn revoked_manifest_id_is_rejected() {
        let manifest = mint_signed_manifest(&default_spec(), &signing_key(), KEY_ID).unwrap();
        let mut revocation = InMemoryRevocationSource::new();
        revocation.revoke("manifest-1");
        let mut pins = InMemoryManifestPinStore::new();
        assert_eq!(
            ManifestVerifier::new().verify(&manifest, &resolver(), &revocation, &mut pins, NOW),
            Err(ManifestError::ManifestRevoked)
        );
    }

    #[test]
    fn revoked_signer_version_composite_is_rejected() {
        let manifest = mint_signed_manifest(&default_spec(), &signing_key(), KEY_ID).unwrap();
        let mut revocation = InMemoryRevocationSource::new();
        // Revoke via the unambiguous composite handle for this manifest's
        // (signer, version) pair (M04, #4076).
        revocation.revoke(composite_revocation_id(&manifest));
        let mut pins = InMemoryManifestPinStore::new();
        assert_eq!(
            ManifestVerifier::new().verify(&manifest, &resolver(), &revocation, &mut pins, NOW),
            Err(ManifestError::ManifestRevoked)
        );
    }

    #[test]
    fn unavailable_revocation_source_is_rejected_with_distinct_token() {
        // M-10 (#3839): an UNAVAILABLE revocation source must fail closed with a
        // token distinct from an actual revocation — never silently pass.
        struct AlwaysUnavailable;
        impl RevocationSource for AlwaysUnavailable {
            fn revocation_status(
                &self,
                _revocation_id: &str,
            ) -> Result<RevocationStatus, crate::revocation::RevocationUnavailable> {
                Err(crate::revocation::RevocationUnavailable::new("backend down"))
            }
        }
        let manifest = mint_signed_manifest(&default_spec(), &signing_key(), KEY_ID).unwrap();
        let mut pins = InMemoryManifestPinStore::new();
        assert_eq!(
            ManifestVerifier::new().verify(&manifest, &resolver(), &AlwaysUnavailable, &mut pins, NOW),
            Err(ManifestError::ManifestRevocationUnavailable)
        );
    }

    #[test]
    fn expired_manifest_is_rejected() {
        let manifest = mint_signed_manifest(&default_spec(), &signing_key(), KEY_ID).unwrap();
        let mut pins = InMemoryManifestPinStore::new();
        // now after expires_at (1_800_000_000).
        assert_eq!(
            ManifestVerifier::new().verify(
                &manifest,
                &resolver(),
                &InMemoryRevocationSource::new(),
                &mut pins,
                1_900_000_000,
            ),
            Err(ManifestError::ManifestExpired)
        );
    }

    #[test]
    fn mismatched_top_level_key_id_is_rejected_as_malformed() {
        // #85 findings 2+3 / #87 finding 3: the top-level `key_id` and
        // `signature.key_id` are both in the signed preimage and MUST agree. The
        // verifier resolves on `signature.key_id` and otherwise never reads the
        // top-level field, so a divergent top-level `key_id` would be silently
        // accepted without the cross-check. Mutate the top-level field AFTER signing
        // (it stays within the signed shape; the cross-check runs before signature
        // verification, so this is the reject reason).
        let mut manifest = mint_signed_manifest(&default_spec(), &signing_key(), KEY_ID).unwrap();
        manifest.key_id = "some-other-key".to_string();
        assert_ne!(manifest.key_id, manifest.signature.key_id);
        let mut pins = InMemoryManifestPinStore::new();
        assert_eq!(
            ManifestVerifier::new().verify(
                &manifest,
                &resolver(),
                &InMemoryRevocationSource::new(),
                &mut pins,
                NOW,
            ),
            Err(ManifestError::ManifestMalformed)
        );
    }

    #[test]
    fn issued_at_slightly_in_future_within_skew_is_accepted() {
        // #87 finding 2: a manifest whose `issued_at` is in the future relative to
        // `now`, but within MAX_CLOCK_SKEW_SECS, must be ACCEPTED — matching Core
        // freshness's symmetric skew tolerance. Evaluate at issued_at − skew (the
        // inclusive lower bound).
        use super::MAX_CLOCK_SKEW_SECS;
        let manifest = mint_signed_manifest(&default_spec(), &signing_key(), KEY_ID).unwrap();
        let issued_at = manifest.issued_at.expect("spec sets issued_at");
        let now_within_skew = issued_at - MAX_CLOCK_SKEW_SECS;
        let mut pins = InMemoryManifestPinStore::new();
        ManifestVerifier::new()
            .verify(
                &manifest,
                &resolver(),
                &InMemoryRevocationSource::new(),
                &mut pins,
                now_within_skew,
            )
            .expect("future-dated issued_at within skew must be accepted");
    }

    #[test]
    fn issued_at_beyond_skew_is_rejected() {
        // The mirror of the test above: one second BEYOND the skew tolerance on the
        // future side must be rejected as expired/out-of-window.
        use super::MAX_CLOCK_SKEW_SECS;
        let manifest = mint_signed_manifest(&default_spec(), &signing_key(), KEY_ID).unwrap();
        let issued_at = manifest.issued_at.expect("spec sets issued_at");
        let now_beyond_skew = issued_at - MAX_CLOCK_SKEW_SECS - 1;
        let mut pins = InMemoryManifestPinStore::new();
        assert_eq!(
            ManifestVerifier::new().verify(
                &manifest,
                &resolver(),
                &InMemoryRevocationSource::new(),
                &mut pins,
                now_beyond_skew,
            ),
            Err(ManifestError::ManifestExpired)
        );
    }

    #[test]
    fn expires_at_within_skew_is_accepted() {
        // Symmetric upper bound: `now` just past `expires_at` but within skew is
        // still accepted (inclusive expires_at + skew boundary).
        use super::MAX_CLOCK_SKEW_SECS;
        let manifest = mint_signed_manifest(&default_spec(), &signing_key(), KEY_ID).unwrap();
        let expires_at = manifest.expires_at.expect("spec sets expires_at");
        let now_within_skew = expires_at + MAX_CLOCK_SKEW_SECS;
        let mut pins = InMemoryManifestPinStore::new();
        ManifestVerifier::new()
            .verify(
                &manifest,
                &resolver(),
                &InMemoryRevocationSource::new(),
                &mut pins,
                now_within_skew,
            )
            .expect("now within expires_at + skew must be accepted");
    }

    #[test]
    fn rug_pull_same_version_changed_schema_is_rejected() {
        let verifier = ManifestVerifier::new();
        let resolver = resolver();
        let revocation = InMemoryRevocationSource::new();
        let mut pins = InMemoryManifestPinStore::new();

        // First, trusted manifest: pins echo@1.0.0 with its schema_hash.
        let first = mint_signed_manifest(&default_spec(), &signing_key(), KEY_ID).unwrap();
        verifier
            .verify(&first, &resolver, &revocation, &mut pins, NOW)
            .expect("first trust");

        // Second manifest: SAME tool name+version, DIFFERENT schema → rug pull.
        let evil_spec = spec_with(
            "1",
            "1.0.0",
            json!({ "type": "object", "properties": { "text": { "type": "number" }, "exfiltrate": { "type": "boolean" } } }),
        );
        let evil = mint_signed_manifest(&evil_spec, &signing_key(), KEY_ID).unwrap();
        assert_eq!(
            verifier.verify(&evil, &resolver, &revocation, &mut pins, NOW),
            Err(ManifestError::ManifestRugPull)
        );
        // The original pin is intact (not moved to the impostor schema).
        assert_eq!(
            pins.pinned("echo"),
            Some(("1.0.0".to_string(), first.tools[0].schema_hash.clone()))
        );
    }

    #[test]
    fn legitimate_version_bump_is_allowed_and_updates_pin() {
        let verifier = ManifestVerifier::new();
        let resolver = resolver();
        let revocation = InMemoryRevocationSource::new();
        let mut pins = InMemoryManifestPinStore::new();

        let first = mint_signed_manifest(&default_spec(), &signing_key(), KEY_ID).unwrap();
        verifier
            .verify(&first, &resolver, &revocation, &mut pins, NOW)
            .expect("first trust");

        // New tool version carrying a new schema → allowed, pin updated.
        let bumped_spec = spec_with(
            "2",
            "2.0.0",
            json!({ "type": "object", "properties": { "text": { "type": "string" }, "lang": { "type": "string" } } }),
        );
        let bumped = mint_signed_manifest(&bumped_spec, &signing_key(), KEY_ID).unwrap();
        let verified = verifier
            .verify(&bumped, &resolver, &revocation, &mut pins, NOW)
            .expect("version bump must be allowed");
        assert_eq!(verified[0].version, "2.0.0");
        assert_eq!(
            pins.pinned("echo"),
            Some(("2.0.0".to_string(), bumped.tools[0].schema_hash.clone()))
        );
    }

    #[test]
    fn duplicate_tool_name_is_rejected_without_partial_mutation() {
        // P7-04 (#4064): a signed manifest carrying two tools that share a name
        // but differ in schema_hash must be rejected AS A WHOLE with NO pin
        // committed for the first entry — the deny-before-commit guarantee.
        let verifier = ManifestVerifier::new();
        let resolver = resolver();
        let revocation = InMemoryRevocationSource::new();
        let mut pins = InMemoryManifestPinStore::new();

        // echo@1.0.0/hashA then echo@1.0.0/hashB (same name+version, different schema).
        let dup_spec = spec_with_tools(
            "1",
            vec![
                ("echo", "1.0.0", input_schema()),
                (
                    "echo",
                    "1.0.0",
                    json!({ "type": "object", "properties": { "text": { "type": "number" }, "exfiltrate": { "type": "boolean" } } }),
                ),
            ],
        );
        let dup = mint_signed_manifest(&dup_spec, &signing_key(), KEY_ID).unwrap();
        // Sanity: the two entries really do carry distinct schema hashes.
        assert_ne!(dup.tools[0].schema_hash, dup.tools[1].schema_hash);

        // Snapshot the store before (empty) and assert it is BYTE-FOR-BYTE
        // unchanged after the failed verify — echo was NOT pinned to hashA.
        let before = pins.pinned("echo");
        let result = verifier.verify(&dup, &resolver, &revocation, &mut pins, NOW);
        assert!(result.is_err(), "duplicate-name manifest must be rejected");
        assert_eq!(
            pins.pinned("echo"),
            before,
            "no partial mutation: echo must not be pinned to the first entry's hash"
        );
        assert_eq!(pins.pinned("echo"), None);
    }

    #[test]
    fn multi_tool_manifest_with_distinct_names_pins_all() {
        // Guard: a legitimate multi-tool manifest (distinct names) pins every tool.
        let verifier = ManifestVerifier::new();
        let resolver = resolver();
        let revocation = InMemoryRevocationSource::new();
        let mut pins = InMemoryManifestPinStore::new();

        let spec = spec_with_tools(
            "1",
            vec![
                ("echo", "1.0.0", input_schema()),
                ("sum", "2.0.0", json!({ "type": "object", "properties": { "n": { "type": "string" } } })),
            ],
        );
        let manifest = mint_signed_manifest(&spec, &signing_key(), KEY_ID).unwrap();
        let verified = verifier
            .verify(&manifest, &resolver, &revocation, &mut pins, NOW)
            .expect("distinct-name multi-tool manifest must verify");
        assert_eq!(verified.len(), 2);
        assert_eq!(
            pins.pinned("echo"),
            Some(("1.0.0".to_string(), manifest.tools[0].schema_hash.clone()))
        );
        assert_eq!(
            pins.pinned("sum"),
            Some(("2.0.0".to_string(), manifest.tools[1].schema_hash.clone()))
        );
    }

    #[test]
    fn single_entry_manifest_still_pins() {
        // Guard: the single-tool happy path is unaffected by the dedup check.
        let manifest = mint_signed_manifest(&default_spec(), &signing_key(), KEY_ID).unwrap();
        let mut pins = InMemoryManifestPinStore::new();
        let verified = ManifestVerifier::new()
            .verify(
                &manifest,
                &resolver(),
                &InMemoryRevocationSource::new(),
                &mut pins,
                NOW,
            )
            .expect("single-entry manifest must verify");
        assert_eq!(verified.len(), 1);
        assert_eq!(
            pins.pinned("echo"),
            Some(("1.0.0".to_string(), manifest.tools[0].schema_hash.clone()))
        );
    }

    #[test]
    fn composite_revocation_handle_does_not_collide_across_distinct_signer_version_pairs() {
        // M04 (#4076): the composite revocation handle must encode `(signer,
        // version)` UNAMBIGUOUSLY. A naive `signer#version` concatenation collides
        // when `signer` itself contains `#`: `("a#b","c")` and `("a","b#c")` both
        // flatten to `"a#b#c"`. Revoking the FIRST pair must NOT revoke the SECOND.
        let verifier = ManifestVerifier::new();

        // Two distinct signers that collide under naive `signer#version`.
        let signer_a = "did:evil#1";
        let signer_b = "did:evil";

        // Trust both signers (same key material is fine; identity is the signer
        // string + key_id, and resolution is what binds the signature).
        let mut resolver = InMemoryTrustResolver::new();
        resolver.insert(signer_a, KEY_ID, signing_key().public_key());
        resolver.insert(signer_b, KEY_ID, signing_key().public_key());

        // Pair A: signer "did:evil#1", version "2"  → composite "did:evil#1#2".
        let spec_a = ManifestSpec {
            signer: signer_a.to_string(),
            manifest_id: "manifest-A".to_string(),
            version: "2".to_string(),
            issued_at: Some(1_700_000_000),
            expires_at: Some(1_800_000_000),
            tools: vec![ToolSpec {
                name: "echo".to_string(),
                version: "1.0.0".to_string(),
                input_schema: input_schema(),
                output_schema: json!({ "type": "string" }),
            }],
        };
        // Pair B: signer "did:evil", version "1#2" → naive composite "did:evil#1#2".
        let spec_b = ManifestSpec {
            signer: signer_b.to_string(),
            manifest_id: "manifest-B".to_string(),
            version: "1#2".to_string(),
            issued_at: Some(1_700_000_000),
            expires_at: Some(1_800_000_000),
            tools: vec![ToolSpec {
                name: "echo".to_string(),
                version: "1.0.0".to_string(),
                input_schema: input_schema(),
                output_schema: json!({ "type": "string" }),
            }],
        };
        let manifest_a = mint_signed_manifest(&spec_a, &signing_key(), KEY_ID).unwrap();
        let manifest_b = mint_signed_manifest(&spec_b, &signing_key(), KEY_ID).unwrap();

        // Revoke ONLY pair A's composite handle.
        let mut revocation = InMemoryRevocationSource::new();
        revocation.revoke(composite_revocation_id(&manifest_a));

        // Pair A is revoked.
        let mut pins_a = InMemoryManifestPinStore::new();
        assert_eq!(
            verifier.verify(&manifest_a, &resolver, &revocation, &mut pins_a, NOW),
            Err(ManifestError::ManifestRevoked)
        );

        // Pair B is a DISTINCT (signer, version) pair and was NOT revoked — under a
        // naive `signer#version` handle it would collide with A and be falsely
        // rejected. With an unambiguous handle it must verify cleanly.
        let mut pins_b = InMemoryManifestPinStore::new();
        verifier
            .verify(&manifest_b, &resolver, &revocation, &mut pins_b, NOW)
            .expect("distinct (signer,version) pair must not collide with a revoked one");
    }

    #[test]
    fn excessive_tool_count_is_rejected_as_malformed_without_mutating_pins() {
        // M05 (#4076): a hostile-but-resolvable signed manifest with an absurd tool
        // count is a DoS at the trust boundary. The verifier must enforce a breadth
        // bound and reject with ManifestMalformed BEFORE the commit loop — leaving
        // the pin store untouched.
        let tool_specs: Vec<ToolSpec> = (0..=MAX_TOOLS)
            .map(|i| ToolSpec {
                name: format!("tool-{i}"),
                version: "1.0.0".to_string(),
                input_schema: input_schema(),
                output_schema: json!({ "type": "string" }),
            })
            .collect();
        let spec = ManifestSpec {
            signer: SIGNER.to_string(),
            manifest_id: "manifest-1".to_string(),
            version: "1".to_string(),
            issued_at: Some(1_700_000_000),
            expires_at: Some(1_800_000_000),
            tools: tool_specs,
        };
        let manifest = mint_signed_manifest(&spec, &signing_key(), KEY_ID).unwrap();
        let mut pins = InMemoryManifestPinStore::new();
        assert_eq!(
            ManifestVerifier::new().verify(
                &manifest,
                &resolver(),
                &InMemoryRevocationSource::new(),
                &mut pins,
                NOW,
            ),
            Err(ManifestError::ManifestMalformed)
        );
        // Deny-before-commit: nothing was pinned.
        assert_eq!(pins.pinned("tool-0"), None);
    }

    #[test]
    fn oversized_tool_schema_is_rejected_as_malformed_without_mutating_pins() {
        // M05 (#4076): a single tool carrying an enormous schema blob is a DoS even
        // at a small tool count. The verifier must enforce a per-tool schema-size
        // bound and reject ManifestMalformed BEFORE committing any pin.
        let mut huge_props = serde_json::Map::new();
        // Build a schema whose serialized size exceeds MAX_TOOL_SCHEMA_BYTES.
        let entries = (MAX_TOOL_SCHEMA_BYTES / 16) + 16;
        for i in 0..entries {
            huge_props.insert(
                format!("k{i}"),
                json!({ "type": "string" }),
            );
        }
        let huge_schema = json!({ "type": "object", "properties": Value::Object(huge_props) });
        let spec = ManifestSpec {
            signer: SIGNER.to_string(),
            manifest_id: "manifest-1".to_string(),
            version: "1".to_string(),
            issued_at: Some(1_700_000_000),
            expires_at: Some(1_800_000_000),
            tools: vec![ToolSpec {
                name: "echo".to_string(),
                version: "1.0.0".to_string(),
                input_schema: huge_schema,
                output_schema: json!({ "type": "string" }),
            }],
        };
        let manifest = mint_signed_manifest(&spec, &signing_key(), KEY_ID).unwrap();
        let mut pins = InMemoryManifestPinStore::new();
        assert_eq!(
            ManifestVerifier::new().verify(
                &manifest,
                &resolver(),
                &InMemoryRevocationSource::new(),
                &mut pins,
                NOW,
            ),
            Err(ManifestError::ManifestMalformed)
        );
        assert_eq!(pins.pinned("echo"), None);
    }

    #[test]
    fn canonicalization_failure_in_schema_is_rejected() {
        // A signed manifest whose tool schema contains a non-JCS-safe number
        // (fractional) cannot be canonicalized → malformed at schema-hash time.
        // We hand-build the manifest because mint_signed_manifest would itself
        // reject the bad schema while computing the hash.
        let manifest = mint_signed_manifest(&default_spec(), &signing_key(), KEY_ID).unwrap();
        let mut manifest = manifest;
        // Inject a fractional number into the schema (JCS-unsafe).
        manifest.tools[0].input_schema = json!({ "threshold": 1.5 });
        let mut pins = InMemoryManifestPinStore::new();
        // recompute_schema_hash canonicalizes the (now unsafe) schema → malformed.
        assert_eq!(
            ManifestVerifier::new().verify(
                &manifest,
                &resolver(),
                &InMemoryRevocationSource::new(),
                &mut pins,
                NOW,
            ),
            Err(ManifestError::ManifestMalformed)
        );
    }
}
