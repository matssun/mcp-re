// SPDX-License-Identifier: Apache-2.0
//! Interpretation and validation of trust-document bytes.
//!
//! A trust document is a JSON array of `{ "signer", "key_id", "public_key" }` entries
//! with an optional `"slots"` array. It carries request-signer keys and
//! authorization-issuer keys, and `slots` is what separates them.
//!
//! This module is the AUTHORITATIVE boundary for that interpretation, and it is two
//! stages with one owner each:
//!
//!   1. [`TrustDocument::parse`] — the STRUCTURAL stage. Bytes become a document or a
//!      refusal, once. Every entry is well-formed and names nothing this module does not
//!      know; every public key decodes; a `key_id` names at most one entry.
//!   2. the SLOT projections — [`TrustDocument::resolver`],
//!      [`TrustDocument::request_signers`], [`TrustDocument::authorization_issuers`] —
//!      read the parsed document and never the bytes, so the products of one parse
//!      cannot describe different documents.
//!
//! The rules are security rules, not input diagnostics, and they hold for every
//! construction path — a command line, a reload, or a programmatic caller:
//!
//!   * a `key_id` enrolled twice — for one signer or for two — is refused rather than
//!     last-write-wins, because the serving path resolves a request signer by `key_id`
//!     alone and a document that binds one `key_id` to two signers is ambiguous under
//!     that coordinate;
//!   * a duplicated JSON member, an unknown member, or an unknown slot name is refused,
//!     so a typo can never leave a key enrolled more widely than the operator wrote;
//!   * `slots` present is authoritative — a key not listing `request` is not a request
//!     signer, whatever else it is in the file for;
//!   * `slots` absent is treated as `["request"]`, so declaring slots NARROWS a key and
//!     is never a new requirement; an absent `slots` is never an authorization issuer;
//!   * the deployment's own `response_kid` is excluded from both slot maps, so an
//!     issuer key can never be presented as a client credential or as someone else's
//!     authority.
//!
//! The parser takes BYTES, not a path. Reading the file is the caller's concern; what
//! the bytes mean is this module's.

use std::collections::HashMap;

use mcp_re_core::InMemoryTrustResolver;
use mcp_re_core::VerificationKey;
use serde::Deserialize;

/// The closed slot vocabulary. An unlisted name is a parse refusal, not a narrower key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
enum Slot {
    Request,
    Response,
    AuthorizationIssuer,
}

impl TryFrom<String> for Slot {
    type Error = String;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        match name.as_str() {
            "request" => Ok(Slot::Request),
            "response" => Ok(Slot::Response),
            "authorization-issuer" => Ok(Slot::AuthorizationIssuer),
            other => Err(format!(
                "unknown slot {other:?} (request|response|authorization-issuer)"
            )),
        }
    }
}

/// One entry as written. `deny_unknown_fields` and serde's duplicate-member refusal are
/// the structural half of the closed vocabulary: `"slot"` is not a quiet `"slots"`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    signer: String,
    key_id: String,
    public_key: String,
    #[serde(default, deserialize_with = "declared_slots")]
    slots: Option<Vec<Slot>>,
}

/// `slots` absent is `None`; `slots` present must be an array — `null` is refused rather
/// than read as absent, so the two spellings of "no slots" cannot mean different things.
fn declared_slots<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Vec<Slot>>, D::Error> {
    Vec::<Slot>::deserialize(d).map(Some)
}

/// One structurally valid entry: the key already decoded, the slots already named.
#[derive(Debug)]
struct TrustEntry {
    signer: String,
    key_id: String,
    key: VerificationKey,
    slots: Option<Vec<Slot>>,
}

impl TrustEntry {
    fn lists(&self, slot: Slot) -> bool {
        self.slots.as_ref().is_some_and(|s| s.contains(&slot))
    }
}

/// A parsed, structurally validated trust document.
///
/// The representation is private: holding one means [`TrustDocument::parse`] accepted the
/// bytes, and every projection below is a pure function of the same accepted entries.
#[derive(Debug)]
pub(crate) struct TrustDocument {
    entries: Vec<TrustEntry>,
}

impl TrustDocument {
    /// The one structural stage. `Err` names the first rule the bytes break.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, String> {
        let raw: Vec<RawEntry> =
            serde_json::from_slice(bytes).map_err(|e| format!("trust file: {e}"))?;
        let mut entries: Vec<TrustEntry> = Vec::with_capacity(raw.len());
        for entry in raw {
            let RawEntry {
                signer,
                key_id,
                public_key,
                slots,
            } = entry;
            if let Some(prior) = entries.iter().find(|e| e.key_id == key_id) {
                return Err(if prior.signer == signer {
                    format!(
                        "trust file: duplicate entry for {signer}#{key_id} (last-write-wins \
                         key substitution refused)"
                    )
                } else {
                    format!(
                        "trust file: duplicate key_id {key_id} enrolled for {} and {signer}: a \
                         request signer is resolved by key_id alone, so the document is \
                         ambiguous (last-write-wins signer substitution refused)",
                        prior.signer
                    )
                });
            }
            let key = VerificationKey::from_b64url(&public_key)
                .map_err(|_| format!("trust entry {signer}#{key_id}: invalid public_key"))?;
            entries.push(TrustEntry {
                signer,
                key_id,
                key,
                slots,
            });
        }
        Ok(Self { entries })
    }

    /// Every enrolled `(signer, key_id) -> key`, whatever the slot. Which slot a key may
    /// sign in is decided by the slot maps, never by this resolver alone.
    pub(crate) fn resolver(&self) -> InMemoryTrustResolver {
        let mut resolver = InMemoryTrustResolver::new();
        for e in &self.entries {
            resolver.insert(&e.signer, &e.key_id, e.key.clone());
        }
        resolver
    }

    /// The `key_id -> signer` map for keys enrolled FOR THE REQUEST SLOT: `slots` absent,
    /// or listing `request`; never the deployment's own `response_kid`.
    pub(crate) fn request_signers(&self, response_kid: &str) -> HashMap<String, String> {
        self.entries
            .iter()
            .filter(|e| e.key_id != response_kid)
            .filter(|e| e.slots.is_none() || e.lists(Slot::Request))
            .map(|e| (e.key_id.clone(), e.signer.clone()))
            .collect()
    }

    /// The `key_id -> key` map for keys enrolled as AUTHORIZATION AUTHORITIES: only an
    /// entry that lists `authorization-issuer`; never the deployment's own `response_kid`.
    /// *This key signs requests* and *this key decides permission* are different
    /// authorities (ADR-MCPRE-065 §8), so an absent `slots` enrols none.
    pub(crate) fn authorization_issuers(
        &self,
        response_kid: &str,
    ) -> HashMap<String, VerificationKey> {
        self.entries
            .iter()
            .filter(|e| e.key_id != response_kid)
            .filter(|e| e.lists(Slot::AuthorizationIssuer))
            .map(|e| (e.key_id.clone(), e.key.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_core::SigningKey;
    use mcp_re_core::TrustResolver;

    fn key(seed: u8) -> String {
        SigningKey::from_seed_bytes(&[seed; 32])
            .public_key()
            .to_b64url()
    }

    fn parse(json: &str) -> Result<TrustDocument, String> {
        TrustDocument::parse(json.as_bytes())
    }

    fn signers(json: &str) -> HashMap<String, String> {
        parse(json).expect("loads").request_signers("response-kid")
    }

    fn issuers(json: &str) -> HashMap<String, VerificationKey> {
        parse(json)
            .expect("loads")
            .authorization_issuers("response-kid")
    }

    /// A trust file with one request signer and one authorization authority.
    fn two_slot_file(request_key: &str, authority_key: &str) -> String {
        format!(
            r#"[{{"signer":"did:example:agent-1","key_id":"key-1","public_key":"{request_key}",
                  "slots":["request"]}},
                {{"signer":"did:example:pdp","key_id":"pdp-1","public_key":"{authority_key}",
                  "slots":["authorization-issuer"]}}]"#
        )
    }

    // --- structural stage ------------------------------------------------------------

    #[test]
    fn loads_a_trust_file() {
        let json = format!(
            r#"[{{"signer":"did:example:agent-1","key_id":"key-1","public_key":"{}"}}]"#,
            key(1)
        );
        let resolver = parse(&json).expect("load").resolver();
        assert!(resolver.resolve("did:example:agent-1", "key-1").is_ok());
        assert!(resolver.resolve("did:example:agent-1", "other").is_err());
    }

    #[test]
    fn trust_file_with_bad_key_errors() {
        assert!(parse(r#"[{"signer":"s","key_id":"k","public_key":"!!!not-base64"}]"#).is_err());
    }

    #[test]
    fn load_trust_rejects_malformed_entries() {
        assert!(parse(r#"{"not":"an array"}"#).is_err());
        assert!(parse(r#"[{"key_id":"k","public_key":"x"}]"#)
            .unwrap_err()
            .contains("signer"));
        assert!(parse(r#"[{"signer":"s","public_key":"x"}]"#)
            .unwrap_err()
            .contains("key_id"));
        assert!(parse(r#"[{"signer":"s","key_id":"k"}]"#)
            .unwrap_err()
            .contains("public_key"));
        assert!(parse(r#"["not an object"]"#).is_err());
    }

    #[test]
    fn trust_file_with_duplicate_key_id_is_rejected() {
        // Two entries sharing (signer,key_id) but DIFFERENT public_key must fail closed,
        // not silently last-write-wins (a key-substitution primitive via an appended entry).
        let json = format!(
            r#"[{{"signer":"s","key_id":"k","public_key":"{}"}},
                {{"signer":"s","key_id":"k","public_key":"{}"}}]"#,
            key(1),
            key(2)
        );
        let err = parse(&json).expect_err("duplicate (signer,key_id) must be refused");
        assert!(err.contains("duplicate entry"), "got: {err}");
    }

    #[test]
    fn trust_file_duplicate_same_key_is_also_rejected() {
        // Uniform posture: even an exact-duplicate entry is a malformed file, not a
        // silently-tolerated redundancy.
        let json = format!(
            r#"[{{"signer":"s","key_id":"k","public_key":"{}"}},
                {{"signer":"s","key_id":"k","public_key":"{}"}}]"#,
            key(3),
            key(3)
        );
        assert!(parse(&json).is_err());
    }

    #[test]
    fn trust_file_same_signer_distinct_key_ids_is_fine() {
        // One signer legitimately holds multiple key ids (rotation), which must still load.
        let json = format!(
            r#"[{{"signer":"s","key_id":"k1","public_key":"{}"}},
                {{"signer":"s","key_id":"k2","public_key":"{}"}}]"#,
            key(4),
            key(5)
        );
        let resolver = parse(&json).expect("distinct key ids load").resolver();
        assert!(resolver.resolve("s", "k1").is_ok());
        assert!(resolver.resolve("s", "k2").is_ok());
    }

    /// The serving path resolves a request signer by `key_id` alone. A document binding
    /// one `key_id` to two signers used to load, and file order decided which signer the
    /// coordinate named; the other signer's key then verified nothing, silently.
    #[test]
    fn a_key_id_shared_by_two_signers_is_refused_rather_than_resolved_by_file_order() {
        let json = format!(
            r#"[{{"signer":"a","key_id":"k","public_key":"{}"}},
                {{"signer":"b","key_id":"k","public_key":"{}"}}]"#,
            key(6),
            key(7)
        );
        let err = parse(&json).expect_err("an ambiguous identity coordinate must be refused");
        assert!(err.contains("duplicate key_id k"), "{err}");
        assert!(err.contains("a and b"), "{err}");
    }

    #[test]
    fn a_duplicate_authority_kid_is_refused_rather_than_resolved_by_file_order() {
        let json = format!(
            r#"[{{"signer":"a","key_id":"pdp-1","public_key":"{}","slots":["authorization-issuer"]}},
                {{"signer":"b","key_id":"pdp-1","public_key":"{}","slots":["authorization-issuer"]}}]"#,
            key(5),
            key(6)
        );
        let err = parse(&json).expect_err("a substitutable authority must be refused");
        assert!(err.contains("duplicate key_id pdp-1"), "{err}");
    }

    /// A duplicated JSON member is an ambiguity between parsers — one reads the first
    /// value, another the last — and this document has one meaning or none.
    #[test]
    fn a_duplicated_member_is_refused_rather_than_read_last_wins() {
        let json = format!(
            r#"[{{"signer":"a","signer":"b","key_id":"k","public_key":"{}"}}]"#,
            key(8)
        );
        let err = parse(&json).expect_err("a duplicated member must be refused");
        assert!(err.contains("duplicate field `signer`"), "{err}");
    }

    /// The member vocabulary is closed for the same reason the slot vocabulary is: a
    /// misspelt `"slot"` would otherwise leave the key enrolled for everything.
    #[test]
    fn an_unknown_member_is_refused_rather_than_ignored() {
        let json = format!(
            r#"[{{"signer":"s","key_id":"k","public_key":"{}","slot":["authorization-issuer"]}}]"#,
            key(9)
        );
        let err = parse(&json).expect_err("an unknown member must be refused");
        assert!(err.contains("unknown field `slot`"), "{err}");
    }

    /// The slot vocabulary is closed. An unrecognised slot is refused rather than
    /// ignored, so a typo narrows nothing silently — `"reqest"` must not leave a key
    /// enrolled for everything by accident.
    #[test]
    fn an_unknown_slot_is_refused_rather_than_ignored() {
        let json = format!(
            r#"[{{"signer":"s","key_id":"k","public_key":"{}","slots":["reqest"]}}]"#,
            key(5)
        );
        let err = parse(&json).expect_err("an unknown slot must be refused");
        assert!(err.contains("unknown slot"), "{err}");
    }

    #[test]
    fn slots_must_be_an_array_when_present() {
        for slots in [r#""request""#, "null", "{}"] {
            let json = format!(
                r#"[{{"signer":"s","key_id":"k","public_key":"{}","slots":{slots}}}]"#,
                key(10)
            );
            assert!(parse(&json).is_err(), "slots {slots} must be refused");
        }
    }

    // --- slot projections ------------------------------------------------------------

    #[test]
    fn an_authority_key_is_not_a_request_signer_and_a_request_signer_is_not_an_authority() {
        let json = two_slot_file(&key(1), &key(2));
        assert_eq!(signers(&json).keys().collect::<Vec<_>>(), vec!["key-1"]);
        assert_eq!(issuers(&json).keys().collect::<Vec<_>>(), vec!["pdp-1"]);
    }

    /// `slots` absent means `["request"]`, so an existing trust file keeps working, and
    /// it never acquires a policy authority by being left alone.
    #[test]
    fn a_slotless_entry_is_a_request_signer_only() {
        let json = format!(
            r#"[{{"signer":"s","key_id":"key-1","public_key":"{}"}}]"#,
            key(3)
        );
        assert!(issuers(&json).is_empty());
        assert_eq!(signers(&json).get("key-1").map(String::as_str), Some("s"));
    }

    /// `slots` present is AUTHORITATIVE: a key that does not list `request` is not a
    /// request signer, whatever else the file carries it for — and an empty list enrols
    /// the key for nothing.
    #[test]
    fn slots_present_narrows_and_is_authoritative() {
        let json = format!(
            r#"[{{"signer":"s","key_id":"req","public_key":"{}","slots":["request"]}},
                {{"signer":"s","key_id":"authz","public_key":"{}","slots":["authorization-issuer"]}},
                {{"signer":"s","key_id":"none","public_key":"{}","slots":[]}}]"#,
            key(2),
            key(3),
            key(4)
        );
        let signers = signers(&json);
        assert_eq!(signers.get("req").map(String::as_str), Some("s"));
        assert!(
            !signers.contains_key("authz"),
            "a key enrolled only as an authorization issuer must not become a request signer"
        );
        assert!(!signers.contains_key("none"));
        assert!(!issuers(&json).contains_key("none"));
    }

    /// The deployment's own issuer key must never be presentable as a client credential
    /// or as an authorization authority, and that holds whether or not the entry
    /// declares slots.
    #[test]
    fn the_response_kid_is_never_a_request_signer_nor_an_authority() {
        for slots in ["", r#","slots":["request","authorization-issuer"]"#] {
            let json = format!(
                r#"[{{"signer":"s","key_id":"response-kid","public_key":"{}"{slots}}}]"#,
                key(4)
            );
            assert!(
                !signers(&json).contains_key("response-kid"),
                "the issuer key became presentable as a client credential (slots: {slots:?})"
            );
            assert!(!issuers(&json).contains_key("response-kid"));
            assert!(
                parse(&json)
                    .expect("loads")
                    .resolver()
                    .resolve("s", "response-kid")
                    .is_ok(),
                "the exclusion is a slot rule, not a deletion from the document"
            );
        }
    }

    /// The projections are functions of the parsed document: whatever a slot map says a
    /// key is, the resolver holds that key under the same coordinate, and it holds no
    /// coordinate the document did not write.
    #[test]
    fn every_slot_map_entry_names_a_coordinate_the_resolver_holds() {
        let json = format!(
            r#"[{{"signer":"a","key_id":"k1","public_key":"{}"}},
                {{"signer":"b","key_id":"k2","public_key":"{}","slots":["request","authorization-issuer"]}},
                {{"signer":"c","key_id":"k3","public_key":"{}","slots":["response"]}}]"#,
            key(11),
            key(12),
            key(13)
        );
        let doc = parse(&json).expect("loads");
        let resolver = doc.resolver();
        let signers = doc.request_signers("response-kid");
        for (kid, signer) in &signers {
            assert!(resolver.resolve(signer, kid).is_ok(), "{signer}#{kid}");
        }
        assert_eq!(signers.len(), 2);
        let issuers = doc.authorization_issuers("response-kid");
        assert_eq!(issuers.len(), 1);
        assert_eq!(
            resolver.resolve("b", "k2").expect("held").to_b64url(),
            issuers["k2"].to_b64url()
        );
        assert!(resolver.resolve("c", "k3").is_ok());
        assert!(
            resolver.resolve("a", "k2").is_err(),
            "no coordinate the document did not write"
        );
    }
}
