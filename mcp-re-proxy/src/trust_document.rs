// SPDX-License-Identifier: Apache-2.0
//! Interpretation and validation of trust-document bytes.
//!
//! A trust document is a JSON array of `{ "signer", "key_id", "public_key" }` entries
//! with an optional `"slots"` array. It carries both request-signer keys and
//! authorization-issuer keys, and `slots` is what separates them.
//!
//! This module is the AUTHORITATIVE boundary for that interpretation. The rules below
//! are security rules, not input diagnostics, and they hold for every construction path
//! -- a command line, a reload, or a programmatic caller that never meets a parser:
//!
//!   * a duplicate `(signer, key_id)` is refused rather than last-write-wins;
//!   * `slots` present is authoritative -- a key not listing `request` is not a request
//!     signer, whatever else it is in the file for;
//!   * `slots` absent is treated as `["request"]`, so declaring slots NARROWS a key and
//!     is never a new requirement;
//!   * the deployment's own `response_kid` is excluded from the request signers either
//!     way, so an issuer key can never be presented as a client credential.
//!
//! The functions take BYTES, not a path. Reading the file is the caller's concern; what
//! the bytes mean is this module's.

use std::collections::HashMap;

use mcp_re_core::InMemoryTrustResolver;
use mcp_re_core::VerificationKey;
use serde_json::Value;

/// The `kid -> signer` map for keys this file enrols FOR THE REQUEST SLOT.
///
/// The SignerSlot type exists so trust resolution — not a role string read after the
/// fact — decides which slot a key may sign in. That only means something if the trust
/// file can express it. Previously it could not: every entry whose `key_id` was not
/// the response kid was granted the request slot unconditionally, so a key enrolled
/// for another purpose (this same file carries authorization-issuer keys) silently
/// became a full request-signing credential, and its resolved actor id then flowed
/// into the replay key, the Mode-A transport binding and the audit record.
///
/// An entry may now declare `"slots": ["request"]`. The rules:
///
///   * `slots` present  — authoritative. A key that does not list `request` is not a
///     request signer, whatever else it is in the file for.
///   * `slots` absent   — treated as `["request"]`, which is exactly the historical
///     behaviour, so an existing trust file keeps working. Declaring slots is how an
///     operator NARROWS a key; it is not a new requirement.
///
/// `response_kid` is excluded either way: the deployment's own issuer key must never
/// be presentable as a client credential.
pub fn load_trust_request_signers(
    bytes: &[u8],
    response_kid: &str,
) -> Result<HashMap<String, String>, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|e| format!("trust file: {e}"))?;
    let array = value.as_array().ok_or("trust file must be a JSON array")?;
    let mut out = std::collections::HashMap::new();
    for entry in array {
        let signer = entry["signer"]
            .as_str()
            .ok_or("trust entry missing signer")?;
        let key_id = entry["key_id"]
            .as_str()
            .ok_or("trust entry missing key_id")?;
        if key_id == response_kid {
            continue;
        }
        let request_slot = match entry.get("slots") {
            None => true,
            Some(slots) => {
                let listed = slots.as_array().ok_or_else(|| {
                    format!("trust entry {signer}#{key_id}: slots must be an array")
                })?;
                let mut found = false;
                for slot in listed {
                    match slot.as_str() {
                        Some("request") => found = true,
                        // Named so a typo is a startup failure rather than a silently
                        // narrower key that then fails every request at verify time.
                        Some(other) if other == "response" || other == "authorization-issuer" => {}
                        _ => {
                            return Err(format!(
                                "trust entry {signer}#{key_id}: unknown slot {slot}                                  (request|response|authorization-issuer)"
                            ))
                        }
                    }
                }
                found
            }
        };
        if request_slot {
            out.insert(key_id.to_string(), signer.to_string());
        }
    }
    Ok(out)
}

/// Load a JSON trust file into an [`InMemoryTrustResolver`]. The file is an array
/// of `{ "signer", "key_id", "public_key" }` (the public key Base64URL-no-pad) with an
/// optional `"slots"` array; it carries both request-signer keys and
/// authorization-issuer keys, and `slots` is what separates them (see
/// [`load_trust_request_signers`]).
pub fn load_trust(bytes: &[u8]) -> Result<InMemoryTrustResolver, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|e| format!("trust file: {e}"))?;
    let array = value.as_array().ok_or("trust file must be a JSON array")?;
    let mut resolver = InMemoryTrustResolver::new();
    // Fail closed on a duplicate (signer, key_id): the resolver's `insert` is
    // last-write-wins, so a second entry sharing the key coordinate — with a
    // DIFFERENT public_key — would silently swap the trusted key. Reject at load
    // rather than trust the file ordering, mirroring the duplicate-header rigor
    // applied elsewhere.
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    for entry in array {
        let signer = entry["signer"]
            .as_str()
            .ok_or("trust entry missing signer")?;
        let key_id = entry["key_id"]
            .as_str()
            .ok_or("trust entry missing key_id")?;
        if !seen.insert((signer.to_string(), key_id.to_string())) {
            return Err(format!(
                "trust file: duplicate entry for {signer}#{key_id} (last-write-wins \
                 key substitution refused)"
            ));
        }
        let pk = entry["public_key"]
            .as_str()
            .ok_or("trust entry missing public_key")?;
        let key = VerificationKey::from_b64url(pk)
            .map_err(|_| format!("trust entry {signer}#{key_id}: invalid public_key"))?;
        resolver.insert(signer, key_id, key);
    }
    Ok(resolver)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_core::SigningKey;
    use mcp_re_core::TrustResolver;
    #[test]
    fn loads_a_trust_file() {
        let key = SigningKey::from_seed_bytes(&[1u8; 32])
            .public_key()
            .to_b64url();
        let json = format!(
            r#"[{{"signer":"did:example:agent-1","key_id":"key-1","public_key":"{key}"}}]"#
        );
        let resolver = load_trust(json.as_bytes()).expect("load");
        assert!(resolver.resolve("did:example:agent-1", "key-1").is_ok());
        assert!(resolver.resolve("did:example:agent-1", "other").is_err());
    }

    #[test]
    fn trust_file_with_bad_key_errors() {
        let json = r#"[{"signer":"s","key_id":"k","public_key":"!!!not-base64"}]"#;
        assert!(load_trust(json.as_bytes()).is_err());
    }

    #[test]
    fn trust_file_with_duplicate_key_id_is_rejected() {
        // Audit LOW (ledger `54aadf7b6257f126`): two entries sharing (signer,key_id)
        // but DIFFERENT public_key must fail closed, not silently last-write-wins
        // (a key-substitution primitive via an appended entry).
        let k1 = SigningKey::from_seed_bytes(&[1u8; 32])
            .public_key()
            .to_b64url();
        let k2 = SigningKey::from_seed_bytes(&[2u8; 32])
            .public_key()
            .to_b64url();
        let json = format!(
            r#"[{{"signer":"s","key_id":"k","public_key":"{k1}"}},
                {{"signer":"s","key_id":"k","public_key":"{k2}"}}]"#
        );
        let err =
            load_trust(json.as_bytes()).expect_err("duplicate (signer,key_id) must be refused");
        assert!(err.contains("duplicate entry"), "got: {err}");
    }

    #[test]
    fn trust_file_duplicate_same_key_is_also_rejected() {
        // Uniform posture: even an exact-duplicate entry is a malformed file, not a
        // silently-tolerated redundancy.
        let k = SigningKey::from_seed_bytes(&[3u8; 32])
            .public_key()
            .to_b64url();
        let json = format!(
            r#"[{{"signer":"s","key_id":"k","public_key":"{k}"}},
                {{"signer":"s","key_id":"k","public_key":"{k}"}}]"#
        );
        assert!(load_trust(json.as_bytes()).is_err());
    }

    #[test]
    fn trust_file_same_signer_distinct_key_ids_is_fine() {
        // The dedup is on the (signer,key_id) PAIR — one signer legitimately holds
        // multiple key ids (rotation), which must still load.
        let k1 = SigningKey::from_seed_bytes(&[4u8; 32])
            .public_key()
            .to_b64url();
        let k2 = SigningKey::from_seed_bytes(&[5u8; 32])
            .public_key()
            .to_b64url();
        let json = format!(
            r#"[{{"signer":"s","key_id":"k1","public_key":"{k1}"}},
                {{"signer":"s","key_id":"k2","public_key":"{k2}"}}]"#
        );
        let resolver = load_trust(json.as_bytes()).expect("distinct key ids load");
        assert!(resolver.resolve("s", "k1").is_ok());
        assert!(resolver.resolve("s", "k2").is_ok());
    }

    #[test]
    fn load_trust_rejects_malformed_entries() {
        assert!(load_trust(br#"{"not":"an array"}"#).is_err());
        assert!(load_trust(br#"[{"key_id":"k","public_key":"x"}]"#)
            .unwrap_err()
            .contains("signer"));
        assert!(load_trust(br#"[{"signer":"s","public_key":"x"}]"#)
            .unwrap_err()
            .contains("key_id"));
        assert!(load_trust(br#"[{"signer":"s","key_id":"k"}]"#)
            .unwrap_err()
            .contains("public_key"));
    }

    // --- slot discipline and response_kid exclusion -----------------------------------
    //
    // These rules had no direct test. `load_trust_request_signers` was reachable only
    // through a private file-reading helper, so what was covered was "the trust plane
    // loads a file", not "a key without the request slot is not a request signer". A
    // programmatic caller reaching this boundary without a parser or a file was covered
    // by nothing at all.

    fn key(seed: u8) -> String {
        SigningKey::from_seed_bytes(&[seed; 32])
            .public_key()
            .to_b64url()
    }

    /// `slots` absent means `["request"]`, so an existing trust file keeps working.
    #[test]
    fn a_key_without_slots_is_a_request_signer() {
        let json = format!(
            r#"[{{"signer":"s","key_id":"k1","public_key":"{}"}}]"#,
            key(1)
        );
        let signers = load_trust_request_signers(json.as_bytes(), "response-kid").expect("loads");
        assert_eq!(signers.get("k1").map(String::as_str), Some("s"));
    }

    /// `slots` present is AUTHORITATIVE: a key that does not list `request` is not a
    /// request signer, whatever else the file carries it for.
    #[test]
    fn slots_present_narrows_and_is_authoritative() {
        let json = format!(
            r#"[{{"signer":"s","key_id":"req","public_key":"{}","slots":["request"]}},
                {{"signer":"s","key_id":"authz","public_key":"{}","slots":["authorization-issuer"]}}]"#,
            key(2),
            key(3)
        );
        let signers = load_trust_request_signers(json.as_bytes(), "response-kid").expect("loads");
        assert_eq!(signers.get("req").map(String::as_str), Some("s"));
        assert!(
            !signers.contains_key("authz"),
            "a key enrolled only as an authorization issuer must not become a request signer"
        );
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
        let err = load_trust_request_signers(json.as_bytes(), "response-kid")
            .expect_err("an unknown slot must be refused");
        assert!(err.contains("unknown slot"), "{err}");
    }

    /// The deployment's own issuer key must never be presentable as a client credential,
    /// and that holds whether or not the entry declares slots.
    #[test]
    fn the_response_kid_is_never_a_request_signer() {
        for slots in ["", r#","slots":["request"]"#] {
            let json = format!(
                r#"[{{"signer":"s","key_id":"response-kid","public_key":"{}"{slots}}}]"#,
                key(4)
            );
            let signers =
                load_trust_request_signers(json.as_bytes(), "response-kid").expect("loads");
            assert!(
                !signers.contains_key("response-kid"),
                "the issuer key became presentable as a client credential (slots: {slots:?})"
            );
        }
    }
}
