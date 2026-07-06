//! MCPS-075 (audit gap G-1): property-based testing of the RFC 8785 (JCS)
//! canonicalizer — the most security-critical unit in MCP-RE, since the entire
//! signature scheme rests on a byte-identical preimage.
//!
//! This is a BLACK-BOX integration test: it drives ONLY the public API
//! re-exported at the crate root (`canonicalize`, `canonicalize_json_value`,
//! `canonicalize_value`, `parse`, `JcsValue`). It never reaches into the
//! canonicalizer internals.
//!
//! # Properties (the approved G-1 design)
//! - **A — idempotence.** `canonicalize` is a fixpoint: if `canonicalize(x)` is
//!   `Ok(c)`, then `canonicalize(&c) == Ok(c)`.
//! - **B — dual-path agreement.** For inputs BOTH the raw-bytes path
//!   (`canonicalize`) and the serde path (`canonicalize_json_value`) accept, the
//!   two produce byte-identical output.
//! - **C1 — collision resistance.** A provably semantics-changing mutation of a
//!   `JcsValue` always changes the canonical preimage.
//! - **C2 — order independence.** Permuting object members (top-level and
//!   recursively) yields a byte-identical canonical form — which is exactly what
//!   makes C1's "distinct" meaningful.
//!
//! # Determinism in the Bazel sandbox
//! `failure_persistence: None` is REQUIRED: the sandbox is read-only, so proptest
//! must NOT attempt to write a regression file. The randomized search is seeded
//! per-run; the DURABLE, deterministic corpus is the committed inline
//! [`seed_corpus`] module below, asserted with ordinary `#[test]`s that pin the
//! adversarial inputs regardless of the proptest RNG.

use mcp_re_core::canonicalize;
use mcp_re_core::canonicalize_json_value;
use mcp_re_core::canonicalize_value;
use mcp_re_core::JcsValue;
use proptest::prelude::prop;
use proptest::prelude::prop_oneof;
use proptest::prelude::Just;
use proptest::prelude::ProptestConfig;
use proptest::prelude::Strategy;
use proptest::prop_assert_eq;
use proptest::prop_assert_ne;
use proptest::proptest;

/// ±(2^53 − 1): the inclusive safe-integer bound of the JCS-safe domain.
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// Recursion depth used by the generators. Stays comfortably below the
/// canonicalizer's MAX_PARSE_DEPTH (128) so generated values are in-domain on the
/// depth axis — depth-bound rejection is exercised separately in the seed corpus.
const GEN_DEPTH: u32 = 4;

// ---------------------------------------------------------------------------
// Strategies — JCS-safe `serde_json::Value` (for properties A & B).
// ---------------------------------------------------------------------------

/// A recursive strategy producing only JCS-safe `serde_json::Value`s:
/// `Null`, `Bool`, integers in ±(2^53 − 1) (NEVER floats), arbitrary-unicode
/// `String`, `Array`, and `Object` with UNIQUE keys (deduped at build time so the
/// documented duplicate-key divergence between the two paths is never triggered).
fn jcs_safe_json() -> impl Strategy<Value = serde_json::Value> {
    let leaf = prop_oneof![
        Just(serde_json::Value::Null),
        proptest::bool::ANY.prop_map(serde_json::Value::Bool),
        (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).prop_map(serde_json::Value::from),
        ".*".prop_map(serde_json::Value::String),
    ];
    leaf.prop_recursive(GEN_DEPTH, 64, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(serde_json::Value::Array),
            // Build the object from (key, value) pairs, deduping keys so EVERY
            // generated object has unique member names (the raw path rejects
            // duplicates; the serde path silently dedupes — we stay in the
            // shared, both-accept domain per the issue).
            prop::collection::vec((".*", inner), 0..8).prop_map(|pairs| {
                let mut map = serde_json::Map::new();
                for (k, v) in pairs {
                    map.insert(k, v);
                }
                serde_json::Value::Object(map)
            }),
        ]
    })
}

// ---------------------------------------------------------------------------
// Strategies — JCS-safe `JcsValue` (for properties C1 & C2).
// ---------------------------------------------------------------------------

/// A recursive strategy producing JCS-safe [`JcsValue`]s directly, with UNIQUE
/// object keys (deduped at build time). Used by the collision-resistance and
/// order-independence properties, which operate on already-validated values.
fn jcs_value() -> impl Strategy<Value = JcsValue> {
    let leaf = prop_oneof![
        Just(JcsValue::Null),
        proptest::bool::ANY.prop_map(JcsValue::Bool),
        (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).prop_map(JcsValue::Integer),
        ".*".prop_map(JcsValue::String),
    ];
    leaf.prop_recursive(GEN_DEPTH, 64, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(JcsValue::Array),
            prop::collection::vec((".*", inner), 0..8).prop_map(dedup_object),
        ]
    })
}

/// Build a [`JcsValue::Object`] from arbitrary (key, value) pairs, keeping the
/// FIRST occurrence of each key so the result has unique member names (no
/// duplicate-key construction). Insertion order is preserved for the survivors.
fn dedup_object(pairs: Vec<(String, JcsValue)>) -> JcsValue {
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut members: Vec<(String, JcsValue)> = Vec::new();
    for (k, v) in pairs {
        if seen.insert(k.clone()) {
            members.push((k, v));
        }
    }
    JcsValue::Object(members)
}

// ---------------------------------------------------------------------------
// C1 — semantics-changing mutation helpers.
// ---------------------------------------------------------------------------

/// Produce a `v2` that is GUARANTEED semantically distinct from `v`, by mutating
/// the value in an order-and-canonicalization-invariant way:
/// - `Integer` -> increment by 1 staying in range (decrement at the max).
/// - `Bool`    -> flip.
/// - `Null`    -> becomes `Bool(true)`.
/// - `String`  -> append a char NOT already trivially collapsible.
/// - `Array`   -> push a fresh element.
/// - `Object`  -> insert a fresh key guaranteed absent.
///
/// Every branch changes the *abstract value*, which (because canonicalization is
/// a function of the abstract value — proved by C2) must change the preimage.
fn mutate_semantics_changing(v: &JcsValue) -> JcsValue {
    match v {
        JcsValue::Integer(i) => {
            // Stay within ±(2^53 − 1); at the max, go down instead of up.
            if *i < MAX_SAFE_INTEGER {
                JcsValue::Integer(i + 1)
            } else {
                JcsValue::Integer(i - 1)
            }
        }
        JcsValue::Bool(b) => JcsValue::Bool(!b),
        JcsValue::Null => JcsValue::Bool(true),
        JcsValue::String(s) => {
            let mut next = s.clone();
            // 'x' is a plain ASCII letter: never escaped, never collapsed, so the
            // canonical string genuinely grows by one code point.
            next.push('x');
            JcsValue::String(next)
        }
        JcsValue::Array(items) => {
            let mut next = items.clone();
            next.push(JcsValue::Null);
            JcsValue::Array(next)
        }
        JcsValue::Object(members) => {
            // Find a key that is provably absent so we ADD a member (changing the
            // value) rather than overwrite one. Existing keys are arbitrary, so we
            // pick a sentinel and extend it until unique.
            let existing: std::collections::BTreeSet<&str> =
                members.iter().map(|(k, _)| k.as_str()).collect();
            let mut fresh = String::from("__mcp_re_fresh__");
            while existing.contains(fresh.as_str()) {
                fresh.push('_');
            }
            let mut next = members.clone();
            next.push((fresh, JcsValue::Null));
            JcsValue::Object(next)
        }
    }
}

// ---------------------------------------------------------------------------
// C2 — recursive member-order permutation (canonicalization-invariant).
// ---------------------------------------------------------------------------

/// Reverse object member order at EVERY level (and recurse into arrays/values),
/// producing a value that is semantically IDENTICAL to `v` but stored in a
/// different member order. Canonicalization MUST erase this difference.
fn permute_member_order(v: &JcsValue) -> JcsValue {
    match v {
        JcsValue::Array(items) => {
            JcsValue::Array(items.iter().map(permute_member_order).collect())
        }
        JcsValue::Object(members) => {
            let mut permuted: Vec<(String, JcsValue)> = members
                .iter()
                .map(|(k, val)| (k.clone(), permute_member_order(val)))
                .collect();
            permuted.reverse();
            JcsValue::Object(permuted)
        }
        other => other.clone(),
    }
}

// ---------------------------------------------------------------------------
// Properties.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 4096,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// Property A — idempotence / fixpoint. For arbitrary input bytes: if
    /// `canonicalize(x)` succeeds, re-canonicalizing the output yields the SAME
    /// bytes. When `canonicalize(x)` errors the case is a vacuous pass — we only
    /// require that it does not panic (exercises the Err path safely).
    ///
    /// The input strategy mixes (i) arbitrary `Vec<u8>` (mostly rejected — fuzzes
    /// the parser's Err path) and (ii) serialized JCS-safe JSON (exercises Ok).
    #[test]
    fn prop_a_idempotent(
        input in prop_oneof![
            prop::collection::vec(proptest::num::u8::ANY, 0..256),
            jcs_safe_json().prop_map(|v| serde_json::to_vec(&v).expect("serialize jcs-safe value")),
        ]
    ) {
        if let Ok(canonical) = canonicalize(&input) {
            let again = canonicalize(&canonical)
                .expect("a canonical form must itself canonicalize");
            prop_assert_eq!(
                &again,
                &canonical,
                "canonicalization is not idempotent: re-canonicalizing the canonical \
                 form produced different bytes"
            );
        }
        // Err(_) => vacuous pass; reaching here without panicking is the assertion.
    }

    /// Property B — dual-path agreement. For a JCS-safe `serde_json::Value`,
    /// when BOTH the raw-bytes path and the serde path accept the input, they
    /// MUST produce byte-identical canonical output. Scoped strictly to inputs
    /// both accept (per the issue): if either errors, the case is a vacuous pass.
    #[test]
    fn prop_b_dual_path_agreement(value in jcs_safe_json()) {
        let bytes = serde_json::to_vec(&value).expect("serialize jcs-safe value");
        let raw = canonicalize(&bytes).expect("raw-bytes path must accept jcs_safe_json()");
        let serde = canonicalize_json_value(&value).expect("serde path must accept jcs_safe_json()");
        prop_assert_eq!(
            &raw,
            &serde,
            "raw-bytes path and serde path disagree on the canonical preimage"
        );
    }

    /// Property C1 — collision resistance. A provably semantics-changing mutation
    /// of a JCS-safe value MUST change the canonical preimage. (No two distinct
    /// abstract values may share a preimage — that would be a signature-scheme
    /// collision.)
    #[test]
    fn prop_c1_collision_resistance(value in jcs_value()) {
        let mutated = mutate_semantics_changing(&value);
        // Generated values stay well under the serializer depth bound (GEN_DEPTH
        // ≪ 128), so canonicalization always succeeds here.
        let original = canonicalize_value(&value).expect("within depth bound");
        let changed = canonicalize_value(&mutated).expect("within depth bound");
        prop_assert_ne!(
            original,
            changed,
            "a semantics-changing mutation did NOT change the canonical preimage \
             (preimage collision)"
        );
    }

    /// Property C2 — order independence / intended convergence. Permuting object
    /// member order (at every level) MUST yield a byte-IDENTICAL canonical form.
    /// This is what makes C1's "distinct" meaningful: order is normalized away,
    /// so any surviving difference reflects a genuine semantic difference.
    #[test]
    fn prop_c2_order_independence(value in jcs_value()) {
        let permuted = permute_member_order(&value);
        let original = canonicalize_value(&value).expect("within depth bound");
        let reordered = canonicalize_value(&permuted).expect("within depth bound");
        prop_assert_eq!(
            original,
            reordered,
            "permuting object member order changed the canonical form: \
             canonicalization does not normalize member order"
        );
    }
}

// ---------------------------------------------------------------------------
// Committed inline SEED CORPUS — deterministic regardless of the proptest RNG.
//
// These hand-picked adversarial inputs are the DURABLE corpus (proptest's own
// failure_persistence is disabled for the read-only sandbox). Each pins a
// documented invariant of the JCS-safe domain / canonical output.
// ---------------------------------------------------------------------------

mod seed_corpus {
    use super::canonicalize;
    use super::canonicalize_value;
    use mcp_re_core::McpReError;

    fn canon(input: &str) -> Result<Vec<u8>, McpReError> {
        canonicalize(input.as_bytes())
    }

    fn canon_str(input: &str) -> String {
        String::from_utf8(canonicalize(input.as_bytes()).expect("must canonicalize")).expect("utf8")
    }

    /// Duplicate keys on the raw-bytes path MUST be rejected (top level + nested).
    #[test]
    fn duplicate_keys_rejected_on_raw_path() {
        assert_eq!(canon(r#"{"a":1,"a":2}"#).unwrap_err(), McpReError::CanonicalizationFailed);
        assert_eq!(
            canon(r#"{"o":{"a":1,"a":2}}"#).unwrap_err(),
            McpReError::CanonicalizationFailed
        );
    }

    /// Key-order permutations MUST converge to the same canonical bytes.
    #[test]
    fn key_order_permutations_converge() {
        let a = canon_str(r#"{"b":1,"a":2,"c":3}"#);
        let b = canon_str(r#"{"c":3,"a":2,"b":1}"#);
        let c = canon_str(r#"{"a":2,"b":1,"c":3}"#);
        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(a, r#"{"a":2,"b":1,"c":3}"#);
    }

    /// Nested key-order permutations MUST converge too.
    #[test]
    fn nested_key_order_permutations_converge() {
        let a = canon_str(r#"{"z":{"y":1,"x":2},"a":3}"#);
        let b = canon_str(r#"{"a":3,"z":{"x":2,"y":1}}"#);
        assert_eq!(a, b);
        assert_eq!(a, r#"{"a":3,"z":{"x":2,"y":1}}"#);
    }

    /// `\u`-escaped ASCII MUST decode to the literal char (and re-canonicalize to
    /// the bare char), confirming escape-form normalization.
    #[test]
    fn unicode_escape_forms_normalize() {
        // \u0041 == 'A'.
        assert_eq!(canon_str(r#""\u0041""#), r#""A""#);
        // é == 'é' — emitted as literal UTF-8, never re-escaped.
        let out = canonicalize(r#""é""#.as_bytes()).expect("é canonicalizes");
        assert_eq!(out, "\"\u{00e9}\"".as_bytes());
        assert!(!String::from_utf8(out).unwrap().contains("\\u"));
    }

    /// Surrogate pairs: a valid pair decodes to the astral code point; an unpaired
    /// surrogate MUST be rejected.
    #[test]
    fn surrogate_pairs() {
        // U+1F600 GRINNING FACE via surrogate pair -> literal 4-byte UTF-8.
        assert_eq!(canon_str(r#""\uD83D\uDE00""#), "\"\u{1F600}\"");
        // Unpaired high and low surrogates reject.
        assert_eq!(canon(r#""\uD800""#).unwrap_err(), McpReError::CanonicalizationFailed);
        assert_eq!(canon(r#""\uDC00""#).unwrap_err(), McpReError::CanonicalizationFailed);
    }

    /// Max safe integer accepted at the inclusive boundary; one beyond rejected.
    #[test]
    fn safe_integer_boundary() {
        assert_eq!(canon_str("9007199254740991"), "9007199254740991");
        assert_eq!(canon_str("-9007199254740991"), "-9007199254740991");
        assert_eq!(canon("9007199254740992").unwrap_err(), McpReError::CanonicalizationFailed);
        assert_eq!(canon("-9007199254740992").unwrap_err(), McpReError::CanonicalizationFailed);
    }

    /// Nesting within the depth bound (128) canonicalizes; just over the bound is
    /// rejected (fails closed, no stack overflow).
    #[test]
    fn nesting_depth_boundary() {
        let within = "[".repeat(128) + &"]".repeat(128);
        canonicalize(within.as_bytes()).expect("128-deep is within the inclusive bound");
        let over = "[".repeat(129) + &"]".repeat(129);
        assert_eq!(
            canonicalize(over.as_bytes()).unwrap_err(),
            McpReError::CanonicalizationFailed
        );
    }

    /// Malformed number forms MUST be rejected: leading zero, leading `+`,
    /// trailing dot, bare fraction, exponent.
    #[test]
    fn malformed_number_forms_rejected() {
        for bad in ["01", "+1", "1.", "1.5", "1e3", "1E3", ".5"] {
            assert_eq!(
                canon(bad).unwrap_err(),
                McpReError::CanonicalizationFailed,
                "{bad} must be rejected"
            );
        }
        // -0 normalizes to 0 (accepted, not a malformed form).
        assert_eq!(canon_str("-0"), "0");
    }

    /// Empty object and empty array canonicalize to themselves.
    #[test]
    fn empty_containers() {
        assert_eq!(canon_str("{}"), "{}");
        assert_eq!(canon_str("[]"), "[]");
        assert_eq!(canon_str(r#"{"a":{},"b":[]}"#), r#"{"a":{},"b":[]}"#);
    }

    /// Idempotence on a representative adversarial document: canonicalizing the
    /// canonical form is a fixpoint.
    #[test]
    fn idempotence_on_adversarial_document() {
        let input = r#"{"b":[3,2,1],"a":{"d":1,"c":"é\t"},"id":"123","z":"😀"}"#;
        let once = canonicalize(input.as_bytes()).expect("canonicalizes");
        let twice = canonicalize(&once).expect("re-canonicalizes");
        assert_eq!(once, twice);
    }

    /// Programmatic collision-resistance spot check on the value path: two
    /// distinct integers cannot share a preimage.
    #[test]
    fn distinct_integers_distinct_preimage() {
        use super::JcsValue;
        assert_ne!(
            canonicalize_value(&JcsValue::Integer(1)).expect("leaf canonicalizes"),
            canonicalize_value(&JcsValue::Integer(2)).expect("leaf canonicalizes")
        );
        // Order-permuted object converges (value path).
        let a = JcsValue::Object(vec![
            ("b".to_string(), JcsValue::Integer(1)),
            ("a".to_string(), JcsValue::Integer(2)),
        ]);
        let b = JcsValue::Object(vec![
            ("a".to_string(), JcsValue::Integer(2)),
            ("b".to_string(), JcsValue::Integer(1)),
        ]);
        assert_eq!(
            canonicalize_value(&a).expect("shallow object canonicalizes"),
            canonicalize_value(&b).expect("shallow object canonicalizes")
        );
    }
}
