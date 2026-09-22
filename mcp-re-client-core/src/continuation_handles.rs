// SPDX-License-Identifier: Apache-2.0
//! The five handles an MRTR answer leg signs over, as one value that exists whole or does
//! not exist.
//!
//! One fact: **a continuation is present or absent, never partial.**
//!
//! # The defect this module exists to remove
//!
//! Both published SDK bindings took the five handles as five independent optionals and
//! folded the continuation in under `if let (Some, Some, Some, Some, Some)`. With one to
//! four of them present the `if let` simply did not fire: the request was signed,
//! returned, and carried NO continuation block and NO error. The doc comment above it said
//! "All five are `Some` together (or all `None` for an ordinary request)" — which
//! describes what a correct caller does, not what an inhabitant satisfies. That is the
//! quantifier gap in its plainest form, and it was the same code in both bindings.
//!
//! # Why it matters more than a dropped field usually does
//!
//! The continuation is the signed link between an answer leg and the `InputRequiredResult`
//! it answers — that is, to the human approval it answers. Dropping it does not produce a
//! refusal; it produces a valid, freshly-signed request that a server processes as an
//! unrelated new call. A caller bug — a lost `requestState`, a renamed field in a wrapper,
//! a partially restored session — therefore converted an approved-continuation flow into
//! an unapproved fresh request, with no error anywhere in the client.
//!
//! # What this owns and what it does not
//!
//! [`ContinuationHandles::from_optional`] is a TOTAL classifier over the five optionals
//! with exactly three outcomes: all absent is an ordinary request, all present is an
//! answer leg, and anything between is a refusal. It says nothing about whether the
//! handles are the RIGHT ones for this correlation — that binding is checked by the
//! server, against the bases it retained.

use mcp_re_http_profile::HttpContinuation;
use mcp_re_http_profile::RequestEvidenceDigest;

/// The two evidence-handle digests plus the opaque `requestState` an answer leg signs.
///
/// The representation is private and [`Self::from_optional`] is the only producer, so a
/// partially-filled set is not an inhabitant rather than being one the caller must
/// remember to reject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuationHandles {
    prev: RequestEvidenceDigest,
    irr: RequestEvidenceDigest,
    request_state: String,
}

/// A continuation was partially supplied: some handles were given and some were not.
///
/// Carries HOW MANY of the five were present and never WHICH or their values. The count is
/// what a caller debugs with; the values include the opaque `requestState`, which is
/// correlation material and does not belong in an error a client logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartialContinuation {
    /// How many of the five handles were supplied — always 1 through 4 here.
    pub supplied: u8,
}

impl std::fmt::Display for PartialContinuation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "an MRTR answer leg needs all five continuation handles and {} of 5 were \
             supplied: a partially-supplied continuation is refused rather than dropped, \
             because a request signed without it is an ordinary new call and not an answer \
             to the approval it was meant to answer",
            self.supplied
        )
    }
}

impl std::error::Error for PartialContinuation {}

impl ContinuationHandles {
    /// Classify five optional handles: none, all, or a refusal.
    ///
    /// `Ok(None)` is an ordinary first-leg request and is not a degenerate case — it is
    /// one of the two legal shapes, and returning it here is what lets a caller pass the
    /// result straight through without a second decision.
    pub fn from_optional(
        prev_alg: Option<String>,
        prev_value: Option<String>,
        irr_alg: Option<String>,
        irr_value: Option<String>,
        request_state: Option<String>,
    ) -> Result<Option<Self>, PartialContinuation> {
        let supplied = [
            prev_alg.is_some(),
            prev_value.is_some(),
            irr_alg.is_some(),
            irr_value.is_some(),
            request_state.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        match (prev_alg, prev_value, irr_alg, irr_value, request_state) {
            (None, None, None, None, None) => Ok(None),
            (Some(pa), Some(pv), Some(ia), Some(iv), Some(state)) => {
                Ok(Some(ContinuationHandles {
                    prev: RequestEvidenceDigest {
                        digest_alg: pa,
                        digest_value: pv,
                    },
                    irr: RequestEvidenceDigest {
                        digest_alg: ia,
                        digest_value: iv,
                    },
                    request_state: state,
                }))
            }
            // `supplied` is 1..=4 on this arm by construction: 0 and 5 are the two arms
            // above, and the cast is over a count of a five-element array.
            #[allow(clippy::cast_possible_truncation)]
            _ => Err(PartialContinuation {
                supplied: supplied as u8,
            }),
        }
    }

    /// The signed continuation these handles build.
    pub fn continuation(&self) -> HttpContinuation {
        HttpContinuation::from_handles(
            self.prev.clone(),
            self.irr.clone(),
            self.request_state.as_bytes(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Option<String> {
        Some(v.to_owned())
    }

    /// POSITIVE CONTROL 1: all five absent is an ordinary request, not a refusal.
    #[test]
    fn no_handles_at_all_is_an_ordinary_request() {
        assert_eq!(
            ContinuationHandles::from_optional(None, None, None, None, None),
            Ok(None)
        );
    }

    /// POSITIVE CONTROL 2: all five present builds the continuation, so the refusal below
    /// is not satisfied by a classifier that refuses every answer leg.
    #[test]
    fn all_five_handles_build_an_answer_leg() {
        let handles = ContinuationHandles::from_optional(
            s("sha-256"),
            s("cHJldg"),
            s("sha-256"),
            s("aXJy"),
            s("opaque-state"),
        )
        .expect("five handles are an answer leg")
        .expect("and it is present");
        assert_eq!(
            handles.continuation(),
            HttpContinuation::from_handles(
                RequestEvidenceDigest {
                    digest_alg: "sha-256".to_owned(),
                    digest_value: "cHJldg".to_owned(),
                },
                RequestEvidenceDigest {
                    digest_alg: "sha-256".to_owned(),
                    digest_value: "aXJy".to_owned(),
                },
                b"opaque-state",
            )
        );
    }

    /// LOAD-BEARING: the defect. EVERY proper non-empty subset of the five is refused —
    /// all 30 of them, not a sampled few, because the old `if let` fell through on each
    /// one identically and a test over one subset would leave the other 29 unpinned.
    #[test]
    fn every_partial_set_is_refused_and_says_how_many_were_supplied() {
        let full = [
            s("sha-256"),
            s("cHJldg"),
            s("sha-256"),
            s("aXJy"),
            s("opaque-state"),
        ];
        for mask in 1u8..31 {
            let mut given: Vec<Option<String>> = Vec::with_capacity(5);
            let mut count = 0u8;
            for (i, handle) in full.iter().enumerate() {
                // `1u8 << i` for i in 0..5 is 1..=16, so no shift overflows.
                #[allow(clippy::arithmetic_side_effects)]
                let present = mask & (1u8 << i) != 0;
                if present {
                    count = count.saturating_add(1);
                }
                given.push(present.then(|| handle.clone()).flatten());
            }
            let refusal = ContinuationHandles::from_optional(
                given[0].clone(),
                given[1].clone(),
                given[2].clone(),
                given[3].clone(),
                given[4].clone(),
            )
            .expect_err("a partial continuation is refused, never dropped");
            assert_eq!(refusal, PartialContinuation { supplied: count });
        }
    }

    /// The refusal names the rule and carries no handle value — `requestState` is
    /// correlation material and a refusal is a line a client logs.
    #[test]
    fn the_refusal_carries_a_count_and_no_correlation_material() {
        let refusal = ContinuationHandles::from_optional(None, None, None, None, s("secret-state"))
            .expect_err("one of five is partial");
        let why = refusal.to_string();
        assert!(!why.contains("secret-state"), "{why}");
        assert!(why.contains("1 of 5"), "{why}");
    }
}
