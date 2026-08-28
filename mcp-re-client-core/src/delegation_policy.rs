// SPDX-License-Identifier: Apache-2.0
//! The client's delegation policy — one owner for the credential-scope inputs and the
//! clock-skew bound applied to both freshness windows.
//!
//! # Why this is a module and not four fields beside the verifier
//!
//! The seal is the reason. `clock_skew` is clamped at construction so no inhabitant can
//! carry an unbounded tolerance, and in one crate the only lever that makes a private
//! field mean anything is **module privacy**: while this type lived beside
//! `verify_delegated_response`, that function could read the representation directly, so
//! "private" bound nobody who was actually going to destructure it. Here it binds every
//! consumer, and [`DelegationPolicy::with_expectations`] is the whole projection.
//!
//! It is also authority **E** of the client-response-verification blueprint, distinct from
//! delegated response verification itself: *what the credential must satisfy* is not *is
//! this response a genuine delegated answer*.

use mcp_re_http_profile::DelegationExpectations;

/// The deployment policy the client applies when verifying a DELEGATED-key-signed
/// response (ADR-MCPRE-052 §3) — the owned, client-side mirror of
/// [`mcp_re_http_profile::DelegationExpectations`]. The trusted ROOT issuer is
/// injected through the actor resolver (the credential's `issuer_kid` resolved for
/// the `Response` slot); this carries the audience-scope, epoch, and skew policy the
/// credential must satisfy.
/// # Why every field is private
///
/// `clock_skew` had to be, and a type whose invariant-bearing field is private while its
/// siblings are `pub` tells a reader nothing about which is which — it only says somebody
/// sealed one field. The remaining three carry no clamp, but they are the policy's
/// representation, and the two verification entry points below used to destructure all
/// four to build a [`DelegationExpectations`] apiece: two copies of one mapping, which is
/// how one of them ends up with a stale field. [`with_expectations`](Self::with_expectations)
/// is now the single projection, so there is one place where this policy becomes the
/// profile's expectations and one place where the skew bound is applied to both windows.
#[derive(Debug, Clone)]
pub struct DelegationPolicy {
    /// This client's accepted verifier audience identifier(s); the credential's
    /// `aud` must name one.
    verifier_audiences: Vec<String>,
    /// The audience-scope hash the delegated key must be scoped to (the request's
    /// audience hash the deployment coordinates).
    expected_audience_hash: String,
    /// The accepted trust-epoch set (default `{ current }`, optionally
    /// `{ current, previous }` in a bounded rollout window).
    accepted_epochs: Vec<String>,
    /// Clock-skew tolerance, seconds, ALREADY bounded to the profile's
    /// `0..=MAX_CLOCK_SKEW_BOUND` range.
    ///
    /// The field used to be `pub` and its own documentation said so — *nothing can
    /// guarantee it was ever validated*. The clamp lived in
    /// [`bounded_clock_skew`](Self::bounded_clock_skew), which every reader had to remember
    /// to call, and a reader that took the field directly got the unbounded number. Now
    /// [`new`](Self::new) is the only producer and it clamps, so the bound is a property of
    /// every inhabitant rather than of the call sites somebody checked.
    ///
    /// It governs BOTH the credential's `nbf`/`exp` window and the RFC 9421
    /// response-signature freshness gate, and the two must be the same number: a
    /// deployment that widened the skew for a real clock spread and got it on one
    /// window only is running two different notions of "close enough" on one message.
    clock_skew: i64,
}

impl DelegationPolicy {
    /// The clock-skew tolerance this policy actually applies: the configured value
    /// clamped to the profile's `0..=MAX_CLOCK_SKEW_BOUND` range.
    ///
    /// The bound is the profile's, not this crate's ([`VerifierPolicy::new`] refuses
    /// anything outside it), and it has to be applied HERE because the delegation
    /// credential's freshness check consumes the number raw: `DelegationExpectations`
    /// carries it straight through to `DelegationVerifyParams.max_clock_skew`, which
    /// widens `nbf`/`exp` with no cap of its own. Passing the configured value there
    /// while the signature gate silently clamped it meant a policy of 604800 accepted a
    /// delegated credential a week past its `exp` — the TTL is the primary bound on a
    /// compromised delegated key, so that window has to stay bounded (DEL-4).
    ///
    /// Clamping rather than rejecting keeps a misconfiguration from turning every
    /// response unverifiable, and unlike the previous fallback it leaves the two windows
    /// equal: one number, bounded, on both gates.
    ///
    /// [`VerifierPolicy::new`]: mcp_re_http_profile::VerifierPolicy::new
    fn bounded_clock_skew(&self) -> i64 {
        self.clock_skew
    }

    /// The RFC 9421 signature-acceptance policy this delegation policy implies.
    ///
    /// Built from [`bounded_clock_skew`](Self::bounded_clock_skew), so the construction
    /// can no longer fail on the skew argument; the fallback remains only because
    /// `new` is fallible in its algorithm argument too.
    fn verifier_policy(&self) -> mcp_re_http_profile::VerifierPolicy {
        mcp_re_http_profile::VerifierPolicy::new(&["ed25519"], self.bounded_clock_skew())
            .unwrap_or_default()
    }

    /// Build a delegation policy, bounding the configured clock skew as it goes.
    ///
    /// The clamp is HERE and nowhere else. A configured 604800 accepted a delegated
    /// credential a week past its `exp` while the signature gate silently clamped the same
    /// number — the TTL is the primary bound on a compromised delegated key, so that window
    /// has to stay bounded (DEL-4). Applying it at construction is what makes *both gates
    /// read one bounded number* true of every policy rather than of the paths that
    /// remembered to ask for the bounded projection.
    pub fn new(
        verifier_audiences: Vec<String>,
        expected_audience_hash: impl Into<String>,
        accepted_epochs: Vec<String>,
        max_clock_skew: i64,
    ) -> Self {
        DelegationPolicy {
            verifier_audiences,
            expected_audience_hash: expected_audience_hash.into(),
            accepted_epochs,
            clock_skew: max_clock_skew
                .clamp(0, mcp_re_http_profile::VerifierPolicy::MAX_CLOCK_SKEW_BOUND),
        }
    }

    /// Apply `f` to the profile expectations and signature policy this policy implies.
    ///
    /// A closure rather than a return value because [`DelegationExpectations`] BORROWS
    /// `&[&str]`: the `Vec<&str>` views of the owned `Vec<String>` fields have to outlive
    /// the call, so they cannot leave this frame. Handing the built pair to a closure keeps
    /// the one destructuring of this policy inside the policy — the two verification entry
    /// points had a verbatim copy each, and the skew bound had to be remembered at both.
    ///
    /// Both halves come from [`bounded_clock_skew`](Self::bounded_clock_skew), so the
    /// credential's `nbf`/`exp` window and the RFC 9421 freshness gate cannot be given two
    /// different notions of "close enough" for one message.
    /// `pub(crate)`, and that is the widening this owner intends: the projection IS the
    /// consumer contract. Every field stays private, so a consumer can obtain the
    /// expectations this policy implies and nothing else — it cannot reach the
    /// representation to build a different set.
    pub(crate) fn with_expectations<T>(
        &self,
        f: impl FnOnce(&DelegationExpectations<'_>, &mcp_re_http_profile::VerifierPolicy) -> T,
    ) -> T {
        let audiences: Vec<&str> = self.verifier_audiences.iter().map(String::as_str).collect();
        let epochs: Vec<&str> = self.accepted_epochs.iter().map(String::as_str).collect();
        let expect = DelegationExpectations {
            verifier_audiences: &audiences,
            expected_audience_hash: self.expected_audience_hash.as_str(),
            accepted_epochs: &epochs,
            max_clock_skew: self.bounded_clock_skew(),
        };
        f(&expect, &self.verifier_policy())
    }
}

#[cfg(test)]
mod policy_seal_tests {
    //! MCPRE-172 item 6 — the clock-skew carrier is sealed at construction.

    use super::*;

    #[test]
    fn a_configured_skew_beyond_the_profile_bound_is_not_constructible() {
        // The operational test for a seal: can the check be deleted and still leave an
        // invalid value unconstructible? The clamp used to live in the projection every
        // reader had to remember to call, and a reader taking the field got 604800 — a
        // delegated credential accepted a week past its `exp`. There is now no inhabitant
        // carrying it.
        let policy = DelegationPolicy::new(
            vec!["aud".to_owned()],
            "hash",
            vec!["epoch".to_owned()],
            604_800,
        );
        assert_eq!(
            policy.bounded_clock_skew(),
            mcp_re_http_profile::VerifierPolicy::MAX_CLOCK_SKEW_BOUND
        );
    }

    #[test]
    fn a_negative_skew_narrows_to_zero_rather_than_skewing_the_window_backwards() {
        let policy =
            DelegationPolicy::new(vec!["aud".to_owned()], "hash", vec!["epoch".to_owned()], -1);
        assert_eq!(policy.bounded_clock_skew(), 0);
    }

    #[test]
    fn both_gates_read_the_same_bounded_number() {
        // The property the field's own documentation states: the credential window and the
        // RFC 9421 signature window must be one number. The verifier policy is built from
        // the same bounded value the credential expectations carry.
        let policy = DelegationPolicy::new(
            vec!["aud".to_owned()],
            "hash",
            vec!["epoch".to_owned()],
            120,
        );
        assert_eq!(policy.verifier_policy().max_clock_skew(), 120);
        assert_eq!(policy.bounded_clock_skew(), 120);
    }
}
