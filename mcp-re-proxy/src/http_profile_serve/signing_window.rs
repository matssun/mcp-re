// SPDX-License-Identifier: Apache-2.0
//! The validity a response signed under a delegated credential may advertise.
//!
//! ADR-MCPRE-052 §4 gives the delegated snapshot a fail-closed bound: a signer MUST stop
//! signing off it once `now >= exp`. A receipt that advertised validity beyond that bound
//! would be asserting a window the verifier refuses the moment the credential's own window
//! closes — the signature is still well-formed, so the client learns nothing until it
//! fails.
//!
//! The bound is therefore not a step the signing paths perform. It is what a
//! [`SigningWindow`] IS: `expires` is private, no constructor accepts one, and the two
//! that exist derive it. Holding a window means holding a validity that does not outlive
//! the credential authorizing it, whichever path obtained it.

use std::sync::Arc;

use mcp_re_http_profile::ActiveDelegatedKey;

use crate::async_inner::DispatchCompletionBound;
use crate::delegated_server_signer::DelegatedSigningReader;

/// A delegated credential snapshotted for one exchange, with the response validity it
/// authorizes.
///
/// The snapshot is taken once per exchange because `now` is fixed for its whole duration:
/// a key valid when the exchange opened is valid when its reply is signed.
pub(crate) struct SigningWindow {
    /// The credential the signature is made under.
    key: Arc<ActiveDelegatedKey>,
    /// Unix seconds this response's validity runs FROM — the exchange's one clock
    /// reading, which is also what the receipt advertises as `created`.
    ///
    /// Kept because the freshness rule is about the window, not about its far end alone:
    /// asking whether a verifier still admits this window at some instant needs both
    /// bounds, and reconstructing `created` at the asking site would be the second copy
    /// this type exists to prevent.
    created: i64,
    /// Unix seconds this response may claim validity until.
    ///
    /// Never later than `key.exp`. There is no constructor that takes this value, so the
    /// relation holds for every window that exists rather than for the ones whose caller
    /// remembered to clamp.
    expires: i64,
}

impl SigningWindow {
    /// Open a window over the signer's current credential, or `None` when the deployment
    /// has no valid delegated key — the fail-closed posture, since delegated signing is
    /// the only response-signing mode there is.
    pub(crate) fn open(signer: &DelegatedSigningReader, now: i64, ttl_secs: i64) -> Option<Self> {
        signer
            .current(now)
            .map(|key| Self::over(key, now, ttl_secs))
    }

    /// Open a window over a credential already snapshotted earlier in this exchange.
    ///
    /// The same derivation as [`SigningWindow::open`]: a refusal minted late in an
    /// exchange signs under the credential that exchange took, and advertises no more
    /// validity for having been reached by a different path.
    pub(crate) fn over(key: Arc<ActiveDelegatedKey>, now: i64, ttl_secs: i64) -> Self {
        let exp = key.exp();
        Self {
            key,
            created: now,
            // `now + ttl_secs` is the configured window; `exp` is the credential's own.
            // The response advertises whichever closes first.
            expires: now.saturating_add(ttl_secs).min(exp),
        }
    }

    /// Would a conforming verifier still admit a response advertising this window, at
    /// `instant`?
    ///
    /// Asked through [`mcp_re_http_profile::verify::window_admits`] — the §5.1 rule ITSELF, the
    /// same function the request floor applies — rather than through a formula written
    /// here that agrees with it. A signer and a verifier disagreeing about freshness is
    /// precisely the failure this asks about, so the two must not be two statements.
    ///
    /// Skew is ZERO on purpose, and that is the conservative direction: the proxy does not
    /// know the client's policy, and a verifier configured with any tolerance at all
    /// admits everything a zero-tolerance one does. Passing here therefore means EVERY
    /// conforming verifier still admits it, not merely a lenient one.
    pub(crate) fn admissible_at(&self, instant: i64) -> bool {
        mcp_re_http_profile::verify::window_admits(self.created, self.expires, instant, 0)
    }

    /// Does this window survive the worst instant a dispatch under `bound` can complete
    /// at?
    ///
    /// The question asked before the execution threshold. A window that fails it would
    /// authorize a reply the client must refuse — a well-formed signature over an expired
    /// assertion, which the caller learns about only by failing, AFTER the backend has
    /// run.
    ///
    /// An [`Unstated`](DispatchCompletionBound::Unstated) bound is `false`. There is no
    /// worst completion instant to evaluate at, so there is no instant at which this can
    /// be shown to hold, and choosing a number on the plane's behalf would be assuming the
    /// very thing the caller asked to be told.
    ///
    /// WHAT THIS ESTABLISHES, exactly: that the window survives `created + bound`.
    /// `created` is the exchange's single clock reading, taken at ANSWERABLE, and the
    /// dispatch begins after the local pre-dispatch stages rather than at that instant —
    /// so the true completion can be later than the instant checked, by however long those
    /// stages take. Closing that remainder needs a second clock reading, which
    /// [`Exchange`](super::Exchange) deliberately does not take: re-asking the signer mid
    /// exchange is what degrades a post-dispatch refusal to an unsigned error. This is
    /// therefore a bound on the DISPATCH budget and not a guarantee about wall-clock
    /// completion, and no caller may read it as the latter.
    pub(crate) fn covers(&self, bound: DispatchCompletionBound) -> bool {
        bound
            .latest_completion(self.created)
            .is_some_and(|latest| self.admissible_at(latest))
    }

    /// The credential this window authorizes signing under.
    pub(crate) fn key(&self) -> &ActiveDelegatedKey {
        &self.key
    }

    /// The shared snapshot, for an exchange that must carry it to a later stage.
    pub(crate) fn shared(&self) -> Arc<ActiveDelegatedKey> {
        Arc::clone(&self.key)
    }

    /// Unix seconds the signed response may claim validity until.
    pub(crate) fn expires(&self) -> i64 {
        self.expires
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn key(exp: i64) -> Arc<ActiveDelegatedKey> {
        Arc::new(crate::delegated_wiring::test_support::issued_expiring_at(
            exp, 7,
        ))
    }

    /// The configured TTL wins while it closes first — the ordinary case, in which the
    /// credential has plenty of life left.
    #[test]
    fn the_configured_ttl_bounds_a_window_inside_the_credential() {
        assert_eq!(SigningWindow::over(key(10_000), 1_000, 60).expires(), 1_060);
    }

    /// ADR-MCPRE-052 §4: past the credential's own `exp` the signature authorizes
    /// nothing, so no configured TTL can advertise validity there.
    #[test]
    fn the_credential_bounds_a_ttl_that_would_outlive_it() {
        assert_eq!(SigningWindow::over(key(1_030), 1_000, 60).expires(), 1_030);
    }

    /// A credential already past its bound yields a window claiming no validity at all
    /// rather than one running backwards from the configured TTL.
    #[test]
    fn an_expired_credential_advertises_no_future_validity() {
        assert_eq!(SigningWindow::over(key(900), 1_000, 60).expires(), 900);
    }

    /// The clamp is arithmetic that cannot be skipped by choosing a large TTL: a
    /// deployment configuring an absurd window still advertises the credential's.
    #[test]
    fn a_saturating_ttl_does_not_wrap_past_the_credential() {
        assert_eq!(
            SigningWindow::over(key(2_000), i64::MAX - 1, i64::MAX).expires(),
            2_000
        );
    }

    /// **The hostile case.** A credential whose remaining life is shorter than the
    /// dispatch budget does not cover it — which is what refuses the exchange before the
    /// backend runs.
    ///
    /// Without this the reply is signed under a window that has already closed by the time
    /// the dispatch can complete: well-formed, and refused by the client, after the action
    /// has executed. `exp` is 30s out and the plane may take 60s.
    #[test]
    fn a_credential_shorter_than_the_dispatch_budget_does_not_cover_it() {
        let window = SigningWindow::over(key(1_030), 1_000, 300);
        assert!(!window.covers(DispatchCompletionBound::Within(Duration::from_secs(60))));
    }

    /// **The mirror.** The same window covers a budget that fits inside it, so the check
    /// refuses a real condition rather than everything.
    ///
    /// A control that only asserted the refusal would pass against a `covers` that always
    /// returned `false`, which would refuse every dispatch this deployment ever makes.
    #[test]
    fn a_credential_longer_than_the_dispatch_budget_covers_it() {
        let window = SigningWindow::over(key(1_030), 1_000, 300);
        assert!(window.covers(DispatchCompletionBound::Within(Duration::from_secs(20))));
    }

    /// An UNSTATED bound is refused rather than assumed.
    ///
    /// There is no worst completion instant to evaluate the window at, so there is no
    /// instant at which the property can be shown to hold. A plane that cannot bound its
    /// own completion cannot support a claim about what is true at that completion, and
    /// picking a number on its behalf would assume exactly what the caller asked to be
    /// told.
    #[test]
    fn a_plane_that_states_no_bound_is_refused_however_long_the_credential_lives() {
        let window = SigningWindow::over(key(i64::MAX - 1), 1_000, 300);
        assert!(!window.covers(DispatchCompletionBound::Unstated));
    }

    /// The boundary is the verifier's, not a rounded-down one: a sub-second budget ends
    /// inside the NEXT whole second, and the window must still admit it there.
    ///
    /// Truncating instead would claim the dispatch finishes a second earlier than it may,
    /// and the case it gets wrong is exactly the one at the edge.
    #[test]
    fn a_sub_second_budget_is_measured_at_the_second_it_can_still_be_running_in() {
        // `expires` is 1_030; the verifier admits while `now < expires`, so 1_029 is
        // admissible and 1_030 is not.
        let window = SigningWindow::over(key(1_030), 1_000, 300);
        assert!(
            window.covers(DispatchCompletionBound::Within(Duration::from_millis(
                28_500
            )))
        );
        assert!(
            !window.covers(DispatchCompletionBound::Within(Duration::from_millis(
                29_500
            )))
        );
    }

    /// The window's own far end is the verifier's rule and not a local comparison: at
    /// `expires` itself the response is no longer admissible.
    ///
    /// Asked through `mcp_re_http_profile::verify::window_admits`, so a change to §5.1 freshness
    /// moves this control rather than leaving a signer that quietly disagrees with the
    /// floor.
    #[test]
    fn admissibility_ends_at_expires_exactly_as_the_floor_says_it_does() {
        let window = SigningWindow::over(key(1_030), 1_000, 300);
        assert!(window.admissible_at(1_029));
        assert!(!window.admissible_at(1_030));
        assert!(!window.admissible_at(1_031));
    }
}
