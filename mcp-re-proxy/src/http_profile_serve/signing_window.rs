// SPDX-License-Identifier: Apache-2.0
//! The proxy's two questions about a [`SigningWindow`].
//!
//! The window itself is owned by `mcp-re-http-profile`: its `expires` is private, its only
//! constructor derives it from the credential's own bound, and the delegated key is
//! reachable only through emitters that take a window. What is proxy-specific is where a
//! window comes from (the deployment's [`DelegatedSigningReader`]) and whether it survives
//! the dispatch budget the inner plane states ([`DispatchCompletionBound`]).

pub(crate) use mcp_re_http_profile::custody::SigningWindow;

use crate::async_inner::DispatchCompletionBound;
use crate::delegated_server_signer::DelegatedSigningReader;

/// Open a window over the signer's current credential, or `None` when the deployment has
/// no valid delegated key — the fail-closed posture, since delegated signing is the only
/// response-signing mode there is.
pub(crate) fn open(
    signer: &DelegatedSigningReader,
    now: i64,
    ttl_secs: i64,
) -> Option<SigningWindow> {
    signer
        .current(now)
        .and_then(|key| SigningWindow::over(key, now, ttl_secs))
}

/// Does `window` survive the worst instant a dispatch under `bound` can complete at?
///
/// The question asked before the execution threshold. A window that fails it would
/// authorize a reply the client must refuse — a well-formed signature over an expired
/// assertion, which the caller learns about only by failing, AFTER the backend has run.
///
/// An [`Unstated`](DispatchCompletionBound::Unstated) bound is `false`. There is no worst
/// completion instant to evaluate at, so there is no instant at which this can be shown to
/// hold, and choosing a number on the plane's behalf would be assuming the very thing the
/// caller asked to be told.
///
/// WHAT THIS ESTABLISHES, exactly: that the window survives `created + bound`. `created` is
/// the exchange's single clock reading, taken at ANSWERABLE, and the dispatch begins after
/// the local pre-dispatch stages rather than at that instant — so the true completion can
/// be later than the instant checked, by however long those stages take. Closing that
/// remainder needs a second clock reading, which [`Exchange`](super::Exchange)
/// deliberately does not take: re-asking the signer mid exchange is what degrades a
/// post-dispatch refusal to an unsigned error. This is therefore a bound on the DISPATCH
/// budget and not a guarantee about wall-clock completion, and no caller may read it as
/// the latter.
pub(crate) fn covers(window: &SigningWindow, bound: DispatchCompletionBound) -> bool {
    bound
        .latest_completion(window.created())
        .is_some_and(|latest| window.admissible_at(latest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    fn key(exp: i64) -> Arc<mcp_re_http_profile::ActiveDelegatedKey> {
        Arc::new(crate::delegated_wiring::test_support::issued_expiring_at(
            exp, 7,
        ))
    }

    /// `open` yields a window only while the signer holds a live credential.
    #[test]
    fn open_yields_a_window_only_while_the_signer_holds_a_live_credential() {
        let signer = Arc::new(crate::delegated_server_signer::DelegatedServerSigner::new());
        let reader = signer.reader();
        assert!(open(&reader, 0, 60).is_none());
        signer.publish(crate::delegated_wiring::test_support::issued_expiring_at(
            100, 7,
        ));
        assert_eq!(
            open(&reader, 50, 60)
                .expect("a live credential opens a window")
                .expires(),
            100
        );
        assert!(open(&reader, 100, 60).is_none());
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
        let window =
            SigningWindow::over(key(1_030), 1_000, 300).expect("a live credential opens a window");
        assert!(!covers(
            &window,
            DispatchCompletionBound::Within(Duration::from_secs(60))
        ));
    }

    /// **The mirror.** The same window covers a budget that fits inside it, so the check
    /// refuses a real condition rather than everything.
    ///
    /// A control that only asserted the refusal would pass against a `covers` that always
    /// returned `false`, which would refuse every dispatch this deployment ever makes.
    #[test]
    fn a_credential_longer_than_the_dispatch_budget_covers_it() {
        let window =
            SigningWindow::over(key(1_030), 1_000, 300).expect("a live credential opens a window");
        assert!(covers(
            &window,
            DispatchCompletionBound::Within(Duration::from_secs(20))
        ));
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
        let window = SigningWindow::over(key(i64::MAX - 1), 1_000, 300)
            .expect("a live credential opens a window");
        assert!(!covers(&window, DispatchCompletionBound::Unstated));
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
        let window =
            SigningWindow::over(key(1_030), 1_000, 300).expect("a live credential opens a window");
        assert!(covers(
            &window,
            DispatchCompletionBound::Within(Duration::from_millis(28_500))
        ));
        assert!(!covers(
            &window,
            DispatchCompletionBound::Within(Duration::from_millis(29_500))
        ));
    }
}
