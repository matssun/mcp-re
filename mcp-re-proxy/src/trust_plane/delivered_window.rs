// SPDX-License-Identifier: Apache-2.0
//! What revocation window this deployment actually DELIVERS.
//!
//! One fact, and it is the one an operator sizes an incident response against: **how long a
//! key removed from `--trust` can keep resolving.** It is not the tier's `T`, and it is not
//! the reload cadence `R` — it is their SUM while every re-read succeeds, because a reload swaps the snapshot the tier
//! resolves against while holding no handle to the tier's cache and evicting nothing.
//!
//! While re-reads fail, the reloader keeps the last-good store for up to its failure budget
//! of cadences, so the worst case is budget x R + T (budget x R for `Live`), with R + T the
//! bound while every re-read succeeds.
//!
//! The composition is stated as arithmetic here because every other surface prints the two
//! numbers side by side and leaves the composition to a preposition, which reads as *the
//! tighter of* rather than *add these*.
//!
//! Both strings are startup-line content and neither decides anything. They are separated
//! from the plane's materialization for that reason: what the deployment DOES is the
//! plane's, and what the deployment CLAIMS about it is one sentence that must stay true of
//! every tier and every cadence — including the two absences, where the honest answer is
//! `UNBOUNDED` rather than a number.

use crate::revocation_tier::RevocationTier;

/// The qualifier carried on the revocation-tier startup line: how fast the trust STORE
/// itself can change.
///
/// Every tier's window is a claim about how quickly a key removed from `--trust` stops
/// resolving, and nothing resolves faster than the file is re-read. The default tier
/// (`bounded-cache`) is accepted without a cadence — unlike `live`/`push`, whose claims
/// are refused outright without one — so its tier line is the
/// one an operator gets by omission. The correction therefore rides on the SAME line as
/// the claim: as a separate line further down it was read as being about something else,
/// and the tier line was quoted on its own.
pub(super) fn store_change_cadence(reload: crate::startup_plan::TrustReloadPlan) -> String {
    match reload.cadence_secs() {
        Some(secs) => format!("{secs}s (--trust re-read on that cadence)"),
        None => "NONE: --trust is read once at startup, so the window above bounds CACHING \
                 only — the store itself changes only when every replica restarts"
            .to_string(),
    }
}
/// The revocation window the deployment actually delivers: the store cadence `R` and the
/// tier's cached-entry lifetime `T` ADD, and this states the sum. The worst case is
/// budget x R + T (budget x R for `Live`), the reload failure budget being the number of
/// consecutive failed re-reads the reloader tolerates; R + T bounds the window while every
/// re-read succeeds.
///
/// A reload swaps the snapshot the tier resolves AGAINST; it holds no handle to the tier's
/// cache and evicts nothing, and a cached entry restarts a full `T` at every miss. So an
/// entry re-cached one tick before the swap survives it by a further `T`, and a key removed
/// from `--trust` can keep resolving for up to `R + T`. `Live` caches no positive trust, so
/// there the store cadence is the whole window.
///
/// Stated as arithmetic because every other surface prints the two numbers side by side and
/// leaves the composition to a preposition, which an operator sizing an incident response
/// reads as "the tighter of" rather than "add these".
pub(in crate::trust_plane) fn delivered_revocation_window(
    tier: &RevocationTier,
    reload: crate::startup_plan::TrustReloadPlan,
) -> String {
    let Some(cadence) = reload.cadence_secs() else {
        return "UNBOUNDED: --trust is read once at startup, so a removed key keeps \
                resolving until every replica restarts"
            .to_string();
    };
    let r = i64::try_from(cadence.get()).unwrap_or(i64::MAX);
    let budget = i64::from(super::reload::TRUST_RELOAD_FAILURE_BUDGET);
    let tolerated = super::reload::TRUST_RELOAD_FAILURE_BUDGET.saturating_sub(1);
    match tier {
        RevocationTier::Live => {
            let worst = r.saturating_mul(budget);
            format!(
                "worst case {worst}s = {budget} x R {r}s (the reloader keeps the last-good \
                 store across {tolerated} failed re-reads and fails closed on the {budget}th; \
                 this tier caches no positive trust), plus each re-read's own duration; \
                 R = {r}s while every re-read succeeds"
            )
        }
        RevocationTier::BoundedCache { t_secs } | RevocationTier::Push { t_secs } => {
            let worst = r.saturating_mul(budget).saturating_add(*t_secs);
            let healthy = r.saturating_add(*t_secs);
            format!(
                "worst case {worst}s = {budget} x R {r}s + T {t_secs}s (the reloader keeps the \
                 last-good store across {tolerated} failed re-reads and fails closed on the \
                 {budget}th, and the reload swaps the store but evicts nothing already cached, \
                 so a cached entry outlives the swap by a further T), plus each re-read's own \
                 duration; R + T = {healthy}s while every re-read succeeds"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::startup_plan::TrustReloadPlan;

    #[test]
    fn a_store_that_is_never_re_read_delivers_an_unbounded_window() {
        // The honest answer is not a number. With no cadence the tier's `T` bounds CACHING
        // only: the snapshot itself never changes, so a removed key resolves until every
        // replica restarts — and saying "worst case 60s" there would be false.
        let window = delivered_revocation_window(
            &RevocationTier::BoundedCache { t_secs: 60 },
            TrustReloadPlan::ReadOnceAtStartup,
        );
        assert!(window.starts_with("UNBOUNDED"), "got {window}");
        assert!(store_change_cadence(TrustReloadPlan::ReadOnceAtStartup).contains("NONE"));
    }

    #[test]
    fn the_worst_case_composes_the_reload_failure_budget() {
        // A key removed during a run of tolerated failed re-reads resolves for budget
        // cadences plus T.
        let budget = i64::from(crate::trust_plane::reload::TRUST_RELOAD_FAILURE_BUDGET);
        let plan = TrustReloadPlan::Every {
            secs: crate::config_state::TrustRevocationState::cadence(30),
        };
        for tier in [
            RevocationTier::BoundedCache { t_secs: 60 },
            RevocationTier::Push { t_secs: 60 },
        ] {
            let window = delivered_revocation_window(&tier, plan);
            assert!(
                window.starts_with(&format!("worst case {}s ", budget * 30 + 60)),
                "got {window}"
            );
            assert!(window.contains("R + T = 90s"), "got {window}");
        }
        let live = delivered_revocation_window(&RevocationTier::Live, plan);
        assert!(
            live.starts_with(&format!("worst case {}s ", budget * 30)),
            "got {live}"
        );
    }
}
