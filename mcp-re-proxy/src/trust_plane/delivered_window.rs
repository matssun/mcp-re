// SPDX-License-Identifier: Apache-2.0
//! What revocation window this deployment actually DELIVERS.
//!
//! One fact, and it is the one an operator sizes an incident response against: **how long a
//! key removed from `--trust` can keep resolving.** It is not the tier's `T`, and it is not
//! the reload cadence `R` — it is their SUM, because a reload swaps the snapshot the tier
//! resolves against while holding no handle to the tier's cache and evicting nothing.
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
/// are refused outright without one — so its "enforced fleet-wide within T" line is the
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
/// tier's cached-entry lifetime `T` ADD, and this states the sum.
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
pub(super) fn delivered_revocation_window(
    tier: &RevocationTier,
    reload: crate::startup_plan::TrustReloadPlan,
) -> String {
    let Some(cadence) = reload.cadence_secs() else {
        return "UNBOUNDED: --trust is read once at startup, so a removed key keeps \
                resolving until every replica restarts"
            .to_string();
    };
    let r = i64::try_from(cadence.get()).unwrap_or(i64::MAX);
    match tier {
        RevocationTier::Live => format!(
            "worst case {r}s (the store cadence R={r}s; this tier caches no positive trust)"
        ),
        RevocationTier::BoundedCache { t_secs } | RevocationTier::Push { t_secs } => {
            let total = r.saturating_add(*t_secs);
            format!(
                "worst case {total}s = R {r}s + T {t_secs}s (the reload swaps the store but \
                 evicts nothing already cached, so a cached entry outlives the swap by a \
                 further T)"
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
}
