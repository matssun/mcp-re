// SPDX-License-Identifier: Apache-2.0
//! How current an authoritative admission record must be, as a flat command line says it.
//!
//! The sibling of [`super::availability`], and for the same reason: the request carries a
//! `NonZeroU64`, so every value the rule refuses is a value the type no longer admits —
//! and argv is the one place it is still sayable.

/// Why the budget is REQUIRED rather than defaulted.
///
/// The number is the deployment's revocation-currentness promise: after a revocation, no
/// replica acts on an older record than this. A default would be this code choosing an
/// operator's revocation SLA, and the operator would discover what had been chosen by
/// reading the source. It also sets the authority's republication cadence, which is
/// operational work nobody should inherit silently.
pub(super) const MISSING_RECORD_MAX_AGE: &str =
    "--admission optional|required requires --admission-record-max-age-secs: a signed \
     authoritative record that never goes out of date is one a party with store-write \
     access can restore forever, so a deployment that verifies records must say how long \
     one lives (and republish at least that often)";

/// Read `--admission-record-max-age-secs`.
pub(super) fn parse(value: &str) -> Result<i64, String> {
    value
        .parse::<i64>()
        .map_err(|_| format!("--admission-record-max-age-secs must be an integer, got {value:?}"))
}

/// The declared budget, as the positive window an enforcing request carries.
///
/// A zero or negative window is not a stricter spelling of `--admission off`: it refuses
/// every record the instant it is signed, so an authority publishing correctly still admits
/// nobody. A gate is turned off by turning it off.
pub(super) fn window(secs: Option<i64>) -> Result<std::num::NonZeroU64, String> {
    let secs = secs.ok_or(MISSING_RECORD_MAX_AGE)?;
    u64::try_from(secs)
        .ok()
        .and_then(std::num::NonZeroU64::new)
        .ok_or_else(|| {
            format!(
                "--admission-record-max-age-secs must be > 0, got {secs}. It is how long a \
                 signed authoritative record stays readable, so zero admits nobody and a \
                 negative window is not a stricter spelling of --admission off."
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_integer_names_its_own_flag() {
        let err = parse("soon").expect_err("not an integer");
        assert!(err.contains("--admission-record-max-age-secs"), "{err}");
    }

    #[test]
    fn a_positive_window_is_carried_through() {
        assert_eq!(window(Some(45)).expect("positive").get(), 45);
    }

    #[test]
    fn a_non_positive_window_is_refused_and_says_why() {
        for bad in [0_i64, -1, -86_400] {
            let err = window(Some(bad)).expect_err("non-positive");
            assert!(err.contains("must be > 0"), "{bad}: {err}");
            assert!(
                err.contains("admits nobody"),
                "{bad}: the refusal must not read as a stricter setting: {err}"
            );
        }
    }

    #[test]
    fn an_absent_window_is_refused_as_a_missing_gate_input() {
        let err = window(None).expect_err("absent");
        assert!(err.contains("--admission-record-max-age-secs"), "{err}");
        assert!(err.contains("republish"), "{err}");
    }
}
