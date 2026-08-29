// SPDX-License-Identifier: Apache-2.0
//! The admission flag family, parsed as one — ADR-MCPRE-067 §16.
//!
//! An operator names `--admission` and then, flatly, the gate's inputs. The request has one
//! tagged value, so this is the adapter.
//!
//! **Seven refusals live here now.** Five said that a gate input was set beside
//! `--admission off`, and two were the degraded pair's illegal cells. The union and the
//! `NonZeroU64` bound make all seven unbuildable, so the boundary has nothing left to
//! examine and the parser — the one place that still sees the selection beside the value —
//! answers them (ADR-MCPRE-067 §7). What did NOT move is every clause about what a supplied
//! value SAYS: an authority that names nothing, or a key that does not decode, is still the
//! configuration boundary's.

use crate::deployment_request::{
    AdmissionAvailabilityRequest, AdmissionGateRequest, AdmissionRequest, SharedStoreRequest,
};
use std::num::NonZeroU64;

/// How strictly the gate is applied, before its inputs are known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Strictness {
    #[default]
    Off,
    Optional,
    Required,
}

/// The admission inputs, as they accumulate across the argument list.
#[derive(Default)]
pub(super) struct AdmissionFlags {
    strictness: Strictness,
    authority_kid: Option<String>,
    authority_pubkey_b64url: Option<String>,
    store_url: Option<String>,
    degraded_bound_secs: Option<i64>,
    allow_degraded: Option<bool>,
}

impl AdmissionFlags {
    /// Read `--admission`.
    pub(super) fn take_strictness(&mut self, value: &str) -> Result<(), String> {
        self.strictness = match value {
            "off" => Strictness::Off,
            "optional" => Strictness::Optional,
            "required" => Strictness::Required,
            other => {
                return Err(format!(
                    "--admission must be off|optional|required, got {other:?}"
                ))
            }
        };
        Ok(())
    }

    /// Read `--admission-authority-kid`.
    pub(super) fn take_authority_kid(&mut self, value: String) {
        self.authority_kid = Some(value);
    }

    /// Read `--admission-authority-pubkey`.
    pub(super) fn take_authority_pubkey(&mut self, value: String) {
        self.authority_pubkey_b64url = Some(value);
    }

    /// Read `--admission-redis-url`.
    pub(super) fn take_store_url(&mut self, value: String) {
        self.store_url = Some(value);
    }

    /// Read `--admission-degraded-bound-secs`.
    pub(super) fn take_degraded_bound(&mut self, value: &str) -> Result<(), String> {
        self.degraded_bound_secs = Some(value.parse().map_err(|_| {
            format!("--admission-degraded-bound-secs must be an integer, got {value:?}")
        })?);
        Ok(())
    }

    /// Read `--admission-allow-degraded`.
    pub(super) fn take_allow_degraded(&mut self, value: &str) -> Result<(), String> {
        self.allow_degraded = Some(match value {
            "true" => true,
            "false" => false,
            other => {
                return Err(format!(
                    "--admission-allow-degraded must be true|false, got {other:?}"
                ))
            }
        });
        Ok(())
    }

    /// The admission form this command line names, with its own inputs.
    pub(super) fn finish(self) -> Result<AdmissionRequest, String> {
        if self.strictness == Strictness::Off {
            return self
                .dangling_refusal()
                .map(|_| AdmissionRequest::NotEnforced);
        }
        let gate = AdmissionGateRequest {
            authority_kid: self
                .required("--admission-authority-kid", self.authority_kid.clone())?,
            authority_pubkey_b64url: self.required(
                "--admission-authority-pubkey",
                self.authority_pubkey_b64url.clone(),
            )?,
            store: SharedStoreRequest::redis(
                self.required("--admission-redis-url", self.store_url.clone())?,
            ),
            availability: self.availability()?,
        };
        Ok(match self.strictness {
            Strictness::Optional => AdmissionRequest::Optional(gate),
            _ => AdmissionRequest::Required(gate),
        })
    }

    /// A gate input the enforcing forms are inhabited by. Absence is argv-shaped: an
    /// assembled request always carries one, so only a command line can omit it.
    fn required(&self, flag: &str, value: Option<String>) -> Result<String, String> {
        value.ok_or_else(|| {
            format!(
                "--admission optional|required requires --admission-authority-kid and \
                 --admission-authority-pubkey and --admission-redis-url (an assertion is \
                 only evidence if the issuer is one this deployment trusts, and currency \
                 is only checked against a record it can read): missing {flag}"
            )
        })
    }

    /// A gate input named beside `--admission off`.
    ///
    /// Five flags, one sentence each half: the gate's inputs live inside the enforcing
    /// forms, so an unenforced request has nowhere to carry them and an auditor cannot be
    /// shown a configured-looking authority that gates nothing.
    fn dangling_refusal(&self) -> Result<(), String> {
        let authority = self.authority_kid.is_some()
            || self.authority_pubkey_b64url.is_some()
            || self.store_url.is_some();
        if authority {
            return Err(
                "--admission-authority-kid / --admission-authority-pubkey / \
                 --admission-redis-url are set but --admission is off; enable it or remove \
                 them"
                    .to_string(),
            );
        }
        if self.degraded_bound_secs.is_some() || self.allow_degraded == Some(true) {
            return Err(
                "--admission-allow-degraded / --admission-degraded-bound-secs are set but \
                 --admission is off; a degraded window tolerates an UNREACHABLE ADMISSION \
                 AUTHORITY, and with the gate off there is no authority to be unreachable \
                 and no window to widen. Enable --admission or remove them"
                    .to_string(),
            );
        }
        Ok(())
    }

    /// What this deployment does when the authority is unreachable.
    ///
    /// The two illegal cells of the old table are refused here because only a command line
    /// can state them: a bound where nothing reads it, and a degraded window of zero width.
    /// After assembly the availability is one tagged value and the bound is a `NonZeroU64`.
    fn availability(&self) -> Result<AdmissionAvailabilityRequest, String> {
        if self.allow_degraded != Some(true) {
            if self.degraded_bound_secs.is_some_and(|bound| bound != 0) {
                return Err(
                    "--admission-degraded-bound-secs is set but --admission-allow-degraded \
                     is false; the bound is read only when degraded mode is on, so this \
                     window can never open. Pass --admission-allow-degraded true to use it, \
                     or remove it to fail closed on an unreachable authority"
                        .to_string(),
                );
            }
            return Ok(AdmissionAvailabilityRequest::FailClosed);
        }
        let bound = self.degraded_bound_secs.unwrap_or(0);
        let bound_secs = u64::try_from(bound)
            .ok()
            .and_then(NonZeroU64::new)
            .ok_or_else(|| {
                "--admission-degraded-bound-secs must be > 0 when --admission-allow-degraded \
                 is true: the PEP serves an unreachable authority for P + --max-clock-skew \
                 seconds, so a zero P still admits a revoked workload for the skew tolerance \
                 while claiming no window was configured"
                    .to_string()
            })?;
        Ok(AdmissionAvailabilityRequest::Degraded { bound_secs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enforcing() -> AdmissionFlags {
        let mut flags = AdmissionFlags::default();
        flags.take_strictness("required").expect("a known level");
        flags.take_authority_kid("authority-1".to_string());
        flags.take_authority_pubkey("k".to_string());
        flags.take_store_url("redis://127.0.0.1:6379".to_string());
        flags
    }

    /// Every gate input beside `--admission off` is answered where it is still visible.
    #[test]
    fn a_gate_input_beside_off_is_refused_by_the_adapter() {
        /// A flag a case must name in its refusal, and the value that provokes it.
        type Case = (&'static str, fn(&mut AdmissionFlags));
        let cases: [Case; 5] = [
            ("--admission-authority-kid", |f| {
                f.take_authority_kid("a".to_string());
            }),
            ("--admission-authority-pubkey", |f| {
                f.take_authority_pubkey("k".to_string());
            }),
            ("--admission-redis-url", |f| {
                f.take_store_url("redis://h:6379".to_string());
            }),
            ("--admission-degraded-bound-secs", |f| {
                f.take_degraded_bound("30").expect("an integer");
            }),
            ("--admission-allow-degraded", |f| {
                f.take_allow_degraded("true").expect("a boolean");
            }),
        ];
        for (flag, mutate) in cases {
            let mut flags = AdmissionFlags::default();
            mutate(&mut flags);
            let err = flags.finish().expect_err("a gate input beside off");
            assert!(err.contains(flag), "{flag}: {err}");
            assert!(err.contains("--admission is off"), "{flag}: {err}");
        }
    }

    /// The negative control: `off` alone is a coherent command line, and so is a fully
    /// configured gate.
    #[test]
    fn off_alone_and_a_configured_gate_are_both_accepted() {
        assert_eq!(
            AdmissionFlags::default().finish().expect("off alone"),
            AdmissionRequest::NotEnforced
        );
        let gate = enforcing().finish().expect("a configured gate");
        assert!(gate.is_enforced());
        assert_eq!(gate.flag_value(), "required");
    }

    /// The two illegal cells of the degraded table, refused here because after assembly
    /// neither can be written.
    #[test]
    fn the_two_illegal_degraded_cells_are_refused_by_the_adapter() {
        let mut inert = enforcing();
        inert.take_degraded_bound("30").expect("an integer");
        let err = inert.finish().expect_err("a bound nothing reads");
        assert!(err.contains("can never open"), "{err}");

        let mut zero_width = enforcing();
        zero_width.take_allow_degraded("true").expect("a boolean");
        let err = zero_width.finish().expect_err("a zero-width window");
        assert!(err.contains("must be > 0"), "{err}");
    }

    /// And the legal degraded cell is accepted, carrying its window.
    #[test]
    fn a_positive_window_under_degraded_mode_is_accepted() {
        let mut flags = enforcing();
        flags.take_allow_degraded("true").expect("a boolean");
        flags.take_degraded_bound("30").expect("an integer");
        let gate = flags.finish().expect("a bounded window");
        assert_eq!(
            gate.gate().map(|g| g.availability.bound_secs()),
            Some(Some(30))
        );
    }

    /// An enforcing form is inhabited by its inputs, so a command line that omits one names
    /// no form at all.
    #[test]
    fn an_enforcing_level_without_its_inputs_is_refused() {
        let mut flags = AdmissionFlags::default();
        flags.take_strictness("optional").expect("a known level");
        let err = flags.finish().expect_err("no authority");
        assert!(err.contains("--admission-authority-kid"), "{err}");
    }

    /// What a degraded cell is expected to be, and — when refused — WHICH mistake it is.
    ///
    /// Three refusals a single "is it rejected" assertion would conflate. They are
    /// different operator errors: a setting that applies to nothing, a setting that can
    /// never be reached, and a window narrower than it claims.
    #[derive(Debug, Clone, Copy)]
    enum Cell {
        /// Accepted, classifying to exactly this availability. `None` for `off`, which has
        /// no availability choice to make.
        Legal(Option<Option<u64>>),
        /// No gate exists, so no admission-specific parameter means anything.
        DanglingUnderOff,
        /// A gate exists, but both readers of the bound return before consulting it.
        UnreachableBound,
        /// A gate exists and will open a window, but not the width that was asked for.
        InvalidWidth,
    }

    impl Cell {
        /// The phrase that identifies this refusal and no other.
        fn marker(self) -> &'static str {
            match self {
                Cell::Legal(_) => unreachable!("a legal cell has no refusal to identify"),
                Cell::DanglingUnderOff => "--admission is off",
                Cell::UnreachableBound => "--admission-allow-degraded is false",
                Cell::InvalidWidth => "P + --max-clock-skew",
            }
        }
    }

    /// The complete degraded truth table, asserted cell by cell.
    ///
    /// It used to live at the configuration boundary. It could not stay: the request has no
    /// encoding for any of the refused cells any more. It is here rather than deleted
    /// because a FLAT COMMAND LINE can still state every one of them, and the property the
    /// table protects — that each mistake is answered with its own diagnostic and not
    /// another's — is a property of the diagnostics, which is what this layer owns.
    #[test]
    fn the_degraded_truth_table_is_complete_and_each_refusal_names_its_own_mistake() {
        let cases: &[(bool, Option<bool>, Option<i64>, Cell)] = &[
            // gate off: nothing admission-specific may be configured
            (false, None, None, Cell::Legal(None)),
            (false, None, Some(30), Cell::DanglingUnderOff),
            (false, None, Some(-30), Cell::DanglingUnderOff),
            (false, Some(true), None, Cell::DanglingUnderOff),
            (false, Some(true), Some(30), Cell::DanglingUnderOff),
            // gate on
            (true, None, None, Cell::Legal(Some(None))),
            (true, Some(false), Some(30), Cell::UnreachableBound),
            (true, Some(false), Some(-30), Cell::UnreachableBound),
            (true, Some(true), Some(0), Cell::InvalidWidth),
            (true, Some(true), Some(-30), Cell::InvalidWidth),
            (true, Some(true), Some(30), Cell::Legal(Some(Some(30)))),
        ];
        for &(gate, allow, bound, expected) in cases {
            let mut flags = if gate {
                enforcing()
            } else {
                AdmissionFlags::default()
            };
            if let Some(allow) = allow {
                flags
                    .take_allow_degraded(if allow { "true" } else { "false" })
                    .expect("a boolean");
            }
            if let Some(bound) = bound {
                flags
                    .take_degraded_bound(&bound.to_string())
                    .expect("an integer");
            }
            let at = format!("gate={gate} allow={allow:?} P={bound:?}");
            let outcome = flags.finish();
            let Cell::Legal(window) = expected else {
                let marker = expected.marker();
                let refusal = outcome.expect_err(&format!("{at}: accepted a refused cell"));
                assert!(
                    refusal.contains(marker),
                    "{at}: expected {expected:?} ({marker}), got {refusal}"
                );
                continue;
            };
            let request = outcome.unwrap_or_else(|e| panic!("{at}: refused — {e}"));
            assert_eq!(
                request.gate().map(|gate| gate.availability.bound_secs()),
                window,
                "{at}: assembled the wrong availability"
            );
        }
    }

    /// The `off` half of the table again, from the other direction: the width argument is
    /// never the reason given when no gate exists, because no window is opened at all.
    #[test]
    fn no_refusal_under_an_off_gate_argues_about_window_width() {
        for (allow, bound) in [(true, 30), (true, 0), (false, 30)] {
            let mut flags = AdmissionFlags::default();
            flags
                .take_allow_degraded(if allow { "true" } else { "false" })
                .expect("a boolean");
            flags
                .take_degraded_bound(&bound.to_string())
                .expect("an integer");
            if let Err(refusal) = flags.finish() {
                assert!(
                    !refusal.contains("P + --max-clock-skew"),
                    "allow={allow} P={bound}: the width argument must not be given with no \
                     gate: {refusal}"
                );
            }
        }
    }
}
