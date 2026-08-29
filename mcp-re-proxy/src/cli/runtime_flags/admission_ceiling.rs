// SPDX-License-Identifier: Apache-2.0
//! The per-request admission ceiling, in either of its two spellings.
//!
//! MCPRE-114. A ceiling ALWAYS applies — `ServerLimits::default()` carries a per-core one —
//! because without it a single client holding a valid mTLS certificate drives unbounded
//! concurrent work, each request buffering up to `--max-body-bytes` BEFORE the verify gate.
//! `--max-in-flight` overrides the per-core ceiling directly; `--max-in-flight-total` sets a
//! fleet-wide target the fleet divides evenly across cores.
//!
//! The two are ALTERNATIVES rather than two values to reconcile, so this module owns one
//! rule the rest of the CLI has no analogue for: naming both is a refusal.

use crate::config_state::InFlightLimitRequest;
use std::num::NonZeroUsize;

/// The ceiling as it accumulates across the argument list: at most one, ever stated once.
#[derive(Default)]
pub(super) struct AdmissionCeiling(InFlightLimitRequest);

impl AdmissionCeiling {
    /// Whether this flag is one of the ceiling's two spellings.
    pub(super) fn owns(flag: &str) -> bool {
        matches!(flag, "--max-in-flight" | "--max-in-flight-total")
    }

    /// Read one spelling. [`Self::owns`] decided it is one.
    pub(super) fn take(&mut self, flag: &str, value: &str) -> Result<(), String> {
        let n: usize = value.parse().map_err(|_| format!("invalid {flag}"))?;
        let Some(n) = NonZeroUsize::new(n) else {
            return Err(if flag == "--max-in-flight" {
                "--max-in-flight must be > 0; there is no \"no ceiling\" setting, because \
                 unbounded in-flight requests are attacker-controlled buffering ahead of \
                 the verify gate"
                    .to_string()
            } else {
                "--max-in-flight-total must be > 0 (omit it to keep the per-core default \
                 ceiling)"
                    .to_string()
            });
        };
        self.refuse_a_second_statement(flag)?;
        self.0 = if flag == "--max-in-flight" {
            InFlightLimitRequest::PerCore(n)
        } else {
            InFlightLimitRequest::FleetTotal(n)
        };
        Ok(())
    }

    /// The ceiling this argument list states, or `Unspecified` if it stated none — which is
    /// what leaves the per-core default in force.
    pub(super) fn finish(self) -> InFlightLimitRequest {
        self.0
    }

    /// Refuse a SECOND admission limit: the two flags are alternative ways to state one, so
    /// naming both — or the same one twice — is a refusal rather than a precedence question.
    ///
    /// They are not two values to reconcile. One bounds each core directly and the other is
    /// divided evenly across the resolved cores, so which aggregate a total implies is not
    /// known until the core count is; equivalence is a property of the host, not of the
    /// request. There is therefore no "they agree" case to exempt.
    ///
    /// The rule the chart already enforced (`_helpers.tpl`: "set one OR the other, not
    /// both").
    ///
    /// # Why this is the parser's job and not the boundary's
    ///
    /// [`InFlightLimitRequest`] holds ONE limit, so a `DeploymentRequest` naming both cannot
    /// be constructed — by a parser, an embedder or a test — and the boundary has no such
    /// state left to refuse. What remains is only reachable while READING an argument list,
    /// where "already set" is a fact about the input rather than about the request: without
    /// this, the second flag would silently overwrite the first.
    fn refuse_a_second_statement(&self, flag: &str) -> Result<(), String> {
        let stated = match self.0 {
            InFlightLimitRequest::Unspecified => return Ok(()),
            InFlightLimitRequest::PerCore(n) => format!("--max-in-flight {n}"),
            InFlightLimitRequest::FleetTotal(n) => format!("--max-in-flight-total {n}"),
        };
        Err(format!(
            "{stated} already states the admission limit; {flag} would state it a second \
             time. --max-in-flight bounds each core directly and --max-in-flight-total is \
             divided evenly across the resolved cores, so the two cannot be checked against \
             each other before the core count is known. Set one."
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two spellings are alternatives: naming both is refused, because the second would
    /// silently replace the first. Stating the same one twice is the same refusal.
    #[test]
    fn the_two_spellings_are_alternatives_and_neither_may_be_restated() {
        for second in ["--max-in-flight-total", "--max-in-flight"] {
            let mut ceiling = AdmissionCeiling::default();
            ceiling.take("--max-in-flight", "16").expect("a ceiling");
            let err = ceiling.take(second, "64").expect_err("two statements");
            assert!(err.contains("--max-in-flight 16"), "{second}: {err}");
        }
    }

    /// Neither spelling admits zero, and each says why in its own terms.
    #[test]
    fn no_spelling_admits_zero() {
        for (flag, marker) in [
            ("--max-in-flight", "no ceiling"),
            ("--max-in-flight-total", "omit it"),
        ] {
            let err = AdmissionCeiling::default()
                .take(flag, "0")
                .expect_err("zero is not a ceiling");
            assert!(err.contains(marker), "{flag}: {err}");
        }
    }

    /// An argument list that states no ceiling leaves the per-core default in force, which
    /// is what makes "a ceiling always applies" true.
    #[test]
    fn an_unstated_ceiling_is_unspecified_rather_than_absent() {
        assert!(matches!(
            AdmissionCeiling::default().finish(),
            InFlightLimitRequest::Unspecified
        ));
    }
}
