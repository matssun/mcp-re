// SPDX-License-Identifier: Apache-2.0
//! What an enforcing deployment does when the admission authority is unreachable.
//!
//! Its own module because it is its own rule, and the only part of the family with a
//! grammar: two flat flags that between them can state four combinations, of which two are
//! deployments and two are mistakes. After assembly neither mistake is writable — the
//! availability is one tagged value and its window is a `NonZeroU64` — so this is where
//! both are answered.

use super::AdmissionFlags;
use crate::deployment_request::AdmissionAvailabilityRequest;
use std::num::NonZeroU64;

impl AdmissionFlags {
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

    /// What this deployment does when the authority is unreachable.
    ///
    /// The two illegal cells of the old table are refused here because only a command line
    /// can state them: a bound where nothing reads it, and a degraded window of zero width.
    /// After assembly the availability is one tagged value and the bound is a `NonZeroU64`.
    pub(super) fn availability(&self) -> Result<AdmissionAvailabilityRequest, String> {
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
