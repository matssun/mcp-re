// SPDX-License-Identifier: Apache-2.0
//! The serving runtime's shape and its DoS ceilings.
//!
//! One family, because an operator tunes these together and they are all inputs to how one
//! process serves. Three subordinate authorities sit under it, and each answers a question
//! the other two do not:
//!
//! - [`connection_limits`] — what ONE connection is held to, and the windows it runs in.
//! - [`admission_ceiling`] — how many requests may be in flight, in either spelling of the
//!   one limit; it owns the refusal that makes them alternatives.
//! - the thread topology below — how many runtimes and workers exist to be held to any of
//!   it.
//!
//! What is left here is the routing and the composition: no value's meaning is decided at
//! this level.

mod admission_ceiling;
mod connection_limits;

// The cap is `connection_limits`' own bound and production has no other reader; the
// family's end-to-end refusal test in `cli` names it rather than restating the number.
#[cfg(test)]
pub(super) use connection_limits::MAX_INNER_READ_TIMEOUT_SECS;

use crate::config_state::InFlightLimitRequest;
use crate::tls::ServerLimits;
use admission_ceiling::AdmissionCeiling;

/// The runtime inputs, as they accumulate across the argument list.
#[derive(Default)]
pub(super) struct RuntimeFlags {
    limits: ServerLimits,
    admission: AdmissionCeiling,
    cores: usize,
    workers_per_shard: usize,
}

/// How one process serves.
pub(super) struct ServingRuntime {
    pub(super) limits: ServerLimits,
    pub(super) in_flight_limit: InFlightLimitRequest,
    pub(super) cores: usize,
    pub(super) workers_per_shard: usize,
}

impl RuntimeFlags {
    /// Whether this value-taking flag belongs to the family.
    pub(super) fn owns(flag: &str) -> bool {
        connection_limits::owns(flag)
            || AdmissionCeiling::owns(flag)
            || matches!(flag, "--cores" | "--workers-per-shard")
    }

    /// Route one flag of the family to the authority that owns its meaning. [`Self::owns`]
    /// decided it is one.
    pub(super) fn take(&mut self, flag: &str, value: &str) -> Result<(), String> {
        if AdmissionCeiling::owns(flag) {
            self.admission.take(flag, value)
        } else if connection_limits::owns(flag) {
            connection_limits::take(&mut self.limits, flag, value)
        } else {
            self.take_topology(flag, value)
        }
    }

    /// The thread topology.
    ///
    /// Sharding and thread count are not interchangeable: at an identical 16 threads,
    /// 8 shards x 2 workers measured 19,910 rps against 44,816 for 2 shards x 8, because
    /// Tokio steals work only within one runtime.
    fn take_topology(&mut self, flag: &str, value: &str) -> Result<(), String> {
        let n: usize = value.parse().map_err(|_| {
            format!("invalid {flag} (expected a non-negative integer; 0 = auto/single-threaded)")
        })?;
        // ADR-MCPRE-051 §1: `--cores 0` is auto (one worker per core). An explicit count
        // makes the 1→N linear-scaling benchmark reproducible and can cap workers below
        // the core count.
        if flag == "--cores" {
            self.cores = n;
        } else {
            self.workers_per_shard = n;
        }
        Ok(())
    }

    /// How this process serves. Total: every input has a default that is what its absence
    /// has always meant.
    pub(super) fn finish(self) -> ServingRuntime {
        ServingRuntime {
            limits: self.limits,
            in_flight_limit: self.admission.finish(),
            cores: self.cores,
            workers_per_shard: self.workers_per_shard,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The routing table is disjoint and total over what [`RuntimeFlags::owns`] claims: a
    /// flag the family claims reaches exactly the authority that owns its meaning, which is
    /// the one thing this level decides.
    #[test]
    fn every_claimed_flag_routes_to_the_authority_that_owns_it() {
        for flag in [
            "--max-body-bytes",
            "--read-timeout-secs",
            "--max-in-flight",
            "--cores",
        ] {
            assert!(RuntimeFlags::owns(flag), "{flag} is claimed by the family");
            RuntimeFlags::default()
                .take(flag, "8")
                .unwrap_or_else(|e| panic!("{flag} must reach an owner: {e}"));
        }
        assert!(!RuntimeFlags::owns("--bind"), "another family's flag");
    }

    /// The topology flags are non-negative counts, and `0` is the auto posture rather than
    /// a refusal.
    #[test]
    fn the_topology_counts_admit_zero_as_the_auto_posture() {
        let mut flags = RuntimeFlags::default();
        flags.take("--cores", "0").expect("auto");
        flags.take("--workers-per-shard", "8").expect("a count");
        assert!(flags.take("--cores", "-1").is_err());
        let runtime = flags.finish();
        assert_eq!(runtime.cores, 0);
        assert_eq!(runtime.workers_per_shard, 8);
    }

    /// The ceiling the admission authority read is the one the composed runtime carries:
    /// this level transports it and does not re-decide it.
    #[test]
    fn the_composed_runtime_carries_the_ceiling_the_admission_authority_read() {
        let mut flags = RuntimeFlags::default();
        flags.take("--max-in-flight", "16").expect("a ceiling");
        assert!(matches!(
            flags.finish().in_flight_limit,
            InFlightLimitRequest::PerCore(n) if n.get() == 16
        ));
    }
}
