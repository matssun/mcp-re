// SPDX-License-Identifier: Apache-2.0
//! The serving runtime's shape and its DoS ceilings.
//!
//! Two subordinate concerns, kept in one family because an operator tunes them together
//! and because they are all inputs to how one process serves: the thread topology, and the
//! limits every connection is held to. The parsing of each is trivial; the two that are
//! not — the admission ceiling and the timeouts — have their own helpers below.

use crate::config_state::InFlightLimitRequest;
use crate::tls::ServerLimits;
use std::num::NonZeroUsize;
use std::time::Duration;

/// The runtime inputs, as they accumulate across the argument list.
#[derive(Default)]
pub(super) struct RuntimeFlags {
    limits: ServerLimits,
    in_flight_limit: InFlightLimitRequest,
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
        matches!(
            flag,
            "--max-header-bytes"
                | "--max-body-bytes"
                | "--read-timeout-secs"
                | "--write-timeout-secs"
                | "--request-deadline-secs"
                | "--max-connections"
                | "--max-connection-age-secs"
                | "--drain-grace-secs"
                | "--max-in-flight"
                | "--max-in-flight-total"
                | "--cores"
                | "--workers-per-shard"
        )
    }

    /// Read one flag of the family. [`Self::owns`] decided it is one.
    pub(super) fn take(&mut self, flag: &str, value: &str) -> Result<(), String> {
        match flag {
            "--max-in-flight" | "--max-in-flight-total" => return self.take_admission(flag, value),
            "--cores" | "--workers-per-shard" => return self.take_topology(flag, value),
            _ => self.take_limit(flag, value)?,
        }
        Ok(())
    }

    /// The per-connection ceilings and the windows they are enforced over.
    fn take_limit(&mut self, flag: &str, value: &str) -> Result<(), String> {
        let count = |kind: &str| -> Result<usize, String> {
            value.parse().map_err(|_| format!("invalid {kind}"))
        };
        match flag {
            "--max-header-bytes" => self.limits.max_header_bytes = count(flag)?,
            "--max-body-bytes" => self.limits.max_body_bytes = count(flag)?,
            "--max-connections" => self.limits.max_concurrent_connections = count(flag)?,
            "--read-timeout-secs" => self.limits.read_timeout = super::parse_timeout(value, flag)?,
            "--write-timeout-secs" => {
                self.limits.write_timeout = super::parse_timeout(value, flag)?
            }
            // Aggregate wall-clock deadline over the whole server read phase (handshake +
            // header/body); slow-loris defense. `0` disables, like the per-socket knob.
            "--request-deadline-secs" => {
                self.limits.request_deadline = super::parse_timeout(value, flag)?
            }
            // MCPRE-116 / ADR-MCPS-023 §A1: how long one mTLS connection may serve before
            // it is gracefully closed and the peer must re-handshake. The client-cert
            // chain, its CRL status and its validity window are checked at the handshake
            // and NOWHERE else, so this is what bounds revocation latency for a peer that
            // simply keeps its connection open.
            "--max-connection-age-secs" => {
                self.limits.max_connection_age = super::parse_timeout(value, flag)?
            }
            // MCPRE-115 (ADR-MCPRE-051 §6): the bounded drain window. Exposed because the
            // k8s side of the invariant (`request_deadline <= drain_grace <
            // terminationGracePeriodSeconds`, minus any preStop delay) cannot be satisfied
            // from the chart alone while this value is a hardcoded constant.
            _ => self.limits.drain_grace = Duration::from_secs(count(flag)? as u64),
        }
        Ok(())
    }

    /// The per-request admission ceiling, in either of its two spellings.
    ///
    /// MCPRE-114. A ceiling ALWAYS applies — `ServerLimits::default()` carries a per-core
    /// one — because without it a single client holding a valid mTLS certificate drives
    /// unbounded concurrent work, each request buffering up to `--max-body-bytes` BEFORE
    /// the verify gate. `--max-in-flight` overrides the per-core ceiling directly;
    /// `--max-in-flight-total` sets a fleet-wide target the fleet divides evenly across
    /// cores. The two are ALTERNATIVES, and naming both is refused.
    fn take_admission(&mut self, flag: &str, value: &str) -> Result<(), String> {
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
        super::second_admission_limit(self.in_flight_limit, flag)?;
        self.in_flight_limit = if flag == "--max-in-flight" {
            InFlightLimitRequest::PerCore(n)
        } else {
            InFlightLimitRequest::FleetTotal(n)
        };
        Ok(())
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
            in_flight_limit: self.in_flight_limit,
            cores: self.cores,
            workers_per_shard: self.workers_per_shard,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The admission ceiling has two spellings and they are alternatives: naming both is
    /// refused, because the second would silently replace the first.
    #[test]
    fn the_two_admission_spellings_are_alternatives() {
        let mut flags = RuntimeFlags::default();
        flags.take("--max-in-flight", "16").expect("a ceiling");
        let err = flags
            .take("--max-in-flight-total", "64")
            .expect_err("two ceilings");
        assert!(err.contains("--max-in-flight"), "{err}");
    }

    /// Neither spelling admits zero, and each says why in its own terms.
    #[test]
    fn no_spelling_of_the_ceiling_admits_zero() {
        for (flag, marker) in [
            ("--max-in-flight", "no ceiling"),
            ("--max-in-flight-total", "omit it"),
        ] {
            let err = RuntimeFlags::default()
                .take(flag, "0")
                .expect_err("zero is not a ceiling");
            assert!(err.contains(marker), "{flag}: {err}");
        }
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
}
