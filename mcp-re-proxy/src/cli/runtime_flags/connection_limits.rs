// SPDX-License-Identifier: Apache-2.0
//! What one connection is held to: the byte ceilings, and the windows they run in.
//!
//! Every input here bounds ONE connection's demand on the process, which is why they are
//! read together. The windows carry the load-bearing part: a timeout that can be turned off
//! is a slow-loris defense that can be turned off, so this module owns both the "`0`
//! disables" mapping and the upper bound that keeps an out-of-range value from disabling
//! the control by overflowing downstream.

use crate::tls::ServerLimits;
use std::time::Duration;

/// The maximum accepted timeout in seconds: 1 day. Generous for any legitimate inner yet
/// far below the range that would overflow `Instant::now() + timeout` in the deadline
/// reader, making that overflow practically unreachable (the `checked_add` there is
/// defense-in-depth).
pub(in crate::cli) const MAX_INNER_READ_TIMEOUT_SECS: u64 = 86_400;

/// Whether this flag is one of the per-connection ceilings or windows.
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
    )
}

/// Read one such flag into `limits`. [`owns`] decided it is one.
pub(super) fn take(limits: &mut ServerLimits, flag: &str, value: &str) -> Result<(), String> {
    let count = |kind: &str| -> Result<usize, String> {
        value.parse().map_err(|_| format!("invalid {kind}"))
    };
    match flag {
        "--max-header-bytes" => limits.max_header_bytes = count(flag)?,
        "--max-body-bytes" => limits.max_body_bytes = count(flag)?,
        "--max-connections" => limits.max_concurrent_connections = count(flag)?,
        "--read-timeout-secs" => limits.read_timeout = parse_timeout(value, flag)?,
        "--write-timeout-secs" => limits.write_timeout = parse_timeout(value, flag)?,
        // Aggregate wall-clock deadline over the whole server read phase (handshake +
        // header/body); slow-loris defense. `0` disables, like the per-socket knob.
        "--request-deadline-secs" => limits.request_deadline = parse_timeout(value, flag)?,
        // MCPRE-116 / ADR-MCPS-023 §A1: how long one mTLS connection may serve before it is
        // gracefully closed and the peer must re-handshake. The client-cert chain, its CRL
        // status and its validity window are checked at the handshake and NOWHERE else, so
        // this is what bounds revocation latency for a peer that simply keeps its
        // connection open.
        "--max-connection-age-secs" => limits.max_connection_age = parse_timeout(value, flag)?,
        // MCPRE-115 (ADR-MCPRE-051 §6): the bounded drain window. Exposed because the k8s
        // side of the invariant (`request_deadline <= drain_grace <
        // terminationGracePeriodSeconds`, minus any preStop delay) cannot be satisfied from
        // the chart alone while this value is a hardcoded constant.
        _ => limits.drain_grace = Duration::from_secs(count(flag)? as u64),
    }
    Ok(())
}

/// Parse a timeout in whole seconds; `0` disables the timeout (`None`). The value is CAPPED
/// at [`MAX_INNER_READ_TIMEOUT_SECS`] (1 day) and an over-cap value is REJECTED loudly.
/// This matters for `--request-deadline-secs`, whose value is later added to
/// `Instant::now()` in the fail-closed deadline reader (`tls::DeadlineStream`): an absurdly
/// large value would overflow `checked_add` and — if not rejected here — silently DISABLE
/// the slow-loris defense. Bounding at parse time keeps the control fail-closed.
fn parse_timeout(value: &str, flag: &str) -> Result<Option<Duration>, String> {
    let secs: u64 = value.parse().map_err(|_| format!("invalid {flag}"))?;
    if secs > MAX_INNER_READ_TIMEOUT_SECS {
        return Err(format!(
            "{flag} must be <= {MAX_INNER_READ_TIMEOUT_SECS} seconds (1 day); got {secs}"
        ));
    }
    Ok(if secs == 0 {
        None
    } else {
        Some(Duration::from_secs(secs))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `0` is the disabled posture and the cap is inclusive: the two edges of the window
    /// mapping, held here rather than only end-to-end through `parse_args`.
    #[test]
    fn zero_disables_a_window_and_the_cap_is_the_last_accepted_value() {
        let mut limits = ServerLimits::default();
        take(&mut limits, "--read-timeout-secs", "0").expect("zero parses");
        assert_eq!(limits.read_timeout, None, "zero is the disabled posture");

        let cap = MAX_INNER_READ_TIMEOUT_SECS.to_string();
        take(&mut limits, "--request-deadline-secs", &cap).expect("the cap itself is accepted");
        assert_eq!(
            limits.request_deadline,
            Some(Duration::from_secs(MAX_INNER_READ_TIMEOUT_SECS))
        );

        let over = (MAX_INNER_READ_TIMEOUT_SECS + 1).to_string();
        let err = take(&mut limits, "--request-deadline-secs", &over)
            .expect_err("over the cap is refused");
        assert!(
            err.contains("--request-deadline-secs") && err.contains("<="),
            "the refusal names the flag and the bound; got: {err}"
        );
    }

    /// A byte ceiling is a count, and a non-count is refused rather than defaulted.
    #[test]
    fn a_byte_ceiling_is_a_count() {
        let mut limits = ServerLimits::default();
        take(&mut limits, "--max-body-bytes", "4096").expect("a count");
        assert_eq!(limits.max_body_bytes, 4096);
        assert!(take(&mut limits, "--max-body-bytes", "big").is_err());
    }
}
