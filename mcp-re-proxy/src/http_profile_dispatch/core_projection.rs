// SPDX-License-Identifier: Apache-2.0
//! What the replay-tier gate's failures mean in Core's terms — ADR-MCPRE-066 Slice 2.
//!
//! The tier gate is a third producer of audit rejection reasons, and it used to produce them
//! as strings. That is how nothing at the audit boundary could tell a Core verdict from a
//! foreign one: a string carries no authority, so any producer of one was a producer of
//! rejection reasons, and the guard had to go looking for them (#637, ADR-MCPRE-066 §5).
//!
//! It now names the verdict, and its wire token is derived from that. Same shape as the
//! carrier's own projection in `mcp-re-http-profile`, and for the same reason: exactly one
//! place per crate decides what its failures mean, so there is no second table to fall out
//! of step with the first.
//!
//! No wildcard arm. A new tier-gate failure is a compile error here until it says which Core
//! verdict it is.

use mcp_re_core::McpReError;

use super::ProxyDispatchError;

impl From<&ProxyDispatchError> for McpReError {
    fn from(e: &ProxyDispatchError) -> McpReError {
        match e {
            // A tier below the strict-production minimum and no declared tier are one fact
            // for the caller: the store this deployment would admit against cannot be relied
            // upon. Fail closed on the operational token rather than inventing a
            // configuration one — the request is refused, and why is the operator's startup
            // line, not the client's rejection code.
            ProxyDispatchError::SubMinimumReplayTier(_)
            | ProxyDispatchError::NoDeclaredReplayTier => McpReError::ReplayCacheUnavailable,
            ProxyDispatchError::Dispatch(e) => McpReError::from(e),
        }
    }
}

impl ProxyDispatchError {
    /// The frozen `mcp-re.*` wire token this failure maps to — derived from the projection
    /// above, never chosen here.
    pub fn wire_code(&self) -> &'static str {
        McpReError::from(self).wire_code()
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ReplayDurabilityTier;

    /// Both tier failures are the same fact about the store, and the projection says so.
    #[test]
    fn an_unusable_tier_and_an_undeclared_one_are_one_verdict() {
        assert_eq!(
            McpReError::from(&ProxyDispatchError::SubMinimumReplayTier(
                ReplayDurabilityTier::RedisAsyncBounded
            )),
            McpReError::from(&ProxyDispatchError::NoDeclaredReplayTier)
        );
        assert_eq!(
            ProxyDispatchError::NoDeclaredReplayTier.wire_code(),
            "mcp-re.replay_cache_unavailable"
        );
    }

    /// The delegating arm does not re-decide: a dispatch failure keeps the verdict the
    /// dispatcher's own projection gave it.
    #[test]
    fn a_delegated_failure_keeps_the_dispatchers_verdict() {
        use mcp_re_http_profile::DispatchError;
        let inner = DispatchError::ReplayDetected;
        assert_eq!(
            McpReError::from(&ProxyDispatchError::Dispatch(inner.clone())),
            McpReError::from(&inner)
        );
    }
}
