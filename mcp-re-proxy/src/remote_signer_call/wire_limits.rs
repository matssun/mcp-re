// SPDX-License-Identifier: Apache-2.0
//! The bounds every remote-signer HTTP call is made under.
//!
//! Two numbers and one read, shared by the AWS KMS, GCP Cloud KMS and AWS STS transports
//! because they are one fact about how this proxy talks to a control plane — not three
//! coincidentally equal constants. They were written three times, byte-for-byte, and each
//! copy carried a comment pointing at its siblings to say they matched; a comment is how a
//! duplication is remembered, not how it is owned.
//!
//! Neither number is a provider's. A cloud vendor does not publish "read at most 8 KiB of
//! our error body"; that is this proxy's rule about what it is willing to buffer from a
//! remote it does not control, and about how long it will wait before calling a signer
//! unreachable.

use std::io::Read;
use std::time::Duration;

/// How long any single remote-signer HTTP exchange may take before it is a failure.
///
/// Short on purpose: these calls sit on the handshake and response-signing paths, so a slow
/// signer must become a fast refusal rather than a queue. A caller that needs to back off
/// after such a failure takes its cooldown FROM this value, so the two cannot drift apart.
pub(crate) const NETWORK_TIMEOUT: Duration = Duration::from_secs(5);

/// The most of a remote error body this proxy will read, for diagnostics only.
///
/// A bound rather than a preference: the body arrives from a remote that may be
/// misbehaving, it is rendered into a refusal string, and an unbounded read would let that
/// remote choose this process's memory.
pub(crate) const MAX_ERROR_BODY_BYTES: u64 = 8 * 1024;

/// Read a bounded, lossy string from an HTTP error response body.
///
/// Diagnostics only — nothing decides anything from these bytes. Lossy because an error
/// body that is not UTF-8 is still worth showing an operator, and failing to render it
/// would replace a partial diagnostic with none. The read result is discarded for the same
/// reason: a truncated or failed read yields whatever arrived, which beats reporting a
/// second failure about the first one's body.
pub(crate) fn read_error_body(resp: ureq::Response) -> String {
    let mut buf = Vec::new();
    let _ = resp
        .into_reader()
        .take(MAX_ERROR_BODY_BYTES)
        .read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cap is a bound on what a remote can make this process buffer, so what matters is
    /// that it is finite and modest — not its exact value.
    #[test]
    fn the_error_body_cap_bounds_what_a_remote_can_make_us_buffer() {
        assert_eq!(MAX_ERROR_BODY_BYTES, 8 * 1024);
        assert!(
            MAX_ERROR_BODY_BYTES > 0,
            "a zero cap would render no diagnostic at all"
        );
    }

    /// The timeout is what makes a slow signer a fast refusal rather than a queue on the
    /// handshake path.
    #[test]
    fn the_network_timeout_is_short_enough_to_refuse_rather_than_queue() {
        assert_eq!(NETWORK_TIMEOUT, Duration::from_secs(5));
        assert!(
            NETWORK_TIMEOUT <= Duration::from_secs(10),
            "these calls sit on the handshake path; a long wait is a queue"
        );
    }
}
