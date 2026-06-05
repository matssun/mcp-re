//! Pairing of a verified response's metadata with its unwrapped payload
//! (issue #4077 / MCPS-MED-4).

use mcps_core::UnwrappedResult;
use mcps_core::VerifiedResponse;

/// The full client-side outcome of verifying AND unwrapping a signed proxy
/// response: the cryptographic verdict ([`VerifiedResponse`] — signer/key/bound
/// request hash) plus the [`UnwrappedResult`] restoring the ORIGINAL MCP shape
/// the proxy reshaped before signing.
///
/// Returned by `HostSession::verify_and_unwrap_response`. Callers that only need
/// the verdict keep using `HostSession::verify_response`; callers that consume
/// the result payload use this so a scalar arrives as a scalar and an inner error
/// arrives as an error rather than a success.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedResult {
    /// The verification verdict: server signer, key id, and bound request hash.
    pub verified: VerifiedResponse,
    /// The original MCP `result` shape recovered after verification.
    pub unwrapped: UnwrappedResult,
}
