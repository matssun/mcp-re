// SPDX-License-Identifier: Apache-2.0
//! The bytes a caller retained for a pending MRTR correlation.
//!
//! ## What this owns, and what it does not
//!
//! It owns one fact: **these three byte strings were read together, out of one correlation
//! record.** They are not derived here and cannot be — they are the exact RFC 9421
//! signature bases and the opaque `requestState` the client committed to on the prior legs,
//! and only the deployment's correlation store holds them.
//!
//! It does NOT own the binding to the request being dispatched. The store is keyed by the
//! actor the verifier resolved and by the request's own `requestState`
//! (`mcp-re-proxy::http_profile_serve::continuation`), so the lookup is what ties a record
//! to a correlation — and the lookup lives in the caller. A value of this type says "a
//! correlation record was read", never "THIS request's record was read". That gap is real
//! and is recorded as an owner question rather than papered over here, because closing it
//! means deciding where correlation lookup lives, which is a design question about the
//! store and not about this type.
//!
//! ## What the seal buys anyway
//!
//! The fields are `pub(crate)` and [`RetainedContinuation::from_correlation`] is the only
//! way in from outside. That is not the same as binding, and it is not nothing: no consumer
//! can assemble a binding out of three byte slices it happened to be holding, and each
//! crate that does hold a correlation store now has one auditable construction site instead
//! of an anonymous struct literal.
//!
//! Confusing the two bases with each other is caught by the mechanism rather than by the
//! type: [`crate::HttpContinuation::verify`] digests each under a DISTINCT role label
//! (ADR-MCPRE-059 `http_profile.continuation_binding`), so a swapped pair fails
//! `continuation_binding_failed` and is never admitted.
//!
//! ## Why the fields are `pub(crate)` and not module-private
//!
//! Module privacy is the lever this project prefers, and it is unavailable here.
//! `RetainedContinuation` is mirrored into the Verus lane as a TRANSPARENT external type
//! specification (`crate::verus_std_specs::ExRetainedContinuation`) because the
//! unbypassability proof must see the value the binding reads, and Verus rejects anything
//! narrower than `pub` on a transparent datatype — MEASURED, not assumed:
//! `pub(crate)` fields fail the lane with "external_type_specification: private fields not
//! supported for transparent datatypes". So the fields stay `pub` and the seal is
//! `#[non_exhaustive]`, which refuses a struct literal from any other crate (E0639).
//!
//! WHAT THAT DOES AND DOES NOT BUY, stated because `CLAUDE.md` is right to be sceptical of
//! this attribute. Its warning — that `#[non_exhaustive]` seals nothing — rests on a stated
//! premise: that an owner's consumers live in the owner's own crate. For THIS value the
//! premise does not hold. Every producer is in another crate: the proxy's serving path, the
//! example proxy, the conformance battery. So the attribute binds every production
//! consumer, and the honest limit is that it does not bind `mcp-re-http-profile` itself,
//! where the only other construction sites are this module's own tests.
//!
//! The alternative was an `external_body` mirror, which would make the type opaque to the
//! prover — and the proof's own body reads these fields to drive the binding, so that
//! would have cost the proof to buy the seal. A Verus-proved postcondition outranks a seal
//! (`CLAUDE.md`), so the seal gives way at exactly the point they conflict, and no further.

/// The bytes the caller retained for a pending correlation, needed to verify an MRTR
/// continuation.
///
/// Built only through [`Self::from_correlation`]; a struct literal is refused outside this
/// crate:
///
/// ```compile_fail
/// let _ = mcp_re_http_profile::RetainedContinuation {
///     previous_request_base: b"prev",
///     input_required_response_base: b"irr",
///     request_state: b"state",
/// };
/// ```
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RetainedContinuation<'a> {
    /// The RFC 9421 signature base of the client request that produced the
    /// `InputRequiredResult`.
    pub previous_request_base: &'a [u8],
    /// The RFC 9421 signature base of the verified `InputRequiredResult` response.
    pub input_required_response_base: &'a [u8],
    /// The opaque `requestState` bytes (never interpreted, only digest-bound).
    pub request_state: &'a [u8],
}

impl<'a> RetainedContinuation<'a> {
    /// The bases and state read out of ONE correlation record.
    ///
    /// Named for its provenance because that is the whole claim: the caller is asserting
    /// that these three came from a single retained record, not that they belong to the
    /// request about to be dispatched. The dispatcher checks the second half
    /// cryptographically — an answer leg whose continuation does not digest to these bases
    /// fails closed before the nonce is burned.
    pub fn from_correlation(
        previous_request_base: &'a [u8],
        input_required_response_base: &'a [u8],
        request_state: &'a [u8],
    ) -> RetainedContinuation<'a> {
        RetainedContinuation {
            previous_request_base,
            input_required_response_base,
            request_state,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_constructor_keeps_the_three_slots_apart() {
        // The ordering is load-bearing — the two bases are checked under distinct role
        // labels downstream — so a constructor that transposed them would turn every
        // legitimate answer leg into a binding failure.
        let c = RetainedContinuation::from_correlation(b"prev", b"irr", b"state");
        assert_eq!(c.previous_request_base, b"prev".as_slice());
        assert_eq!(c.input_required_response_base, b"irr".as_slice());
        assert_eq!(c.request_state, b"state".as_slice());
    }
}
