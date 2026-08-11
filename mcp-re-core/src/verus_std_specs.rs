//! Verus specifications for the `std` functions the proved code calls.
//!
//! ADR-MCPRE-059 Phase 2. Compiled only under `--features verify`; no production build
//! contains this module.
//!
//! Everything here is an **assumption**, not a proof: `assume_specification` tells the
//! verifier what a `std` function does without checking that `std` does it. Each entry is
//! therefore part of the Trusted Computing Base and MUST be registered in
//! `verification/policy/assumptions.toml`. Keep the set as small as the proofs require,
//! and prefer a vstd-provided specification over a local one whenever vstd grows it.

use crate::error::McpReError;
use verus_builtin_macros::verus;
use vstd::prelude::*;

verus! {

/// Makes the frozen error taxonomy nameable in a specification without verifying the
/// `thiserror`-derived `Display` impl that travels with it.
///
/// Trusted only in the sense that the verifier treats `McpReError` as an opaque datatype
/// with the variants declared here; no behavioural claim rides on it.
#[verifier::external_type_specification]
pub struct ExMcpReError(McpReError);

/// `<[T]>::split_last` — total; the proofs here use it only for control flow, so no
/// claim is made about what it returns.
///
/// Trusted against the standard library. A wrong specification could not weaken the
/// theorems that depend on it, because they depend on nothing but its totality.
pub assume_specification<T>[ <[T]>::split_last ](slice: &[T]) -> (result: Option<(&T, &[T])>)
;

/// `u8::is_ascii_digit` — true exactly on the ASCII code points `'0'..='9'`.
///
/// Trusted against the Rust standard library's documented behaviour
/// (`b'0' == 0x30`, `b'9' == 0x39`), which vstd does not currently specify.
pub assume_specification[ u8::is_ascii_digit ](b: &u8) -> (result: bool)
    ensures
        result == (0x30u8 <= *b && *b <= 0x39u8),
;

}
