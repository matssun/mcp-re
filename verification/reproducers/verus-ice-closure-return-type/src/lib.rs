// SPDX-License-Identifier: Apache-2.0
//! Minimal reproducer: Verus ICEs on a verified function whose closure parameter
//! returns a type with no Verus specification.
//!
//! Expected: a diagnostic naming the unspecified type.
//! Actual:   thread '<unnamed>' panicked at vir/src/sst_to_air.rs:510:45:
//!           called `Option::unwrap()` on a `None` value
//!
//! Observed on verus 0.2026.08.09.92f466f (commit 92f466f2), macOS aarch64,
//! toolchain 1.97.1.
//!
//! Narrowing (each verified cleanly, so the trigger is the closure's RETURN type,
//! not the closure parameter itself and not the reference argument):
//!
//!   fn f(g: impl Fn(u64) -> u64) -> u64      OK
//!   fn f(g: impl Fn(&str) -> u64) -> u64     OK
//!   fn f(g: impl Fn(&str) -> Opaque) -> u64  ICE     <-- this file
//!
//! Adding `#[verifier::external_type_specification]` for `Opaque` removes the ICE.
//!
//! The ceiling is registered as ceiling 1 of
//! `verification/baseline/wp2-http-profile-triage.md`, and its workaround is ASM-0013 in
//! `verification/policy/assumptions.toml`, which declares `VerificationKey` opaque.
//!
//! **Nothing in this crate is proved.** The `ensures` below is never discharged: the
//! prover panics before it reaches the obligation. It is part of the trigger's shape (a
//! verified function with a specification), not a result, and no unit or theorem cites it.

use verus_builtin_macros::verus_spec;
#[allow(unused_imports)]
use vstd::prelude::*;

/// Stands in for any foreign type the prover has no specification for. In the original
/// case this was an Ed25519 verification key returned by a trust-resolution closure.
pub struct Opaque;

#[verus_spec(out => ensures out == 1u64)]
pub fn ice(resolve: impl Fn(&str) -> Option<Opaque>) -> u64 {
    let _ = resolve;
    1
}
