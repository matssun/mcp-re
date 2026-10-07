// SPDX-License-Identifier: Apache-2.0
//! The credential thumbprint, `base64url-no-pad(SHA-256(bytes))`, as one owner.
//!
//! The composition is this project's and is proved; the two library calls it composes are the
//! only premises, each behind a leaf whose `external_body` names exactly what the library is
//! trusted to compute (r12 Ruling 38): `sha256_digest` the `sha2` crate's digest (ASM-0018),
//! `b64url_digest` the `base64` crate's encoding (ASM-0073). Their uninterpreted names below
//! add no axiom of their own (ASM-0074, ASM-0075).

use mcp_re_core::b64url_encode;
use sha2::Digest;
use sha2::Sha256;
#[cfg(feature = "verify")]
use verus_builtin_macros::{verus, verus_spec, verus_verify};
#[cfg(feature = "verify")]
#[allow(unused_imports)]
use vstd::prelude::*;

#[cfg(feature = "verify")]
verus! {

/// SHA-256 of the bytes, UNINTERPRETED: what it denotes is ASM-0018's, and no collision or
/// preimage property is assumed by declaring it.
pub uninterp spec fn sha256_of(bytes: Seq<u8>) -> Seq<u8>;

/// The base64url-no-pad encoding of the bytes, UNINTERPRETED: what it denotes, and that it is
/// injective, is ASM-0073's.
pub uninterp spec fn b64url_of(bytes: Seq<u8>) -> Seq<char>;

/// The credential thumbprint: the base64url-no-pad encoding of the SHA-256 digest. A
/// definition, so the composition adds no premise.
pub open spec fn thumbprint_of(bytes: Seq<u8>) -> Seq<char> {
    b64url_of(sha256_of(bytes))
}

}

/// SHA-256 of `bytes`, as computed by the `sha2` crate.
// ASM-0018: below `boundary.crypto_primitives`. Trusted to return the FIPS 180-4 digest of its
// input, named for the prover as `sha256_of`; nothing is claimed about the digest's strength.
#[cfg_attr(feature = "verify", verus_verify(external_body))]
#[cfg_attr(feature = "verify", verus_spec(out =>
    ensures out@ == sha256_of(bytes@),
))]
fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The base64url-no-pad encoding of a digest, as computed by the `base64` crate.
// ASM-0073: beyond `boundary.base64_encoding`. Trusted to return the RFC 4648 §5 encoding of its
// input without padding, named for the prover as `b64url_of`, and that encoding is injective.
#[cfg_attr(feature = "verify", verus_verify(external_body))]
#[cfg_attr(feature = "verify", verus_spec(out =>
    ensures out@ == b64url_of(digest@),
))]
fn b64url_digest(digest: [u8; 32]) -> String {
    b64url_encode(&digest)
}

/// `base64url-no-pad(SHA-256(bytes))` — the shared thumbprint primitive.
// Proved: the composition is this project's, so it is checked rather than trusted. Only the two
// library leaves above are premises.
#[cfg_attr(feature = "verify", verus_verify)]
#[cfg_attr(feature = "verify", verus_spec(out =>
    ensures out@ == thumbprint_of(bytes@),
))]
pub(super) fn sha256_b64url(bytes: &[u8]) -> String {
    b64url_digest(sha256_digest(bytes))
}
