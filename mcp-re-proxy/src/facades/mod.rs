// SPDX-License-Identifier: Apache-2.0
//! The compatibility surface of the ADR-MCPRE-063 migration, in one place.
//!
//! Every module here translates between a historical vocabulary and an authority that now
//! owns the fact behind it. None of them decides anything: a facade that still made a
//! security decision would be the second implementation the migration exists to remove.
//!
//! They are grouped rather than scattered so the surface is COUNTABLE. Each one is a debt
//! with a known creditor — the callers that have not yet moved to the authority — and when
//! the last of those callers moves, the file is deleted whole rather than untangled.
//!
//! | module | historical vocabulary | authority behind it |
//! |---|---|---|
//! | [`asserted_identity`] | `validate_asserted_identity_value`, `AssertedIdentityRejection`, `MAX_ASSERTED_IDENTITY_LEN`, `IdentityPolicy`/`IdentitySource` | the peer-identity value and certificate identity authorities (Slice 1) |
//! | [`delegated_key_correspondence`] | `TlsError::DelegatedKeyMismatch`'s single message | credential/key correspondence (Slice 2) |

pub mod asserted_identity;
pub mod delegated_key_correspondence;
