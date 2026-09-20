// SPDX-License-Identifier: Apache-2.0
//! The compatibility surface of the ADR-MCPRE-063 migration, in one place.
//!
//! Every module here translates between a historical vocabulary and an authority that now
//! owns the fact behind it. None of them decides anything: a facade that still made a
//! security decision would be the second implementation the migration exists to remove.
//!
//! They are grouped rather than scattered so the surface is COUNTABLE. Each one is a debt
//! with a known creditor — the callers that have not yet moved to the authority.
//!
//! | module | historical vocabulary | authority behind it | creditors |
//! |---|---|---|---|
//! | [`asserted_identity`] | `From<IdentityPolicy> for CertificateIdentityPolicy`, `From<CertificateIdentitySource> for IdentitySource` | the certificate identity authority (Slice 1) | `transport/identity.rs`'s `extract_identity`; `tls.rs`'s `authenticate_relationship_peer` call |
//!
//! **The surface is now one module holding two conversions.** That is the whole of the
//! remaining debt, and it is named rather than promised away: the module goes when its two
//! creditors stop speaking the configuration vocabulary, which is `extract_identity`'s
//! disposition to make and not this module's.

pub mod asserted_identity;
