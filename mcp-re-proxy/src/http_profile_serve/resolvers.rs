// SPDX-License-Identifier: Apache-2.0
//! The two TRUST SEAMS a deployment supplies, and why they are two.
//!
//! Both answer "is this keyid one we trust?", and they are deliberately not one seam.
//! Admitting a workload and signing a message are different authorities, so a key trusted
//! for one must not become usable for the other by sharing a resolver. Keeping them apart
//! is the whole content of this module, and it is why they live beside each other rather
//! than beside the stage that calls each.

use std::sync::Arc;

use mcp_re_core::VerificationKey;
use mcp_re_http_profile::ResolverOutcome;
use mcp_re_http_profile::SignerSlot;

/// The trust seam: resolve a presented keyid FOR a signing slot to a structured
/// actor (identity + verification key). A key not trusted for `slot` resolves to
/// `None` (fail closed). `Send + Sync` so one `HttpProfileProxy` serves every core.
/// The proxy's trust seam. Returns a [`ResolverOutcome`] rather than an `Option` so a
/// store OUTAGE is distinguishable from an UNKNOWN KEYID (C079): both fail closed, but
/// only one of them is a statement about the caller's key.
pub type ActorResolver = Box<dyn Fn(&str, SignerSlot) -> ResolverOutcome + Send + Sync>;

/// Resolves an admission assertion's `issuer_kid` to the admission authority's root
/// key. `None` means the issuer is not one this deployment trusts to admit anything —
/// a kid never introduces trust, so an assertion naming an unresolvable issuer is
/// refused exactly as an unknown request keyid is.
///
/// Separate from [`ActorResolver`] because admitting a workload and signing a message
/// are different authorities: a key trusted for one must not be usable for the other
/// by sharing a seam.
pub type AdmissionAuthorityResolver = Arc<dyn Fn(&str) -> Option<VerificationKey> + Send + Sync>;
