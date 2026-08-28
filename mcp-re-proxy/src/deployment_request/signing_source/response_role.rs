// SPDX-License-Identifier: Apache-2.0
//! The response/evidence-signing key role.

use super::SigningSourceRequest;

/// Which key signs this deployment's responses.
///
/// A named role rather than a bare [`SigningSourceRequest`] field, because response
/// signing and channel establishment are different propositions over potentially
/// different credentials (ADR-MCPRE-067 §10). A deployment may choose the same mechanism
/// for both; that the two keys happen to live in the same KMS is provider context, and not
/// evidence that they are the same key, have the same role, or may share an authorization
/// policy.
///
/// This is the key the verify-before-return guardrail is measured against, and the one a
/// delegation credential chains to.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResponseSigningRequest {
    /// The mechanism asked to hold it.
    pub source: SigningSourceRequest,
}
