// SPDX-License-Identifier: Apache-2.0
//! What a `--trust` document BECOMES.
//!
//! One fact, and it is a correspondence rather than a lifecycle: **two products come out of
//! one read, so they can never disagree.** The resolver that answers `resolve` and the
//! `kid -> signer` map the actor seam reads as an identity coordinate are built together
//! from the same bytes; built separately they could describe different trust pictures while
//! both looking current.
//!
//! Separate from [`reload`](super::reload), which owns *how often the read happens and when
//! to stop trusting a stale one*. This module is called by both the first read at
//! materialization and every re-read after it, and it must give the same answer to both.
//!
//! `response_kid` is excluded from the request-signer map here rather than at either caller:
//! the deployment's own issuer key must never be presentable as a client credential, and a
//! rule enforced at the read is one neither caller can forget.

use std::collections::HashMap;

/// Read `--trust` and build the snapshot the revocation tiers resolve against.
///
/// Two things come out of one read so they can never disagree: the
/// [`InMemoryTrustResolver`](mcp_re_core::InMemoryTrustResolver) that answers
/// `resolve`, and the `kid -> signer` map the actor seam uses as the identity
/// coordinate. `response_kid` is excluded from the request-signer map: the
/// deployment's own issuer key must never be presentable as a client credential.
pub(in crate::trust_plane) fn load_trust_snapshot(
    trust_path: &str,
    response_kid: &str,
) -> Result<crate::reloading_trust::ReloadingTrustStore, String> {
    let (resolver, signers) = read_trust_file(trust_path, response_kid)?;
    Ok(crate::reloading_trust::ReloadingTrustStore::new(
        resolver, signers,
    ))
}
/// The file read shared by startup and every reload.
pub(super) fn read_trust_file(
    trust_path: &str,
    response_kid: &str,
) -> Result<(mcp_re_core::InMemoryTrustResolver, HashMap<String, String>), String> {
    let bytes = std::fs::read(trust_path).map_err(|e| format!("{trust_path}: {e}"))?;
    let resolver = crate::trust_document::load_trust(&bytes)?;
    // Slot-scoped: only entries this file enrols for the REQUEST slot become client
    // request signers. A key carried here for another purpose is not one.
    let signers = crate::trust_document::load_trust_request_signers(&bytes, response_kid)?;
    Ok((resolver, signers))
}
