// SPDX-License-Identifier: Apache-2.0
//! What the proxy asserts under its own credential when it refuses — ADR-MCPRE-052 §4.
//!
//! A signed refusal is a security artifact: the proxy stating, under a delegated
//! credential, that it refused and what the client may still assume. Minting one from
//! inside the serving assembly meant *which refusals are signed, under which credential,
//! with which posture* was held by call ordering rather than by a type.
//!
//! [`ResponseSigning`] owns it. It holds the credential source and the configured window,
//! it opens every [`SigningWindow`] this deployment signs under — reply and refusal alike —
//! and it decides which audit event a refusal is. The assembly asks it for a receipt; it
//! does not assemble one.
//!
//! The audit sink is passed in rather than held. Emitting is a delivery capability the
//! assembly also uses for its own records; what belongs here is the choice of WHICH record
//! a refusal is, and that choice never leaves this module.

use std::sync::Arc;

use crate::audit_sink::MaybeAuditSink;
use crate::delegated_server_signer::DelegatedServerSigner;
use crate::refusal::RefusalPosture;
use mcp_re_http_profile::ExecutionDisposition;

use super::signing_window::SigningWindow;
use super::Exchange;
use super::Refusal;
use super::ServedHttpResponse;

/// How the signed artifact is built, and what the last-resort receipt states when it
/// cannot be.
mod artifact;
/// Which security record a refusal IS — the §9 taxonomy split between a request the
/// boundary never accepted and a response side fault after it did.
mod audit_event;

/// The deployment's response-signing authority.
///
/// One owner for the credential, the configured validity, and the receipt a refusal is
/// served as — so the reply path and the refusal path cannot drift apart in what they sign
/// under or how long they claim it for.
pub(crate) struct ResponseSigning {
    /// ADR-MCPRE-052 delegated-signing custody — the ONLY response-signing mode. Every
    /// response and rejection is signed by the active short-TTL delegated key + inline
    /// credential; the root is never on the request path, and this fails closed when no
    /// valid delegated key is available. There is no direct-root mode.
    signer: Arc<DelegatedServerSigner>,
    /// Response-signature validity window (seconds added to `created`), before the
    /// credential's own bound is applied.
    sig_ttl_secs: i64,
}

impl ResponseSigning {
    /// Assemble the authority from the credential source and the configured window.
    pub(crate) fn new(signer: Arc<DelegatedServerSigner>, sig_ttl_secs: i64) -> Self {
        Self {
            signer,
            sig_ttl_secs,
        }
    }

    /// Open the window this deployment may sign under at `now`, or `None` when no valid
    /// delegated credential exists — the fail-closed posture.
    pub(crate) fn window(&self, now: i64) -> Option<SigningWindow> {
        SigningWindow::open(&self.signer, now, self.sig_ttl_secs)
    }

    /// Turn a stage's decision into the signed refusal the client receives.
    ///
    /// The ONLY place in the pipeline that signs. It is also the only place that consults
    /// the exchange machine, which is the point: the retry contract is a fact about the whole
    /// exchange, so a stage could not state it correctly even if it tried. The stage says
    /// WHAT was refused; the machine says what the client may still assume.
    pub(crate) fn refuse(
        &self,
        audit: &MaybeAuditSink,
        ex: &Exchange<'_>,
        refusal: Refusal,
        execution: ExecutionDisposition,
    ) -> ServedHttpResponse {
        let (bound, actor) = match refusal.posture {
            // An unverified request has no trustworthy hash to bind to and no resolved actor
            // to attribute the denial to.
            RefusalPosture::Preflight => (None, None),
            _ => (Some(ex.verified.evidence()), Some(ex.actor_id.to_owned())),
        };
        if refusal.posture == RefusalPosture::AfterAdmission {
            return self.response_rejection(
                audit,
                ex.http_req,
                &refusal.cause,
                refusal.status,
                ex.now,
                bound,
                actor,
                execution,
                ex.key.clone(),
            );
        }
        self.rejection(
            audit,
            ex.http_req,
            &refusal.cause,
            refusal.status,
            ex.now,
            bound,
            actor,
            execution,
            ex.key.clone(),
        )
    }
}
