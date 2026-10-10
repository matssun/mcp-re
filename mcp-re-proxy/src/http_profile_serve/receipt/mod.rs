// SPDX-License-Identifier: Apache-2.0
//! What the proxy asserts under its own credential when it refuses — ADR-MCPRE-052 §4.
//!
//! A signed refusal is a security artifact: the proxy stating, under a delegated
//! credential, that it refused and what the client may still assume. Minting one from
//! inside the serving assembly meant *which refusals are signed, under which credential,
//! with which receipt* was held by call ordering rather than by a type.
//!
//! [`ResponseSigning`] owns it. It holds the credential source and the configured window,
//! it opens every [`SigningWindow`] this deployment signs under — reply and refusal alike —
//! and it decides which audit event a refusal is, from the entry it is served from. The assembly asks it for a receipt; it
//! does not assemble one.
//!
//! The audit sink is passed in rather than held. Emitting is a delivery capability the
//! assembly also uses for its own records; what belongs here is the choice of WHICH record
//! a refusal is, and that choice never leaves this module.

use std::sync::Arc;

use crate::audit_sink::MaybeAuditSink;
use crate::delegated_server_signer::DelegatedServerSigner;
use crate::delegated_server_signer::DelegatedSigningReader;
use mcp_re_http_profile::ExecutionDisposition;

use super::reply::ValidatedReply;
use super::signing_window;
use super::signing_window::SigningWindow;
use crate::exchange_state::Established;
use crate::exchange_state::ExchangeEvent;
use mcp_re_http_profile::HttpResponse;

use super::Exchange;
use super::Refusal;
use super::ServedHttpResponse;

/// How the signed artifact is built, and what the last-resort receipt states when it
/// cannot be.
mod artifact;
/// Which security record a refusal IS — the §9 taxonomy split between a request the
/// boundary never accepted and a response side fault after it did.
mod audit_event;

pub(in crate::http_profile_serve) use audit_event::Accepted;

/// Where a refusal is served from, which decides the record it becomes.
///
/// The request side is `request.rejected`, taken by EXCLUSIVE borrow, which only a region
/// still owning the exchange can give (an [`Accepted`] lends it only shared). The response
/// side is `response.rejected` and needs an [`Accepted`].
pub(in crate::http_profile_serve) enum RefusalPoint<'s, 'a> {
    Request(
        &'s mut Exchange<'a>,
        Option<Arc<mcp_re_http_profile::ActiveDelegatedKey>>,
    ),
    Response(&'s Accepted<'a>),
}

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
    ///
    /// The READ half, narrowed at construction: this authority signs under the deployment's
    /// delegated key and has no way to publish or retire one.
    signer: DelegatedSigningReader,
    /// Response-signature validity window (seconds added to `created`), before the
    /// credential's own bound is applied.
    sig_ttl_secs: i64,
}

impl ResponseSigning {
    /// Assemble the authority from the credential source and the configured window.
    pub(crate) fn new(signer: &Arc<DelegatedServerSigner>, sig_ttl_secs: i64) -> Self {
        Self {
            signer: signer.reader(),
            sig_ttl_secs,
        }
    }

    /// Open the window this deployment may sign under at `now`, or `None` when no valid
    /// delegated credential exists — the fail-closed posture.
    pub(crate) fn window(&self, now: i64) -> Option<SigningWindow> {
        signing_window::open(&self.signer, now, self.sig_ttl_secs)
    }

    /// Turn a stage's decision into the signed refusal the client receives.
    ///
    /// The ONLY place in the pipeline that signs. It is also the only place that consults
    /// the exchange machine, which is the point: the retry contract is a fact about the whole
    /// exchange, so a stage could not state it correctly even if it tried. The stage says
    /// WHAT was refused; the machine says what the client may still assume.
    /// RESPONSE-SIGNED — the enforcement boundary puts its signature on the reply.
    ///
    /// ```text
    /// ensures   Ok  => the returned response carries the delegated signature bound to THIS
    ///                  request, and the returned bytes are its signature base
    ///           Err => 500, bound
    /// refusal   NOT free
    /// ```
    ///
    /// Here rather than in the assembly because it is the same claim [`Self::refuse`]
    /// makes, about the same credential and the same window: this module's whole reason to
    /// exist is that the reply path and the refusal path cannot drift apart in what they
    /// sign under. Both take a [`SigningWindow`], and only this owner opens one.
    pub(in crate::http_profile_serve) fn sign_reply(
        &self,
        ex: &Exchange<'_>,
        reply: ValidatedReply,
        window: &SigningWindow,
    ) -> Result<(HttpResponse, Established<Vec<u8>>), Refusal> {
        let mut response = reply.into_response();
        // Scoped so the timer covers the signature and nothing after it.
        let sign_result = {
            let _t = crate::stage_timers::Timed::start(crate::stage_timers::Stage::Sign);
            mcp_re_http_profile::sign_delegated_response_full(&mut response, ex.http_req, window)
        };
        sign_result
            .map(|base| {
                (
                    response,
                    Established::new(base, ExchangeEvent::ResponseSigned),
                )
            })
            .map_err(|e| Refusal::new(e, 500))
    }

    /// Serve a stage's refusal as the receipt its entry says it is: `request.rejected`
    /// from [`RefusalPoint::Request`], `response.rejected` from [`RefusalPoint::Response`].
    pub(in crate::http_profile_serve) fn refuse(
        &self,
        audit: &MaybeAuditSink,
        at: RefusalPoint<'_, '_>,
        refusal: Refusal,
        execution: ExecutionDisposition,
    ) -> ServedHttpResponse {
        match at {
            RefusalPoint::Response(acc) => {
                let ex = acc.exchange();
                self.response_rejection(
                    audit,
                    ex.http_req,
                    &refusal.cause,
                    refusal.status,
                    ex.now,
                    Some(ex.verified.evidence()),
                    Some(ex.actor_id.to_owned()),
                    execution,
                    Some(Arc::clone(acc.key())),
                )
            }
            RefusalPoint::Request(ex, snapshot) => self.rejection(
                audit,
                ex.http_req,
                &refusal.cause,
                refusal.status,
                ex.now,
                Some(ex.verified.evidence()),
                Some(ex.actor_id.to_owned()),
                execution,
                snapshot,
                ex.verdicts.authorization(),
                ex.verdicts.admission_facet(),
                ex.verdicts.admission_refusal(),
            ),
        }
    }
}
