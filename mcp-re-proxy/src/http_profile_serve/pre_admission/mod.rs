// SPDX-License-Identifier: Apache-2.0
//! The stages a request passes before this deployment will spend anything on it, and the
//! two facts that outlive them.
//!
//! Everything here refuses for free: no nonce is burned, no approval is spent, no backend
//! is reached. That is the property the region exists to hold, and it is why the ordering
//! is here rather than distributed over the call sites — a stage moved out of this region
//! stops being free and nothing local would say so.
//!
//! The stages themselves are not the decisions. Each one asks an owner
//! ([`crate::authorization::AuthorizationStage`], [`crate::admission_enforcer`],
//! [`crate::transport::TransportBinding`]) and names the refusal a failure becomes; what a
//! refusal COSTS the client is the request machine's, stated once where
//! [`HttpProfileProxy::refuse`] signs.

use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::OutstandingId;
use mcp_re_http_profile::VerifiedMcpRequest;

use crate::async_serve::ServedHttpResponse;
use crate::authorization::AuthorizationPosture;
use crate::exchange_state::ExchangeProgress;

use super::Exchange;
use super::HttpProfileProxy;

/// May this caller act at all, right now — the channel it arrived on, and the currency of
/// its admission.
mod standing;

/// May this ACTION be performed — the ADR-MCPRE-065 decision over the signed body.
mod action;

/// What survives pre-admission: the terminal the reply must take, and this deployment's
/// authorization posture.
///
/// Exactly two, because exactly two are read later. The binding and what admission decided
/// over do not appear: they are prerequisites the stages below consumed, and reconstructing
/// them downstream is how a decision gets taken twice.
pub(super) struct AdmittedRequest {
    /// Which terminal the exchange has — a bodied reply, or the bodyless 202 a
    /// notification gets. Decided from the REQUEST, where the fact lives.
    pub(super) outstanding: OutstandingId,
    /// The ADR-MCPRE-065 posture. Held rather than re-asked because the dispatch consumes
    /// it: the body [`crate::request_stages::ReadyForDispatch`] carries has exactly one
    /// producer, and it is this value.
    pub(super) authorized: AuthorizationPosture,
}

impl HttpProfileProxy {
    /// VERIFIED — the RFC 9421 signature over the inbound message.
    ///
    /// ```text
    /// ensures   Ok  => the message is signed by a key this deployment trusts for the
    ///                  request slot, and is addressed to this audience
    ///           Err => the configured status, signed but NOT bound to an exchange
    /// forbids   any effect on the request's behalf
    /// refusal   free
    /// ```
    ///
    /// Its refusal is minted here rather than through [`HttpProfileProxy::refuse`]: there
    /// is no [`Exchange`] yet, because nothing about the request is trusted.
    pub(super) fn verify_stage(
        &self,
        http_req: &HttpRequest,
        now: i64,
        progress: &mut ExchangeProgress,
    ) -> Result<VerifiedMcpRequest, ServedHttpResponse> {
        match self.requests.verify(http_req, now) {
            Ok(verified) => Ok(progress.establish(verified)),
            Err(refusal) => Err(self.responses.rejection(
                &self.audit,
                http_req,
                &refusal.cause,
                refusal.status,
                now,
                None,
                None,
                Self::disposition(progress),
                None,
            )),
        }
    }

    /// The pre-admission region, run in the one order that keeps every refusal in it free.
    ///
    /// The prerequisite chain is CARRIED rather than re-derived: the binding reaches
    /// admission, and what admission decided over reaches authorization. Authorization
    /// receives the ADR-MCPRE-064 product whole; it never reopens it.
    pub(super) async fn admit_request(
        &self,
        ex: &Exchange<'_>,
        peer: Option<&crate::communication_assurance::AuthenticatedChannelPeer>,
        progress: &mut ExchangeProgress,
    ) -> Result<AdmittedRequest, ServedHttpResponse> {
        // What this request IS, decided once and carried: a legal JSON-RPC 2.0 request, and
        // the outstanding id that selects its terminal.
        let outstanding = self
            .requests
            .validate_envelope(ex.http_req)
            .map_err(|refusal| self.refuse(ex, refusal, progress))?;
        let bound = self
            .transport_binding_stage(ex, peer)
            .map(|established| progress.establish(established))
            .map_err(|refusal| self.refuse(ex, refusal, progress))?;
        let decided_over = self
            .admission_stage(ex, bound.as_ref())
            .await
            .map(|established| progress.establish(established))
            .map_err(|refusal| self.refuse(ex, refusal, progress))?;
        let authorized = self
            .authorization_stage(ex, decided_over.as_ref())
            .map_err(|refusal| self.refuse(ex, refusal, progress))?;
        Ok(AdmittedRequest {
            outstanding,
            authorized,
        })
    }

    /// ADR-MCPS-035: the request is now ADMITTED.
    ///
    /// Emitted here rather than at signature verification so `accepted` and `rejected` are
    /// MUTUALLY EXCLUSIVE per request: a signature-valid request that then loses replay
    /// admission is a rejection, and a record claiming both would make the surface useless
    /// for attribution.
    ///
    /// Every exit AFTER this records `mcp-re.response.rejected` instead — the request was
    /// admitted, so a `request.rejected` record would contradict this one, and the fault is
    /// on the response side anyway.
    pub(super) fn record_request_accepted(
        &self,
        admitted: &AdmittedRequest,
        actor_id: &str,
        now: i64,
    ) {
        crate::audit_record::record_to(
            &self.audit,
            crate::audit_record::AuditSubject::request(
                mcp_re_core::audit::AuditEvent::request_accepted(),
                // The live product, asked for its own projection. Nothing here reconstructs
                // an authorization fact, and an unconfigured deployment says so rather than
                // reading as an allow (ADR-MCPRE-066 §1.1, invariant 5).
                admitted.authorized.audit_facet(),
            ),
            Some(actor_id.to_owned()),
            200,
            now,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::audit::AuthorizationFacet;

    /// The carrier keeps the two postures apart. A region product that flattened them would
    /// let the accepted record say *a policy permitted this* on a deployment where none is
    /// deployed — the one thing ADR-MCPRE-066 §1.1 invariant 5 forbids.
    #[test]
    fn the_carrier_does_not_flatten_the_authorization_posture() {
        let unconfigured = AdmittedRequest {
            outstanding: OutstandingId::Notification,
            authorized: AuthorizationPosture::NoPolicyConfigured,
        };
        assert!(matches!(
            unconfigured.authorized.audit_facet(),
            AuthorizationFacet::NotConfigured
        ));
    }

    /// The terminal is a fact about the REQUEST, and the carrier is what holds it across
    /// the dispatch — no reply can make a notification bodied or stop it being one.
    #[test]
    fn the_carrier_holds_the_terminal_selected_by_the_request() {
        let notification = AdmittedRequest {
            outstanding: OutstandingId::Notification,
            authorized: AuthorizationPosture::NoPolicyConfigured,
        };
        assert!(matches!(
            notification.outstanding,
            OutstandingId::Notification
        ));
    }
}
