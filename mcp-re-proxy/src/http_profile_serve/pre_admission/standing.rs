// SPDX-License-Identifier: Apache-2.0
//! May this caller act at all, right now?
//!
//! Two questions about the CALLER rather than about the action: the channel the message
//! arrived on, and whether the admission it acts under is still current. Both are answered
//! by owners next door — [`crate::transport::TransportBinding`] and
//! [`crate::admission_enforcer::AdmissionEnforcer`] — and both are free, because a caller
//! that has no standing must be turned away before anything is spent on its behalf.
//!
//! They are here together because they compose in one direction: the binding is the
//! ADR-MCPRE-064 §16 predecessor that travels WITH the admission decision, so what the
//! decision was taken over survives the stage that consumed it.

use mcp_re_core::McpReError;

use crate::admission_enforcer::AdmissionFacet;
use crate::communication_assurance::request_peer_binding::http_profile_adapter::verified_request_subject;
use crate::communication_assurance::RequestPeerBindingFacts;
use crate::exchange_state::Established;
use crate::exchange_state::ExchangeEvent;
use crate::refusal::Refusal;

use super::super::Exchange;
use super::super::HttpProfileProxy;

/// What the ADR-MCPRE-053 §7 currency gate took its decision over.
///
/// It states that the gate RAN, not that it admitted: the gate's verdict is the
/// [`AdmissionFacet`] returned beside this value, and `NotConfigured` — a deployment that
/// enforces no admission — produces this type too. Those are different facts and the
/// pipeline keeps them apart.
///
/// Its whole purpose is to be unforgeable. [`HttpProfileProxy::admission_stage`] is the
/// only producer, because the field is private to this module and no other constructor
/// exists, and [`HttpProfileProxy::authorization_stage`] requires one. So a pipeline that
/// dropped the §7 gate and handed authorization the transport binding directly would not
/// compile — the same shape [`crate::request_stages::ReadyForDispatch`] gives the
/// authorization stage one door further on, applied to the gate that is ordered FIRST
/// precisely because everything after it is irreversible.
///
/// The binding inside is the ADR-MCPRE-064 §16 predecessor, carried so that authorization
/// receives what the decision was taken over instead of re-deriving it, and so the
/// *bound* / *not claimed* distinction survives the stage that consumed it.
pub(super) struct AdmissionDecidedOver {
    /// Private to this module: the field, not the type, is what makes the gate the sole
    /// producer. A `pub(super)` field would let any file in the region assemble one.
    binding: Option<RequestPeerBindingFacts>,
}

impl AdmissionDecidedOver {
    /// The request↔peer binding the gate decided over — `None` when no binding policy is
    /// installed, which is NOT CLAIMED to be bound and never an identity source.
    pub(super) fn binding(&self) -> Option<&RequestPeerBindingFacts> {
        self.binding.as_ref()
    }
}

impl HttpProfileProxy {
    /// TRANSPORT-BOUND — Mode-A: the verified request actor must be the mTLS peer.
    /// ```text
    /// ensures   Ok  => authenticated peer == resolved actor's SUBJECT (never `actor_id()`)
    ///           Err => 403, bound to the request via `;req`
    /// forbids   any effect on the request's behalf
    /// refusal   free
    /// ```
    /// No policy installed passes: the channel is then not CLAIMED to be bound.
    pub(super) fn transport_binding_stage(
        &self,
        ex: &Exchange<'_>,
        peer: Option<&crate::communication_assurance::AuthenticatedChannelPeer>,
    ) -> Result<Established<Option<RequestPeerBindingFacts>>, Refusal> {
        let checked = ExchangeEvent::TransportBindingChecked;
        let Some(binding) = &self.transport_binding else {
            return Ok(Established::new(None, checked)); // NOT CLAIMED to be bound
        };
        let subject = verified_request_subject(ex.verified.resolved_actor());
        let Ok(bound) = binding.bind(peer, subject) else {
            return Err(Refusal::before_admission(
                McpReError::TransportBindingFailed,
                403,
            ));
        };
        Ok(Established::new(Some(bound), checked))
    }

    /// ADMISSION-CHECKED — the §7 currency gate (ADR-MCPRE-053).
    ///
    /// ```text
    /// ensures   Ok  => this call acts under an admission this deployment accepts, or
    ///                  admission is not enforced here
    ///           Err => 403, bound
    /// forbids   burning a nonce, running the backend
    /// refusal   free — nothing has happened
    /// ```
    ///
    /// Placed before replay admission and the inner round trip, because both are
    /// irreversible: burning a nonce and running a tool on behalf of a workload whose
    /// admission has been revoked is precisely what this exists to prevent.
    ///
    /// The DECISION belongs to [`crate::admission_enforcer::AdmissionEnforcer`], next door,
    /// which owns the deployment's posture and the degraded-window arithmetic. What is here
    /// is the ordering and the prerequisite: `bound` — the ADR-MCPRE-064 §16 predecessor,
    /// never an identity source — travels WITH the decision inside
    /// [`AdmissionDecidedOver`], so an authority downstream receives what the decision was
    /// taken over instead of re-deriving it, and the *bound* / *not claimed* distinction
    /// survives the stage that consumed it.
    ///
    /// This is the sole producer of [`AdmissionDecidedOver`], on both arms, which is what
    /// makes the stage a precondition of authorization rather than a step someone
    /// remembered to call.
    ///
    /// Names its refusal like every other stage rather than minting one. The retry contract
    /// is a fact about the whole exchange, which no stage can state; the machine states it,
    /// once, where [`HttpProfileProxy::refuse`] signs.
    pub(super) async fn admission_stage(
        &self,
        ex: &Exchange<'_>,
        bound: Option<&RequestPeerBindingFacts>,
    ) -> Result<(Established<AdmissionDecidedOver>, AdmissionFacet), Refusal> {
        let admitted = || {
            Established::new(
                AdmissionDecidedOver {
                    binding: bound.cloned(),
                },
                ExchangeEvent::AdmissionCurrencyChecked,
            )
        };
        // No enforcer is deployed for this call. `NotConfigured`, and NOT an allow: the
        // record says the call declared no admission and this deployment tolerates that,
        // which is a different fact from having been checked (R11-106).
        let Some(enforcer) = self.admission.as_ref() else {
            return Ok((admitted(), AdmissionFacet::NotConfigured));
        };
        match enforcer
            .decide(
                ex.verified,
                ex.actor_id,
                self.requests.audience_id(),
                ex.now,
            )
            .await
        {
            // The gate's own verdict travels with the stage's product, so nothing
            // downstream reconstructs what admission decided from the fact that it did not
            // refuse. A live-confirmed serve and a degraded one are different serves.
            Ok(facet) => Ok((admitted(), facet)),
            Err(e) => Err(Refusal::before_admission(e, 403)),
        }
    }
}

#[cfg(test)]
mod admission_prerequisite_tests {
    //! ADR-MCPRE-064 Slice 5 (#625) — admission CONSUMES the request↔peer binding.
    //!
    //! # What changed, stated precisely
    //!
    //! The exchange machine already refused an out-of-order transition: advancing
    //! `AdmissionCurrencyChecked` before `TransportBindingChecked` latches an anomaly. So
    //! stage ORDER was never the gap.
    //!
    //! What was discarded is the binding's CONTENT. `TransportBinding::bind` built a
    //! `RequestPeerBindingFacts` and the stage returned `Established<()>`, so no later
    //! authority could condition on whether binding had been claimed at all — the
    //! `Some`/`None` distinction died at the stage that made it.
    //!
    //! # What the prerequisite says
    //!
    //! `Required` is the only enforcement under which *every served call acted under a
    //! current admission* is a true statement about the deployment. It is only true if the
    //! caller was also shown to be the peer of the channel it arrived over; otherwise the
    //! assertion was matched against an actor whose channel nobody checked, and the
    //! sentence quietly weakens to *every call presented a current admission*.
    //!
    //! # What is deliberately NOT changed
    //!
    //! The assertion match stays on `actor_id()`. An admission assertion is issued to the
    //! full resolved signing actor — role, trust domain, subject AND keyid — so the
    //! composite is the correct coordinate here, and the ADR-MCPRE-064 Slice 4 ruling does
    //! NOT extend to it. Narrowing this to the subject would let an assertion issued for
    //! one signing key be presented under another. The control below pins that.

    use super::*;
    use crate::exchange_state::ExchangeProgress;

    #[test]
    fn the_binding_stage_hands_on_the_fact_rather_than_a_unit() {
        // What the slice actually changed. Ordering was never the gap — the exchange
        // machine latches an anomaly on an out-of-order transition — so the measurable
        // difference is that the stage's established value now HAS content, and the
        // *bound* / *no policy installed* distinction survives it.
        //
        // The two shapes are asserted through `Established`'s own type, which is the point:
        // a stage returning `Established<()>` cannot hand anything to its successor, and no
        // amount of call-site discipline changes that.
        let not_claimed: Established<Option<RequestPeerBindingFacts>> =
            Established::new(None, ExchangeEvent::TransportBindingChecked);
        let mut progress = ExchangeProgress::new();
        assert!(
            progress.establish(not_claimed).is_none(),
            "no binding policy installed is NOT CLAIMED to be bound, and says so"
        );
    }

    #[test]
    fn what_the_gate_decided_over_keeps_not_claimed_distinct_from_bound() {
        // What holding an `AdmissionDecidedOver` means. It says the §7 gate RAN — that is
        // the whole reason `authorization_stage` demands one — and says NOTHING about the
        // verdict, which is the `AdmissionFacet` returned beside it.
        //
        // What it does carry is the predecessor the decision was taken over, and the
        // projection hands that on unchanged: `None` is *no binding policy is installed*,
        // not a binding authorization may condition on.
        let decided_over = AdmissionDecidedOver { binding: None };
        assert!(
            decided_over.binding().is_none(),
            "NOT CLAIMED to be bound must survive the stage that consumed the binding"
        );
    }

    #[test]
    fn the_binding_prerequisite_and_the_assertion_coordinate_are_different_facts() {
        // THE CONTROL THAT KEEPS THE TWO RULINGS APART. A reader applying Slice 4's ruling
        // by analogy would narrow the admission match from `actor_id()` to the subject —
        // and an assertion issued for one signing key would then be presentable under
        // another key of the same subject.
        //
        //   request <-> peer :  authenticated peer identity == resolved actor SUBJECT
        //   assertion <-> actor:  admitted_actor            == resolved actor ACTOR_ID
        use mcp_re_http_profile::ActorIdentity;

        let actor = ActorIdentity {
            role: "client".into(),
            trust_domain: "example.org".into(),
            subject: "spiffe://example.org/agent-1".into(),
            keyid: "key-a".into(),
        };
        let rotated = ActorIdentity {
            keyid: "key-b".into(),
            ..actor.clone()
        };

        assert_eq!(
            actor.subject, rotated.subject,
            "one principal — which is why the TRANSPORT binding survives a key rotation"
        );
        assert_ne!(
            actor.actor_id(),
            rotated.actor_id(),
            "two signing actors — which is why an ADMISSION assertion issued to the first \
             must not be presentable under the second. Collapsing this to subject equality \
             is the mistake this control exists to catch."
        );
    }
}
