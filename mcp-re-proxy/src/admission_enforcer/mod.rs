// SPDX-License-Identifier: Apache-2.0
//! The §7 admission gate — ADR-MCPRE-053.
//!
//! Not a serving stage: this is the deployment's admission posture and the degraded-window
//! arithmetic over it, with its own name, its own invariant, and no dependence on the
//! request being served.
//!
//! The four collaborators enter through [`AdmissionEnforcer::new`]; the fifth member is not
//! one of them, because a caller able to supply it could hand a fresh replica a degraded
//! window it never earned. The representation is private, and the window's arithmetic
//! belongs to [`degraded_window`] — so holding an enforcer means holding a gate that never
//! treated its own startup as a confirmation.

use std::sync::Arc;

use mcp_re_http_profile::authenticate_admission;
use mcp_re_http_profile::check_admission;
use mcp_re_http_profile::AdmissionPolicy;
use mcp_re_http_profile::VerifiedMcpRequest;

use crate::admission_source::AsyncAdmissionSource;
use crate::http_profile_serve::AdmissionAuthorityResolver;

/// How long a replica may serve on last-known state while the authority is unreachable.
mod degraded_window;
mod enforcement;
mod facet;
mod refusal;
mod refusal_class;
mod replica_history;
mod statement;

pub use enforcement::AdmissionEnforcement;
pub use facet::AdmissionFacet;
pub(crate) use refusal::AdmissionRefusal;
pub use refusal_class::AdmissionRefusalClass;
pub(crate) use statement::AdmissionStatement;

use degraded_window::DegradedWindow;

/// The §7 admission gate's collaborators, held together because none of them is
/// meaningful alone. The representation is private, so [`AdmissionEnforcer::new`] is the
/// only producer.
pub(crate) struct AdmissionEnforcer {
    /// The authoritative state this PEP consults per call.
    source: Arc<dyn AsyncAdmissionSource>,
    /// The N/P/TTL freshness budget and the degraded-mode opt-in (§5.2).
    policy: AdmissionPolicy,
    /// What an admission-free request means here.
    enforcement: AdmissionEnforcement,
    /// Resolves an assertion's `issuer_kid` to the admission authority's root key.
    /// A kid never introduces trust: an assertion signed by an unresolvable issuer
    /// is refused, exactly as an unknown request keyid is.
    resolve_authority: AdmissionAuthorityResolver,
    /// How long this replica may still serve on last-known state, and the clock that
    /// decides it. See [`degraded_window`].
    window: DegradedWindow,
}

impl AdmissionEnforcer {
    /// Assemble the gate from its four collaborators. The fifth field is not one of
    /// them: a caller able to supply `last_authoritative_read` could hand a fresh replica
    /// a degraded window it never earned.
    pub(crate) fn new(
        source: Arc<dyn AsyncAdmissionSource>,
        policy: AdmissionPolicy,
        enforcement: AdmissionEnforcement,
        resolve_authority: AdmissionAuthorityResolver,
    ) -> Self {
        Self {
            source,
            policy,
            enforcement,
            resolve_authority,
            window: DegradedWindow::unearned(),
        }
    }

    /// Decide §7 admission for one verified request.
    ///
    /// `Ok(())` means this deployment accepts the admission the call acts under, or that a
    /// call declaring none is acceptable here. `Err` carries the frozen wire code the
    /// refusal is served as — never a reason phrase, and never a status: what a refusal
    /// COSTS the client is a fact about the whole exchange, and the serving path's machine
    /// owns it.
    ///
    /// It takes the verified request and the verifier-resolved actor id, and nothing the
    /// request asserts about itself.
    pub(crate) async fn decide(
        &self,
        verified: &VerifiedMcpRequest,
        actor_id: &str,
        audience_id: &str,
        now: i64,
    ) -> Result<AdmissionFacet, AdmissionRefusal> {
        let block = verified.request_block();
        let (binding, assertion) = match (
            block.admission.as_ref(),
            block.admission_assertion.as_deref(),
        ) {
            (Some(b), Some(a)) => (b, a),
            // The block validator already refuses one half without the other, so
            // reaching here means BOTH are absent: the call declares no admission.
            _ => {
                if self.enforcement == AdmissionEnforcement::Required {
                    // The client presented nothing: the evidence it owed is absent, which is
                    // not the authority being unreachable.
                    return Err(AdmissionRefusal::no_evidence());
                }
                // The call declared no admission and this deployment tolerates that. NOT
                // the same fact as having been checked and passed, and the record now says
                // which one it was (R11-106).
                return Ok(AdmissionFacet::NotConfigured);
            }
        };

        // AUTHENTICATE FIRST. The assertion is verified against the configured authority,
        // equated with the VERIFIER-RESOLVED actor — the FULL signing actor, keyid
        // included, never the bare subject and never anything the request asserts — and the
        // call's binding is equated with it. An assertion issued to another workload, or
        // under another key, names a different actor and is refused, so possession alone
        // does not satisfy the gate (§16.4). Nothing below runs for a request that did not
        // pass: no store round trip is spent on, and no window refreshed by, an identity the
        // caller merely asserted.
        let resolve = Arc::clone(&self.resolve_authority);
        let authenticated = authenticate_admission(
            binding,
            assertion,
            actor_id,
            mcp_re_http_profile::PROFILE_TAG,
            &[audience_id],
            &self.policy,
            now,
            move |kid: &str| resolve(kid),
        )
        .map_err(AdmissionRefusal::authentication)?;
        let authoritative = self.lookup(authenticated.admission_id(), now).await?;
        // The PROJECTION, not the product. `CurrentAdmissionState` exists so that reaching
        // this line means the state was authenticated as the configured authority's and found
        // current; the currency check consumes the semantic fact, which is what its Verus
        // contract is stated over.
        let verdict = check_admission(
            authenticated,
            authoritative.as_ref().map(|current| current.state()),
            &self.policy,
            now,
        )
        .map_err(AdmissionRefusal::currency)?;
        self.convert(verdict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The window is a MEMBER of the gate and not a constructor parameter, so every
    /// enforcer that exists begins with an unearned one. Its arithmetic is measured in
    /// [`degraded_window`]; what belongs here is that the gate holds one it did not let a
    /// caller choose.
    #[test]
    fn a_new_enforcer_has_a_window_nobody_earned() {
        let enforcer = AdmissionEnforcer::new(
            Arc::new(crate::admission_source::InMemoryAdmissionSource::new(
                crate::admission_source::test_support::verifier_for(
                    &mcp_re_core::SigningKey::from_seed_bytes(&[3u8; 32]),
                    60,
                    5,
                ),
            )),
            AdmissionPolicy {
                max_assertion_age: 300,
                max_clock_skew: 5,
                degraded_propagation_bound: 60,
                allow_degraded_mode: true,
            },
            AdmissionEnforcement::Required,
            Arc::new(|_kid: &str| None),
        );
        assert!(
            enforcer.window.exhausted(&enforcer.policy),
            "a gate must not treat its own construction as a confirmation"
        );
    }

    /// The serving-path consequence of the store's reply split: a key a store writer gave
    /// another type is refused at the store and is never the outage that would reach the
    /// degraded fork, even on a deployment that opted into degraded mode. The Redis source
    /// exists only in the `redis_replay` build, so this selects in `proxy_ext_unit_test`.
    #[cfg(feature = "redis_replay")]
    #[tokio::test]
    async fn a_key_of_another_type_is_refused_at_the_store_and_never_degraded() {
        use crate::async_redis_store::retention_promise::scripted_server::{serve, Script};
        use mcp_re_http_profile::authoritative_admission::record::AdmissionRecordRefusal;
        let (url, _) = serve(Script {
            policy: Some("noeviction".to_string()),
            recorded: vec!["GET".to_string()],
            reply: "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n"
                .to_string(),
        })
        .await;
        let verifier = crate::admission_source::test_support::verifier_for(
            &mcp_re_core::SigningKey::from_seed_bytes(&[3u8; 32]),
            60,
            5,
        );
        let source = crate::redis_admission_source::RedisAdmissionSource::connect(&url, verifier)
            .await
            .expect("noeviction is the supported configuration");
        let enforcer = AdmissionEnforcer::new(
            Arc::new(source),
            AdmissionPolicy {
                max_assertion_age: 300,
                max_clock_skew: 5,
                degraded_propagation_bound: 60,
                allow_degraded_mode: true,
            },
            AdmissionEnforcement::Required,
            Arc::new(|_kid: &str| None),
        );
        let refusal = enforcer
            .lookup("wl", 1_030)
            .await
            .expect_err("an answered key of another type is a refusal, not the degraded route");
        assert_eq!(
            refusal.class(),
            AdmissionRefusalClass::RecordRefused(AdmissionRecordRefusal::Malformed)
        );
    }
}
