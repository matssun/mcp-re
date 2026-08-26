// SPDX-License-Identifier: Apache-2.0
//! Building this deployment's authorization mechanism — ADR-MCPRE-065 §8.
//!
//! The composition root asks for an evaluator and gets back either one to install or a
//! posture line saying nothing is installed. What it never gets is an evaluator it has to
//! assemble itself: the trust material, the audiences and the decision profile are read
//! here, together, so no caller can pair one deployment's authority set with another's
//! accepted scope.
//!
//! # What the ON line has to admit
//!
//! Authorization authorities are read ONCE, at startup. `--trust` has a reload path and
//! this does not use it, so removing an authority from the file takes effect at the next
//! restart and not before. That is a real revocation window, so the startup line states it
//! rather than leaving an operator to infer the trust-store cadence applies here too.

use std::sync::Arc;

use crate::config_state::{AuthorizationState, TrustDocumentSource};
use crate::serving_capabilities::Established;

use super::evaluator::AuthorizationEvaluator;
use super::pdp::{PdpDecisionEvaluator, PdpDecisionPolicy};

/// The OFF line: what a deployment that installs nothing actually does.
const AUTHORIZATION_OFF: &str = "authorization = OFF: no authorization authority is \
     installed, so every request is served at the 'no policy configured' posture — which \
     claims nothing and is not an allow. This deployment answers WHO SIGNED THIS and WHICH \
     CHANNEL IT ARRIVED ON, never MAY-ACT; authorization must be enforced upstream. Install \
     one with --authz pdp-decision.";

/// Build the evaluator this deployment installs, if it installs one.
///
/// `Err` refuses startup. The one refusal is a configured profile with no authority to
/// decide under: such a deployment would answer every call with an authorization refusal
/// while its startup transcript announced enforcement, so it fails closed at boot where an
/// operator can still read why.
pub(crate) fn evaluator(
    state: &AuthorizationState,
    trust: &TrustDocumentSource,
    response_kid: &str,
    audience_id: &str,
    max_clock_skew: i64,
) -> Result<Established<Arc<dyn AuthorizationEvaluator>>, String> {
    let Some(enforced) = state.enforced() else {
        return Ok(Established::off(AUTHORIZATION_OFF));
    };
    let bytes = std::fs::read(trust.path()).map_err(|e| format!("{}: {e}", trust.path()))?;
    let issuers = crate::trust_document::load_authorization_issuers(&bytes, response_kid)?;
    if issuers.is_empty() {
        return Err(format!(
            "--authz pdp-decision installs the carried-PDP-decision authority, but {} enrols \
             no key for the `authorization-issuer` slot, so no decision could ever be \
             authenticated and every call would be refused. Add the authority's key with \
             \"slots\":[\"authorization-issuer\"], or run --authz off.",
            trust.path()
        ));
    }
    let line = format!(
        "authorization = PDP-DECISION enforced ({} trusted authority key(s) from {}, \
         accepted scope {}, decisions accepted up to {}s old). A request carrying no \
         applicable decision is REFUSED. Authority keys are read ONCE at startup: a --trust \
         reload does not refresh them, so withdrawing an authority needs a restart.",
        issuers.len(),
        trust.path(),
        scope_name(enforced.accepted_scope()),
        enforced.max_decision_age_secs(),
    );
    let policy = PdpDecisionPolicy {
        resolve_authority: Arc::new(move |kid: &str| issuers.get(kid).cloned()),
        accepted_scope: enforced.accepted_scope(),
        freshness: mcp_re_http_profile::pdp_decision::PdpDecisionFreshness {
            // The verifier-local skew tolerance is a clock-agreement parameter, not a
            // policy identity, so the deployment's one `--max-clock-skew` governs here as
            // it does the RFC 9421 freshness gate. Reusing it keeps a deployment from
            // agreeing with a peer's clock on the request and disagreeing on the decision.
            max_clock_skew,
            // Saturating rather than fallible: layer A narrowed the bound to a positive
            // `i64` before it became a `NonZeroU64`, so the conversion back cannot fail.
            max_decision_age: i64::try_from(enforced.max_decision_age_secs().get())
                .unwrap_or(i64::MAX),
        },
    };
    let evaluator = PdpDecisionEvaluator::new(
        policy,
        mcp_re_http_profile::PROFILE_TAG,
        vec![audience_id.to_owned()],
        Arc::new(crate::clock::now_unix),
    );
    Ok(Established::on(
        Arc::new(evaluator) as Arc<dyn AuthorizationEvaluator>,
        line,
    ))
}

/// The operator-facing spelling of an accepted scope.
fn scope_name(scope: mcp_re_http_profile::pdp_decision::DecisionScope) -> &'static str {
    match scope {
        mcp_re_http_profile::pdp_decision::DecisionScope::Principal => "principal",
        mcp_re_http_profile::pdp_decision::DecisionScope::Credential => "credential",
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::evaluator;
    use crate::config_state::TrustDocumentSource;
    use crate::deployment_request::{AuthzKind, DeploymentRequest};
    use crate::startup_posture::SeamState;
    use mcp_re_core::SigningKey;
    use mcp_re_http_profile::pdp_decision::DecisionScope;

    /// A trust file written for one test, removed when it ends.
    struct TrustFile(std::path::PathBuf);

    impl TrustFile {
        fn holding(body: &str, name: &str) -> Self {
            // The counter is not decoration: these run concurrently in one process, and a
            // path keyed only by the pid would let one test's `Drop` delete the file
            // another is reading.
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "mcp-re-authz-capability-{name}-{}-{}.json",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::write(&path, body).expect("write fixture");
            TrustFile(path)
        }

        fn source(&self) -> TrustDocumentSource {
            TrustDocumentSource::new(self.0.display().to_string()).expect("a named locator")
        }
    }

    impl Drop for TrustFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn state(config: &DeploymentRequest) -> crate::config_state::AuthorizationState {
        crate::config_state::authorization::classify_and_validate(config)
            .0
            .expect("a recognised state")
    }

    fn pdp_config() -> DeploymentRequest {
        let mut config = crate::config_state::test_support::legal_config();
        config.authorization.kind = AuthzKind::PdpDecision;
        config.authorization.decision_scope = Some(DecisionScope::Principal);
        config.authorization.max_decision_age_secs = Some(600);
        config
    }

    fn authority_entry() -> String {
        format!(
            r#"[{{"signer":"did:example:pdp","key_id":"pdp-1","public_key":"{}",
                  "slots":["authorization-issuer"]}}]"#,
            SigningKey::from_seed_bytes(&[7u8; 32])
                .public_key()
                .to_b64url()
        )
    }

    #[test]
    fn a_deployment_installing_nothing_says_so_without_reading_any_trust_material() {
        let file = TrustFile::holding("[]", "off");
        let established = evaluator(
            &state(&crate::config_state::test_support::legal_config()),
            &file.source(),
            "response-kid",
            "verifier-1",
            30,
        )
        .expect("off never refuses");
        let (artifact, posture) = established.into_parts();
        assert!(artifact.is_none(), "off installs no evaluator");
        let SeamState::Off(line) = posture else {
            panic!("a deployment installing nothing must declare an OFF posture")
        };
        assert!(
            line.contains("not an allow"),
            "the OFF line must not read as permission: {line}"
        );
    }

    #[test]
    fn a_configured_profile_installs_an_evaluator_over_the_enrolled_authorities() {
        let file = TrustFile::holding(&authority_entry(), "on");
        let (artifact, posture) = evaluator(
            &state(&pdp_config()),
            &file.source(),
            "response-kid",
            "verifier-1",
            30,
        )
        .expect("a complete profile installs")
        .into_parts();
        assert!(
            artifact.is_some(),
            "a configured profile installs an evaluator"
        );
        let SeamState::On(line) = posture else {
            panic!("an installed authority must declare an ON posture")
        };
        assert!(
            line.contains("REFUSED"),
            "the ON line must state strictness: {line}"
        );
        assert!(
            line.contains("read ONCE at startup"),
            "the ON line must admit its refresh window: {line}"
        );
    }

    #[test]
    fn a_configured_profile_with_no_enrolled_authority_refuses_startup() {
        // Serving would refuse every call while the transcript announced enforcement.
        let file = TrustFile::holding("[]", "empty");
        let Err(err) = evaluator(
            &state(&pdp_config()),
            &file.source(),
            "response-kid",
            "verifier-1",
            30,
        ) else {
            panic!("an authority-less profile must fail closed at boot")
        };
        assert!(err.contains("authorization-issuer"), "{err}");
    }

    #[test]
    fn a_request_signer_key_does_not_become_an_authorization_authority() {
        let file = TrustFile::holding(
            &format!(
                r#"[{{"signer":"did:example:agent-1","key_id":"key-1","public_key":"{}"}}]"#,
                SigningKey::from_seed_bytes(&[8u8; 32])
                    .public_key()
                    .to_b64url()
            ),
            "signers-only",
        );
        assert!(
            evaluator(
                &state(&pdp_config()),
                &file.source(),
                "response-kid",
                "verifier-1",
                30,
            )
            .is_err(),
            "a request-slot key must not answer as an authorization authority"
        );
    }

    // --- What the installed authority actually does -----------------------------------
    //
    // The controls above prove a deployment can SELECT the mechanism. These prove the
    // thing it selected enforces: the same three outcomes ADR-MCPRE-065 §7.1 names, driven
    // through an evaluator this module built from configuration and trust material rather
    // than through one a test assembled.

    use crate::authorization::decide::authorize;
    use mcp_re_http_profile::pdp_decision::{
        issue_authorization_decision, DecidedActor, PdpDecisionClaims, PdpDecisionOutcome,
    };
    use mcp_re_http_profile::{ArtifactBinding, ArtifactType, Audience, VerifiedMcpRequest};

    const CALL: &[u8] =
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#;

    fn pdp_key() -> mcp_re_core::SigningKey {
        mcp_re_core::SigningKey::from_seed_bytes(&[7u8; 32])
    }

    /// A decision about the harness actor, at the deployment's accepted scope.
    fn decision(outcome: PdpDecisionOutcome, target: &str) -> String {
        let claims = PdpDecisionClaims {
            iss: "did:example:pdp".into(),
            issuer_kid: "pdp-1".into(),
            iat: crate::clock::now_unix(),
            nbf: crate::clock::now_unix() - 5,
            exp: crate::clock::now_unix() + 300,
            jti: "decision-1".into(),
            aud: Audience::One("verifier-1".into()),
            mcp_re_profile: mcp_re_http_profile::PROFILE_TAG.into(),
            mcp_re_decided_actor: DecidedActor::Principal {
                trust_domain: "example.org".into(),
                subject: "did:example:agent-1".into(),
            },
            mcp_re_decided_operation: "tools/call".into(),
            mcp_re_decided_target: Some(target.into()),
            mcp_re_decision: outcome,
            mcp_re_policy_version: "2026-08-01".into(),
        };
        let key = pdp_key();
        issue_authorization_decision(&claims, |input| {
            mcp_re_core::b64url_decode(&key.sign(input))
                .map_err(|_| mcp_re_http_profile::HttpProfileError::InvalidSignature)
        })
        .expect("the fixture authority issues")
    }

    /// A verified request carrying `decision`, bound to it in the evidence form.
    fn request_carrying(decision: Option<&str>) -> VerifiedMcpRequest {
        let mut verified = crate::authorization::action_harness::verified_over(CALL);
        if let Some(d) = decision {
            verified
                .request_block
                .artifact_bindings
                .push(ArtifactBinding::opaque_digest(
                    ArtifactType::PdpDecision,
                    d.as_bytes(),
                ));
            verified.request_block.authorization_decision = Some(d.to_owned());
        }
        verified
    }

    /// The evaluator a `--authz pdp-decision` deployment installs, over the fixture
    /// authority's key.
    fn installed() -> std::sync::Arc<dyn super::AuthorizationEvaluator> {
        let file = TrustFile::holding(
            &format!(
                r#"[{{"signer":"did:example:pdp","key_id":"pdp-1","public_key":"{}",
                      "slots":["authorization-issuer"]}}]"#,
                pdp_key().public_key().to_b64url()
            ),
            "enforcing",
        );
        let (artifact, _) = evaluator(
            &state(&pdp_config()),
            &file.source(),
            "response-kid",
            "verifier-1",
            30,
        )
        .expect("a complete profile installs")
        .into_parts();
        artifact.expect("a configured profile installs an evaluator")
    }

    #[test]
    fn a_configured_deployment_permits_a_correctly_bound_permit() {
        let d = decision(PdpDecisionOutcome::Permit, "read");
        let verified = request_carrying(Some(&d));
        let posture = authorize(Some(installed().as_ref()), &verified, CALL, None)
            .expect("a permit decision authorizes");
        let facts = posture
            .authorized()
            .expect("a permit is an authorization, not an unconfigured posture");
        assert_eq!(facts.audit_attribution().authority, "did:example:pdp");
    }

    #[test]
    fn a_configured_deployment_refuses_a_deny() {
        let d = decision(PdpDecisionOutcome::Deny, "read");
        let verified = request_carrying(Some(&d));
        assert!(
            authorize(Some(installed().as_ref()), &verified, CALL, None).is_err(),
            "a signed deny is a refusal, never a fall-through to the unconfigured posture"
        );
    }

    #[test]
    fn a_configured_deployment_refuses_a_request_carrying_no_decision() {
        // ADR-MCPRE-065 §7.1: a deployment that configured an authority has left the
        // not-configured posture. There is no permissive reading of a missing decision.
        let verified = request_carrying(None);
        assert!(
            authorize(Some(installed().as_ref()), &verified, CALL, None).is_err(),
            "an undecorated request must not pass an installed authority"
        );
    }

    #[test]
    fn a_decision_for_another_action_does_not_authorize_this_one() {
        let d = decision(PdpDecisionOutcome::Permit, "delete");
        let verified = request_carrying(Some(&d));
        assert!(
            authorize(Some(installed().as_ref()), &verified, CALL, None).is_err(),
            "the action coordinate comes from the signed body, not from the decision"
        );
    }
}
