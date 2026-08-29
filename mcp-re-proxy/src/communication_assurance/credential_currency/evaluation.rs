// SPDX-License-Identifier: Apache-2.0
//! The per-request currency evaluation — the conjunction production already computes, with
//! the refusal it already reaches, and the reason it reached it.
//!
//! **The admitted set is unchanged.** Every request production admits, this admits, and
//! every one it refuses, this refuses. What is new is that the refusal names which of the
//! five facts failed, and that *nobody asked* is a state rather than a silent `None`.
//!
//! # Why the evaluation takes the acceptance and not the authenticated peer
//!
//! Currency is a predicate on a credential at an instant and says nothing about who the
//! peer is. Gating it on authentication would stop checking currency under
//! `PeerIdentityProvenance::IngressAssertion`, where no transport identity is derived at all and the
//! credential the mechanism accepted is still the one holding the connection open. The
//! composition that DOES need an authenticated peer derives currency from that peer's own
//! acceptance — see [`super::super::current_authenticated_peer`].

use super::x509_adapter::read_currency_facts;
use super::x509_adapter::CertificateCurrencyFacts;
use super::CredentialCurrencyOutcome;
use super::CredentialCurrencyPolicy;
use super::CredentialCurrencyRefusal;
use super::CurrencyControls;
use super::CurrentCredentialFacts;
use crate::client_revocation::ClientRevocationIndex;
use crate::client_revocation::RevocationVerdict;
use crate::communication_assurance::mechanism_verified_credential::MechanismVerifiedCredentialEvidence;

/// Is the credential the mechanism accepted for this relationship acceptable at `now`?
///
/// THE evaluation. It takes the acceptance, the deployment's policy and the instant, and
/// nothing else — no chain parameter, no certificate parameter — so the facts it reports
/// are about the credential the acceptance is about and cannot be about another.
///
/// An absent acceptance is refused as [`CredentialCurrencyRefusal::CredentialUnreadable`]
/// wherever a policy asks, exactly as production refuses an absent leaf: returning "no
/// objection" for a peer that presented nothing would waive the checks one line before an
/// unparseable certificate fails closed.
pub(crate) fn evaluate_credential_currency<'a>(
    accepted: Option<&'a MechanismVerifiedCredentialEvidence>,
    policy: &CredentialCurrencyPolicy,
    now: i64,
) -> CredentialCurrencyOutcome<'a> {
    let Some(accepted) = accepted else {
        // An absent acceptance still has to answer the policy question first: with no
        // control configured there is no decision to make, and this function is not the
        // mandatory-client-auth gate — the rustls verifier is.
        return match policy.controls() {
            None => CredentialCurrencyOutcome::NotEvaluated,
            Some(_) => {
                CredentialCurrencyOutcome::Refused(CredentialCurrencyRefusal::CredentialUnreadable)
            }
        };
    };
    match evaluate_chain_currency(&accepted.credential().credential_chain_der(), policy, now) {
        Ok(None) => CredentialCurrencyOutcome::NotEvaluated,
        Ok(Some(controls)) => CredentialCurrencyOutcome::Current(
            CurrentCredentialFacts::evaluated(accepted, now, controls),
        ),
        Err(refusal) => CredentialCurrencyOutcome::Refused(refusal),
    }
}

/// The evaluation over a credential chain, leaf first — the whole decision, and PRIVATE to
/// this authority.
///
/// `Ok(None)` is *no control configured*; `Ok(Some(controls))` is *evaluated and
/// acceptable*, naming which optional controls ran.
///
/// Not published, for the reason Slice 1 keeps its field set and selector private: a chain
/// is a representation, and a public chain entrance would let a caller evaluate the currency
/// of certificates no relationship ever presented and pair the answer with a peer. The one
/// public route is [`evaluate_credential_currency`], which projects the chain from an
/// acceptance it was handed. This is separately testable — and it has to be, because the
/// hostile inputs the decision must survive (unparseable DER, an inverted window, an absent
/// leaf) are inputs no handshake produces.
fn evaluate_chain_currency(
    chain: &[&[u8]],
    policy: &CredentialCurrencyPolicy,
    now: i64,
) -> Result<Option<CurrencyControls>, CredentialCurrencyRefusal> {
    let Some(controls) = policy.controls() else {
        return Ok(None);
    };
    match leaf_refusal(chain, policy, now)
        .or_else(|| issuer_validity_refusal(chain, now))
        .or_else(|| issuer_revocation_refusal(chain, policy.revocation(), now))
    {
        Some(refusal) => Err(refusal),
        None => Ok(Some(controls)),
    }
}

/// The leaf's three facts, in reporting order: window, then span, then revocation.
///
/// The CONJUNCTION is production's and is unchanged. Only the order in which a failure is
/// named is new, and it is fixed rather than incidental so a consumer reading a refusal
/// reads the same fact twice.
fn leaf_refusal(
    chain: &[&[u8]],
    policy: &CredentialCurrencyPolicy,
    now: i64,
) -> Option<CredentialCurrencyRefusal> {
    // NOT `?`. An absent, unparseable or never-ordered leaf must REFUSE, and `?` here would
    // return "no objection" — waiving the checks one line before an unparseable certificate
    // fails closed, which is the direction production is careful to get right.
    let Some(facts) = chain
        .first()
        .and_then(|leaf| read_currency_facts(leaf))
        .filter(CertificateCurrencyFacts::window_is_orderable)
    else {
        return Some(CredentialCurrencyRefusal::CredentialUnreadable);
    };
    if !facts.contains(now) {
        return Some(CredentialCurrencyRefusal::LeafOutsideValidityWindow {
            not_before: facts.not_before,
            not_after: facts.not_after,
        });
    }
    if let Some(ceiling) = policy.ceiling() {
        let ceiling_secs = ceiling.as_secs() as i64;
        if facts.span_secs() > ceiling_secs {
            return Some(CredentialCurrencyRefusal::LeafExceedsConfiguredLifetime {
                span_secs: facts.span_secs(),
                ceiling_secs,
            });
        }
    }
    let index = policy.revocation()?;
    // `admits` at the leaf: an index carrying no lists at all admits everything, and any
    // other index refuses BOTH `Revoked` and `Unknown`. The leaf is the certificate a
    // deployment's CRLs are expected to cover.
    if index.admits(facts.issuer_der, facts.serial, now) {
        return None;
    }
    Some(CredentialCurrencyRefusal::LeafRevocationRefused {
        verdict: index.verdict(facts.issuer_der, facts.serial, now),
    })
}

/// Every certificate ABOVE the leaf, still inside its own window.
///
/// Runs whenever any control is configured, with no revocation index needed: chain building
/// happens during client authentication, which runs on a FULL handshake only, so without
/// this a peer whose issuing intermediate has since expired keeps being admitted on every
/// reconnect that resumes.
fn issuer_validity_refusal(chain: &[&[u8]], now: i64) -> Option<CredentialCurrencyRefusal> {
    let issuers = chain.get(1..).filter(|rest| !rest.is_empty())?;
    issuers
        .iter()
        .find_map(|der| match read_currency_facts(der) {
            None => Some(CredentialCurrencyRefusal::IssuerUnreadable),
            Some(facts) if facts.self_issued || facts.contains(now) => None,
            Some(_) => Some(CredentialCurrencyRefusal::IssuerOutsideValidityWindow),
        })
}

/// Every certificate above the leaf, not EXPLICITLY revoked.
///
/// `Revoked` is the only refusal. `Unknown` admits, unlike at the leaf: whether the chain
/// reaches a CRL-covered issuer is a path-building question the handshake already settled,
/// and re-deciding it from the certificates the peer chose to send would refuse chains a
/// full handshake admitted. An index carrying no lists at all is not consulted.
fn issuer_revocation_refusal(
    chain: &[&[u8]],
    index: Option<&ClientRevocationIndex>,
    now: i64,
) -> Option<CredentialCurrencyRefusal> {
    let index = index?;
    let issuers = chain.get(1..).filter(|rest| !rest.is_empty())?;
    if index.is_empty() {
        return None;
    }
    issuers.iter().find_map(|der| {
        match read_currency_facts(der).filter(CertificateCurrencyFacts::window_is_orderable) {
            None => Some(CredentialCurrencyRefusal::IssuerUnreadable),
            Some(facts)
                if index.verdict(facts.issuer_der, facts.serial, now)
                    == RevocationVerdict::Revoked =>
            {
                Some(CredentialCurrencyRefusal::IssuerRevoked)
            }
            Some(_) => None,
        }
    })
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    //! The claims migrated from `tls::lifetime_tests` (MCPS-078 audit gap G-5, C095),
    //! restated against the authority that now owns them.
    //!
    //! Every one of them survives, and each is now STRONGER: production answered
    //! `Some(error bytes)` for all seven failure modes, so a control could only assert
    //! *something refused*. These assert WHICH fact refused, so a weakening that swapped one
    //! refusal for another — an expired credential reported as over-long, an unreadable one
    //! reported as revoked — goes red instead of staying green.
    //!
    //! Hostile inputs are minted rather than handshaked, deliberately: an inverted validity
    //! window, a zero-length one and unparseable DER are inputs no mechanism produces, and
    //! they are exactly the ones the fail-closed direction has to survive.

    use super::*;

    use std::sync::Arc;
    use std::time::Duration;

    use rcgen::CertificateParams;
    use rcgen::ExtendedKeyUsagePurpose;
    use rcgen::KeyPair;

    use crate::client_revocation::ClientRevocationIndex;

    /// 2020-01-01T01:00:00Z — inside the `mint((2020,1,1), (2020,1,2))` window.
    const IN_2020: i64 = 1_577_836_800 + 3600;

    fn hour() -> CredentialCurrencyPolicy {
        CredentialCurrencyPolicy::Ceiling(Duration::from_secs(3600))
    }

    fn two_days() -> CredentialCurrencyPolicy {
        CredentialCurrencyPolicy::Ceiling(Duration::from_secs(48 * 3600))
    }

    /// A self-signed leaf with an explicit validity window, day granularity. Self-signed is
    /// sufficient: this authority reads validity, serial and issuer, never a signature.
    fn mint(not_before: (i32, u8, u8), not_after: (i32, u8, u8)) -> Vec<u8> {
        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
        params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
        params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = params.self_signed(&key).expect("leaf self-signed");
        cert.der().as_ref().to_vec()
    }

    fn evaluate(
        chain: &[&[u8]],
        policy: &CredentialCurrencyPolicy,
        now: i64,
    ) -> Result<Option<CurrencyControls>, CredentialCurrencyRefusal> {
        evaluate_chain_currency(chain, policy, now)
    }

    #[test]
    fn a_deployment_that_configures_nothing_evaluates_nothing() {
        // The finding this whole authority exists to make visible. NOT `Ok(Some(..))`:
        // "no control configured" is not a verdict about the credential, and reporting it
        // as one would say "checked, and fine" about a credential nobody looked at.
        let short = mint((2020, 1, 1), (2020, 1, 2));
        assert_eq!(
            evaluate(&[&short], &CredentialCurrencyPolicy::NotEvaluated, IN_2020),
            Ok(None)
        );
        // Including for a credential that is long expired — the point exactly.
        assert_eq!(
            evaluate(
                &[&short],
                &CredentialCurrencyPolicy::NotEvaluated,
                IN_2020 + 315_360_000
            ),
            Ok(None),
            "with no control configured an expired credential is UNEXAMINED, not current"
        );
    }

    #[test]
    fn the_public_entrance_reports_an_unexamined_credential_as_unexamined() {
        // Through `evaluate_credential_currency` — the entrance the serving path takes —
        // with a REAL accepted credential and a deployment that configured nothing. The
        // outcome must be `NotEvaluated` and not `Current`: nothing about the admitted set
        // distinguishes them, so only a control that reads the STATE catches a collapse.
        use crate::communication_assurance::channel_associated_credential::mechanism_harness::{
            handshake, mutually_authenticated_peers,
        };
        use crate::communication_assurance::mechanism_verified_credential::rustls_adapter::verified_credential;

        let peers = mutually_authenticated_peers();
        let accepted =
            verified_credential(&handshake(&peers.client, &peers.server)).expect("accepts");
        assert_eq!(
            evaluate_credential_currency(
                Some(&accepted),
                &CredentialCurrencyPolicy::NotEvaluated,
                NOW_FAR_FUTURE
            ),
            CredentialCurrencyOutcome::NotEvaluated,
            "a credential nobody examined is unexamined, not current"
        );
    }

    /// Past every harness certificate's `notAfter` (rcgen defaults run to the year 4096),
    /// so the credential above is long expired — and STILL unexamined, which is the point.
    const NOW_FAR_FUTURE: i64 = 100_000_000_000;

    #[test]
    fn an_absent_leaf_is_refused_wherever_a_control_is_configured() {
        // C095: the ceiling is a check ON the peer certificate, so "there is no peer
        // certificate to check" must not be an admission. This is the case that once
        // short-circuited to admit, one line before an unparseable certificate failed closed.
        assert_eq!(
            evaluate(&[], &hour(), 0),
            Err(CredentialCurrencyRefusal::CredentialUnreadable)
        );
    }

    #[test]
    fn an_absent_leaf_is_evaluated_by_nobody_when_no_control_is_configured() {
        // The converse, so the rule above cannot be read as "always refuse a missing leaf":
        // this authority is not the mandatory-client-auth gate, the rustls verifier is.
        assert_eq!(
            evaluate(&[], &CredentialCurrencyPolicy::NotEvaluated, 0),
            Ok(None)
        );
    }

    #[test]
    fn unparseable_der_is_refused_as_unreadable_and_not_as_something_else() {
        let garbage: &[u8] = b"this is definitely not a DER X.509 certificate";
        assert_eq!(
            evaluate(&[garbage], &hour(), IN_2020),
            Err(CredentialCurrencyRefusal::CredentialUnreadable)
        );
    }

    #[test]
    fn an_inverted_or_degenerate_window_is_unreadable_not_an_admissible_span() {
        // MCPS-078 G-5. An inverted window once yielded a NEGATIVE span, and a zero-length
        // one a span of 0 — both of which are "within ANY ceiling". A certificate that
        // never had a window is not one whose window is generous.
        let inverted = mint((2021, 1, 1), (2020, 1, 1));
        let degenerate = mint((2021, 1, 1), (2021, 1, 1));
        for der in [&inverted, &degenerate] {
            assert_eq!(
                evaluate(&[der], &hour(), IN_2020),
                Err(CredentialCurrencyRefusal::CredentialUnreadable),
                "a window that is not orderable fails closed"
            );
        }
    }

    #[test]
    fn an_over_long_span_is_refused_as_a_lifetime_breach_naming_both_numbers() {
        let long = mint((2020, 1, 1), (2021, 1, 1));
        let Err(CredentialCurrencyRefusal::LeafExceedsConfiguredLifetime {
            span_secs,
            ceiling_secs,
        }) = evaluate(&[&long], &hour(), IN_2020)
        else {
            panic!("a 1-year credential must be refused under a 1-hour ceiling");
        };
        assert_eq!(ceiling_secs, 3600);
        assert!(span_secs > ceiling_secs);
    }

    #[test]
    fn a_span_within_the_ceiling_is_current_and_names_the_control_that_ran() {
        let short = mint((2020, 1, 1), (2020, 1, 2));
        assert_eq!(
            evaluate(&[&short], &two_days(), IN_2020),
            Ok(Some(CurrencyControls::Lifetime))
        );
    }

    #[test]
    fn expiry_is_a_different_refusal_from_an_over_long_span() {
        // The span check alone admits this forever: a 1-day credential satisfies a 2-day
        // ceiling in 2020 and equally in 2030. On a keep-alive or HTTP/2 connection the
        // credential is accepted once at handshake, so this per-request clock comparison is
        // the only thing that ever notices the expiry — and reporting it as a LIFETIME
        // breach would send an operator to change a ceiling that is not the problem.
        let short = mint((2020, 1, 1), (2020, 1, 2));
        assert_eq!(
            evaluate(&[&short], &two_days(), IN_2020),
            Ok(Some(CurrencyControls::Lifetime)),
            "inside its window the credential is current"
        );
        for (now, when) in [
            (IN_2020 + 86_400, "after notAfter"),
            (IN_2020 - 86_400, "before notBefore"),
        ] {
            let outcome = evaluate(&[&short], &two_days(), now);
            assert!(
                matches!(
                    outcome,
                    Err(CredentialCurrencyRefusal::LeafOutsideValidityWindow { .. })
                ),
                "{when}: expected a validity-window refusal, got {outcome:?}"
            );
        }
    }

    #[test]
    fn the_validity_window_runs_in_a_revocation_only_deployment() {
        // Fusing the window check to `max_client_cert_lifetime` once made a CRL-only
        // deployment stop re-checking expiry at all. The window is not an optional control.
        let short = mint((2020, 1, 1), (2020, 1, 2));
        let policy = CredentialCurrencyPolicy::Revocation(Arc::new(ClientRevocationIndex::empty()));
        assert_eq!(
            evaluate(&[&short], &policy, IN_2020),
            Ok(Some(CurrencyControls::Revocation))
        );
        assert!(
            matches!(
                evaluate(&[&short], &policy, IN_2020 + 86_400),
                Err(CredentialCurrencyRefusal::LeafOutsideValidityWindow { .. })
            ),
            "a CRL-only deployment must still notice expiry"
        );
    }

    #[test]
    fn a_self_issued_certificate_in_the_chain_is_exempt_from_the_window() {
        // A peer may send its root. Path building matches that against the CONFIGURED anchor
        // set rather than against its own window, so holding it to one here would refuse
        // chains a full handshake admits. `mint` is self-signed, hence self-issued.
        let leaf = mint((2020, 1, 1), (2020, 1, 2));
        let expired_root = mint((2019, 1, 1), (2019, 6, 1));
        assert_eq!(
            evaluate(&[&leaf, &expired_root], &two_days(), IN_2020),
            Ok(Some(CurrencyControls::Lifetime)),
            "a self-issued certificate is exempt, so this chain is admitted"
        );
    }

    #[test]
    fn an_unreadable_issuer_is_refused_as_an_issuer_and_not_as_the_credential() {
        // Both fail closed, and they are different incidents: one says the peer's own
        // credential is unusable, the other that something it presented above the leaf is.
        let leaf = mint((2020, 1, 1), (2020, 1, 2));
        let garbage: &[u8] = b"not a certificate";
        assert_eq!(
            evaluate(&[&leaf, garbage], &two_days(), IN_2020),
            Err(CredentialCurrencyRefusal::IssuerUnreadable)
        );
    }
}

#[cfg(test)]
mod chain_validity_tests {
    //! ADR-MCPRE-055: a resumed TLS 1.3 handshake restores the stored peer chain and
    //! skips chain building, so the per-request gate is the only place an INTERMEDIATE's
    //! expiry is ever re-read. The trust epoch cannot cover it — the epoch digests the
    //! configured anchor set, and an intermediate is not in it.

    use super::*;

    use std::time::Duration;

    use rcgen::BasicConstraints;
    use rcgen::CertificateParams;
    use rcgen::DnType;
    use rcgen::IsCa;
    use rcgen::KeyPair;
    use rcgen::KeyUsagePurpose;
    use rustls_pki_types::CertificateDer;

    struct Signer {
        params: CertificateParams,
        key: KeyPair,
        der: CertificateDer<'static>,
    }

    impl Signer {
        fn issuer(&self) -> rcgen::Issuer<'_, &KeyPair> {
            rcgen::Issuer::from_params(&self.params, &self.key)
        }
    }

    fn root(name: &str) -> Signer {
        let key = KeyPair::generate().expect("root key");
        let mut params = CertificateParams::new(Vec::new()).expect("root params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name.push(DnType::CommonName, name);
        let der = params.self_signed(&key).expect("root").der().clone();
        Signer { params, key, der }
    }

    /// A CA signed by `issuer` with an explicit validity window, so its expiry is a
    /// deterministic input rather than a wall-clock accident.
    fn intermediate(issuer: &Signer, name: &str, not_after: (i32, u8, u8)) -> Signer {
        let key = KeyPair::generate().expect("intermediate key");
        let mut params = CertificateParams::new(Vec::new()).expect("intermediate params");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name.push(DnType::CommonName, name);
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
        let der = params
            .signed_by(&key, &issuer.issuer())
            .expect("intermediate")
            .der()
            .clone();
        Signer { params, key, der }
    }

    fn leaf(issuer: &Signer) -> CertificateDer<'static> {
        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
        params.distinguished_name.push(DnType::CommonName, "peer");
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2999, 1, 1);
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        params
            .signed_by(&key, &issuer.issuer())
            .expect("leaf")
            .der()
            .clone()
    }

    /// The evaluation runs whenever any control is configured; a ceiling wide enough to
    /// admit the leaf isolates the chain decision.
    fn policy() -> CredentialCurrencyPolicy {
        CredentialCurrencyPolicy::Ceiling(Duration::from_secs(365 * 24 * 3600 * 1000))
    }

    const NOW: i64 = 1_800_000_000; // 2027-01-15

    fn rejected(chain: &[&[u8]]) -> bool {
        evaluate_chain_currency(chain, &policy(), NOW).is_err()
    }

    /// The refusal this chain produces, or `None` if it was admitted.
    ///
    /// Production answered `Some(error bytes)` for every one of these, so a control could
    /// only assert THAT something refused. Naming the fact is what stops a weakening from
    /// swapping one refusal for another and staying green.
    fn refusal(chain: &[&[u8]]) -> Option<CredentialCurrencyRefusal> {
        evaluate_chain_currency(chain, &policy(), NOW).err()
    }

    /// A leaf under a still-valid intermediate is served.
    #[test]
    fn a_chain_whose_intermediate_is_current_is_admitted() {
        let root = root("chain-root");
        let ica = intermediate(&root, "chain-ica", (2999, 1, 1));
        let peer = leaf(&ica);
        assert!(!rejected(&[peer.as_ref(), ica.der.as_ref()]));
    }

    /// A leaf under an EXPIRED intermediate is refused, even though the leaf itself is
    /// current, un-revoked and within the lifetime ceiling.
    ///
    /// The broken implementation this catches: applying `within_window` to `chain[0]`
    /// only. With resumption enabled the peer never re-runs chain building, so every
    /// reconnect restores the same expired chain and keeps being admitted.
    #[test]
    fn a_chain_whose_intermediate_has_expired_is_refused() {
        let root = root("chain-root");
        let ica = intermediate(&root, "chain-ica", (2021, 1, 1));
        let peer = leaf(&ica);
        assert_eq!(
            refusal(&[peer.as_ref(), ica.der.as_ref()]),
            Some(CredentialCurrencyRefusal::IssuerOutsideValidityWindow),
            "an expired issuing intermediate must stop the leaf being served, and must not \
             be reported as a problem with the leaf"
        );
    }

    /// A peer that redundantly sends its (self-issued) root is NOT refused on that
    /// root's window. Path building matches a root against the configured anchor set
    /// rather than against its own validity, so refusing it here would refuse chains a
    /// full handshake admits.
    #[test]
    fn a_self_issued_root_in_the_presented_chain_is_not_held_to_a_window() {
        let root = root("chain-root");
        let ica = intermediate(&root, "chain-ica", (2999, 1, 1));
        let peer = leaf(&ica);
        assert!(!rejected(&[
            peer.as_ref(),
            ica.der.as_ref(),
            root.der.as_ref()
        ]));
    }

    /// An unparseable certificate above the leaf fails closed, matching the leaf.
    #[test]
    fn an_unparseable_intermediate_is_refused() {
        let root = root("chain-root");
        let ica = intermediate(&root, "chain-ica", (2999, 1, 1));
        let peer = leaf(&ica);
        assert_eq!(
            refusal(&[peer.as_ref(), b"not der".as_ref()]),
            Some(CredentialCurrencyRefusal::IssuerUnreadable),
            "an unreadable issuer is a different incident from an unreadable credential"
        );
    }
}

#[cfg(test)]
mod per_request_revocation_tests {
    //! The per-request CRL consultation in [`evaluate_chain_currency`] is the
    //! ONLY way a revocation reaches a peer that already holds a connection: rustls runs
    //! client authentication on a full handshake only, and the trust epoch deliberately
    //! digests the anchor set and the client-auth policy — not the CRLs — so a revocation
    //! published after the handshake moves nothing the epoch can see.
    //!
    //! The certificates here are real and signed, and the CRLs are real and signed, so
    //! the (issuer `Name` DER, serial) coordinate the index is keyed by is the one the
    //! serving path actually extracts rather than a synthetic pair.

    use super::*;

    use std::sync::Arc;

    use rcgen::BasicConstraints;
    use rcgen::CertificateParams;
    use rcgen::CertificateRevocationListParams;
    use rcgen::DnType;
    use rcgen::IsCa;
    use rcgen::KeyPair;
    use rcgen::KeyUsagePurpose;
    use rcgen::RevocationReason;
    use rcgen::RevokedCertParams;
    use rcgen::SerialNumber;
    use rustls_pki_types::CertificateDer;

    use crate::client_revocation::ClientRevocationIndex;

    /// 2027-01-15 — inside every window minted below, and before the CRLs' `nextUpdate`.
    const NOW: i64 = 1_800_000_000;
    const LEAF_SERIAL: u64 = 0x2a;
    const ICA_SERIAL: u64 = 0x2b;

    struct Ca {
        params: CertificateParams,
        key: KeyPair,
        der: CertificateDer<'static>,
    }

    impl Ca {
        fn issuer(&self) -> rcgen::Issuer<'_, &KeyPair> {
            rcgen::Issuer::from_params(&self.params, &self.key)
        }
    }

    fn ca_params(name: &str, constraints: BasicConstraints) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::new()).expect("ca params");
        params.is_ca = IsCa::Ca(constraints);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name.push(DnType::CommonName, name);
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);
        params
    }

    fn root(name: &str) -> Ca {
        let key = KeyPair::generate().expect("root key");
        let params = ca_params(name, BasicConstraints::Unconstrained);
        let der = params.self_signed(&key).expect("root").der().clone();
        Ca { params, key, der }
    }

    /// A CA signed by `issuer` carrying an explicit serial, so `issuer`'s CRL can name
    /// exactly this intermediate.
    fn intermediate(issuer: &Ca, name: &str, serial: u64) -> Ca {
        let key = KeyPair::generate().expect("intermediate key");
        let mut params = ca_params(name, BasicConstraints::Constrained(0));
        params.serial_number = Some(SerialNumber::from(serial));
        let der = params
            .signed_by(&key, &issuer.issuer())
            .expect("intermediate")
            .der()
            .clone();
        Ca { params, key, der }
    }

    /// A client leaf with an explicit serial, so a CRL can revoke exactly this
    /// certificate.
    fn leaf(issuer: &Ca, serial: u64) -> CertificateDer<'static> {
        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
        params.distinguished_name.push(DnType::CommonName, "peer");
        params.serial_number = Some(SerialNumber::from(serial));
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        params
            .signed_by(&key, &issuer.issuer())
            .expect("leaf")
            .der()
            .clone()
    }

    /// A signed CRL from `ca` revoking each serial in `revoked`. An empty list is the
    /// "issuer covered, nothing revoked" state a deployment runs in most of the time.
    fn crl(ca: &Ca, revoked: &[u64], next_update: (i32, u8, u8)) -> Vec<u8> {
        let params = CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2020, 1, 1),
            next_update: rcgen::date_time_ymd(next_update.0, next_update.1, next_update.2),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: revoked
                .iter()
                .map(|serial| RevokedCertParams {
                    serial_number: SerialNumber::from(*serial),
                    revocation_time: rcgen::date_time_ymd(2021, 1, 1),
                    reason_code: Some(RevocationReason::KeyCompromise),
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        params.signed_by(&ca.issuer()).expect("crl").der().to_vec()
    }

    /// The index in force for the request under test — the snapshot the serving path
    /// takes once per request, not the atomic cell it was loaded from.
    fn shared(crls: &[Vec<u8>]) -> Arc<ClientRevocationIndex> {
        Arc::new(ClientRevocationIndex::from_crl_ders(crls).expect("index builds"))
    }

    /// No lifetime ceiling: revocation ALONE must arm the per-request evaluation, and
    /// nothing else here can account for a refusal.
    fn options(revocation: &Arc<ClientRevocationIndex>) -> CredentialCurrencyPolicy {
        CredentialCurrencyPolicy::Revocation(Arc::clone(revocation))
    }

    fn rejected(chain: &[&[u8]], policy: &CredentialCurrencyPolicy) -> bool {
        evaluate_chain_currency(chain, policy, NOW).is_err()
    }

    /// A leaf whose issuer is covered by a CRL that does not list it keeps being served.
    ///
    /// This is the control every refusal below is read against, and it is also what
    /// catches the (issuer, serial) coordinate being passed in the wrong order: the
    /// swapped call finds no CRL for the "issuer" it was handed, answers `Unknown`, and
    /// refuses this request under the deny-unknown policy.
    #[test]
    fn a_leaf_a_current_crl_does_not_list_is_served() {
        let ca = root("revocation-ca");
        let peer = leaf(&ca, LEAF_SERIAL);
        let revocation = shared(&[crl(&ca, &[], (2035, 1, 1))]);
        assert!(!rejected(&[peer.as_ref()], &options(&revocation)));
    }

    /// A leaf listed on a CRL in force is refused on every request, with no lifetime
    /// ceiling configured at all.
    ///
    /// The broken implementation this catches: dropping the `not_revoked` conjunct, or
    /// arming the gate on `max_client_cert_lifetime` alone — either leaves a revoked peer
    /// serving on the connection it already holds for as long as it holds it.
    #[test]
    fn a_leaf_on_a_current_crl_is_refused() {
        let ca = root("revocation-ca");
        let peer = leaf(&ca, LEAF_SERIAL);
        let revocation = shared(&[crl(&ca, &[LEAF_SERIAL], (2035, 1, 1))]);
        assert!(
            rejected(&[peer.as_ref()], &options(&revocation)),
            "a revoked leaf must stop being served"
        );
    }

    /// The evaluation honours the index it is HANDED, so a reloaded CRL reaches a request
    /// on a connection whose handshake is long past.
    ///
    /// The claim split when this authority took the policy as a value. The half that lives
    /// here is that two indexes give two answers for one chain — an authority that cached a
    /// verdict, or read some other index, would answer the same twice. The other half is
    /// that the serving path re-snapshots per request, and it moved with the code that does
    /// it: `tls::currency_policy_reads_the_index_in_force_at_the_time_of_the_call`.
    #[test]
    fn a_reloaded_crl_refuses_a_leaf_that_was_served_a_moment_earlier() {
        let ca = root("revocation-ca");
        let peer = leaf(&ca, LEAF_SERIAL);

        let before = options(&shared(&[crl(&ca, &[], (2035, 1, 1))]));
        assert!(!rejected(&[peer.as_ref()], &before));

        let after = options(&shared(&[crl(&ca, &[LEAF_SERIAL], (2035, 1, 1))]));
        assert!(
            rejected(&[peer.as_ref()], &after),
            "the reloaded CRL must reach the connection already being served"
        );
    }

    /// A leaf whose issuer no configured CRL covers is `Unknown`, and deny-unknown is the
    /// handshake's posture, so it is refused.
    #[test]
    fn a_leaf_whose_issuer_no_crl_covers_is_refused() {
        let ca = root("revocation-ca");
        let other = root("unrelated-ca");
        let peer = leaf(&ca, LEAF_SERIAL);
        let revocation = shared(&[crl(&other, &[], (2035, 1, 1))]);
        assert!(rejected(&[peer.as_ref()], &options(&revocation)));
    }

    /// A CRL past its `nextUpdate` can no longer answer `Good`, so its issuer's
    /// certificates become `Unknown` and are refused — the same direction as rustls'
    /// `enforce_revocation_expiration`.
    #[test]
    fn a_leaf_under_a_crl_that_has_fallen_out_of_force_is_refused() {
        let ca = root("revocation-ca");
        let peer = leaf(&ca, LEAF_SERIAL);
        let revocation = shared(&[crl(&ca, &[], (2021, 1, 1))]);
        assert!(rejected(&[peer.as_ref()], &options(&revocation)));
    }

    /// A chain whose intermediate is covered and unlisted is served — the control for
    /// the refusal below.
    #[test]
    fn a_chain_whose_intermediate_is_on_no_crl_is_served() {
        let ca = root("revocation-root");
        let ica = intermediate(&ca, "revocation-ica", ICA_SERIAL);
        let peer = leaf(&ica, LEAF_SERIAL);
        let revocation = shared(&[crl(&ca, &[], (2035, 1, 1)), crl(&ica, &[], (2035, 1, 1))]);
        assert!(!rejected(
            &[peer.as_ref(), ica.der.as_ref()],
            &options(&revocation)
        ));
    }

    /// Revoking the ISSUING INTERMEDIATE stops the leaf being served, even though the
    /// leaf's own serial is on no CRL.
    ///
    /// The broken implementation this catches: asking the index about `chain[0]` only.
    /// The handshake verifier checks revocation to the trust anchor, so a per-request
    /// check that stopped at the leaf would keep honouring a revoked intermediate on
    /// every connection the peer already holds.
    #[test]
    fn a_chain_under_a_revoked_intermediate_is_refused() {
        let ca = root("revocation-root");
        let ica = intermediate(&ca, "revocation-ica", ICA_SERIAL);
        let peer = leaf(&ica, LEAF_SERIAL);
        let revocation = shared(&[
            crl(&ca, &[ICA_SERIAL], (2035, 1, 1)),
            crl(&ica, &[], (2035, 1, 1)),
        ]);
        assert!(
            rejected(&[peer.as_ref(), ica.der.as_ref()], &options(&revocation)),
            "a revoked issuing intermediate must stop the leaf being served"
        );
    }

    /// An intermediate is refused only on an EXPLICIT `Revoked` verdict. Whether the
    /// presented chain reaches a CRL-covered issuer is a path-building question the
    /// handshake settled, so an `Unknown` intermediate must not be re-decided here.
    #[test]
    fn an_intermediate_no_crl_covers_does_not_refuse_the_chain() {
        let ca = root("revocation-root");
        let ica = intermediate(&ca, "revocation-ica", ICA_SERIAL);
        let peer = leaf(&ica, LEAF_SERIAL);
        let revocation = shared(&[crl(&ica, &[], (2035, 1, 1))]);
        assert!(!rejected(
            &[peer.as_ref(), ica.der.as_ref()],
            &options(&revocation)
        ));
    }
}
