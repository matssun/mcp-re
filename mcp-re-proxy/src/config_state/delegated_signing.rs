// SPDX-License-Identifier: Apache-2.0
//! The `DelegatedSigning` semantic owner — unit `proxy.delegated_signing_configuration_state`.
//!
//! **A guard-only owner: no modes, and still facts of its own.** Delegated response
//! signing is unconditional — ADR-MCPRE-052 is the only response-signing mode, so there is
//! no state to choose and no enum to classify into. What this owner has instead is one
//! required value, two guards, and two defaulting rules:
//!
//! | Field | Kind | Rule |
//! |---|---|---|
//! | `delegated_trust_epoch` | required | the §7 hard gate; no default; no `#`, `<= MAX_DELEGATED_TRUST_EPOCH_BASE_LEN` |
//! | `delegated_ttl_secs` | guard | `0 < ttl <= MAX_DELEGATED_TTL_SECS` |
//! | `delegated_overlap_secs` | guard | `0 < overlap < ttl` |
//! | `delegated_issuer_kid` | derived | defaults to `server_key_id` |
//! | `delegated_audience_hash` | derived | defaults to `audience` |
//!
//! **The resolved values live here because the rule does.** [`DelegatedSigningFacts`]
//! resolves both defaults once, and nothing after this point can see that a default was
//! ever involved.
//!
//! **The two guards have two owners, and only one of them is here.** The CEILING
//! `ttl <= MAX_DELEGATED_TTL_SECS` is a deployment policy number and is this owner's. The
//! RELATION `0 < overlap < ttl` is not: it holds between two fields of
//! `mcp_re_http_profile::custody::DelegatedKeyWindow`, and only that struct can hold a relation
//! between its own fields. This owner produces one and never restates it.

use mcp_re_http_profile::custody::{DelegatedKeyWindow, TrustEpoch, TrustEpochRefusal};

use crate::config_state::coordinate;
use crate::config_state::coordinate::CoordinateFault;
use crate::deployment_request::{DelegatedSigningRequest, DeploymentRequest};

/// The delegated-key TTL `T` an operator did not state, in seconds.
///
/// It lives beside the guard that bounds it rather than in the parser that applies it: the
/// owner deciding `0 < ttl <= MAX_DELEGATED_TTL_SECS` is the one that should say which
/// value an omitted `--delegated-ttl-secs` means, or a later change to the ceiling could
/// leave a default outside it with nothing to notice.
pub const DEFAULT_DELEGATED_TTL_SECS: i64 = 300;

/// The rotation-overlap window `O` an operator did not state, in seconds.
///
/// Paired with [`DEFAULT_DELEGATED_TTL_SECS`] by this owner's `0 < overlap < ttl` guard,
/// which the two defaults must satisfy together — a pairing that is invisible where they
/// are applied and obvious here.
pub const DEFAULT_DELEGATED_OVERLAP_SECS: i64 = 60;

const _: () = {
    assert!(DEFAULT_DELEGATED_TTL_SECS > 0 && DEFAULT_DELEGATED_TTL_SECS <= MAX_DELEGATED_TTL_SECS);
    assert!(DEFAULT_DELEGATED_OVERLAP_SECS > 0);
    assert!(DEFAULT_DELEGATED_OVERLAP_SECS < DEFAULT_DELEGATED_TTL_SECS);
};

/// What layer A established about delegated response signing.
///
/// Built only where the required value is present, so holding one is evidence that the
/// §7 epoch gate was satisfied and that both defaulting rules have already been applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedSigningFacts {
    trust_epoch: TrustEpoch,
    issuer_kid: String,
    audience_hash: String,
    rotation: DelegatedKeyWindow,
}

impl DelegatedSigningFacts {
    /// The base label delegated credentials are minted under: the whole label without a
    /// shared counter, else the signing plane extends it to `<base>#<counter>`, which an
    /// operator `INCR` moves and which is not this owner's to promise.
    pub fn trust_epoch(&self) -> &TrustEpoch {
        &self.trust_epoch
    }

    /// Which key issues delegated response-signing credentials.
    ///
    /// The invariant that makes it safe belongs to signing, and two consumers take opposite
    /// halves of it: this kid answers the Response slot, and it is never enrolled as a
    /// REQUEST signer. They read one resolved value rather than each resolving the fallback,
    /// so they cannot disagree about which key that is.
    pub fn issuer_kid(&self) -> &str {
        &self.issuer_kid
    }

    /// The validated rotation window — the pair, never the halves, all the way to the
    /// custody config minted from it.
    ///
    /// It IS `mcp-re-http-profile`'s sealed value, not a local wrapper around one. A
    /// wrapper here would carry no invariant of its own — the relation is the profile
    /// type's and the ceiling is applied during validation, not held by a type — so it
    /// would be a second name for one fact and one more place for a consumer to unpack.
    pub fn rotation_window(&self) -> DelegatedKeyWindow {
        self.rotation
    }

    /// The audience the delegated credential is scoped to.
    ///
    /// Overridable so a deployment can scope the delegated key to something other than the
    /// response audience, where its verifiers expect that.
    pub fn audience_hash(&self) -> &str {
        &self.audience_hash
    }
}

/// Check this owner's guards and resolve its facts.
///
/// `None` means the request names no legal delegated-signing posture at all: the epoch has
/// no default, so there is nothing to resolve and the refusal beside it says why. The two
/// range guards do not gate construction — they are defects in a posture that is otherwise
/// fully determined, and reporting them together with everything else is the point of
/// collecting violations rather than returning at the first.
pub fn classify_and_validate(
    config: &DeploymentRequest,
) -> (Option<DelegatedSigningFacts>, Vec<String>) {
    let mut violations = Vec::new();
    let requested = &config.delegated_signing;
    let epoch = requested.trust_epoch.clone();
    if epoch.is_none() {
        violations.push(
            "delegated-required response signing requires a trust epoch \
             (--delegated-trust-epoch): it is the base label every delegated credential is \
             minted under and it has no default, so without it no credential names the \
             deployment whose keys a verifier is deciding about. The base alone is NOT the \
             cross-fleet kill switch: the comparable <base>#<counter> label, and with it the \
             operator's trust-epoch advance that moves every replica to the next label, \
             exist only where a shared counter is configured (--trust-epoch-redis-url). With \
             the base alone the label never advances and a credential's exp is the only \
             thing that ends it"
                .to_string(),
        );
    }
    // The range guards are reported whether or not an epoch was named, so an operator meets
    // every defect in one run; they also gate construction.
    let range = ttl_violations(requested);
    let window_is_valid = range.is_empty();
    violations.extend(range);
    let Some(trust_epoch) = epoch else {
        return (None, violations);
    };
    // Construction IS the gate: `ttl_violations` reported every defect for the operator,
    // and this is the one value that may go on.
    let Ok(window) = DelegatedKeyWindow::of(requested.ttl_secs, requested.overlap_secs) else {
        return (None, violations);
    };
    if !window_is_valid {
        return (None, violations);
    }
    let issuer_kid = (requested.issuer_kid.clone()).unwrap_or_else(|| config.server_key_id.clone());
    let audience_hash =
        (requested.audience_hash.clone()).unwrap_or_else(|| config.audience.clone());
    // Each fact is checked AFTER resolution, so an empty flag and an empty defaulting source
    // are one question (CF-10): every fact is minted verbatim into every delegation
    // credential, where an empty issuer names no issuer and an empty epoch no deployment.
    let fact_defects =
        empty_fact_violations([&trust_epoch, &issuer_kid, &audience_hash].map(String::as_str));
    let epoch = TrustEpoch::fixed(trust_epoch);
    if !fact_defects.is_empty() || epoch.is_err() {
        violations.extend(fact_defects);
        violations.extend(epoch.err().and_then(epoch_base_violation));
        return (None, violations);
    }
    let facts = epoch.map(|trust_epoch| DelegatedSigningFacts {
        trust_epoch,
        rotation: window,
        issuer_kid,
        audience_hash,
    });
    (facts.ok(), violations)
}

/// A base holding `#` renders a `<base>#<counter>` two pairs share (`a#1` at 2 is `a#1#2`).
/// An empty base is [`empty_fact_violations`]'s to report.
fn epoch_base_violation(refusal: TrustEpochRefusal) -> Option<String> {
    (refusal != TrustEpochRefusal::Empty).then(|| {
        format!(
            "--delegated-trust-epoch must not contain '#' and is at most \
             {MAX_DELEGATED_TRUST_EPOCH_BASE_LEN} bytes: `#` separates the base from the \
             shared counter in <base>#<counter>, so a base holding one names two labels"
        )
    })
}

/// The longest `--delegated-trust-epoch` base, in bytes; it is minted into every credential.
pub const MAX_DELEGATED_TRUST_EPOCH_BASE_LEN: usize = TrustEpoch::MAX_BASE_LEN;

/// The resolved facts that are not canonical: empty, or unequal to their trimmed form.
///
/// Separate from [`ttl_violations`] because the two gate construction differently: a TTL out
/// of range is a defect in a posture that is otherwise fully determined, while a fact that
/// is empty leaves the posture uninhabitable, so no `DelegatedSigningFacts` is built.
///
/// A minted fact is non-empty and equal to its trimmed form. It is refused rather than
/// trimmed because the same string is read verbatim by other owners (`server_key_id`,
/// `audience`), so trimming here would fork the credential's label from the one they hold.
fn empty_fact_violations([trust_epoch, issuer_kid, audience_hash]: [&str; 3]) -> Vec<String> {
    [
        (
            "--delegated-trust-epoch",
            trust_epoch,
            "--delegated-trust-epoch is empty: the base label is minted into every delegation \
             credential — verbatim where no shared counter is configured, and as the base of \
             <base>#<counter> where one is — so an empty base names no deployment in either \
             posture",
        ),
        (
            "the delegated issuer kid",
            issuer_kid,
            "the delegated issuer kid resolves to empty: set --delegated-issuer-kid, or give \
             --server-key-id a value, since the credential chains to whichever this resolves \
             to and an empty kid names no root key for a verifier to find",
        ),
        (
            "the delegated audience scope",
            audience_hash,
            "the delegated audience scope resolves to empty: set --delegated-audience-hash, \
             or give --audience a value, since an empty scope makes two deployments' \
             credentials indistinguishable to the verifier that checks them",
        ),
    ]
    .into_iter()
    // A label of spaces satisfies a presence check and names nothing, and a padded label
    // names a different one from the label written without the padding; these three are
    // minted verbatim into every delegation credential, so both are refused.
    .filter_map(
        |(name, value, empty_message)| match coordinate::fault(value)? {
            CoordinateFault::Blank => Some(empty_message.to_string()),
            CoordinateFault::Padded => Some(format!(
                "{name} {value:?} has leading or trailing whitespace: it is minted verbatim \
             into every delegation credential, so it names a different label from the one \
             written without it"
            )),
        },
    )
    .collect()
}

/// The credential-lifetime guards.
///
/// `exp` is the only thing that expires a delegated response-signing credential — advancing
/// the trust epoch does not reach one already issued, because no verifier reads the counter
/// — so the TTL IS the exposure window of an exfiltrated hot-path key and needs a ceiling,
/// not merely a positive value. The rotor's successor-before-expiry rule is checked for the
/// same reason the ceiling is: these are public fields on a config a caller can build.
fn ttl_violations(requested: &DelegatedSigningRequest) -> Vec<String> {
    let mut out = Vec::new();
    if requested.ttl_secs <= 0 {
        out.push(
            "--delegated-ttl-secs must be greater than 0 (it is the life of every delegated \
             response-signing credential)"
                .to_string(),
        );
    } else if requested.ttl_secs > MAX_DELEGATED_TTL_SECS {
        out.push(format!(
            "--delegated-ttl-secs {} exceeds the ceiling of {MAX_DELEGATED_TTL_SECS}s: the \
             credential's exp is the ONLY thing that expires it (a trust-epoch advance does \
             not reach credentials already issued), so the TTL is exactly how long an \
             exfiltrated delegated signing key stays verifiable; the delegated key is the \
             SHORT-lived hot-path credential — set a TTL <= {MAX_DELEGATED_TTL_SECS}s",
            requested.ttl_secs
        ));
    }
    // The RELATION is asked of its owner rather than restated: a second copy of
    // `0 < overlap < ttl` here would be a second place for it to be right.
    if let Err(why) = DelegatedKeyWindow::of(requested.ttl_secs, requested.overlap_secs) {
        out.push(format!(
            "--delegated-overlap-secs must satisfy 0 < overlap < ttl (got overlap={}, ttl={}): \
             {why}; the rotor mints a successor one overlap before expiry, so outside that \
             range response signing either never rotates or stops",
            requested.overlap_secs, requested.ttl_secs
        ));
    }
    out
}

/// The ceiling on `--delegated-ttl-secs` (ADR-MCPRE-052).
///
/// The credential's `exp` is the ONLY thing that ever expires a delegated response-signing
/// key: advancing the trust epoch does not reach credentials already issued under it,
/// because no verifier reads the counter. So the TTL IS the exposure window of an
/// exfiltrated hot-path key, and an unbounded TTL turns the short-lived delegated key the
/// specs describe into a long-lived one while every document still calls it short-lived.
///
/// One hour, the same ceiling as [`MAX_CLIENT_CERT_LIFETIME`]: both bound how long a
/// credential the deployment cannot revoke stays usable, so they answer the same question
/// and are held to the same number.
pub const MAX_DELEGATED_TTL_SECS: i64 = 3600;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;

    fn run(
        mutate: impl FnOnce(&mut DeploymentRequest),
    ) -> (Option<DelegatedSigningFacts>, Vec<String>) {
        let mut config = legal_config();
        mutate(&mut config);
        classify_and_validate(&config)
    }

    #[test]
    fn a_legal_request_resolves_every_fact_and_reports_nothing() {
        let (facts, violations) = run(|_| {});
        assert!(violations.is_empty(), "{violations:?}");
        let facts = facts.expect("the legal fixture names an epoch");
        assert!(!facts.trust_epoch().base().is_empty());
        assert!(!facts.issuer_kid().is_empty());
        assert!(!facts.audience_hash().is_empty());
    }

    /// The §7 hard gate. It has no default, so there is no posture to describe without it.
    #[test]
    fn an_absent_trust_epoch_names_no_posture() {
        let (facts, violations) = run(|c| c.delegated_signing.trust_epoch = None);
        assert!(
            facts.is_none(),
            "there is nothing to resolve without an epoch"
        );
        assert!(
            violations
                .iter()
                .any(|v| v.contains("--delegated-trust-epoch")),
            "{violations:?}"
        );
    }

    /// A refusal may not promise an effect the flag it asks for does not produce.
    ///
    /// `--delegated-trust-epoch` supplies a base label and nothing else. The counter that
    /// makes the label globally comparable, and the operator `INCR` that moves every replica
    /// to the next one, come from a shared source this owner neither requires nor can
    /// observe — so a deployment naming the epoch and no source mints the bare base, which is
    /// a supported posture and not the one this refusal is describing. Any sentence here that
    /// reaches for `<base>#<counter>` must therefore carry the condition that produces it.
    #[test]
    fn the_epoch_refusal_conditions_the_counter_on_the_source_that_produces_it() {
        let (_, violations) = run(|c| c.delegated_signing.trust_epoch = None);
        let refusal = violations
            .iter()
            .find(|v| v.contains("--delegated-trust-epoch"))
            .expect("an absent epoch is refused");
        assert!(
            refusal.contains("--trust-epoch-redis-url"),
            "the refusal must name where the counter comes from: {refusal}"
        );
        for sentence in refusal.split('.') {
            assert!(
                !sentence.contains("<base>#<counter>")
                    || sentence.contains("--trust-epoch-redis-url"),
                "this sentence promises a counter the flag alone does not deliver: {sentence}"
            );
        }
    }

    /// G8. Each fact is refused when it is present but empty, by whichever route made it so.
    ///
    /// The mutation is made on the REQUEST, never on an argument list, because that is the
    /// claim: `DeploymentRequest` has 76 public fields, so an embedder reaches the serving
    /// path without a parser, and the parser's own non-empty guards would not run.
    ///
    /// The positive half of each case is the legal fixture, which resolves the same fact to
    /// a meaningful value and is asserted clean by
    /// `a_legal_request_resolves_every_fact_and_reports_nothing` — so a predicate that
    /// simply rejected this owner outright would fail there.
    #[test]
    fn a_fact_that_resolves_to_empty_is_refused_however_it_got_that_way() {
        for (name, mutate) in [
            (
                "--delegated-trust-epoch",
                (|c: &mut DeploymentRequest| c.delegated_signing.trust_epoch = Some(String::new()))
                    as fn(&mut DeploymentRequest),
            ),
            ("the delegated issuer kid", |c| {
                c.delegated_signing.issuer_kid = Some(String::new())
            }),
            (
                // The defaulting source is empty rather than the flag: the same fact, the
                // same refusal, which is what asking of the RESOLVED value buys.
                "the delegated issuer kid",
                |c| {
                    c.delegated_signing.issuer_kid = None;
                    c.server_key_id = String::new();
                },
            ),
            ("the delegated audience scope", |c| {
                c.delegated_signing.audience_hash = Some(String::new())
            }),
            ("the delegated audience scope", |c| {
                c.delegated_signing.audience_hash = None;
                c.audience = String::new();
            }),
        ] {
            let (facts, violations) = run(mutate);
            assert!(
                facts.is_none(),
                "{name}: an empty fact left the posture inhabitable"
            );
            assert!(
                violations.iter().any(|v| v.contains(name)),
                "{name}: not refused — {violations:?}"
            );
        }
    }

    /// A base the `<base>#<counter>` label cannot parse back uniquely is refused, and so is
    /// one past the length bound; a base at the bound is legal.
    #[test]
    fn an_epoch_base_that_renders_an_ambiguous_label_is_refused() {
        let at_bound = "e".repeat(MAX_DELEGATED_TRUST_EPOCH_BASE_LEN);
        let past_bound = "e".repeat(MAX_DELEGATED_TRUST_EPOCH_BASE_LEN + 1);
        for (base, legal) in [
            ("a#1", false),
            (past_bound.as_str(), false),
            (at_bound.as_str(), true),
        ] {
            let (facts, violations) =
                run(|c| c.delegated_signing.trust_epoch = Some(base.to_string()));
            assert_eq!(facts.is_some(), legal, "{base:?}: {violations:?}");
            assert_eq!(
                violations
                    .iter()
                    .any(|v| v.contains("must not contain '#'")),
                !legal,
                "{base:?}: {violations:?}"
            );
        }
    }

    /// The smallest meaningful value passes the same guard the empty one fails.
    #[test]
    fn a_one_character_fact_is_not_refused_by_the_emptiness_guard() {
        let (facts, violations) = run(|c| {
            c.delegated_signing.trust_epoch = Some("e".to_string());
            c.delegated_signing.issuer_kid = Some("k".to_string());
            c.delegated_signing.audience_hash = Some("a".to_string());
        });
        assert!(violations.is_empty(), "{violations:?}");
        let facts = facts.expect("a one-character fact is a fact");
        assert_eq!(facts.trust_epoch().label(), "e");
        assert_eq!(facts.issuer_kid(), "k");
        assert_eq!(facts.audience_hash(), "a");
    }

    /// Both defaults are applied HERE, so downstream cannot observe that they existed.
    #[test]
    fn the_two_defaults_are_resolved_by_this_owner() {
        let (facts, _) = run(|c| {
            c.delegated_signing.issuer_kid = None;
            c.delegated_signing.audience_hash = None;
            c.server_key_id = "server-key-7".to_string();
            c.audience = "did:example:aud-7".to_string();
        });
        let facts = facts.expect("defaults do not make a request illegal");
        assert_eq!(facts.issuer_kid(), "server-key-7");
        assert_eq!(facts.audience_hash(), "did:example:aud-7");
    }

    /// An explicit value wins over the fallback, and the fallback source is not consulted.
    #[test]
    fn an_explicit_value_overrides_the_fallback() {
        let (facts, _) = run(|c| {
            c.delegated_signing.issuer_kid = Some("explicit-kid".to_string());
            c.delegated_signing.audience_hash = Some("explicit-aud".to_string());
            c.server_key_id = "not-this".to_string();
            c.audience = "not-this-either".to_string();
        });
        let facts = facts.expect("an override does not make a request illegal");
        assert_eq!(facts.issuer_kid(), "explicit-kid");
        assert_eq!(facts.audience_hash(), "explicit-aud");
    }

    /// A range defect is reported beside every other violation, and resolves no facts.
    ///
    /// This test previously asserted the opposite half — that the facts still resolve,
    /// because a TTL defect leaves the posture "otherwise fully determined". That was true
    /// while the window lived in the request: the facts did not carry it, so they could not
    /// be wrong about it. Now that the PAIR is a fact, a resolved fact set carrying an
    /// out-of-range window would be a witness to something no guard ever accepted.
    ///
    /// The half worth keeping is the reporting one, and it is unchanged: gating construction
    /// and collecting every violation are not in tension, so an operator still sees all of
    /// their defects in one run.
    #[test]
    fn a_range_defect_is_reported_and_resolves_no_facts() {
        let (facts, violations) = run(|c| c.delegated_signing.ttl_secs = 0);
        assert!(
            facts.is_none(),
            "a fact set cannot carry a window the guard refused"
        );
        assert!(
            violations
                .iter()
                .any(|v| v.contains("--delegated-ttl-secs must be greater than 0")),
            "{violations:?}"
        );
    }

    /// The pairing the window exists to hold: `0 < overlap < ttl`, as one value.
    ///
    /// The operational test for the seal — delete the guard and an invalid pair is still
    /// unconstructible — holds because `DelegatedKeyWindow`'s fields are private to its module
    /// and `classify_and_validate` is its only producer. Planning can no longer take a
    /// validated TTL and pair it with an overlap nothing checked.
    #[test]
    fn an_overlap_outside_the_ttl_resolves_no_window() {
        let (facts, violations) = run(|c| {
            c.delegated_signing.ttl_secs = 300;
            c.delegated_signing.overlap_secs = 300;
        });
        assert!(facts.is_none(), "overlap == ttl is outside the guard");
        assert!(
            violations.iter().any(|v| v.contains("0 < overlap < ttl")),
            "{violations:?}"
        );
        let (facts, violations) = run(|c| {
            c.delegated_signing.ttl_secs = 300;
            c.delegated_signing.overlap_secs = 60;
        });
        let window = facts.expect("a legal pair resolves").rotation_window();
        assert!(violations.is_empty(), "{violations:?}");
        assert_eq!((window.ttl(), window.overlap()), (300, 60));
    }

    #[test]
    fn a_ttl_above_the_ceiling_is_refused() {
        let (_, violations) = run(|c| c.delegated_signing.ttl_secs = MAX_DELEGATED_TTL_SECS + 1);
        assert!(
            violations.iter().any(|v| v.contains("exceeds the ceiling")),
            "{violations:?}"
        );
    }

    /// Outside `0 < overlap < ttl` the rotor either never rotates or stops.
    #[test]
    fn an_overlap_outside_the_rotor_range_is_refused() {
        for overlap in [0, -1, 300, 600] {
            let (_, violations) = run(|c| {
                c.delegated_signing.ttl_secs = 300;
                c.delegated_signing.overlap_secs = overlap;
            });
            assert!(
                violations.iter().any(|v| v.contains("0 < overlap < ttl")),
                "overlap {overlap} must be refused: {violations:?}"
            );
        }
    }

    /// The fallback is required IF AND ONLY IF the resolution reads it.
    ///
    /// This owner is the sole authority over the resolved issuer kid. The boundary used to
    /// carry a second clause refusing an empty `--server-key-id` unconditionally, which
    /// enforced the wrong premise: the invariant is not "the fallback is always
    /// meaningful", it is "a meaningful SOURCE for the resolved kid exists". With an
    /// explicit `--delegated-issuer-kid` the fallback is read by nothing, and refusing on
    /// it was dangling-input policy wearing requiredness as a disguise.
    ///
    /// All four branches are pinned, because three of them are admissions and an
    /// admission that stops happening is the failure this test exists to catch.
    #[test]
    fn the_issuer_kid_fallback_is_required_only_where_the_resolution_reads_it() {
        let cases: [(&str, bool, &str, bool); 4] = [
            // (label, explicit override present, server_key_id, admitted)
            ("explicit override, empty fallback", true, "", true),
            (
                "explicit override, present fallback",
                true,
                "server-key-1",
                true,
            ),
            ("no override, present fallback", false, "server-key-1", true),
            ("no override, empty fallback", false, "", false),
        ];
        for (label, explicit, key_id, admitted) in cases {
            let mut config = legal_config();
            config.delegated_signing.issuer_kid = explicit.then(|| "root-issuer-9".to_string());
            config.server_key_id = key_id.to_string();
            let (facts, violations) = classify_and_validate(&config);
            assert_eq!(
                facts.is_some(),
                admitted,
                "{label}: expected admitted={admitted}, got violations {violations:?}"
            );
            let Some(facts) = facts else {
                assert!(
                    violations.iter().any(|v| v.contains("issuer kid")),
                    "{label}: the refusal must name the resolved kid, got {violations:?}"
                );
                continue;
            };
            let expected = if explicit { "root-issuer-9" } else { key_id };
            assert_eq!(
                facts.issuer_kid(),
                expected,
                "{label}: the explicit override must win wherever it is present"
            );
        }
    }

    /// Whitespace-only and padded values are refused for all three minted facts.
    ///
    /// They are minted VERBATIM into every delegation credential, so a label of spaces is
    /// indistinguishable from absence to the verifier reading it back, and a padded label
    /// names a different one from the unpadded label other owners hold. Refusal, not
    /// trimming, keeps the checked fact and the stored fact one value.
    #[test]
    fn a_whitespace_minted_fact_is_refused_like_an_empty_one() {
        type MintedFact = (&'static str, &'static str, fn(&mut DeploymentRequest));
        let cases: [MintedFact; 7] = [
            ("--delegated-trust-epoch", "blank", |c| {
                c.delegated_signing.trust_epoch = Some("   ".to_string());
            }),
            ("--delegated-trust-epoch", "padded", |c| {
                c.delegated_signing.trust_epoch = Some(" epoch-1".to_string());
            }),
            ("the delegated issuer kid", "blank server key id", |c| {
                c.delegated_signing.issuer_kid = None;
                c.server_key_id = "   ".to_string();
            }),
            ("the delegated issuer kid", "padded override", |c| {
                c.delegated_signing.issuer_kid = Some("kid ".to_string());
            }),
            ("the delegated issuer kid", "padded server key id", |c| {
                c.delegated_signing.issuer_kid = None;
                c.server_key_id = " server-key-1".to_string();
            }),
            ("the delegated audience scope", "blank", |c| {
                c.delegated_signing.audience_hash = Some("   ".to_string());
            }),
            ("the delegated audience scope", "padded", |c| {
                c.delegated_signing.audience_hash = Some(" aud".to_string());
            }),
        ];
        for (name, label, mutate) in cases {
            let (facts, violations) = run(mutate);
            assert!(
                facts.is_none(),
                "{name} ({label}) must not resolve to a fact"
            );
            assert!(
                violations.iter().any(|v| v.contains(name)),
                "{name} ({label}) must be named in the refusal: {violations:?}"
            );
        }
    }
}
