// SPDX-License-Identifier: Apache-2.0
//! The `DelegatedSigning` semantic owner — `work/CONFIG-STATE-ATLAS.md`, "Delegated
//! signing".
//!
//! **A guard-only owner: no modes, and still facts of its own.** Delegated response
//! signing is unconditional — ADR-MCPRE-052 is the only response-signing mode, so there is
//! no state to choose and no enum to classify into. What this owner has instead is one
//! required value, two guards, and two defaulting rules:
//!
//! | Field | Kind | Rule |
//! |---|---|---|
//! | `delegated_trust_epoch` | required | the §7 hard gate; no default |
//! | `delegated_ttl_secs` | guard | `0 < ttl <= MAX_DELEGATED_TTL_SECS` |
//! | `delegated_overlap_secs` | guard | `0 < overlap < ttl` |
//! | `delegated_issuer_kid` | derived | defaults to `server_key_id` |
//! | `delegated_audience_hash` | derived | defaults to `audience` |
//!
//! **The resolved values live here because the rule does.** A default applied downstream is
//! a rule with two homes: the layer that owns it and the layer that re-applies it. Both
//! spelled `--delegated-issuer-kid` falling back to `--server-key-id`, so they agreed —
//! nothing made them, and a deployment could have been told it was chaining to one issuer
//! while minting under another. [`DelegatedSigningFacts`] resolves both once, and nothing
//! after this point can see that a default was ever involved.
//!
//! **The TTL and the overlap are checked here and kept in `DeploymentRequest`.** They are this owner's
//! invariant, so the guards belong to it. The values do not, because nothing downstream
//! re-derives them: planning reads an `i64` and hands it to a `CustodyConfig` field that is
//! an `i64`. A normalized witness here would strengthen only the middle hop and widen again
//! at the consumer, so the guard would still not reach it. Strengthening
//! `mcp_re_http_profile::CustodyConfig` is what would make that hold, and that is a
//! different type in a different crate.

use crate::cli::{DeploymentRequest, MAX_DELEGATED_TTL_SECS};

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
    trust_epoch: String,
    issuer_kid: String,
    audience_hash: String,
}

impl DelegatedSigningFacts {
    /// The epoch label every delegated credential is minted under (`<base>#<counter>`).
    pub fn trust_epoch(&self) -> &str {
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
    let epoch = config.delegated_trust_epoch.clone();
    if epoch.is_none() {
        violations.push(
            "delegated-required response signing requires a trust epoch \
             (--delegated-trust-epoch): without it every credential is minted under a bare \
             label instead of <base>#<counter>, so a restarted replica appears unrevoked to \
             verifiers pinned past an operator INCR and the cross-fleet kill switch stops \
             working"
                .to_string(),
        );
    }
    // The range guards are reported whether or not an epoch was named: an operator fixing
    // one defect should not have to run the proxy again to be told about the next.
    violations.extend(ttl_violations(config));
    let Some(trust_epoch) = epoch else {
        return (None, violations);
    };
    let facts = DelegatedSigningFacts {
        trust_epoch,
        issuer_kid: config
            .delegated_issuer_kid
            .clone()
            .unwrap_or_else(|| config.server_key_id.clone()),
        audience_hash: config
            .delegated_audience_hash
            .clone()
            .unwrap_or_else(|| config.audience.clone()),
    };
    // Each fact is checked AFTER resolution, which is the only place the question can be
    // asked once. An empty value arrives two ways — an operator passing the flag empty, or a
    // defaulting source that is itself empty — and asking of the resolved fact covers both
    // without this owner reading `server_key_id` and `audience` a second time to guess which
    // happened (CF-10). A present-but-empty fact is not a witness: every one of these is
    // minted verbatim into every delegation credential, where an empty issuer names no
    // issuer and an empty epoch is the bare label the epoch exists to replace.
    let empty_facts = empty_fact_violations(&facts);
    if !empty_facts.is_empty() {
        violations.extend(empty_facts);
        return (None, violations);
    }
    (Some(facts), violations)
}

/// The resolved facts that are present but say nothing.
///
/// Separate from [`ttl_violations`] because the two gate construction differently: a TTL out
/// of range is a defect in a posture that is otherwise fully determined, while a fact that
/// is empty leaves the posture uninhabitable, so no `DelegatedSigningFacts` is built.
fn empty_fact_violations(facts: &DelegatedSigningFacts) -> Vec<String> {
    [
        (
            facts.trust_epoch.as_str(),
            "--delegated-trust-epoch is empty: the epoch is minted into every delegation \
             credential as <base>#<counter>, and an empty base makes the cross-fleet kill \
             switch unable to name the deployment it is revoking",
        ),
        (
            facts.issuer_kid.as_str(),
            "the delegated issuer kid resolves to empty: set --delegated-issuer-kid, or give \
             --server-key-id a value, since the credential chains to whichever this resolves \
             to and an empty kid names no root key for a verifier to find",
        ),
        (
            facts.audience_hash.as_str(),
            "the delegated audience scope resolves to empty: set --delegated-audience-hash, \
             or give --audience a value, since an empty scope makes two deployments' \
             credentials indistinguishable to the verifier that checks them",
        ),
    ]
    .into_iter()
    .filter(|(value, _)| value.is_empty())
    .map(|(_, message)| message.to_string())
    .collect()
}

/// The credential-lifetime guards.
///
/// `exp` is the only thing that expires a delegated response-signing credential — advancing
/// the trust epoch does not reach one already issued, because no verifier reads the counter
/// — so the TTL IS the exposure window of an exfiltrated hot-path key and needs a ceiling,
/// not merely a positive value. The rotor's successor-before-expiry rule is checked for the
/// same reason the ceiling is: these are public fields on a config a caller can build.
fn ttl_violations(config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    if config.delegated_ttl_secs <= 0 {
        out.push(
            "--delegated-ttl-secs must be greater than 0 (it is the life of every delegated \
             response-signing credential)"
                .to_string(),
        );
    } else if config.delegated_ttl_secs > MAX_DELEGATED_TTL_SECS {
        out.push(format!(
            "--delegated-ttl-secs {} exceeds the ceiling of {MAX_DELEGATED_TTL_SECS}s: the \
             credential's exp is the ONLY thing that expires it (a trust-epoch advance does \
             not reach credentials already issued), so the TTL is exactly how long an \
             exfiltrated delegated signing key stays verifiable; the delegated key is the \
             SHORT-lived hot-path credential — set a TTL <= {MAX_DELEGATED_TTL_SECS}s",
            config.delegated_ttl_secs
        ));
    }
    if config.delegated_overlap_secs <= 0
        || config.delegated_overlap_secs >= config.delegated_ttl_secs
    {
        out.push(format!(
            "--delegated-overlap-secs must satisfy 0 < overlap < ttl (got overlap={}, ttl={}); \
             the rotor mints a successor one overlap before expiry, so outside that range \
             response signing either never rotates or stops",
            config.delegated_overlap_secs, config.delegated_ttl_secs
        ));
    }
    out
}

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
        assert!(!facts.trust_epoch().is_empty());
        assert!(!facts.issuer_kid().is_empty());
        assert!(!facts.audience_hash().is_empty());
    }

    /// The §7 hard gate. It has no default, so there is no posture to describe without it.
    #[test]
    fn an_absent_trust_epoch_names_no_posture() {
        let (facts, violations) = run(|c| c.delegated_trust_epoch = None);
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
                (|c: &mut DeploymentRequest| c.delegated_trust_epoch = Some(String::new()))
                    as fn(&mut DeploymentRequest),
            ),
            ("the delegated issuer kid", |c| {
                c.delegated_issuer_kid = Some(String::new())
            }),
            (
                // The defaulting source is empty rather than the flag: the same fact, the
                // same refusal, which is what asking of the RESOLVED value buys.
                "the delegated issuer kid",
                |c| {
                    c.delegated_issuer_kid = None;
                    c.server_key_id = String::new();
                },
            ),
            ("the delegated audience scope", |c| {
                c.delegated_audience_hash = Some(String::new())
            }),
            ("the delegated audience scope", |c| {
                c.delegated_audience_hash = None;
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

    /// The smallest meaningful value passes the same guard the empty one fails.
    #[test]
    fn a_one_character_fact_is_not_refused_by_the_emptiness_guard() {
        let (facts, violations) = run(|c| {
            c.delegated_trust_epoch = Some("e".to_string());
            c.delegated_issuer_kid = Some("k".to_string());
            c.delegated_audience_hash = Some("a".to_string());
        });
        assert!(violations.is_empty(), "{violations:?}");
        let facts = facts.expect("a one-character fact is a fact");
        assert_eq!(facts.trust_epoch(), "e");
        assert_eq!(facts.issuer_kid(), "k");
        assert_eq!(facts.audience_hash(), "a");
    }

    /// Both defaults are applied HERE, so downstream cannot observe that they existed.
    #[test]
    fn the_two_defaults_are_resolved_by_this_owner() {
        let (facts, _) = run(|c| {
            c.delegated_issuer_kid = None;
            c.delegated_audience_hash = None;
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
            c.delegated_issuer_kid = Some("explicit-kid".to_string());
            c.delegated_audience_hash = Some("explicit-aud".to_string());
            c.server_key_id = "not-this".to_string();
            c.audience = "not-this-either".to_string();
        });
        let facts = facts.expect("an override does not make a request illegal");
        assert_eq!(facts.issuer_kid(), "explicit-kid");
        assert_eq!(facts.audience_hash(), "explicit-aud");
    }

    /// A TTL defect is a defect in a posture that is otherwise fully determined, so the
    /// facts still resolve and the violation is reported beside them.
    #[test]
    fn a_range_defect_is_reported_without_erasing_the_resolved_facts() {
        let (facts, violations) = run(|c| c.delegated_ttl_secs = 0);
        assert!(
            facts.is_some(),
            "the epoch is present, so the facts resolve"
        );
        assert!(
            violations
                .iter()
                .any(|v| v.contains("--delegated-ttl-secs must be greater than 0")),
            "{violations:?}"
        );
    }

    #[test]
    fn a_ttl_above_the_ceiling_is_refused() {
        let (_, violations) = run(|c| c.delegated_ttl_secs = MAX_DELEGATED_TTL_SECS + 1);
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
                c.delegated_ttl_secs = 300;
                c.delegated_overlap_secs = overlap;
            });
            assert!(
                violations.iter().any(|v| v.contains("0 < overlap < ttl")),
                "overlap {overlap} must be refused: {violations:?}"
            );
        }
    }
}
