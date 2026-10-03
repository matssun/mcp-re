// SPDX-License-Identifier: Apache-2.0
//! How an arbitrary scalar is SPELLED inside a line-oriented audit record.
//!
//! The property, stated once:
//!
//! > One logical audit record produces exactly one physical audit record, and no field
//! > name and no field value can synthesize a new field or a new line.
//!
//! Before this module the record's text was assembled by whoever happened to hold the
//! values — `AuthorizationFacet::audit_fields` returned finished text, and the sink
//! concatenated it into a wider `format!`. That destroys the information the property needs:
//! given `authz_authority=acme authz_version=1`, no function of that string can tell the
//! space the owner emitted as a separator from one that arrived inside a value. So the
//! question "can this line be read back as the fields that were written?" had no owner and
//! therefore no answer. [`RefusalCause`](crate::refusal) fixed the same shape one layer
//! down, and named it: the question the pre-rendered string made unanswerable.
//!
//! The authority split this preserves:
//!
//! | owner | decides |
//! |---|---|
//! | the domain owner | WHAT a field means, and whether its own value is a closed token or open text |
//! | this module | HOW an arbitrary scalar is spelled so the record grammar survives it |
//! | the sink | transport |
//!
//! This module has no way to ask what `authz_target` means, and the owners have no way to
//! reach a separator: whatever a name or a token spells, [`render_record`] emits bytes in
//! the grammar, in every build profile. The property is owned there because that function is
//! a rendered record's sole producer — it quantifies over no minting site, and no minting
//! site can bypass it. [`AuditValue::Token`] is `&'static str` so that the ORDINARY
//! misclassification — calling a slice borrowed out of a request body a token — is a compile
//! error; that is a lifetime bound and not a provenance one, since `String::leak` reaches
//! `'static` from bytes of any origin, and the rendering depends on none of it.
//!
//! **The object of the claim** is the `String` [`render_record`] returns.
//! [`crate::audit_sink`] prefixes `mcp-re-proxy: audit ` to it before it reaches stderr, and
//! that prefix's first token carries no `=`; what a reader recovers is the substring after
//! it, and the prefix's grammar is the sink's.
//!
//! **Not in scope: a length bound.** The record carries no cap on a value's size. That is
//! the sink's bounded-queue economics, and truncation is lossy — adding it here would
//! destroy the injectivity this module exists to establish. A bound belongs where
//! `STDERR_AUDIT_QUEUE_DEPTH` lives, expressed as a refusal or as a digest-plus-marker,
//! never as a silent cut. `audit_sink::offer` reserves in RECORDS and not in bytes, so that
//! bound is stated by neither owner today.
//!
//! **Not in scope: the drop warning.** `audit_sink`'s `dropped={n}` line is prose that
//! happens to open with a `key=value`, not a record; its one value is a `u64`, and
//! `app.rs` distinguishes records from it by the literal `audit seq=` prefix. Converting it
//! would be churn with no property attached.

use super::scalar::escape_scalar;
use super::scalar::is_separator_free;

/// The reserved rendering of [`AuditValue::Absent`]: *the owner resolved nothing*.
///
/// Disjoint from every rendered value, in all four arms. `escape_scalar` spells a leading
/// `-` as an escape; [`is_separator_free`] is false for a leading `-`, so the verbatim arms
/// escape it too rather than emitting it; and every `Number` carries at least one digit
/// after any sign. *Nobody was resolved* and *the resolved name is `-`* are different facts
/// and stay different bytes.
const ABSENT: &str = "-";

/// One field's value, CLASSIFIED BY ITS OWNER.
///
/// The classification is the whole security content of this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuditValue<'a> {
    /// A member of a closed internal vocabulary. Rendered verbatim.
    Token(&'static str),
    /// An integer coordinate. Rendered verbatim.
    Number(i64),
    /// Arbitrary text of any provenance. Escaped by [`escape_scalar`].
    ///
    /// `Cow`, so an owner that COMPOSES a value — `DecisionEvidenceIdentity::rendered`
    /// spells `<alg>:<value>` — can hand one over without every other field paying for a
    /// clone, and without the composing owner being pushed into spelling it here.
    Text(std::borrow::Cow<'a, str>),
    /// The owner resolved nothing.
    Absent,
}

/// One `key=value` field of a record.
///
/// The representation stays open to the crate and the constructors below are naming
/// conveniences, not a boundary: a validating constructor over an open representation is a
/// check a struct literal walks around. The grammar is enforced where the bytes are produced
/// ([`render_record`]) instead, so this type has no illegal inhabitant to exclude.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuditField<'a> {
    pub(crate) name: &'static str,
    pub(crate) value: AuditValue<'a>,
}

impl<'a> AuditField<'a> {
    /// A field whose value is a member of a closed vocabulary.
    pub(crate) fn token(name: &'static str, value: &'static str) -> Self {
        AuditField {
            name,
            value: AuditValue::Token(value),
        }
    }

    /// A field whose value is an integer coordinate.
    pub(crate) fn number(name: &'static str, value: i64) -> Self {
        AuditField {
            name,
            value: AuditValue::Number(value),
        }
    }

    /// A field whose value is arbitrary text, of any provenance.
    pub(crate) fn text(name: &'static str, value: impl Into<std::borrow::Cow<'a, str>>) -> Self {
        AuditField {
            name,
            value: AuditValue::Text(value.into()),
        }
    }

    /// A field whose owner resolved nothing, or that text when it did.
    pub(crate) fn text_or_absent(
        name: &'static str,
        value: Option<impl Into<std::borrow::Cow<'a, str>>>,
    ) -> Self {
        match value {
            Some(v) => AuditField::text(name, v),
            None => AuditField {
                name,
                value: AuditValue::Absent,
            },
        }
    }

    /// A field whose owner resolved nothing, or that token when it did.
    pub(crate) fn token_or_absent(name: &'static str, value: Option<&'static str>) -> Self {
        match value {
            Some(v) => AuditField::token(name, v),
            None => AuditField {
                name,
                value: AuditValue::Absent,
            },
        }
    }
}

/// THE rendering. One logical record in, one physical record out.
///
/// For any input whatsoever, in any build profile, the returned `String` contains no U+000A
/// and no U+000D, each field contributes exactly one whitespace-delimited token, and each
/// token contains exactly one `=`. `split(' ')` then `split_once('=')` recovers the field
/// sequence; each name, each `Token` and each `Text` is then recovered by
/// [`unescape_scalar`], a `Number` reads as decimal, and the absent marker is the reserved
/// bare `-` that no other arm produces. The caller appends exactly one U+000A.
///
/// "Any input whatsoever" is the whole claim and it is quantified over inhabitants of
/// [`AuditField`], not over the sites that build them: a name or a token that is not already
/// grammar-conforming is escaped here rather than asserted about, so there is no build in
/// which the screen is absent and none in which it panics.
pub(crate) fn render_record(fields: &[AuditField<'_>]) -> String {
    let mut out = String::new();
    for field in fields {
        if !out.is_empty() {
            out.push(' ');
        }
        push_verbatim_or_escaped(&mut out, field.name);
        out.push('=');
        match &field.value {
            AuditValue::Token(t) => push_verbatim_or_escaped(&mut out, t),
            AuditValue::Number(n) => out.push_str(&n.to_string()),
            AuditValue::Text(s) => out.push_str(&escape_scalar(s)),
            AuditValue::Absent => out.push_str(ABSENT),
        }
    }
    out
}

/// Append a name or a closed-vocabulary token: as itself where that is already its own
/// escape image, and as its escape where it is not.
///
/// The escape is a FLOOR, not a spelling change: every name and every vocabulary member this
/// crate mints satisfies [`is_separator_free`] and so renders to the bytes it would render
/// to verbatim, leaving an operator's `grep` intact. Only the value that could not be
/// rendered at all moves — spelled recoverably rather than pushed in to break the record.
fn push_verbatim_or_escaped(out: &mut String, text: &str) {
    if is_separator_free(text) {
        out.push_str(text);
    } else {
        out.push_str(&escape_scalar(text));
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission_enforcer::AdmissionFacet;
    use crate::admission_enforcer::AdmissionRefusalClass;
    use crate::audit_record::scalar::unescape_scalar;
    use crate::audit_record::AuditRecord;
    use crate::audit_record::AuditSubject;
    use crate::authorization::AuthorizationFacet;
    use crate::authorization::AuthorizationRefusalFacet;
    use mcp_re_http_profile::authoritative_admission::record::AdmissionRecordRefusal;
    use mcp_re_policy::PolicyError;

    /// The tokens a rendered record splits into, one per field.
    fn tokens(line: &str) -> Vec<&str> {
        line.split(' ').collect()
    }

    /// The logical record recovered from a physical one, as `(name, value)` pairs.
    fn parse(line: &str) -> Vec<(String, String)> {
        tokens(line)
            .iter()
            .map(|t| {
                let (name, value) = t.split_once('=').expect("every token carries one `=`");
                (name.to_owned(), value.to_owned())
            })
            .collect()
    }

    /// A value that ends the physical record still renders as one line.
    #[test]
    fn a_scalar_carrying_a_newline_still_renders_one_physical_record() {
        let forged = "read\nmcp-re-proxy: audit seq=9 event=mcp-re.request.accepted \
                      decision=Accepted";
        let line = render_record(&[
            AuditField::number("seq", 1),
            AuditField::text("authz_target", forged),
        ]);
        assert!(!line.contains('\n'), "{line}");
        assert!(!line.contains('\r'), "{line}");
        assert_eq!(tokens(&line).len(), 2, "{line}");
        assert_eq!(
            unescape_scalar(&parse(&line)[1].1).as_deref(),
            Some(forged),
            "the forged text survives as the VALUE it was"
        );
    }

    /// A value carrying the field separator cannot add a field.
    #[test]
    fn a_scalar_carrying_the_field_separator_cannot_add_a_field() {
        let line = render_record(&[
            AuditField::text("authz_authority", "trusted"),
            AuditField::text("authz_decision_id", "x authz_authority=forged"),
        ]);
        let fields = parse(&line);
        assert_eq!(fields.len(), 2, "{line}");
        let authorities: Vec<_> = fields
            .iter()
            .filter(|(n, _)| n == "authz_authority")
            .collect();
        assert_eq!(authorities.len(), 1, "{line}");
        assert_eq!(
            unescape_scalar(&authorities[0].1).as_deref(),
            Some("trusted")
        );
    }

    /// A value carrying the key separator keeps one `=` per token.
    #[test]
    fn a_scalar_carrying_the_key_separator_keeps_one_equals_per_token() {
        let line = render_record(&[AuditField::text("authz_target", "a=b")]);
        for token in tokens(&line) {
            assert_eq!(token.matches('=').count(), 1, "{token:?} in {line}");
        }
        assert_eq!(unescape_scalar(&parse(&line)[0].1).as_deref(), Some("a=b"));
    }

    /// *Nobody was resolved* and *the resolved value is `-`* stay different facts.
    #[test]
    fn the_absent_marker_is_not_producible_by_any_scalar() {
        assert_ne!(escape_scalar("-"), ABSENT);
        let absent = render_record(&[AuditField::text_or_absent("actor", Option::<&str>::None)]);
        let literal = render_record(&[AuditField::text_or_absent("actor", Some("-"))]);
        assert_eq!(absent, "actor=-");
        assert_ne!(absent, literal);
        assert_eq!(unescape_scalar(&parse(&literal)[0].1).as_deref(), Some("-"));
    }

    /// The record grammar's other half: a field NAME may not carry a separator either.
    #[test]
    fn no_field_name_contains_a_separator() {
        for name in [
            "seq",
            "event",
            "decision",
            "reason",
            "actor",
            "status",
            "at",
            "authz",
            "authz_authority",
            "authz_version",
            "authz_decision_id",
            "authz_decision_evidence",
            "authz_operation",
            "authz_target",
            "authz_evidence",
            "authz_policy_reason",
        ] {
            assert!(is_separator_free(name), "{name:?}");
        }
        assert!(!is_separator_free(""));
        assert!(!is_separator_free("a b"));
        assert!(!is_separator_free("a=b"));
        assert!(!is_separator_free("a\\b"));
        assert!(!is_separator_free("a\u{202E}b"));
    }

    /// The end-to-end statement: every hazard in a different field, all recovered.
    #[test]
    fn a_rendered_record_parses_back_to_the_fields_that_were_written() {
        let written: Vec<(&'static str, &'static str)> = vec![
            ("actor", "a\nb"),
            ("authz_authority", "a b"),
            ("authz_version", "a=b"),
            ("authz_decision_id", "a\\b"),
            ("authz_operation", "-leading"),
            ("authz_target", "a\u{202E}b"),
            ("authz_evidence", "a\u{7}b"),
        ];
        let mut fields = vec![
            AuditField::number("seq", 9),
            AuditField::token("event", "e"),
        ];
        fields.extend(written.iter().map(|(n, v)| AuditField::text(n, *v)));
        let line = render_record(&fields);

        assert!(!line.contains('\n') && !line.contains('\r'), "{line}");
        let parsed = parse(&line);
        assert_eq!(parsed.len(), fields.len(), "{line}");
        assert_eq!(parsed[0], ("seq".to_owned(), "9".to_owned()));
        assert_eq!(parsed[1], ("event".to_owned(), "e".to_owned()));
        for (index, (name, value)) in written.iter().enumerate() {
            let (got_name, got_value) = &parsed[index + 2];
            assert_eq!(got_name, name, "{line}");
            assert_eq!(
                unescape_scalar(got_value).as_deref(),
                Some(*value),
                "{line}"
            );
        }
    }

    /// A token that would end the physical record is spelled, not emitted.
    ///
    /// The `Token` half of the statement above. It holds in BOTH build profiles: nothing
    /// here asserts about a panic, and the rendering has one outcome whether or not
    /// `debug_assertions` is on.
    #[test]
    fn a_token_carrying_a_newline_still_renders_one_physical_record() {
        let forged = "e\nmcp-re-proxy: audit seq=9 event=mcp-re.request.accepted";
        let line = render_record(&[
            AuditField::number("seq", 1),
            AuditField::token("event", forged),
        ]);
        assert!(!line.contains('\n') && !line.contains('\r'), "{line}");
        assert_eq!(tokens(&line).len(), 2, "{line}");
        assert_eq!(
            unescape_scalar(&parse(&line)[1].1).as_deref(),
            Some(forged),
            "the forged token survives as the VALUE it was"
        );
    }

    /// A field NAME carrying a separator cannot add a field either.
    ///
    /// Profile-independent for the same reason as the test above.
    #[test]
    fn a_field_name_carrying_a_separator_cannot_add_a_field() {
        let line = render_record(&[
            AuditField::text("authz_authority", "trusted"),
            AuditField {
                name: "x status=200 authz_authority",
                value: AuditValue::Token("forged"),
            },
        ]);
        let fields = parse(&line);
        assert_eq!(fields.len(), 2, "{line}");
        assert_eq!(fields[0].0, "authz_authority", "{line}");
        assert_eq!(
            unescape_scalar(&fields[1].0).as_deref(),
            Some("x status=200 authz_authority"),
            "the hazardous name is recoverable as the NAME it was: {line}"
        );
    }

    /// *Nobody was resolved* and *the resolved token is `-`* stay different facts.
    ///
    /// The `Text` arm's half of this is
    /// `the_absent_marker_is_not_producible_by_any_scalar`; the verbatim arms reach the same
    /// reservation through `is_separator_free`, which is false for a leading `-`.
    #[test]
    fn a_token_that_is_the_bare_absent_marker_is_not_the_absent_marker() {
        let absent = render_record(&[AuditField::token_or_absent("reason", None)]);
        let literal = render_record(&[AuditField::token_or_absent("reason", Some("-"))]);
        assert_eq!(absent, "reason=-");
        assert_ne!(
            absent, literal,
            "a Core reason of `-` collapses into ABSENT"
        );
        assert_eq!(unescape_scalar(&parse(&literal)[0].1).as_deref(), Some("-"));
        // The name side of the same reservation, and the `Number` side: a negative
        // coordinate carries a digit, so it is not the marker either.
        let negative = render_record(&[AuditField::number("at", -1)]);
        assert_eq!(negative, "at=-1");
        assert_ne!(parse(&negative)[0].1, ABSENT);
    }

    /// Every record this proxy actually produces, over both subject kinds and every
    /// independently constructible facet arm.
    ///
    /// `AuthorizationFacet::Authorized` is absent because its attribution holds a
    /// `VerifiedAuthorizationAction`, whose representation and constructor are private to
    /// `authorization::verified_action`, so no inhabitant is reachable from here. That arm's
    /// coordinate is rendered by `authorization::capability::tests::the_audit_record_answers_which_decision_and_which_evidence_separately`.
    fn real_records() -> Vec<AuditRecord> {
        let admissions = [
            AdmissionFacet::NotReached,
            AdmissionFacet::NotConfigured,
            AdmissionFacet::LiveConfirmed,
            AdmissionFacet::Degraded,
            AdmissionFacet::Refused,
        ];
        let authorizations = [
            AuthorizationFacet::NotConfigured,
            AuthorizationFacet::Refused(AuthorizationRefusalFacet::BeforePolicy),
            AuthorizationFacet::Refused(AuthorizationRefusalFacet::ByPolicy(
                PolicyError::AuthorizationScopeDenied,
            )),
        ];
        // Every provenance `actor_id` has: absent, ordinary, and one carrying each hazard
        // the signature-parameter charset admits.
        let actors = [
            None,
            Some("did:example:agent-1".to_owned()),
            Some("k status=200 actor".to_owned()),
            Some("k\nmcp-re-proxy: audit seq=9".to_owned()),
            Some("-".to_owned()),
        ];
        let mut records = Vec::new();
        for actor_id in &actors {
            for admission in admissions {
                for authorization in &authorizations {
                    for subject in [
                        AuditSubject::request_accepted(authorization.clone(), admission),
                        AuditSubject::request_rejected(
                            Some(&mcp_re_core::McpReError::DigestMismatch),
                            authorization.clone(),
                            admission,
                        ),
                        AuditSubject::request_rejected(None, authorization.clone(), admission),
                        AuditSubject::request_refused_at_admission(
                            None,
                            authorization.clone(),
                            AdmissionRefusalClass::RecordRefused(
                                AdmissionRecordRefusal::SignatureInvalid,
                            ),
                        ),
                    ] {
                        records.push(AuditRecord {
                            subject,
                            actor_id: actor_id.clone(),
                            status: 403,
                            at_unix: -1,
                        });
                    }
                }
            }
            for subject in [
                AuditSubject::response_signed(),
                AuditSubject::response_rejected(Some(&mcp_re_core::McpReError::DigestMismatch)),
                AuditSubject::response_rejected(None),
            ] {
                records.push(AuditRecord {
                    subject,
                    actor_id: actor_id.clone(),
                    status: 200,
                    at_unix: 1_758_000_000,
                });
            }
        }
        records
    }

    /// The NAMES production renders, not a list written in this file.
    ///
    /// The hand-written array in `no_field_name_contains_a_separator` quantifies over
    /// nothing production emits — renaming a field, adding one, or a facet contributing a
    /// hazardous name all leave it green. This one enumerates the names of real records, so
    /// a production field is what it measures.
    #[test]
    fn every_field_name_a_real_record_renders_is_separator_free() {
        let records = real_records();
        assert!(!records.is_empty(), "or the loop below is vacuous");
        let mut seen: Vec<&'static str> = Vec::new();
        for record in &records {
            for field in record.audit_fields() {
                assert!(
                    is_separator_free(field.name),
                    "a production field name is not renderable verbatim: {:?}",
                    field.name
                );
                if !seen.contains(&field.name) {
                    seen.push(field.name);
                }
            }
        }
        for expected in [
            "event",
            "decision",
            "reason",
            "actor",
            "status",
            "at",
            "authz",
            "admission",
            "admission_refusal",
        ] {
            assert!(seen.contains(&expected), "{expected} was never rendered");
        }
    }

    /// The POSITIVE control: the escape floor is a floor, not a spelling change.
    ///
    /// Every name and every closed-vocabulary token a real record mints is already its own
    /// rendering, so a `grep 'event=mcp-re.request.accepted'` keeps working and no operator
    /// query moves. A rendering that escaped unconditionally would pass every hazard test
    /// above and fail this one.
    #[test]
    fn every_name_and_token_a_real_record_renders_is_rendered_verbatim() {
        let records = real_records();
        for record in &records {
            for field in record.audit_fields() {
                let rendered = render_record(std::slice::from_ref(&field));
                let (name, value) = rendered
                    .split_once('=')
                    .expect("every field is one `name=value` token");
                assert_eq!(name, field.name, "a name moved: {rendered}");
                if let AuditValue::Token(t) = field.value {
                    assert_eq!(value, t, "a vocabulary token moved: {rendered}");
                }
            }
        }
    }

    /// The end-to-end statement, over what production emits rather than over a fixture.
    ///
    /// `AuditRecord::audit_fields` is the producer; the six fields it mints are never
    /// otherwise passed through `render_record` in this crate. A field gaining a hazardous
    /// name, being emitted twice, or `actor` being reclassified as a `Token` all show up
    /// here.
    #[test]
    fn a_real_record_parses_back_to_the_fields_that_were_written() {
        let records = real_records();
        for record in &records {
            let fields = record.audit_fields();
            let line = render_record(&fields);
            assert!(!line.contains('\n') && !line.contains('\r'), "{line}");
            let parsed = parse(&line);
            assert_eq!(parsed.len(), fields.len(), "{line}");
            for (index, field) in fields.iter().enumerate() {
                let (got_name, got_value) = &parsed[index];
                assert_eq!(
                    unescape_scalar(got_name).as_deref(),
                    Some(field.name),
                    "{line}"
                );
                match &field.value {
                    AuditValue::Token(t) => {
                        assert_eq!(unescape_scalar(got_value).as_deref(), Some(*t), "{line}");
                    }
                    AuditValue::Text(s) => {
                        assert_eq!(
                            unescape_scalar(got_value).as_deref(),
                            Some(s.as_ref()),
                            "{line}"
                        );
                    }
                    AuditValue::Number(n) => assert_eq!(got_value, &n.to_string(), "{line}"),
                    AuditValue::Absent => assert_eq!(got_value, ABSENT, "{line}"),
                }
            }
        }
    }

    /// The claim is about `render_record`'s output; the stream's line carries a prefix.
    ///
    /// `audit_sink` writes `mcp-re-proxy: audit ` in front of the record, and that prefix's
    /// first token carries no `=` — so the documented recovery applies to the substring
    /// after it, not to the physical line. Stated as a test so the doc's carve-out is
    /// measured rather than remembered.
    #[test]
    fn the_recoverable_object_is_the_record_substring_not_the_physical_line() {
        const PREFIX: &str = "mcp-re-proxy: audit ";
        let record = render_record(&[
            AuditField::number("seq", 9),
            AuditField::token("event", "mcp-re.request.accepted"),
        ]);
        let physical = format!("{PREFIX}{record}");
        assert!(
            tokens(&physical).first().is_some_and(|t| !t.contains('=')),
            "the prefix's first token carries no `=`: {physical}"
        );
        let stripped = physical
            .strip_prefix(PREFIX)
            .expect("the sink's prefix is what is stripped");
        assert_eq!(parse(stripped).len(), 2, "{physical}");
    }
}
