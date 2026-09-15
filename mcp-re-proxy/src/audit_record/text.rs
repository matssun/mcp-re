// SPDX-License-Identifier: Apache-2.0
//! How an arbitrary scalar is SPELLED inside a line-oriented audit record.
//!
//! The property, stated once:
//!
//! > One logical audit record produces exactly one physical audit record, and no field
//! > value can synthesize a new field or a new line.
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
//! reach a separator. [`AuditValue::Token`] is `&'static str` precisely so the
//! classification is checkable: a string read out of a request body cannot be `'static`, so
//! calling client-chosen text a token is a compile error rather than a review finding.
//!
//! **Not in scope: a length bound.** The record carries no cap on a value's size. That is
//! the sink's bounded-queue economics, and truncation is lossy — adding it here would
//! destroy the injectivity this module exists to establish. A bound belongs where
//! `STDERR_AUDIT_QUEUE_DEPTH` lives, expressed as a refusal or as a digest-plus-marker,
//! never as a silent cut.
//!
//! **Not in scope: the drop warning.** `audit_sink`'s `dropped={n}` line is prose that
//! happens to open with a `key=value`, not a record; its one value is a `u64`, and
//! `app.rs` distinguishes records from it by the literal `audit seq=` prefix. Converting it
//! would be churn with no property attached.

use super::scalar::escape_scalar;
use super::scalar::is_separator_free;

/// The reserved rendering of [`AuditValue::Absent`]: *the owner resolved nothing*.
///
/// Disjoint from every escaped scalar, because `escape_scalar` spells a leading `-` as an
/// escape. *Nobody was resolved* and *the resolved name is `-`* are different facts and stay
/// different bytes.
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
/// For any input whatsoever the returned `String` contains no U+000A and no U+000D, each
/// field contributes exactly one whitespace-delimited token, each token contains exactly one
/// `=`, and the field sequence is recoverable by `split(' ')`, `split_once('=')` and
/// [`unescape_scalar`]. The caller appends exactly one U+000A.
pub(crate) fn render_record(fields: &[AuditField<'_>]) -> String {
    let mut out = String::new();
    for field in fields {
        if !out.is_empty() {
            out.push(' ');
        }
        debug_assert!(
            is_separator_free(field.name),
            "an audit field name may not carry a separator: {:?}",
            field.name
        );
        out.push_str(field.name);
        out.push('=');
        match &field.value {
            AuditValue::Token(t) => {
                debug_assert!(
                    is_separator_free(t),
                    "a token is a closed vocabulary member and may not carry a separator: \
                     {t:?} — classify it as Text"
                );
                out.push_str(t);
            }
            AuditValue::Number(n) => out.push_str(&n.to_string()),
            AuditValue::Text(s) => out.push_str(&escape_scalar(s)),
            AuditValue::Absent => out.push_str(ABSENT),
        }
    }
    out
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_record::scalar::unescape_scalar;

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
}
