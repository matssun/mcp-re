// SPDX-License-Identifier: Apache-2.0
//! The RFC 9421 `Signature-Input` member value: what was signed.
//!
//! One authority: **a member value is an inner list followed by a parameter tail, and both
//! halves are read in exactly one spelling.** The two closed sets themselves belong to their
//! own owners — [`super::covered_components`] and [`super::signature_parameters`] — because
//! they are two independently describable rules over two different vocabularies. What is
//! left here is the shape they sit in, which is why the function that states it is short.
//!
//! Reading the DICTIONARY this member lives in is [`super::sf_dictionary`]'s: a different
//! specification, a different closed set, and the collapse argument that motivates every
//! refusal in this subtree is stated there once.

use crate::error::HttpProfileError;
use crate::message::required_header;
use crate::sigbase::CoveredComponent;
use crate::sigbase::SignatureParams;

use super::covered_components::parse_covered_components;
use super::sf_dictionary::member_value;
use super::signature_parameters::parse_signature_parameters;

/// One parsed `Signature-Input` dictionary member.
pub(crate) struct ParsedSignatureInput {
    pub(crate) components: Vec<CoveredComponent>,
    pub(crate) params: SignatureParams,
}

/// Parse one `("a" "b";req ...);k=v;...` signature-input member value.
///
/// `pub(crate)`: the five verification stages and the two bodyless shapes all read this one
/// grammar. A second parser would be a second place for the closed allowlists to drift, and
/// the drift would be silent — both copies would still fail closed while disagreeing about
/// which wire forms are the same message.
pub(crate) fn parse_signature_input(value: &str) -> Result<ParsedSignatureInput, HttpProfileError> {
    let value = value.trim();
    if !value.starts_with('(') {
        return Err(HttpProfileError::MalformedEvidence("inner list"));
    }
    let close = value
        .find(')')
        .ok_or(HttpProfileError::MalformedEvidence("inner list"))?;
    let list = value
        .get(1..close)
        .ok_or(HttpProfileError::MalformedEvidence("inner list"))?;
    // Class C: `close` is a byte position inside `value`; `get` decides the range.
    #[allow(clippy::arithmetic_side_effects)]
    let after_close = close + 1;
    let param_tail = value
        .get(after_close..)
        .ok_or(HttpProfileError::MalformedEvidence("inner list"))?;
    Ok(ParsedSignatureInput {
        components: parse_covered_components(list)?,
        params: parse_signature_parameters(param_tail)?,
    })
}
/// Parse the `Signature-Input` member for `label`. Shared with the bodyless
/// component sets (`crate::bodyless`) so both read one grammar: a second parser
/// would be a second place for the closed allowlist to drift.
pub(crate) fn parse_signature_input_for(
    headers: &[(String, String)],
    label: &str,
    what: &'static str,
) -> Result<ParsedSignatureInput, HttpProfileError> {
    let input_header = required_header(headers, "signature-input")
        .map_err(|_| HttpProfileError::MissingEvidence(what))?;
    parse_signature_input(member_value(input_header, label)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANONICAL: &str = r#"("@method" "@target-uri" "content-digest");created=1700000000;expires=1700000300;nonce="n";keyid="k";alg="ed25519""#;

    /// The verifier rebuilds `@signature-params` from PARSED values and re-serialises
    /// canonically, so any wire spelling it silently normalises away verifies under the
    /// same signature as the canonical one. That breaks the one-to-one correspondence
    /// between the received bytes and the signed bytes the profile claims — an
    /// intermediary could rewrite the raw header and nothing would notice.
    #[test]
    fn alternate_signature_input_spellings_are_refused_not_normalised() {
        parse_signature_input(CANONICAL).expect("the canonical form parses");

        let alternates = [
            // Inner-list whitespace.
            r#"("@method"  "@target-uri" "content-digest");created=1700000000;expires=1700000300;nonce="n";keyid="k";alg="ed25519""#,
            "(\"@method\"\t\"@target-uri\" \"content-digest\");created=1700000000;expires=1700000300;nonce=\"n\";keyid=\"k\";alg=\"ed25519\"",
            r#"( "@method" "@target-uri" "content-digest");created=1700000000;expires=1700000300;nonce="n";keyid="k";alg="ed25519""#,
            r#"("@method" "@target-uri" "content-digest" );created=1700000000;expires=1700000300;nonce="n";keyid="k";alg="ed25519""#,
            // Parameter spacing and empty slots.
            r#"("@method" "@target-uri" "content-digest") ;created=1700000000;expires=1700000300;nonce="n";keyid="k";alg="ed25519""#,
            r#"("@method" "@target-uri" "content-digest");created=1700000000;expires=1700000300;nonce="n";keyid="k";alg="ed25519";"#,
            r#"("@method" "@target-uri" "content-digest");created=1700000000;;expires=1700000300;nonce="n";keyid="k";alg="ed25519""#,
            r#"("@method" "@target-uri" "content-digest");created=1700000000; expires=1700000300;nonce="n";keyid="k";alg="ed25519""#,
        ];
        for alternate in alternates {
            assert!(
                parse_signature_input(alternate).is_err(),
                "must be refused rather than normalised: {alternate}"
            );
        }
    }

    /// A space inside a quoted parameter value is a legitimate byte of that value, not
    /// a spelling variant — refusing it would break keyids and nonces the profile
    /// admits.
    #[test]
    fn a_space_inside_a_quoted_parameter_value_is_kept() {
        let with_space = r#"("@method");created=1700000000;expires=1700000300;nonce="n";keyid="key one";alg="ed25519""#;
        let parsed = parse_signature_input(with_space).expect("a quoted space is data");
        assert_eq!(parsed.params.keyid.as_deref(), Some("key one"));
    }
}
