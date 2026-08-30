// SPDX-License-Identifier: Apache-2.0
//! WHICH headers a retained hop keeps: exactly the ones the signature base names.
//!
//! A grammar question, not a size one, and the answer has to be exact in both directions.
//! Retaining LESS than the covered set means the chain cannot be re-verified — the
//! reconstruction would fail on a hop that was perfectly valid. Retaining MORE means
//! keeping bytes nothing will ever check, and on this store those bytes are a live
//! credential.
//!
//! So the set is read out of `signature-input` rather than guessed at, and every way a
//! sender could make that header LOOK like it names more than it does is refused rather
//! than resolved: a signature PARAMETER is not a component, a decoy dictionary member is
//! not this label's list, and a component's own parameters are not component names. Each
//! of those, read loosely, would widen the retained set to headers the signature does not
//! cover.

/// written to a store that holds credential material.
///
/// The covered set is read from the ONE `Signature-Input` dictionary member the verifier
/// checked — `label`, which is [`mcp_re_http_profile::REQUEST_LABEL`] for a request and
/// [`mcp_re_http_profile::RESPONSE_LABEL`] for a response — and from inside that member's
/// component list `( … )` only. Both restrictions are load-bearing. Verification reads a
/// single member and ignores every other one, so a client may add `decoy=("cookie")` to a
/// value that verifies normally; and a component may carry its own parameters, so
/// `("@method";key="cookie")` names one component, not two. Neither may decide what is
/// retained.
pub(super) fn covered_headers(headers: &[(String, String)], label: &str) -> Vec<(String, String)> {
    let mut covered: Vec<String> = Vec::new();
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("signature-input") {
            continue;
        }
        let Some(list) = component_list_for(value, label) else {
            continue;
        };
        for component in component_names(list) {
            // `@method`, `@target-uri`, … are derived, not headers.
            if !component.starts_with('@') {
                covered.push(component.to_ascii_lowercase());
            }
        }
    }
    headers
        .iter()
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            lower == "signature" || lower == "signature-input" || covered.contains(&lower)
        })
        .cloned()
        .collect()
}

/// The `( … )` component list of the dictionary member named `label`, if it has one.
fn component_list_for<'a>(value: &'a str, label: &str) -> Option<&'a str> {
    for member in dictionary_members(value) {
        let Some((name, rest)) = member.split_once('=') else {
            continue;
        };
        if name.trim() != label {
            continue;
        }
        // Class B: the brackets are split ON, so their widths are not restated as offsets.
        let (_, tail) = rest.split_once('(')?;
        let (list, _) = tail.split_once(')')?;
        return Some(list);
    }
    None
}

/// The top-level members of a structured-fields dictionary: commas inside a quoted string
/// do not separate members.
// Class C: `index` is a byte offset from `char_indices` at an ASCII comma, so `index + 1`
// is a char boundary at most `value.len()`.
#[allow(clippy::arithmetic_side_effects)]
fn dictionary_members(value: &str) -> Vec<&str> {
    let mut members = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => {
                members.push(&value[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    members.push(&value[start..]);
    members
}

/// The component names in one component list: the leading quoted token of each
/// whitespace-separated item, so an item's own `;key="…"` parameters are not names.
fn component_names(list: &str) -> impl Iterator<Item = &str> {
    list.split_whitespace().filter_map(|item| {
        let rest = item.strip_prefix('"')?;
        let end = rest.find('"')?;
        Some(&rest[..end])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// not widen what is kept: only the `( … )` component list is the covered set.
    #[test]
    fn a_signature_parameter_cannot_widen_the_covered_set() {
        let headers = vec![
            (
                "Signature-Input".to_owned(),
                "mcp-re=(\"@method\");keyid=\"cookie\"".to_owned(),
            ),
            ("cookie".to_owned(), "session=secret".to_owned()),
        ];
        let kept = covered_headers(&headers, mcp_re_http_profile::REQUEST_LABEL);
        assert!(
            !kept.iter().any(|(name, _)| name == "cookie"),
            "kept {kept:?}"
        );
    }

    /// R8-C042/C121: a second dictionary member is not the covered set.
    ///
    /// The verifier reads ONE member and ignores every other, so a value carrying a
    /// decoy label verifies exactly as it would without it. If retention unioned the
    /// members instead, an enrolled client could name any header it liked — its own
    /// `cookie`, or an internal header an ingress adds that the client cannot even read
    /// — and have it written verbatim into a store of credential material with no
    /// expiry.
    #[test]
    fn a_decoy_dictionary_member_cannot_widen_the_covered_set() {
        let headers = vec![
            (
                "Signature-Input".to_owned(),
                "mcp-re=(\"@method\" \"authorization\");keyid=\"k\", \
                 decoy=(\"cookie\" \"x-forwarded-client-cert\")"
                    .to_owned(),
            ),
            ("authorization".to_owned(), "Bearer live".to_owned()),
            ("cookie".to_owned(), "session=secret".to_owned()),
            (
                "x-forwarded-client-cert".to_owned(),
                "By=spiffe://mesh".to_owned(),
            ),
        ];
        let kept = covered_headers(&headers, mcp_re_http_profile::REQUEST_LABEL);
        let names: Vec<&str> = kept.iter().map(|(name, _)| name.as_str()).collect();
        assert!(
            !names.contains(&"cookie") && !names.contains(&"x-forwarded-client-cert"),
            "an unverified dictionary member decided what is retained: {names:?}"
        );
        assert!(
            names.contains(&"authorization"),
            "the verified member's own covered header must still be kept: {names:?}"
        );
    }
}
