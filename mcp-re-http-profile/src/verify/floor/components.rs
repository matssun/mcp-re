// SPDX-License-Identifier: Apache-2.0
//! What the signature must cover.
//!
//! One authority: **a component the profile relies on is inside the signature base, not
//! beside it.** Two rules with one subject:
//!
//! - the UNCONDITIONAL set a message shape requires ([`require_components`]);
//! - the PRESENT ⇒ COVERED set ([`require_conditional_coverage`]) — presence is the
//!   condition rather than a configured protocol version, because that is the question the
//!   verifier can answer from the message in front of it.
//!
//! Both are shared by the bodied and BODYLESS paths. The bodyless path (§8.1) once had
//! neither, so a bodyless request could carry an `Authorization: Bearer <token>` entirely
//! outside its signature and an intermediary could swap the presented credential without
//! invalidating anything. Two copies of a rule this shape is how one of them ends up
//! missing, so there is one copy.

use crate::error::HttpProfileError;
use crate::message::single_header;
use crate::sigbase::CoveredComponent;

use super::transport_headers::MCP_COVERABLE_TRANSPORT_HEADERS;

pub(crate) fn require_components(
    covered: &[CoveredComponent],
    required_plain: &[&'static str],
    required_req: &[&'static str],
) -> Result<(), HttpProfileError> {
    for name in required_plain {
        if !covered.iter().any(|c| !c.req && c.name == *name) {
            return Err(HttpProfileError::MissingCoveredComponent(name));
        }
    }
    for name in required_req {
        if !covered.iter().any(|c| c.req && c.name == *name) {
            return Err(HttpProfileError::MissingCoveredComponent(name));
        }
    }
    Ok(())
}
/// Enforce PRESENT ⇒ COVERED for every conditionally-mandatory request header
/// (§4.1): `authorization`, `dpop`, and the MCP transport headers.
///
/// Presence is the condition rather than a configured protocol version, because that
/// is the question the verifier can answer from the message in front of it: if the
/// sender put the header on the wire, the signature covers it or the request is
/// rejected. A deployment whose version does not define these simply never sends them
/// and nothing here fires.
///
/// Shared by the bodied and BODYLESS request paths. The bodyless path (§8.1) had none
/// of these checks, which meant a bodyless request could carry an
/// `Authorization: Bearer <token>` — or an `Mcp-Method` contradicting nothing because
/// there is no body to contradict — entirely outside its signature. An intermediary
/// could then add or swap the presented credential without invalidating anything,
/// which is precisely what covering it prevents on the bodied path. Two copies of a
/// rule this shape is how one of them ends up missing, so there is one copy.
pub(crate) fn require_conditional_coverage(
    headers: &[(String, String)],
    covered: &[CoveredComponent],
) -> Result<(), HttpProfileError> {
    for header in conditionally_covered_request_headers() {
        // `single_header` also fails closed on a duplicated header, so a smuggled
        // second `authorization` cannot slip past by being the uncovered one.
        if single_header(headers, header)?.is_some()
            && !covered.iter().any(|c| !c.req && c.name == header)
        {
            return Err(HttpProfileError::MissingCoveredComponent(header));
        }
    }
    Ok(())
}
/// Every request header that is mandatory-if-present, in one place so the signer and
/// the verifier cannot disagree about the set: `authorization`/`dpop` bind the presented
/// credential surface, and [`MCP_COVERABLE_TRANSPORT_HEADERS`] binds the routing claims
/// made in the clear (whose rationale lives on that constant).
pub(crate) fn conditionally_covered_request_headers() -> impl Iterator<Item = &'static str> {
    ["authorization", "dpop"]
        .into_iter()
        .chain(MCP_COVERABLE_TRANSPORT_HEADERS)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED: [&str; 5] = [
        "authorization",
        "dpop",
        "mcp-method",
        "mcp-name",
        "mcp-protocol-version",
    ];

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
            .collect()
    }

    fn mixed_case(name: &str) -> String {
        name.split('-')
            .map(|part| {
                let mut chars = part.chars();
                chars
                    .next()
                    .map(|first| first.to_ascii_uppercase().to_string() + chars.as_str())
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>()
            .join("-")
    }

    #[test]
    fn the_conditionally_covered_set_is_exactly_the_credential_and_transport_headers() {
        let set: Vec<&str> = conditionally_covered_request_headers().collect();
        assert_eq!(set, EXPECTED);
    }

    #[test]
    fn every_conditionally_covered_header_present_but_uncovered_is_refused() {
        for name in EXPECTED {
            let hs = headers(&[(&mixed_case(name), "x")]);
            let uncovered = [CoveredComponent::new("@method")];
            assert_eq!(
                require_conditional_coverage(&hs, &uncovered),
                Err(HttpProfileError::MissingCoveredComponent(name))
            );
            let covered = [CoveredComponent::new("@method"), CoveredComponent::new(name)];
            assert_eq!(require_conditional_coverage(&hs, &covered), Ok(()));
        }
    }

    #[test]
    fn a_duplicated_conditionally_covered_header_is_refused_even_when_one_is_covered() {
        let hs = headers(&[("Authorization", "a"), ("authorization", "b")]);
        let covered = [CoveredComponent::new("authorization")];
        assert_eq!(
            require_conditional_coverage(&hs, &covered),
            Err(HttpProfileError::DuplicateHeader("authorization"))
        );
    }

    #[test]
    fn a_req_flagged_component_does_not_cover_a_present_request_header() {
        let hs = headers(&[("DPoP", "x")]);
        let covered = [CoveredComponent::req("dpop")];
        assert_eq!(
            require_conditional_coverage(&hs, &covered),
            Err(HttpProfileError::MissingCoveredComponent("dpop"))
        );
    }

    #[test]
    fn require_components_refuses_a_missing_component_and_admits_a_superset() {
        assert_eq!(
            require_components(
                &[CoveredComponent::new("@method")],
                &["@method", "content-digest"],
                &[]
            ),
            Err(HttpProfileError::MissingCoveredComponent("content-digest"))
        );
        assert_eq!(
            require_components(
                &[
                    CoveredComponent::new("@method"),
                    CoveredComponent::new("content-digest"),
                    CoveredComponent::new("content-length"),
                ],
                &["@method", "content-digest"],
                &[]
            ),
            Ok(())
        );
        assert_eq!(
            require_components(&[CoveredComponent::req("@method")], &["@method"], &[]),
            Err(HttpProfileError::MissingCoveredComponent("@method"))
        );
    }
}
