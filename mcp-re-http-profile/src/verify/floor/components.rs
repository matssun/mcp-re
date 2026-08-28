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
