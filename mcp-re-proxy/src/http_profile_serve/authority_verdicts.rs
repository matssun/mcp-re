// SPDX-License-Identifier: Apache-2.0
//! What the request-side authorities established for one exchange, as independent
//! coordinates.
//!
//! ADR-MCPRE-066's algebra — two authorities, one record — given a type. They were two
//! fields on [`Exchange`](super::Exchange) until the §7 admission verdict joined the
//! authorization one (R11-106) and the pair became a concept rather than a coincidence:
//! same shape, same lifetime, same single writer, same single reader.
//!
//! `None` on either is not missing data. It states that **no verdict was reached**, which is
//! the thing a refusal named before that authority ran has to report — and a fact no refusal
//! CAUSE can derive from its own kind, because the same Core verdict is reachable on both
//! sides of a policy. A stage refusing after a PERMIT would otherwise record that nothing
//! decided.

use crate::admission_enforcer::AdmissionFacet;
use crate::authorization::AuthorizationFacet;

/// The two request-side verdicts, each in its own authority's vocabulary.
///
/// Written by the admission region, which is the authority that obtains them, and read by
/// the refusal composition. A stage between neither sets nor clears them.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct AuthorityVerdicts {
    /// What this deployment's authorization authority established.
    pub(super) authorization: Option<AuthorizationFacet>,
    /// What the §7 admission gate established. Rendered `not-reached` when absent, never as
    /// a guess at one of its four verdicts.
    pub(super) admission: Option<AdmissionFacet>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh exchange has reached NEITHER authority, and the two are separately settable.
    ///
    /// The property that matters is that they do not move together: an exchange can refuse
    /// after admission and before authorization, and the record has to say exactly that. A
    /// single "verdicts reached" flag — the shape this type exists instead of — could not.
    #[test]
    fn the_two_verdicts_start_absent_and_are_set_independently() {
        let mut v = AuthorityVerdicts::default();
        assert_eq!(v.authorization, None);
        assert_eq!(v.admission, None);
        v.admission = Some(AdmissionFacet::LiveConfirmed);
        assert_eq!(
            v.authorization, None,
            "admission does not settle authorization"
        );
        v.authorization = Some(AuthorizationFacet::NotConfigured);
        assert_eq!(v.admission, Some(AdmissionFacet::LiveConfirmed));
    }
}
