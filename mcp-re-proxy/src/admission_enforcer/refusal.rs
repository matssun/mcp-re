// SPDX-License-Identifier: Apache-2.0
//! A refusal by the §7 gate: the error the client is served, and the class the record carries.
//!
//! One value so the two cannot be produced apart. The error is the frozen wire vocabulary —
//! nearly uniform, by design — and the class is the gate's own account of which fact fired;
//! a caller that held only the error would have to reconstruct the class from it, which is
//! exactly the collapse the class exists to undo.

use mcp_re_http_profile::HttpProfileError;

use super::AdmissionRefusalClass;

/// Why [`AdmissionEnforcer::decide`](super::AdmissionEnforcer::decide) refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmissionRefusal {
    error: HttpProfileError,
    class: AdmissionRefusalClass,
}

impl AdmissionRefusal {
    /// The deployment requires admission and the call carried none.
    pub(super) fn no_evidence() -> Self {
        AdmissionRefusal {
            error: HttpProfileError::MissingEvidence("admission"),
            class: AdmissionRefusalClass::NoEvidence,
        }
    }

    /// The assertion did not authenticate against the authority, the presenter or the binding.
    pub(super) fn authentication(error: HttpProfileError) -> Self {
        let class = AdmissionRefusalClass::of_authentication(&error);
        AdmissionRefusal { error, class }
    }

    /// The authenticated admission is not the authority's current statement.
    pub(super) fn currency(error: HttpProfileError) -> Self {
        let class = AdmissionRefusalClass::of_currency(&error);
        AdmissionRefusal { error, class }
    }

    /// The store answered, and what it answered is a refusal of this class.
    pub(super) fn at_store(class: AdmissionRefusalClass) -> Self {
        AdmissionRefusal {
            error: HttpProfileError::AdmissionNotCurrent,
            class,
        }
    }

    /// The replica's own window is closed: no last-known state may be served on.
    pub(super) fn window_closed() -> Self {
        AdmissionRefusal {
            error: HttpProfileError::AdmissionStateUnavailable,
            class: AdmissionRefusalClass::StateUnavailable,
        }
    }

    /// Which fact made the gate refuse.
    pub(crate) fn class(&self) -> AdmissionRefusalClass {
        self.class
    }

    /// The error the client is served.
    pub(crate) fn into_error(self) -> HttpProfileError {
        self.error
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire error and the class are separate facts: a closed window and an unauthentic
    /// store answer are different classes, and an absent record and a revoked workload share
    /// one wire error while keeping different classes.
    #[test]
    fn the_class_is_not_derivable_from_the_wire_error() {
        let absent = AdmissionRefusal::at_store(AdmissionRefusalClass::NoRecord);
        let revoked = AdmissionRefusal::currency(HttpProfileError::AdmissionNotCurrent);
        assert_eq!(absent.error, revoked.error);
        assert_ne!(absent.class(), revoked.class());
        assert_eq!(
            AdmissionRefusal::window_closed().into_error(),
            HttpProfileError::AdmissionStateUnavailable
        );
        assert_eq!(
            AdmissionRefusal::no_evidence().into_error(),
            HttpProfileError::MissingEvidence("admission")
        );
    }
}
