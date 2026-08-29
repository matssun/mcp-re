// SPDX-License-Identifier: Apache-2.0
//! Whether a call must carry admission evidence, and what verifies it — ADR-MCPRE-067 §7.
//!
//! ```text
//! semantic role       whether an unadmitted call is served
//!         ↓
//! typed selection     AdmissionRequest
//!         ↓
//! gate inputs         AdmissionGateRequest — the authority, its record, its availability
//!         ↓
//! mechanism payload   SharedStoreRequest / the base64url Ed25519 encoding
//! ```
//!
//! **`NotEnforced` is an explicit operator decision, not an absence** — which is why its
//! parameters used to be refused rather than ignored: an `--admission-redis-url` beside
//! `--admission off` reads to an auditor as *admission is configured* while nothing is.
//! The gate's inputs now live INSIDE the two enforcing forms, so there is no `off` to hang
//! them from and the five dangling clauses have no configuration to examine.
//!
//! The degraded table went the same way. Two of its four cells were refusals — a bound
//! configured where nothing reads it, and a degraded window of zero width — and both are
//! unrepresentable: the availability is one tagged value, and the bound is a `NonZeroU64`
//! carried only by the arm that opens a window.

mod availability;
mod gate;

pub use availability::AdmissionAvailabilityRequest;
pub use gate::AdmissionGateRequest;

/// What a call carrying no admission evidence means here.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AdmissionRequest {
    /// The gate is not applied. Admission evidence, if present, decides nothing.
    #[default]
    NotEnforced,
    /// Evidence is verified when presented; its absence is not a refusal. For a rollout
    /// that has not reached every client.
    Optional(AdmissionGateRequest),
    /// A call with no admission evidence is refused.
    Required(AdmissionGateRequest),
}

impl AdmissionRequest {
    /// The gate's inputs, where a gate is applied.
    ///
    /// `None` is not a missing value: the unenforced form has no authority, no record and
    /// no availability question, because there is nothing that could be unreachable.
    pub fn gate(&self) -> Option<&AdmissionGateRequest> {
        match self {
            AdmissionRequest::NotEnforced => None,
            AdmissionRequest::Optional(gate) | AdmissionRequest::Required(gate) => Some(gate),
        }
    }

    /// Whether a gate is applied at all.
    pub fn is_enforced(&self) -> bool {
        self.gate().is_some()
    }

    /// The operator-facing spelling, for a diagnostic that must name what was asked for.
    pub fn flag_value(&self) -> &'static str {
        match self {
            AdmissionRequest::NotEnforced => "off",
            AdmissionRequest::Optional(_) => "optional",
            AdmissionRequest::Required(_) => "required",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment_request::SharedStoreRequest;
    use std::num::NonZeroU64;

    fn gate() -> AdmissionGateRequest {
        AdmissionGateRequest {
            authority_kid: "authority-1".to_string(),
            authority_pubkey_b64url: "k".to_string(),
            store: SharedStoreRequest::redis("redis://127.0.0.1:6379"),
            availability: AdmissionAvailabilityRequest::FailClosed,
        }
    }

    /// The unenforced form carries no gate inputs, so the five dangling clauses have
    /// nothing to refuse: there is no place to put an authority beside `off`.
    #[test]
    fn the_unenforced_form_has_no_gate_inputs_to_dangle() {
        assert_eq!(AdmissionRequest::default(), AdmissionRequest::NotEnforced);
        assert!(AdmissionRequest::NotEnforced.gate().is_none());
        assert!(!AdmissionRequest::NotEnforced.is_enforced());
    }

    /// Both enforcing forms carry the same inputs, and the projection hands them back as
    /// one value — a consumer cannot take the strictness from one form and the authority
    /// from another.
    #[test]
    fn both_enforcing_forms_carry_the_gate_they_apply() {
        for form in [
            AdmissionRequest::Optional(gate()),
            AdmissionRequest::Required(gate()),
        ] {
            let named = form.flag_value();
            let held = form
                .gate()
                .unwrap_or_else(|| panic!("{named} applies a gate"));
            assert_eq!(held.authority_kid, "authority-1");
            assert!(form.is_enforced());
        }
    }

    /// A degraded window is a positive number carried by the arm that opens one. The two
    /// refused cells of the old table — a bound nothing reads, and a zero-width window —
    /// cannot be written.
    #[test]
    fn a_degraded_window_exists_only_where_one_opens_and_only_above_zero() {
        let degraded = AdmissionAvailabilityRequest::Degraded {
            bound_secs: NonZeroU64::new(30).expect("a positive window"),
        };
        assert_eq!(degraded.bound_secs(), Some(30));
        assert_eq!(AdmissionAvailabilityRequest::FailClosed.bound_secs(), None);
    }
}
