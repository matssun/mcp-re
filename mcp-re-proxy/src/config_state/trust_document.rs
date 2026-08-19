// SPDX-License-Identifier: Apache-2.0
//! Where the request-signer set is read from, as one owned fact.
//!
//! `--trust` names the document every request signer is resolved against. It had no owner,
//! so it travelled as a bare `String`: validated once in the boundary's residue, then
//! carried into `TrustPlan` beside a sealed `TrustRevocationState` as a public field. That
//! pairing is the defect — the revocation machine owns HOW the document is observed, and
//! nothing owned WHICH document, so a plan could be assembled holding one deployment's
//! revocation posture and another's locator.
//!
//! ```text
//!     --trust  ──▶  TrustDocumentSource   ← the only authority over the locator
//!                          │
//!                          ├──▶  TrustPlan (sealed, with the revocation posture)
//!                          └──▶  any other legitimate consumer
//! ```
//!
//! # What this owner claims, and what it must not
//!
//! It claims exactly one thing: **the locator names something**. That is purely knowable
//! from the request (ADR-MCPRE-056 §5.1) and needs no filesystem.
//!
//! It deliberately does NOT claim the file exists, is readable, parses, or holds a key the
//! deployment trusts. Those are observations, and they belong to materialization — a
//! locator owner that claimed them would be asserting at plan time a fact only
//! `load_trust_snapshot` can establish, and the plane would then have a reason to re-check
//! what its input already promised.
//!
//! The stored path is the operator's string **verbatim**. Emptiness is judged on the
//! trimmed value because a path of blanks names nothing, but the value handed to the
//! filesystem is never rewritten: a proxy must open the path the operator wrote, not a
//! normalization of it.

use crate::deployment_request::DeploymentRequest;

/// The trust document this deployment reads its request-signer set from.
///
/// The representation is private to this module, so the only way to hold one is to have
/// gone through a constructor that refused an empty locator. Possession IS the statement
/// that the deployment named a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustDocumentSource {
    path: String,
}

impl TrustDocumentSource {
    /// The only public constructor, and it performs the check.
    ///
    /// `None` when the locator names nothing. Construction itself validates, so a
    /// `TrustDocumentSource` means the same thing whichever crate built it — the guarantee
    /// travels with the value rather than with the classifier that usually produces it.
    pub fn new(path: impl Into<String>) -> Option<Self> {
        let path = path.into();
        (!path.trim().is_empty()).then_some(Self { path })
    }

    /// The locator, verbatim, for the code that opens it.
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Resolve the locator, or say why the deployment names no trust document.
///
/// The guard moved here from the validation residue, which is where rules with no owner
/// live; this one now has one. An empty locator gates construction rather than being
/// reported beside a usable value.
pub fn classify_and_validate(
    config: &DeploymentRequest,
) -> (Option<TrustDocumentSource>, Vec<String>) {
    match TrustDocumentSource::new(config.trust_path.clone()) {
        Some(source) => (Some(source), Vec::new()),
        None => (
            None,
            vec![
                "--trust is empty: it names the trust document the request-signer set is \
                  read from, so an empty path leaves no signer trusted and no file to say so"
                    .to_string(),
            ],
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_for(path: &str) -> Option<TrustDocumentSource> {
        let mut config = crate::config_state::test_support::legal_config();
        config.trust_path = path.to_string();
        classify_and_validate(&config).0
    }

    /// A locator that names nothing resolves no source, so no plan can carry one.
    #[test]
    fn a_locator_that_names_nothing_resolves_no_source() {
        assert!(source_for("").is_none(), "an empty path names nothing");
        assert!(
            source_for("   ").is_none(),
            "a path of blanks names nothing either"
        );
        assert!(source_for("/trust.json").is_some());
    }

    /// The path reaches the filesystem exactly as written.
    ///
    /// Trimming to decide emptiness and trimming the stored value are different acts. The
    /// second would silently open a different file than the operator named, which is the
    /// class of helpfulness a trust locator must not have.
    #[test]
    fn the_stored_path_is_the_operators_string_verbatim() {
        let source = source_for(" /trust.json ").expect("a non-blank path resolves");
        assert_eq!(source.path(), " /trust.json ");
    }

    /// The public constructor carries the same guard, so no crate can hold a source over a
    /// locator the classifier would have refused.
    #[test]
    fn the_public_constructor_validates_too() {
        assert!(TrustDocumentSource::new("").is_none());
        assert!(TrustDocumentSource::new("\t\n ").is_none());
        assert_eq!(
            TrustDocumentSource::new("/etc/mcp-re/trust.json")
                .expect("a named document")
                .path(),
            "/etc/mcp-re/trust.json"
        );
    }

    /// The refusal names the flag, because that is what an operator can act on.
    #[test]
    fn the_refusal_names_the_flag() {
        let mut config = crate::config_state::test_support::legal_config();
        config.trust_path = String::new();
        let (source, violations) = classify_and_validate(&config);
        assert!(source.is_none());
        assert!(
            violations.iter().any(|v| v.contains("--trust is empty")),
            "got: {violations:?}"
        );
    }
}
