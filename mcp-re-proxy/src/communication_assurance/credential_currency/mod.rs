// SPDX-License-Identifier: Apache-2.0
//! Whether the credential a relationship authenticated with is still acceptable NOW —
//! ADR-MCPRE-064, Slice 3.
//!
//! # The proposition
//!
//! Possession of [`CurrentCredentialFacts`] means:
//!
//! > At this instant, under this deployment's configured currency controls, the credential
//! > the establishment mechanism accepted for this relationship is still acceptable: its
//! > leaf is inside its own validity window, within any configured lifetime ceiling, and
//! > admitted by the CRLs in force; and every issuer it presented is inside its own window
//! > and not explicitly revoked.
//!
//! # Why the outcome has three states and not two
//!
//! Production returns before parsing anything when a deployment configures neither a
//! lifetime ceiling nor CRLs. **Nothing is checked in that deployment — not even expiry**,
//! so a peer holding a keep-alive or HTTP/2 connection open past its `notAfter` keeps being
//! served. The handshake caught it once; nothing catches it again.
//!
//! A two-state answer would report that deployment as *no currency objection*, which is the
//! same sentence as *checked, and fine*. [`CredentialCurrencyOutcome::NotEvaluated`] is a
//! distinct state so a consumer can tell **nobody asked** from **asked and satisfied**, and
//! so the product is unobtainable where its premise is absent rather than vacuously true.
//!
//! # Why the policy is an enum and not two `Option`s
//!
//! The controls are a lifetime ceiling and a CRL index, each independently configured — and
//! *neither configured* is the state that changes what the authority does at all. Carried as
//! two `Option`s, `NotEvaluated` would be a fourth combination that callers must remember to
//! check, and *evaluated with nothing to evaluate* would be a fifth that means nothing.
//! [`CredentialCurrencyPolicy`] enumerates the four legal deployments and makes the fifth
//! unrepresentable.
//!
//! # The distinctions this authority refuses to collapse
//!
//! Production computes five separable facts and returns one `Option<Vec<u8>>`, so nothing
//! downstream can tell an expired credential from a revoked one from an absent one. The
//! conjunction is unchanged here — the same requests are admitted — but the refusal names
//! which fact failed, and in particular preserves the strength asymmetry that one boolean
//! was hiding:
//!
//! ```text
//! leaf     revocation goes through `admits`      Unknown REFUSES
//! issuer   revocation compares != Revoked        Unknown ADMITS
//! ```
//!
//! That asymmetry is deliberate and is kept, not repaired: whether a chain reaches a
//! CRL-covered issuer is a path-building question the handshake already settled, and
//! re-deciding it here from the certificates the peer chose to send would refuse chains a
//! full handshake admitted. An authority whose algebra is more precise than its semantics
//! would report the wrong fact; one that is less precise reports no fact at all.
//!
//! # What this authority does NOT establish
//!
//! Not identity, not authentication, not admission, not authorization. It is a predicate on
//! an accepted credential at an instant, and it says nothing about who the peer is — which
//! is why it consumes the ACCEPTANCE rather than the authenticated peer. Under
//! `IdentityStrategy::LbAssertion` no transport identity is derived at all and currency
//! still applies to the credential the mechanism accepted; an authority gated on
//! authentication would silently stop checking currency in exactly that deployment.
//!
//! The composition with an authenticated peer is [`super::current_authenticated_peer`],
//! which derives currency from that peer's OWN acceptance.

pub(crate) mod evaluation;
pub mod policy;
mod x509_adapter;

pub use policy::CredentialCurrencyPolicy;
pub use policy::CurrencyControls;

use crate::client_revocation::RevocationVerdict;
use crate::communication_assurance::mechanism_verified_credential::MechanismVerifiedCredentialEvidence;

/// The credential this relationship authenticated with is acceptable at `evaluated_at`.
///
/// Sealed: the representation is private to this module tree and the constructor is private
/// to it, so the only inhabitants are the ones [`evaluation::evaluate_credential_currency`]
/// produced from an acceptance it was handed. Borrowed rather than owned — this is read on
/// every request of every keep-alive connection, and cloning a credential chain per request
/// is a cost with no fact behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentCredentialFacts<'a> {
    /// The acceptance this is about, carried WHOLE rather than destructured (R-COMPOSE).
    accepted: &'a MechanismVerifiedCredentialEvidence,
    /// The instant the evaluation was made. Currency is a claim about a moment, and a
    /// product that omitted it would be read as a standing property.
    evaluated_at: i64,
    /// Which optional controls actually ran.
    applied: CurrencyControls,
}

impl<'a> CurrentCredentialFacts<'a> {
    /// Record an evaluated, acceptable credential. PRIVATE to this authority: reachable by
    /// this module and its descendants — the evaluator, which is the one production call
    /// site — and by nothing else in the crate.
    fn evaluated(
        accepted: &'a MechanismVerifiedCredentialEvidence,
        evaluated_at: i64,
        applied: CurrencyControls,
    ) -> Self {
        CurrentCredentialFacts {
            accepted,
            evaluated_at,
            applied,
        }
    }

    /// The acceptance whose credential was evaluated.
    pub fn accepted(&self) -> &MechanismVerifiedCredentialEvidence {
        self.accepted
    }

    /// The instant this credential was found acceptable.
    pub fn evaluated_at(&self) -> i64 {
        self.evaluated_at
    }

    /// Which optional controls ran.
    pub fn applied_controls(&self) -> CurrencyControls {
        self.applied
    }
}

/// What a per-request currency evaluation concluded.
///
/// Three states, because *nobody asked* and *asked and satisfied* are different facts and a
/// deployment can be in either. A `Result<Option<_>, _>` would spell the same three, and
/// would leave the reading of the `None` to whoever matched on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialCurrencyOutcome<'a> {
    /// The deployment configures no currency control, so nothing was evaluated. The
    /// credential is not thereby current — it is unexamined.
    NotEvaluated,
    /// Evaluated, and acceptable now.
    Current(CurrentCredentialFacts<'a>),
    /// Evaluated, and refused. The variant names WHICH fact failed.
    Refused(CredentialCurrencyRefusal),
}

/// Why an accepted credential is not acceptable now.
///
/// Unlike the mechanism-boundary algebras of Slices 1 and 4, **these are reachable legal
/// domain states**: a credential really does expire on an open connection, and an operator
/// really does revoke one. That is the difference this authority exists to make visible —
/// production collapses all seven into one `mcp-re.transport_binding_failed`, so nothing
/// downstream can tell an expired credential from a revoked one from an absent one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialCurrencyRefusal {
    /// No leaf was presented, its DER does not parse, or its validity window is not
    /// orderable (`notAfter <= notBefore`) — a certificate that never had a window rather
    /// than one that has closed.
    CredentialUnreadable,
    /// The leaf's own validity window does not contain this instant. Independent of every
    /// configured control: a short-lived certificate satisfies a span ceiling for the rest
    /// of time, so without this a peer keeping one connection open keeps serving expired.
    LeafOutsideValidityWindow {
        /// The window's start, Unix seconds.
        not_before: i64,
        /// The window's end, Unix seconds, exclusive.
        not_after: i64,
    },
    /// The leaf's validity SPAN exceeds the configured ceiling — the short-lived-credential
    /// posture, and a different question from whether the window contains now.
    LeafExceedsConfiguredLifetime {
        /// `notAfter - notBefore`, seconds.
        span_secs: i64,
        /// The configured maximum, seconds.
        ceiling_secs: i64,
    },
    /// The CRLs in force do not admit the leaf. **`Unknown` refuses here**, unlike at an
    /// issuer: the leaf is the certificate this deployment's CRLs are expected to cover.
    LeafRevocationRefused {
        /// What the index concluded.
        verdict: RevocationVerdict,
    },
    /// An issuer the peer presented does not parse, or its window is not orderable while
    /// its revocation standing is being read.
    IssuerUnreadable,
    /// An issuer's own validity window does not contain this instant. A SELF-ISSUED
    /// certificate is exempt — a peer may send its root, and path building matches that
    /// against the configured anchor set rather than against its own window.
    IssuerOutsideValidityWindow,
    /// An issuer is EXPLICITLY revoked. `Unknown` does not refuse here: whether the chain
    /// reaches a CRL-covered issuer is a path-building question the handshake settled.
    IssuerRevoked,
}
