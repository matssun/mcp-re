// SPDX-License-Identifier: Apache-2.0
//! The authoritative admission-state source (#414 rev 2 §4.3/§5.2) — what the PEP
//! consults to decide whether a workload's admission is STILL current.
//!
//! ADR-MCPRE-053 built both halves of the evidence: the authority-signed assertion,
//! and the §7 binding that ties a call to it. It deliberately did not say where the
//! *authoritative* state comes from, because which authority a deployment trusts is
//! an operator's decision. This is that seam.
//!
//! **Why a snapshot is not enough.** An assertion says an authority admitted this
//! workload at a generation. It cannot say the workload is admitted *now* — a
//! revocation between issuance and use is exactly the case the two-part design
//! exists for. Without a source to compare against, a PEP either trusts the snapshot
//! for its whole TTL (admitting a revoked workload for minutes) or refuses every
//! call. Neither is admission control.
//!
//! **Reachable-and-absent is not unreachable.** The two failures read the same to a
//! naive `Option`, and they must not:
//!
//! - `Ok(Some(state))` — the authority has a record; compare generations.
//! - `Ok(None)` — the authority is healthy and knows nothing about this workload.
//!   That is a definitive negative: the call is refused. Treating it as "unreachable"
//!   would route an unknown workload into degraded mode, where it would be SERVED on
//!   its own assertion — turning an unadmitted caller into an admitted one by being
//!   unknown, which is backwards.
//! - `Err(Unavailable)` — no answer. Only this reaches the §5.2 degraded fork, and
//!   only when the deployment opted in, bounded by P.
//!
//! The same distinction `ResolverOutcome` draws for the trust seam (C079), for the
//! same reason: an outage is not a statement about the caller.
//!
//! **A store is not an authority.** Every source here reads bytes somebody else wrote, so
//! what it hands the gate is [`CurrentAdmissionState`] — a value obtainable only by
//! verifying a record against the configured admission authority, inside the deployment's
//! declared currentness budget. A party with store-write access and no signing authority
//! can therefore delete state, corrupt it or make the store unreachable; it cannot mint an
//! admission, move one workload's record onto another's key, rewind a generation, or
//! restore an old admitted record past the budget. The decision itself has one owner,
//! [`AdmissionRecordVerifier`], so a source cannot forget to make it.
//!
//! A REACHABLE store answering with a record that fails any of those checks is a definitive
//! negative — `Ok(None)` — and never `Err(Unavailable)`. Sending it to the degraded fork
//! would serve the caller on its own assertion, which would make corrupting a record a
//! cheaper un-revoke than issuing one.

use std::future::Future;
use std::pin::Pin;

use mcp_re_http_profile::authoritative_admission::record::CurrentAdmissionState;

/// What a reachable store's answer means — the one owner of the classification, so that
/// "a store that answered is never an outage" is a property of a type rather than a rule
/// each source re-implements.
mod answer;
mod in_memory;
mod verifier;

pub use in_memory::InMemoryAdmissionSource;
pub use verifier::AdmissionRecordVerifier;

// Crate-visible, and only these two items: the shared arm of this authority lives in
// `crate::redis_admission_source` because that module is compiled under `redis_replay`,
// which makes it a sibling rather than a child. The classification is the rule the
// statement quantifies over every source, so the sibling must reach it — while `answer`'s
// module body stays private, so nothing else about it becomes crate API.
pub(crate) use answer::classify_answer;
pub(crate) use answer::AnsweredAs;

/// A fail-closed admission-source failure: the authority could not be reached or
/// did not answer. NOT a verdict about the workload, and never a fallback to allow.
#[derive(Debug, Clone)]
pub enum AdmissionSourceError {
    /// The authoritative source could not be reached or answered.
    Unavailable { details: String },
}

impl std::fmt::Display for AdmissionSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdmissionSourceError::Unavailable { details } => {
                write!(f, "admission source unavailable: {details}")
            }
        }
    }
}

/// A boxed source future (the lookup is awaited on the serving path).
pub type AdmissionFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, AdmissionSourceError>> + Send + 'a>>;

/// The authoritative admission state a PEP consults per call.
///
/// Implementations MUST be non-blocking: `current` is awaited on the per-core
/// request path, before the inner backend runs.
pub trait AsyncAdmissionSource: Send + Sync {
    /// The current, AUTHENTICATED authoritative state for `admission_id`.
    ///
    /// `Ok(None)` means the store answered and has no record this deployment will act on —
    /// absent, or present and not the configured authority's current statement. Both are
    /// definitive negatives. `Err` means no answer at all; see the module docs for why the
    /// two must not collapse.
    ///
    /// `now` is the verifier's clock, passed rather than read here: currentness is decided
    /// against the same instant the rest of the exchange is decided against, and a source
    /// reading its own clock would be a second one to disagree with.
    fn current<'a>(
        &'a self,
        admission_id: &'a str,
        now: i64,
    ) -> AdmissionFuture<'a, Option<CurrentAdmissionState>>;
}

/// The key an admission record lives under in a shared store.
pub const ADMISSION_KEY_PREFIX: &str = "mcp-re:admission:";

/// The shared-store key for a workload's authoritative admission record.
///
/// The id is used verbatim rather than digested: unlike a continuation's
/// `requestState`, an admission id is not a capability — it is a name an operator
/// assigns and must be able to read in `redis-cli` when a revocation is not taking
/// effect. Nothing is authorized by knowing it; the record it addresses only ever
/// *narrows* what a call may do.
pub fn admission_key(admission_id: &str) -> String {
    format!("{ADMISSION_KEY_PREFIX}{admission_id}")
}

/// Fixtures the source batteries share, so a record is built ONE way.
///
/// A record assembled two ways is two chances to disagree about what a valid one looks
/// like, which is the failure this artifact exists to prevent.
#[cfg(test)]
pub(crate) mod test_support {
    use mcp_re_core::{b64url_decode, SigningKey};
    use mcp_re_http_profile::authoritative_admission::record::{
        issue_admission_state_record, AdmissionStateClaims, AdmissionStateCurrentness,
    };
    use mcp_re_http_profile::{AdmissionStatus, HttpProfileError};
    use std::sync::Arc;

    pub(crate) const AUTHORITY_KID: &str = "admission-authority/root/1";
    pub(crate) const PROFILE: &str = mcp_re_http_profile::PROFILE_TAG;

    pub(crate) fn claims(
        admission_id: &str,
        generation: u64,
        revision: u64,
        iat: i64,
    ) -> AdmissionStateClaims {
        AdmissionStateClaims {
            iss: "admission-authority".to_owned(),
            iat,
            nbf: iat,
            exp: iat.saturating_add(60),
            mcp_re_profile: PROFILE.to_owned(),
            mcp_re_admission_id: admission_id.to_owned(),
            mcp_re_admission_generation: generation,
            mcp_re_admission_status: AdmissionStatus::Admitted,
            mcp_re_state_revision: revision,
            issuer_kid: AUTHORITY_KID.to_owned(),
        }
    }

    pub(crate) fn issue(key: &SigningKey, claims: &AdmissionStateClaims) -> String {
        issue_admission_state_record(claims, |bytes: &[u8]| {
            b64url_decode(&key.sign(bytes))
                .map_err(|_| HttpProfileError::MalformedEvidence("test signature"))
        })
        .expect("the test authority issues")
    }

    pub(crate) fn signed_admitted(
        key: &SigningKey,
        admission_id: &str,
        generation: u64,
        revision: u64,
        iat: i64,
    ) -> String {
        issue(key, &claims(admission_id, generation, revision, iat))
    }

    pub(crate) fn signed_revoked(
        key: &SigningKey,
        admission_id: &str,
        generation: u64,
        revision: u64,
        iat: i64,
    ) -> String {
        let mut c = claims(admission_id, generation, revision, iat);
        c.mcp_re_admission_status = AdmissionStatus::Revoked;
        issue(key, &c)
    }

    /// A verifier configured to trust exactly `key` under [`AUTHORITY_KID`] — the one-entry
    /// resolver shape a real deployment builds from its validated admission state.
    pub(crate) fn verifier_for(
        key: &SigningKey,
        max_record_age: i64,
        max_clock_skew: i64,
    ) -> super::AdmissionRecordVerifier {
        let public = key.public_key();
        super::AdmissionRecordVerifier::new(
            Arc::new(move |presented: &str| (presented == AUTHORITY_KID).then(|| public.clone())),
            PROFILE,
            AdmissionStateCurrentness {
                max_record_age,
                max_clock_skew,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_readable_by_an_operator() {
        assert_eq!(admission_key("workload-7"), "mcp-re:admission:workload-7");
    }
}
