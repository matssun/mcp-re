// SPDX-License-Identifier: Apache-2.0
//! WHAT a retention marker persists — and, deliberately, what it does not.

use mcp_re_http_profile::scitt::EvidenceDigest;

use super::RetentionError;

/// The bytes a reservation marker holds: a commitment to the submitted request, and no
/// part of the request itself.
///
/// # Why the request is not here
///
/// The predecessor wrote `retained_request(request)` into the marker — the request's
/// covered headers among them, which for this profile include the live `authorization`
/// bearer and the `dpop` proof. It was written at `reserve`, BEFORE the exchange had
/// dispatched, into a store with no expiry. For a call that then never dispatched, that is
/// a live credential on disk for an exchange the boundary refused, and no path could clear
/// it once `reserve` itself had failed (R9-C099).
///
/// Nothing read those bytes. The completed hop is where the full retained message belongs;
/// what a marker owes an auditor is the identity of the exchange it stands for, and the
/// digest is that identity — it commits to the request without disclosing it.
///
/// # Why the digest is here even though the file NAME carries it
///
/// Not a duplication worth removing. A marker copied out of the store, or read through a
/// tool that does not preserve names, still names its own exchange; the reconciliation the
/// marker exists for does not then depend on where the file sits.
///
/// # Why the STAGE is not here
///
/// Which side of the dispatch commitment a marker records is carried by its extension, and
/// only by it — see [`super::ReservedBeforeDispatch`]. The commitment is a rename, so a
/// stage field would have to be rewritten to advance it, and a partial write could leave a
/// name and a body disagreeing about whether an execution threshold was crossed. One
/// representation, advanced atomically.
#[derive(serde::Serialize)]
pub(super) struct ReservationMarker<'a> {
    /// The digest of the request's retained form: the same token the marker is named by,
    /// and the same one a completed hop's request half hashes to.
    request_digest: &'a str,
}

impl<'a> ReservationMarker<'a> {
    /// The marker for an exchange identified by `digest`.
    pub(super) fn of(digest: &'a EvidenceDigest) -> Self {
        ReservationMarker {
            request_digest: digest.as_str(),
        }
    }

    /// The bytes to publish.
    pub(super) fn to_bytes(&self) -> Result<Vec<u8>, RetentionError> {
        serde_json::to_vec(self)
            .map_err(|_| RetentionError::Malformed("reservation marker does not serialize"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The marker is the digest and nothing else. Asserted on the exact bytes rather than
    /// on a round trip, because the property that matters is an ABSENCE: a round trip
    /// would pass just as well if the struct grew a field carrying the request back.
    #[test]
    fn a_marker_carries_the_commitment_and_nothing_else() {
        let digest = EvidenceDigest::of(b"the request bytes");
        let bytes = ReservationMarker::of(&digest)
            .to_bytes()
            .expect("serializes");
        assert_eq!(
            String::from_utf8(bytes).expect("utf-8"),
            format!("{{\"request_digest\":\"{}\"}}", digest.as_str())
        );
    }

    /// No credential reaches the marker, stated over a request that carries one.
    ///
    /// The broken implementation this catches is the previous one: `reserve` wrote
    /// `retained_request(request)`, whose covered headers include this profile's live
    /// bearer and DPoP proof, into a marker for a call that had not yet dispatched.
    #[test]
    fn a_marker_never_carries_the_request_or_its_credentials() {
        let request_bytes = br#"{"authorization":"Bearer super-secret","dpop":"proof"}"#;
        let digest = EvidenceDigest::of(request_bytes);
        let bytes = ReservationMarker::of(&digest)
            .to_bytes()
            .expect("serializes");
        let rendered = String::from_utf8(bytes).expect("utf-8");
        assert!(!rendered.contains("super-secret"), "{rendered}");
        assert!(!rendered.contains("Bearer"), "{rendered}");
        assert!(!rendered.contains("proof"), "{rendered}");
        assert!(rendered.contains(digest.as_str()));
    }
}
