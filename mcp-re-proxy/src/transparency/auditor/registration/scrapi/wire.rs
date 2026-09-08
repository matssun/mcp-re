// SPDX-License-Identifier: Apache-2.0
//! The SCRAPI wire vocabulary this mechanism speaks.
//!
//! One fact: **which media types, paths and statuses one draft revision names.**
//!
//! It is a vocabulary rather than an authority, and it is a module rather than constants
//! scattered through the state machine so that the revision is pinned in ONE place. When
//! the draft moves, this is the file that says what moved.

/// The protocol revision this mechanism implements.
///
/// **An Internet-Draft, not a published RFC.** Drafts are renumbered, restructured and
/// withdrawn; a deployment reading this string is reading a version pin, not a standards
/// citation. It is `pub` and re-exported so an operator-facing report can state which
/// revision a registration was performed under, because "SCITT" alone does not identify a
/// protocol anyone can reproduce.
pub const SCRAPI_REVISION: &str = "draft-ietf-scitt-scrapi-11";

/// The registration endpoint, relative to the service's base URL.
pub(super) const ENTRIES_PATH: &str = "entries";

/// The media type a Signed Statement is submitted as, and a Receipt comes back as.
pub(super) const COSE_MEDIA_TYPE: &str = "application/cose";

/// Registration completed synchronously; the body is the Receipt.
pub(super) const STATUS_CREATED: u16 = 201;

/// Registration was accepted for asynchronous processing; `Location` names where to poll.
pub(super) const STATUS_ACCEPTED: u16 = 202;

/// The receipt resource exists and is not ready.
///
/// **Not success and not failure.** A reader that folded `204` into either would report a
/// registration that has not happened yet as one that has, or abandon one still in flight.
pub(super) const STATUS_PENDING: u16 = 204;

/// The receipt resource is ready; the body is the Receipt.
pub(super) const STATUS_READY: u16 = 200;

/// The service is rate limiting.
pub(super) const STATUS_TOO_MANY_REQUESTS: u16 = 429;

/// The service is over capacity or down for maintenance.
pub(super) const STATUS_UNAVAILABLE: u16 = 503;

/// Whether `status` is a client-error refusal — the service read the submission and said
/// no. `429` is excluded: it is a request to come back, not a judgement about the bytes.
pub(super) fn is_refusal(status: u16) -> bool {
    (400..500).contains(&status) && status != STATUS_TOO_MANY_REQUESTS
}

/// Whether `media_type` is the COSE type, ignoring parameters and case.
pub(super) fn is_cose(media_type: &str) -> bool {
    media_type
        .split(';')
        .next()
        .is_some_and(|base| base.trim().eq_ignore_ascii_case(COSE_MEDIA_TYPE))
}

/// `base` joined with the entries path, with exactly one separator.
pub(super) fn entries_url(base: &str) -> String {
    format!("{}/{ENTRIES_PATH}", base.trim_end_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cose_type_is_matched_past_its_parameters() {
        for good in [
            "application/cose",
            "Application/COSE",
            "application/cose; charset=utf-8",
            " application/cose ",
        ] {
            assert!(is_cose(good), "{good:?}");
        }
        for bad in [
            "application/json",
            "application/concise-problem-details+cbor",
            "application/cose-key",
            "",
        ] {
            assert!(!is_cose(bad), "{bad:?}");
        }
    }

    /// `429` is not a refusal. It says come back, and reading it as a judgement about the
    /// statement would report a definitive negative for a submission nobody judged.
    #[test]
    fn rate_limiting_is_not_a_refusal() {
        for status in [400, 401, 403, 404, 409, 422] {
            assert!(is_refusal(status), "{status}");
        }
        for status in [200, 201, 202, 204, 429, 500, 502, 503] {
            assert!(!is_refusal(status), "{status}");
        }
    }

    #[test]
    fn the_entries_url_has_exactly_one_separator() {
        for base in ["https://ts.example.test", "https://ts.example.test/"] {
            assert_eq!(entries_url(base), "https://ts.example.test/entries");
        }
        assert_eq!(
            entries_url("https://ts.example.test/scitt/"),
            "https://ts.example.test/scitt/entries",
        );
    }
}
