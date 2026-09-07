// SPDX-License-Identifier: Apache-2.0
//! Reading a remote signer's failure for what it says about the QUOTA.
//!
//! Its own module because it is its own question. `RemoteSignerFailure` is a value — a
//! status and a body, kept apart so a classifier reads facts rather than a rendered string;
//! this is the one rule that reads it, and the two providers differ only in the data they
//! hand it (ADR-MCPRE-061 EX-008).

use super::RemoteSignerFailure;

/// A status that means the SERVICE is shedding load, whoever asked and whatever they asked
/// for — as opposed to a status about this request.
///
/// The two are the same on both providers and are checked before either provider's own
/// vocabulary, because a gateway sheds load before the service's error shape is reached at
/// all: an AWS `__type` and a Cloud KMS `error.status` are both absent from a 429 minted by
/// the front door.
fn is_load_shedding_status(status: Option<u16>) -> bool {
    matches!(status, Some(429) | Some(503))
}

/// Read a JSON string field out of an error body, without deserializing the whole document
/// into a schema neither provider guarantees.
///
/// Returns `None` for a body that is not JSON, has no such field, or whose field is not a
/// string — all of which mean *this body does not state the thing*, which is exactly what a
/// classifier must not read as a positive.
pub(super) fn json_string_field(body: &str, path: &[&str]) -> Option<String> {
    let mut node: serde_json::Value = serde_json::from_str(body).ok()?;
    for (index, key) in path.iter().enumerate() {
        let next = node.get_mut(key)?.take();
        if index + 1 == path.len() {
            return next.as_str().map(str::to_owned);
        }
        node = next;
    }
    None
}

/// Where a provider states the name of the error it is returning, and which names mean the
/// account or project quota is gone.
///
/// DATA, supplied by each provider, so the RULE below is written once. The rule is the same
/// on both — shed load first, then read the stated name and compare it to a known set — and
/// what differs is only where the name lives on the wire and what it is spelled.
#[derive(Debug, Clone, Copy)]
pub(crate) struct QuotaSignals {
    /// The JSON path the name is stated at.
    pub(crate) path: &'static [&'static str],
    /// The names that mean the quota, and not this request, is the problem.
    pub(crate) exhausted: &'static [&'static str],
    /// Whether the wire name is namespaced (`com.amazonaws.kms#ThrottlingException`), in
    /// which case the suffix is what is compared.
    pub(crate) namespaced: bool,
}

/// Does this failure say the ACCOUNT or PROJECT is over its quota, rather than that one
/// request was malformed?
///
/// One rule, two data sets (ADR-MCPRE-061 EX-008). It used to be written twice, and the
/// two copies had already drifted in shape — one folded the suffix rule into a closure and
/// the other did not — while stating the same proposition.
///
/// **A body that states no name states nothing**, which is not a positive: a permanent
/// misconfiguration must never arm a quota window, because that would turn it into a
/// permanent local refusal that hides it.
pub(crate) fn quota_verdict(
    failure: &RemoteSignerFailure,
    signals: QuotaSignals,
) -> crate::handshake_quota::QuotaVerdict {
    use crate::handshake_quota::QuotaVerdict;
    if is_load_shedding_status(failure.status()) {
        return QuotaVerdict::Exhausted;
    }
    let stated = failure
        .body()
        .and_then(|body| json_string_field(body, signals.path));
    let names_quota = stated.as_deref().is_some_and(|stated| {
        let name = if signals.namespaced {
            stated.rsplit('#').next().unwrap_or(stated)
        } else {
            stated
        };
        signals.exhausted.contains(&name)
    });
    if names_quota {
        QuotaVerdict::Exhausted
    } else {
        QuotaVerdict::Unrelated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake_quota::QuotaVerdict;

    // The chained cause reaches the operator WITHOUT entering the body a classifier reads.
    // This is the property the separate field exists for: appending the cause to the body
    // is the obvious implementation, and it would make a `__type` lookup fail on a body
    // that genuinely states one.

    /// A call that got no answer has no status, and must not be read as one.
    #[test]
    fn a_transport_failure_states_no_status() {
        let failure = RemoteSignerFailure::transport("connection refused".to_string());
        assert_eq!(failure.status(), None);
        assert_eq!(failure.body(), None);
        assert!(!is_load_shedding_status(failure.status()));
    }

    #[test]
    fn only_the_shared_load_shedding_statuses_are_load_shedding() {
        assert!(is_load_shedding_status(Some(429)));
        assert!(is_load_shedding_status(Some(503)));
        for other in [400u16, 401, 403, 404, 500, 502] {
            assert!(!is_load_shedding_status(Some(other)), "{other}");
        }
        assert!(!is_load_shedding_status(None));
    }

    #[test]
    fn a_nested_json_field_is_read_at_its_path() {
        let body = "{\"error\":{\"status\":\"RESOURCE_EXHAUSTED\",\"code\":429}}";
        assert_eq!(
            json_string_field(body, &["error", "status"]).as_deref(),
            Some("RESOURCE_EXHAUSTED")
        );
        assert_eq!(json_string_field(body, &["error", "message"]), None);
        assert_eq!(json_string_field(body, &["__type"]), None);
    }

    /// A body that does not STATE the field must not read as a positive, however it fails
    /// to state it.
    #[test]
    fn a_body_that_states_nothing_yields_nothing() {
        assert_eq!(json_string_field("not json at all", &["__type"]), None);
        assert_eq!(json_string_field("", &["__type"]), None);
        assert_eq!(json_string_field("{\"__type\":429}", &["__type"]), None);
        assert_eq!(json_string_field("[1,2,3]", &["__type"]), None);
        assert_eq!(
            json_string_field(
                "{\"error\":\"a string, not an object\"}",
                &["error", "status"]
            ),
            None
        );
    }

    /// The two providers' data, so the RULE below is exercised with what actually reaches it
    /// (ADR-MCPRE-061 EX-008). These mirror the sets `aws_kms_keysource` and
    /// `gcp_kms_keysource` pass; the adapters' own controls establish that each really does
    /// pass its own, and what is measured here is the rule over both shapes.
    const AWS: QuotaSignals = QuotaSignals {
        path: &["__type"],
        exhausted: &["ThrottlingException", "LimitExceededException"],
        namespaced: true,
    };
    const GCP: QuotaSignals = QuotaSignals {
        path: &["error", "status"],
        exhausted: &["RESOURCE_EXHAUSTED"],
        namespaced: false,
    };

    fn verdict(status: u16, body: &str, signals: QuotaSignals) -> QuotaVerdict {
        quota_verdict(
            &RemoteSignerFailure::status_body(status, body.to_string()),
            signals,
        )
    }

    /// A gateway sheds load before either service's error shape is reached, so the status is
    /// checked FIRST and a 429/503 with an empty body is still exhaustion. Reading the body
    /// first would classify a front-door 429 as unrelated and leave the window unarmed.
    #[test]
    fn a_shed_load_status_is_exhaustion_on_either_provider_whatever_the_body_says() {
        for signals in [AWS, GCP] {
            for status in [429u16, 503] {
                assert_eq!(verdict(status, "", signals), QuotaVerdict::Exhausted);
                assert_eq!(
                    verdict(status, "{\"__type\":\"ValidationException\"}", signals),
                    QuotaVerdict::Exhausted,
                    "a front-door {status} states no service error shape at all"
                );
            }
        }
    }

    /// The stated name decides, at the provider's own path — and AWS namespaces it, so the
    /// SUFFIX is what is compared. A whole-string comparison would miss every real
    /// `com.amazonaws.kms#ThrottlingException`.
    #[test]
    fn a_stated_exhaustion_name_arms_the_window_at_each_providers_own_path() {
        assert_eq!(
            verdict(
                400,
                "{\"__type\":\"com.amazonaws.kms#ThrottlingException\"}",
                AWS
            ),
            QuotaVerdict::Exhausted
        );
        assert_eq!(
            verdict(400, "{\"__type\":\"LimitExceededException\"}", AWS),
            QuotaVerdict::Exhausted,
            "an un-namespaced name still matches"
        );
        assert_eq!(
            verdict(400, "{\"error\":{\"status\":\"RESOURCE_EXHAUSTED\"}}", GCP),
            QuotaVerdict::Exhausted
        );
    }

    /// **A body that states no name states nothing, and nothing is not a positive.** A
    /// permanent misconfiguration classified as exhaustion becomes a permanent local refusal
    /// that hides the misconfiguration it came from.
    #[test]
    fn a_failure_that_states_no_quota_arms_nothing() {
        for signals in [AWS, GCP] {
            for body in [
                "",
                "not json at all",
                "{}",
                "{\"__type\":\"ValidationException\"}",
                "{\"error\":{\"status\":\"INVALID_ARGUMENT\"}}",
                "{\"__type\":429}",
            ] {
                assert_eq!(
                    verdict(400, body, signals),
                    QuotaVerdict::Unrelated,
                    "body {body:?} states no quota"
                );
            }
        }
    }

    /// Each provider reads its OWN path. A body stating the other provider's field is not a
    /// positive here, which is what keeps one adapter's vocabulary from arming the other's
    /// window.
    #[test]
    fn one_providers_vocabulary_does_not_arm_the_others_window() {
        assert_eq!(
            verdict(400, "{\"error\":{\"status\":\"RESOURCE_EXHAUSTED\"}}", AWS),
            QuotaVerdict::Unrelated
        );
        assert_eq!(
            verdict(400, "{\"__type\":\"ThrottlingException\"}", GCP),
            QuotaVerdict::Unrelated
        );
    }

    /// A call that got no answer has no body to state anything, so it arms nothing — a
    /// connect refusal is not evidence that a quota is gone.
    #[test]
    fn a_transport_failure_arms_nothing() {
        for signals in [AWS, GCP] {
            assert_eq!(
                quota_verdict(
                    &RemoteSignerFailure::transport("connection refused".to_string()),
                    signals
                ),
                QuotaVerdict::Unrelated
            );
        }
    }
}
