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
fn json_string_field(body: &str, path: &[&str]) -> Option<String> {
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
    fn a_chained_cause_renders_but_never_enters_the_body() {
        let failure = RemoteSignerFailure::status_body(
            503,
            "{\"error\":{\"status\":\"UNAVAILABLE\"}}".to_string(),
        )
        .after("asymmetricSign HTTP 401: ".to_string());

        assert_eq!(
            failure.body(),
            Some("{\"error\":{\"status\":\"UNAVAILABLE\"}}"),
            "the classifier must still see the service's own answer"
        );
        assert_eq!(
            json_string_field(failure.body().unwrap(), &["error", "status"]).as_deref(),
            Some("UNAVAILABLE"),
            "and must still be able to read the field out of it"
        );
        assert_eq!(failure.status(), Some(503));

        let rendered = format!("{}", failure.into_key_error("gcp-kms", "asymmetricSign"));
        assert!(rendered.contains("HTTP 503"), "{rendered}");
        assert!(
            rendered.contains("HTTP 401"),
            "the cause must survive: {rendered}"
        );
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
}
