// SPDX-License-Identifier: Apache-2.0
//! The checks that cannot be expressed in the type.
//!
//! Three groups, and they answer different questions:
//!
//! * **the local leg** — where this client offers its signing key, and the two bounds that
//!   keep one caller from holding the sidecar;
//! * **trust and delegation** — which documents this client will believe, and how far a
//!   window may be widened before believing one stops meaning anything;
//! * **the routes** — whether each binding digests something the request actually carries.

use super::bearer_token;
use super::err;
use super::ArtifactType;
use super::BindScope;
use super::BindingSource;
use super::ClientConfig;
use super::ConfigError;
use super::LocalConfig;
use super::AUTHORIZATION;
use super::MAX_CLOCK_SKEW_SECS;
use super::MAX_MANIFEST_RELOAD_SECS;

/// The profile's signature-validity ceiling, `VerifierPolicy::DEFAULT_MAX_SIGNATURE_VALIDITY`.
const MAX_REQUEST_LIFETIME_SECS: i64 = 3600;

/// Where this client offers its signing key, and the bounds that keep one caller from
/// holding the sidecar.
pub(super) fn check_local(local: &LocalConfig) -> Result<(), ConfigError> {
    // The refusal itself is `BindScope`'s, not a statement here that happens to run
    // first: a scope in hand means the bind was permitted, so there is no check at this
    // site that could be deleted to admit an off-host listener.
    BindScope::decide(local.bind, local.allow_non_loopback)?;
    if !(1..=MAX_REQUEST_LIFETIME_SECS).contains(&local.request_lifetime_secs) {
        return Err(err(
            "local.request_lifetime_secs is outside 1..=3600: no verifier accepts a wider \
             expires - created",
        ));
    }
    if local.max_in_flight == 0 {
        return Err(err("local.max_in_flight must be positive"));
    }
    Ok(())
}

/// Which documents this client will believe, and how far a window may be widened.
pub(super) fn check_trust_and_delegation(config: &ClientConfig) -> Result<(), ConfigError> {
    if config.trust.org_keys.is_empty() {
        return Err(err(
            "trust.org_keys is empty: a client that pins no manifest-signing key \
             accepts a trust-anchor manifest signed by anyone",
        ));
    }
    if config.delegation.verifier_audiences.is_empty() {
        return Err(err("delegation.verifier_audiences is empty"));
    }
    if config.delegation.expected_audience_hash.is_empty() {
        return Err(err("delegation.expected_audience_hash is empty"));
    }
    if config.delegation.accepted_epochs.is_empty() {
        return Err(err("delegation.accepted_epochs is empty"));
    }
    if !(0..=MAX_CLOCK_SKEW_SECS).contains(&config.delegation.max_clock_skew) {
        return Err(err(format!(
            "delegation.max_clock_skew {} is outside 0..={MAX_CLOCK_SKEW_SECS}. The value \
             widens the delegated credential's nbf/exp window directly, so an unbounded one \
             accepts a server credential long past its exp — while the response-signature \
             freshness gate silently reverts to the profile default, leaving no symptom",
            config.delegation.max_clock_skew
        )));
    }
    if !(1..=MAX_MANIFEST_RELOAD_SECS).contains(&config.trust.reload_secs) {
        return Err(err(format!(
            "trust.reload_secs {} is outside 1..={MAX_MANIFEST_RELOAD_SECS}. Withdrawing \
             anchors whose manifest has passed its expires_at happens in a refresh cycle and \
             nowhere else, so 0 leaves an expired trust picture verifying forever and a long \
             cadence is how long it keeps doing so",
            config.trust.reload_secs
        )));
    }
    Ok(())
}

/// Whether every route names a distinct id and every binding digests something the request
/// actually carries.
pub(super) fn check_routes(config: &ClientConfig) -> Result<(), ConfigError> {
    if config.routes.is_empty() {
        return Err(err("routes is empty"));
    }
    if let Some(default_route) = &config.local.default_route {
        if !config.routes.iter().any(|r| &r.route_id == default_route) {
            return Err(err(format!(
                "local.default_route {default_route:?} names no configured route"
            )));
        }
    }
    let mut seen = std::collections::HashSet::new();
    for route in &config.routes {
        if !seen.insert(route.route_id.as_str()) {
            return Err(err(format!(
                "duplicate route_id {:?}: a later route would silently replace an \
                 earlier one, including its bindings",
                route.route_id
            )));
        }
        if route.target_uri != route.audience.target_uri {
            return Err(err(format!(
                "route {:?}: target_uri differs from audience.target_uri, so every \
                 request on it fails AudienceMismatch at signing",
                route.route_id
            )));
        }
        if route.artifact_bindings.is_empty() {
            return Err(err(format!(
                "route {:?} has no artifact_bindings; the server rejects a request \
                 whose evidence block carries none",
                route.route_id
            )));
        }
        for binding in &route.artifact_bindings {
            check_binding(route, binding)?;
        }
    }
    Ok(())
}

/// One binding digests something the request actually carries.
///
/// A binding that digests a value the request need not send is a binding to NOTHING: it
/// commits to bytes the verifier will never see, so it passes locally and proves nothing at
/// the far end. Each arm below refuses one shape of that.
///
/// The DPoP cases are the sharp ones. The verifier takes the credential from the request's
/// covered `Authorization` header and from nowhere else, so that header is the only place a
/// digest can commit to transmitted bytes; a literal or a file digests a value that only has
/// to match by coincidence. And RFC 9449's `ath` is over the access TOKEN, so a header whose
/// value is not a Bearer credential leaves the verifier nothing to match.
fn check_binding(
    route: &super::RouteConfig,
    binding: &super::BindingConfig,
) -> Result<(), ConfigError> {
    if let BindingSource::Header { name } = &binding.source {
        let name: &str = name;
        let Some(header) = route
            .extra_headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
        else {
            return Err(err(format!(
                "route {:?} binds header {name:?}, which it does not send: \
                 the binding would digest nothing the server sees",
                route.route_id
            )));
        };
        if binding.artifact_type == ArtifactType::OauthDpop && bearer_token(&header.value).is_none()
        {
            return Err(err(format!(
                "route {:?} binds an oauth-dpop artifact to header {name:?}, whose \
                 value is not a Bearer credential: the verifier digests the token \
                 after the Bearer scheme, so there is nothing here it can match",
                route.route_id
            )));
        }
    }
    match (binding.artifact_type, &binding.source) {
        (ArtifactType::OauthDpop, BindingSource::Header { name })
            if !name.eq_ignore_ascii_case(AUTHORIZATION) =>
        {
            return Err(err(format!(
                "route {:?} binds an oauth-dpop artifact to header {name:?}; the \
                 verifier reads the access token from {AUTHORIZATION:?} and no \
                 other header",
                route.route_id
            )))
        }
        (ArtifactType::OauthDpop, BindingSource::Header { .. }) => {}
        (ArtifactType::OauthDpop, _) => {
            return Err(err(format!(
                "route {:?} sources an oauth-dpop artifact from config rather than \
                 from the {AUTHORIZATION:?} header it sends: the digest would cover \
                 a restated value the request need not carry, which is a binding to \
                 nothing",
                route.route_id
            )))
        }
        // The mTLS binding commits to the DER of the client certificate the
        // TLS layer presents. A literal cannot be that, at any length.
        (ArtifactType::OauthMtls, BindingSource::Literal { .. }) => {
            return Err(err(format!(
                "route {:?} sources an oauth-mtls artifact from a literal; the \
                 binding must digest the DER of the client certificate this client \
                 presents, which config text cannot restate",
                route.route_id
            )))
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::ClientConfig;
    use super::MAX_MANIFEST_RELOAD_SECS;
    use super::MAX_REQUEST_LIFETIME_SECS;

    /// A document valid in every respect except the one under test, so a refusal can only be
    /// about `trust.reload_secs`.
    fn with_reload_secs(secs: u64) -> Result<ClientConfig, String> {
        let doc = format!(
            r#"{{
  "local": {{ "bind": "127.0.0.1:8640" }},
  "identity": {{ "key_id": "c1", "signing_key_seed_path": "/dev/null" }},
  "remote": {{
    "addr": "10.0.0.5:8600",
    "expected_server_name": "proxy.internal",
    "client_cert_path": "/dev/null",
    "client_key_path": "/dev/null",
    "server_ca_path": "/dev/null"
  }},
  "trust": {{
    "manifest_path": "/dev/null",
    "profile": "mcp-re-http-v1",
    "org_keys": [{{ "kid": "org-1", "public_key": "AAAA" }}],
    "floor": {{ "kind": "durable", "dir": "/var/lib/mcp-re/floor" }},
    "reload_secs": {secs}
  }},
  "delegation": {{
    "verifier_audiences": ["v1"],
    "expected_audience_hash": "v1",
    "accepted_epochs": ["e1"]
  }},
  "routes": [{{
    "route_id": "r1",
    "target_uri": "https://mcp.example.com/mcp",
    "audience": {{ "audience_id": "v1", "target_uri": "https://mcp.example.com/mcp", "route": "a" }},
    "extra_headers": [{{ "name": "Authorization", "value": "Bearer tok" }}],
    "artifact_bindings": [{{ "artifact_type": "oauth-dpop", "source": {{ "kind": "header", "name": "Authorization" }} }}]
  }}]
}}"#
        );
        ClientConfig::from_json(doc.as_bytes()).map_err(|e| e.to_string())
    }

    /// The refresh cadence is the only place anchors whose manifest has expired are
    /// withdrawn, so `0` leaves an expired trust picture verifying forever and a long cadence
    /// is how long it keeps doing so. THM-0127 points at this bound, so it is pinned at both
    /// edges: a bound moved by one in either direction flips exactly one of these four.
    #[test]
    fn the_reload_cadence_bound_is_exactly_one_to_the_documented_maximum() {
        let just_above = MAX_MANIFEST_RELOAD_SECS
            .checked_add(1)
            .expect("the documented maximum leaves room for one more");
        for refused in [0, just_above] {
            let error = with_reload_secs(refused)
                .err()
                .unwrap_or_else(|| panic!("reload_secs {refused} must not start"));
            assert!(
                error.contains("trust.reload_secs")
                    && error.contains(&format!("1..={MAX_MANIFEST_RELOAD_SECS}")),
                "reload_secs {refused}: the refusal must name the field and the bound, got {error}"
            );
        }
        for accepted in [1, MAX_MANIFEST_RELOAD_SECS] {
            with_reload_secs(accepted)
                .unwrap_or_else(|e| panic!("reload_secs {accepted} is inside the bound: {e}"));
        }
    }

    /// The edge test above is written in terms of the constant, so it cannot notice the
    /// constant moving. This pins the value the field documentation and the round-7 closure
    /// describe: an hour bounds how long an expired manifest keeps verifying.
    #[test]
    fn the_documented_maximum_is_one_hour() {
        assert_eq!(MAX_MANIFEST_RELOAD_SECS, 3600);
    }

    #[test]
    fn a_route_whose_target_uri_differs_from_its_audience_is_refused() {
        let mut config = with_reload_secs(60).expect("the baseline document is valid");
        config.routes[0].target_uri = "https://mcp.example.com/mcp/".to_owned();
        let error = config
            .validate()
            .expect_err("a mismatched target_uri must be refused");
        assert!(error.to_string().contains("target_uri"), "got {error}");
    }

    #[test]
    fn an_empty_expected_audience_hash_is_refused() {
        let mut config = with_reload_secs(60).expect("the baseline document is valid");
        config.delegation.expected_audience_hash = String::new();
        let error = config
            .validate()
            .expect_err("an empty audience hash must be refused");
        assert!(
            error
                .to_string()
                .contains("delegation.expected_audience_hash"),
            "got {error}"
        );
    }

    #[test]
    fn the_request_lifetime_bound_is_exactly_one_to_the_profiles_signature_validity_ceiling() {
        let just_above = MAX_REQUEST_LIFETIME_SECS
            .checked_add(1)
            .expect("the ceiling leaves room for one more");
        for (secs, accepted) in [
            (0, false),
            (just_above, false),
            (1, true),
            (MAX_REQUEST_LIFETIME_SECS, true),
        ] {
            let mut config = with_reload_secs(60).expect("the baseline document is valid");
            config.local.request_lifetime_secs = secs;
            let result = config.validate();
            if accepted {
                result.unwrap_or_else(|e| panic!("lifetime {secs} is inside the bound: {e}"));
            } else {
                let error = result.expect_err("a lifetime outside the bound must be refused");
                assert!(
                    error.to_string().contains("local.request_lifetime_secs"),
                    "lifetime {secs}: got {error}"
                );
            }
        }
    }

    #[test]
    fn the_request_lifetime_ceiling_is_the_profiles() {
        assert_eq!(
            MAX_REQUEST_LIFETIME_SECS,
            mcp_re_http_profile::VerifierPolicy::DEFAULT_MAX_SIGNATURE_VALIDITY
        );
    }
}
