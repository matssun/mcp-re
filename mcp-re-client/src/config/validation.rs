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
//!
//! The last is the subtle one. A binding that digests a value the request need not send is
//! a binding to NOTHING: it commits to bytes the verifier will never see, so it passes
//! locally and proves nothing at the far end. Every arm below refuses one shape of that.

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

/// Where this client offers its signing key, and the bounds that keep one caller from
/// holding the sidecar.
pub(super) fn check_local(local: &LocalConfig) -> Result<(), ConfigError> {
    // The refusal itself is `BindScope`'s, not a statement here that happens to run
    // first: a scope in hand means the bind was permitted, so there is no check at this
    // site that could be deleted to admit an off-host listener.
    BindScope::decide(local.bind, local.allow_non_loopback)?;
    if local.request_lifetime_secs <= 0 {
        return Err(err("local.request_lifetime_secs must be positive"));
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
        // The verifier takes the DPoP credential from the request's covered
        // `Authorization` header, never from anything the caller restates, so
        // that header is the only place a digest can commit to transmitted
        // bytes. A literal or a file digests a value that only has to match
        // by coincidence — the binding-to-nothing this type documents.
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
