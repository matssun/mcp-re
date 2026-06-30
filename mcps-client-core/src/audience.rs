//! Signer→audience binding resolution (MCPS-43, #190; ADR-MCPS-043 §Signer→audience
//! binding; CONTEXT.md §Signer→audience binding).
//!
//! The expected `(server_signer, audience)` pair is resolved from LOCAL policy +
//! the VERIFIED transport identity, **before discovery is consulted**. Discovery
//! may describe a server but can never choose, widen, or rewrite the audience —
//! [`resolve_signer_audience`] takes no discovery input at all, so that property is
//! structural.
//!
//! `audience` is a concrete TUPLE `{scheme, host, port, tenant_id, route_id, realm}`,
//! not a bare hostname. The `tenant_id` and `route_id` discriminators are MANDATORY
//! (non-empty) because one signer commonly serves many audiences on the same host
//! (shared-SaaS / wildcard certs): hostname alone is insufficient, so two tenants
//! or routes on the same host get DISTINCT audience strings — a request/response for
//! one can never be replayed as the other (the audience changes the signed preimage,
//! hence the `request_hash`).
//!
//! The signed response carries no `audience` field; it binds the request (and thus
//! the audience baked into it) via `request_hash` (MCPS-41), and its `server_signer`
//! must equal the resolved expected signer (the pinned-signer guard,
//! [`crate::ResponseExpectation::with_expected_server_signer`]). A re-targeted
//! response therefore fails closed at the `request_hash` / signer binding.

use mcps_core::McpsError;
use std::collections::HashMap;

/// A concrete audience tuple. Canonicalizes to the single `audience` string carried
/// in the request envelope; `tenant_id` and `route_id` are mandatory discriminators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudienceTuple {
    scheme: String,
    host: String,
    port: u16,
    tenant_id: String,
    route_id: String,
    realm: String,
}

/// Escape the tuple field delimiters (`%`, `;`, `=`) so the canonical string is
/// unambiguous and reversible regardless of field contents.
fn escape_field(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace(';', "%3B")
        .replace('=', "%3D")
}

impl AudienceTuple {
    /// Build an audience tuple. `tenant_id` and `route_id` are MANDATORY: an empty
    /// discriminator is rejected with [`McpsError::InvalidAudience`] (hostname alone
    /// is insufficient for shared-SaaS/wildcard signers).
    pub fn new(
        scheme: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        tenant_id: impl Into<String>,
        route_id: impl Into<String>,
        realm: impl Into<String>,
    ) -> Result<Self, McpsError> {
        let tenant_id = tenant_id.into();
        let route_id = route_id.into();
        if tenant_id.is_empty() || route_id.is_empty() {
            return Err(McpsError::InvalidAudience);
        }
        Ok(AudienceTuple {
            scheme: scheme.into(),
            host: host.into(),
            port,
            tenant_id,
            route_id,
            realm: realm.into(),
        })
    }

    /// The route discriminator.
    pub fn route_id(&self) -> &str {
        &self.route_id
    }

    /// The tenant discriminator.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// The verified host this audience is bound to.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The canonical `audience` string for the request envelope. Deterministic,
    /// fixed field order, escaped — so both the signer and the verifier derive the
    /// same value, and distinct tuples never collide.
    pub fn to_audience_string(&self) -> String {
        format!(
            "mcps-audience:v1:scheme={};host={};port={};tenant={};route={};realm={}",
            escape_field(&self.scheme),
            escape_field(&self.host),
            self.port,
            escape_field(&self.tenant_id),
            escape_field(&self.route_id),
            escape_field(&self.realm),
        )
    }
}

/// The resolved expectation: the server signer plus the audience tuple bound to a
/// route. Both are produced from local policy + verified transport, never discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerAudienceBinding {
    /// The signer identity a valid response MUST carry.
    pub expected_server_signer: String,
    /// The concrete audience tuple the request is bound to.
    pub audience: AudienceTuple,
}

impl SignerAudienceBinding {
    /// The canonical audience string for the request envelope.
    pub fn audience_string(&self) -> String {
        self.audience.to_audience_string()
    }
}

/// The VERIFIED transport identity (e.g. the TLS-verified host and an optional
/// cert SAN / SPIFFE id). The binding's audience host MUST match the verified host
/// — an audience can only be bound to a transport the client actually authenticated.
#[derive(Debug, Clone)]
pub struct TransportIdentity {
    /// The transport-verified host (e.g. TLS SNI/cert CN verified by the client).
    pub verified_host: String,
    /// An optional stronger verified identity (cert SAN / SPIFFE id).
    pub verified_identity: Option<String>,
}

/// Local signer→audience policy: a per-route map of expected `(signer, audience)`
/// bindings. Resolved from explicit config; discovery never writes here.
#[derive(Debug, Clone, Default)]
pub struct SignerAudiencePolicy {
    bindings: HashMap<String, SignerAudienceBinding>,
}

impl SignerAudiencePolicy {
    /// An empty policy.
    pub fn new() -> Self {
        SignerAudiencePolicy::default()
    }

    /// Bind a route to an expected `(server_signer, audience)`. The route key is the
    /// audience tuple's `route_id` (so routes are addressed by the same discriminator
    /// the audience carries).
    pub fn bind(mut self, binding: SignerAudienceBinding) -> Self {
        self.bindings
            .insert(binding.audience.route_id().to_string(), binding);
        self
    }
}

/// Resolve the expected `(server_signer, audience)` for `route_id` from `policy`
/// and the `transport` identity — PRE-DISCOVERY. There is deliberately no discovery
/// parameter: discovery cannot choose/widen/rewrite the audience.
///
/// Fails closed when the route is unknown ([`McpsError::InvalidAudience`]) or when
/// the bound audience host does not match the verified transport host
/// ([`McpsError::TransportBindingFailed`]) — the audience is only valid on a
/// transport the client actually authenticated.
pub fn resolve_signer_audience(
    policy: &SignerAudiencePolicy,
    transport: &TransportIdentity,
    route_id: &str,
) -> Result<SignerAudienceBinding, McpsError> {
    let binding = policy
        .bindings
        .get(route_id)
        .ok_or(McpsError::InvalidAudience)?;
    if binding.audience.host() != transport.verified_host {
        return Err(McpsError::TransportBindingFailed);
    }
    Ok(binding.clone())
}

/// Client-side self-check: the audience a request actually carried must equal the
/// resolved tuple's canonical string. Used to assert the request was built against
/// the resolved audience; a mismatch is [`McpsError::InvalidAudience`].
pub fn enforce_request_audience(
    request_audience: &str,
    expected: &AudienceTuple,
) -> Result<(), McpsError> {
    if request_audience == expected.to_audience_string() {
        Ok(())
    } else {
        Err(McpsError::InvalidAudience)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(host: &str, tenant: &str, route: &str) -> AudienceTuple {
        AudienceTuple::new("https", host, 443, tenant, route, "prod").unwrap()
    }

    #[test]
    fn empty_discriminators_are_rejected() {
        assert_eq!(
            AudienceTuple::new("https", "h", 443, "", "route", "prod").unwrap_err(),
            McpsError::InvalidAudience
        );
        assert_eq!(
            AudienceTuple::new("https", "h", 443, "tenant", "", "prod").unwrap_err(),
            McpsError::InvalidAudience
        );
    }

    #[test]
    fn same_host_different_tenant_or_route_yield_distinct_audiences() {
        // Shared-SaaS / wildcard signer: hostname alone is insufficient.
        let base = tuple("api.example.com", "acme", "tools").to_audience_string();
        let other_tenant = tuple("api.example.com", "globex", "tools").to_audience_string();
        let other_route = tuple("api.example.com", "acme", "admin").to_audience_string();
        assert_ne!(base, other_tenant);
        assert_ne!(base, other_route);
        assert_ne!(other_tenant, other_route);
    }

    #[test]
    fn audience_string_is_deterministic_and_escaped() {
        let a = tuple("h", "t;e=n%t", "r").to_audience_string();
        let b = tuple("h", "t;e=n%t", "r").to_audience_string();
        assert_eq!(a, b);
        // The raw delimiter-bearing tenant is escaped, so it cannot forge fields.
        assert!(a.contains("tenant=t%3Be%3Dn%25t"));
    }

    #[test]
    fn resolve_requires_transport_host_match() {
        let binding = SignerAudienceBinding {
            expected_server_signer: "did:example:server".to_string(),
            audience: tuple("api.example.com", "acme", "tools"),
        };
        let policy = SignerAudiencePolicy::new().bind(binding.clone());

        // Matching verified host -> resolves.
        let ok_transport = TransportIdentity {
            verified_host: "api.example.com".to_string(),
            verified_identity: None,
        };
        assert_eq!(
            resolve_signer_audience(&policy, &ok_transport, "tools").unwrap(),
            binding
        );

        // Mismatched verified host -> transport binding failure (fail closed).
        let bad_transport = TransportIdentity {
            verified_host: "evil.example.com".to_string(),
            verified_identity: None,
        };
        assert_eq!(
            resolve_signer_audience(&policy, &bad_transport, "tools").unwrap_err(),
            McpsError::TransportBindingFailed
        );
    }

    #[test]
    fn unknown_route_fails_closed() {
        let policy = SignerAudiencePolicy::new();
        let transport = TransportIdentity {
            verified_host: "api.example.com".to_string(),
            verified_identity: None,
        };
        assert_eq!(
            resolve_signer_audience(&policy, &transport, "nope").unwrap_err(),
            McpsError::InvalidAudience
        );
    }

    #[test]
    fn resolution_is_independent_of_any_discovery_input() {
        // The resolver signature has no discovery parameter; the resolved audience
        // depends only on policy + transport. This test documents/locks that: the
        // same (policy, transport, route) always yields the same binding.
        let binding = SignerAudienceBinding {
            expected_server_signer: "did:example:server".to_string(),
            audience: tuple("api.example.com", "acme", "tools"),
        };
        let policy = SignerAudiencePolicy::new().bind(binding.clone());
        let transport = TransportIdentity {
            verified_host: "api.example.com".to_string(),
            verified_identity: Some("spiffe://example/acme".to_string()),
        };
        let a = resolve_signer_audience(&policy, &transport, "tools").unwrap();
        let b = resolve_signer_audience(&policy, &transport, "tools").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.expected_server_signer, "did:example:server");
    }

    #[test]
    fn request_audience_self_check() {
        let aud = tuple("api.example.com", "acme", "tools");
        assert!(enforce_request_audience(&aud.to_audience_string(), &aud).is_ok());
        assert_eq!(
            enforce_request_audience("mcps-audience:v1:scheme=https;host=other", &aud).unwrap_err(),
            McpsError::InvalidAudience
        );
    }
}
