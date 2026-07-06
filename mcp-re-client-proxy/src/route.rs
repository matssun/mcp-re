//! Route registry + per-route policy (MCPS-49, #196; ADR-MCPS-044 §Security
//! adapter scope).
//!
//! Route resolution is STATIC — a route is looked up by a configured route id, not
//! inferred from the request's intent. This keeps the proxy a security adapter, not
//! an orchestrator: "static route resolution IN, intent routing OUT".

use mcp_re_client_core::AuthorizationBindingPolicy;
use mcp_re_client_core::AuthorizationBindingProvider;
use mcp_re_client_core::EnforcementMode;
use mcp_re_client_core::SignerAudienceBinding;
use std::collections::HashMap;

/// One configured route: the enforcement posture, whether legacy fallback is
/// explicitly permitted, the resolved signer→audience binding, and the
/// authorization-binding policy + provider used to bind each request.
pub struct Route {
    /// The static route id (the registry key).
    pub route_id: String,
    /// Strict (`require_mcp_re`) or migration (`allow_legacy_explicit`).
    pub enforcement_mode: EnforcementMode,
    /// Whether THIS route is explicitly legacy-allowlisted (only consulted under
    /// `allow_legacy_explicit`).
    pub legacy_allowed: bool,
    /// The expected `(server_signer, audience)` for this route (MCPS-43).
    pub signer_audience: SignerAudienceBinding,
    /// The permitted authorization-binding types for this route (MCPS-45).
    pub authz_policy: AuthorizationBindingPolicy,
    /// The provider producing the per-request authorization binding (MCPS-45).
    pub authz_provider: Box<dyn AuthorizationBindingProvider>,
}

/// A static registry of routes keyed by route id. Populated from explicit config;
/// the proxy never adds or rewrites a route at runtime from request content.
#[derive(Default)]
pub struct RouteRegistry {
    routes: HashMap<String, Route>,
}

impl RouteRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        RouteRegistry::default()
    }

    /// Register a route under its `route_id`.
    pub fn register(mut self, route: Route) -> Self {
        self.routes.insert(route.route_id.clone(), route);
        self
    }

    /// Look up a route by id (static resolution).
    pub fn get(&self, route_id: &str) -> Option<&Route> {
        self.routes.get(route_id)
    }
}
