// SPDX-License-Identifier: Apache-2.0
//! Route registry + per-route RFC 9421 evidence policy (MCPS-49, #196).
//!
//! Route resolution is STATIC — a route is looked up by a configured route id, not
//! inferred from the request's intent. The proxy is a security adapter, not an
//! orchestrator: "static route resolution IN, intent routing OUT".

use mcp_re_client_core::ArtifactBinding;
use mcp_re_client_core::AudienceTuple;
use mcp_re_client_core::ResolvedActor;
use mcp_re_client_core::SignerSlot;
use std::collections::HashMap;

/// The per-route trust seam: resolve the response signer keyid to a structured
/// actor for RFC 9421 response verification.
pub type RouteActorResolver = Box<dyn Fn(&str, SignerSlot) -> Option<ResolvedActor> + Send + Sync>;

/// One configured route: the canonical `@target-uri`, the resolved audience tuple,
/// the (required, non-empty) authorization artifact bindings, the expected server
/// signer keyid, and the trust resolver used to verify the response.
pub struct Route {
    /// The static route id (the registry key).
    pub route_id: String,
    /// The canonical RFC 9421 `@target-uri` for this route.
    pub target_uri: String,
    /// The resolved audience tuple (audience id + target uri + route).
    pub audience: AudienceTuple,
    /// The authorization artifact bindings bound into each signed request.
    pub artifact_bindings: Vec<ArtifactBinding>,
    /// The expected server signer keyid (pinned; the verified response must match).
    pub expected_server_keyid: Option<String>,
    /// The trust seam resolving the response signer for verification.
    pub resolve_actor: RouteActorResolver,
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
