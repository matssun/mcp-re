// SPDX-License-Identifier: Apache-2.0
//! Route registry + per-route RFC 9421 evidence policy (MCPS-49, #196).
//!
//! Route resolution is STATIC — a route is looked up by a configured route id, not
//! inferred from the request's intent. The proxy is a security adapter, not an
//! orchestrator: "static route resolution IN, intent routing OUT".

use mcp_re_client_core::ArtifactBinding;
use mcp_re_client_core::AudienceTuple;
use mcp_re_client_core::DelegationPolicy;
use mcp_re_client_core::ResolvedActor;
use mcp_re_client_core::RevocationSource;
use mcp_re_client_core::SignerSlot;
use mcp_re_client_core::TrustedIssuerSet;
use std::collections::HashMap;

/// The per-route trust seam: resolve the response signer keyid to a structured
/// actor for RFC 9421 response verification.
pub type RouteActorResolver = Box<dyn Fn(&str, SignerSlot) -> Option<ResolvedActor> + Send + Sync>;

/// How the proxy verifies the server's response for a route. Delegated-signing is the
/// ONLY response mode (ADR-MCPRE-052, MCPRE-122): the client enforces the same
/// strictness as the server — a delegated-signed response is required, and any
/// direct-root, unsigned, or object/`_meta` carrier fails closed. There is no
/// direct-root client verification mode.
///
/// Both variants carry the ROOT-resolving trust seam INSIDE them. It used to be a
/// separate `Route::resolve_actor` field, which made the two halves of a trust decision
/// — which roots resolve, and which are revoked — independently settable. A route could
/// then resolve roots from one source and check revocation against another (or against
/// nothing), and revocation would be silently inert. Keeping them in one variant means
/// a route cannot be built with a mismatched pair.
pub enum ClientVerification {
    /// Verify a delegated-signed response (a success OR a rejection receipt) carrying
    /// the inline delegation credential. No direct-root, unsigned, or object/`_meta`
    /// downgrade is accepted.
    ///
    /// For a resolver and a revocation source that are genuinely DIFFERENT objects — a
    /// live directory plus a separately-fed denylist. The [`RevocationSource`] is a
    /// required field, so the verifier is never silently never-revoked (ADR-MCPRE-052 §3
    /// step 7); an operator relying on short TTLs alone passes an explicit empty
    /// `StaticRevocationList` — a visible choice, not a default.
    ///
    /// The resolver receives no `now`, so it cannot express a time-bounded trust
    /// decision. Use [`ClientVerification::DelegatedAnchored`] for anything with an
    /// overlap window.
    DelegatedRequired(DelegationPolicy, RouteActorResolver, Box<dyn RevocationSource>),
    /// Verify against a [`TrustedIssuerSet`] — the trust-anchor lifecycle: current
    /// roots, retiring roots with a `valid_until` overlap deadline, revoked roots.
    ///
    /// This is the variant a signed trust-anchor manifest loads into
    /// ([`mcp_re_client_core::load_signed_manifest_with_floor`]). The set supplies both
    /// the resolver and the revocation source, and the proxy rebuilds the resolver per
    /// request with that request's `now` — so a retiring root stops being trusted the
    /// moment its window closes, rather than at whatever time the route was built.
    DelegatedAnchored(DelegationPolicy, TrustedIssuerSet),
}

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
    /// The authorization artifact bindings bound into each signed request (required,
    /// non-empty — the server rejects a request whose evidence block has no binding).
    pub artifact_bindings: Vec<ArtifactBinding>,
    /// Extra request headers to include AND cover in the signed request — e.g. the
    /// `Authorization: Bearer <token>` header whose bytes an OAuth-DPoP artifact
    /// binding digests. Empty when no binding needs a request header.
    pub extra_headers: Vec<(String, String)>,
    /// The expected server signer keyid (pinned). Under delegated-signing the trust
    /// pinning is the ROOT `issuer_kid` the resolver resolves (the delegated key is
    /// authorized by the credential, not enrolled); this field is retained for route
    /// bookkeeping.
    pub expected_server_keyid: Option<String>,
    /// How the server's response is verified for this route (delegated-signing),
    /// INCLUDING the trust seam that resolves the credential's ROOT `issuer_kid`. The
    /// resolver lives inside the variant so it cannot be paired with a revocation
    /// source that describes a different set of roots.
    pub verification: ClientVerification,
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
