// SPDX-License-Identifier: Apache-2.0
//! The client sidecar's configuration document.
//!
//! One JSON file rather than a flag surface. The proxy takes flags because its
//! configuration is flat and a container image passes it as `args`; a client's is not
//! flat — a route carries an audience tuple, a list of artifact bindings and a header
//! set — and flattening that into repeated flags produces a shape where the bindings of
//! one route can silently attach to another.
//!
//! `deny_unknown_fields` throughout: a misspelled security field must be a startup
//! failure, never a silently-defaulted one. `allow_non_loopback` spelled
//! `allow_nonloopback` would otherwise leave the guard on and read as though it were
//! off — or, worse the other way around, leave a field the operator believes is set
//! doing nothing.

use std::net::SocketAddr;
use std::path::PathBuf;

use mcp_re_client_core::ArtifactBinding;
use mcp_re_client_core::ArtifactType;
use mcp_re_client_core::AudienceTuple;
use serde::Deserialize;
use serde::Serialize;

/// The whole configuration document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// The local plain-MCP listener.
    pub local: LocalConfig,
    /// This client's signing identity.
    pub identity: IdentityConfig,
    /// The remote MCP-RE server and the mTLS material used to reach it.
    pub remote: RemoteConfig,
    /// Where the trust anchors come from, and the durable floor under them.
    pub trust: TrustConfig,
    /// The delegated-response policy every route verifies under.
    pub delegation: DelegationConfig,
    /// The static route table. Non-empty.
    pub routes: Vec<RouteConfig>,
}

/// The local, plain-MCP leg.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalConfig {
    /// Where to accept plain MCP. Loopback unless `allow_non_loopback` says otherwise.
    pub bind: SocketAddr,
    /// Admit a NON-loopback bind address.
    ///
    /// The local leg is unauthenticated by construction — that is the point of the
    /// sidecar, the local client speaks ordinary MCP and holds no key. So anything that
    /// can reach this socket gets requests signed with this client's key, under this
    /// client's identity, against every configured route. On loopback that set is
    /// "processes on this host"; on `0.0.0.0` it is the network.
    ///
    /// Defaulting to refuse costs an operator one field in the one deployment that
    /// genuinely fronts this with its own authenticated hop, and costs nothing in the
    /// far more common one where `0.0.0.0` was copied from the server's config.
    #[serde(default)]
    pub allow_non_loopback: bool,
    /// How long a signed request stays fresh, seconds (RFC 9421 `expires - created`).
    #[serde(default = "default_request_lifetime")]
    pub request_lifetime_secs: i64,
    /// The route to use for a request whose path is not `/route/<id>`, for clients that
    /// POST to a fixed path. Absent means every request must name its route.
    #[serde(default)]
    pub default_route: Option<String>,
    /// How many local requests may be in flight at once. Beyond it the listener answers
    /// 503 rather than spawning without bound.
    #[serde(default = "default_max_in_flight")]
    pub max_in_flight: usize,
}

fn default_max_in_flight() -> usize {
    64
}

fn default_request_lifetime() -> i64 {
    60
}

/// The client's own signing identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    /// The RFC 9421 `keyid` this client signs under.
    pub key_id: String,
    /// Path to the Ed25519 seed (32 bytes, Base64URL-no-pad text) — the same file
    /// format the proxy's `FileKeySource` reads. Keep it `0600`.
    pub signing_key_seed_path: PathBuf,
}

/// The remote leg: which server, and the mTLS material to reach it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteConfig {
    /// Where the connection goes.
    pub addr: SocketAddr,
    /// The identity the server must PROVE — matched against its certificate by rustls.
    /// Not inferred from `addr`: an address is where you dialled, not who answered.
    pub expected_server_name: String,
    /// This client's certificate chain (PEM, leaf first) for mTLS client auth.
    pub client_cert_path: PathBuf,
    /// This client's TLS private key (PEM).
    pub client_key_path: PathBuf,
    /// The CA that must issue the server's certificate (PEM).
    pub server_ca_path: PathBuf,
}

/// Trust anchors and the durable rollback floor beneath them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustConfig {
    /// The signed trust-anchor manifest (ADR-MCPRE-052), re-read on every refresh.
    pub manifest_path: PathBuf,
    /// The profile the manifest must govern.
    pub profile: String,
    /// The pinned org/admin keys whose signature over a manifest this client accepts.
    /// Non-empty: a client that pins nothing accepts a manifest from anyone.
    pub org_keys: Vec<OrgKey>,
    /// The durable rollback floor.
    pub floor: FloorConfig,
    /// How often to re-read the manifest, seconds. Bounded
    /// `1..=`[`MAX_MANIFEST_RELOAD_SECS`], and not optional: the withdrawal of anchors
    /// whose manifest has passed its own `expires_at` happens in a refresh cycle and
    /// nowhere else, so the cadence is also the ceiling on how long an expired trust
    /// picture can stay in force. A client with no refresh has no expiry enforcement
    /// and no revocation path at all.
    #[serde(default = "default_manifest_reload")]
    pub reload_secs: u64,
}

fn default_manifest_reload() -> u64 {
    300
}

/// The longest accepted manifest re-read cadence.
///
/// `crate::anchors::refresh_once` is the only code that withdraws anchors once the
/// manifest in force has expired, so the interval between cycles is exactly how long a
/// lapsed trust picture keeps verifying responses. An hour bounds that without
/// dictating the common cadence, which is [`default_manifest_reload`].
pub const MAX_MANIFEST_RELOAD_SECS: u64 = 3600;

/// The largest accepted `delegation.max_clock_skew`.
///
/// The same value bounds every verifier in the profile
/// (`mcp_re_http_profile::VerifierPolicy::MAX_CLOCK_SKEW_BOUND`) — pinned equal by
/// `a_config_skew_bound_matches_the_profile_bound`. Duplicated rather than imported
/// because `mcp-re-http-profile` is not a dependency of this crate outside tests.
///
/// It has to be checked HERE because the two consumers of the value disagree about an
/// out-of-range one: the RFC 9421 freshness gate falls back to the profile default,
/// while the delegated-credential window uses the number raw. Unbounded, that combination
/// accepts a server credential arbitrarily far past its `exp` while reporting nothing.
pub const MAX_CLOCK_SKEW_SECS: i64 = 300;

/// A pinned manifest-signing key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrgKey {
    /// The `signer_kid` this key answers to.
    pub kid: String,
    /// The Ed25519 public key, Base64URL-no-pad.
    pub public_key: String,
}

/// Where the accepted-manifest-version floor lives.
///
/// Named rather than defaulted. `InMemoryVersionFloor` protects against rollback
/// within one process lifetime and says nothing about the next one, so "which floor"
/// has to be a decision an operator made and can be seen to have made — a client that
/// silently got the ephemeral floor would report the same posture as one with a durable
/// one while providing none of it across the restart that matters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum FloorConfig {
    /// Durable: a directory of version markers (`FileManifestFloor`).
    Durable {
        /// The floor directory. Put it on storage that survives a restart.
        dir: PathBuf,
        /// The operator-declared minimum the floor can never read below, whatever the
        /// filesystem says. This is the part of the floor an attacker cannot reach by
        /// unlinking it, and the part an ephemeral volume cannot lose.
        #[serde(default)]
        bootstrap_version: u64,
    },
    /// Explicitly NO durability across restarts, for an ephemeral client that accepts
    /// re-opening the rollback window on every start.
    Ephemeral {
        /// The version to start the in-process floor at.
        #[serde(default)]
        bootstrap_version: u64,
    },
}

/// The delegated-response policy (ADR-MCPRE-052 §3) every route verifies under.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationConfig {
    /// This client's accepted verifier audience identifier(s).
    pub verifier_audiences: Vec<String>,
    /// The audience-scope hash the server's delegated key must be scoped to.
    pub expected_audience_hash: String,
    /// The accepted trust-epoch set — `{current}`, or `{current, previous}` inside a
    /// bounded rollout window.
    pub accepted_epochs: Vec<String>,
    /// Clock-skew tolerance, seconds. Governs both the credential window and the
    /// RFC 9421 response-signature freshness gate. Bounded `0..=`[`MAX_CLOCK_SKEW_SECS`].
    #[serde(default = "default_skew")]
    pub max_clock_skew: i64,
}

fn default_skew() -> i64 {
    60
}

/// One configured route.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// The static route id. The local client selects it by path: `POST /route/<id>`.
    pub route_id: String,
    /// The canonical RFC 9421 `@target-uri`.
    pub target_uri: String,
    /// The audience tuple this route's requests are scoped to.
    pub audience: AudienceTuple,
    /// The authorization artifact bindings bound into every signed request on this
    /// route. Non-empty: the server rejects a request whose evidence block has none.
    pub artifact_bindings: Vec<BindingConfig>,
    /// Extra request headers to send AND cover in the signature.
    #[serde(default)]
    pub extra_headers: Vec<HeaderConfig>,
    /// The pinned server signer keyid, if this route pins one.
    #[serde(default)]
    pub expected_server_keyid: Option<String>,
}

/// A request header sent on a route and covered by its signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderConfig {
    /// The header name.
    pub name: String,
    /// The header value, verbatim.
    pub value: String,
}

/// An artifact binding and where its bytes come from.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingConfig {
    /// Which authorization artifact this binds.
    pub artifact_type: ArtifactType,
    /// The bytes to digest.
    pub source: BindingSource,
}

/// Where an artifact binding's digested bytes come from.
///
/// A binding must digest the SAME bytes the server sees, which is why the header form
/// names a header rather than restating its value: an OAuth-DPoP binding whose digest
/// covers one token while the `Authorization` header carries another is a binding to
/// nothing, and restating the value in two config fields is how that happens.
///
/// Which forms are legal is therefore per artifact type, and [`ClientConfig::validate`]
/// enforces it: for an artifact the verifier recovers from the request itself — the
/// DPoP access token, which it takes from the covered `Authorization` header — only
/// [`BindingSource::Header`] can name the transmitted bytes, so the literal and file
/// forms are refused there rather than left to fail as an opaque
/// `artifact_binding_failed` at request time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum BindingSource {
    /// Digest the value of one of this route's `extra_headers`, byte for byte.
    Header {
        /// The header name, matched case-insensitively against `extra_headers`.
        name: String,
    },
    /// Digest a literal string from the config.
    Literal {
        /// The exact text to digest.
        value: String,
    },
    /// Digest the contents of a file, read once at startup.
    File {
        /// The file whose bytes are digested.
        path: PathBuf,
    },
}

/// A configuration that could not be used as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn err(message: impl Into<String>) -> ConfigError {
    ConfigError(message.into())
}

/// The header the profile's verifier reads a DPoP access token from.
const AUTHORIZATION: &str = "Authorization";

/// The bearer credential inside an `Authorization` header value, or `None`.
///
/// Byte-identical to the verifier's own extraction
/// (`mcp_re_http_profile::authorization_bearer_bytes`), pinned by
/// `a_dpop_binding_digests_what_the_verifier_digests`: the digest must cover the token,
/// not the `Bearer ` scheme in front of it, or the binding cannot verify anywhere.
fn bearer_token(authorization_header: &str) -> Option<&str> {
    let token = authorization_header.strip_prefix("Bearer ")?.trim();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

impl ClientConfig {
    /// Parse a configuration document.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ConfigError> {
        let config: ClientConfig =
            serde_json::from_slice(bytes).map_err(|e| err(format!("config: {e}")))?;
        config.validate()?;
        Ok(config)
    }

    /// Read and parse a configuration file.
    pub fn read(path: &std::path::Path) -> Result<Self, ConfigError> {
        let bytes =
            std::fs::read(path).map_err(|e| err(format!("config {}: {e}", path.display())))?;
        ClientConfig::from_json(&bytes)
    }

    /// The checks that cannot be expressed in the type: non-empty collections, unique
    /// route ids, a resolvable binding source, and the loopback guard.
    ///
    /// Public because every field of this struct is public and the type derives
    /// `Deserialize`: a consumer that builds or mutates a config rather than going
    /// through [`ClientConfig::from_json`] must be able to re-establish the invariant,
    /// and [`crate::build`] runs it on whatever it is handed for the same reason.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.local.allow_non_loopback && !self.local.bind.ip().is_loopback() {
            return Err(err(format!(
                "local.bind {} is not a loopback address. The local leg is \
                 unauthenticated, so binding it off-host offers this client's signing \
                 key as a service to the network. Set local.allow_non_loopback if that \
                 is genuinely intended.",
                self.local.bind
            )));
        }
        if self.local.request_lifetime_secs <= 0 {
            return Err(err("local.request_lifetime_secs must be positive"));
        }
        if self.local.max_in_flight == 0 {
            return Err(err("local.max_in_flight must be positive"));
        }
        if self.trust.org_keys.is_empty() {
            return Err(err(
                "trust.org_keys is empty: a client that pins no manifest-signing key \
                 accepts a trust-anchor manifest signed by anyone",
            ));
        }
        if self.delegation.verifier_audiences.is_empty() {
            return Err(err("delegation.verifier_audiences is empty"));
        }
        if self.delegation.accepted_epochs.is_empty() {
            return Err(err("delegation.accepted_epochs is empty"));
        }
        if !(0..=MAX_CLOCK_SKEW_SECS).contains(&self.delegation.max_clock_skew) {
            return Err(err(format!(
                "delegation.max_clock_skew {} is outside 0..={MAX_CLOCK_SKEW_SECS}. The value \
                 widens the delegated credential's nbf/exp window directly, so an unbounded one \
                 accepts a server credential long past its exp — while the response-signature \
                 freshness gate silently reverts to the profile default, leaving no symptom",
                self.delegation.max_clock_skew
            )));
        }
        if !(1..=MAX_MANIFEST_RELOAD_SECS).contains(&self.trust.reload_secs) {
            return Err(err(format!(
                "trust.reload_secs {} is outside 1..={MAX_MANIFEST_RELOAD_SECS}. Withdrawing \
                 anchors whose manifest has passed its expires_at happens in a refresh cycle and \
                 nowhere else, so 0 leaves an expired trust picture verifying forever and a long \
                 cadence is how long it keeps doing so",
                self.trust.reload_secs
            )));
        }
        if self.routes.is_empty() {
            return Err(err("routes is empty"));
        }
        if let Some(default_route) = &self.local.default_route {
            if !self.routes.iter().any(|r| &r.route_id == default_route) {
                return Err(err(format!(
                    "local.default_route {default_route:?} names no configured route"
                )));
            }
        }
        let mut seen = std::collections::HashSet::new();
        for route in &self.routes {
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
                if let BindingSource::Header { name } = &binding.source {
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
                    if binding.artifact_type == ArtifactType::OauthDpop
                        && bearer_token(&header.value).is_none()
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
            }
        }
        Ok(())
    }
}

impl RouteConfig {
    /// Resolve this route's bindings into digested [`ArtifactBinding`]s.
    ///
    /// Header bytes are taken from THIS route's `extra_headers`, so the digest covers
    /// exactly the bytes the request will carry — and for `oauth-dpop`, exactly the
    /// bytes the verifier recovers from that header: RFC 9449's `ath` is over the
    /// access token, so the `Bearer ` scheme in front of it is not part of the digest.
    pub fn resolve_bindings(&self) -> Result<Vec<ArtifactBinding>, ConfigError> {
        self.artifact_bindings
            .iter()
            .map(|binding| {
                let bytes: Vec<u8> = match &binding.source {
                    BindingSource::Header { name } => {
                        let value = self
                            .extra_headers
                            .iter()
                            .find(|h| h.name.eq_ignore_ascii_case(name))
                            .map(|h| h.value.as_str())
                            .ok_or_else(|| {
                                err(format!(
                                    "route {:?} sends no header {name:?}",
                                    self.route_id
                                ))
                            })?;
                        if binding.artifact_type == ArtifactType::OauthDpop {
                            bearer_token(value)
                                .ok_or_else(|| {
                                    err(format!(
                                        "route {:?} binds an oauth-dpop artifact to header \
                                         {name:?}, whose value is not a Bearer credential",
                                        self.route_id
                                    ))
                                })?
                                .as_bytes()
                                .to_vec()
                        } else {
                            value.as_bytes().to_vec()
                        }
                    }
                    BindingSource::Literal { value } => value.as_bytes().to_vec(),
                    BindingSource::File { path } => std::fs::read(path).map_err(|e| {
                        err(format!(
                            "route {:?} binding file {}: {e}",
                            self.route_id,
                            path.display()
                        ))
                    })?,
                };
                Ok(ArtifactBinding::opaque_digest(
                    binding.artifact_type,
                    &bytes,
                ))
            })
            .collect()
    }

    /// This route's headers as the `(name, value)` pairs the signer covers.
    pub fn header_pairs(&self) -> Vec<(String, String)> {
        self.extra_headers
            .iter()
            .map(|h| (h.name.clone(), h.value.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(local: &str, routes: &str) -> String {
        format!(
            r#"{{
  "local": {local},
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
    "floor": {{ "kind": "durable", "dir": "/var/lib/mcp-re/floor" }}
  }},
  "delegation": {{
    "verifier_audiences": ["v1"],
    "expected_audience_hash": "v1",
    "accepted_epochs": ["e1"]
  }},
  "routes": {routes}
}}"#
        )
    }

    const ROUTE: &str = r#"[{
      "route_id": "r1",
      "target_uri": "https://mcp.example.com/mcp",
      "audience": { "audience_id": "v1", "target_uri": "https://mcp.example.com/mcp", "route": "a" },
      "extra_headers": [{ "name": "Authorization", "value": "Bearer tok" }],
      "artifact_bindings": [{ "artifact_type": "oauth-dpop", "source": { "kind": "header", "name": "Authorization" } }]
    }]"#;

    #[test]
    fn a_loopback_bind_is_accepted() {
        let doc = document(r#"{ "bind": "127.0.0.1:8640" }"#, ROUTE);
        ClientConfig::from_json(doc.as_bytes()).expect("loopback config loads");
    }

    /// The local leg carries no authentication, so an off-host bind hands the signing
    /// key to the network. Refusing by default is the whole guard.
    #[test]
    fn a_non_loopback_bind_is_refused_unless_declared() {
        let doc = document(r#"{ "bind": "0.0.0.0:8640" }"#, ROUTE);
        let error = ClientConfig::from_json(doc.as_bytes()).expect_err("must refuse");
        assert!(
            error.0.contains("not a loopback address"),
            "unexpected: {error}"
        );

        let declared = document(
            r#"{ "bind": "0.0.0.0:8640", "allow_non_loopback": true }"#,
            ROUTE,
        );
        ClientConfig::from_json(declared.as_bytes()).expect("an explicit opt-in is honoured");
    }

    /// An unknown field is a startup failure, not a silent default — a misspelled
    /// security switch must never read as "off" while the operator believes it is on.
    #[test]
    fn an_unknown_field_fails_rather_than_defaulting() {
        let doc = document(
            r#"{ "bind": "127.0.0.1:8640", "allow_nonloopback": true }"#,
            ROUTE,
        );
        ClientConfig::from_json(doc.as_bytes()).expect_err("a misspelled field must fail closed");
    }

    /// A binding that digests a header the route does not send is a binding to nothing.
    #[test]
    fn a_binding_on_an_unsent_header_is_refused() {
        let route = r#"[{
          "route_id": "r1",
          "target_uri": "https://mcp.example.com/mcp",
          "audience": { "audience_id": "v1", "target_uri": "https://mcp.example.com/mcp", "route": "a" },
          "artifact_bindings": [{ "artifact_type": "oauth-dpop", "source": { "kind": "header", "name": "Authorization" } }]
        }]"#;
        let error =
            ClientConfig::from_json(document(r#"{ "bind": "127.0.0.1:8640" }"#, route).as_bytes())
                .expect_err("must refuse");
        assert!(error.0.contains("does not send"), "unexpected: {error}");
    }

    /// The header form digests the bytes the VERIFIER recovers from the request.
    ///
    /// For `oauth-dpop` that is RFC 9449's `ath` — the access token — not the whole
    /// header value: the profile takes the credential from the covered `Authorization`
    /// header via `authorization_bearer_bytes`, which strips the `Bearer ` scheme. A
    /// digest over the scheme-prefixed value is one no verifier can ever match, so the
    /// route's only permitted binding form would fail closed on every request.
    #[test]
    fn a_dpop_binding_digests_what_the_verifier_digests() {
        let route = r#"[{
          "route_id": "r1",
          "target_uri": "https://mcp.example.com/mcp",
          "audience": { "audience_id": "v1", "target_uri": "https://mcp.example.com/mcp", "route": "a" },
          "extra_headers": [{ "name": "Authorization", "value": "Bearer tok-1" }],
          "artifact_bindings": [{ "artifact_type": "oauth-dpop", "source": { "kind": "header", "name": "authorization" } }]
        }]"#;
        let config =
            ClientConfig::from_json(document(r#"{ "bind": "127.0.0.1:8640" }"#, route).as_bytes())
                .expect("loads");
        let resolved = config.routes[0]
            .resolve_bindings()
            .expect("bindings resolve");
        // The verifier's own extraction over the headers this route sends.
        let credential =
            mcp_re_http_profile::authorization_bearer_bytes(&config.routes[0].header_pairs())
                .expect("the route sends a bearer credential");
        assert_eq!(credential, b"tok-1");
        assert_eq!(
            resolved,
            vec![ArtifactBinding::opaque_digest(
                ArtifactType::OauthDpop,
                &credential
            )],
            "the digest must cover the token the verifier digests, not the header value"
        );
    }

    /// A non-dpop header binding still digests the header value verbatim: nothing in
    /// the profile re-interprets those bytes.
    #[test]
    fn a_non_dpop_header_binding_digests_the_value_verbatim() {
        let route = r#"[{
          "route_id": "r1",
          "target_uri": "https://mcp.example.com/mcp",
          "audience": { "audience_id": "v1", "target_uri": "https://mcp.example.com/mcp", "route": "a" },
          "extra_headers": [{ "name": "X-Rar", "value": "details-blob" }],
          "artifact_bindings": [{ "artifact_type": "oauth-rar", "source": { "kind": "header", "name": "x-rar" } }]
        }]"#;
        let config =
            ClientConfig::from_json(document(r#"{ "bind": "127.0.0.1:8640" }"#, route).as_bytes())
                .expect("loads");
        assert_eq!(
            config.routes[0].resolve_bindings().expect("resolve"),
            vec![ArtifactBinding::opaque_digest(
                ArtifactType::OauthRar,
                b"details-blob"
            )]
        );
    }

    /// A restated token is the binding-to-nothing the type documentation forbids: the
    /// verifier reads the credential from the `Authorization` header the request
    /// carries, so a literal only matches it by coincidence.
    #[test]
    fn a_literal_or_file_dpop_binding_is_refused() {
        for source in [
            r#"{ "kind": "literal", "value": "Bearer B" }"#,
            r#"{ "kind": "file", "path": "/dev/null" }"#,
        ] {
            let route = format!(
                r#"[{{
              "route_id": "r1",
              "target_uri": "https://mcp.example.com/mcp",
              "audience": {{ "audience_id": "v1", "target_uri": "https://mcp.example.com/mcp", "route": "a" }},
              "extra_headers": [{{ "name": "Authorization", "value": "Bearer A" }}],
              "artifact_bindings": [{{ "artifact_type": "oauth-dpop", "source": {source} }}]
            }}]"#
            );
            let error = ClientConfig::from_json(
                document(r#"{ "bind": "127.0.0.1:8640" }"#, &route).as_bytes(),
            )
            .expect_err("a restated dpop credential must not start");
            assert!(
                error.0.contains("binding to nothing"),
                "unexpected: {error}"
            );
        }
    }

    /// The verifier reads the token from `Authorization` and nowhere else, so binding
    /// a dpop artifact to some other header the route happens to send digests bytes no
    /// verifier will look at.
    #[test]
    fn a_dpop_binding_on_another_header_is_refused() {
        let route = r#"[{
          "route_id": "r1",
          "target_uri": "https://mcp.example.com/mcp",
          "audience": { "audience_id": "v1", "target_uri": "https://mcp.example.com/mcp", "route": "a" },
          "extra_headers": [{ "name": "X-Token", "value": "Bearer A" }],
          "artifact_bindings": [{ "artifact_type": "oauth-dpop", "source": { "kind": "header", "name": "X-Token" } }]
        }]"#;
        let error =
            ClientConfig::from_json(document(r#"{ "bind": "127.0.0.1:8640" }"#, route).as_bytes())
                .expect_err("must refuse");
        assert!(
            error.0.contains("and no other header"),
            "unexpected: {error}"
        );
    }

    /// A dpop binding over a header carrying no Bearer credential digests something
    /// the verifier cannot even extract.
    #[test]
    fn a_dpop_binding_on_a_non_bearer_authorization_is_refused() {
        let route = r#"[{
          "route_id": "r1",
          "target_uri": "https://mcp.example.com/mcp",
          "audience": { "audience_id": "v1", "target_uri": "https://mcp.example.com/mcp", "route": "a" },
          "extra_headers": [{ "name": "Authorization", "value": "Basic dXNlcjpwdw==" }],
          "artifact_bindings": [{ "artifact_type": "oauth-dpop", "source": { "kind": "header", "name": "Authorization" } }]
        }]"#;
        let error =
            ClientConfig::from_json(document(r#"{ "bind": "127.0.0.1:8640" }"#, route).as_bytes())
                .expect_err("must refuse");
        assert!(
            error.0.contains("not a Bearer credential"),
            "unexpected: {error}"
        );
    }

    /// The mTLS binding commits to the DER of the certificate the TLS layer presents.
    #[test]
    fn a_literal_mtls_binding_is_refused() {
        let route = r#"[{
          "route_id": "r1",
          "target_uri": "https://mcp.example.com/mcp",
          "audience": { "audience_id": "v1", "target_uri": "https://mcp.example.com/mcp", "route": "a" },
          "artifact_bindings": [{ "artifact_type": "oauth-mtls", "source": { "kind": "literal", "value": "my-cert" } }]
        }]"#;
        let error =
            ClientConfig::from_json(document(r#"{ "bind": "127.0.0.1:8640" }"#, route).as_bytes())
                .expect_err("must refuse");
        assert!(
            error.0.contains("config text cannot restate"),
            "unexpected: {error}"
        );
    }

    /// The bound has to be the profile's, or the config admits a value
    /// `VerifierPolicy::new` will reject and silently replace with its default.
    #[test]
    fn a_config_skew_bound_matches_the_profile_bound() {
        assert_eq!(
            MAX_CLOCK_SKEW_SECS,
            mcp_re_http_profile::VerifierPolicy::MAX_CLOCK_SKEW_BOUND
        );
    }

    /// An unbounded skew widens the delegated credential window raw while the
    /// freshness gate reverts to the default, so the misconfiguration has no symptom
    /// at all unless it is refused here.
    #[test]
    fn an_out_of_range_clock_skew_is_refused() {
        let doc = document(r#"{ "bind": "127.0.0.1:8640" }"#, ROUTE).replace(
            r#""accepted_epochs": ["e1"]"#,
            r#""accepted_epochs": ["e1"], "max_clock_skew": 31536000"#,
        );
        let error = ClientConfig::from_json(doc.as_bytes()).expect_err("must refuse");
        assert!(error.0.contains("max_clock_skew"), "unexpected: {error}");

        let negative = document(r#"{ "bind": "127.0.0.1:8640" }"#, ROUTE).replace(
            r#""accepted_epochs": ["e1"]"#,
            r#""accepted_epochs": ["e1"], "max_clock_skew": -1"#,
        );
        ClientConfig::from_json(negative.as_bytes()).expect_err("a negative skew must not start");

        let at_bound = document(r#"{ "bind": "127.0.0.1:8640" }"#, ROUTE).replace(
            r#""accepted_epochs": ["e1"]"#,
            &format!(r#""accepted_epochs": ["e1"], "max_clock_skew": {MAX_CLOCK_SKEW_SECS}"#),
        );
        ClientConfig::from_json(at_bound.as_bytes()).expect("the bound itself is legal");
    }

    /// Withdrawing anchors past the manifest's own `expires_at` happens in a refresh
    /// cycle and nowhere else, so a client with no refresh keeps verifying under a
    /// trust picture whose governing document lapsed — and a long cadence is exactly
    /// how long it does so.
    #[test]
    fn a_disabled_or_unbounded_reload_cadence_is_refused() {
        for secs in ["0", "86400"] {
            let doc = document(r#"{ "bind": "127.0.0.1:8640" }"#, ROUTE).replace(
                r#""floor": { "kind": "durable", "dir": "/var/lib/mcp-re/floor" }"#,
                &format!(
                    r#""floor": {{ "kind": "durable", "dir": "/var/lib/mcp-re/floor" }}, "reload_secs": {secs}"#
                ),
            );
            let error = ClientConfig::from_json(doc.as_bytes())
                .expect_err("a cadence outside the bound must not start");
            assert!(
                error.0.contains("trust.reload_secs"),
                "reload_secs {secs}: unexpected {error}"
            );
        }
        let ok = document(r#"{ "bind": "127.0.0.1:8640" }"#, ROUTE).replace(
            r#""floor": { "kind": "durable", "dir": "/var/lib/mcp-re/floor" }"#,
            &format!(
                r#""floor": {{ "kind": "durable", "dir": "/var/lib/mcp-re/floor" }}, "reload_secs": {MAX_MANIFEST_RELOAD_SECS}"#
            ),
        );
        ClientConfig::from_json(ok.as_bytes()).expect("the bound itself is legal");
    }

    /// Two routes under one id would leave the later one's bindings attached to the
    /// earlier one's name.
    #[test]
    fn a_duplicate_route_id_is_refused() {
        let routes = r#"[
          {
            "route_id": "r1",
            "target_uri": "https://a.example.com/mcp",
            "audience": { "audience_id": "v1", "target_uri": "https://a.example.com/mcp", "route": "a" },
            "artifact_bindings": [{ "artifact_type": "oauth-rar", "source": { "kind": "literal", "value": "x" } }]
          },
          {
            "route_id": "r1",
            "target_uri": "https://b.example.com/mcp",
            "audience": { "audience_id": "v1", "target_uri": "https://b.example.com/mcp", "route": "b" },
            "artifact_bindings": [{ "artifact_type": "oauth-rar", "source": { "kind": "literal", "value": "y" } }]
          }
        ]"#;
        let error =
            ClientConfig::from_json(document(r#"{ "bind": "127.0.0.1:8640" }"#, routes).as_bytes())
                .expect_err("must refuse");
        assert!(
            error.0.contains("duplicate route_id"),
            "unexpected: {error}"
        );
    }

    /// Pinning nothing means accepting a manifest signed by anyone.
    #[test]
    fn an_empty_org_key_pin_set_is_refused() {
        let doc = document(r#"{ "bind": "127.0.0.1:8640" }"#, ROUTE)
            .replace(r#"[{ "kid": "org-1", "public_key": "AAAA" }]"#, "[]");
        let error = ClientConfig::from_json(doc.as_bytes()).expect_err("must refuse");
        assert!(
            error.0.contains("pins no manifest-signing key"),
            "unexpected: {error}"
        );
    }

    /// Which floor is a decision, so it is spelled out; an absent `floor` does not
    /// quietly become the ephemeral one.
    #[test]
    fn the_floor_must_be_named() {
        let floor =
            ",\n    \"floor\": { \"kind\": \"durable\", \"dir\": \"/var/lib/mcp-re/floor\" }";
        let full = document(r#"{ "bind": "127.0.0.1:8640" }"#, ROUTE);
        let doc = full.replace(floor, "");
        assert_ne!(
            doc, full,
            "the fixture must actually lose its floor, or this test passes for the \
             wrong reason"
        );
        ClientConfig::from_json(doc.as_bytes())
            .expect_err("a document with no floor must not start");
    }
}
