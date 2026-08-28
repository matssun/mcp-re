//! Transport-binding abstraction (MCPS-024, ADR-MCPS-014).
//!
//! Phase 6 binds the MCP-RE signing identity to the transport channel: an mTLS
//! client certificate proves *which channel* a request arrived on, and the
//! transport-binding policy asserts that channel identity is consistent with the
//! request's verified `signer`. A mismatch — or a required-but-absent verified
//! client identity — fails closed with `mcp-re.transport_binding_failed`.
//!
//! This module is std-only: it defines the identity type, the provider seam, and
//! the binding policy. `mcp-re-core` stays pure — the `transport_binding_failed`
//! code lives in its taxonomy but is emitted here, at the proxy, which is the only
//! component holding the connection.

//!
//! # The reachability boundary — read this before adding anything
//!
//! This module is the LIVE half. Everything here is on the served path of every deployment
//! that enforces a channel binding.
//!
//! [`ingress`] is the DEFERRED half: the Mode-B and Mode-C LB-signed ingress assertion
//! verifiers. **No serving path can reach them.** `--transport-binding lb-assertion` and
//! `attested-ingress` are refused at Layer-A validation, and [`TransportBinding`] has
//! exactly one constructor. That unreachability is an intentional deployment fact, not an
//! oversight: the capability is neither deleted nor made selectable
//! (`docs/AGENT_INSTRUCTIONS.md` §9 names both mistakes).
//!
//! The split is at that boundary because the two halves have opposite change rules, and
//! nothing in a single file's shape said which one governed served traffic — EX-005 in
//! `docs/architecture/review-dispositions.md` measured 913 of 1268 production lines as
//! unreachable. Do not dissolve it.

/// The DEFERRED ingress-attestation capability: Mode B (v1) and Mode C (v2). Unreachable
/// from any serving path, and deliberately so — see the module note above.
pub mod ingress;

/// The client identity a channel carries, and the only two verifications that may produce
/// one.
mod identity;

pub use identity::extract_identity;
pub use identity::IdentitySource;
pub use identity::TransportIdentity;

use mcp_re_core::McpReError;

use crate::communication_assurance::bind_request_to_peer;
use crate::communication_assurance::AuthenticatedChannelPeer;
use crate::communication_assurance::RequestPeerBindingFacts;
use crate::communication_assurance::VerifiedRequestSubject;

/// Which certificate field is the AUTHORITATIVE source of the transport identity.
///
/// This is a deployment policy, not a heuristic: the proxy reads exactly the
/// configured field and NEVER silently falls through to a weaker one. If the
/// selected field is absent from the client certificate, identity extraction
/// returns `None` and the (required) transport binding fails closed — a missing
/// URI SAN must never be quietly downgraded to a DNS SAN or a Common Name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IdentityPolicy {
    /// URI Subject Alternative Name (SPIFFE-style). The recommended default:
    /// URI SANs are unambiguous, namespaced, and the SPIFFE/workload-identity
    /// convention.
    #[default]
    UriSan,
    /// DNS Subject Alternative Name. Use only when the deployment's client
    /// identities are genuinely DNS names and this is an explicit choice.
    DnsSan,
    /// Subject Common Name. LEGACY ONLY — the CN is unstructured and deprecated
    /// for identity by the CA/Browser Forum. Selecting it emits a startup
    /// warning; prefer a URI or DNS SAN.
    CnLegacy,
}

/// The parsed HTTP request headers of an inbound connection, the only request
/// context a [`TransportBindingProvider`] is given. This is a thin, case-
/// insensitive view over the already-parsed header block — providers never see
/// the socket, the body, or the TLS connection, so a header-reading provider
/// cannot accidentally reach for connection state it must not trust.
///
/// Header names compare ASCII-case-insensitively (per RFC 7230). The FIRST
/// occurrence of a name wins.
#[derive(Debug, Clone, Default)]
pub struct RequestHeaders {
    /// `(lowercased-name, raw-value)` pairs in wire order.
    headers: Vec<(String, String)>,
}

impl RequestHeaders {
    /// Parse an HTTP/1.1 header block (the bytes up to and including the
    /// terminating `\r\n\r\n`, or any prefix of it) into a header view. The
    /// request line (first line) is skipped; malformed lines without a `:` are
    /// ignored. Values are trimmed of surrounding whitespace.
    pub fn parse(header_block: &str) -> Self {
        let mut headers = Vec::new();
        for (index, line) in header_block.lines().enumerate() {
            // Skip the request line (`POST / HTTP/1.1`) and blank lines.
            if index == 0 || line.trim().is_empty() {
                continue;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }
        RequestHeaders { headers }
    }

    /// Construct directly from `(name, value)` pairs (used in tests). Names are
    /// lowercased so lookup stays case-insensitive.
    pub fn from_pairs<I, N, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (N, V)>,
        N: Into<String>,
        V: Into<String>,
    {
        let headers = pairs
            .into_iter()
            .map(|(name, value)| (name.into().to_ascii_lowercase(), value.into()))
            .collect();
        RequestHeaders { headers }
    }

    /// The first value for `name` (case-insensitive), or `None` if absent.
    pub fn first(&self, name: &str) -> Option<&str> {
        let lowered = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(header_name, _)| *header_name == lowered)
            .map(|(_, value)| value.as_str())
    }

    /// The number of values present for `name` (case-insensitive). Used to fail
    /// closed on a duplicated trust header.
    pub fn count(&self, name: &str) -> usize {
        let lowered = name.to_ascii_lowercase();
        self.headers
            .iter()
            .filter(|(header_name, _)| *header_name == lowered)
            .count()
    }
}

/// Produces the verified client identity for an inbound request, or `None` when
/// no identity is available (fail closed: a binding that requires identity then
/// rejects). The request headers are the ONLY context — direct-TLS identity is
/// extracted functionally by the serve loop (see `tls::connection_identity`) and
/// does not go through this trait. `StaticIdentityProvider` ignores the request
/// and is used in tests.
pub trait TransportBindingProvider {
    /// The verified client identity for this request, if any.
    fn verified_identity(&self, request: &RequestHeaders) -> Option<TransportIdentity>;
}

/// A fixed identity (or none). Useful in tests and as a degenerate provider; it
/// ignores the request entirely and always yields the identity it was built with.
#[derive(Debug, Clone, Default)]
pub struct StaticIdentityProvider {
    identity: Option<TransportIdentity>,
}

impl StaticIdentityProvider {
    /// A provider that yields `identity` (or `None`).
    pub fn new(identity: Option<TransportIdentity>) -> Self {
        StaticIdentityProvider { identity }
    }
}

impl TransportBindingProvider for StaticIdentityProvider {
    fn verified_identity(&self, _request: &RequestHeaders) -> Option<TransportIdentity> {
        self.identity.clone()
    }
}

// The trusted-ingress identity vocabulary — `MAX_ASSERTED_IDENTITY_LEN`,
// `AssertedIdentityRejection`, `validate_asserted_identity_value` — is a compatibility
// facade over the peer-identity value owner (ADR-MCPRE-063 Slice 1) and lives in
// `asserted_identity_facade`. Re-exported here so this module's own callers, and the
// crate root, keep their existing paths.
pub use crate::facades::asserted_identity::validate_asserted_identity_value;
pub use crate::facades::asserted_identity::AssertedIdentityRejection;
pub use crate::facades::asserted_identity::MAX_ASSERTED_IDENTITY_LEN;

/// The SEP-2243 transport routing header naming the JSON-RPC method (ADR-MCPS-025).
/// Lowercased for case-insensitive [`RequestHeaders`] lookup.
pub const MCP_METHOD_HEADER: &str = "mcp-method";

/// The SEP-2243 transport routing header naming the tool/resource (ADR-MCPS-025).
/// Lowercased for case-insensitive [`RequestHeaders`] lookup.
pub const MCP_NAME_HEADER: &str = "mcp-name";

/// Why a SEP-2243 routing header was rejected (ADR-MCPS-025).
///
/// Routing headers (`Mcp-Method` / `Mcp-Name`) are untrusted hints: the signed
/// body is authoritative and the proxy never routes on them. But ADR-MCPS-025
/// rule 4 applies the ADR-MCPS-023 strict-header rules to them too — a duplicated
/// or malformed routing header is a header-smuggling / log-injection vector and
/// fails closed at the transport boundary before the handler runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingHeaderRejection {
    /// The header appeared more than once (a downstream-injected duplicate must
    /// not be able to shadow or confuse the first).
    Duplicate {
        /// The offending header name (`mcp-method` / `mcp-name`).
        header: &'static str,
    },
    /// The header's lone value failed the strict shape rules (empty, oversized, or
    /// containing a control character) — see [`validate_asserted_identity_value`].
    Malformed {
        /// The offending header name (`mcp-method` / `mcp-name`).
        header: &'static str,
    },
}

/// Apply the ADR-MCPS-023 strict-header rules to the SEP-2243 routing headers
/// (`Mcp-Method` / `Mcp-Name`) per ADR-MCPS-025 rule 4: each MUST be single-valued
/// and well-formed (non-empty, length-bounded, no control characters). Absent
/// headers pass — they are optional routing hints, not required. Present-but-bad
/// headers fail closed; the proxy never trusts a routing header for any security
/// decision, so this is hygiene (anti-smuggling), not a routing check.
pub fn validate_routing_headers(headers: &RequestHeaders) -> Result<(), RoutingHeaderRejection> {
    for header in [MCP_METHOD_HEADER, MCP_NAME_HEADER] {
        match headers.count(header) {
            0 => continue,
            1 => {
                let value = headers.first(header).unwrap_or("");
                if validate_asserted_identity_value(value).is_err() {
                    return Err(RoutingHeaderRejection::Malformed { header });
                }
            }
            _ => return Err(RoutingHeaderRejection::Duplicate { header }),
        }
    }
    Ok(())
}

/// Decides whether the actor a request verifier resolved is bound to the peer that
/// authenticated the relationship it arrived over. A failure is always
/// [`McpReError::TransportBindingFailed`].
pub trait TransportBindingPolicy {
    /// The binding fact, or [`McpReError::TransportBindingFailed`].
    fn bind(
        &self,
        peer: AuthenticatedChannelPeer,
        subject: VerifiedRequestSubject,
    ) -> Result<RequestPeerBindingFacts, McpReError>;
}

/// The strongest default: the authenticated peer and the resolved request actor must be
/// the same principal (the key-holder is the cert-holder).
///
/// A COMPATIBILITY facade, and nothing more. The relation lives in the ADR-MCPRE-064
/// Slice 4 authority; this converts its refusal into the historical error. There is no
/// check here to delete.
#[derive(Debug, Clone, Default)]
pub struct ExactMatchBinding;

impl ExactMatchBinding {
    /// Construct the exact-match policy.
    pub fn new() -> Self {
        ExactMatchBinding
    }
}

impl TransportBindingPolicy for ExactMatchBinding {
    fn bind(
        &self,
        peer: AuthenticatedChannelPeer,
        subject: VerifiedRequestSubject,
    ) -> Result<RequestPeerBindingFacts, McpReError> {
        bind_request_to_peer(peer, subject).map_err(|_| McpReError::TransportBindingFailed)
    }
}

/// A binding the serving path is permitted to enforce.
///
/// [`TransportBindingPolicy`] is the vocabulary of binding rules; this is the subset the
/// configuration owner recognised. The distinction is the whole point: a
/// `Box<dyn TransportBindingPolicy>` parameter states only that SOME rule will run, and
/// every implementation satisfies it — including one whose `check` returns `Ok(())` for
/// every request, which the serving path cannot distinguish from a binding that held.
///
/// The representation is private and every constructor is `pub(crate)`, so a value of this
/// type exists only where `config_state::transport` recognised a
/// [`ChannelBindingState`](crate::config_state::ChannelBindingState). Possession is
/// therefore the proof that the mode was approved, with no trailing clause about which
/// call site built it.
///
/// `pub(crate)` seals nothing against this crate's own composition root, and normally that
/// makes it the wrong lever. Here it is the right one, because the consumers being excluded
/// are the ones outside the crate: `app.rs` SHOULD build these, and an embedder should not.
pub(crate) struct TransportBinding {
    policy: Box<dyn TransportBindingPolicy + Send + Sync>,
}

impl TransportBinding {
    /// The exact-match binding (Mode A): the request signer must equal the channel identity.
    ///
    /// The one binding any deployment can be in — `BindingKind::Exact` is the only kind
    /// that reaches a channel-binding state. A second deployable mode arrives here as a
    /// second constructor, not as a caller-supplied policy object.
    pub(crate) fn exact_match() -> Self {
        TransportBinding {
            policy: Box::new(ExactMatchBinding::new()),
        }
    }

    /// Apply the binding to two SEMANTIC products, and hand back the fact it establishes.
    ///
    /// The serving path's only projection of the private policy. It takes the channel peer
    /// and the verified request subject — never two strings a caller chose — so the
    /// relation is over values whose provenance their own authorities state.
    ///
    /// An ABSENT channel peer fails closed. A configured binding is a claim that every
    /// served request is bound; a request that presents no authenticated peer has not
    /// been shown to be, and treating "nothing to compare" as a pass would satisfy the
    /// claim with an absence.
    pub(crate) fn bind(
        &self,
        peer: Option<&AuthenticatedChannelPeer>,
        subject: VerifiedRequestSubject,
    ) -> Result<RequestPeerBindingFacts, McpReError> {
        let peer = peer.ok_or(McpReError::TransportBindingFailed)?;
        self.policy.bind(peer.clone(), subject)
    }
}

// `MappedBinding` — a cross-namespace signer -> allowed-identities allowlist — was removed
// here by ADR-MCPRE-064 Slice 4. It had no production path: no `BindingKind` reaches it and
// `TransportBinding` never had a constructor for it. It also cannot honestly satisfy the
// binding trait any more, because the fact that trait now produces is *these two denote the
// SAME principal*, and a mapping deliberately relates two DIFFERENT ones.
//
// The capability is deferred, not discarded. A cross-namespace relation is its own authority
// producing its own fact, and the requirements its tests pinned are recorded in
// ADR-MCPRE-064 §15 so the next author inherits them rather than rediscovering them: an
// explicit enumerated allowlist, exact string equality only, no wildcards or globs or
// regular expressions, a literal `"*"` with no special meaning, and an absent identity or an
// unmapped signer failing closed.

#[cfg(test)]
mod tests {
    use super::ExactMatchBinding;
    use super::IdentitySource;
    use super::RequestHeaders;
    use super::StaticIdentityProvider;
    use super::TransportBinding;
    use super::TransportBindingPolicy;
    use super::TransportBindingProvider;
    use super::TransportIdentity;
    use mcp_re_core::McpReError;

    use super::AuthenticatedChannelPeer;
    use super::RequestPeerBindingFacts;
    use super::VerifiedRequestSubject;
    use crate::communication_assurance::bind_request_to_peer;

    const PRINCIPAL: &str = "spiffe://example.org/agent-1";

    /// A real authenticated channel peer naming `value`.
    ///
    /// Driven through a real handshake rather than constructed: the whole difference
    /// between this operand and the freely-constructible `TransportIdentity` it replaces is
    /// that it cannot be fabricated, and a synthetic fixture would prove nothing about that.
    fn channel_peer(value: &str) -> AuthenticatedChannelPeer {
        use crate::communication_assurance::authenticate_relationship_peer;
        use crate::communication_assurance::certificate_identity_policy::CertificateIdentityPolicy;
        use crate::communication_assurance::channel_associated_credential::mechanism_harness::*;
        use crate::communication_assurance::mechanism_verified_credential::rustls_adapter::verified_credential;

        let root = make_ca("binding-root");
        let server_ca = make_ca("binding-server-ca");
        let (server_leaf, server_key) = make_leaf(&server_ca, "localhost", false);
        let (client_leaf, client_key) = make_uri_leaf(&root, value);
        let server = server_config(&[root.der()], vec![server_leaf], server_key);
        let client = client_config(&server_ca.der(), Some((vec![client_leaf], client_key)));
        let accepted = verified_credential(&handshake(&client, &server)).expect("accepts");
        AuthenticatedChannelPeer::CurrencyNotEvaluated(
            authenticate_relationship_peer(accepted, CertificateIdentityPolicy::UriSan)
                .expect("the leaf carries a URI SAN"),
        )
    }

    /// The subject the request verifier resolved, through the ONE producer.
    fn subject(value: &str) -> VerifiedRequestSubject {
        use mcp_re_http_profile::ActorIdentity;
        use mcp_re_http_profile::ResolvedActor;
        use mcp_re_http_profile::SignerSlot;

        crate::communication_assurance::request_peer_binding::http_profile_adapter::verified_request_subject(
            &ResolvedActor {
                identity: ActorIdentity {
                    role: "client".into(),
                    trust_domain: "example.org".into(),
                    subject: value.into(),
                    keyid: "key-a".into(),
                },
                verification_key: mcp_re_core::SigningKey::from_seed_bytes(&[9u8; 32]).public_key(),
                slot: SignerSlot::Request,
            },
        )
    }

    #[allow(dead_code)]
    fn spiffe(value: &str) -> TransportIdentity {
        TransportIdentity::attested_by_verified_ingress(value, IdentitySource::UriSan)
    }

    /// A request carrying a single header.
    fn req_with(name: &str, value: &str) -> RequestHeaders {
        RequestHeaders::from_pairs([(name, value)])
    }

    #[test]
    fn static_provider_yields_its_identity_ignoring_request() {
        let id = spiffe("spiffe://example.org/agent-1");
        let provider = StaticIdentityProvider::new(Some(id.clone()));
        // The request argument is ignored: same identity regardless of headers.
        let empty = RequestHeaders::default();
        let populated = req_with("x-forwarded-client-cert", "URI=spiffe://other");
        assert_eq!(provider.verified_identity(&empty), Some(id.clone()));
        assert_eq!(provider.verified_identity(&populated), Some(id));
        assert_eq!(
            StaticIdentityProvider::new(None).verified_identity(&empty),
            None
        );
    }

    // --- Issue #21 (cluster 2): ADR-MCPS-023 strict rules on the XFCC value -----

    #[test]
    fn request_headers_parse_skips_request_line_and_is_case_insensitive() {
        let block =
            "POST /mcp HTTP/1.1\r\nHost: proxy\r\nX-Forwarded-Client-Cert: URI=spiffe://x\r\n\r\n";
        let headers = RequestHeaders::parse(block);
        assert_eq!(headers.first("host"), Some("proxy"));
        assert_eq!(
            headers.first("X-Forwarded-Client-Cert"),
            Some("URI=spiffe://x")
        );
        assert_eq!(
            headers.first("POST"),
            None,
            "the request line is not a header"
        );
        assert_eq!(headers.count("x-forwarded-client-cert"), 1);
    }

    /// The binding relation, over the two SEMANTIC products — ADR-MCPRE-064 Slice 4.
    ///
    /// The operands are a channel peer whose provenance descends from a mechanism
    /// adapter's acceptance, and a subject with exactly one producer. Neither is a string
    /// a caller chose, which is what the old `check(&str, Option<&TransportIdentity>)`
    /// signature could not say.
    #[test]
    fn exact_match_binds_a_peer_and_a_request_actor_that_name_one_principal() {
        let peer = channel_peer(PRINCIPAL);
        let bound = ExactMatchBinding::new()
            .bind(peer, subject(PRINCIPAL))
            .expect("the same principal on both sides binds");
        assert_eq!(bound.principal().as_str(), PRINCIPAL);
    }

    #[test]
    fn exact_match_refuses_two_different_principals() {
        assert_eq!(
            ExactMatchBinding::new()
                .bind(
                    channel_peer(PRINCIPAL),
                    subject("spiffe://example.org/agent-2")
                )
                .unwrap_err(),
            McpReError::TransportBindingFailed
        );
    }

    #[test]
    fn the_composite_actor_id_is_not_the_binding_coordinate() {
        // THE SLICE-4 RULING, as a control. The channel identity is a subject; the
        // `role:trust_domain:subject:keyid` composite is the replay/audit coordinate. A
        // binding taken over the composite forces certificate issuance to serialize the
        // request verifier's internal trust record — and to be reissued on every
        // signing-key rotation.
        let composite = format!("client:example.org:{}:key-a", PRINCIPAL.replace(':', "%3A"));
        assert_ne!(composite, PRINCIPAL);
        assert_eq!(
            ExactMatchBinding::new()
                .bind(channel_peer(PRINCIPAL), subject(&composite))
                .unwrap_err(),
            McpReError::TransportBindingFailed,
            "a certificate naming the principal must not be expected to name the composite"
        );
    }

    #[test]
    fn an_absent_channel_peer_fails_closed() {
        // A configured binding claims every served request is bound. A request presenting
        // no authenticated peer has not been shown to be, and satisfying the claim with an
        // absence is the `identity.map(check).unwrap_or(true)` defect.
        assert_eq!(
            TransportBinding::exact_match()
                .bind(None, subject(PRINCIPAL))
                .unwrap_err(),
            McpReError::TransportBindingFailed
        );
    }

    #[test]
    fn the_installable_binding_is_exact_match() {
        let installable = TransportBinding::exact_match();
        assert!(installable
            .bind(Some(&channel_peer(PRINCIPAL)), subject(PRINCIPAL))
            .is_ok());
        assert!(installable
            .bind(
                Some(&channel_peer(PRINCIPAL)),
                subject("spiffe://example.org/agent-2")
            )
            .is_err());
    }

    /// A permissive policy is expressible, which is exactly why it must not be installable.
    ///
    /// The state the seal excludes: an implementation of the public
    /// [`TransportBindingPolicy`] trait that admits every request. Nothing stops an embedder
    /// writing it — the point is that there is no public route from one of these to the
    /// serving path, so `TransportBinding` cannot wrap it.
    ///
    /// Note what the new trait costs such an implementation: to admit everything it must
    /// PRODUCE a `RequestPeerBindingFacts`, and the only producer is the authority's own
    /// relation. The permissive policy below can therefore only call that relation and
    /// hand back its answer, which is not permissive at all — the seal now defeats this
    /// shape at the type level, not merely at the composition root.
    #[test]
    fn a_permissive_policy_cannot_manufacture_the_binding_fact() {
        struct AdmitEverything;
        impl TransportBindingPolicy for AdmitEverything {
            fn bind(
                &self,
                peer: AuthenticatedChannelPeer,
                subject: VerifiedRequestSubject,
            ) -> Result<RequestPeerBindingFacts, McpReError> {
                // There is no other way to obtain the return value.
                bind_request_to_peer(peer, subject).map_err(|_| McpReError::TransportBindingFailed)
            }
        }
        assert!(AdmitEverything
            .bind(
                channel_peer(PRINCIPAL),
                subject("spiffe://example.org/agent-2")
            )
            .is_err());
    }

    #[test]
    fn asserted_identity_accepts_a_well_formed_value_and_trims() {
        assert_eq!(
            super::validate_asserted_identity_value("  spiffe://example.org/agent-1  "),
            Ok("spiffe://example.org/agent-1")
        );
    }

    #[test]
    fn asserted_identity_rejects_empty() {
        assert_eq!(
            super::validate_asserted_identity_value("   "),
            Err(super::AssertedIdentityRejection::Empty)
        );
    }

    #[test]
    fn asserted_identity_rejects_oversized() {
        let huge = "a".repeat(super::MAX_ASSERTED_IDENTITY_LEN + 1);
        assert_eq!(
            super::validate_asserted_identity_value(&huge),
            Err(super::AssertedIdentityRejection::TooLong)
        );
        // Exactly at the bound is accepted.
        let at_bound = "a".repeat(super::MAX_ASSERTED_IDENTITY_LEN);
        assert!(super::validate_asserted_identity_value(&at_bound).is_ok());
    }

    #[test]
    fn asserted_identity_rejects_control_characters() {
        // CR/LF (header smuggling / log injection), NUL, and a bare control char.
        for bad in [
            "agent\r\nX-Spoof: y",
            "agent\nid",
            "agent\0id",
            "ag\u{7}ent",
        ] {
            assert_eq!(
                super::validate_asserted_identity_value(bad),
                Err(super::AssertedIdentityRejection::Malformed),
                "control characters must fail closed: {bad:?}"
            );
        }
    }

    // ---- ADR-MCPS-025 routing-header hygiene ----------------------------------

    #[test]
    fn routing_headers_absent_pass() {
        // Mcp-Method / Mcp-Name are optional hints; absent is fine.
        let headers = super::RequestHeaders::default();
        assert_eq!(super::validate_routing_headers(&headers), Ok(()));
    }

    #[test]
    fn routing_headers_well_formed_pass() {
        let headers =
            super::RequestHeaders::from_pairs([("Mcp-Method", "tools/call"), ("Mcp-Name", "echo")]);
        assert_eq!(super::validate_routing_headers(&headers), Ok(()));
    }

    #[test]
    fn duplicate_routing_header_fails_closed() {
        let headers = super::RequestHeaders::from_pairs([
            ("Mcp-Method", "tools/call"),
            ("mcp-method", "tools/list"),
        ]);
        assert_eq!(
            super::validate_routing_headers(&headers),
            Err(super::RoutingHeaderRejection::Duplicate {
                header: super::MCP_METHOD_HEADER
            })
        );
    }

    #[test]
    fn malformed_routing_header_fails_closed() {
        // A CRLF-laced routing header is a smuggling vector — fail closed even
        // though the proxy never routes on it.
        let headers = super::RequestHeaders::from_pairs([("Mcp-Name", "echo\r\nX-Spoof: evil")]);
        assert_eq!(
            super::validate_routing_headers(&headers),
            Err(super::RoutingHeaderRejection::Malformed {
                header: super::MCP_NAME_HEADER
            })
        );
    }

    #[test]
    fn empty_routing_header_fails_closed() {
        let headers = super::RequestHeaders::from_pairs([("Mcp-Method", "   ")]);
        assert_eq!(
            super::validate_routing_headers(&headers),
            Err(super::RoutingHeaderRejection::Malformed {
                header: super::MCP_METHOD_HEADER
            })
        );
    }
}
