//! The TLS transport-identity authority (MCPS-025, ADR-MCPS-014).
//!
//! What a client certificate must satisfy to be served, and what verified identity it
//! carries. The proxy terminates TLS with `rustls` (the `ring` provider), requires and
//! verifies a client certificate against a configured client-CA, and extracts the identity
//! from the leaf (first URI SAN → DNS SAN → CN). The extracted identity is handed to the
//! request handler, where the transport-binding policy (MCPS-026) ties it to the request
//! `signer`.
//!
//! Every per-request decision here takes its input as an ARGUMENT and never a connection:
//! the unmigrated rejection guards take the peer chain leaf-first
//! (`cert_lifetime_rejection_for_chain`, `ocsp_rejection_for_chain`), and
//! `resolve_authenticated_identity` takes the mechanism's acceptance — a semantic product,
//! not a representation. `routing_header_rejection` and `assertion_header` read headers. Both
//! serving shapes therefore reach the same verdict from the same input — the async fleet
//! captures the chain at handshake because `hyper` owns the stream thereafter, and
//! [`crate::blocking_mtls_harness`] reads it from the live `ServerConnection` it holds.
//! Whoever holds the connection is not part of the decision.
//!
//! # What this module does NOT own
//!
//! The blocking mTLS + HTTP/1.1 harness (ADR-MCPRE-061 §2 class 4, MCPRE-138). Accepting a
//! socket, framing a request and writing a reply is a capability that merely uses TLS; it
//! lives in [`crate::blocking_mtls_harness`]. Listener lifetime — anchors, the epoch they
//! digest to, the session store and the signing budget — belongs to
//! [`crate::tls_listener_state`] (MCPRE-137, ADR-MCPRE-062).

use std::sync::Arc;
use std::time::Duration;

use mcp_re_core::json_rpc_error_object;
use mcp_re_core::McpReError;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::CertificateRevocationListDer;

use crate::communication_assurance::authenticate_relationship_peer;
use crate::communication_assurance::authenticated_relationship_peer::AuthenticatedRelationshipPeerFacts;
use crate::communication_assurance::credential_currency::evaluation::evaluate_credential_currency;
use crate::communication_assurance::credential_currency::CredentialCurrencyOutcome;
use crate::communication_assurance::credential_currency::CredentialCurrencyPolicy;
use crate::communication_assurance::credential_currency::CredentialCurrencyRefusal;
use crate::communication_assurance::current_authenticated_peer::current_authenticated_peer;
use crate::communication_assurance::current_authenticated_peer::CurrentPeerRefusal;
use crate::communication_assurance::peer_identity_provenance::PeerIdentityProvenance;
use crate::communication_assurance::AuthenticatedChannelPeer;
use crate::communication_assurance::MechanismVerifiedCredentialEvidence;
use crate::transport::IdentityPolicy;
use crate::transport::RequestHeaders;

/// Resource limits applied to every served connection — the blocking server's
/// defense against slow-loris, oversized-request, and connection-exhaustion
/// denial of service. Every limit fails closed: a connection that exceeds one is
/// dropped (or never accepted), never served partially.
#[derive(Debug, Clone)]
pub struct ServerLimits {
    /// Maximum bytes accepted before the end-of-headers marker. Caps header
    /// floods and unterminated header streams.
    pub max_header_bytes: usize,
    /// Maximum request body (`Content-Length`, and bytes actually read). Caps
    /// oversized payloads.
    pub max_body_bytes: usize,
    /// Per-socket read timeout (covers a stalled TLS handshake and slow-loris
    /// body trickling, since reading drives the handshake). `None` disables.
    pub read_timeout: Option<Duration>,
    /// AGGREGATE wall-clock deadline over the WHOLE server read phase (TLS
    /// handshake + HTTP header block + body), the server-side mirror of
    /// mcp-re-transport's `DeadlineStream` (MCPS-094) and bounded response read
    /// (MCPS-093). The per-socket `read_timeout` bounds each INDIVIDUAL read, but a
    /// peer trickling one byte just under that timeout resets the per-read
    /// inactivity timer on every byte and can extend a single connection's total
    /// lifetime without bound (slow-loris below the per-read threshold), holding a
    /// serve thread. This caps the TOTAL handshake+request read wall-clock; once it
    /// elapses the next read fails closed (the connection is dropped). `None`
    /// disables the aggregate bound, preserving the per-read-only semantics.
    pub request_deadline: Option<Duration>,
    /// Per-socket write timeout. `None` disables.
    pub write_timeout: Option<Duration>,
    /// Maximum simultaneously-served connections in the threaded [`serve`] loop.
    /// Connections beyond the cap are dropped (TCP-accepted then closed) rather
    /// than queued unboundedly.
    pub max_concurrent_connections: usize,
    /// MCPRE-114 (ADR-MCPRE-051 §1): per-core bounded ADMISSION control — the
    /// maximum number of requests being served CONCURRENTLY on one core (async
    /// serving path). A request that arrives while the ceiling is full is rejected
    /// fail-closed with `503 Service Unavailable` BEFORE the handler runs, rather
    /// than queued without bound — so tail latency stays bounded under overload
    /// instead of degrading unboundedly. `None` disables the ceiling (unbounded
    /// in-flight; the historical behavior). Bounds only the async
    /// (`async_serve`) path; the blocking loop bounds concurrency via
    /// `max_concurrent_connections`.
    ///
    /// # RESOLVED, not requested
    ///
    /// On the validated path this is not what an operator wrote. The admission limit is
    /// stated once, in
    /// [`DeploymentRequest::in_flight_limit`](crate::deployment_request::DeploymentRequest::in_flight_limit), which can express
    /// per-core, fleet-wide, or nothing at all; the boundary resolves that to a basis and
    /// the composition root writes the per-core answer HERE. Setting this field on a
    /// `DeploymentRequest` therefore states nothing — it is overwritten.
    ///
    /// The fail-safe default remains, and is the same constant the basis resolves an
    /// unstated limit to, so a `ServerLimits` built directly — by a test, or an embedder
    /// driving `async_serve` with no `DeploymentRequest` — is bounded on exactly the same terms.
    pub max_in_flight_requests: Option<usize>,
    /// MCPRE-115 (ADR-MCPRE-051 §6): the BOUNDED GRACE WINDOW for graceful drain on
    /// the async serving path. On shutdown each per-core [`serve`] loop stops
    /// accepting and then waits up to this long for its IN-FLIGHT requests to
    /// complete before returning (after which the runtime is dropped and any
    /// still-running request is abandoned). Each in-flight request is ALSO bounded by
    /// `request_deadline`, so with `drain_grace >= request_deadline` every admitted
    /// request finishes within the window — zero abandoned. Size it UNDER the
    /// deployment's k8s `terminationGracePeriodSeconds` and AT OR ABOVE
    /// `request_deadline`: `request_deadline <= drain_grace < terminationGracePeriodSeconds`.
    /// Idle keep-alive connections carry no in-flight request and do not extend the
    /// drain — an idle drain returns promptly.
    pub drain_grace: Duration,
    /// The maximum age of a single mTLS connection before it is gracefully closed,
    /// forcing the peer to re-handshake.
    ///
    /// What this bounds is CHAIN re-validation for an already-established peer.
    /// Client-certificate chain building happens at the handshake and nowhere else, so
    /// a change to the trusted client CAs — a CA withdrawn, a CA expired — reaches a
    /// keep-alive or HTTP/2 connection only when the peer re-handshakes.
    ///
    /// Revocation and the certificates' own validity windows no longer depend on it:
    /// both are re-checked on EVERY request whenever a per-request certificate control
    /// is configured, and to the same depth the handshake checks — the whole presented
    /// chain, not just the leaf (see
    /// [`client_revocation`](crate::client_revocation)). Chain BUILDING is what remains
    /// bound by this age instead: whether a path to a trusted anchor still exists —
    /// signatures, name constraints, anchor membership — is settled by the handshake
    /// verifier and nowhere else.
    ///
    /// Graceful: in-flight requests on the connection finish; only new requests are
    /// refused, and the peer reconnects transparently. `None` disables the bound,
    /// which restores the unbounded behaviour and is refused under `--fleet`.
    pub max_connection_age: Option<Duration>,
}

impl Default for ServerLimits {
    fn default() -> Self {
        ServerLimits {
            max_header_bytes: 64 * 1024,
            max_body_bytes: 16 * 1024 * 1024,
            read_timeout: Some(Duration::from_secs(30)),
            request_deadline: Some(Duration::from_secs(30)),
            write_timeout: Some(Duration::from_secs(30)),
            max_concurrent_connections: 256,
            // A DEFENSIBLE per-core ceiling rather than the unbounded historical
            // default. Unbounded meant one peer holding a valid client certificate
            // could multiplex unbounded HTTP/2 streams, each buffering up to
            // `max_body_bytes` BEFORE the verify gate — attacker-controlled memory
            // with zero authenticated requests, and it also left hyper's HTTP/2
            // `max_concurrent_streams` unset.
            //
            // MATCHED TO `max_concurrent_connections` on purpose. That cap already
            // admitted 256 concurrent connections per core, so one in-flight request
            // per admitted connection tightens nothing that was previously allowed —
            // it just stops the H2 multiplexer exceeding it. A smaller number would be
            // a throughput policy rather than a memory bound, and it would shed inside
            // the ADR-MCPRE-051 §7 envelope (concurrency 128), which is a load-shaping
            // decision no default should make silently.
            max_in_flight_requests: Some(
                crate::config_state::in_flight_limit::DEFAULT_PER_CORE_IN_FLIGHT,
            ),
            // >= request_deadline (so every admitted request can finish) and, in
            // production, < k8s terminationGracePeriodSeconds.
            drain_grace: Duration::from_secs(30),
            // Bounds how long a peer keeps serving on a certificate validated only at
            // its handshake. 300s is well inside the 1h `max_client_cert_lifetime`
            // ceiling and short enough that a CRL reload takes effect within one
            // cadence, while being long enough that re-handshake cost is negligible.
            max_connection_age: Some(Duration::from_secs(300)),
        }
    }
}

/// The trusted-ingress Tier-3 (ADR-MCPS-023, issue #71) assertion header. A single
/// HTTP header carrying the LB-signed, request-bound ingress assertion (the
/// `<key_id>.<identity>.<request_hash>.<validation_time>.<signature>` wire form).
/// Lowercased for case-insensitive [`RequestHeaders`] lookup. The serve loop fails
/// closed on a DUPLICATED header (via [`RequestHeaders::count`]) before the value
/// is ever read — a duplicate signals a downstream injection attempt.
pub const MCP_INGRESS_ASSERTION_HEADER: &str = "mcp-ingress-assertion";

/// How the serve loop turns a connection into a served request: which client-cert
/// field is the authoritative identity, the resource limits, and the maximum
/// client-certificate lifetime.
#[derive(Debug, Clone, Default)]
pub struct ServerOptions {
    /// The authoritative client-certificate identity field (no implicit fallback).
    /// Used for [`PeerIdentityProvenance::ChannelCredential`].
    pub identity_policy: IdentityPolicy,
    /// Where the request's verified transport identity is taken from. Mutually
    /// exclusive by construction.
    pub peer_identity_provenance: PeerIdentityProvenance,
    /// Connection resource limits (DoS defense).
    pub limits: ServerLimits,
    /// Maximum allowed client-certificate validity span
    /// (`not_after - not_before`). This is the v1 revocation posture: with no
    /// online CRL/OCSP, a compromised client cert is usable until expiry, so the
    /// proxy ENFORCES short lifetimes — a cert whose span exceeds this (or whose
    /// validity cannot be parsed) is rejected with `mcp-re.transport_binding_failed`.
    /// `None` disables the check. The production CLI defaults this to 1 hour; this
    /// library `Default` leaves it `None` so existing callers are unchanged.
    ///
    /// Exposure window of a compromised transport credential is bounded by
    /// `max_client_cert_lifetime`. The end-to-end request-authority exposure
    /// window is `cert_lifetime + resolver_cache_ttl + request_lifetime +
    /// max_clock_skew`.
    pub max_client_cert_lifetime: Option<Duration>,
    /// PER-REQUEST offline CRL revocation: the revoked-serial index built from the
    /// SAME CRLs the handshake verifier holds, behind an atomic swap so a reload
    /// reaches connections that are already open.
    ///
    /// rustls runs client authentication on a full handshake only, so without this a
    /// revoked peer keeps serving for as long as it holds one connection — the
    /// `--client-crl-reload-secs` rebuild reaches only NEW connections, and
    /// `max_connection_age` bounds the exposure without ending it. `None` disables
    /// the per-request check; `app.rs` installs it only when CRLs are configured, so
    /// a deployment with none is unchanged.
    pub client_revocation: Option<Arc<crate::client_revocation::SharedClientRevocation>>,
    /// ONLINE OCSP client-cert revocation (#4030), the online sibling of #3839's
    /// offline CRL posture. When `Some`, after the handshake the serve loop asks
    /// the leaf's OCSP responder whether it is revoked, BEFORE the handler, and
    /// fails closed (rejects) on `Revoked`/`Unknown`/error unless the checker is
    /// in soft-fail mode (see [`ocsp_rejection_for_chain`]). `None` disables the online
    /// check (the default). This field — and the entire online check — exists
    /// ONLY in a build with the `online_ocsp` feature; the default build has no
    /// such field and the hook is a compile-time no-op, so it is byte-for-byte
    /// unchanged.
    #[cfg(feature = "online_ocsp")]
    pub ocsp_checker: Option<crate::ocsp::OcspChecker>,
    /// The canonical RFC 9421 `@target-uri` this deployment binds requests to
    /// (ADR-MCPRE-050). Client and server MUST agree on it byte-for-byte; the
    /// verifier checks it against the request evidence block's audience tuple. Empty
    /// when unset (the audience/target check then fails closed).
    pub target_uri: String,
    /// Whether producing the handshake signature may BLOCK — set when the TLS server
    /// key is delegated to a KMS or a PKCS#11 token (ADR-MCPS-028 §G).
    ///
    /// rustls' `Signer::sign` is synchronous, so on those custody paths the
    /// CertificateVerify signature is a blocking HTTPS round trip or an FFI `C_Sign`
    /// executed inside a single `poll`. On the per-core `current_thread` runtime that
    /// freezes the WHOLE core — its accept loop, its keep-alive connections and every
    /// in-flight request — for the duration, and `tokio::time::timeout` cannot preempt
    /// it because the timer never gets to run. Any peer opening connections triggers
    /// it; a stalled KMS costs seconds per connection and a wedged token is unbounded.
    ///
    /// When set, the handshake is run on the blocking pool instead of the runtime
    /// thread (see `async_serve::serve_connection`). Left `false` for the exported-key
    /// path, where signing is in-memory and the async handshake is both correct and
    /// cheaper.
    pub tls_signing_may_block: bool,
}

/// Errors building the TLS server configuration.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// A client-CA certificate could not be added to the trust store.
    #[error("invalid client CA certificate")]
    BadClientCa,
    /// The client-certificate verifier could not be built.
    #[error("client verifier build failed: {0}")]
    Verifier(String),
    /// The server certificate/key or protocol configuration was rejected.
    #[error("server TLS config failed: {0}")]
    Config(String),
    /// Delegated TLS (ADR-MCPS-028 §G, issue #58): the leaf certificate's
    /// `SubjectPublicKeyInfo` is not an RFC 8410 Ed25519 key (delegated TLS is
    /// Ed25519-only), OR the delegated signer's public key does not match the leaf
    /// certificate's public key. Either is a deployment error and FAILS CLOSED at
    /// config construction — no server is started.
    #[error("delegated TLS credential mismatch: {0}")]
    DelegatedKeyMismatch(String),
}

/// The freshness of a configured client CRL relative to a verification instant
/// (ADR-MCPS-023 §A1, MCPS-58).
///
/// The client verifier ([`crate::tls_listener_state`]) now enforces `nextUpdate` at handshake time, so a
/// `Stale` CRL fails every new handshake closed. This startup gate surfaces that
/// condition **loudly at boot**: under strict the proxy refuses to start, rather
/// than coming up and silently rejecting every client at the first handshake, and
/// it warns while a CRL is `NearExpiry` so the operator can reload/restart with a
/// refreshed CRL before the cutover (the "restart before `nextUpdate`" contract;
/// the in-process hot-reloader is a v0.10 follow-up).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrlFreshness {
    /// `now < nextUpdate - warn_window` — comfortably valid.
    Fresh,
    /// `nextUpdate - warn_window <= now < nextUpdate` — still valid, but a
    /// refreshed CRL must be in place before `next_update_unix` or new handshakes
    /// will start failing closed.
    NearExpiry { next_update_unix: i64 },
    /// `now >= nextUpdate` — expired; the verifier fails all new handshakes closed.
    Stale { next_update_unix: i64 },
    /// The CRL carries no `nextUpdate` at all, so it never falls out of force.
    ///
    /// Neither rustls' expiration enforcement nor
    /// [`client_revocation`](crate::client_revocation) has anything to compare against,
    /// so such a CRL would be honoured — and its issuer answered `Good` for — for the
    /// whole process lifetime, however long the reload has been failing. That is the
    /// exact opposite of the self-bounding property the TLS plane's fail-closed argument
    /// rests on, so it is a refusal rather than a freshness class the caller may ignore.
    NoNextUpdate,
}

/// Refuse a client CRL that omits `nextUpdate`.
///
/// RFC 5280 §5.1.2.5 requires a conforming CRL issuer to include it, and every
/// self-bounding claim this proxy makes about revocation is a claim about it: past
/// `nextUpdate` the handshake verifier fails closed and the per-request index downgrades
/// the issuer to `Unknown`, which is refused. A CRL without one reaches neither point,
/// so it is refused where it is read — at startup and on every reload — rather than
/// admitted into a posture that says it bounds itself.
pub fn crl_next_update_required(crl_der: &[u8], index: usize) -> Result<(), TlsError> {
    if crl_freshness(crl_der, 0, 0)? == CrlFreshness::NoNextUpdate {
        return Err(TlsError::Verifier(format!(
            "client CRL #{index} omits nextUpdate. It would never fall out of force, so a \
             reload that stops working (unreadable mount, dead reload thread) would leave \
             this replica admitting certificates revoked afterwards for the rest of its \
             lifetime. RFC 5280 §5.1.2.5 requires conforming CRL issuers to include \
             nextUpdate; publish a CRL that does."
        )));
    }
    Ok(())
}

/// Classify a DER-encoded client CRL's `nextUpdate` against `now_unix`, warning
/// `warn_window_secs` ahead of expiry. Pure and offline-testable.
///
/// A CRL with no `nextUpdate` is classified [`CrlFreshness::NoNextUpdate`], which
/// [`crl_next_update_required`] turns into a refusal: nothing in the stack can age such
/// a CRL out. A CRL that cannot be parsed is a hard error — the verifier build would
/// reject it too, so this fails closed rather than silently skipping the gate.
pub fn crl_freshness(
    crl_der: &[u8],
    now_unix: i64,
    warn_window_secs: i64,
) -> Result<CrlFreshness, TlsError> {
    use der::Decode;
    use x509_cert::crl::CertificateList;
    let crl = CertificateList::from_der(crl_der)
        .map_err(|e| TlsError::Verifier(format!("malformed client CRL: {e}")))?;
    let next_update = match crl.tbs_cert_list.next_update {
        Some(t) => t.to_unix_duration().as_secs() as i64,
        None => return Ok(CrlFreshness::NoNextUpdate),
    };
    Ok(if now_unix >= next_update {
        CrlFreshness::Stale {
            next_update_unix: next_update,
        }
    } else if now_unix >= next_update - warn_window_secs {
        CrlFreshness::NearExpiry {
            next_update_unix: next_update,
        }
    } else {
        CrlFreshness::Fresh
    })
}

/// The startup revocation-posture facts for a configured client CRL
/// (ADR-MCPS-023 §A1, MCPS-58).
///
/// These feed the operator-visible `mcp-re.revocation.posture` diagnostic line. That
/// line is a **posture diagnostic, not a structured per-request audit guarantee** —
/// the structured evidence/audit vocabulary lands with Mode C attested ingress
/// (MCPS-62), where `delegated_attestor_crl` actually exists. The field names here
/// (`crl_digest`, `crl_this_update`, `crl_next_update`) are the canonical ones so a
/// future structured audit sink can reuse them verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlPosture {
    /// `sha256:<base64url>` over the CRL DER (the MCP-RE hash-identifier format).
    pub crl_digest: String,
    /// `thisUpdate` as a Unix timestamp.
    pub this_update_unix: i64,
    /// `nextUpdate` as a Unix timestamp, if present (RFC 5280 permits omission).
    pub next_update_unix: Option<i64>,
}

/// Extract the [`CrlPosture`] facts from a DER-encoded client CRL. Pure and
/// offline-testable. A malformed CRL is a hard error (fail closed), consistent
/// with [`crl_freshness`] and the verifier build.
pub fn crl_posture(crl_der: &[u8]) -> Result<CrlPosture, TlsError> {
    use der::Decode;
    use x509_cert::crl::CertificateList;
    let crl = CertificateList::from_der(crl_der)
        .map_err(|e| TlsError::Verifier(format!("malformed client CRL: {e}")))?;
    let this_update = crl.tbs_cert_list.this_update.to_unix_duration().as_secs() as i64;
    let next_update_unix = crl
        .tbs_cert_list
        .next_update
        .map(|t| t.to_unix_duration().as_secs() as i64);
    Ok(CrlPosture {
        crl_digest: mcp_re_core::sha256_hash_id(crl_der),
        this_update_unix: this_update,
        next_update_unix,
    })
}
/// Produce the delegated TLS certificate resolver for a credential and its signer, in the
/// historical error vocabulary (ADR-MCPS-028 §G, issue #58).
///
/// **Compatibility facade.** It performs no check and makes no decision. Correspondence is
/// a structural precondition of the resolver's existence — [`DelegatedCertResolver::materialize`]
/// establishes it over the very operands it then moves into the resolver — so there is no
/// window here in which the credential and the signer are an unpaired pair, and nothing to
/// delete. All this function does is render a refusal into `TlsError`.
///
/// The budget is supplied by the listener's security state and installed unchanged: it
/// bounds how fast unauthenticated peers can drive a remote, billed, account-throttled
/// signer, and a bucket created per build would be refilled on every reload — bounding a
/// window rather than a rate. That is a listener capability, not a property of the
/// credential, and it is deliberately not part of what correspondence establishes.
pub(crate) fn validated_delegated_resolver(
    server_chain: Vec<CertificateDer<'static>>,
    signer: Arc<dyn crate::delegated_tls::RawEd25519TlsSigner>,
    budget: Arc<crate::delegated_tls::TlsHandshakeSignBudget>,
) -> Result<Arc<crate::delegated_tls::DelegatedCertResolver>, TlsError> {
    crate::delegated_tls::DelegatedCertResolver::materialize(server_chain, signer, budget).map_err(
        |refusal| {
            TlsError::DelegatedKeyMismatch(
                crate::facades::delegated_key_correspondence::correspondence_message(&refusal),
            )
        },
    )
}

/// The authenticated channel peer of this relationship, with whatever currency assurance
/// the deployment's controls established — for both direct-TLS serving paths
/// (ADR-MCPRE-064 Slice 4, issue #623).
///
/// The strategy dispatch is the only decision here. Under [`PeerIdentityProvenance::ChannelCredential`]
/// the peer comes from the ADR-MCPRE-064 authorities: the mechanism's own acceptance plus
/// the configured identity policy authenticate it, and the deployment's currency policy
/// then either makes it a CURRENT peer or leaves it explicitly unexamined. Under
/// [`PeerIdentityProvenance::IngressAssertion`] there is no channel peer, unchanged.
///
/// **Nothing but the acceptance and the deployment's own policies is supplied.** There is
/// no certificate parameter, no leaf parameter, no chain and no identity — which is what
/// makes the historical route not merely unused from here but unavailable. Both serving
/// paths call THIS function, so their peers are the same fact and not two derivations that
/// currently agree.
///
/// One evaluation per request. A credential the currency controls REFUSE never becomes a
/// peer at all — the caller renders that as the transport-boundary refusal, exactly as
/// before — and a deployment configuring no control yields the unexamined arm rather than
/// a silently current one.
pub(crate) fn resolve_channel_peer(
    accepted: Option<&MechanismVerifiedCredentialEvidence>,
    options: &ServerOptions,
    now: i64,
) -> Result<Option<AuthenticatedChannelPeer>, CredentialCurrencyRefusal> {
    let policy = currency_policy(options);
    let Some(peer) = authenticated_peer(accepted, options) else {
        // No channel peer to speak of — LB assertion, no acceptance, or a leaf carrying no
        // configured identity field. The credential's CURRENCY is still the deployment's
        // question, so it is asked here rather than skipped with the identity.
        return match evaluate_credential_currency(accepted, &policy, now) {
            CredentialCurrencyOutcome::Refused(refusal) => Err(refusal),
            CredentialCurrencyOutcome::NotEvaluated | CredentialCurrencyOutcome::Current(_) => {
                Ok(None)
            }
        };
    };
    match current_authenticated_peer(peer, &policy, now) {
        Ok(current) => Ok(Some(AuthenticatedChannelPeer::Current(current))),
        Err(CurrentPeerRefusal::CurrencyNotEvaluated) => {
            // Recovered from the policy rather than from the refusal, because the refusal
            // consumed the peer. The classification is total, so this is the same branch.
            match authenticated_peer(accepted, options) {
                Some(peer) => Ok(Some(AuthenticatedChannelPeer::CurrencyNotEvaluated(peer))),
                None => Ok(None),
            }
        }
        Err(CurrentPeerRefusal::CredentialNotCurrent(refusal)) => Err(refusal),
    }
}

/// The peer this relationship authenticated as, before any currency question.
///
/// Private: the serving path consumes [`resolve_channel_peer`], which is the whole
/// question. Publishing this would let a caller take the identity half without the
/// currency half and pair them itself.
fn authenticated_peer(
    accepted: Option<&MechanismVerifiedCredentialEvidence>,
    options: &ServerOptions,
) -> Option<AuthenticatedRelationshipPeerFacts> {
    match &options.peer_identity_provenance {
        PeerIdentityProvenance::ChannelCredential => {
            authenticate_relationship_peer(accepted?.clone(), options.identity_policy.into()).ok()
        }
        PeerIdentityProvenance::IngressAssertion => None,
    }
}

/// The channel peer for one served request, or the transport-boundary refusal.
///
/// A FACADE over [`resolve_channel_peer`], and THE single call both direct-TLS serving
/// paths make about their relationship. It asks the ADR-MCPRE-064 authorities once and
/// renders a currency refusal in the historical wire vocabulary; it parses no certificate,
/// compares no clock, consults no CRL and decides no identity — there is no check here to
/// delete.
///
/// It takes the ACCEPTANCE, never a chain: the facts are then about the credential this
/// relationship actually authenticated with, and there is no parameter through which
/// another peer's certificates could enter.
///
/// The wire outcome is unchanged. Every request production admitted is admitted, every one
/// it refused is refused, and a currency refusal is still `mcp-re.transport_binding_failed`
/// bound to the request id — the reason is typed, and rendering it on the wire is a
/// separate decision this migration does not take.
///
/// NOTE: online-OCSP revocation (`#[cfg(feature = "online_ocsp")]`) needs the full peer
/// chain and is NOT yet wired on the async path — combining `async_serve` with
/// `online_ocsp` is a tracked follow-up; the default and shared-replay tier builds have
/// full parity.
pub(crate) fn served_channel_peer(
    accepted: Option<&MechanismVerifiedCredentialEvidence>,
    options: &ServerOptions,
    request: &[u8],
    now: i64,
) -> Result<Option<AuthenticatedChannelPeer>, Vec<u8>> {
    resolve_channel_peer(accepted, options, now)
        .map_err(|_refusal| transport_binding_failure(request))
}

/// The deployment's configured currency controls, classified.
///
/// A TOTAL selector: every `ServerOptions` is exactly one policy, and the classification
/// cannot fail. The revocation index is SNAPSHOTTED here, once per request, so the leaf
/// check and the issuer check cannot read two different indexes across a reload.
fn currency_policy(options: &ServerOptions) -> CredentialCurrencyPolicy {
    let index = options
        .client_revocation
        .as_ref()
        .map(|revocation| revocation.load());
    match (options.max_client_cert_lifetime, index) {
        (None, None) => CredentialCurrencyPolicy::NotEvaluated,
        (Some(ceiling), None) => CredentialCurrencyPolicy::Ceiling(ceiling),
        (None, Some(index)) => CredentialCurrencyPolicy::Revocation(index),
        (Some(ceiling), Some(index)) => {
            CredentialCurrencyPolicy::CeilingAndRevocation(ceiling, index)
        }
    }
}

/// The historical transport-boundary refusal, bound to the request id when it can be read.
fn transport_binding_failure(request: &[u8]) -> Vec<u8> {
    let id = serde_json::from_slice::<serde_json::Value>(request)
        .ok()
        .and_then(|value| value.get("id").cloned())
        .unwrap_or(serde_json::Value::Null);
    json_rpc_error_object(&McpReError::TransportBindingFailed, &id)
}

/// Extract the raw Tier-3 ingress-assertion header value to hand to the
/// post-verification LB check (issue #71), under the [`PeerIdentityProvenance::IngressAssertion`]
/// strategy ONLY. The header is fetched case-insensitively and fails CLOSED on a
/// DUPLICATE: a single header value is returned only when EXACTLY one is present.
///
/// Returns `Some(value)` for a single present header; `None` when the strategy is
/// not LB-assertion, when the header is absent (the proxy then fails closed because
/// the LB verifier requires it), or when the header is duplicated (a downstream
/// injection attempt — fail closed). The proxy's required-header guard turns the
/// resulting `None` into a closed rejection.
pub(crate) fn assertion_header<'a>(
    options: &ServerOptions,
    headers: &'a RequestHeaders,
) -> Option<&'a str> {
    match &options.peer_identity_provenance {
        PeerIdentityProvenance::IngressAssertion => {
            // Fail closed on a duplicated trust header before reading any value.
            if headers.count(MCP_INGRESS_ASSERTION_HEADER) != 1 {
                return None;
            }
            headers.first(MCP_INGRESS_ASSERTION_HEADER)
        }
        _ => None,
    }
}

/// Wall-clock Unix seconds for the transport-layer certificate-validity check.
///
/// The serving path's own `now` is threaded from `app.rs` for every EVIDENCE
/// decision; this one is read here because the check runs at the transport layer,
/// below the request pipeline, and a pre-epoch fault clamps to 0 — which fails every
/// validity window closed.
pub(crate) fn wall_clock_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// ADR-MCPS-025 routing-header hygiene rejection — runs at the SAME per-connection
/// point as [`cert_lifetime_rejection`] (after the verified handshake, before the
/// handler). Returns `Some(error_bytes)` when a SEP-2243 routing header
/// (`Mcp-Method` / `Mcp-Name`) is duplicated or malformed, `None` when the routing
/// headers are absent or well-formed.
///
/// The proxy never routes on these headers — the signed body is authoritative —
/// so this is anti-smuggling hygiene (ADR-MCPS-025 rule 4 applying the ADR-MCPS-023
/// strict-header rules). A defect maps to `mcp-re.transport_binding_failed`, the same
/// transport-boundary token the sibling cert-lifetime / OCSP rejections use.
pub(crate) fn routing_header_rejection(
    headers: &RequestHeaders,
    request: &[u8],
) -> Option<Vec<u8>> {
    crate::transport::validate_routing_headers(headers)
        .err()
        .map(|_rejection| {
            let id = serde_json::from_slice::<serde_json::Value>(request)
                .ok()
                .and_then(|value| value.get("id").cloned())
                .unwrap_or(serde_json::Value::Null);
            json_rpc_error_object(&McpReError::TransportBindingFailed, &id)
        })
}

/// Online OCSP revocation rejection (#4030) — the online sibling of
/// [`cert_lifetime_rejection`], running at the SAME per-connection point (after
/// the verified handshake, before the handler). Returns `Some(error_bytes)` (a
/// `mcp-re.transport_binding_failed` JSON-RPC error bound to the request id) when
/// an OCSP checker is configured AND the verified client leaf must be rejected;
/// `None` when no checker is configured or the leaf is admitted.
///
/// Fail-closed posture (mirrors the offline CRL deny-unknown default): the leaf
/// is REJECTED when the responder reports `Revoked` (always), or `Unknown`, or
/// the check errors (unreachable / timeout / parse), UNLESS the checker is in
/// soft-fail mode — in which case only `Revoked` rejects. The issuer is taken
/// from the verified peer chain (the cert directly after the leaf); a leaf with
/// no chained issuer cannot be checked and is treated as an indeterminate
/// result (rejected unless soft-fail). The HTTP fetch carries the checker's
/// mandatory timeout so this can never wedge the blocking serve thread.
///
/// The chain is handed in leaf-first, exactly as the channel-associated credential
/// evidence carries it, so the decision does not depend on who holds the connection. The
/// policy — which responder verdicts reject, and what an unobtainable verdict means —
/// is this module's, not the caller's.
#[cfg(feature = "online_ocsp")]
pub(crate) fn ocsp_rejection_for_chain(
    chain: &[&[u8]],
    options: &ServerOptions,
    request: &[u8],
) -> Option<Vec<u8>> {
    let checker = options.ocsp_checker.as_ref()?;
    let reject = || {
        let id = serde_json::from_slice::<serde_json::Value>(request)
            .ok()
            .and_then(|value| value.get("id").cloned())
            .unwrap_or(serde_json::Value::Null);
        Some(json_rpc_error_object(
            &McpReError::TransportBindingFailed,
            &id,
        ))
    };

    let leaf = chain.first()?;
    // The issuer is the next cert in the verified chain. Without it we cannot
    // build a CertID; treat as an indeterminate (Unknown) result and apply the
    // fail-closed policy (reject unless soft-fail).
    let Some(issuer) = chain.get(1) else {
        return if checker.allows_on_error() {
            None
        } else {
            reject()
        };
    };

    match checker.check(leaf, issuer) {
        Ok(status) => {
            if checker.allows(status) {
                None
            } else {
                reject()
            }
        }
        // Transport/codec error: indeterminate, fail closed unless soft-fail.
        Err(_) => {
            if checker.allows_on_error() {
                None
            } else {
                reject()
            }
        }
    }
}

/// Load the configured offline client-certificate revocation lists (#3839) into
/// the DER form rustls' `WebPkiClientVerifier` consumes. Each path may hold one or
/// more CRLs in PEM (`-----BEGIN X509 CRL-----`) or a single raw DER CRL. Fails
/// closed: a missing or malformed CRL file is a hard startup error (`Err`) rather
/// than a silently-skipped revocation check. An empty `paths` yields an empty vec
/// (revocation checking disabled — the pre-#3839 behavior).
///
/// OFFLINE only: these bytes are read once at startup and never refreshed over the
/// network. Online OCSP / CRL-distribution-point fetching is deliberately NOT done
/// here and is deferred to a follow-up (it needs an HTTP client + a live
/// responder, which would expand the firewalled supply chain).
pub fn load_client_crls(
    paths: &[String],
) -> Result<Vec<rustls_pki_types::CertificateRevocationListDer<'static>>, String> {
    use rustls_pki_types::pem::PemObject;

    let mut crls: Vec<CertificateRevocationListDer<'static>> = Vec::new();
    for path in paths {
        let bytes = std::fs::read(path).map_err(|e| format!("client CRL {path}: {e}"))?;
        // Try PEM first (one file may carry several `X509 CRL` blocks). If the file
        // contains no PEM CRL block, treat the whole file as a single DER CRL.
        let pem: Vec<CertificateRevocationListDer<'static>> =
            CertificateRevocationListDer::pem_slice_iter(&bytes)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("client CRL {path}: malformed PEM: {e}"))?;
        if pem.is_empty() {
            // No PEM CRL block found → interpret the bytes as one DER CRL. Empty
            // input cannot be a valid DER CRL, so reject it (fail closed) rather
            // than load a no-op file.
            if bytes.is_empty() {
                return Err(format!("client CRL {path}: file is empty"));
            }
            crls.push(CertificateRevocationListDer::from(bytes));
        } else {
            crls.extend(pem);
        }
    }
    Ok(crls)
}

#[cfg(test)]
mod currency_policy_tests {
    //! ADR-MCPRE-064 Slice 3. The classification is a TOTAL selector over deployment state,
    //! and it is where the per-request index snapshot is taken.

    use std::sync::Arc;
    use std::time::Duration;

    use super::currency_policy;
    use super::ServerOptions;
    use crate::client_revocation::ClientRevocationIndex;
    use crate::client_revocation::SharedClientRevocation;
    use crate::communication_assurance::CredentialCurrencyPolicy;

    fn shared() -> Arc<SharedClientRevocation> {
        Arc::new(SharedClientRevocation::new(ClientRevocationIndex::empty()))
    }

    #[test]
    fn every_deployment_classifies_to_exactly_one_policy() {
        // A total selector, and the reason the policy is an enum: the fifth combination two
        // `Option`s would admit — evaluating with nothing configured — cannot be written.
        let ceiling = Duration::from_secs(3600);
        let revocation = shared();

        assert!(matches!(
            currency_policy(&ServerOptions::default()),
            CredentialCurrencyPolicy::NotEvaluated
        ));
        assert!(matches!(
            currency_policy(&ServerOptions {
                max_client_cert_lifetime: Some(ceiling),
                ..Default::default()
            }),
            CredentialCurrencyPolicy::Ceiling(_)
        ));
        assert!(matches!(
            currency_policy(&ServerOptions {
                client_revocation: Some(Arc::clone(&revocation)),
                ..Default::default()
            }),
            CredentialCurrencyPolicy::Revocation(_)
        ));
        assert!(matches!(
            currency_policy(&ServerOptions {
                max_client_cert_lifetime: Some(ceiling),
                client_revocation: Some(revocation),
                ..Default::default()
            }),
            CredentialCurrencyPolicy::CeilingAndRevocation(_, _)
        ));
    }

    #[test]
    fn currency_policy_reads_the_index_in_force_at_the_time_of_the_call() {
        // The half of the reload claim that moved here when the authority began taking the
        // index as a value. The broken implementation this catches is hoisting `load()` out
        // of the per-request decision — caching it per connection is exactly the
        // handshake-only posture the per-request check exists to replace.
        let revocation = shared();
        let options = ServerOptions {
            client_revocation: Some(Arc::clone(&revocation)),
            ..Default::default()
        };
        let before = currency_policy(&options);
        assert!(
            before
                .revocation()
                .is_some_and(ClientRevocationIndex::is_empty),
            "the first snapshot is the empty index that was in force"
        );

        revocation.store(ClientRevocationIndex::empty());
        let after = currency_policy(&options);
        assert!(
            !std::ptr::eq(
                before.revocation().expect("configured"),
                after.revocation().expect("configured")
            ),
            "a second call must re-read the cell, not reuse the first snapshot"
        );
    }
}

#[cfg(test)]
mod routing_header_tests {
    #[test]
    fn routing_header_rejection_fails_closed_on_bad_headers_only() {
        // ADR-MCPS-025 rule 4 enforcement at the transport seam. Clean/absent
        // routing headers pass; a duplicate or malformed one fails closed with
        // mcp-re.transport_binding_failed bound to the request id.
        use crate::transport::RequestHeaders;
        let req = br#"{"jsonrpc":"2.0","id":"req-1","method":"tools/call"}"#;

        let clean = RequestHeaders::from_pairs([("Mcp-Method", "tools/call")]);
        assert!(super::routing_header_rejection(&clean, req).is_none());

        let duplicate = RequestHeaders::from_pairs([
            ("Mcp-Method", "tools/call"),
            ("mcp-method", "tools/list"),
        ]);
        let rejected =
            super::routing_header_rejection(&duplicate, req).expect("duplicate must reject");
        let value: serde_json::Value =
            serde_json::from_slice(&rejected).expect("json error object");
        assert_eq!(value["error"]["message"], "mcp-re.transport_binding_failed");
        assert_eq!(value["id"], "req-1");

        let malformed = RequestHeaders::from_pairs([("Mcp-Name", "echo\r\nX-Spoof: evil")]);
        assert!(super::routing_header_rejection(&malformed, req).is_some());
    }
}

/// MCPS-079 fault-injection module ("test of the tests"), the symmetric mirror of
/// mcp-re-transport's `fault_accept_any` (server-side). Compiled ONLY under the
/// `fault_accept_any_client` feature, which is off by default and never enabled by
/// production targets or the default `bazel test //...`. It re-introduces the
/// `AcceptAnyClient` anti-pattern the verifying proxy was built to eliminate, so
/// the periodic fault-injection harness can prove the proxy's client-cert
/// rejection guards (the more important boundary — the proxy guards the inner)
/// would FAIL if the control were broken.
#[cfg(feature = "fault_accept_any_client")]
pub(crate) mod fault_accept_any {
    use std::sync::Arc;

    use rustls::client::danger::HandshakeSignatureValid;
    use rustls::crypto::verify_tls12_signature;
    use rustls::crypto::verify_tls13_signature;
    use rustls::crypto::CryptoProvider;
    use rustls::server::danger::ClientCertVerified;
    use rustls::server::danger::ClientCertVerifier;
    use rustls::DigitallySignedStruct;
    use rustls::DistinguishedName;
    use rustls::Error as RustlsError;
    use rustls::SignatureScheme;
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::UnixTime;

    /// A client-certificate verifier that accepts ANY client certificate: any CA,
    /// any identity, any validity window — and, via the `client_auth_mandatory`
    /// override, also accepts a connection that presents NO client certificate at
    /// all. Handshake SIGNATURES are still checked via the crypto provider (so the
    /// TLS handshake completes against a real client) — only the trust/identity/
    /// expiry decision is neutered. This is the exact shape of the control break
    /// the proxy's client-auth tests exist to catch.
    #[derive(Debug)]
    pub struct AcceptAnyClientVerifier {
        provider: Arc<CryptoProvider>,
    }

    impl AcceptAnyClientVerifier {
        pub fn new(provider: Arc<CryptoProvider>) -> Self {
            AcceptAnyClientVerifier { provider }
        }
    }

    impl ClientCertVerifier for AcceptAnyClientVerifier {
        fn verify_client_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _now: UnixTime,
        ) -> Result<ClientCertVerified, RustlsError> {
            // THE BREAK: trust, identity, and expiry are never checked.
            Ok(ClientCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }

        fn root_hint_subjects(&self) -> &[DistinguishedName] {
            // No trust anchors are advertised — the faulted verifier ignores trust
            // entirely, so there are no issuer hints to send to the client.
            &[]
        }

        fn client_auth_mandatory(&self) -> bool {
            // THE SECOND BREAK: a client certificate is no longer required. This is
            // what flips T1 (`missing_client_certificate_is_rejected`): with this
            // returning `false`, a connection presenting NO client cert completes
            // the handshake instead of being rejected. T2
            // (`untrusted_client_certificate_is_rejected`) flips via
            // `verify_client_cert` above accepting any presented cert.
            false
        }
    }
}

#[cfg(test)]
mod crl_next_update_tests {
    //! The TLS plane performs no security transition on `Drop` and gives its CRL reload
    //! loop no failure budget, both on the ground that a CRL bounds ITSELF. That argument
    //! holds only while every loaded CRL states a `nextUpdate`, so a CRL without one is
    //! refused where it is read rather than admitted into a posture that claims it
    //! self-bounds.

    use super::*;
    use der::Decode;
    use der::Encode;
    use x509_cert::crl::CertificateList;

    fn crl_with_next_update() -> Vec<u8> {
        let key = rcgen::KeyPair::generate().expect("ca key");
        let mut params = rcgen::CertificateParams::new(Vec::new()).expect("ca params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "crl-gate-ca");
        let _ca = params.self_signed(&key).expect("ca");
        let crl_params = rcgen::CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2024, 1, 1),
            next_update: rcgen::date_time_ymd(2999, 1, 1),
            crl_number: rcgen::SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        crl_params
            .signed_by(&rcgen::Issuer::from_params(&params, &key))
            .expect("crl")
            .der()
            .to_vec()
    }

    /// The same CRL with its `nextUpdate` removed. RFC 5280 permits the encoding, which
    /// is exactly why the gate has to refuse it rather than assume no CA emits one.
    fn crl_without_next_update() -> Vec<u8> {
        let mut list = CertificateList::from_der(&crl_with_next_update()).expect("parse");
        list.tbs_cert_list.next_update = None;
        list.to_der().expect("re-encode")
    }

    #[test]
    fn a_crl_that_states_its_next_update_is_accepted() {
        let der = crl_with_next_update();
        assert_eq!(
            crl_freshness(&der, 0, 0).expect("parse"),
            CrlFreshness::Fresh
        );
        assert!(crl_next_update_required(&der, 0).is_ok());
    }

    /// The broken implementation this catches: classifying a `nextUpdate`-less CRL as
    /// `Fresh`. Nothing downstream can age it out — rustls' expiration enforcement has
    /// no field to compare and `ClientRevocationIndex::verdict` answers `Good` for its
    /// issuer at any `now` — so a permanently failing reload would leave the replica
    /// admitting certificates revoked afterwards for the rest of its lifetime.
    #[test]
    fn a_crl_that_never_falls_out_of_force_is_refused() {
        let der = crl_without_next_update();
        assert_eq!(
            crl_freshness(&der, 0, 0).expect("parse"),
            CrlFreshness::NoNextUpdate
        );
        let err = crl_next_update_required(&der, 3).expect_err("must be refused");
        let message = err.to_string();
        assert!(message.contains("#3"), "names the offending CRL: {message}");
        assert!(
            message.contains("nextUpdate"),
            "names what is missing: {message}"
        );
    }
}

/// Reading the configured CRL files, which is a TLS concern and was a CLI one.
///
/// It moved here with `ChannelEstablishmentPlan`: the TLS plane is the only caller, and reaching for it
/// through `cli` was the last thing keeping a configuration module named in a plane that
/// no longer takes configuration.
#[cfg(test)]
mod client_crl_loading_tests {
    #[test]
    fn missing_client_crl_file_fails_closed() {
        // A configured-but-unreadable CRL path is a hard error, never a silently
        // skipped revocation check.
        let err =
            super::load_client_crls(&["/no/such/MCPS3839_MISSING.crl".to_string()]).unwrap_err();
        assert!(err.contains("MCPS3839_MISSING"), "got: {err}");
    }

    #[test]
    fn no_crl_paths_loads_empty_vec() {
        // The no-CRL path: empty input → empty vec (revocation disabled), no error.
        let crls = super::load_client_crls(&[]).expect("empty load");
        assert!(crls.is_empty());
    }
}

#[cfg(test)]
mod delegated_credential_key_correspondence_tests {
    //! ADR-MCPRE-063 Slice 2 — characterization of the credential/key correspondence
    //! semantics currently bundled into [`validated_delegated_resolver`].
    //!
    //! Written BEFORE the migration and against the unmigrated implementation, which is
    //! the order Slice 1 established: a control written after a migration proves the
    //! migration self-consistent, not the property.
    //!
    //! What these controls pin is that each of the six vectors REFUSES. What they cannot
    //! pin — and the reason this slice exists — is which fact each refusal reports: all
    //! six arrive as `TlsError::DelegatedKeyMismatch(String)`, so the only thing telling
    //! an empty credential chain apart from a genuine key mismatch is prose. A caller,
    //! an audit record and a test can all match on the variant; none of them can match on
    //! the sentence.

    use x509_parser::certificate::X509Certificate;
    use x509_parser::prelude::FromDer;

    use super::*;
    use crate::communication_assurance::credential_key_correspondence::establish_credential_key_correspondence;
    use crate::communication_assurance::credential_key_correspondence::CorrespondenceMismatch;
    use crate::communication_assurance::credential_key_correspondence::CredentialKeyCorrespondenceRefusal;
    use crate::communication_assurance::credential_public_key_evidence::CredentialKeyRefusal;
    use crate::communication_assurance::ed25519_public_key::Rfc8410SpkiRefusal;
    use crate::communication_assurance::signing_key_evidence::SigningKeyExportEvidence;
    use crate::communication_assurance::signing_key_evidence::SigningKeyRefusal;
    use crate::communication_assurance::CertificateChainEvidence;
    use rcgen::CertificateParams;
    use rcgen::KeyPair;
    use rcgen::PKCS_ED25519;

    /// A delegated signer whose exported public key is whatever the test supplies —
    /// including nothing, which is the "signer yielded no exportable key" vector.
    struct TestSigner {
        exported_spki: Option<Vec<u8>>,
    }

    impl crate::delegated_tls::RawEd25519TlsSigner for TestSigner {
        fn sign_tls_ed25519(
            &self,
            _message: &[u8],
        ) -> Result<Vec<u8>, crate::key_source::KeyError> {
            Ok(vec![0u8; 64])
        }

        fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, crate::key_source::KeyError> {
            self.exported_spki.clone().ok_or_else(|| {
                crate::key_source::KeyError::Malformed(
                    "test signer exports no public key".to_string(),
                )
            })
        }
    }

    fn signer(
        exported_spki: Option<Vec<u8>>,
    ) -> Arc<dyn crate::delegated_tls::RawEd25519TlsSigner> {
        Arc::new(TestSigner { exported_spki })
    }

    fn budget() -> Arc<crate::delegated_tls::TlsHandshakeSignBudget> {
        Arc::new(crate::delegated_tls::TlsHandshakeSignBudget::new(64, 64))
    }

    /// A self-signed leaf and the SPKI DER of the key it presents.
    fn ed25519_leaf() -> (CertificateDer<'static>, Vec<u8>) {
        let key = KeyPair::generate_for(&PKCS_ED25519).expect("ed25519 key");
        let params =
            CertificateParams::new(vec!["delegated.example.org".to_string()]).expect("leaf params");
        let cert = params.self_signed(&key).expect("self-signed leaf");
        let der = cert.der().clone();
        let (_, parsed) = X509Certificate::from_der(der.as_ref()).expect("parse leaf");
        let spki = parsed.public_key().raw.to_vec();
        (der, spki)
    }

    /// A leaf whose public key is a P-256 key: a well-formed SPKI of an algorithm the
    /// delegated path does not support, which is NOT the same as unreadable bytes.
    fn p256_leaf() -> CertificateDer<'static> {
        let key = KeyPair::generate().expect("p256 key");
        let params =
            CertificateParams::new(vec!["delegated.example.org".to_string()]).expect("leaf params");
        params
            .self_signed(&key)
            .expect("self-signed leaf")
            .der()
            .clone()
    }

    #[test]
    fn matching_credential_and_signing_key_is_accepted() {
        let (leaf, spki) = ed25519_leaf();
        assert!(
            validated_delegated_resolver(vec![leaf], signer(Some(spki)), budget()).is_ok(),
            "equal keys under the required profile are the accepting case"
        );
    }

    #[test]
    fn a_signing_key_that_is_not_the_credential_key_is_refused() {
        let (leaf, _) = ed25519_leaf();
        let (_, other_spki) = ed25519_leaf();
        assert!(
            validated_delegated_resolver(vec![leaf], signer(Some(other_spki)), budget()).is_err(),
            "the signer signs for a different key than the credential presents"
        );
    }

    #[test]
    fn an_empty_credential_chain_is_refused() {
        let (_, spki) = ed25519_leaf();
        assert!(validated_delegated_resolver(Vec::new(), signer(Some(spki)), budget()).is_err());
    }

    #[test]
    fn an_unparseable_credential_is_refused() {
        let garbage = CertificateDer::from(vec![0x30, 0x82, 0xff, 0xff, 0x00]);
        let (_, spki) = ed25519_leaf();
        assert!(validated_delegated_resolver(vec![garbage], signer(Some(spki)), budget()).is_err());
    }

    #[test]
    fn a_credential_whose_key_is_a_supported_shape_of_another_algorithm_is_refused() {
        let (_, spki) = ed25519_leaf();
        assert!(
            validated_delegated_resolver(vec![p256_leaf()], signer(Some(spki)), budget()).is_err(),
            "a P-256 credential key is well-formed and of the wrong profile"
        );
    }

    #[test]
    fn a_signer_that_exports_no_public_key_is_refused() {
        let (leaf, _) = ed25519_leaf();
        assert!(validated_delegated_resolver(vec![leaf], signer(None), budget()).is_err());
    }

    #[test]
    fn a_signing_key_of_another_algorithm_is_refused() {
        let (leaf, _) = ed25519_leaf();
        // A well-formed P-256 SPKI, taken from a real certificate rather than invented.
        let p256 = p256_leaf();
        let (_, parsed) = X509Certificate::from_der(p256.as_ref()).expect("parse");
        let p256_spki = parsed.public_key().raw.to_vec();
        assert!(
            validated_delegated_resolver(vec![leaf], signer(Some(p256_spki)), budget()).is_err()
        );
    }

    #[test]
    fn a_signing_key_of_another_algorithm_carrying_the_credential_point_is_refused() {
        // The control that actually reaches the required-profile conjunct.
        //
        // Deleting the profile check and comparing the trailing 32 bytes leaves every
        // other negative here GREEN: a P-256 signing key is then refused only because its
        // bytes happen not to match, which is incidental, not enforcement. This vector
        // removes the coincidence — a non-Ed25519 SPKI whose trailing bytes ARE the
        // credential's public point — so the only thing that can refuse it is the profile
        // rule itself. That is the algorithm-confusion shape: a signer of the wrong
        // algorithm accepted as if it were the credential's key.
        let (leaf, spki) = ed25519_leaf();
        let point = &spki[spki.len() - 32..];
        let mut confusable = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2a, 0x86, 0x48, 0x03, 0x21, 0x00,
        ];
        confusable.extend_from_slice(point);
        assert!(
            validated_delegated_resolver(vec![leaf], signer(Some(confusable)), budget()).is_err(),
            "an SPKI declaring another algorithm must be refused on the profile rule, even \
             when its trailing bytes are exactly the credential's public point"
        );
    }

    #[test]
    fn every_characterized_failure_is_a_distinct_typed_refusal() {
        // The replacement for the characterization test this suite opened with.
        //
        // Before the slice, every vector arrived as `TlsError::DelegatedKeyMismatch` and
        // was distinguishable ONLY as prose. They are now values of a hierarchical
        // algebra: two sides, each with its own failures, and one mismatch belonging to
        // the relation. The facade still renders a message, because its callers expect
        // one — but the message is a rendering of a fact rather than the only place the
        // fact exists.
        //
        // The property is deliberately count-free. Characterization found six prose-only
        // failures and the algebra already distinguishes more than six, because the key
        // representation alone has three; a later adapter may legitimately add another.
        // What must hold is that every characterized failure is its own value — a name
        // pinning a number would have to be renamed the first time the architecture is
        // right about something new.
        let (leaf, spki) = ed25519_leaf();
        let (_, other_spki) = ed25519_leaf();
        let p256 = p256_leaf();
        let (_, parsed) = X509Certificate::from_der(p256.as_ref()).expect("parse");
        let p256_spki = parsed.public_key().raw.to_vec();
        let garbage = [0x30u8, 0x82, 0xff, 0xff, 0x00];
        let empty: [u8; 0] = [];

        let cases: Vec<(
            &str,
            CertificateChainEvidence<'_>,
            SigningKeyExportEvidence<'_>,
            CredentialKeyCorrespondenceRefusal,
        )> = vec![
            (
                "empty credential chain",
                CertificateChainEvidence::absent(),
                SigningKeyExportEvidence::exported(&spki),
                CredentialKeyCorrespondenceRefusal::Credential(CredentialKeyRefusal::Absent),
            ),
            (
                "unparseable credential",
                CertificateChainEvidence::from_leaf_der(&garbage),
                SigningKeyExportEvidence::exported(&spki),
                CredentialKeyCorrespondenceRefusal::Credential(
                    CredentialKeyRefusal::UninterpretableCredential,
                ),
            ),
            (
                "credential key of another algorithm",
                CertificateChainEvidence::from_leaf_der(p256.as_ref()),
                SigningKeyExportEvidence::exported(&spki),
                CredentialKeyCorrespondenceRefusal::Credential(CredentialKeyRefusal::Key(
                    Rfc8410SpkiRefusal::UnsupportedAlgorithm {
                        oid: "1.2.840.10045.2.1".to_string(),
                    },
                )),
            ),
            (
                "signer exports nothing",
                CertificateChainEvidence::from_leaf_der(leaf.as_ref()),
                SigningKeyExportEvidence::unavailable(),
                CredentialKeyCorrespondenceRefusal::SigningKey(SigningKeyRefusal::Unavailable),
            ),
            (
                "signing key of another algorithm",
                CertificateChainEvidence::from_leaf_der(leaf.as_ref()),
                SigningKeyExportEvidence::exported(&p256_spki),
                CredentialKeyCorrespondenceRefusal::SigningKey(SigningKeyRefusal::Key(
                    Rfc8410SpkiRefusal::UnsupportedAlgorithm {
                        oid: "1.2.840.10045.2.1".to_string(),
                    },
                )),
            ),
            (
                "signer exports unreadable bytes",
                CertificateChainEvidence::from_leaf_der(leaf.as_ref()),
                SigningKeyExportEvidence::exported(&empty),
                CredentialKeyCorrespondenceRefusal::SigningKey(SigningKeyRefusal::Key(
                    Rfc8410SpkiRefusal::Uninterpretable,
                )),
            ),
            (
                "key mismatch",
                CertificateChainEvidence::from_leaf_der(leaf.as_ref()),
                SigningKeyExportEvidence::exported(&other_spki),
                CredentialKeyCorrespondenceRefusal::Mismatch(CorrespondenceMismatch),
            ),
        ];

        let mut seen = Vec::new();
        for (name, credential, export, expected) in cases {
            let refusal = establish_credential_key_correspondence(credential, export)
                .err()
                .unwrap_or_else(|| panic!("{name} must refuse"));
            assert_eq!(refusal, expected, "{name} reported the wrong fact");
            seen.push(refusal);
        }

        for (i, left) in seen.iter().enumerate() {
            for right in seen.iter().skip(i + 1) {
                assert_ne!(
                    left, right,
                    "every vector must be a DISTINCT value, not a distinct sentence"
                );
            }
        }
    }

    #[test]
    fn the_accepting_case_yields_the_one_key_both_sides_presented() {
        let (leaf, spki) = ed25519_leaf();
        let facts = establish_credential_key_correspondence(
            CertificateChainEvidence::from_leaf_der(leaf.as_ref()),
            SigningKeyExportEvidence::exported(&spki),
        )
        .expect("equal keys of the required profile");
        assert_eq!(
            facts.corresponding_key().raw_point().as_slice(),
            &spki[spki.len() - 32..],
            "the corresponding key is the key, not a re-derivation of it"
        );
    }
}

#[cfg(test)]
mod channel_peer_resolution_tests {
    //! ADR-MCPRE-064 (#619, #621, #623) — the direct-TLS serving paths resolve their
    //! channel peer from the AUTHENTICATED peer and the deployment's own currency policy,
    //! never from certificate representation.
    //!
    //! Every control drives a real handshake. What a synthetic chain would prove about
    //! which credential a relationship authenticated with is nothing, and the property at
    //! stake here is provenance rather than parsing.

    use super::*;

    use crate::communication_assurance::mechanism_verified_credential::EstablishmentPath;
    use crate::communication_assurance::CertificateIdentitySource;

    use rustls::HandshakeKind;

    use crate::communication_assurance::channel_associated_credential::mechanism_harness::*;
    use crate::communication_assurance::mechanism_verified_credential::rustls_adapter::verified_credential;

    const NOW: i64 = 1_800_000_000;

    const IDENTITY_A: &str = "spiffe://example.org/A";
    const IDENTITY_B: &str = "spiffe://example.org/B";

    fn direct_tls(policy: IdentityPolicy) -> ServerOptions {
        ServerOptions {
            identity_policy: policy,
            peer_identity_provenance: PeerIdentityProvenance::ChannelCredential,
            ..Default::default()
        }
    }

    /// A real relationship whose client chain is `[leaf(uri_san), intermediate(decoy)]` —
    /// the decoy answers the same policy with a DIFFERENT identity, so a route that read
    /// any certificate other than the accepted credential's leaf returns the wrong
    /// identity rather than merely a different-looking success.
    fn accepted(uri_san: &str, decoy: &str) -> MechanismVerifiedCredentialEvidence {
        let root = make_ca("serving-root");
        let intermediate = make_intermediate(&root, "serving-intermediate", decoy);
        let server_ca = make_ca("serving-server-ca");
        let (server_leaf, server_key) = make_leaf(&server_ca, "localhost", false);
        let (client_leaf, client_key) = make_uri_leaf(&intermediate, uri_san);
        let server = server_config(&[root.der()], vec![server_leaf], server_key);
        let client = client_config(
            &server_ca.der(),
            Some((vec![client_leaf, intermediate.der()], client_key)),
        );
        let conn = handshake(&client, &server);
        assert_eq!(conn.handshake_kind(), Some(HandshakeKind::Full));
        verified_credential(&conn).expect("an established relationship accepts")
    }

    #[test]
    fn direct_tls_resolves_the_identity_the_relationship_authenticated_as() {
        let acceptance = accepted(IDENTITY_A, IDENTITY_B);
        let peer =
            resolve_channel_peer(Some(&acceptance), &direct_tls(IdentityPolicy::UriSan), NOW)
                .expect("no currency control is configured")
                .expect("the accepted credential's leaf carries the configured field");

        assert_eq!(peer.identity().as_str(), IDENTITY_A);
        assert_eq!(peer.identity_source(), CertificateIdentitySource::UriSan);
    }

    #[test]
    fn an_issuer_in_the_accepted_chain_never_becomes_the_transport_identity() {
        // The failure a raw-chain route invites: two certificates in the accepted chain
        // answer the policy, and reading "some certificate the peer presented" binds the
        // deployment to the CA rather than to the workload.
        let acceptance = accepted(IDENTITY_A, IDENTITY_B);
        let peer =
            resolve_channel_peer(Some(&acceptance), &direct_tls(IdentityPolicy::UriSan), NOW)
                .expect("no currency control is configured")
                .expect("resolution succeeds");
        assert_ne!(peer.identity().as_str(), IDENTITY_B);
    }

    #[test]
    fn each_relationship_resolves_its_own_peers_identity() {
        // The L-5 control at the serving boundary: two live relationships, one options
        // record. A route that reached past its own acceptance would answer the same
        // identity twice.
        let first = accepted(IDENTITY_A, IDENTITY_B);
        let second = accepted(IDENTITY_B, IDENTITY_A);
        let options = direct_tls(IdentityPolicy::UriSan);

        let from_first = resolve_channel_peer(Some(&first), &options, NOW)
            .expect("no currency control is configured")
            .expect("first resolves");
        let from_second = resolve_channel_peer(Some(&second), &options, NOW)
            .expect("no currency control is configured")
            .expect("second resolves");
        assert_eq!(from_first.identity().as_str(), IDENTITY_A);
        assert_eq!(from_second.identity().as_str(), IDENTITY_B);
    }

    #[test]
    fn a_resumed_relationship_resolves_the_same_identity_as_a_full_handshake() {
        // Resumption restores the stored peer chain, so it is the same peer and must
        // resolve to the same identity — while the establishment path stays DIFFERENT,
        // which is what a consumer needing "the verifier ran in this establishment" reads.
        let peers = mutually_authenticated_peers();
        let full = verified_credential(&handshake(&peers.client, &peers.server)).expect("accepts");
        let resumed_conn = handshake(&peers.client, &peers.server);
        assert_eq!(
            resumed_conn.handshake_kind(),
            Some(HandshakeKind::Resumed),
            "without a real resumption this control is a second full handshake"
        );
        let resumed = verified_credential(&resumed_conn).expect("accepts");
        let options = direct_tls(IdentityPolicy::DnsSan);

        let from_full = resolve_channel_peer(Some(&full), &options, NOW)
            .expect("no currency control is configured")
            .expect("a peer");
        let from_resumed = resolve_channel_peer(Some(&resumed), &options, NOW)
            .expect("no currency control is configured")
            .expect("a peer");

        assert_eq!(
            from_full.identity(),
            from_resumed.identity(),
            "a resumed relationship is the same authenticated peer"
        );
        assert_eq!(
            from_full.establishment_path(),
            EstablishmentPath::FullHandshake
        );
        assert_eq!(
            from_resumed.establishment_path(),
            EstablishmentPath::ResumedSession,
            "the resumed/full distinction survives all the way to the channel peer"
        );
        assert_ne!(from_full, from_resumed);
    }

    #[test]
    fn a_leaf_without_the_configured_field_resolves_no_identity() {
        // No-fallback, at the serving boundary. The peer's leaf carries a DNS SAN and the
        // deployment configured URI SANs: the request must reach the fail-closed core with
        // no identity rather than with a weaker field's value.
        let peers = mutually_authenticated_peers();
        let acceptance =
            verified_credential(&handshake(&peers.client, &peers.server)).expect("accepts");
        assert!(
            resolve_channel_peer(Some(&acceptance), &direct_tls(IdentityPolicy::UriSan), NOW)
                .expect("no currency control is configured")
                .is_none(),
            "a present DNS SAN is not a reason to answer under a URI-SAN policy"
        );
    }

    #[test]
    fn an_absent_acceptance_resolves_no_identity() {
        assert!(
            resolve_channel_peer(None, &direct_tls(IdentityPolicy::UriSan), NOW)
                .expect("no currency control is configured")
                .is_none(),
            "no acceptance is no authenticated peer"
        );
    }

    #[test]
    fn an_lb_assertion_deployment_resolves_no_transport_identity() {
        // Untouched by this migration: under LB assertion the client certificate is not
        // consulted for identity, and a live accepted credential must not change that.
        let acceptance = accepted(IDENTITY_A, IDENTITY_B);
        let options = ServerOptions {
            identity_policy: IdentityPolicy::UriSan,
            peer_identity_provenance: PeerIdentityProvenance::IngressAssertion,
            ..Default::default()
        };
        assert!(resolve_channel_peer(Some(&acceptance), &options, NOW)
            .expect("no currency control is configured")
            .is_none());
    }
}
