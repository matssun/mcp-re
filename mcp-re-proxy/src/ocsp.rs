//! ONLINE client-certificate revocation via OCSP (#4030, Phase 7,
//! ADR-MCPS-019) — compiled ONLY under the non-default `online_ocsp` feature.
//!
//! The proxy asks the verified client leaf's OCSP responder (RFC 6960) whether it is
//! revoked at connection time, before the request reaches the inner server, so a
//! compromised credential is refused without waiting for a CRL update and restart.
//!
//! # Design
//!
//! A per-connection fail-closed rejection hook, a sibling of
//! `tls::cert_lifetime_rejection`: it runs after the mTLS handshake (the leaf is already
//! chain-verified) and before the handler. A transport error, parse error, trust failure
//! or `Unknown` status all deny; the checker takes no policy input that could admit one.
//!
//! The checker is dormant: no validated deployment enables the online half (THM-0013), and
//! its fetch is a blocking one. The fetch timeout bounds connect, send and the body read; it
//! does NOT bound name resolution, which `ureq` does not interrupt, so a hostile responder
//! hostname can hold a serving thread for the resolver's own limit. Bounding resolution is
//! the async OCSP follow-up's, not this module's.
//!
//! The deterministic pieces — responder-URL extraction, status mapping, the trust
//! pipeline — are small functions the unit tests exercise with no network.
//!
//! # CertID hash
//!
//! CertIDs are built with **SHA-256** (`sha2::Sha256`). The responder MUST be configured to
//! answer SHA-256 CertIDs; an OpenSSL test responder does so with `openssl ocsp ... -sha256`
//! (see `tests/ocsp_e2e_test.rs`).
//!
//! # Issuer binding
//!
//! `check` takes the issuer as an argument, and the CertID, the signer candidate and the
//! responder identity are all measured against it. [`leaf_is_issued_by`] therefore refuses
//! an issuer that did not sign the leaf, so those checks run against the key that issued the
//! handshake-verified leaf and not against whatever a peer presented after it.
//!
//! # Responder-response trust chain (#4063 / MCPS-088, closes #4030)
//!
//! A `Good` admits the client, so RFC 6960 §3.2 requires the response be TRUSTED before its
//! status is acted on. This module runs the full chain BEFORE mapping a status and fails
//! CLOSED on any gap:
//!
//!   1. **Responder signature** — verified over the DER of `tbs_response_data`,
//!      algorithm-agnostically (RSA PKCS#1 v1.5 SHA-256/384/512, ECDSA P-256/P-384, Ed25519,
//!      via `x509-parser`'s `ring`-backed verifier). The signer is EITHER the issuer OR a
//!      delegated responder certificate in `basic.certs` that is in its validity window,
//!      issuer-signed, and carries the `id-kp-OCSPSigning` EKU and `id-pkix-ocsp-nocheck`,
//!      is not a CA and, when it states key usage, permits `digitalSignature`. See
//!      [`verify_responder_signature`] and [`delegated_responder_is_valid`].
//!   2. **Responder identity** — `responder_id` (byName or byKey) must match the signer from
//!      (1). See [`responder_id_matches`].
//!   3. **Nonce** — the request carries a 16-byte CSPRNG nonce; a responder that echoes one
//!      MUST echo ours. See [`nonce_ok`].
//!   4. **CertID binding** — exactly one `SingleResponse` must bind to the CertID we
//!      requested; none, or more than one, is refused. See [`select_matching_single_response`].
//!   5. **Freshness** — `now >= thisUpdate - skew` and `now <= upper + skew`, where `upper`
//!      is `nextUpdate` capped at `thisUpdate + max_response_age`, so a response omitting
//!      `nextUpdate` cannot be replayed indefinitely. See [`acceptance_bound`].
//!
//! The answer that comes out carries the end of its own acceptance window, so possession
//! means "a verified responder said this, valid until T": [`OcspChecker::allows`] refuses an
//! answer past it.

use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use der::asn1::Null;
use der::asn1::OctetString;
use der::oid::ObjectIdentifier;
use der::Decode;
use der::Encode;
use sha2::Digest;
use sha2::Sha256;
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;
use x509_ocsp::builder::OcspRequestBuilder;
use x509_ocsp::ext::Nonce;
use x509_ocsp::BasicOcspResponse;
use x509_ocsp::CertId;
use x509_ocsp::CertStatus;
use x509_ocsp::OcspResponse;
use x509_ocsp::OcspResponseStatus;
use x509_ocsp::Request;
use x509_ocsp::ResponderId;
use x509_ocsp::SingleResponse;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::FromDer;
use x509_parser::time::ASN1Time;

use crate::outbound_fetch::VettedDestination;

/// The `id-kp-OCSPSigning` extended-key-usage OID (`1.3.6.1.5.5.7.3.9`,
/// RFC 6960 §4.2.2.2). A delegated responder certificate — one carried in the
/// response's `certs` rather than being the issuer itself — MUST carry this EKU
/// for its signature over the response to be trusted.
const ID_KP_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";

/// The `id-pkix-ocsp-nocheck` extension OID (`1.3.6.1.5.5.7.48.1.5`, RFC 6960 §4.2.2.2.1).
/// This module has no revocation source for a delegated responder certificate, so the
/// extension — which licenses a relying party to skip that check — is the only way the
/// responder's standing can be established here.
const ID_PKIX_OCSP_NOCHECK: &str = "1.3.6.1.5.5.7.48.1.5";

/// The request nonce length in bytes (RFC 8954 permits 1..32; 16 is ample
/// entropy against replay/substitution while staying within responders that cap
/// nonce length). The nonce is freshly drawn per request from the OS CSPRNG.
const OCSP_NONCE_LEN: usize = 16;

/// The freshness skew tolerance: a few minutes absorbs clock drift between the
/// proxy and the responder without widening the window enough to matter for
/// revocation latency. `thisUpdate` may be up to this far in the future, and
/// `nextUpdate` up to this far in the past, before the response is rejected.
const OCSP_FRESHNESS_SKEW: Duration = Duration::from_secs(300);

/// The maximum age a response may have relative to its `thisUpdate`, applied as
/// an absolute upper bound on acceptance EVEN WHEN `nextUpdate` is absent. RFC
/// 6960 permits responders to omit `nextUpdate` (and to ignore the request
/// nonce), which would otherwise let a captured responder-signed `good` be
/// replayed by an active network attacker indefinitely — keeping a since-revoked
/// client admitted and defeating the online check's purpose of bounding
/// revocation latency. Capping acceptance at `thisUpdate + max_response_age (+
/// skew)` bounds that replay window. One day is comfortably longer than any
/// well-configured responder's refresh interval while still bounding latency.
const OCSP_MAX_RESPONSE_AGE: Duration = Duration::from_secs(86_400);

/// The OCSP access-method OID `id-ad-ocsp` (`1.3.6.1.5.5.7.48.1`) used inside the
/// Authority Information Access (AIA) extension to point at the responder URL.
const ID_AD_OCSP: &str = "1.3.6.1.5.5.7.48.1";

/// The `id-sha256` digest-algorithm OID (`2.16.840.1.101.3.4.2.1`). The CertID
/// hash algorithm is SHA-256, so the responder must be configured to answer
/// SHA-256 CertIDs. Declared as a literal so the build does not depend on a
/// digest crate exposing its `AssociatedOid` impl under the current feature set.
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// The default HTTP fetch timeout: a per-request deadline over connect, send and the body
/// read, after which the check fails closed. It does not cover DNS resolution, which `ureq`
/// does not interrupt.
const DEFAULT_OCSP_TIMEOUT: Duration = Duration::from_secs(5);

/// What a VERIFIED responder said about the client leaf certificate.
///
/// The deterministic mapping of the OCSP `CertStatus` CHOICE, and nothing more: it is not
/// an admission decision, and on its own it is not evidence that anything was verified. A
/// value of this type is only meaningful inside a [`TrustedRevocationAnswer`], which is
/// what makes it earned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertRevocationStatus {
    /// The responder asserts the certificate is NOT revoked (`good`).
    Good,
    /// The responder asserts the certificate IS revoked (`revoked`).
    Revoked,
    /// The responder itself does not know the certificate's status (`unknown`).
    ///
    /// This is a RESPONDER VERDICT and is deliberately distinct from
    /// [`RevocationEvidence::NotEstablished`] — a responder that answers "I do not know"
    /// has been reached, verified, and has spoken, and a fetch that never happened has
    /// not. Both fail closed, and conflating them would make the audit trail say the
    /// responder answered when nothing did.
    Unknown,
}

/// The conclusion the RFC 6960 §3.2 trust chain reached — and the ONLY way to speak one.
///
/// The representation is private and [`verify_and_map_response`] is its sole producer, so
/// possession of one means all five checks ran: the responder signature verified against
/// the issuer or a delegated `id-kp-OCSPSigning` responder, the `responder_id` matched that
/// signer, a present nonce echoed ours, a `SingleResponse` bound to the CertID we asked
/// about, and that response was fresh. There is no constructor taking a status.
///
/// It also carries the end of its own acceptance window, as a `Duration` since the Unix
/// epoch: a freshness proof taken at T is not an admission token forever. It is not `Copy`,
/// so the dated value is handed on rather than duplicated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedRevocationAnswer {
    status: CertRevocationStatus,
    valid_until: Duration,
}

impl TrustedRevocationAnswer {
    /// What the verified responder said.
    pub fn status(&self) -> CertRevocationStatus {
        self.status
    }

    /// Whether this answer admits the certificate at `now`: it said `Good` and `now` is
    /// still inside the window it was accepted for.
    fn admits_at(&self, now: SystemTime) -> bool {
        self.status == CertRevocationStatus::Good
            && system_time_to_unix(now).is_some_and(|now| now <= self.valid_until)
    }

    /// A verified answer, for a test whose subject is the POLICY rather than the chain.
    ///
    /// `#[cfg(test)]`. The policy — only a `Good` inside its window admits — is a different
    /// proposition from "the chain ran", and a test of the first should not have to mint a
    /// signed OCSP response to state it. It compiles to nothing outside the test build, so
    /// the seal holds against every production path and against every other crate.
    #[cfg(test)]
    fn answered(status: CertRevocationStatus, valid_until: Duration) -> Self {
        TrustedRevocationAnswer {
            status,
            valid_until,
        }
    }
}

/// What this proxy knows about a certificate's revocation, and whether it EARNED it.
///
/// The two are not the same fact and the census asked for them to stop being the same
/// value. A responder that answered `unknown` was reached and verified; a check with no
/// responder URL, or one whose destination the outbound guard refused, reached nothing.
/// Both deny — that is the POLICY, and it is [`OcspChecker::allows`]'s — but only one of
/// them is a statement about the certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationEvidence {
    /// A verified responder answered. See [`TrustedRevocationAnswer`].
    Answered(TrustedRevocationAnswer),
    /// No trusted result could be established locally. Never a responder verdict.
    NotEstablished(NotEstablished),
}

/// Why no trusted revocation result could be established.
///
/// Local facts, every one of them: nothing here is anything a responder said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotEstablished {
    /// The leaf carries no AIA OCSP URL and no operator override was configured, so there
    /// was nowhere to ask.
    NoResponderConfigured,
    /// A responder URL existed and the outbound-fetch guard refused it — a certificate
    /// naming a private address or a scheme outside `http`/`https`. See
    /// [`crate::outbound_fetch`].
    DestinationRefused,
}

/// Errors performing an online OCSP check. Every variant is a fail-closed
/// condition: the connection is rejected.
#[derive(Debug, thiserror::Error)]
pub enum OcspError {
    /// A certificate (leaf or issuer) could not be decoded from DER.
    #[error("invalid certificate DER: {0}")]
    BadCertificate(String),
    /// The OCSP request could not be built or DER-encoded.
    #[error("OCSP request build failed: {0}")]
    BuildRequest(String),
    /// The HTTP POST to the responder failed (connect/timeout/transport/status).
    #[error("OCSP responder HTTP error: {0}")]
    Http(String),
    /// The responder's HTTP body could not be read.
    #[error("OCSP response read error: {0}")]
    ReadBody(String),
    /// The response could not be decoded as an `OCSPResponse`.
    #[error("OCSP response decode failed: {0}")]
    DecodeResponse(String),
    /// The responder returned a non-`successful` `OCSPResponseStatus`.
    #[error("OCSP responder returned non-successful status: {0:?}")]
    ResponderStatus(OcspResponseStatus),
    /// A `successful` response carried no `responseBytes`, or they were not a
    /// `BasicOCSPResponse`, or it held no `SingleResponse`.
    #[error("OCSP response malformed: {0}")]
    MalformedResponse(String),
    /// The responder's signature over `tbs_response_data` could not be verified
    /// against the issuer or a valid delegated responder certificate. This is the
    /// RFC 6960 §3.2 trust failure — fail CLOSED.
    #[error("OCSP responder signature not verified: {0}")]
    SignatureNotVerified(String),
    /// The `responder_id` did not match the certificate whose key verified the
    /// signature (the responder asserted an identity it did not sign as).
    #[error("OCSP responder identity mismatch: {0}")]
    ResponderIdentityMismatch(String),
    /// No `SingleResponse` in the response answered the CertID we requested, so
    /// the response carries no evidence about THIS certificate.
    #[error("OCSP response has no SingleResponse for the requested CertID")]
    CertIdMismatch,
    /// The response is stale (`now > nextUpdate + skew`) or not yet valid
    /// (`now < thisUpdate - skew`).
    #[error("OCSP response not fresh: {0}")]
    NotFresh(String),
    /// The responder echoed a nonce that did not equal the request nonce — a
    /// replayed or substituted response.
    #[error("OCSP response nonce mismatch")]
    NonceMismatch,
}

/// Performs an online OCSP revocation check for a verified client leaf
/// certificate against its issuer. Holds only configuration; it is cheap to
/// clone and carries no network state between calls.
///
/// `Debug` is written by hand: the configured responder URL may carry userinfo
/// credentials, and `ServerOptions` derives `Debug` over this type.
#[derive(Clone)]
pub struct OcspChecker {
    /// An explicit responder URL that OVERRIDES the leaf's AIA OCSP URL. `None`
    /// means "use the AIA URL from the leaf" (and a leaf without one establishes nothing).
    ///
    /// Held as the raw string rather than a [`VettedDestination`]: an override that fails
    /// the scheme allowlist must fail the connection being checked, not construction at
    /// startup for a deployment that may never reach this code.
    responder_url_override: Option<String>,
    /// The HTTP fetch timeout (see [`DEFAULT_OCSP_TIMEOUT`]).
    timeout: Duration,
}

impl std::fmt::Debug for OcspChecker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OcspChecker")
            .field("responder_override", &self.responder_url_override.is_some())
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl OcspChecker {
    /// Build a checker. `responder_url_override` (the `--ocsp-responder-url`
    /// AIA override) is used verbatim when set; otherwise the responder URL is
    /// read from the leaf's AIA OCSP entry. The timeout defaults to
    /// [`DEFAULT_OCSP_TIMEOUT`]. There is no fail-open posture to select.
    pub fn new(responder_url_override: Option<String>) -> Self {
        OcspChecker {
            responder_url_override,
            timeout: DEFAULT_OCSP_TIMEOUT,
        }
    }

    /// Perform the full online check for `leaf_der` against `issuer_der`:
    ///
    ///   a. resolve the responder URL (override, else the leaf's AIA OCSP URL;
    ///      none, or one the outbound guard refuses, establishes nothing);
    ///   b. require that `issuer_der` signed `leaf_der`;
    ///   c. build a SHA-256 CertID OCSP request carrying a fresh nonce;
    ///   d. POST it to the responder, reading the body (any transport/timeout
    ///      error → `Err`);
    ///   e. run the §3.2 trust chain over the response.
    ///
    /// Transport, codec and trust failures are `Err(OcspError)`. The admit/deny
    /// decision is [`OcspChecker::allows`].
    pub fn check(
        &self,
        leaf_der: &[u8],
        issuer_der: &[u8],
    ) -> Result<RevocationEvidence, OcspError> {
        // The guard is `crate::outbound_fetch`'s and it runs at CONSTRUCTION: there is no
        // way to reach `post_request` with a destination that did not pass the guard its
        // provenance requires. The reason nothing was established is decided there, once.
        let destination = match self.responder_destination(leaf_der) {
            Ok(destination) => destination,
            Err(reason) => return Ok(RevocationEvidence::NotEstablished(reason)),
        };
        if !leaf_is_issued_by(leaf_der, issuer_der)? {
            return Err(OcspError::BadCertificate(
                "leaf is not signed by the supplied issuer".into(),
            ));
        }

        // A fresh per-request CSPRNG nonce binds the response to THIS request: a
        // captured/replayed response carries a stale (mismatched) nonce and is
        // rejected (RFC 6960 §4.4.1 / RFC 8954).
        let nonce = random_nonce()?;
        let request_der = build_ocsp_request_der_with_nonce(leaf_der, issuer_der, &nonce)?;
        let response_der = self.post_request(&destination, &request_der)?;
        // The expected CertID we requested — used to bind the SingleResponse.
        let expected_cert_id = build_cert_id(leaf_der, issuer_der)?;
        verify_and_map_response(
            &response_der,
            issuer_der,
            &expected_cert_id,
            &nonce,
            SystemTime::now(),
        )
        .map(RevocationEvidence::Answered)
    }

    /// The destination to fetch from, guarded according to where it came from — or why
    /// there is none.
    ///
    /// The configured override wins and is OPERATOR-CONFIGURED; otherwise the AIA OCSP URL
    /// is read from the leaf and is CERTIFICATE-DERIVED. Which constructor is called is the
    /// whole of the provenance decision, and it is made HERE, once — the guard each one
    /// applies belongs to [`crate::outbound_fetch`] and this module cannot choose between
    /// them after the fact. Pure (no network) and unit-tested.
    fn responder_destination(&self, leaf_der: &[u8]) -> Result<VettedDestination, NotEstablished> {
        if let Some(url) = &self.responder_url_override {
            return VettedDestination::operator_configured(url.clone())
                .ok_or(NotEstablished::DestinationRefused);
        }
        let url =
            extract_ocsp_responder_url(leaf_der).ok_or(NotEstablished::NoResponderConfigured)?;
        VettedDestination::certificate_derived(url).ok_or(NotEstablished::DestinationRefused)
    }

    /// POST a DER OCSP request to `destination` and return the raw response body bytes.
    /// Any HTTP/timeout/transport error is `Err`.
    ///
    /// The SSRF posture is not decided here and cannot be: the agent comes from the
    /// destination, which knows its own provenance. Redirects are disabled for every
    /// provenance and the resolved-address vetting is installed for a certificate-derived
    /// one — see [`crate::outbound_fetch::VettedDestination::agent`] for both arguments.
    /// What this function still owns is the RESPONSE bound: a well-formed OCSP response is
    /// well under a kilobyte, and a hostile responder streaming an unbounded body into the
    /// serving thread is refused by the read cap rather than by the network.
    ///
    /// A transport failure is reported by its kind, never by `ureq`'s rendering of it: that
    /// rendering prefixes the request URL, and an operator-configured URL may carry userinfo.
    fn post_request(
        &self,
        destination: &VettedDestination,
        request_der: &[u8],
    ) -> Result<Vec<u8>, OcspError> {
        let response = destination
            .agent(self.timeout)
            .post(destination.url())
            .set("Content-Type", "application/ocsp-request")
            .set("Accept", "application/ocsp-response")
            .timeout(self.timeout)
            .send_bytes(request_der)
            .map_err(|e| OcspError::Http(e.kind().to_string()))?;
        // Bound the response body read so a hostile/oversized responder reply
        // cannot exhaust memory; a well-formed OCSP response is small.
        let mut body = Vec::new();
        use std::io::Read;
        response
            .into_reader()
            .take(MAX_OCSP_RESPONSE_BYTES)
            .read_to_end(&mut body)
            .map_err(|e| OcspError::ReadBody(e.to_string()))?;
        Ok(body)
    }

    /// The admit/deny decision for the evidence a check produced, at `now`.
    ///
    /// Only a `Good` answer still inside its own acceptance window admits. `Revoked`, a
    /// responder that said `unknown`, an answer past its window, and every reason no
    /// trusted result was established all deny.
    ///
    /// It takes [`RevocationEvidence`], not a status: a `Good` that nothing earned cannot
    /// be handed to this function, because there is no way to make one.
    /// Returns `true` to ALLOW the connection, `false` to REJECT it.
    pub fn allows(&self, evidence: RevocationEvidence, now: SystemTime) -> bool {
        match evidence {
            RevocationEvidence::Answered(answer) => answer.admits_at(now),
            RevocationEvidence::NotEstablished(_) => false,
        }
    }
}

/// Cap on the OCSP response body read (64 KiB). A legitimate single-cert OCSP
/// response is well under a kilobyte; this defends against a hostile or
/// misbehaving responder streaming an unbounded body into the serving thread.
const MAX_OCSP_RESPONSE_BYTES: u64 = 64 * 1024;

/// Extract the OCSP responder URL from a leaf certificate's Authority
/// Information Access (AIA) extension — the first `id-ad-ocsp` access
/// description whose location is a URI. Returns `None` if the cert cannot be
/// parsed, has no AIA extension, or has no OCSP URI entry. Pure (no network).
fn extract_ocsp_responder_url(leaf_der: &[u8]) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(leaf_der).ok()?;
    for ext in cert.extensions() {
        if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
            for desc in aia.iter() {
                if desc.access_method.to_id_string() == ID_AD_OCSP {
                    if let GeneralName::URI(uri) = &desc.access_location {
                        return Some((*uri).to_string());
                    }
                }
            }
        }
    }
    None
}

/// Build a DER-encoded OCSP request for `leaf_der` against `issuer_der` carrying
/// a SHA-256 CertID and the request `nonce` as the RFC 6960 §4.4.1 Nonce
/// extension. Pure (no network).
fn build_ocsp_request_der_with_nonce(
    leaf_der: &[u8],
    issuer_der: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, OcspError> {
    let cert_id = build_cert_id(leaf_der, issuer_der)?;
    let nonce_ext =
        Nonce::new(nonce.to_vec()).map_err(|e| OcspError::BuildRequest(format!("nonce: {e}")))?;
    let ocsp_request = OcspRequestBuilder::default()
        .with_request(Request::new(cert_id))
        .with_extension(nonce_ext)
        .map_err(|e| OcspError::BuildRequest(format!("nonce extension: {e}")))?
        .build();
    ocsp_request
        .to_der()
        .map_err(|e| OcspError::BuildRequest(format!("DER encode: {e}")))
}

/// Build the SHA-256 `CertID` for `leaf_der` under `issuer_der`, decoding both
/// certificates. The same CertID is sent in the request AND recomputed after the
/// response arrives to bind the acted-on `SingleResponse` to our query.
fn build_cert_id(leaf_der: &[u8], issuer_der: &[u8]) -> Result<CertId, OcspError> {
    let leaf = Certificate::from_der(leaf_der)
        .map_err(|e| OcspError::BadCertificate(format!("leaf: {e}")))?;
    let issuer = Certificate::from_der(issuer_der)
        .map_err(|e| OcspError::BadCertificate(format!("issuer: {e}")))?;
    build_sha256_cert_id(&issuer, &leaf)
}

/// Draw a fresh `OCSP_NONCE_LEN`-byte nonce from the OS CSPRNG (`getrandom`).
/// Fails closed (the caller turns the error into a rejected connection) if the
/// platform RNG is unavailable rather than sending a predictable nonce.
fn random_nonce() -> Result<Vec<u8>, OcspError> {
    let mut bytes = vec![0u8; OCSP_NONCE_LEN];
    getrandom::fill(&mut bytes)
        .map_err(|e| OcspError::BuildRequest(format!("nonce CSPRNG: {e}")))?;
    Ok(bytes)
}

/// Build the SHA-256 `CertID` (RFC 6960 §4.1.1) for `cert` under `issuer`:
///
///   * `hashAlgorithm` = `id-sha256`;
///   * `issuerNameHash` = SHA-256 of the issuer's DER-encoded subject DN;
///   * `issuerKeyHash` = SHA-256 of the issuer's `subjectPublicKey` raw bits
///     (the BIT STRING value, excluding tag/length/unused-bits);
///   * `serialNumber` = the leaf's serial number.
///
/// Built by hand (rather than `CertId::from_cert::<Sha256>`) so the build does
/// not require `sha2::Sha256: AssociatedOid`, which is gated behind a `sha2`
/// crate feature not enabled in this build's dependency set.
fn build_sha256_cert_id(issuer: &Certificate, cert: &Certificate) -> Result<CertId, OcspError> {
    let issuer_subject_der = issuer
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|e| OcspError::BuildRequest(format!("issuer subject DER: {e}")))?;
    let issuer_name_hash = Sha256::digest(&issuer_subject_der);
    let issuer_key_hash = Sha256::digest(
        issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    );
    Ok(CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: OID_SHA256,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(issuer_name_hash.as_slice())
            .map_err(|e| OcspError::BuildRequest(format!("issuer name hash: {e}")))?,
        issuer_key_hash: OctetString::new(issuer_key_hash.as_slice())
            .map_err(|e| OcspError::BuildRequest(format!("issuer key hash: {e}")))?,
        serial_number: cert.tbs_certificate.serial_number.clone(),
    })
}

/// Map an OCSP `CertStatus` CHOICE to a [`CertRevocationStatus`]. Pure and
/// unit-tested. `good` → `Good`, `revoked` → `Revoked`, `unknown` → `Unknown`.
fn map_cert_status(status: &CertStatus) -> CertRevocationStatus {
    match status {
        CertStatus::Good(_) => CertRevocationStatus::Good,
        CertStatus::Revoked(_) => CertRevocationStatus::Revoked,
        CertStatus::Unknown(_) => CertRevocationStatus::Unknown,
    }
}

/// The RFC 6960 §3.2 response-trust pipeline. Decode `response_der`, require a
/// `Successful` status, parse the `BasicOCSPResponse`, then — BEFORE trusting any
/// status — verify in order: (1) the responder signature over
/// `tbs_response_data` against the issuer or a delegated `id-kp-OCSPSigning`
/// responder cert; (2) the `responder_id` matches that signer; (3) the request
/// `nonce` echoes (when present); (4) a `SingleResponse` binds to
/// `expected_cert_id`; (5) that response is fresh at `now`. Only then is its
/// `cert_status` mapped. ANY failure is an `Err`, which the caller treats as
/// fail-closed (deny). Pure (no network), unit-tested.
fn verify_and_map_response(
    response_der: &[u8],
    issuer_der: &[u8],
    expected_cert_id: &CertId,
    request_nonce: &[u8],
    now: SystemTime,
) -> Result<TrustedRevocationAnswer, OcspError> {
    let response = OcspResponse::from_der(response_der)
        .map_err(|e| OcspError::DecodeResponse(e.to_string()))?;
    if response.response_status != OcspResponseStatus::Successful {
        return Err(OcspError::ResponderStatus(response.response_status));
    }
    let response_bytes = response
        .response_bytes
        .ok_or_else(|| OcspError::MalformedResponse("successful response with no bytes".into()))?;
    let basic = BasicOcspResponse::from_der(response_bytes.response.as_bytes())
        .map_err(|e| OcspError::MalformedResponse(format!("not a BasicOCSPResponse: {e}")))?;

    // (1) responder signature + (2) responder identity, against the issuer or a
    // delegated responder cert. Returns the cert whose key verified the response
    // so the identity check can be made against the SAME key.
    let signer = verify_responder_signature(&basic, issuer_der, now)?;
    if !responder_id_matches(&basic.tbs_response_data.responder_id, &signer) {
        return Err(OcspError::ResponderIdentityMismatch(
            "responder_id does not match the signing certificate".into(),
        ));
    }

    // (3) nonce: if the responder echoed a nonce it MUST equal ours. (A responder
    // that omits the nonce entirely is permitted by RFC 6960 — many do not honor
    // nonces — but a PRESENT, MISMATCHED nonce is a replay/substitution.)
    if !nonce_ok(&basic, request_nonce) {
        return Err(OcspError::NonceMismatch);
    }

    // (4) CertID binding: select the one SingleResponse that answers OUR cert.
    let single = select_matching_single_response(&basic, expected_cert_id)
        .ok_or(OcspError::CertIdMismatch)?;

    // (5) freshness of the selected response, which also yields the end of its window.
    let Some(valid_until) =
        acceptance_bound(single, now, OCSP_FRESHNESS_SKEW, OCSP_MAX_RESPONSE_AGE)
    else {
        return Err(OcspError::NotFresh(
            "response not fresh: now outside [thisUpdate - skew, upper + skew], \
             where upper = min(nextUpdate, thisUpdate + max_response_age)"
                .into(),
        ));
    };

    // The ONLY construction of a `TrustedRevocationAnswer` in the crate, and it is here,
    // after all five checks. Everything above this line is what possession of the returned
    // value means.
    Ok(TrustedRevocationAnswer {
        status: map_cert_status(&single.cert_status),
        valid_until,
    })
}

/// Whether `issuer_der` issued `leaf_der`: the leaf names it as issuer AND its signature
/// verifies under the issuer's key. A parse failure is `BadCertificate`.
fn leaf_is_issued_by(leaf_der: &[u8], issuer_der: &[u8]) -> Result<bool, OcspError> {
    let (_, leaf) = X509Certificate::from_der(leaf_der)
        .map_err(|e| OcspError::BadCertificate(format!("leaf: {e}")))?;
    let (_, issuer) = X509Certificate::from_der(issuer_der)
        .map_err(|e| OcspError::BadCertificate(format!("issuer: {e}")))?;
    Ok(leaf.issuer() == issuer.subject() && cert_is_signed_by(&leaf, &issuer)?)
}

/// Verify the `BasicOcspResponse` signature over its `tbs_response_data` and
/// return the certificate whose public key verified it. The signer is EITHER the
/// issuer (direct) OR a delegated responder cert carried in `basic.certs` that is
/// itself signed by the issuer and carries the `id-kp-OCSPSigning` EKU. Fails
/// closed (`SignatureNotVerified`) when no candidate verifies.
///
/// The signer cert is returned as its DER bytes so the caller can run the
/// responder-identity check against the SAME key/name that verified the
/// signature.
///
/// The cryptographic verify (`x509-parser/verify`, enabled unconditionally at the
/// workspace level) is compiled into the `online_ocsp` module itself, so the
/// shipping `online_ocsp` + `--client-ocsp require` build performs this check for
/// real. When no candidate key verifies, this returns `SignatureNotVerified`, so a
/// `Good` status can NEVER be admitted on an unverified signature.
fn verify_responder_signature(
    basic: &BasicOcspResponse,
    issuer_der: &[u8],
    now: SystemTime,
) -> Result<Vec<u8>, OcspError> {
    // The exact bytes the responder signed: DER of tbs_response_data.
    let tbs_der = basic
        .tbs_response_data
        .to_der()
        .map_err(|e| OcspError::SignatureNotVerified(format!("re-encode tbs: {e}")))?;
    let sig_alg_der = basic
        .signature_algorithm
        .to_der()
        .map_err(|e| OcspError::SignatureNotVerified(format!("re-encode sigalg: {e}")))?;
    // The signature BIT STRING value (no unused-bits prefix); signatures are
    // whole octets, so `unused_bits == 0`.
    let sig_bytes = basic.signature.raw_bytes();

    // Candidate 1: the issuer signed directly.
    if signature_verifies(issuer_der, &sig_alg_der, sig_bytes, &tbs_der)? {
        return Ok(issuer_der.to_vec());
    }

    // Candidate 2..n: a delegated responder cert in `basic.certs` that is itself
    // issuer-signed AND carries the id-kp-OCSPSigning EKU.
    if let Some(certs) = &basic.certs {
        for cert in certs {
            let cert_der = cert
                .to_der()
                .map_err(|e| OcspError::SignatureNotVerified(format!("responder cert DER: {e}")))?;
            if !delegated_responder_is_valid(&cert_der, issuer_der, now)? {
                continue;
            }
            if signature_verifies(&cert_der, &sig_alg_der, sig_bytes, &tbs_der)? {
                return Ok(cert_der);
            }
        }
    }

    Err(OcspError::SignatureNotVerified(
        "no issuer or delegated id-kp-OCSPSigning responder key verified the signature".into(),
    ))
}

/// Whether `cert_der` is a valid delegated OCSP responder for `issuer_der` at
/// `now` (RFC 6960 §4.2.2.2 / §4.2.2.2.1): within its own `notBefore`/`notAfter`
/// window, carrying the `id-kp-OCSPSigning` extended key usage and
/// `id-pkix-ocsp-nocheck`, not a CA, permitting `digitalSignature` when it states key
/// usage, and signed by the issuer. An extension that fails to parse refuses. Pure; the
/// cryptographic issuer-signature check is compiled with the `online_ocsp` module exactly
/// as the response-signature check is.
fn delegated_responder_is_valid(
    cert_der: &[u8],
    issuer_der: &[u8],
    now: SystemTime,
) -> Result<bool, OcspError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| OcspError::SignatureNotVerified(format!("delegated cert parse: {e}")))?;
    // RFC 6960 §4.2.2.2.1: the responder certificate MUST itself be valid at the
    // response time. Reject an expired or not-yet-valid delegated responder cert
    // (e.g. a rotated-out signer) — treating it as not-a-valid-responder so no
    // candidate key verifies, the caller fails closed (status → Unknown → deny),
    // and a possibly-revoked client is never admitted under a stale signer key.
    let Some(now_unix) = system_time_to_unix(now) else {
        return Ok(false);
    };
    let Ok(now_asn1) = ASN1Time::from_timestamp(now_unix.as_secs() as i64) else {
        return Ok(false);
    };
    if !cert.validity().is_valid_at(now_asn1) {
        return Ok(false);
    }
    // Must declare the id-kp-OCSPSigning EKU (x509-parser surfaces it both as the
    // dedicated `ocsp_signing` flag and in `other`; check both for robustness).
    let has_ocsp_eku = match cert.extended_key_usage() {
        Ok(Some(eku)) => {
            eku.value.ocsp_signing
                || eku
                    .value
                    .other
                    .iter()
                    .any(|oid| oid.to_id_string() == ID_KP_OCSP_SIGNING)
        }
        _ => false,
    };
    if !has_ocsp_eku || !responder_standing_is_established(&cert) {
        return Ok(false);
    }
    // Must be signed by the issuer.
    let (_, issuer) = X509Certificate::from_der(issuer_der)
        .map_err(|e| OcspError::SignatureNotVerified(format!("issuer parse: {e}")))?;
    cert_is_signed_by(&cert, &issuer)
}

/// Whether a delegated responder certificate's own standing is established: it carries
/// `id-pkix-ocsp-nocheck` (the only licence this module has to skip a revocation check of
/// it), is not a CA, and permits `digitalSignature` when it states key usage.
fn responder_standing_is_established(cert: &X509Certificate<'_>) -> bool {
    let nocheck = cert
        .extensions()
        .iter()
        .any(|ext| ext.oid.to_id_string() == ID_PKIX_OCSP_NOCHECK);
    let not_a_ca = cert
        .basic_constraints()
        .is_ok_and(|bc| !bc.is_some_and(|bc| bc.value.ca));
    let may_sign = cert
        .key_usage()
        .is_ok_and(|ku| ku.is_none_or(|ku| ku.value.digital_signature()));
    nocheck && not_a_ca && may_sign
}

/// Whether `child`'s signature verifies under `issuer`'s public key, via
/// `x509-parser`'s `ring`-backed verifier. Always compiled with the `online_ocsp`
/// module (the workspace enables `x509-parser/verify` unconditionally), so the
/// shipping `online_ocsp` build performs the real cryptographic check.
fn cert_is_signed_by(
    child: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> Result<bool, OcspError> {
    match child.verify_signature(Some(issuer.public_key())) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify a signature `sig_bits_der` (a DER BIT STRING) with algorithm
/// `sig_alg_der` (a DER AlgorithmIdentifier) over `signed_der` using the public
/// key of the certificate `signer_cert_der`. Algorithm-agnostic: RSA PKCS#1 v1.5
/// SHA-256/384/512 and ECDSA P-256/P-384, via `x509-parser`'s `ring`-backed
/// `verify_signature`.
///
/// Always compiled with the `online_ocsp` module (the workspace enables
/// `x509-parser/verify` unconditionally), so the shipping `online_ocsp` +
/// `--client-ocsp require` build performs the REAL RFC 6960 §3.2 signature
/// check. A non-verifying response yields `Ok(false)`, so the caller fails closed
/// (status → Unknown → deny): no `Good` is ever admitted on an unverified
/// signature.
fn signature_verifies(
    signer_cert_der: &[u8],
    sig_alg_der: &[u8],
    sig_bytes: &[u8],
    signed_der: &[u8],
) -> Result<bool, OcspError> {
    use x509_parser::prelude::FromDer as _;
    let (_, signer) = X509Certificate::from_der(signer_cert_der)
        .map_err(|e| OcspError::SignatureNotVerified(format!("signer cert parse: {e}")))?;
    let (_, sig_alg) = x509_parser::x509::AlgorithmIdentifier::from_der(sig_alg_der)
        .map_err(|e| OcspError::SignatureNotVerified(format!("signature algorithm parse: {e}")))?;
    // The signature value as an asn1-rs BIT STRING (whole octets → 0 unused bits).
    let sig_bits = asn1_rs::BitString::new(0, sig_bytes);
    match x509_parser::verify::verify_signature(
        signer.public_key(),
        &sig_alg,
        &sig_bits,
        signed_der,
    ) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Whether the response's `responder_id` identifies `signer_cert_der` — the cert
/// whose key verified the signature. `byName` must equal the signer's subject DN;
/// `byKey` must equal the SHA-1 hash of the signer's `subjectPublicKey` bits
/// (RFC 6960 §4.2.1 KeyHash). Pure.
fn responder_id_matches(responder_id: &ResponderId, signer_cert_der: &[u8]) -> bool {
    let Ok(signer) = Certificate::from_der(signer_cert_der) else {
        return false;
    };
    match responder_id {
        ResponderId::ByName(name) => {
            let (Ok(a), Ok(b)) = (name.to_der(), signer.tbs_certificate.subject.to_der()) else {
                return false;
            };
            a == b
        }
        ResponderId::ByKey(key_hash) => {
            // KeyHash is the SHA-1 hash of the responder public-key BIT STRING
            // value. Compute it from the signer's SPKI subjectPublicKey bits.
            let spk_bits = signer
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes();
            let digest = sha1_hash(spk_bits);
            key_hash.as_bytes() == digest.as_slice()
        }
    }
}

/// SHA-1 of `data`, used solely for the RFC 6960 ResponderID `byKey` KeyHash
/// comparison (the standard fixes KeyHash to SHA-1; this is an identity match,
/// not a security primitive). Implemented locally to avoid adding a `sha1` dep.
fn sha1_hash(data: &[u8]) -> [u8; 20] {
    // Minimal SHA-1 (FIPS 180-4). Used only for the byKey ResponderID match.
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let ml = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&ml.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Select the `SingleResponse` whose `CertID` binds to `expected` — the cert we
/// asked about. Compares the binding fields (hash-algorithm OID, issuer name
/// hash, issuer key hash, serial number) so a response answering a DIFFERENT cert
/// is never mistaken for evidence about ours. Returns `None` when none matches, and when
/// MORE THAN ONE does: two verdicts for one certificate would resolve to whichever came
/// first, so the caller fails closed instead. Pure.
fn select_matching_single_response<'a>(
    basic: &'a BasicOcspResponse,
    expected: &CertId,
) -> Option<&'a SingleResponse> {
    let mut matching = basic
        .tbs_response_data
        .responses
        .iter()
        .filter(|single| cert_ids_bind(&single.cert_id, expected));
    let only = matching.next()?;
    matching.next().is_none().then_some(only)
}

/// Whether two CertIDs identify the same certificate: same hash-algorithm OID and
/// identical issuer name hash, issuer key hash, and serial number.
fn cert_ids_bind(a: &CertId, b: &CertId) -> bool {
    a.hash_algorithm.oid == b.hash_algorithm.oid
        && a.issuer_name_hash.as_bytes() == b.issuer_name_hash.as_bytes()
        && a.issuer_key_hash.as_bytes() == b.issuer_key_hash.as_bytes()
        && a.serial_number == b.serial_number
}

/// The end of `single`'s acceptance window, as a `Duration` since the Unix epoch, when it is
/// fresh at `now` within `skew` — `None` otherwise. Fresh means `now >= thisUpdate - skew`
/// and `now <= upper + skew`, where `upper` is `nextUpdate` when present, capped at
/// `thisUpdate + max_age`; the returned bound is `upper + skew`. A response with no
/// `nextUpdate` therefore still has an absolute bound of `thisUpdate + max_age + skew`, so
/// a captured responder-signed response cannot be replayed indefinitely even when the
/// responder omits `nextUpdate` and ignores the nonce. Pure.
fn acceptance_bound(
    single: &SingleResponse,
    now: SystemTime,
    skew: Duration,
    max_age: Duration,
) -> Option<Duration> {
    let now_unix = system_time_to_unix(now)?;
    let this_update = single.this_update.0.to_unix_duration();
    if now_unix.saturating_add(skew) < this_update {
        return None;
    }
    let age_cap = this_update.saturating_add(max_age);
    let upper = match &single.next_update {
        Some(next_update) => next_update.0.to_unix_duration().min(age_cap),
        None => age_cap,
    };
    let bound = upper.saturating_add(skew);
    (now_unix <= bound).then_some(bound)
}

/// `now` as a `Duration` since the Unix epoch, or `None` if it predates the epoch
/// (which would make freshness comparisons meaningless — fail closed).
fn system_time_to_unix(now: SystemTime) -> Option<Duration> {
    now.duration_since(UNIX_EPOCH).ok()
}

/// Whether the response nonce is acceptable: either the responder echoed no nonce
/// (permitted — many responders do not honor nonces) OR it echoed exactly our
/// `request_nonce`. A present-but-different nonce is a replay/substitution. Pure.
fn nonce_ok(basic: &BasicOcspResponse, request_nonce: &[u8]) -> bool {
    match basic.nonce() {
        None => true,
        Some(echoed) => echoed.0.as_bytes() == request_nonce,
    }
}

#[cfg(test)]
mod tests {
    use super::delegated_responder_is_valid;
    use super::extract_ocsp_responder_url;
    use super::leaf_is_issued_by;
    use super::map_cert_status;
    use super::sha1_hash;
    use super::CertRevocationStatus;
    use super::NotEstablished;
    use super::OcspChecker;
    use super::RevocationEvidence;
    use super::TrustedRevocationAnswer;
    use crate::outbound_fetch::VettedDestination;

    use der::asn1::BitString;
    use der::Decode;
    use der::Encode;
    use rcgen::date_time_ymd;
    use rcgen::CertificateParams;
    use rcgen::CustomExtension;
    use rcgen::DnType;
    use rcgen::ExtendedKeyUsagePurpose;
    use rcgen::KeyPair;
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::Certificate;
    use x509_ocsp::builder::OcspRequestBuilder;
    use x509_ocsp::BasicOcspResponse;
    use x509_ocsp::CertStatus;
    use x509_ocsp::OcspGeneralizedTime;
    use x509_ocsp::OcspRequest;
    use x509_ocsp::OcspResponse;
    use x509_ocsp::OcspResponseStatus;
    use x509_ocsp::ResponderId;
    use x509_ocsp::ResponseData;
    use x509_ocsp::SingleResponse;
    use x509_ocsp::Version;

    /// Mint a self-signed CA-ish issuer certificate (its key/subject feed the
    /// CertID hash) and return `(issuer_der, issuer_key)`.
    fn mint_issuer() -> (Vec<u8>, KeyPair) {
        let key = KeyPair::generate().expect("issuer key");
        let mut params = CertificateParams::new(Vec::new()).expect("issuer params");
        params
            .distinguished_name
            .push(DnType::CommonName, "mcp-re-test-ca");
        let cert = params.self_signed(&key).expect("issuer self-signed");
        (cert.der().as_ref().to_vec(), key)
    }

    /// A `SystemTime` `secs` after the Unix epoch (test helper).
    fn at_unix(secs: u64) -> std::time::SystemTime {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)
    }

    /// Mint a CA issuer (`IsCa::Ca` + `KeyCertSign`) able to SIGN child certs, and
    /// return both the rcgen `Issuer` (for signing) and the CA cert's DER.
    fn mint_ca_issuer() -> (rcgen::Issuer<'static, KeyPair>, Vec<u8>) {
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(Vec::new()).expect("ca params");
        params
            .distinguished_name
            .push(DnType::CommonName, "mcp-re-test-ca");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let cert = params.self_signed(&key).expect("ca self-signed");
        let der = cert.der().as_ref().to_vec();
        (rcgen::Issuer::new(params, key), der)
    }

    /// What a delegated responder certificate carries, for the standing tests.
    #[derive(Clone)]
    struct ResponderShape {
        ocsp_signing_eku: bool,
        nocheck: bool,
        ca: bool,
        key_usages: Vec<rcgen::KeyUsagePurpose>,
    }

    impl ResponderShape {
        /// A well-formed delegated responder: EKU and nocheck, not a CA, no key usage stated.
        fn proper() -> Self {
            ResponderShape {
                ocsp_signing_eku: true,
                nocheck: true,
                ca: false,
                key_usages: Vec::new(),
            }
        }
    }

    /// Mint a delegated OCSP responder cert SIGNED BY `issuer` over its own key, shaped by
    /// `shape`, valid over `[nb_ymd, na_ymd)` (each a `(year, month, day)` triple).
    fn mint_responder_with(
        issuer: &rcgen::Issuer<'_, KeyPair>,
        responder_key: &KeyPair,
        shape: &ResponderShape,
        nb_ymd: (i32, u8, u8),
        na_ymd: (i32, u8, u8),
    ) -> Vec<u8> {
        let mut params =
            CertificateParams::new(vec!["ocsp-responder.example".to_string()]).expect("params");
        params
            .distinguished_name
            .push(DnType::CommonName, "ocsp-responder.example");
        params.not_before = date_time_ymd(nb_ymd.0, nb_ymd.1, nb_ymd.2);
        params.not_after = date_time_ymd(na_ymd.0, na_ymd.1, na_ymd.2);
        if shape.ocsp_signing_eku {
            params
                .extended_key_usages
                .push(ExtendedKeyUsagePurpose::OcspSigning);
        }
        if shape.nocheck {
            // id-pkix-ocsp-nocheck, value NULL.
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 5, 5, 7, 48, 1, 5],
                    vec![0x05, 0x00],
                ));
        }
        if shape.ca {
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        }
        params.key_usages = shape.key_usages.clone();
        let cert = params
            .signed_by(responder_key, issuer)
            .expect("responder signed by issuer");
        cert.der().as_ref().to_vec()
    }

    /// A well-formed delegated OCSP responder cert (see [`ResponderShape::proper`]).
    fn mint_delegated_responder(
        issuer: &rcgen::Issuer<'_, KeyPair>,
        nb_ymd: (i32, u8, u8),
        na_ymd: (i32, u8, u8),
    ) -> Vec<u8> {
        let key = KeyPair::generate().expect("responder key");
        mint_responder_with(issuer, &key, &ResponderShape::proper(), nb_ymd, na_ymd)
    }

    /// A leaf (carrying an AIA OCSP URL) SIGNED THROUGH `issuer`.
    fn mint_leaf_signed_by(issuer: &rcgen::Issuer<'_, KeyPair>) -> Vec<u8> {
        let key = KeyPair::generate().expect("leaf key");
        let mut params =
            CertificateParams::new(vec!["leaf.example".to_string()]).expect("leaf params");
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 5, 5, 7, 1, 1],
                build_aia_extension_der("http://ocsp.example.test/r"),
            ));
        params
            .signed_by(&key, issuer)
            .expect("leaf signed by issuer")
            .der()
            .as_ref()
            .to_vec()
    }

    /// RFC 6960 §4.2.2.2.1: a delegated responder cert OUTSIDE its validity window
    /// is rejected (fail closed — no candidate verifies → deny), while the same
    /// cert WITHIN its window and issuer-signed is accepted. Locks the M-95
    /// validity-window check.
    #[test]
    fn delegated_responder_validity_window_enforced() {
        let (issuer, issuer_der) = mint_ca_issuer();
        // Window: 2020-01-01 .. 2021-01-01.
        let responder_der = mint_delegated_responder(&issuer, (2020, 1, 1), (2021, 1, 1));

        // now inside window → valid responder (EKU + issuer signature + lifetime).
        assert!(
            delegated_responder_is_valid(&responder_der, &issuer_der, at_unix(1_593_561_600))
                .unwrap(),
            "in-window, issuer-signed, OCSP-EKU responder must be accepted" // 2020-07-01
        );

        // now AFTER notAfter → rejected (expired signer must not be trusted).
        assert!(
            !delegated_responder_is_valid(&responder_der, &issuer_der, at_unix(1_640_995_200))
                .unwrap(),
            "an EXPIRED delegated responder cert must be rejected (RFC 6960 §4.2.2.2.1)" // 2022-01-01
        );

        // now BEFORE notBefore → rejected (not-yet-valid signer).
        assert!(
            !delegated_responder_is_valid(&responder_der, &issuer_der, at_unix(1_546_300_800))
                .unwrap(),
            "a not-yet-valid delegated responder cert must be rejected" // 2019-01-01
        );
    }

    /// RFC 6960 §4.2.2.2.1: this module has no revocation source for a delegated responder,
    /// so a responder certificate without `id-pkix-ocsp-nocheck` has no established standing.
    #[test]
    fn delegated_responder_without_nocheck_is_refused() {
        let (issuer, issuer_der) = mint_ca_issuer();
        let key = KeyPair::generate().expect("responder key");
        let shape = ResponderShape {
            nocheck: false,
            ..ResponderShape::proper()
        };
        let responder = mint_responder_with(&issuer, &key, &shape, (2020, 1, 1), (2021, 1, 1));
        assert!(
            !delegated_responder_is_valid(&responder, &issuer_der, at_unix(1_593_561_600)).unwrap(),
            "an in-window, issuer-signed, OCSP-EKU responder lacking nocheck must be refused"
        );
    }

    /// A delegated responder that is itself a CA, or whose stated key usage does not permit
    /// `digitalSignature`, is not a signer of OCSP responses.
    #[test]
    fn delegated_responder_that_is_a_ca_or_lacks_digital_signature_is_refused() {
        let (issuer, issuer_der) = mint_ca_issuer();
        let key = KeyPair::generate().expect("responder key");
        let now = at_unix(1_593_561_600);
        for (label, shape) in [
            (
                "a CA",
                ResponderShape {
                    ca: true,
                    ..ResponderShape::proper()
                },
            ),
            (
                "key usage without digitalSignature",
                ResponderShape {
                    key_usages: vec![rcgen::KeyUsagePurpose::KeyEncipherment],
                    ..ResponderShape::proper()
                },
            ),
        ] {
            let responder = mint_responder_with(&issuer, &key, &shape, (2020, 1, 1), (2021, 1, 1));
            assert!(
                !delegated_responder_is_valid(&responder, &issuer_der, now).unwrap(),
                "a responder that is {label} must be refused"
            );
        }
        let signing = ResponderShape {
            key_usages: vec![rcgen::KeyUsagePurpose::DigitalSignature],
            ..ResponderShape::proper()
        };
        let responder = mint_responder_with(&issuer, &key, &signing, (2020, 1, 1), (2021, 1, 1));
        assert!(
            delegated_responder_is_valid(&responder, &issuer_der, now).unwrap(),
            "the positive control: digitalSignature key usage is admitted"
        );
    }

    /// Known-answer vectors for the hand-rolled FIPS 180-4 SHA-1 used by the
    /// ResponderID `byKey` match (the standard fixes KeyHash to SHA-1). Guards the
    /// local implementation against a regression that would make a legitimate
    /// byKey responder mismatch (fail closed).
    #[test]
    fn sha1_known_answer_vectors() {
        // FIPS 180-4 / RFC 3174 published test vectors.
        assert_eq!(
            sha1_hash(b""),
            hex20("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            "SHA-1 of empty input"
        );
        assert_eq!(
            sha1_hash(b"abc"),
            hex20("a9993e364706816aba3e25717850c26c9cd0d89d"),
            "SHA-1(\"abc\")"
        );
        assert_eq!(
            sha1_hash(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            hex20("84983e441c3bd26ebaae4aa1f95129e5e54670f1"),
            "SHA-1 of the 56-byte FIPS multi-block vector"
        );
    }

    /// Decode a 40-char hex string into the 20-byte SHA-1 digest array.
    fn hex20(s: &str) -> [u8; 20] {
        let bytes = s.as_bytes();
        let mut out = [0u8; 20];
        for (i, slot) in out.iter_mut().enumerate() {
            let hi = (bytes[i * 2] as char).to_digit(16).expect("hex hi") as u8;
            let lo = (bytes[i * 2 + 1] as char).to_digit(16).expect("hex lo") as u8;
            *slot = (hi << 4) | lo;
        }
        out
    }

    /// Mint a leaf certificate carrying an AIA OCSP responder URL via a custom
    /// extension (rcgen 0.14 supports raw custom extensions). The AIA value is a
    /// hand-built `AuthorityInfoAccessSyntax` with one `id-ad-ocsp` access
    /// description pointing at `ocsp_url`.
    fn mint_leaf_with_aia(ocsp_url: &str) -> Vec<u8> {
        let key = KeyPair::generate().expect("leaf key");
        let mut params =
            CertificateParams::new(vec!["leaf.example".to_string()]).expect("leaf params");
        params
            .distinguished_name
            .push(DnType::CommonName, "leaf.example");
        // AIA OID 1.3.6.1.5.5.7.1.1; value = SEQUENCE OF AccessDescription, each
        // SEQUENCE { accessMethod OID, accessLocation [6] IA5String(url) }.
        let aia_der = build_aia_extension_der(ocsp_url);
        let ext = CustomExtension::from_oid_content(&[1, 3, 6, 1, 5, 5, 7, 1, 1], aia_der);
        params.custom_extensions.push(ext);
        let cert = params.self_signed(&key).expect("leaf self-signed");
        cert.der().as_ref().to_vec()
    }

    /// Hand-encode an `AuthorityInfoAccessSyntax` containing a single
    /// `id-ad-ocsp` (1.3.6.1.5.5.7.48.1) access description whose location is the
    /// context-tag-6 IA5String form of `url`. Minimal DER, sufficient for
    /// x509-parser to recover the URL.
    fn build_aia_extension_der(url: &str) -> Vec<u8> {
        // accessMethod: OID 1.3.6.1.5.5.7.48.1 → DER bytes.
        let oid = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
        // accessLocation: [6] IA5String (context-specific primitive tag 6).
        let url_bytes = url.as_bytes();
        let mut location = vec![0x86u8, url_bytes.len() as u8];
        location.extend_from_slice(url_bytes);
        // AccessDescription ::= SEQUENCE { accessMethod, accessLocation }
        let mut access_desc_body = Vec::new();
        access_desc_body.extend_from_slice(&oid);
        access_desc_body.extend_from_slice(&location);
        let mut access_desc = vec![0x30u8, access_desc_body.len() as u8];
        access_desc.extend_from_slice(&access_desc_body);
        // AuthorityInfoAccessSyntax ::= SEQUENCE OF AccessDescription
        let mut aia = vec![0x30u8, access_desc.len() as u8];
        aia.extend_from_slice(&access_desc);
        aia
    }

    #[test]
    fn aia_url_extraction_reads_ocsp_responder() {
        let leaf = mint_leaf_with_aia("http://ocsp.example.test/responder");
        let url = extract_ocsp_responder_url(&leaf);
        assert_eq!(
            url.as_deref(),
            Some("http://ocsp.example.test/responder"),
            "the AIA id-ad-ocsp URI must be recovered from the leaf"
        );
    }

    #[test]
    fn aia_url_extraction_none_without_aia() {
        // A leaf with no AIA extension yields None → the caller maps to Unknown.
        let key = KeyPair::generate().expect("key");
        let params = CertificateParams::new(vec!["no-aia.example".to_string()]).expect("params");
        let cert = params.self_signed(&key).expect("self-signed");
        assert!(
            extract_ocsp_responder_url(cert.der().as_ref()).is_none(),
            "a leaf without AIA must yield no responder URL"
        );
    }

    #[test]
    fn aia_url_extraction_none_on_garbage() {
        assert!(
            extract_ocsp_responder_url(b"not a certificate").is_none(),
            "unparseable bytes must yield no responder URL"
        );
    }

    // ADR-MCPS-023 §A1 (v0.9, MCPS-58): an OCSP check that cannot run because the
    // leaf carries no responder URL (no AIA, no operator override) yields an
    // indeterminate result — `check` returns Unknown (fail closed), NEVER Good. A
    // revocation check that never happened must not be recorded as a successful /
    // "not revoked" check. The no-URL path returns before any network I/O, so this
    // is fully offline.
    #[test]
    fn check_without_responder_url_establishes_nothing_and_is_not_good() {
        let key = KeyPair::generate().expect("key");
        let params = CertificateParams::new(vec!["no-aia.example".to_string()]).expect("params");
        let leaf = params.self_signed(&key).expect("self-signed").der().clone();
        let checker = OcspChecker::new(None); // no override
        let evidence = checker
            .check(leaf.as_ref(), leaf.as_ref())
            .expect("the no-responder-URL path returns without network I/O");
        // NOT a responder verdict of `Unknown` — nothing was asked. Keeping the two apart
        // is the point: a check that could not run must not be recorded as a responder
        // saying anything, and it must never be `Good`.
        assert_eq!(
            evidence,
            RevocationEvidence::NotEstablished(NotEstablished::NoResponderConfigured),
        );
        assert!(
            !checker.allows(evidence, SystemTime::now()),
            "a check that could not run must deny"
        );
    }

    #[test]
    fn ocsp_request_der_round_trips() {
        let (issuer_der, _) = mint_issuer();
        // The leaf need not be issued by the issuer; CertID only hashes the
        // issuer subject/key and copies the leaf serial.
        let leaf = mint_leaf_with_aia("http://ocsp.example.test/r");
        let der = build_ocsp_request_der(&leaf, &issuer_der);
        let decoded = OcspRequest::from_der(&der).expect("request DER round-trips");
        assert_eq!(
            decoded.tbs_request.request_list.len(),
            1,
            "exactly one Request (one CertID) must be present"
        );
    }

    use super::acceptance_bound;
    use super::build_cert_id;
    use super::cert_ids_bind;
    use super::nonce_ok;
    use super::responder_id_matches;
    use super::select_matching_single_response;
    use super::verify_and_map_response;
    use super::OcspError;
    use super::OCSP_FRESHNESS_SKEW;
    use super::OCSP_MAX_RESPONSE_AGE;
    use std::time::Duration;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;
    use x509_cert::ext::AsExtension;
    use x509_cert::ext::Extension;
    use x509_ocsp::ext::Nonce;
    use x509_ocsp::CertId;

    /// Knobs for hand-building an OCSP response fixture, so each acceptance test
    /// can isolate exactly ONE broken control (wrong CertID, stale, bad nonce, …).
    struct ResponseFixture {
        status: CertStatus,
        /// `None` ⇒ use the CertID derived from `(issuer, leaf)` (the matching
        /// one); `Some(id)` ⇒ a deliberately different CertID (binding test).
        cert_id: Option<CertId>,
        this_update: OcspGeneralizedTime,
        next_update: Option<OcspGeneralizedTime>,
        /// `Some(bytes)` ⇒ echo this nonce in the response extensions.
        echo_nonce: Option<Vec<u8>>,
        /// The signature bits to place on the BasicOcspResponse. Empty ⇒ unsigned.
        signature: Vec<u8>,
    }

    /// A GeneralizedTime fixture for the given y/m/d at 00:00:00 UTC.
    fn gtime(y: u16, m: u8, d: u8) -> OcspGeneralizedTime {
        OcspGeneralizedTime::from(der::DateTime::new(y, m, d, 0, 0, 0).expect("datetime"))
    }

    /// SystemTime at the given y/m/d 00:00:00 UTC (for injected `now`).
    fn at(y: u16, m: u8, d: u8) -> SystemTime {
        let dt = der::DateTime::new(y, m, d, 0, 0, 0).expect("datetime");
        UNIX_EPOCH + dt.unix_duration()
    }

    /// Whether `single` is fresh at `now` — `acceptance_bound` answering at all.
    fn is_fresh(
        single: &SingleResponse,
        now: SystemTime,
        skew: Duration,
        max_age: Duration,
    ) -> bool {
        acceptance_bound(single, now, skew, max_age).is_some()
    }

    /// A DER OCSP request for `leaf_der` against `issuer_der` with a SHA-256 CertID and NO
    /// nonce, for the request-codec round-trip test; the checker's own path always carries one.
    fn build_ocsp_request_der(leaf_der: &[u8], issuer_der: &[u8]) -> Vec<u8> {
        let cert_id = build_cert_id(leaf_der, issuer_der).expect("cert id");
        OcspRequestBuilder::default()
            .with_request(x509_ocsp::Request::new(cert_id))
            .build()
            .to_der()
            .expect("DER encode")
    }

    /// Build a `(issuer_der, leaf_der, response_der)` triple. The response wraps a
    /// `BasicOcspResponse` built per `fixture`. The signature is whatever the
    /// fixture supplies (unsigned by default); the production trust path verifies
    /// it with the ring-backed verifier that ships in the `online_ocsp` build, so
    /// an unsigned/forged signature is rejected at the signature gate. Returns the
    /// requested-CertID too, for the binding check.
    fn build_fixture(fixture: ResponseFixture) -> (Vec<u8>, Vec<u8>, Vec<u8>, CertId) {
        let (issuer_der, _) = mint_issuer();
        let leaf = mint_leaf_with_aia("http://ocsp.example.test/r");
        let issuer = Certificate::from_der(&issuer_der).expect("issuer");
        let requested_cert_id = build_cert_id(&leaf, &issuer_der).expect("requested cert id");
        let response_cert_id = fixture.cert_id.unwrap_or_else(|| requested_cert_id.clone());

        let mut single = SingleResponse::new(response_cert_id, fixture.status, fixture.this_update);
        single.next_update = fixture.next_update;

        let response_extensions = fixture.echo_nonce.map(|bytes| {
            let nonce = Nonce::new(bytes).expect("nonce");
            let ext: Extension = nonce
                .to_extension(&issuer.tbs_certificate.subject, &[])
                .expect("nonce extension");
            vec![ext]
        });

        let tbs = ResponseData {
            version: Version::V1,
            responder_id: ResponderId::ByName(issuer.tbs_certificate.subject.clone()),
            produced_at: fixture.this_update,
            responses: vec![single],
            response_extensions,
        };
        let basic = BasicOcspResponse {
            tbs_response_data: tbs,
            signature_algorithm: AlgorithmIdentifierOwned {
                // ecdsa-with-SHA256; the bits below are what is actually verified.
                oid: "1.2.840.10045.4.3.2".parse().expect("oid"),
                parameters: None,
            },
            signature: BitString::from_bytes(&fixture.signature).expect("bitstring"),
            certs: None,
        };
        let response = OcspResponse::successful(basic).expect("successful response");
        (
            issuer_der,
            leaf,
            response.to_der().expect("response DER"),
            requested_cert_id,
        )
    }

    /// A fresh, matching-CertID, good, unsigned fixture (the baseline the
    /// acceptance tests perturb). Returns `(issuer, leaf, response, requested_id)`.
    fn good_unsigned_fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>, CertId) {
        build_fixture(ResponseFixture {
            status: CertStatus::good(),
            cert_id: None,
            this_update: gtime(2024, 1, 1),
            next_update: Some(gtime(2024, 1, 2)),
            echo_nonce: None,
            signature: Vec::new(),
        })
    }

    // === #4063 (MCPS-088) acceptance tests — RFC 6960 §3.2 response trust =====
    //
    // Each asserts that a response which would, under the OLD code, ADMIT a leaf
    // (it returned the raw `cert_status`) is now DENIED because one trust control
    // rejects it. The `online_ocsp` build compiles the real ring-backed verifier,
    // so an unsigned signature is rejected at the signature gate — NOTHING admits
    // without a verified signature. The `mod verify` tests below re-prove the
    // per-control gates END-TO-END with a genuinely signed (Ed25519) response.

    /// ACCEPTANCE 1 — forged/unsigned responder returns Good for a leaf, but the
    /// signature is not verifiable ⇒ DENIED. This is the empty-signature fixture
    /// that the OLD code trusted; it must now fail closed.
    #[test]
    fn acceptance_unsigned_good_is_denied() {
        let (issuer, _leaf, response, requested_id) = good_unsigned_fixture();
        let nonce = b"unused-request-nonce".to_vec();
        let result =
            verify_and_map_response(&response, &issuer, &requested_id, &nonce, at(2024, 1, 1));
        assert!(
            matches!(result, Err(OcspError::SignatureNotVerified(_))),
            "an unsigned/forged Good must be rejected at the signature gate, got {result:?}"
        );
    }

    /// ACCEPTANCE 2 — CertID binding. A response whose SingleResponse answers a
    /// DIFFERENT CertID carries no evidence about our leaf. Even setting aside the
    /// signature gate, `select_matching_single_response` must not match it.
    #[test]
    fn acceptance_wrong_certid_is_denied() {
        // A mismatching CertID (different serial via a different leaf).
        let other_leaf = mint_leaf_with_aia("http://ocsp.example.test/other");
        let (issuer_der, _) = mint_issuer();
        let wrong_id = build_cert_id(&other_leaf, &issuer_der).expect("wrong id");
        let (issuer, _leaf, response, requested_id) = build_fixture(ResponseFixture {
            status: CertStatus::good(),
            cert_id: Some(wrong_id.clone()),
            this_update: gtime(2024, 1, 1),
            next_update: Some(gtime(2024, 1, 2)),
            echo_nonce: None,
            signature: Vec::new(),
        });
        // The requested id must NOT equal the response's wrong id.
        assert!(!cert_ids_bind(&requested_id, &wrong_id));
        // End-to-end: denied (at the signature gate; the binding gate is also
        // asserted directly below so that control is proven independently).
        let nonce = b"n".to_vec();
        assert!(
            verify_and_map_response(&response, &issuer, &requested_id, &nonce, at(2024, 1, 1))
                .is_err()
        );
    }

    /// ACCEPTANCE 3 — freshness. A signed-Good response whose `nextUpdate` is in
    /// the past is stale ⇒ DENIED. Proven directly on `is_fresh` (no crypto).
    #[test]
    fn acceptance_stale_response_is_denied() {
        let (issuer, _leaf, response, requested_id) = build_fixture(ResponseFixture {
            status: CertStatus::good(),
            cert_id: None,
            this_update: gtime(2023, 1, 1),
            next_update: Some(gtime(2023, 1, 2)),
            echo_nonce: None,
            signature: Vec::new(),
        });
        // `now` is well past nextUpdate → not fresh.
        let now = at(2024, 6, 1);
        let nonce = b"n".to_vec();
        assert!(
            verify_and_map_response(&response, &issuer, &requested_id, &nonce, now).is_err(),
            "a stale response must be denied"
        );
    }

    /// ACCEPTANCE 4 — nonce. A captured response echoing nonce A, replayed against
    /// a FRESH request nonce B, must be rejected (`nonce_ok` returns false).
    #[test]
    fn acceptance_nonce_mismatch_is_denied() {
        let captured_nonce = b"captured-nonce-AAAA".to_vec();
        let (issuer, _leaf, response, requested_id) = build_fixture(ResponseFixture {
            status: CertStatus::good(),
            cert_id: None,
            this_update: gtime(2024, 1, 1),
            next_update: Some(gtime(2024, 1, 2)),
            echo_nonce: Some(captured_nonce.clone()),
            signature: Vec::new(),
        });
        // Fresh request nonce differs from the echoed one.
        let fresh_nonce = b"fresh-request-nonce-B".to_vec();
        assert_ne!(captured_nonce, fresh_nonce);
        assert!(
            verify_and_map_response(
                &response,
                &issuer,
                &requested_id,
                &fresh_nonce,
                at(2024, 1, 1)
            )
            .is_err(),
            "a response echoing a stale nonce under a fresh request must be denied"
        );
    }

    /// ACCEPTANCE 5 (status-policy negatives) — Revoked and Unknown both DENY
    /// The positive (signed Good → ADMIT) is the `mod verify`
    /// test below (it needs a real responder signature).
    #[test]
    fn acceptance_revoked_and_unknown_deny() {
        // Pure policy: neither Revoked nor Unknown admits, however fresh.
        let checker = OcspChecker::new(None);
        for status in [CertRevocationStatus::Revoked, CertRevocationStatus::Unknown] {
            let answer = TrustedRevocationAnswer::answered(status, FAR_FUTURE);
            assert!(!checker.allows(RevocationEvidence::Answered(answer), at(2024, 1, 1)));
        }
        // An UNSIGNED Revoked/Unknown response is refused at the signature gate,
        // before any status is mapped. Assert that exact outcome: a bare
        // "did not admit" would also be satisfied by an unrelated failure.
        for (label, status) in [
            (
                "revoked",
                CertStatus::revoked(x509_ocsp::RevokedInfo {
                    revocation_time: gtime(2023, 6, 1),
                    revocation_reason: None,
                }),
            ),
            ("unknown", CertStatus::unknown()),
        ] {
            let (issuer, _leaf, response, requested_id) = build_fixture(ResponseFixture {
                status,
                cert_id: None,
                this_update: gtime(2024, 1, 1),
                next_update: Some(gtime(2024, 1, 2)),
                echo_nonce: None,
                signature: Vec::new(),
            });
            let mapped =
                verify_and_map_response(&response, &issuer, &requested_id, b"n", at(2024, 1, 1));
            assert!(
                matches!(mapped, Err(OcspError::SignatureNotVerified(_))),
                "an unsigned {label} response must be refused at the signature gate, \
                 got {mapped:?}"
            );
        }
    }

    // --- Direct unit tests of the individual trust controls (no crypto) -------

    #[test]
    fn certid_binding_matches_only_same_cert() {
        let (issuer_der, _) = mint_issuer();
        let leaf_a = mint_leaf_with_aia("http://a/r");
        let leaf_b = mint_leaf_with_aia("http://b/r");
        let id_a = build_cert_id(&leaf_a, &issuer_der).expect("id a");
        let id_a2 = build_cert_id(&leaf_a, &issuer_der).expect("id a2");
        let id_b = build_cert_id(&leaf_b, &issuer_der).expect("id b");
        assert!(cert_ids_bind(&id_a, &id_a2), "same cert binds");
        assert!(
            !cert_ids_bind(&id_a, &id_b),
            "different serial does not bind"
        );
    }

    #[test]
    fn select_matching_single_response_requires_binding() {
        let other_leaf = mint_leaf_with_aia("http://other/r");
        let (issuer_der, _) = mint_issuer();
        let wrong_id = build_cert_id(&other_leaf, &issuer_der).expect("wrong id");
        let (_i, _l, response, requested_id) = build_fixture(ResponseFixture {
            status: CertStatus::good(),
            cert_id: Some(wrong_id),
            this_update: gtime(2024, 1, 1),
            next_update: Some(gtime(2024, 1, 2)),
            echo_nonce: None,
            signature: Vec::new(),
        });
        let basic = decode_basic(&response);
        assert!(
            select_matching_single_response(&basic, &requested_id).is_none(),
            "a SingleResponse for a different CertID must not be selected"
        );
    }

    #[test]
    fn freshness_window_enforced() {
        // thisUpdate=Jan1, nextUpdate=Jan2; with skew=5m the valid window is
        // ~[Jan1-5m, Jan2+5m].
        let (_i, _l, response, _id) = build_fixture(ResponseFixture {
            status: CertStatus::good(),
            cert_id: None,
            this_update: gtime(2024, 1, 1),
            next_update: Some(gtime(2024, 1, 2)),
            echo_nonce: None,
            signature: Vec::new(),
        });
        let basic = decode_basic(&response);
        let single = &basic.tbs_response_data.responses[0];
        assert!(
            is_fresh(
                single,
                at(2024, 1, 1),
                OCSP_FRESHNESS_SKEW,
                OCSP_MAX_RESPONSE_AGE
            ),
            "within window"
        );
        assert!(
            !is_fresh(
                single,
                at(2023, 12, 31),
                OCSP_FRESHNESS_SKEW,
                OCSP_MAX_RESPONSE_AGE
            ),
            "before thisUpdate (beyond skew) is not fresh"
        );
        assert!(
            !is_fresh(
                single,
                at(2024, 6, 1),
                OCSP_FRESHNESS_SKEW,
                OCSP_MAX_RESPONSE_AGE
            ),
            "after nextUpdate (beyond skew) is not fresh"
        );
    }

    #[test]
    fn freshness_skew_tolerated() {
        let (_i, _l, response, _id) = build_fixture(ResponseFixture {
            status: CertStatus::good(),
            cert_id: None,
            this_update: gtime(2024, 1, 1),
            next_update: Some(gtime(2024, 1, 1)),
            echo_nonce: None,
            signature: Vec::new(),
        });
        let basic = decode_basic(&response);
        let single = &basic.tbs_response_data.responses[0];
        // 2 minutes before thisUpdate is within the 5-minute skew.
        let just_before = at(2024, 1, 1) - Duration::from_secs(120);
        assert!(is_fresh(
            single,
            just_before,
            OCSP_FRESHNESS_SKEW,
            OCSP_MAX_RESPONSE_AGE
        ));
    }

    #[test]
    fn freshness_capped_when_no_next_update() {
        // A responder-signed `good` with thisUpdate=Jan1 and NO nextUpdate (RFC
        // 6960 permits omission). Without an absolute cap, this could be replayed
        // indefinitely; with the max-age cap it must be rejected once it is older
        // than thisUpdate + OCSP_MAX_RESPONSE_AGE (+ skew).
        let (_i, _l, response, _id) = build_fixture(ResponseFixture {
            status: CertStatus::good(),
            cert_id: None,
            this_update: gtime(2024, 1, 1),
            next_update: None,
            echo_nonce: None,
            signature: Vec::new(),
        });
        let basic = decode_basic(&response);
        let single = &basic.tbs_response_data.responses[0];

        // Just after thisUpdate: still within the cap, so fresh.
        assert!(
            is_fresh(
                single,
                at(2024, 1, 1),
                OCSP_FRESHNESS_SKEW,
                OCSP_MAX_RESPONSE_AGE
            ),
            "no-nextUpdate response at thisUpdate is fresh"
        );

        // Within the cap (12h after thisUpdate, cap is 24h): still fresh.
        let within = at(2024, 1, 1) + Duration::from_secs(12 * 3600);
        assert!(
            is_fresh(single, within, OCSP_FRESHNESS_SKEW, OCSP_MAX_RESPONSE_AGE),
            "no-nextUpdate response within max-age cap is fresh"
        );

        // Beyond thisUpdate + max_age + skew: must be rejected. This is the
        // regression — before the cap, a no-nextUpdate response was accepted here.
        let replayed =
            at(2024, 1, 1) + OCSP_MAX_RESPONSE_AGE + OCSP_FRESHNESS_SKEW + Duration::from_secs(60);
        assert!(
            !is_fresh(single, replayed, OCSP_FRESHNESS_SKEW, OCSP_MAX_RESPONSE_AGE),
            "no-nextUpdate response older than the max-age cap must be rejected (anti-replay)"
        );
    }

    #[test]
    fn nonce_match_required_when_present() {
        let req = b"the-request-nonce".to_vec();
        let (_i, _l, matching, _id) = build_fixture(ResponseFixture {
            status: CertStatus::good(),
            cert_id: None,
            this_update: gtime(2024, 1, 1),
            next_update: None,
            echo_nonce: Some(req.clone()),
            signature: Vec::new(),
        });
        let (_i2, _l2, mismatch, _id2) = build_fixture(ResponseFixture {
            status: CertStatus::good(),
            cert_id: None,
            this_update: gtime(2024, 1, 1),
            next_update: None,
            echo_nonce: Some(b"a-different-nonce".to_vec()),
            signature: Vec::new(),
        });
        let (_i3, _l3, absent, _id3) = build_fixture(ResponseFixture {
            status: CertStatus::good(),
            cert_id: None,
            this_update: gtime(2024, 1, 1),
            next_update: None,
            echo_nonce: None,
            signature: Vec::new(),
        });
        assert!(
            nonce_ok(&decode_basic(&matching), &req),
            "echoed == request → ok"
        );
        assert!(
            !nonce_ok(&decode_basic(&mismatch), &req),
            "echoed != request → reject"
        );
        assert!(
            nonce_ok(&decode_basic(&absent), &req),
            "no echoed nonce is permitted (responder may not honor nonces)"
        );
    }

    #[test]
    fn responder_id_byname_matches_issuer() {
        let (issuer_der, _) = mint_issuer();
        let issuer = Certificate::from_der(&issuer_der).expect("issuer");
        let by_name = ResponderId::ByName(issuer.tbs_certificate.subject.clone());
        assert!(responder_id_matches(&by_name, &issuer_der));
        // A cert with a DIFFERENT subject DN must not match.
        let other_key = KeyPair::generate().expect("other key");
        let mut other_params = CertificateParams::new(Vec::new()).expect("other params");
        other_params
            .distinguished_name
            .push(DnType::CommonName, "some-other-ca");
        let other = other_params
            .self_signed(&other_key)
            .expect("other self-signed");
        assert!(!responder_id_matches(&by_name, other.der().as_ref()));
    }

    /// Decode a response DER back to its BasicOcspResponse for white-box control
    /// tests. (Production code only reaches this via verify_and_map_response.)
    fn decode_basic(response_der: &[u8]) -> BasicOcspResponse {
        let response = OcspResponse::from_der(response_der).expect("response");
        let bytes = response.response_bytes.expect("bytes");
        BasicOcspResponse::from_der(bytes.response.as_bytes()).expect("basic")
    }

    #[test]
    fn rejects_non_successful_responder_status() {
        let try_later = OcspResponse::try_later().to_der().expect("try_later DER");
        let (issuer_der, _) = mint_issuer();
        let id = build_cert_id(&mint_leaf_with_aia("http://x/r"), &issuer_der).expect("id");
        assert!(
            verify_and_map_response(&try_later, &issuer_der, &id, b"n", at(2024, 1, 1)).is_err(),
            "a non-successful OCSP responder status must fail closed"
        );
    }

    #[test]
    fn nonce_round_trips_in_request() {
        // The live path builds a request WITH a nonce extension; assert it is
        // present and recoverable (so the responder can echo it).
        let leaf = mint_leaf_with_aia("http://x/r");
        let (issuer_der, _) = mint_issuer();
        let nonce = b"sixteen-byte-non".to_vec();
        let der =
            super::build_ocsp_request_der_with_nonce(&leaf, &issuer_der, &nonce).expect("request");
        let decoded = OcspRequest::from_der(&der).expect("round-trips");
        let echoed = decoded.nonce().expect("nonce present");
        assert_eq!(echoed.0.as_bytes(), nonce.as_slice());
    }

    #[test]
    fn cert_status_helper_maps_choices() {
        assert_eq!(
            map_cert_status(&CertStatus::good()),
            CertRevocationStatus::Good
        );
        assert_eq!(
            map_cert_status(&CertStatus::revoked(x509_ocsp::RevokedInfo {
                revocation_time: gtime(2023, 6, 1),
                revocation_reason: None,
            })),
            CertRevocationStatus::Revoked,
            "a responder's revoked CHOICE must map to Revoked, the only value \
             nothing admits"
        );
        assert_eq!(
            map_cert_status(&CertStatus::unknown()),
            CertRevocationStatus::Unknown
        );
    }

    /// The end of an answer's window, far beyond any `now` the policy tests use.
    const FAR_FUTURE: Duration = Duration::from_secs(u64::MAX / 4);

    #[test]
    fn checker_allows_methods_match_policy() {
        let checker = OcspChecker::new(None);
        let now = at(2024, 1, 1);
        let answer = |status| {
            RevocationEvidence::Answered(TrustedRevocationAnswer::answered(status, FAR_FUTURE))
        };
        assert!(checker.allows(answer(CertRevocationStatus::Good), now));
        assert!(!checker.allows(answer(CertRevocationStatus::Revoked), now));
        assert!(!checker.allows(answer(CertRevocationStatus::Unknown), now));
        for reason in [
            NotEstablished::NoResponderConfigured,
            NotEstablished::DestinationRefused,
        ] {
            assert!(
                !checker.allows(RevocationEvidence::NotEstablished(reason), now),
                "{reason:?} establishes nothing and must deny"
            );
        }
    }

    /// Possession of an answer is not an admission token forever: the answer carries the
    /// end of the window it was accepted for, and `allows` refuses it past that.
    #[test]
    fn an_answer_past_its_own_freshness_bound_is_not_admitted() {
        let checker = OcspChecker::new(None);
        let bound = Duration::from_secs(1_700_000_000);
        let evidence = || {
            RevocationEvidence::Answered(TrustedRevocationAnswer::answered(
                CertRevocationStatus::Good,
                bound,
            ))
        };
        assert!(
            checker.allows(evidence(), UNIX_EPOCH + bound),
            "at the bound"
        );
        assert!(
            !checker.allows(evidence(), UNIX_EPOCH + bound + Duration::from_secs(1)),
            "one second past the bound"
        );
    }

    /// The bound `verify_and_map_response` stores is the one `acceptance_bound` computes,
    /// so an answer taken at T is refused once T's window has closed.
    #[test]
    fn a_verified_answer_is_admitted_only_inside_its_acceptance_window() {
        let (_i, _l, response, _id) = good_unsigned_fixture();
        let basic = decode_basic(&response);
        let single = &basic.tbs_response_data.responses[0];
        let bound = acceptance_bound(
            single,
            at(2024, 1, 1),
            OCSP_FRESHNESS_SKEW,
            OCSP_MAX_RESPONSE_AGE,
        )
        .expect("fresh at thisUpdate");
        assert_eq!(
            bound,
            at(2024, 1, 2).duration_since(UNIX_EPOCH).unwrap() + OCSP_FRESHNESS_SKEW,
            "nextUpdate plus skew"
        );
        assert_eq!(
            acceptance_bound(
                single,
                at(2024, 1, 2) + OCSP_FRESHNESS_SKEW + Duration::from_secs(1),
                OCSP_FRESHNESS_SKEW,
                OCSP_MAX_RESPONSE_AGE
            ),
            None
        );
    }

    /// A credential in the configured responder URL reaches no operational text: not the
    /// checker's `Debug` (which `ServerOptions` derives over), and not a transport error.
    #[test]
    fn a_credential_in_the_responder_url_reaches_no_operational_text() {
        const URL: &str = "http://user:s3cret@127.0.0.1:1/ocsp";
        let checker = OcspChecker::new(Some(URL.to_string()));
        let debug = format!("{checker:?}");
        assert!(!debug.contains("s3cret"), "{debug}");
        assert!(debug.contains("responder_override: true"), "{debug}");
        let destination = VettedDestination::operator_configured(URL).expect("loopback http");
        let error = checker
            .post_request(&destination, b"x")
            .expect_err("nothing listens on 127.0.0.1:1");
        let rendered = error.to_string();
        assert!(!rendered.contains("s3cret"), "{rendered}");
        assert!(!rendered.contains("127.0.0.1:1/ocsp"), "{rendered}");
    }

    /// The per-connection admit decision over the checker: only a verified `Good` admits, so a
    /// chain the checker cannot establish anything about is rejected, and no checker rejects
    /// nothing.
    #[test]
    fn the_connection_hook_rejects_what_the_checker_cannot_establish() {
        use crate::tls::ocsp_rejection_for_chain;
        use crate::tls::ServerOptions;
        let window = crate::config_state::ClientCredentialWindow::new(
            std::time::Duration::from_secs(3600),
            std::time::Duration::from_secs(300),
        )
        .expect("a legal credential window");
        let options = ServerOptions {
            ocsp_checker: Some(OcspChecker::new(None)),
            ..ServerOptions::new(window)
        };
        let request = b"{\"id\":1}";
        let leaf: &[u8] = b"leaf";
        assert!(
            ocsp_rejection_for_chain(&[leaf], &options, request).is_some(),
            "a leaf with no chained issuer is rejected"
        );
        // No override and no AIA URL on the leaf: nothing is asked, so nothing is admitted.
        let chain: [&[u8]; 2] = [b"leaf", b"issuer"];
        assert!(
            ocsp_rejection_for_chain(&chain, &options, request).is_some(),
            "a check that establishes nothing is rejected"
        );
        assert!(
            ocsp_rejection_for_chain(&chain, &ServerOptions::new(window), request).is_none(),
            "without a checker nothing is rejected"
        );
    }

    /// The checker only asks about a leaf the supplied issuer issued: the CertID, the
    /// signer candidate and the responder identity are all measured against that issuer.
    #[test]
    fn check_refuses_an_issuer_that_did_not_sign_the_leaf() {
        let leaf = mint_leaf_with_aia("http://127.0.0.1:1/ocsp");
        let (unrelated_issuer, _) = mint_issuer();
        let checker = OcspChecker::new(Some("http://127.0.0.1:1/ocsp".to_string()));
        let result = checker.check(&leaf, &unrelated_issuer);
        assert!(
            matches!(result, Err(OcspError::BadCertificate(_))),
            "an issuer that did not sign the leaf must be refused before any request: {result:?}"
        );
        // The relation itself: a leaf signed through a CA is issued by that CA and by no other.
        let (issuer, issuer_der) = mint_ca_issuer();
        let issued = mint_leaf_signed_by(&issuer);
        assert!(leaf_is_issued_by(&issued, &issuer_der).expect("parses"));
        assert!(!leaf_is_issued_by(&issued, &unrelated_issuer).expect("parses"));
    }

    // === #4078 (MCP-RE-MED-5, M14) — AIA responder-URL SSRF guard =============
    //
    // The AIA OCSP responder URL is taken VERBATIM from the attacker-influenced
    // leaf certificate and (pre-fix) fetched with no scheme/SSRF guard. A hostile
    // leaf can point the proxy at `file://`, `gopher://`, or an internal/link-local
    // host (169.254/16, 127/8, ::1, 10/8, 172.16/12, 192.168/16, metadata
    // endpoints) → SSRF. The guard must reject such a responder URL BEFORE any
    // network fetch, failing CLOSED (deny) exactly as a
    // missing AIA URL does. The operator-supplied `--ocsp-responder-url` override
    // is scheme-checked (http/https only) but, by design, NOT subject to the
    // private-IP block (an operator may legitimately run an internal responder).

    /// A disallowed scheme on the CERT-supplied AIA URL must be rejected before
    /// any fetch — `check()` short-circuits to `Ok(Unknown)` (fail-closed), never
    /// attempting the network. `file://` is the canonical SSRF/file-read vector.
    #[test]
    fn check_rejects_cert_aia_file_scheme_before_fetch() {
        // A leaf whose ONLY AIA OCSP URL is a file:// URL.
        let leaf = mint_leaf_with_aia("file:///etc/passwd");
        let (issuer_der, _) = mint_issuer();
        let checker = OcspChecker::new(None);
        // If the guard were absent the path would try to POST to `file:///...`
        // (ureq) and return Err(Http(..)); WITH the guard it short-circuits to
        // NotEstablished WITHOUT any fetch — the destination was refused, which is a
        // LOCAL fact and not something a responder said.
        let evidence = checker
            .check(leaf.as_slice(), &issuer_der)
            .expect("an unsafe-scheme AIA URL fails closed, not Err");
        assert_eq!(
            evidence,
            RevocationEvidence::NotEstablished(NotEstablished::DestinationRefused),
            "a file:// AIA responder URL must be refused pre-fetch"
        );
        assert!(
            !checker.allows(evidence, SystemTime::now()),
            "an unestablished result must deny"
        );
    }

    /// A loopback host on the CERT-supplied AIA URL is an SSRF vector and must be
    /// rejected pre-fetch as Unknown (fail closed). `http://127.0.0.1:1/` points
    /// at an unroutable port; were the guard absent the fetch would (slowly)
    /// connection-error as Err(Http), so an Ok(Unknown) proves no fetch occurred.
    #[test]
    fn check_rejects_cert_aia_loopback_host_before_fetch() {
        let leaf = mint_leaf_with_aia("http://127.0.0.1:1/ocsp");
        let (issuer_der, _) = mint_issuer();
        let checker = OcspChecker::new(None);
        let status = checker
            .check(leaf.as_slice(), &issuer_der)
            .expect("a loopback AIA URL fails closed, not Err");
        assert_eq!(
            status,
            RevocationEvidence::NotEstablished(NotEstablished::DestinationRefused)
        );
    }

    /// `localhost` (a hostname, not a literal IP) is the loopback name and must
    /// likewise be rejected on the cert-derived path.
    #[test]
    fn check_rejects_cert_aia_localhost_before_fetch() {
        let leaf = mint_leaf_with_aia("http://localhost:1/ocsp");
        let (issuer_der, _) = mint_issuer();
        let checker = OcspChecker::new(None);
        let status = checker
            .check(leaf.as_slice(), &issuer_der)
            .expect("a localhost AIA URL fails closed");
        assert_eq!(
            status,
            RevocationEvidence::NotEstablished(NotEstablished::DestinationRefused)
        );
    }

    /// Stage-2 audit regression: the responder-host SSRF guard only inspects the
    /// FIRST URL, so a guarded responder that replies `302 Location:
    /// http://<internal>/` must NOT be chased — `ureq` follows redirects by default,
    /// which would reach an address that never passed the guard. This drives the real
    /// fetch (`post_request`) against a local responder that 302s to a SENTINEL
    /// listener standing in for the internal target, and asserts the sentinel is
    /// never contacted.
    #[test]
    fn ocsp_post_does_not_follow_redirects() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread;

        // The "internal" target the redirect points at. Non-blocking so we can probe
        // for a connection without hanging the test.
        let sentinel = TcpListener::bind("127.0.0.1:0").expect("bind sentinel");
        let sentinel_addr = sentinel.local_addr().expect("sentinel addr");
        sentinel
            .set_nonblocking(true)
            .expect("sentinel nonblocking");

        // The guarded responder: accepts one connection, reads the OCSP POST, and
        // replies with a 302 redirect to the sentinel. `responder_hit` proves the
        // fetch actually reached the responder, so a clean sentinel cannot be a
        // false-pass from a failed first request.
        let responder = TcpListener::bind("127.0.0.1:0").expect("bind responder");
        let responder_addr = responder.local_addr().expect("responder addr");
        let responder_hit = Arc::new(AtomicBool::new(false));
        let redirect_to = format!("http://{sentinel_addr}/");
        let hit_flag = Arc::clone(&responder_hit);
        thread::spawn(move || {
            if let Ok((mut stream, _)) = responder.accept() {
                hit_flag.store(true, Ordering::SeqCst);
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {redirect_to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });

        let checker = OcspChecker::new(None);
        let url = format!("http://{responder_addr}/ocsp");
        // The result itself is irrelevant (a 302 carries no valid OCSP body); the
        // security property is that NO request reaches the sentinel.
        // OPERATOR-CONFIGURED, and that is the honest description: this responder is on
        // 127.0.0.1, which is exactly the address a certificate may not name and an
        // operator may. Saying so is also what removed the checker's test-only vetting
        // kill switch — with the provenance on the DESTINATION, a test that needs a
        // loopback responder states it at the destination instead of disabling a guard.
        //
        // Redirects are disabled for EVERY provenance, so this still exercises the
        // property under test.
        let destination = VettedDestination::operator_configured(url)
            .expect("an http loopback URL is a legal operator-configured destination");
        let _ = checker.post_request(&destination, b"dummy-ocsp-request");

        // Wait (bounded) for the responder thread to observe the connection so the test
        // can't false-pass due to a failed first request.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !responder_hit.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            responder_hit.load(Ordering::SeqCst),
            "the OCSP fetch never reached the responder — test would false-pass; check the harness"
        );
        match sentinel.accept() {
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Correct: redirects disabled, the internal target was never reached.
            }
            Ok(_) => panic!(
                "OCSP fetch FOLLOWED the 302 redirect to the internal sentinel — SSRF redirect bypass"
            ),
            Err(e) => panic!("unexpected sentinel accept error: {e}"),
        }
    }

    #[test]
    fn check_with_no_url_is_unknown() {
        // No override and a leaf without AIA → check() short-circuits to Unknown
        // (no network performed).
        let key = KeyPair::generate().expect("key");
        let params = CertificateParams::new(vec!["no-aia.example".to_string()]).expect("params");
        let leaf = params.self_signed(&key).expect("self-signed");
        let (issuer_der, _) = mint_issuer();
        let checker = OcspChecker::new(None);
        let status = checker
            .check(leaf.der().as_ref(), &issuer_der)
            .expect("the no-URL check returns without network I/O");
        assert_eq!(
            status,
            RevocationEvidence::NotEstablished(NotEstablished::NoResponderConfigured)
        );
    }

    #[test]
    fn ocsp_request_builder_default_is_empty() {
        // Sanity: an empty builder builds a request with no CertIDs (guards
        // against an accidental default CertID).
        let req = OcspRequestBuilder::default().build();
        let der = req.to_der().expect("der");
        let decoded = OcspRequest::from_der(&der).expect("round trip");
        assert!(decoded.tbs_request.request_list.is_empty());
        let _ = OcspResponseStatus::Successful;
    }

    // === #4063 (MCPS-088) — responder-SIGNATURE acceptance, run through the
    // SAME production verifier the `online_ocsp` build ships ===================
    //
    // These prove the cryptographic gate END-TO-END through the production
    // `verify_and_map_response`: a response SIGNED by the issuer's key with the
    // correct CertID/freshness/nonce is ADMITTED; a forged/wrong-key or empty
    // signature is DENIED. The verifier (x509-parser/ring) is part of the
    // `online_ocsp` module, so these tests exercise the production path, not a
    // parallel flavor. The in-tree, Bazel-addressable test signer is Ed25519
    // (ed25519-dalek); the verifier is algorithm-agnostic and ALSO covers RSA
    // PKCS#1 SHA-256/384/512 and ECDSA P-256/P-384 (exercised by the
    // openssl-responder `ocsp_e2e_test`).
    mod verify {
        use super::super::verify_and_map_response;
        use super::super::CertRevocationStatus;
        use super::super::OcspChecker;
        use super::super::OcspError;
        use super::super::RevocationEvidence;
        use super::at;
        use super::build_cert_id;
        use super::gtime;
        use super::mint_leaf_with_aia;
        use super::mint_responder_with;
        use super::ResponderShape;
        use der::asn1::BitString;
        use der::Decode;
        use der::Encode;
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        use ed25519_dalek::Signer;
        use ed25519_dalek::SigningKey;
        use rcgen::CertificateParams;
        use rcgen::DnType;
        use rcgen::KeyPair;
        use rcgen::PKCS_ED25519;
        use spki::AlgorithmIdentifierOwned;
        use x509_cert::ext::AsExtension;
        use x509_cert::Certificate;
        use x509_ocsp::ext::Nonce;
        use x509_ocsp::BasicOcspResponse;
        use x509_ocsp::CertStatus;
        use x509_ocsp::OcspResponse;
        use x509_ocsp::ResponderId;
        use x509_ocsp::ResponseData;
        use x509_ocsp::SingleResponse;
        use x509_ocsp::Version;

        fn ed25519_key(signer: &SigningKey) -> KeyPair {
            let pkcs8 = signer.to_pkcs8_der().expect("pkcs8");
            KeyPair::from_pkcs8_der_and_sign_algo(
                &rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec()),
                &PKCS_ED25519,
            )
            .expect("rcgen import")
        }

        /// Mint an Ed25519 issuer cert whose private key is `signer` (so the test
        /// can sign an OCSP response with the SAME key the issuer SPKI carries).
        /// Returns the issuer DER.
        fn mint_issuer_with_key(signer: &SigningKey) -> Vec<u8> {
            let key = ed25519_key(signer);
            let mut params = CertificateParams::new(Vec::new()).expect("params");
            params
                .distinguished_name
                .push(DnType::CommonName, "mcp-re-ed25519-ca");
            let cert = params.self_signed(&key).expect("issuer self-signed");
            cert.der().as_ref().to_vec()
        }

        /// What the response says beyond a single verdict, so each test isolates one gate.
        #[derive(Default)]
        struct Shape {
            /// `None` ⇒ the signing certificate's own subject (byName).
            responder_id: Option<ResponderId>,
            /// `Some(bytes)` ⇒ echo this nonce in the response extensions.
            echoed_nonce: Option<Vec<u8>>,
            /// Further verdicts for the SAME CertID, after the first.
            more_verdicts: Vec<CertStatus>,
            /// Certificates carried in `basic.certs` (a delegated responder).
            certs: Option<Vec<Certificate>>,
        }

        /// Build a response for `(issuer, leaf)` with `status`, then sign its
        /// `tbs_response_data` with `signer`. The `corrupt` flag flips a signature
        /// byte to model a forgery. `signer_subject_der` is the subject the response
        /// names as its responder unless `shape` names another. Returns the response DER
        /// and the requested CertID.
        fn signed_response_with(
            signer: &SigningKey,
            signer_cert_der: &[u8],
            issuer_der: &[u8],
            leaf_der: &[u8],
            status: CertStatus,
            corrupt: bool,
            shape: Shape,
        ) -> (Vec<u8>, x509_ocsp::CertId) {
            let issuer = Certificate::from_der(issuer_der).expect("issuer");
            let signer_cert = Certificate::from_der(signer_cert_der).expect("signer");
            let requested = build_cert_id(leaf_der, issuer_der).expect("cert id");
            let responses = std::iter::once(status)
                .chain(shape.more_verdicts)
                .map(|status| {
                    let mut single =
                        SingleResponse::new(requested.clone(), status, gtime(2024, 1, 1));
                    single.next_update = Some(gtime(2024, 1, 2));
                    single
                })
                .collect();
            let response_extensions = shape.echoed_nonce.map(|bytes| {
                let nonce = Nonce::new(bytes).expect("nonce");
                vec![nonce
                    .to_extension(&issuer.tbs_certificate.subject, &[])
                    .expect("nonce extension")]
            });
            let tbs = ResponseData {
                version: Version::V1,
                responder_id: shape.responder_id.unwrap_or_else(|| {
                    ResponderId::ByName(signer_cert.tbs_certificate.subject.clone())
                }),
                produced_at: gtime(2024, 1, 1),
                responses,
                response_extensions,
            };
            let tbs_der = tbs.to_der().expect("tbs der");
            let mut sig = signer.sign(&tbs_der).to_bytes().to_vec();
            if corrupt {
                sig[0] ^= 0xFF;
            }
            let basic = BasicOcspResponse {
                tbs_response_data: tbs,
                signature_algorithm: AlgorithmIdentifierOwned {
                    // id-Ed25519 (RFC 8410), the OID x509-parser maps to ED25519.
                    oid: "1.3.101.112".parse().expect("oid"),
                    parameters: None,
                },
                signature: BitString::from_bytes(&sig).expect("bitstring"),
                certs: shape.certs,
            };
            let response = OcspResponse::successful(basic).expect("successful");
            (response.to_der().expect("der"), requested)
        }

        /// As [`signed_response_with`], signed by the issuer key itself.
        fn signed_response(
            signer: &SigningKey,
            issuer_der: &[u8],
            leaf_der: &[u8],
            status: CertStatus,
            corrupt: bool,
        ) -> (Vec<u8>, x509_ocsp::CertId) {
            signed_response_with(
                signer,
                issuer_der,
                issuer_der,
                leaf_der,
                status,
                corrupt,
                Shape::default(),
            )
        }

        #[test]
        fn signed_good_is_admitted() {
            let signer = SigningKey::from_bytes(&[7u8; 32]);
            let issuer = mint_issuer_with_key(&signer);
            let leaf = mint_leaf_with_aia("http://ocsp.example.test/r");
            let (response, requested) =
                signed_response(&signer, &issuer, &leaf, CertStatus::good(), false);
            let answer = verify_and_map_response(
                &response,
                &issuer,
                &requested,
                b"req-nonce",
                at(2024, 1, 1),
            )
            .expect("a correctly-signed, fresh, bound Good must verify");
            assert_eq!(
                answer.status(),
                CertRevocationStatus::Good,
                "a verified Good admits the connection"
            );
            let checker = OcspChecker::new(None);
            let evidence = || RevocationEvidence::Answered(answer.clone());
            assert!(checker.allows(evidence(), at(2024, 1, 1)));
            assert!(
                !checker.allows(evidence(), at(2025, 1, 1)),
                "the same answer is not an admission token a year later"
            );
        }

        /// The end-to-end negative control for the `revoked` CHOICE: a response
        /// that clears every trust gate (real signature, matching responder id,
        /// bound CertID, fresh) and carries `revoked` must map to `Revoked` and
        /// be refused by the policy.
        #[test]
        fn signed_revoked_is_mapped_revoked_and_refused() {
            let signer = SigningKey::from_bytes(&[7u8; 32]);
            let issuer = mint_issuer_with_key(&signer);
            let leaf = mint_leaf_with_aia("http://ocsp.example.test/r");
            let revoked = CertStatus::revoked(x509_ocsp::RevokedInfo {
                revocation_time: gtime(2023, 6, 1),
                revocation_reason: None,
            });
            let (response, requested) = signed_response(&signer, &issuer, &leaf, revoked, false);
            let answer = verify_and_map_response(
                &response,
                &issuer,
                &requested,
                b"req-nonce",
                at(2024, 1, 1),
            )
            .expect("a correctly-signed, fresh, bound response must verify");
            assert_eq!(
                answer.status(),
                CertRevocationStatus::Revoked,
                "a verified revoked wire status must reach the policy as Revoked"
            );
            assert!(
                !OcspChecker::new(None)
                    .allows(RevocationEvidence::Answered(answer), at(2024, 1, 1)),
                "revoked denies"
            );
        }

        #[test]
        fn forged_signature_is_denied() {
            let signer = SigningKey::from_bytes(&[7u8; 32]);
            let issuer = mint_issuer_with_key(&signer);
            let leaf = mint_leaf_with_aia("http://ocsp.example.test/r");
            let (response, requested) =
                signed_response(&signer, &issuer, &leaf, CertStatus::good(), true);
            let result = verify_and_map_response(
                &response,
                &issuer,
                &requested,
                b"req-nonce",
                at(2024, 1, 1),
            );
            assert!(
                matches!(result, Err(OcspError::SignatureNotVerified(_))),
                "a forged signature must be rejected, got {result:?}"
            );
        }

        #[test]
        fn wrong_key_signature_is_denied() {
            // Signed by a DIFFERENT key than the issuer SPKI → no candidate
            // verifies → denied.
            let issuer_signer = SigningKey::from_bytes(&[7u8; 32]);
            let attacker_signer = SigningKey::from_bytes(&[9u8; 32]);
            let issuer = mint_issuer_with_key(&issuer_signer);
            let leaf = mint_leaf_with_aia("http://ocsp.example.test/r");
            let (response, requested) =
                signed_response(&attacker_signer, &issuer, &leaf, CertStatus::good(), false);
            let result = verify_and_map_response(
                &response,
                &issuer,
                &requested,
                b"req-nonce",
                at(2024, 1, 1),
            );
            assert!(
                matches!(result, Err(OcspError::SignatureNotVerified(_))),
                "a response signed by a non-issuer key must be rejected, got {result:?}"
            );
        }

        #[test]
        fn signed_good_for_wrong_certid_is_denied() {
            // Correctly SIGNED, but the SingleResponse answers a DIFFERENT cert.
            let signer = SigningKey::from_bytes(&[7u8; 32]);
            let issuer = mint_issuer_with_key(&signer);
            let leaf = mint_leaf_with_aia("http://ocsp.example.test/r");
            let other_leaf = mint_leaf_with_aia("http://ocsp.example.test/other");
            // Sign a response that BINDS to `other_leaf`, but we query for `leaf`.
            let (response, _other_id) =
                signed_response(&signer, &issuer, &other_leaf, CertStatus::good(), false);
            let requested_for_leaf = build_cert_id(&leaf, &issuer).expect("requested id");
            let result = verify_and_map_response(
                &response,
                &issuer,
                &requested_for_leaf,
                b"req-nonce",
                at(2024, 1, 1),
            );
            assert!(
                matches!(result, Err(OcspError::CertIdMismatch)),
                "a signed Good for a different CertID must be rejected, got {result:?}"
            );
        }

        /// Two verdicts for the requested certificate would resolve to whichever came first;
        /// a correctly signed, fresh response carrying `good` then `revoked` is refused.
        #[test]
        fn signed_response_answering_our_certid_twice_is_denied() {
            let signer = SigningKey::from_bytes(&[7u8; 32]);
            let issuer = mint_issuer_with_key(&signer);
            let leaf = mint_leaf_with_aia("http://ocsp.example.test/r");
            let revoked = CertStatus::revoked(x509_ocsp::RevokedInfo {
                revocation_time: gtime(2023, 6, 1),
                revocation_reason: None,
            });
            let (response, requested) = signed_response_with(
                &signer,
                &issuer,
                &issuer,
                &leaf,
                CertStatus::good(),
                false,
                Shape {
                    more_verdicts: vec![revoked],
                    ..Shape::default()
                },
            );
            let result = verify_and_map_response(
                &response,
                &issuer,
                &requested,
                b"req-nonce",
                at(2024, 1, 1),
            );
            assert!(
                matches!(result, Err(OcspError::CertIdMismatch)),
                "an ambiguous answer must fail closed, got {result:?}"
            );
        }

        /// The responder-identity gate in isolation: the response is signed by the issuer key,
        /// so the signature gate passes, but it names another responder.
        #[test]
        fn signed_good_with_a_foreign_responder_id_is_denied() {
            let signer = SigningKey::from_bytes(&[7u8; 32]);
            let issuer = mint_issuer_with_key(&signer);
            let leaf = mint_leaf_with_aia("http://ocsp.example.test/r");
            let (response, requested) = signed_response_with(
                &signer,
                &issuer,
                &issuer,
                &leaf,
                CertStatus::good(),
                false,
                Shape {
                    responder_id: Some(ResponderId::ByName(
                        "CN=some-other-responder".parse().expect("name"),
                    )),
                    ..Shape::default()
                },
            );
            let result = verify_and_map_response(
                &response,
                &issuer,
                &requested,
                b"req-nonce",
                at(2024, 1, 1),
            );
            assert!(
                matches!(result, Err(OcspError::ResponderIdentityMismatch(_))),
                "a response naming a responder it did not sign as must be denied, got {result:?}"
            );
        }

        /// The nonce gate in isolation: a correctly signed response echoing nonce A under a
        /// request that carried nonce B is a replay; the same response under A is admitted.
        #[test]
        fn signed_good_echoing_another_nonce_is_denied() {
            let signer = SigningKey::from_bytes(&[7u8; 32]);
            let issuer = mint_issuer_with_key(&signer);
            let leaf = mint_leaf_with_aia("http://ocsp.example.test/r");
            let respond = |echoed: &[u8]| {
                signed_response_with(
                    &signer,
                    &issuer,
                    &issuer,
                    &leaf,
                    CertStatus::good(),
                    false,
                    Shape {
                        echoed_nonce: Some(echoed.to_vec()),
                        ..Shape::default()
                    },
                )
            };
            let (response, requested) = respond(b"nonce-A-aaaaaaaa");
            let replayed = verify_and_map_response(
                &response,
                &issuer,
                &requested,
                b"nonce-B-bbbbbbbb",
                at(2024, 1, 1),
            );
            assert!(
                matches!(replayed, Err(OcspError::NonceMismatch)),
                "a response echoing another request's nonce must be denied, got {replayed:?}"
            );
            verify_and_map_response(
                &response,
                &issuer,
                &requested,
                b"nonce-A-aaaaaaaa",
                at(2024, 1, 1),
            )
            .expect("the positive control: the same response under its own nonce is admitted");
        }

        /// A CA, an Ed25519 delegated responder it signed, and the key that signs responses.
        fn delegated_responder(shape: &ResponderShape) -> (Vec<u8>, SigningKey, Vec<u8>) {
            let ca_signer = SigningKey::from_bytes(&[7u8; 32]);
            let ca_key = ed25519_key(&ca_signer);
            let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
            ca_params
                .distinguished_name
                .push(DnType::CommonName, "mcp-re-ed25519-ca");
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
            let ca_der = ca_params
                .self_signed(&ca_key)
                .expect("ca self-signed")
                .der()
                .as_ref()
                .to_vec();
            let issuer = rcgen::Issuer::new(ca_params, ca_key);
            let responder_signer = SigningKey::from_bytes(&[11u8; 32]);
            let responder_der = mint_responder_with(
                &issuer,
                &ed25519_key(&responder_signer),
                shape,
                (2023, 1, 1),
                (2025, 1, 1),
            );
            (ca_der, responder_signer, responder_der)
        }

        fn delegated_response(shape: &ResponderShape) -> Result<CertRevocationStatus, OcspError> {
            let (ca_der, responder_signer, responder_der) = delegated_responder(shape);
            let leaf = mint_leaf_with_aia("http://ocsp.example.test/r");
            let (response, requested) = signed_response_with(
                &responder_signer,
                &responder_der,
                &ca_der,
                &leaf,
                CertStatus::good(),
                false,
                Shape {
                    certs: Some(vec![
                        Certificate::from_der(&responder_der).expect("responder cert")
                    ]),
                    ..Shape::default()
                },
            );
            verify_and_map_response(&response, &ca_der, &requested, b"req-nonce", at(2024, 1, 1))
                .map(|answer| answer.status())
        }

        /// The delegated-responder ADMIT path end to end: the response is signed by a responder
        /// certificate the CA issued, which names it, carries the OCSP-signing EKU and nocheck.
        #[test]
        fn delegated_responder_signed_good_is_admitted() {
            assert_eq!(
                delegated_response(&ResponderShape::proper()).expect("a delegated Good verifies"),
                CertRevocationStatus::Good
            );
        }

        /// Each requirement on the delegated responder is load-bearing: dropping the EKU (the
        /// gap EX-006 names) or nocheck turns the admitted response into a denial.
        #[test]
        fn a_delegated_responder_missing_a_requirement_is_denied() {
            for (label, shape) in [
                (
                    "the OCSP-signing EKU",
                    ResponderShape {
                        ocsp_signing_eku: false,
                        ..ResponderShape::proper()
                    },
                ),
                (
                    "id-pkix-ocsp-nocheck",
                    ResponderShape {
                        nocheck: false,
                        ..ResponderShape::proper()
                    },
                ),
            ] {
                let result = delegated_response(&shape);
                assert!(
                    matches!(result, Err(OcspError::SignatureNotVerified(_))),
                    "a delegated responder without {label} must be denied, got {result:?}"
                );
            }
        }

        #[test]
        fn signed_good_but_stale_is_denied() {
            let signer = SigningKey::from_bytes(&[7u8; 32]);
            let issuer = mint_issuer_with_key(&signer);
            let leaf = mint_leaf_with_aia("http://ocsp.example.test/r");
            let (response, requested) =
                signed_response(&signer, &issuer, &leaf, CertStatus::good(), false);
            // now is far past nextUpdate (Jan 2) → stale.
            let result = verify_and_map_response(
                &response,
                &issuer,
                &requested,
                b"req-nonce",
                at(2025, 1, 1),
            );
            assert!(
                matches!(result, Err(OcspError::NotFresh(_))),
                "a signed but stale Good must be rejected, got {result:?}"
            );
        }
    }
}
