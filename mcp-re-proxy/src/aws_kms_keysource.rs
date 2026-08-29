//! Native AWS KMS Ed25519 response signer (ADR-MCPS-028 §B).
//!
//! A non-exporting [`KmsEd25519Backend`] backed by AWS KMS over blocking HTTPS
//! (`ureq`) with a minimal audited SigV4 signer ([`crate::aws_sigv4`]). The
//! response-signing key lives in KMS and is NEVER exported; the adapter uses ONLY
//! two KMS operations — `GetPublicKey` and `Sign` — and locks the signing mode to
//! `KeySpec = ECC_NIST_EDWARDS25519`, `SigningAlgorithm = ED25519_SHA_512`,
//! `MessageType = RAW` (PureEdDSA, no pre-hash). The async `aws-sdk-kms`/tokio/
//! Smithy stack is intentionally NOT used (ADR-MCPS-018 lean-sync firewall).
//!
//! Fail-closed posture (ADR-MCPS-028 §D):
//!   * a KMS key whose `KeySpec` is not `ECC_NIST_EDWARDS25519` is rejected at
//!     construction (`GetPublicKey`), never silently treated as Ed25519;
//!   * a public key that is not an RFC 8410 Ed25519 SPKI is rejected;
//!   * EVERY signature returned by KMS is verified locally against the advertised
//!     public key (catching a misconfigured DIGEST/prehash key or a key mismatch)
//!     BEFORE it is handed to the proxy — a non-verifying signature is an error,
//!     never emitted.

use crate::remote_signer_call::NETWORK_TIMEOUT;
use std::io::Read;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use mcp_re_core::b64url_encode;
use mcp_re_core::verify_ed25519;
use mcp_re_core::VerificationKey;

use crate::aws_sigv4::Header;
use crate::aws_sigv4::SigV4Signer;
use crate::aws_sts::AwsCredentialSource;
use crate::aws_sts::EnvCredentialSource;
use crate::aws_sts::WebIdentityConfig;
use crate::aws_sts::WebIdentityCredentialSource;
use crate::communication_assurance::Ed25519PublicKeyValue;
use crate::delegated_tls::RawEd25519TlsSigner;
use crate::handshake_quota::HandshakeQuotaWindow;
use crate::handshake_quota::QuotaGuarded;
use crate::handshake_quota::QuotaVerdict;
use crate::key_source::KeyError;
use crate::kms_keysource::Ed25519SpkiDer;
use crate::kms_keysource::KmsEd25519Backend;
use crate::kms_keysource::RawEd25519Message;
use crate::kms_keysource::RawEd25519Signature;
use crate::remote_signer_call::read_error_body;
use crate::remote_signer_call::RemoteSignerFailure;

/// The KMS JSON content type and the two `X-Amz-Target` operations used.
const KMS_CONTENT_TYPE: &str = "application/x-amz-json-1.1";
const TARGET_GET_PUBLIC_KEY: &str = "TrentService.GetPublicKey";
const TARGET_SIGN: &str = "TrentService.Sign";

/// Upper bound on a KMS success-path response body (matches the GCP sibling's
/// `read_body` cap). A `GetPublicKey`/`Sign` JSON response is well under a KB; the
/// cap exists so an operator-overridable / substituted endpoint cannot stream an
/// unbounded body into the blocking signing thread.
const MAX_KMS_RESPONSE_BYTES: u64 = 256 * 1024;

/// Cap on an HTTP *error* body read for diagnostics. Mirrors the GCP sibling: an
/// emulator or substituted endpoint could otherwise return an arbitrarily large body
/// on the error path, which is interpolated into a `KeyError` on every rotation attempt.
/// The single Ed25519 key spec and signing mode this adapter accepts.
const KEY_SPEC_ED25519: &str = "ECC_NIST_EDWARDS25519";
const SIGNING_ALGORITHM_ED25519: &str = "ED25519_SHA_512";
const MESSAGE_TYPE_RAW: &str = "RAW";

/// AWS KMS connection configuration. Region + key id are required; `endpoint`
/// overrides the default `https://kms.<region>.amazonaws.com` for an emulator
/// (e.g. LocalStack) or the internal-platform test endpoint.
pub struct AwsKmsConfig {
    pub region: String,
    pub key_id: String,
    pub endpoint: Option<String>,
}

/// The blocking-HTTPS seam to KMS: a single signed POST of a JSON body for a given
/// `X-Amz-Target`, returning the raw response body. Kept as a trait so the
/// adapter's response-parsing + verify-before-return logic is unit-testable with a
/// local-key fake and no network (the SigV4 signing itself is golden-tested in
/// [`crate::aws_sigv4`]).
pub(crate) trait KmsHttpClient {
    /// The response body, or the call's failure with its HTTP status still separable.
    ///
    /// Returning [`RemoteSignerFailure`] rather than a rendered [`KeyError`] is what lets
    /// [`quota_verdict`] answer from the wire fact. It used to render here and the
    /// classifier parsed the prose back out.
    fn post_kms(&self, target: &str, body: &[u8]) -> Result<Vec<u8>, RemoteSignerFailure>;
}

/// Production [`KmsHttpClient`]: SigV4-signs and sends over `ureq` (rustls HTTPS).
pub(crate) struct UreqKmsClient {
    /// Behind a lock so credentials can be REFRESHED between calls.
    ///
    /// They were captured once at process start and never refreshed, while temporary
    /// (session-token) credentials are an explicitly supported mode: under IRSA or any
    /// STS-issued pair the token expires — typically within the hour — and from that
    /// moment every KMS call fails, so the whole fleet loses response signing
    /// permanently and only a restart recovers it.
    signer: std::sync::RwLock<SigV4Signer>,
    /// Where the refreshed credentials come from — the environment, or the IRSA
    /// exchange. Consulted before every signature, so a rotated projected token or a
    /// re-exchanged STS session takes effect without a restart.
    credential_source: Box<dyn AwsCredentialSource>,
    agent: ureq::Agent,
    url: String,
    authority: String,
}

impl UreqKmsClient {
    pub(crate) fn new(
        credential_source: Box<dyn AwsCredentialSource>,
        config: &AwsKmsConfig,
    ) -> Result<Self, KeyError> {
        // UNCONDITIONALLY, whichever endpoint is used. The region decides which host
        // receives this client's KMS traffic when the endpoint is DERIVED from it — but it
        // also goes into the SigV4 credential scope (`Credential=AKID/date/REGION/kms/
        // aws4_request`) and the string-to-sign on every request, including requests to an
        // explicitly configured endpoint. So an unvalidated region is interpolated into a
        // signed header no matter which branch below runs, and a region carrying a newline
        // or a `/` writes into that header rather than into a region field.
        crate::aws_sts::validate_region(&config.region)?;
        let url = match config.endpoint.clone() {
            Some(endpoint) => endpoint,
            None => format!("https://kms.{}.amazonaws.com", config.region),
        };
        let authority = authority_of(&url)?;
        // Mint once here so a misconfigured custody path fails at CONSTRUCTION —
        // where an operator sees it — rather than on the first signature.
        let credentials = credential_source.credentials()?;
        let signer = SigV4Signer::new(credentials, config.region.clone(), "kms".to_string());
        Ok(UreqKmsClient {
            signer: std::sync::RwLock::new(signer),
            credential_source,
            agent: ureq::AgentBuilder::new().build(),
            url,
            authority,
        })
    }
}

impl KmsHttpClient for UreqKmsClient {
    fn post_kms(&self, target: &str, body: &[u8]) -> Result<Vec<u8>, RemoteSignerFailure> {
        // Refresh before signing. Cheap on both sources (a `getenv`, or a cache hit
        // until the refresh margin) and on the cold KMS path only — the root is off
        // the request path — and it is what lets a re-exchanged IRSA session or a
        // rotated env pair take effect without a restart. A refresh that fails leaves
        // the last-good credentials in place: a transient failure to look must not be
        // worse than not looking, and a credential that has genuinely expired fails
        // at KMS with its own error rather than being papered over here.
        //
        // Both takes recover a poisoned lock rather than propagating it. Poison is sticky
        // for the process, so the read take used to mean that ONE panic anywhere under this
        // lock removed AWS KMS signing from the replica permanently — every delegated-TLS
        // handshake fails and the cold-path rotor cannot mint a successor, so the replica
        // fails closed on `delegated_signing_unavailable` at the current delegated key's
        // `exp`. The guarded value is a whole-value credential swap with no half-written
        // state for the poison to protect. Matches the GCP sibling, `delegated_server_signer`
        // and `reloading_trust`.
        if let Ok(refreshed) = self.credential_source.credentials() {
            let mut signer = self.signer.write().unwrap_or_else(|p| p.into_inner());
            signer.set_credentials(refreshed);
        }
        let signer = self.signer.read().unwrap_or_else(|p| p.into_inner());
        let amz_date = format_amz_date(now_unix());
        // Headers that are SIGNED (host, content-type, x-amz-target). x-amz-date and
        // the session token are added by the signer.
        let signed = signer.sign(
            vec![
                Header {
                    name: "host".to_string(),
                    value: self.authority.clone(),
                },
                Header {
                    name: "content-type".to_string(),
                    value: KMS_CONTENT_TYPE.to_string(),
                },
                Header {
                    name: "x-amz-target".to_string(),
                    value: target.to_string(),
                },
            ],
            body,
            &amz_date,
        );

        let mut req = self
            .agent
            .post(&self.url)
            .set("Host", &self.authority)
            .set("Content-Type", KMS_CONTENT_TYPE)
            .set("X-Amz-Target", target)
            .set("X-Amz-Date", &signed.amz_date)
            .set("Authorization", &signed.authorization)
            .timeout(NETWORK_TIMEOUT);
        if let Some(token) = &signed.security_token {
            req = req.set("X-Amz-Security-Token", token);
        }

        // Transport / non-2xx failures are NotFound (could not obtain material from
        // the source), mirroring the PKCS#11 backend's convention. KMS's JSON error
        // body is surfaced for diagnosis.
        match req.send_bytes(body) {
            Ok(resp) => {
                // Bound the success-path read: the KMS endpoint is operator-
                // overridable (`--aws-kms-endpoint`), so a substituted/MITM endpoint
                // could otherwise stream an arbitrarily large body and drive unbounded
                // memory growth on the blocking signing thread. A GetPublicKey/Sign
                // JSON response is well under a KB; cap at 256 KiB like the GCP sibling
                // and fail closed if the body exceeds the cap.
                let mut buf = Vec::new();
                resp.into_reader()
                    // Read cap+1 so a body whose length is EXACTLY the cap is
                    // accepted; only a body strictly larger (len > cap) is rejected.
                    .take(MAX_KMS_RESPONSE_BYTES + 1)
                    .read_to_end(&mut buf)
                    .map_err(|e| {
                        RemoteSignerFailure::rendered(KeyError::NotFound(format!(
                            "aws-kms: read response body: {e}"
                        )))
                    })?;
                if buf.len() as u64 > MAX_KMS_RESPONSE_BYTES {
                    return Err(RemoteSignerFailure::malformed(format!(
                        "aws-kms: response body exceeds {MAX_KMS_RESPONSE_BYTES}-byte cap"
                    )));
                }
                Ok(buf)
            }
            Err(ureq::Error::Status(code, resp)) => {
                // The SUCCESS path above is capped for a stated reason — a substituted or
                // operator-overridden endpoint must not be able to drive unbounded memory
                // growth on the blocking signing thread. That endpoint controls this branch
                // just as fully, by returning any non-2xx status, so `into_string()`'s
                // ~10 MiB read left the guard trivially bypassable. Bounded like the GCP
                // sibling's `read_error_body`.
                Err(RemoteSignerFailure::status_body(
                    code,
                    read_error_body(resp),
                ))
            }
            Err(e) => Err(RemoteSignerFailure::transport(format!("transport: {e}"))),
        }
    }
}

/// Extract the `host[:port]` authority a request will send (and SigV4 must sign)
/// from a `scheme://host[:port]` endpoint URL.
///
/// The signed `host` header and the host `ureq` actually connects to must be the same
/// string, so anything that would make a URL parser read a different authority than the
/// text reads is rejected rather than accepted and signed. That rule is not local to this
/// adapter — the same override reaches the GCP client and the STS exchange — so the
/// decision is [`crate::kms_endpoint_policy::kms_endpoint_authority`], applied here as well as at the CLI
/// because `AwsKmsConfig::endpoint` is public and an embedder reaches this constructor
/// without meeting a parser.
///
/// The path this used to refuse is refused there too: an endpoint is a `host[:port]`
/// authority, and a `/v1`-style suffix is not part of one.
fn authority_of(url: &str) -> Result<String, KeyError> {
    let authority = crate::kms_endpoint_policy::kms_endpoint_authority(url)
        .map_err(|why| KeyError::Malformed(format!("aws-kms: endpoint {why}")))?;
    let path = url
        .split_once("://")
        .and_then(|(_, rest)| rest.split_once('/'))
        .map(|(_, path)| path)
        .unwrap_or("");
    if !path.is_empty() {
        return Err(KeyError::Malformed(format!(
            "aws-kms: endpoint '{url}' must not include a path"
        )));
    }
    Ok(authority)
}

/// Current UNIX time in seconds (production-only; tests use fixed inputs to
/// [`format_amz_date`]).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format a UNIX timestamp as SigV4's `YYYYMMDDTHHMMSSZ` (UTC). Hand-rolled via the
/// civil-from-days algorithm to avoid a date-library dependency.
fn format_amz_date(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let sod = unix_secs % 86_400;
    let (hour, min, sec) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}{m:02}{d:02}T{hour:02}{min:02}{sec:02}Z")
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 → (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The KMS `Sign` request body for the canonical preimage.
fn sign_request_body(key_id: &str, preimage: &[u8]) -> Vec<u8> {
    serde_json::json!({
        "KeyId": key_id,
        "Message": STANDARD.encode(preimage),
        "MessageType": MESSAGE_TYPE_RAW,
        "SigningAlgorithm": SIGNING_ALGORITHM_ED25519,
    })
    .to_string()
    .into_bytes()
}

/// The KMS `GetPublicKey` request body.
fn get_public_key_request_body(key_id: &str) -> Vec<u8> {
    serde_json::json!({ "KeyId": key_id })
        .to_string()
        .into_bytes()
}

/// Parse a `GetPublicKey` response: the `KeySpec` MUST be `ECC_NIST_EDWARDS25519`
/// and `PublicKey` is the standard-base64 RFC 8410 Ed25519 SPKI DER. Fails closed
/// on any other key type so a non-Ed25519 KMS key can never be admitted.
fn parse_get_public_key_response(body: &[u8]) -> Result<Vec<u8>, KeyError> {
    let v: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| KeyError::Malformed(format!("aws-kms: GetPublicKey JSON: {e}")))?;
    // Modern KMS uses `KeySpec`; tolerate the legacy `CustomerMasterKeySpec` alias.
    let key_spec = v
        .get("KeySpec")
        .or_else(|| v.get("CustomerMasterKeySpec"))
        .and_then(|s| s.as_str())
        .ok_or_else(|| KeyError::Malformed("aws-kms: GetPublicKey has no KeySpec".to_string()))?;
    if key_spec != KEY_SPEC_ED25519 {
        return Err(KeyError::Malformed(format!(
            "aws-kms: KMS key spec is '{key_spec}', not {KEY_SPEC_ED25519}; the KMS key MUST be \
             an Ed25519 key"
        )));
    }
    let pk_b64 = v
        .get("PublicKey")
        .and_then(|s| s.as_str())
        .ok_or_else(|| KeyError::Malformed("aws-kms: GetPublicKey has no PublicKey".to_string()))?;
    STANDARD
        .decode(pk_b64)
        .map_err(|e| KeyError::Malformed(format!("aws-kms: PublicKey base64: {e}")))
}

/// Parse a `Sign` response: `Signature` is the standard-base64 raw Ed25519
/// signature.
fn parse_sign_response(body: &[u8]) -> Result<Vec<u8>, KeyError> {
    let v: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| KeyError::Malformed(format!("aws-kms: Sign JSON: {e}")))?;
    let sig_b64 = v.get("Signature").and_then(|s| s.as_str()).ok_or_else(|| {
        KeyError::Malformed("aws-kms: Sign response has no Signature".to_string())
    })?;
    STANDARD
        .decode(sig_b64)
        .map_err(|e| KeyError::Malformed(format!("aws-kms: Signature base64: {e}")))
}

/// What a locally-refused handshake signature says, and it names the quota an operator
/// has to go and look at.
const QUOTA_REFUSAL: &str = "aws-kms: KMS is throttling this account; the delegated-TLS \
     handshake signature is refused locally so the delegated-credential issuance keeps \
     its share of the quota";

/// A non-exporting [`KmsEd25519Backend`] backed by AWS KMS.
pub struct AwsKmsEd25519Backend {
    client: Box<dyn KmsHttpClient + Send + Sync>,
    key_id: String,
    spki_der: Vec<u8>,
    verify_key: VerificationKey,
    /// The handshake path's share of the account quota (ADR-MCPS-028 §G). The window,
    /// the single-flight probe and the straggler rule are
    /// [`HandshakeQuotaWindow`](crate::handshake_quota::HandshakeQuotaWindow)'s; what is
    /// this backend's is which failures mean the quota is gone, and what the refusal says.
    tls_quota: HandshakeQuotaWindow,
}

/// The KMS `__type` values that mean the ACCOUNT is over its budget, rather than that this
/// one request was refused.
///
/// `KMSInternalException` is here deliberately: KMS returns it for its own transient
/// capacity failures, which is a statement about the service and not about the request.
/// `AccessDeniedException` and its siblings are NOT, and must not be — evicting the
/// handshake path over a missing IAM grant would turn a permanent misconfiguration into a
/// permanent local refusal that hides it.
const ACCOUNT_QUOTA_ERROR_TYPES: &[&str] = &[
    "ThrottlingException",
    "LimitExceededException",
    "KMSInternalException",
    "TooManyRequestsException",
];

/// Does this KMS failure say the ACCOUNT is over its quota, rather than that one request
/// was malformed?
///
/// Read from the WIRE FACT: the HTTP status the front door answered with, and the `__type`
/// field of the KMS JSON error body. Both arrive typed on [`RemoteSignerFailure`] and
/// neither is recovered from prose.
///
/// It used to be `format!("{error:?}")` and `contains`, because the transport rendered the
/// status and the body into a `KeyError` string before anything could ask. Two live
/// consequences: a rewording upstream silently stopped arming the window, and any failure
/// whose text happened to carry one of these tokens armed it — including, once
/// `AccessDeniedException` and `ThrottlingException` can appear in the same operator
/// message, a chained diagnosis about something else.
///
/// `__type` is namespaced on the wire (`com.amazonaws.kms#ThrottlingException`), so the
/// suffix is what is compared. A body that states no `__type` at all states nothing, which
/// is not a positive.
fn quota_verdict(failure: &RemoteSignerFailure) -> QuotaVerdict {
    crate::remote_signer_call::quota_verdict(
        failure,
        crate::remote_signer_call::QuotaSignals {
            path: &["__type"],
            exhausted: ACCOUNT_QUOTA_ERROR_TYPES,
            // `__type` is namespaced on the wire
            // (`com.amazonaws.kms#ThrottlingException`), so the suffix is compared.
            namespaced: true,
        },
    )
}

impl AwsKmsEd25519Backend {
    /// Build over an explicit transport — fetches and validates the public key once
    /// (Ed25519 SPKI, correct key spec) and caches it for verify-before-return.
    pub(crate) fn with_client(
        client: Box<dyn KmsHttpClient + Send + Sync>,
        key_id: String,
    ) -> Result<Self, KeyError> {
        let body = get_public_key_request_body(&key_id);
        let resp = client
            .post_kms(TARGET_GET_PUBLIC_KEY, &body)
            .map_err(|failure| failure.into_key_error("aws-kms", TARGET_GET_PUBLIC_KEY))?;
        let spki_der = parse_get_public_key_response(&resp)?;
        let raw = crate::kms_keysource::Ed25519SpkiDer::interpret(&spki_der)?.raw_point();
        let verify_key = VerificationKey::from_bytes(&raw).map_err(|e| {
            KeyError::Malformed(format!("aws-kms: invalid Ed25519 public key: {e}"))
        })?;
        Ok(AwsKmsEd25519Backend {
            client,
            key_id,
            spki_der,
            verify_key,
            tls_quota: HandshakeQuotaWindow::for_network_timeout(NETWORK_TIMEOUT, QUOTA_REFUSAL),
        })
    }

    /// Build a production AWS KMS backend (ureq HTTPS + SigV4) from env credentials.
    pub fn from_env(config: &AwsKmsConfig) -> Result<Self, KeyError> {
        Self::with_credential_source(Box::new(EnvCredentialSource), config)
    }

    /// Build a production backend whose credentials come from **IRSA**: the
    /// projected service-account token EKS mounts is exchanged for temporary
    /// credentials, so no long-lived IAM key material exists in the pod.
    ///
    /// The AWS counterpart of `GcpKmsEd25519Backend`'s metadata-server path, and
    /// chosen the same way — by an explicit operator flag, never by discovery.
    /// `sts_endpoint` overrides the regional default for tests.
    pub fn from_web_identity(
        config: &AwsKmsConfig,
        sts_endpoint: Option<String>,
    ) -> Result<Self, KeyError> {
        let wi = WebIdentityConfig::from_env(&config.region, sts_endpoint)?;
        let source = WebIdentityCredentialSource::new(wi)?;
        Self::with_credential_source(Box::new(source), config)
    }

    /// Build over an explicit credential source. The `GetPublicKey` in
    /// [`Self::with_client`] is the first thing that uses it, so a custody path that
    /// cannot mint credentials fails here — at startup — not on the first response
    /// the proxy tries to sign.
    pub(crate) fn with_credential_source(
        source: Box<dyn AwsCredentialSource>,
        config: &AwsKmsConfig,
    ) -> Result<Self, KeyError> {
        // Report the custody path that was actually taken, not the one configured.
        // The two differ exactly when an operator believes they are on IRSA and are
        // not — which is the case worth seeing in a log, since the proxy signs
        // identically either way and nothing downstream would reveal it.
        eprintln!(
            "mcp-re-proxy: aws-kms key {} credentials = {}",
            config.key_id,
            source.describe()
        );
        let client = UreqKmsClient::new(source, config)?;
        Self::with_client(Box::new(client), config.key_id.clone())
    }

    /// The delegated-TLS handshake signature, against an explicit clock so the
    /// quota-preserving window is provable without waiting on one.
    ///
    /// The window is [`HandshakeQuotaWindow`]'s and so is every rule about it. This
    /// supplies the two things that are AWS's: the signing operation, and which failures
    /// say the account is out of budget.
    fn tls_sign_at(
        &self,
        message: &[u8],
        clock: &dyn Fn() -> std::time::Instant,
    ) -> Result<Vec<u8>, KeyError> {
        // The WIRE call is what the window guards, and it is the only part of the signature
        // path the quota question can be asked about: the length check and
        // verify-before-return below are local, and a local failure is never a statement
        // about the account.
        let response = self
            .tls_quota
            .guard(clock, || self.sign_once(message), quota_verdict)
            .map_err(|guarded| match guarded {
                QuotaGuarded::Refused(why) => KeyError::NotFound(why.to_string()),
                QuotaGuarded::Call(failure) => failure.into_key_error("aws-kms", TARGET_SIGN),
            })?;
        // rustls takes the raw bytes; the 64-byte rule was already applied by
        // `RawEd25519Signature`, so this projects a checked value rather than
        // handing an unchecked one on.
        Ok(self.accept_signature(message, response)?.bytes().to_vec())
    }

    /// The `Sign` wire call, with its failure still typed.
    fn sign_once(&self, preimage: &[u8]) -> Result<Vec<u8>, RemoteSignerFailure> {
        self.client
            .post_kms(TARGET_SIGN, &sign_request_body(&self.key_id, preimage))
    }

    /// Parse, length-check and VERIFY-BEFORE-RETURN a `Sign` response body.
    ///
    /// ADR-MCPS-028 §D / guardrail: the signature MUST verify against the advertised public
    /// key under the unmodified `mcp-re-core` verifier. This catches a misconfigured
    /// DIGEST/prehash KMS key, a key mismatch, or any corruption — fail closed, never emit
    /// it.
    fn accept_signature(
        &self,
        preimage: &[u8],
        response: Vec<u8>,
    ) -> Result<RawEd25519Signature, KeyError> {
        // The length rule belongs to the operand, not to this adapter: interpreting the
        // bytes IS the check, so there is no separate `if` to forget in a third provider.
        let signature =
            RawEd25519Signature::interpret(&parse_sign_response(&response)?, "aws-kms")?;
        verify_ed25519(
            preimage,
            &b64url_encode(signature.bytes()),
            &self.verify_key,
        )
        .map_err(|e| {
            KeyError::Malformed(format!(
                "aws-kms: KMS signature did NOT verify against the advertised public key \
                 (misconfigured DIGEST/prehash key or key mismatch?): {e}"
            ))
        })?;
        Ok(signature)
    }

    /// TEST-ONLY (issue #60): build a backend over an in-memory FAKE KMS transport
    /// backed by the LOCAL Ed25519 key with the given 32-byte `seed`, so an
    /// integration test (`tests/tls_test.rs`) can drive the full delegated-TLS mTLS
    /// handshake against an AWS backend with NO network and NO AWS credentials. The
    /// fake transport answers `GetPublicKey` with the key's RFC 8410 Ed25519 SPKI and
    /// `Sign` with a PureEdDSA RAW signature — exactly what a real KMS Ed25519 key
    /// returns. There is NO production code path into this; it exists only to make the
    /// crate-internal fake-transport reachable from the integration test that mints a
    /// matching server certificate from the same `seed`.
    #[doc(hidden)]
    pub fn for_test_with_local_seed(seed: &[u8; 32], key_id: &str) -> Result<Self, KeyError> {
        let client = LocalKeyKmsTransport {
            key: mcp_re_core::SigningKey::from_seed_bytes(seed),
        };
        Self::with_client(Box::new(client), key_id.to_string())
    }
}

/// TEST-ONLY in-memory [`KmsHttpClient`] backed by a LOCAL Ed25519 key — the same
/// fake-KMS shape used by this module's unit tests, exposed (only via the
/// `#[doc(hidden)]` [`AwsKmsEd25519Backend::for_test_with_local_seed`]) so the
/// delegated-TLS handshake integration test can use a real AWS backend with no
/// network. NOT reachable from any production path.
#[doc(hidden)]
struct LocalKeyKmsTransport {
    key: mcp_re_core::SigningKey,
}

impl KmsHttpClient for LocalKeyKmsTransport {
    fn post_kms(&self, target: &str, body: &[u8]) -> Result<Vec<u8>, RemoteSignerFailure> {
        match target {
            TARGET_GET_PUBLIC_KEY => {
                let point = self.key.public_key().to_bytes();
                let der = Ed25519PublicKeyValue::spki_der_for_point(point);
                Ok(serde_json::json!({
                    "KeySpec": KEY_SPEC_ED25519,
                    "PublicKey": STANDARD.encode(&der),
                })
                .to_string()
                .into_bytes())
            }
            TARGET_SIGN => {
                let v: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
                    RemoteSignerFailure::malformed(format!("fake kms: Sign body: {e}"))
                })?;
                let msg = STANDARD
                    .decode(v.get("Message").and_then(|m| m.as_str()).unwrap_or(""))
                    .map_err(|e| {
                        RemoteSignerFailure::malformed(format!("fake kms: Message b64: {e}"))
                    })?;
                let raw = mcp_re_core::b64url_decode(&self.key.sign(&msg))
                    .map_err(|e| RemoteSignerFailure::malformed(format!("fake kms: sign: {e}")))?;
                Ok(serde_json::json!({
                    "Signature": STANDARD.encode(&raw),
                    "SigningAlgorithm": SIGNING_ALGORITHM_ED25519,
                })
                .to_string()
                .into_bytes())
            }
            other => Err(RemoteSignerFailure::malformed(format!(
                "fake kms: unexpected target {other}"
            ))),
        }
    }
}

impl KmsEd25519Backend for AwsKmsEd25519Backend {
    fn sign_raw_ed25519(
        &self,
        message: RawEd25519Message<'_>,
    ) -> Result<RawEd25519Signature, KeyError> {
        let preimage = message.bytes();
        let response = self
            .sign_once(preimage)
            .map_err(|failure| failure.into_key_error("aws-kms", TARGET_SIGN))?;
        self.accept_signature(preimage, response)
    }

    fn public_key_spki_der(&self) -> Result<Ed25519SpkiDer, KeyError> {
        Ed25519SpkiDer::interpret(&self.spki_der)
    }
}

/// Delegated TLS handshake signing through AWS KMS (issue #60, ADR-MCPS-028 §G).
///
/// The TLS *server* key is a SECOND, DISTINCT KMS key (a separate `key_id` and —
/// the operator SHOULD give it — a distinct authz policy / IAM grant) from the
/// object-signing key, custodied by its own [`AwsKmsEd25519Backend`]. The TLS
/// handshake signature is produced by the SAME RAW-Ed25519 KMS `Sign` path used for
/// response signing (`SigningAlgorithm = ED25519_SHA_512`, `MessageType = RAW`,
/// PureEdDSA), so the TLS private key never leaves KMS.
///
/// rustls verifies the handshake `CertificateVerify` it gets back, and the
/// validated delegated build path (#58) both enforces the 64-byte length and fails
/// closed when the (exportable, cached) public key here does not match the leaf TLS
/// certificate — so verify-before-return is NOT repeated on this path (it stays on
/// the object-signing `sign_raw_ed25519` path, which is reused unchanged).
impl RawEd25519TlsSigner for AwsKmsEd25519Backend {
    fn sign_tls_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        self.tls_sign_at(message, &std::time::Instant::now)
    }

    fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, KeyError> {
        // The advertised KMS public key, fetched + validated as Ed25519 at
        // construction; the #58 build path matches it against the leaf TLS cert.
        Ok(self.spki_der.clone())
    }
}

#[cfg(test)]
mod tests {
    use mcp_re_core::b64url_decode;
    use mcp_re_core::SigningKey;

    use super::*;

    fn spki_from_raw(raw: &[u8; 32]) -> Vec<u8> {
        Ed25519PublicKeyValue::spki_der_for_point(*raw)
    }

    /// GOLDEN: UTC formatting matches well-known timestamps.
    #[test]
    fn amz_date_formats_known_epochs() {
        assert_eq!(format_amz_date(0), "19700101T000000Z");
        // 2001-09-09T01:46:40Z — the well-known 1e9 UNIX timestamp.
        assert_eq!(format_amz_date(1_000_000_000), "20010909T014640Z");
        // 2015-08-30T12:36:00Z — the get-vanilla vector's instant.
        assert_eq!(format_amz_date(1_440_938_160), "20150830T123600Z");
    }

    #[test]
    fn authority_strips_scheme_and_path() {
        assert_eq!(
            authority_of("https://kms.us-east-1.amazonaws.com").unwrap(),
            "kms.us-east-1.amazonaws.com"
        );
        assert_eq!(
            authority_of("http://localhost:4566/").unwrap(),
            "localhost:4566"
        );
        assert!(authority_of("not-a-url").is_err());
    }

    /// Userinfo, a query and a fragment all move where a URL parser sends the request,
    /// while the text before the first `/` — which is what gets signed and sent as
    /// `Host` — still looks like the intended endpoint. `https://kms.x@evil.example.com`
    /// connects to `evil.example.com`.
    ///
    /// R9-C001: the loopback forms are the ones this file's round-8 fix did not have to
    /// reach and the shared gate did — `http://localhost:80@evil.example.com` was read as
    /// loopback by a rule that derived the host BEFORE stripping userinfo, so a plaintext
    /// SigV4 session credential left the machine. The decision now lives in
    /// `kms_endpoint_policy::kms_endpoint_authority`, so this file and the GCP and STS siblings cannot
    /// disagree about it.
    #[test]
    fn an_authority_that_re_points_the_request_is_refused() {
        for hostile in [
            "https://kms.x@evil.example.com",
            "https://kms.us-east-1.amazonaws.com@evil.example.com",
            "https://kms.x@evil.example.com#.amazonaws.com",
            "https://kms.x?@evil.example.com",
            "http://localhost:80@evil.example.com",
            "http://127.0.0.1:4566@evil.example.com",
            "https://user:pass@evil.example.com",
            // Plaintext off the machine, which is what the loopback exception is for.
            "http://kms.attacker.example",
        ] {
            assert!(
                authority_of(hostile).is_err(),
                "{hostile:?} must not be accepted as an endpoint authority"
            );
        }
    }

    /// POSITIVE CONTROL: the endpoints an operator sets still yield the authority SigV4
    /// signs and `ureq` connects to. A check that refused everything would satisfy the
    /// refusal test above.
    #[test]
    fn the_aws_kms_endpoints_an_operator_legitimately_sets_still_yield_an_authority() {
        for (endpoint, authority) in [
            (
                "https://kms.us-east-1.amazonaws.com",
                "kms.us-east-1.amazonaws.com",
            ),
            (
                "https://vpce-0abc123-xy1z.kms.us-east-1.vpce.amazonaws.com",
                "vpce-0abc123-xy1z.kms.us-east-1.vpce.amazonaws.com",
            ),
            (
                "https://kms.emulator.internal:8443",
                "kms.emulator.internal:8443",
            ),
            ("http://localhost:4566", "localhost:4566"),
            ("http://127.0.0.1:4566/", "127.0.0.1:4566"),
            ("http://[::1]:4566", "[::1]:4566"),
        ] {
            assert_eq!(
                authority_of(endpoint).unwrap_or_else(|e| panic!("{endpoint}: {e:?}")),
                authority
            );
        }
    }

    /// The KMS endpoint is region-derived, so the region check has to bite HERE and not
    /// only on the STS twin: the same `--aws-kms-region` builds both. A region carrying
    /// `@`/`#` yields `https://kms.x@evil.example.com#.amazonaws.com`, whose real host is
    /// `evil.example.com` — which then receives the `X-Amz-Security-Token` header and
    /// answers `GetPublicKey` with a substituted root response-signing key.
    #[test]
    fn a_hostile_region_stops_the_default_kms_endpoint_being_built() {
        for hostile in [
            "x@evil.example.com#",
            "evil.example.com/",
            "us-east-1?x=",
            "us-east-1:443@evil.example.com",
            "",
        ] {
            let Err(err) = UreqKmsClient::new(
                Box::new(EnvCredentialSource),
                &AwsKmsConfig {
                    region: hostile.to_string(),
                    key_id: "k1".to_string(),
                    endpoint: None,
                },
            ) else {
                panic!("{hostile:?}: a region that moves the authority must fail closed");
            };
            assert!(
                matches!(&err, KeyError::Malformed(m) if m.contains("region")),
                "{hostile:?}: got {err:?}"
            );
        }
    }

    /// The region reaches the SigV4 credential scope on EVERY request, so an explicit
    /// endpoint does not excuse it from validation.
    ///
    /// `Credential=AKID/date/REGION/kms/aws4_request` and the string-to-sign carry the
    /// region whichever endpoint is used, so a region holding a newline or a `/` writes into
    /// a signed header rather than into a region field. The check used to run only on the
    /// branch that DERIVES the endpoint from it.
    #[test]
    fn a_hostile_region_is_refused_even_with_an_explicit_endpoint() {
        for hostile in [
            "x@evil.example.com#",
            "evil.example.com/",
            "us-east-1\r\nX: y",
            "",
        ] {
            let Err(err) = UreqKmsClient::new(
                Box::new(EnvCredentialSource),
                &AwsKmsConfig {
                    region: hostile.to_string(),
                    key_id: "k1".to_string(),
                    endpoint: Some("http://localhost:4566".to_string()),
                },
            ) else {
                panic!("{hostile:?}: a region that reaches the signature must fail closed");
            };
            assert!(
                matches!(&err, KeyError::Malformed(m) if m.contains("region")),
                "{hostile:?}: got {err:?}"
            );
        }
        // POSITIVE CONTROL: a real region with an emulator endpoint is the LocalStack lane
        // and must still build. It fails later, on credentials, not on the region.
        let err = UreqKmsClient::new(
            Box::new(EnvCredentialSource),
            &AwsKmsConfig {
                region: "us-east-1".to_string(),
                key_id: "k1".to_string(),
                endpoint: Some("http://localhost:4566".to_string()),
            },
        )
        .err();
        assert!(
            !format!("{err:?}").contains("region"),
            "a real region with an emulator endpoint must not be refused, got {err:?}"
        );
    }

    /// A KMS key that is not Ed25519 is rejected at parse time (guardrail #4).
    #[test]
    fn non_ed25519_key_spec_fails_closed() {
        let body = br#"{"KeySpec":"RSA_2048","PublicKey":"AA=="}"#;
        assert!(matches!(
            parse_get_public_key_response(body),
            Err(KeyError::Malformed(_))
        ));
    }

    #[test]
    fn get_public_key_parses_ed25519_spki() {
        let raw = SigningKey::from_seed_bytes(&[3u8; 32])
            .public_key()
            .to_bytes();
        let der = spki_from_raw(&raw);
        let body = serde_json::json!({
            "KeySpec": "ECC_NIST_EDWARDS25519",
            "PublicKey": STANDARD.encode(&der),
        })
        .to_string();
        assert_eq!(parse_get_public_key_response(body.as_bytes()).unwrap(), der);
    }

    /// A fake KMS transport backed by a LOCAL Ed25519 key — exercises the full
    /// GetPublicKey→construct→Sign→verify-before-return path with no network.
    /// `prehash` flips the Sign side to a forbidden DIGEST-style signature to prove
    /// the verify-before-return guard catches it.
    struct FakeKms {
        key: SigningKey,
        prehash: bool,
    }
    impl KmsHttpClient for FakeKms {
        fn post_kms(&self, target: &str, body: &[u8]) -> Result<Vec<u8>, RemoteSignerFailure> {
            match target {
                TARGET_GET_PUBLIC_KEY => {
                    let der = spki_from_raw(&self.key.public_key().to_bytes());
                    Ok(serde_json::json!({
                        "KeySpec": KEY_SPEC_ED25519,
                        "PublicKey": STANDARD.encode(&der),
                    })
                    .to_string()
                    .into_bytes())
                }
                TARGET_SIGN => {
                    let v: serde_json::Value = serde_json::from_slice(body).unwrap();
                    let msg = STANDARD
                        .decode(v.get("Message").unwrap().as_str().unwrap())
                        .unwrap();
                    let to_sign = if self.prehash {
                        let mut d = b"DIGEST:".to_vec();
                        d.extend_from_slice(&msg);
                        d
                    } else {
                        msg
                    };
                    let raw = b64url_decode(&self.key.sign(&to_sign)).unwrap();
                    Ok(serde_json::json!({
                        "Signature": STANDARD.encode(&raw),
                        "SigningAlgorithm": SIGNING_ALGORITHM_ED25519,
                    })
                    .to_string()
                    .into_bytes())
                }
                other => panic!("unexpected KMS target {other}"),
            }
        }
    }

    /// One panic under the SigV4 credential lock must not remove AWS KMS signing from the
    /// replica for the rest of the process.
    ///
    /// Poison is sticky. The `signer` read take used to map it to a hard `KeyError`, so a
    /// single panic turned every later `post_kms` into a permanent failure — the delegated
    /// rotor then cannot mint a successor and the replica fails closed at the current key's
    /// `exp`. The lock protects no invariant: it guards a whole-value swap.
    ///
    /// The handshake window's own poison property is
    /// `handshake_quota::tests::a_poisoned_window_lock_still_signs`; this backend no longer
    /// holds that lock.
    #[test]
    fn a_poisoned_signer_lock_still_signs() {
        // The credential lock on the real `UreqKmsClient`: poisoned, `post_kms` must still
        // reach the point where it fails on the NETWORK, not on the lock.
        let client = UreqKmsClient::new(
            Box::new(StaticCredentials),
            &AwsKmsConfig {
                region: "eu-north-1".to_string(),
                key_id: "alias/mcp-re".to_string(),
                endpoint: Some("http://127.0.0.1:1".to_string()),
            },
        )
        .expect("construct");
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = client.signer.write().expect("not yet poisoned");
            panic!("poisoning the signer on purpose");
        }));
        assert!(
            client.signer.read().is_err(),
            "the signer lock must now be poisoned"
        );
        let err = client
            .post_kms(TARGET_SIGN, b"{}")
            .expect_err("nothing is listening on 127.0.0.1:1");
        let rendered = format!("{err:?}");
        assert!(
            rendered.contains("transport") && !rendered.contains("lock poisoned"),
            "a poisoned credential lock must not become the failure; got {rendered}"
        );
    }

    /// A credential source with nothing to look up, so `post_kms` reaches the network.
    struct StaticCredentials;
    impl AwsCredentialSource for StaticCredentials {
        fn credentials(&self) -> Result<crate::aws_sigv4::AwsCredentials, KeyError> {
            Ok(crate::aws_sigv4::AwsCredentials {
                access_key_id: "AKIAEXAMPLE".to_string(),
                secret_access_key: zeroize::Zeroizing::new("secret".to_string()),
                session_token: None,
            })
        }
        fn describe(&self) -> String {
            "test-static".to_string()
        }
    }

    /// LOAD-BEARING: the full adapter path produces a signature that verifies, and
    /// the SPKI it reports is the advertised key.
    #[test]
    fn aws_backend_signs_and_verifies_end_to_end() {
        let backend = AwsKmsEd25519Backend::with_client(
            Box::new(FakeKms {
                key: SigningKey::from_seed_bytes(&[11u8; 32]),
                prehash: false,
            }),
            "alias/mcp-re".to_string(),
        )
        .expect("construct");
        let preimage = b"mcp-re canonical response preimage";
        let sig = backend
            .sign_raw_ed25519(RawEd25519Message::for_preimage(preimage))
            .expect("sign");
        assert_eq!(sig.bytes().len(), 64);
        // The advertised SPKI parses to the same verify key.
        let raw = backend.public_key_spki_der().unwrap().raw_point();
        let key = VerificationKey::from_bytes(&raw).unwrap();
        verify_ed25519(preimage, &b64url_encode(sig.bytes()), &key).expect("verifies");
    }

    /// A DIGEST/prehash KMS misconfiguration is caught by verify-before-return —
    /// the adapter NEVER returns a non-verifying signature (guardrail #5).
    #[test]
    fn prehash_signature_is_rejected_before_return() {
        let backend = AwsKmsEd25519Backend::with_client(
            Box::new(FakeKms {
                key: SigningKey::from_seed_bytes(&[11u8; 32]),
                prehash: true,
            }),
            "alias/mcp-re".to_string(),
        )
        .expect("construct");
        let err = backend
            .sign_raw_ed25519(RawEd25519Message::for_preimage(
                b"mcp-re canonical response preimage",
            ))
            .expect_err("must fail closed");
        assert!(matches!(err, KeyError::Malformed(_)));
    }

    /// A KMS transport that always reports the account is being throttled, counting
    /// how many times it was actually reached.
    struct ThrottlingKms {
        key: SigningKey,
        signs: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }
    impl KmsHttpClient for ThrottlingKms {
        fn post_kms(&self, target: &str, _body: &[u8]) -> Result<Vec<u8>, RemoteSignerFailure> {
            match target {
                TARGET_GET_PUBLIC_KEY => {
                    let der = spki_from_raw(&self.key.public_key().to_bytes());
                    Ok(serde_json::json!({
                        "KeySpec": KEY_SPEC_ED25519,
                        "PublicKey": STANDARD.encode(&der),
                    })
                    .to_string()
                    .into_bytes())
                }
                TARGET_SIGN => {
                    self.signs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    // Exactly what `UreqKmsClient::post_kms` hands back for a KMS error
                    // response: the status and the body, still separable.
                    Err(RemoteSignerFailure::status_body(
                        400,
                        "{\"__type\":\"com.amazonaws.kms#ThrottlingException\"}".to_string(),
                    ))
                }
                other => panic!("unexpected KMS target {other}"),
            }
        }
    }

    /// A KMS throttle on the HANDSHAKE path must stop that path calling KMS for a
    /// window, so the quota it shares with delegated-credential issuance is not spent
    /// by a flood of unauthenticated connections. Counted at the transport, not
    /// inferred from the error: the property is "KMS was not called", not "the
    /// handshake failed".
    #[test]
    fn a_throttled_tls_sign_stops_calling_kms_for_the_cooldown() {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let backend = AwsKmsEd25519Backend::with_client(
            Box::new(ThrottlingKms {
                key: SigningKey::from_seed_bytes(&[31u8; 32]),
                signs: std::sync::Arc::clone(&counter),
            }),
            "alias/mcp-re-tls".to_string(),
        )
        .expect("construct");
        let signs = || counter.load(std::sync::atomic::Ordering::SeqCst);

        let start = std::time::Instant::now();
        backend
            .tls_sign_at(b"transcript", &|| start)
            .expect_err("KMS is throttling");
        assert_eq!(signs(), 1, "the first handshake does reach KMS");

        for _ in 0..20 {
            backend
                .tls_sign_at(b"transcript", &|| {
                    start + std::time::Duration::from_millis(1)
                })
                .expect_err("refused locally");
        }
        assert_eq!(
            signs(),
            1,
            "a handshake flood inside the cooldown must not convert into KMS calls"
        );

        backend
            .tls_sign_at(b"transcript", &|| start + NETWORK_TIMEOUT)
            .expect_err("KMS is still throttling");
        assert_eq!(signs(), 2, "past the cooldown the path probes KMS again");
    }

    /// AWS's half of the window: which failures mean the ACCOUNT is over its quota, and
    /// not that one request was refused.
    ///
    /// The mechanism the verdict drives — the window, the single-flight probe, the
    /// straggler rule — is [`crate::handshake_quota`]'s and is tested there, against a
    /// closure rather than through a fake KMS transport. What is AWS's is this vocabulary,
    /// and it is worth its own test because it is recovered from a RENDERED error: a
    /// reworded body silently stops arming the window, and an unrelated failure that
    /// happens to contain one of these tokens arms it.
    #[test]
    fn only_account_quota_failures_reach_the_exhausted_verdict() {
        for exhausted in [
            RemoteSignerFailure::status_body(
                400,
                "{\"__type\":\"com.amazonaws.kms#ThrottlingException\"}".to_string(),
            ),
            RemoteSignerFailure::status_body(
                400,
                "{\"__type\":\"LimitExceededException\"}".to_string(),
            ),
            RemoteSignerFailure::status_body(
                400,
                "{\"__type\":\"KMSInternalException\"}".to_string(),
            ),
            // The front door sheds load before KMS's own error shape is reached, so the
            // body states no `__type` at all.
            RemoteSignerFailure::status_body(429, "slow down".to_string()),
            RemoteSignerFailure::status_body(503, String::new()),
        ] {
            assert_eq!(
                quota_verdict(&exhausted),
                QuotaVerdict::Exhausted,
                "{exhausted:?}"
            );
        }
        for unrelated in [
            RemoteSignerFailure::status_body(
                400,
                "{\"__type\":\"AccessDeniedException\"}".to_string(),
            ),
            RemoteSignerFailure::status_body(403, "{\"__type\":\"NotFoundException\"}".to_string()),
            RemoteSignerFailure::transport("connection refused".to_string()),
            RemoteSignerFailure::malformed("a body that never reached the wire".to_string()),
            // The regression the wire fact closes: a DIAGNOSIS that merely MENTIONS a
            // quota error is not a quota error. The old classifier matched this.
            RemoteSignerFailure::status_body(
                400,
                "{\"__type\":\"AccessDeniedException\",\"message\":\"not a ThrottlingException\"}"
                    .to_string(),
            ),
            // A body that states nothing states nothing.
            RemoteSignerFailure::status_body(400, "not json at all".to_string()),
        ] {
            assert_eq!(
                quota_verdict(&unrelated),
                QuotaVerdict::Unrelated,
                "{unrelated:?}"
            );
        }
    }

    /// Issue #60 (test a): the AWS backend AS a [`RawEd25519TlsSigner`] signs a TLS
    /// handshake transcript over the fake KMS transport, returning a raw 64-byte
    /// signature that VERIFIES under the SPKI it reports — the exact assertion the
    /// validated #58 build path and rustls rely on. The TLS sign path reuses the
    /// object-signing RAW-Ed25519 KMS `Sign`, keyed by the TLS key id.
    #[test]
    fn aws_backend_tls_sign_verifies_under_reported_spki() {
        let backend = AwsKmsEd25519Backend::with_client(
            Box::new(FakeKms {
                key: SigningKey::from_seed_bytes(&[23u8; 32]),
                prehash: false,
            }),
            "alias/mcp-re-tls".to_string(),
        )
        .expect("construct");
        let transcript = b"tls handshake transcript bytes";
        let sig = backend.sign_tls_ed25519(transcript).expect("tls sign");
        assert_eq!(
            sig.len(),
            64,
            "delegated TLS signature is a raw 64-byte Ed25519 sig"
        );
        // The reported SPKI is the advertised KMS public key and verifies the sig.
        let raw = crate::kms_keysource::Ed25519SpkiDer::interpret(
            &backend.tls_public_key_spki_der().unwrap(),
        )
        .unwrap()
        .raw_point();
        let key = VerificationKey::from_bytes(&raw).unwrap();
        verify_ed25519(transcript, &b64url_encode(&sig), &key).expect("tls sig verifies");
    }
}
