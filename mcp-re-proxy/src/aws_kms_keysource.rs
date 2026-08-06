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
use crate::delegated_tls::RawEd25519TlsSigner;
use crate::key_source::KeyError;
use crate::kms_keysource::ed25519_raw_point_from_spki;
use crate::kms_keysource::KmsEd25519Backend;

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
const MAX_ERROR_BODY_BYTES: u64 = 8 * 1024;

/// Read a bounded, lossy string from an HTTP error response body (diagnostics only).
fn read_error_body(resp: ureq::Response) -> String {
    let mut buf = Vec::new();
    let _ = resp
        .into_reader()
        .take(MAX_ERROR_BODY_BYTES)
        .read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// The single Ed25519 key spec and signing mode this adapter accepts.
const KEY_SPEC_ED25519: &str = "ECC_NIST_EDWARDS25519";
const SIGNING_ALGORITHM_ED25519: &str = "ED25519_SHA_512";
const MESSAGE_TYPE_RAW: &str = "RAW";

const ED25519_SIGNATURE_LEN: usize = 64;

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
    fn post_kms(&self, target: &str, body: &[u8]) -> Result<Vec<u8>, KeyError>;
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
        let url = config
            .endpoint
            .clone()
            .unwrap_or_else(|| format!("https://kms.{}.amazonaws.com", config.region));
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
    fn post_kms(&self, target: &str, body: &[u8]) -> Result<Vec<u8>, KeyError> {
        // Refresh before signing. Cheap on both sources (a `getenv`, or a cache hit
        // until the refresh margin) and on the cold KMS path only — the root is off
        // the request path — and it is what lets a re-exchanged IRSA session or a
        // rotated env pair take effect without a restart. A refresh that fails leaves
        // the last-good credentials in place: a transient failure to look must not be
        // worse than not looking, and a credential that has genuinely expired fails
        // at KMS with its own error rather than being papered over here.
        if let Ok(refreshed) = self.credential_source.credentials() {
            if let Ok(mut signer) = self.signer.write() {
                signer.set_credentials(refreshed);
            }
        }
        let signer = self
            .signer
            .read()
            .map_err(|_| KeyError::NotFound("aws-kms: credential lock poisoned".to_string()))?;
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
            .timeout(std::time::Duration::from_secs(5));
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
                    .map_err(|e| KeyError::NotFound(format!("aws-kms: read response body: {e}")))?;
                if buf.len() as u64 > MAX_KMS_RESPONSE_BYTES {
                    return Err(KeyError::Malformed(format!(
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
                let body = read_error_body(resp);
                Err(KeyError::NotFound(format!(
                    "aws-kms: {target} returned HTTP {code}: {body}"
                )))
            }
            Err(e) => Err(KeyError::NotFound(format!(
                "aws-kms: {target} transport: {e}"
            ))),
        }
    }
}

/// Extract the `host[:port]` authority a request will send (and SigV4 must sign)
/// from a `scheme://host[:port][/...]` endpoint URL.
fn authority_of(url: &str) -> Result<String, KeyError> {
    let after_scheme = url.split("://").nth(1).ok_or_else(|| {
        KeyError::Malformed(format!("aws-kms: endpoint '{url}' is not scheme://host"))
    })?;

    let mut parts = after_scheme.splitn(2, '/');
    let authority = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    if authority.is_empty() {
        return Err(KeyError::Malformed(format!(
            "aws-kms: endpoint '{url}' has no host"
        )));
    }
    if !path.is_empty() {
        return Err(KeyError::Malformed(format!(
            "aws-kms: endpoint '{url}' must not include a path"
        )));
    }

    Ok(authority.to_string())
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

/// How long the delegated-TLS path stops calling KMS after KMS has reported that the
/// account is being throttled.
///
/// The handshake path and the root-issuance path share one account quota for
/// cryptographic operations, and only the handshake path can be driven by an
/// unauthenticated peer: TLS 1.3 emits the server `CertificateVerify` — one KMS `Sign` —
/// before it has seen a client certificate, and with session resumption refused every
/// connection is a full handshake. Left alone, a connection flood spends the account's
/// quota, and the cold-path rotor's `Sign` for the next delegated credential fails with
/// it; the replica then fails closed on `delegated_signing_unavailable` when the current
/// credential's TTL runs out. A handshake flood becomes a signing outage.
///
/// So the throttle is treated as a signal about the shared quota, not as one request's
/// bad luck: for this window the handshake path refuses locally WITHOUT calling KMS,
/// leaving the quota to the issuance path. Refusing handshakes is the cheap failure —
/// a peer retries a connection; a replica that has lost response signing does not
/// recover until a credential can be minted.
const TLS_SIGN_THROTTLE_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(2);

/// A non-exporting [`KmsEd25519Backend`] backed by AWS KMS.
pub struct AwsKmsEd25519Backend {
    client: Box<dyn KmsHttpClient + Send + Sync>,
    key_id: String,
    spki_der: Vec<u8>,
    verify_key: VerificationKey,
    /// When the delegated-TLS path may call KMS again, set after KMS reported
    /// throttling. `None` outside a cooldown, which is the steady state.
    tls_cooldown_until: std::sync::Mutex<Option<std::time::Instant>>,
}

/// Does this KMS failure say the ACCOUNT is over its quota, rather than that one
/// request was malformed?
///
/// Classified from the rendered error because [`KeyError`] carries no machine-readable
/// KMS code and its taxonomy is frozen. The text it matches is produced by
/// [`UreqKmsClient::post_kms`] in this module, which interpolates the KMS JSON error
/// body verbatim — `{"__type":"ThrottlingException"}` and its siblings — and the HTTP
/// status for the gateway-level limits that never reach KMS's own error shape.
fn is_kms_throttling(error: &KeyError) -> bool {
    let rendered = format!("{error:?}");
    [
        "ThrottlingException",
        "LimitExceededException",
        "KMSInternalException",
        "TooManyRequestsException",
        "returned HTTP 429",
        "returned HTTP 503",
    ]
    .iter()
    .any(|marker| rendered.contains(marker))
}

impl AwsKmsEd25519Backend {
    /// Build over an explicit transport — fetches and validates the public key once
    /// (Ed25519 SPKI, correct key spec) and caches it for verify-before-return.
    pub(crate) fn with_client(
        client: Box<dyn KmsHttpClient + Send + Sync>,
        key_id: String,
    ) -> Result<Self, KeyError> {
        let body = get_public_key_request_body(&key_id);
        let resp = client.post_kms(TARGET_GET_PUBLIC_KEY, &body)?;
        let spki_der = parse_get_public_key_response(&resp)?;
        let raw = ed25519_raw_point_from_spki(&spki_der)?;
        let verify_key = VerificationKey::from_bytes(&raw).map_err(|e| {
            KeyError::Malformed(format!("aws-kms: invalid Ed25519 public key: {e}"))
        })?;
        Ok(AwsKmsEd25519Backend {
            client,
            key_id,
            spki_der,
            verify_key,
            tls_cooldown_until: std::sync::Mutex::new(None),
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
        Self::with_credential_source(Box::new(WebIdentityCredentialSource::new(wi)), config)
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

    /// The delegated-TLS handshake signature, at an explicit instant so the
    /// quota-preserving cooldown is provable without waiting on a clock.
    ///
    /// Inside a cooldown this refuses WITHOUT reaching KMS. See
    /// [`TLS_SIGN_THROTTLE_COOLDOWN`]: the handshake path is the one an unauthenticated
    /// peer can drive, and it shares an account quota with the delegated-credential
    /// issuance that keeps the replica able to sign responses at all.
    fn tls_sign_at(&self, message: &[u8], now: std::time::Instant) -> Result<Vec<u8>, KeyError> {
        {
            let mut cooldown = self.tls_cooldown_until.lock().map_err(|_| {
                KeyError::NotFound("aws-kms: tls cooldown lock poisoned".to_string())
            })?;
            match *cooldown {
                Some(until) if now < until => {
                    return Err(KeyError::NotFound(
                        "aws-kms: KMS is throttling this account; the delegated-TLS \
                         handshake signature is refused locally so the delegated-credential \
                         issuance keeps its share of the quota"
                            .to_string(),
                    ))
                }
                Some(_) => *cooldown = None,
                None => {}
            }
        }
        // The object-signing RAW-Ed25519 KMS `Sign` path verbatim: KMS `Sign` with
        // ED25519_SHA_512 / RAW over the handshake transcript, length-checked.
        let signed = self.sign_raw_ed25519(message);
        if let Err(error) = &signed {
            if is_kms_throttling(error) {
                if let Ok(mut cooldown) = self.tls_cooldown_until.lock() {
                    *cooldown = Some(now + TLS_SIGN_THROTTLE_COOLDOWN);
                }
            }
        }
        signed
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
    fn post_kms(&self, target: &str, body: &[u8]) -> Result<Vec<u8>, KeyError> {
        match target {
            TARGET_GET_PUBLIC_KEY => {
                let mut der = crate::kms_keysource::ED25519_SPKI_PREFIX.to_vec();
                der.extend_from_slice(&self.key.public_key().to_bytes());
                Ok(serde_json::json!({
                    "KeySpec": KEY_SPEC_ED25519,
                    "PublicKey": STANDARD.encode(&der),
                })
                .to_string()
                .into_bytes())
            }
            TARGET_SIGN => {
                let v: serde_json::Value = serde_json::from_slice(body)
                    .map_err(|e| KeyError::Malformed(format!("fake kms: Sign body: {e}")))?;
                let msg = STANDARD
                    .decode(v.get("Message").and_then(|m| m.as_str()).unwrap_or(""))
                    .map_err(|e| KeyError::Malformed(format!("fake kms: Message b64: {e}")))?;
                let raw = mcp_re_core::b64url_decode(&self.key.sign(&msg))
                    .map_err(|e| KeyError::Malformed(format!("fake kms: sign: {e}")))?;
                Ok(serde_json::json!({
                    "Signature": STANDARD.encode(&raw),
                    "SigningAlgorithm": SIGNING_ALGORITHM_ED25519,
                })
                .to_string()
                .into_bytes())
            }
            other => Err(KeyError::Malformed(format!(
                "fake kms: unexpected target {other}"
            ))),
        }
    }
}

impl KmsEd25519Backend for AwsKmsEd25519Backend {
    fn sign_raw_ed25519(&self, preimage: &[u8]) -> Result<Vec<u8>, KeyError> {
        let body = sign_request_body(&self.key_id, preimage);
        let resp = self.client.post_kms(TARGET_SIGN, &body)?;
        let signature = parse_sign_response(&resp)?;
        if signature.len() != ED25519_SIGNATURE_LEN {
            return Err(KeyError::Malformed(format!(
                "aws-kms: Sign returned a {}-byte signature; expected a raw {ED25519_SIGNATURE_LEN}-byte Ed25519 signature",
                signature.len()
            )));
        }
        // VERIFY-BEFORE-RETURN (ADR-MCPS-028 §D / guardrail): the signature MUST
        // verify against the advertised public key under the unmodified mcp-re-core
        // verifier. This catches a misconfigured DIGEST/prehash KMS key, a key
        // mismatch, or any corruption — fail closed, never emit it.
        verify_ed25519(preimage, &b64url_encode(&signature), &self.verify_key).map_err(|e| {
            KeyError::Malformed(format!(
                "aws-kms: KMS signature did NOT verify against the advertised public key \
                 (misconfigured DIGEST/prehash key or key mismatch?): {e}"
            ))
        })?;
        Ok(signature)
    }

    fn public_key_spki_der(&self) -> Result<Vec<u8>, KeyError> {
        Ok(self.spki_der.clone())
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
        self.tls_sign_at(message, std::time::Instant::now())
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
    use crate::kms_keysource::ED25519_SPKI_PREFIX;

    fn spki_from_raw(raw: &[u8; 32]) -> Vec<u8> {
        let mut der = ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(raw);
        der
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
        fn post_kms(&self, target: &str, body: &[u8]) -> Result<Vec<u8>, KeyError> {
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
        let sig = backend.sign_raw_ed25519(preimage).expect("sign");
        assert_eq!(sig.len(), 64);
        // The advertised SPKI parses to the same verify key.
        let raw = ed25519_raw_point_from_spki(&backend.public_key_spki_der().unwrap()).unwrap();
        let key = VerificationKey::from_bytes(&raw).unwrap();
        verify_ed25519(preimage, &b64url_encode(&sig), &key).expect("verifies");
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
            .sign_raw_ed25519(b"mcp-re canonical response preimage")
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
        fn post_kms(&self, target: &str, _body: &[u8]) -> Result<Vec<u8>, KeyError> {
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
                    // The shape `post_kms` renders for a KMS error response.
                    Err(KeyError::NotFound(format!(
                        "aws-kms: {target} returned HTTP 400: \
                         {{\"__type\":\"ThrottlingException\"}}"
                    )))
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
            .tls_sign_at(b"transcript", start)
            .expect_err("KMS is throttling");
        assert_eq!(signs(), 1, "the first handshake does reach KMS");

        for _ in 0..20 {
            backend
                .tls_sign_at(b"transcript", start + std::time::Duration::from_millis(1))
                .expect_err("refused locally");
        }
        assert_eq!(
            signs(),
            1,
            "a handshake flood inside the cooldown must not convert into KMS calls"
        );

        backend
            .tls_sign_at(b"transcript", start + TLS_SIGN_THROTTLE_COOLDOWN)
            .expect_err("KMS is still throttling");
        assert_eq!(signs(), 2, "past the cooldown the path probes KMS again");
    }

    /// The classifier must fire on the account-quota failures and NOT on an ordinary
    /// per-request refusal, which says nothing about the shared quota.
    #[test]
    fn only_quota_failures_open_the_cooldown() {
        for throttling in [
            "aws-kms: TrentService.Sign returned HTTP 400: {\"__type\":\"ThrottlingException\"}",
            "aws-kms: TrentService.Sign returned HTTP 400: {\"__type\":\"LimitExceededException\"}",
            "aws-kms: TrentService.Sign returned HTTP 429: slow down",
        ] {
            assert!(
                is_kms_throttling(&KeyError::NotFound(throttling.to_string())),
                "{throttling}"
            );
        }
        for other in [
            "aws-kms: TrentService.Sign returned HTTP 400: {\"__type\":\"AccessDeniedException\"}",
            "aws-kms: TrentService.Sign transport: connection refused",
        ] {
            assert!(
                !is_kms_throttling(&KeyError::NotFound(other.to_string())),
                "{other}"
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
        let raw = ed25519_raw_point_from_spki(&backend.tls_public_key_spki_der().unwrap()).unwrap();
        let key = VerificationKey::from_bytes(&raw).unwrap();
        verify_ed25519(transcript, &b64url_encode(&sig), &key).expect("tls sig verifies");
    }
}
