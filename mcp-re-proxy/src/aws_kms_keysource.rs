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
    fn post_kms(&self, target: &str, body: &[u8]) -> Result<Vec<u8>, KeyError> {
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
const TLS_SIGN_THROTTLE_COOLDOWN: std::time::Duration = NETWORK_TIMEOUT;

/// MANDATORY per-request network timeout on the KMS calls below. The serve loop is
/// blocking, so an unbounded call (stalled connect/TLS handshake) would wedge the serving
/// thread indefinitely. Named here because [`TLS_SIGN_THROTTLE_COOLDOWN`] is defined
/// against it: a window opened in reaction to a call that may have taken this long must be
/// at least this long, or it is installed already elapsed.
const NETWORK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

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

    /// The delegated-TLS handshake signature, at an explicit instant so the
    /// quota-preserving cooldown is provable without waiting on a clock.
    ///
    /// Inside a cooldown this refuses WITHOUT reaching KMS. See
    /// [`TLS_SIGN_THROTTLE_COOLDOWN`]: the handshake path is the one an unauthenticated
    /// peer can drive, and it shares an account quota with the delegated-credential
    /// issuance that keeps the replica able to sign responses at all.
    /// Open a throttle window ending [`TLS_SIGN_THROTTLE_COOLDOWN`] after `now`, never
    /// SHORTENING one already in force.
    ///
    /// `now` MUST be a clock reading taken AFTER the call being reacted to. That is what
    /// keeps the window from being installed stale: it was previously the handshake's ENTRY
    /// instant, so a KMS call slower than the cooldown opened a window that had already
    /// elapsed — no throttle at all, precisely when KMS was slow enough to need one.
    ///
    /// `max` is a narrower guarantee than it looks: it stops a thread REPLACING a longer
    /// window with a shorter one, which is what plain assignment did when two threads
    /// reported failures out of order. It does NOT sanitise a stale reading — on the `None`
    /// branch, the steady state and the state a successful probe leaves, whatever `until`
    /// it is handed is installed outright. Freshness comes from the caller reading the
    /// clock here, not from `max`.
    fn arm_cooldown(&self, now: std::time::Instant) {
        let mut cooldown = self
            .tls_cooldown_until
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let until = now + TLS_SIGN_THROTTLE_COOLDOWN;
        *cooldown = Some(cooldown.map_or(until, |current| current.max(until)));
    }

    /// The delegated-TLS handshake signature, against an explicit clock so the
    /// quota-preserving cooldown is provable without waiting on one.
    ///
    /// Inside a cooldown this refuses WITHOUT reaching KMS. `clock` is read TWICE and the
    /// distinction is load-bearing: once at the gate, to decide whether this handshake may
    /// reach KMS, and again AFTER the call, to open a window that reacts to when the call
    /// finished rather than to when the handshake arrived.
    fn tls_sign_at(
        &self,
        message: &[u8],
        clock: &dyn Fn() -> std::time::Instant,
    ) -> Result<Vec<u8>, KeyError> {
        let now = clock();
        // Whether THIS thread is the one probing a lapsed window. Only the thread that
        // observes the lapse takes the probe: it re-arms the window before releasing the
        // lock, so the rest of a concurrent handshake cohort at the boundary is still
        // refused instead of all calling KMS at once — which is the flood the
        // window exists to stop, arriving one cooldown late.
        let probing = {
            // Poison recovery, not propagation: the state is one whole-value swap, and a
            // sticky lock error here would refuse every later handshake signature for the
            // process lifetime — a far worse failure than the throttle it guards against.
            let mut cooldown = self
                .tls_cooldown_until
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            match *cooldown {
                Some(until) if now < until => {
                    return Err(KeyError::NotFound(
                        "aws-kms: KMS is throttling this account; the delegated-TLS \
                         handshake signature is refused locally so the delegated-credential \
                         issuance keeps its share of the quota"
                            .to_string(),
                    ))
                }
                Some(_) => {
                    *cooldown = Some(now + TLS_SIGN_THROTTLE_COOLDOWN);
                    true
                }
                None => false,
            }
        };
        // The object-signing RAW-Ed25519 sign path verbatim over the handshake transcript,
        // length-checked + verified.
        let signed = self.sign_raw_ed25519(message);
        match &signed {
            Ok(_) if probing => {
                // The probe went through: the quota is available again, so reopen the path
                // rather than leaving the window this thread armed to run its course.
                *self
                    .tls_cooldown_until
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = None;
            }
            // Armed from a reading taken NOW, after the call — not from the entry instant.
            Err(error) if is_kms_throttling(error) => self.arm_cooldown(clock()),
            _ => {}
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

    /// The AWS twin of the GCP mutex-poison property: one panic anywhere under these
    /// locks must not remove AWS KMS signing from the replica for the rest of the process.
    ///
    /// Poison is sticky. The `signer` read take and the handshake cooldown both used to
    /// map it to a hard `KeyError`, so a single panic turned every later `post_kms` and
    /// every later handshake signature into a permanent failure — the delegated rotor then
    /// cannot mint a successor and the replica fails closed at the current key's `exp`.
    /// Neither lock protects an invariant: both guard whole-value swaps.
    #[test]
    fn a_poisoned_signer_or_cooldown_lock_still_signs() {
        let backend = AwsKmsEd25519Backend::with_client(
            Box::new(FakeKms {
                key: SigningKey::from_seed_bytes(&[19u8; 32]),
                prehash: false,
            }),
            "alias/mcp-re".to_string(),
        )
        .expect("construct");
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = backend.tls_cooldown_until.lock().expect("not yet poisoned");
            panic!("poisoning the cooldown on purpose");
        }));
        assert!(
            backend.tls_cooldown_until.lock().is_err(),
            "the cooldown lock must now be poisoned"
        );
        let sig = backend
            .tls_sign_at(b"transcript", &std::time::Instant::now)
            .expect("a poisoned cooldown lock must not refuse the handshake");
        assert_eq!(sig.len(), 64);

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
            .tls_sign_at(b"transcript", &|| start + TLS_SIGN_THROTTLE_COOLDOWN)
            .expect_err("KMS is still throttling");
        assert_eq!(signs(), 2, "past the cooldown the path probes KMS again");
    }

    /// The classifier must fire on the account-quota failures and NOT on an ordinary
    /// A throttling transport whose call TAKES LONGER THAN THE WINDOW, which is the regime
    /// the window exists for and the one a fast fake cannot reach.
    struct SlowThrottlingKms {
        key: SigningKey,
        signs: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        call_time: std::time::Duration,
    }
    impl KmsHttpClient for SlowThrottlingKms {
        fn post_kms(&self, target: &str, _body: &[u8]) -> Result<Vec<u8>, KeyError> {
            if target == TARGET_GET_PUBLIC_KEY {
                let der = spki_from_raw(&self.key.public_key().to_bytes());
                return Ok(serde_json::json!({
                    "KeySpec": KEY_SPEC_ED25519,
                    "PublicKey": STANDARD.encode(&der),
                })
                .to_string()
                .into_bytes());
            }
            self.signs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(self.call_time);
            Err(KeyError::NotFound(
                "aws-kms: Sign returned HTTP 400: ThrottlingException".to_string(),
            ))
        }
    }

    fn slow_throttling_backend(
        counter: &std::sync::Arc<std::sync::atomic::AtomicUsize>,
        call_time: std::time::Duration,
    ) -> AwsKmsEd25519Backend {
        AwsKmsEd25519Backend::with_client(
            Box::new(SlowThrottlingKms {
                key: SigningKey::from_seed_bytes(&[71u8; 32]),
                signs: std::sync::Arc::clone(counter),
                call_time,
            }),
            "alias/mcp-re".to_string(),
        )
        .expect("construct")
    }

    /// The window must be armed from a reading taken AFTER the call, and must outlast the
    /// call it reacts to.
    ///
    /// Armed from the handshake's ENTRY instant with a 2s window against a 5s timeout, any
    /// KMS call slower than 2s installed a window that had ALREADY elapsed — no throttle at
    /// all, in exactly the regime the throttle exists for. The AWS twin carried this with
    /// no coverage at all.
    #[test]
    fn a_slow_throttled_call_still_opens_a_live_window() {
        assert!(
            TLS_SIGN_THROTTLE_COOLDOWN >= NETWORK_TIMEOUT,
            "a {TLS_SIGN_THROTTLE_COOLDOWN:?} window cannot survive a call that may take \
             {NETWORK_TIMEOUT:?}"
        );
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        // A call that takes longer than the whole window.
        let slow = TLS_SIGN_THROTTLE_COOLDOWN + std::time::Duration::from_millis(20);
        let backend = slow_throttling_backend(&counter, slow);
        let entry = std::time::Instant::now();
        // The clock advances by `slow` across the call, exactly as the real one would.
        let reads = std::sync::atomic::AtomicUsize::new(0);
        let clock = || {
            if reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                entry
            } else {
                entry + slow
            }
        };
        backend
            .tls_sign_at(b"transcript", &clock)
            .expect_err("KMS is throttling");
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
        // A handshake arriving just after the call finished must be REFUSED. Armed from the
        // entry instant the window would already have expired and this would reach KMS.
        backend
            .tls_sign_at(b"transcript", &|| {
                entry + slow + std::time::Duration::from_millis(1)
            })
            .expect_err("the window opened by the slow call must still be in force");
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a window armed from the entry instant is dead on arrival after a slow call"
        );
    }

    /// At the boundary exactly ONE handshake probes KMS.
    #[test]
    fn only_one_handshake_probes_at_the_cooldown_boundary() {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let backend = std::sync::Arc::new(slow_throttling_backend(
            &counter,
            TLS_SIGN_THROTTLE_COOLDOWN + std::time::Duration::from_millis(20),
        ));
        let start = std::time::Instant::now();
        backend
            .tls_sign_at(b"transcript", &|| start)
            .expect_err("throttling");
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
        let boundary = start + TLS_SIGN_THROTTLE_COOLDOWN;
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let backend = std::sync::Arc::clone(&backend);
                std::thread::spawn(move || {
                    let _ = backend.tls_sign_at(b"transcript", &|| boundary);
                })
            })
            .collect();
        for t in threads {
            t.join().expect("joined");
        }
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "the boundary must admit ONE probe, not the whole cohort"
        );
    }

    /// A straggler reporting an OLD failure must not shorten the window in force.
    #[test]
    fn a_straggler_cannot_shorten_the_cooldown_window() {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let backend = AwsKmsEd25519Backend::with_client(
            Box::new(ThrottlingKms {
                key: SigningKey::from_seed_bytes(&[72u8; 32]),
                signs: std::sync::Arc::clone(&counter),
            }),
            "alias/mcp-re".to_string(),
        )
        .expect("construct");
        let start = std::time::Instant::now();
        let later = start + std::time::Duration::from_secs(30);
        backend.arm_cooldown(later);
        backend.arm_cooldown(start);
        let between = start + TLS_SIGN_THROTTLE_COOLDOWN + std::time::Duration::from_secs(1);
        backend
            .tls_sign_at(b"transcript", &|| between)
            .expect_err("still inside the window the later thread opened");
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a straggler's stale window must not reopen the handshake path"
        );
        backend
            .tls_sign_at(b"transcript", &|| later + TLS_SIGN_THROTTLE_COOLDOWN)
            .expect_err("KMS is still throttling");
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "past the real window the path must probe"
        );
    }

    /// POSITIVE CONTROL: a probe that SUCCEEDS reopens the path at once, so re-arming
    /// before probing cannot turn one throttle into a permanent stutter.
    #[test]
    fn a_successful_probe_reopens_the_handshake_path_at_once() {
        struct HealingKms {
            key: SigningKey,
            healed: std::sync::Arc<std::sync::atomic::AtomicBool>,
            signs: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        }
        impl KmsHttpClient for HealingKms {
            fn post_kms(&self, target: &str, body: &[u8]) -> Result<Vec<u8>, KeyError> {
                if target == TARGET_GET_PUBLIC_KEY {
                    let der = spki_from_raw(&self.key.public_key().to_bytes());
                    return Ok(serde_json::json!({
                        "KeySpec": KEY_SPEC_ED25519,
                        "PublicKey": STANDARD.encode(&der),
                    })
                    .to_string()
                    .into_bytes());
                }
                self.signs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if !self.healed.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err(KeyError::NotFound(
                        "aws-kms: Sign returned HTTP 400: ThrottlingException".to_string(),
                    ));
                }
                let v: serde_json::Value = serde_json::from_slice(body).expect("body");
                let msg = STANDARD
                    .decode(v.get("Message").and_then(|m| m.as_str()).unwrap_or(""))
                    .expect("b64");
                let raw = b64url_decode(&self.key.sign(&msg)).expect("sign");
                Ok(serde_json::json!({
                    "Signature": STANDARD.encode(&raw),
                    "SigningAlgorithm": SIGNING_ALGORITHM_ED25519,
                })
                .to_string()
                .into_bytes())
            }
        }
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let healed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let backend = AwsKmsEd25519Backend::with_client(
            Box::new(HealingKms {
                key: SigningKey::from_seed_bytes(&[73u8; 32]),
                healed: std::sync::Arc::clone(&healed),
                signs: std::sync::Arc::clone(&counter),
            }),
            "alias/mcp-re".to_string(),
        )
        .expect("construct");
        let start = std::time::Instant::now();
        backend
            .tls_sign_at(b"transcript", &|| start)
            .expect_err("throttled");
        healed.store(true, std::sync::atomic::Ordering::SeqCst);
        let boundary = start + TLS_SIGN_THROTTLE_COOLDOWN;
        backend
            .tls_sign_at(b"transcript", &|| boundary)
            .expect("the probe succeeds");
        let before = counter.load(std::sync::atomic::Ordering::SeqCst);
        for _ in 0..5 {
            backend
                .tls_sign_at(b"transcript", &|| {
                    boundary + std::time::Duration::from_millis(1)
                })
                .expect("the path is open again");
        }
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            before + 5,
            "after a successful probe every handshake must reach KMS again"
        );
    }

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
