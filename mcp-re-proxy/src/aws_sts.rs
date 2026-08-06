//! AWS credential sources for the KMS adapter (ADR-MCPS-028 §B).
//!
//! Two, behind one trait, selected explicitly by the operator:
//!
//! * [`EnvCredentialSource`] — the narrow static/temporary pair from
//!   `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`.
//! * [`WebIdentityCredentialSource`] — **IRSA**: the projected Kubernetes service
//!   account token at `AWS_WEB_IDENTITY_TOKEN_FILE` is exchanged for temporary
//!   credentials via STS `AssumeRoleWithWebIdentity`, so no long-lived IAM key
//!   material exists in the pod at all.
//!
//! IRSA is the AWS counterpart of the GKE workload-identity path in
//! [`crate::gcp_kms_keysource`], and exists for the same reason: an EKS deployment
//! that mounts a static IAM key pair holds a non-expiring credential that authorizes
//! KMS `Sign` for as long as the Secret exists. Under IRSA the pod holds only a
//! short-lived OIDC assertion that names it, and every credential derived from it
//! expires on its own.
//!
//! # Why the exchange is not SigV4-signed
//!
//! `AssumeRoleWithWebIdentity` is the one STS action that takes **no** AWS
//! credentials — it is authenticated by the web identity token in the body, which is
//! the whole point: it is the call a workload with no AWS credentials makes to get
//! some. So this module deliberately does not touch [`crate::aws_sigv4`]. Every call
//! *after* it, in [`crate::aws_kms_keysource`], is signed with what it returns.
//!
//! # Fail-closed posture
//!
//! * Selection is explicit (`--aws-kms-use-web-identity`). There is no discovery
//!   chain and no fallback: a web-identity source that cannot mint credentials
//!   returns an error, it never silently degrades to whatever is in the environment.
//! * The token file is re-read on **every** exchange. `kubelet` rewrites the
//!   projected token in place well before expiry; a token cached at construction is
//!   a token that stops working mid-run.
//! * The response body and every error body are length-bounded, and the whole call
//!   is under a network timeout, because this runs on a blocking thread.
//! * An unparseable or absent `Expiration` is treated as **already expired** rather
//!   than as "good until further notice", which forces a re-exchange on the next use.

use std::io::Read;
use std::sync::Mutex;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use zeroize::Zeroizing;

use crate::aws_sigv4::AwsCredentials;
use crate::key_source::KeyError;

/// Refresh a credential this long before its stated expiry. Matches the GCP
/// sibling's `TOKEN_REFRESH_MARGIN`: enough that an in-flight KMS call cannot be
/// signed with a credential that expires before it lands.
const CREDENTIAL_REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// Timeout on the STS exchange. Matches the GCP sibling's `NETWORK_TIMEOUT`; this
/// runs on a blocking thread, so an endpoint that never answers must not wedge it.
const NETWORK_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on an `AssumeRoleWithWebIdentity` success body. A real response is a
/// few KB; the cap stops a substituted endpoint streaming an unbounded body into the
/// blocking thread.
const MAX_STS_RESPONSE_BYTES: u64 = 256 * 1024;

/// Cap on an STS *error* body read, which is interpolated into a [`KeyError`].
const MAX_ERROR_BODY_BYTES: u64 = 8 * 1024;

/// Upper bound on the projected service-account token read from disk. A JWT is well
/// under this; the cap stops a hostile or misconfigured mount handing us a huge file
/// to hold in memory and post.
const MAX_TOKEN_FILE_BYTES: u64 = 64 * 1024;

/// Requested session length. AWS clamps this to the role's `MaxSessionDuration`, and
/// the value we cache comes from the response's `Expiration`, never from this.
const REQUESTED_DURATION_SECS: u32 = 3600;

/// The STS API version the query protocol requires.
const STS_API_VERSION: &str = "2011-06-15";

/// How long a credential whose response carried NO usable `Expiration` is reused.
///
/// An absent, unparseable or already-past `Expiration` parses to `UNIX_EPOCH`, which no
/// cache gate can ever satisfy — so without a floor every KMS operation performs its
/// own `AssumeRoleWithWebIdentity`. The module used to call that affordable because the
/// KMS path is cold; under delegated TLS it is one STS exchange per TLS handshake,
/// driven by unauthenticated connections, against a far tighter quota than KMS `Sign`,
/// and STS throttling then also stops the cold-path rotor refreshing credentials.
///
/// The floor is not a guess at the credential's life. `AssumeRoleWithWebIdentity`
/// refuses a `DurationSeconds` below 900, so a session AWS has just issued is valid for
/// at least that long whatever the response said, and this window is well inside it. It
/// applies ONLY when the stated expiry is at or before the exchange instant: a real
/// expiry, including one about to lapse, is never extended.
const UNKNOWN_EXPIRY_REUSE: Duration = Duration::from_secs(300);

/// Default session name when `AWS_ROLE_SESSION_NAME` is unset. It lands in
/// CloudTrail as the assumed-role session, so it names the software, not the pod:
/// a per-pod name would make every replica a distinct principal in the audit trail
/// for no gain.
const DEFAULT_SESSION_NAME: &str = "mcp-re-proxy";

/// A source of AWS credentials for the KMS adapter.
///
/// Implementations must be cheap enough to call on every KMS operation — the KMS
/// path is the cold path (the root is off the request path under ADR-MCPRE-052), but
/// it is still not a place to do a network round trip per call. Both implementations
/// here are a `getenv` or a cache hit in the common case.
pub trait AwsCredentialSource: Send + Sync {
    fn credentials(&self) -> Result<AwsCredentials, KeyError>;

    /// One line for the startup banner, so an operator can see which custody path a
    /// running proxy actually took rather than which one they meant to configure.
    fn describe(&self) -> String;
}

/// Static or STS credentials from the narrow, explicit environment-variable set.
pub struct EnvCredentialSource;

impl EnvCredentialSource {
    /// Read credentials from the explicit, NARROW set of environment variables
    /// (ADR-MCPS-028 credential scope). No profile/IMDS/SDK-chain discovery — that
    /// remains a deliberate non-feature. A session token is honoured when present,
    /// which is what lets an externally-refreshed STS pair work here.
    fn from_env() -> Result<AwsCredentials, KeyError> {
        let access_key_id = std::env::var("AWS_ACCESS_KEY_ID")
            .map_err(|_| KeyError::NotFound("aws-kms: AWS_ACCESS_KEY_ID not set".to_string()))?;
        let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY").map_err(|_| {
            KeyError::NotFound("aws-kms: AWS_SECRET_ACCESS_KEY not set".to_string())
        })?;
        Ok(AwsCredentials {
            access_key_id,
            secret_access_key: Zeroizing::new(secret_access_key),
            session_token: std::env::var("AWS_SESSION_TOKEN")
                .map(Zeroizing::new)
                .ok()
                .filter(|s| !s.is_empty()),
        })
    }
}

impl AwsCredentialSource for EnvCredentialSource {
    fn credentials(&self) -> Result<AwsCredentials, KeyError> {
        Self::from_env()
    }

    fn describe(&self) -> String {
        "env (AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY[/AWS_SESSION_TOKEN])".to_string()
    }
}

/// The IRSA inputs, read from the environment EKS populates on a pod whose service
/// account carries an `eks.amazonaws.com/role-arn` annotation.
///
/// `Debug` is safe to derive here and only here: none of these fields is a secret.
/// The role ARN and the token *path* are configuration; the token itself is read
/// from that path per exchange and never stored on this struct.
#[derive(Debug)]
pub struct WebIdentityConfig {
    pub role_arn: String,
    pub token_file: String,
    pub session_name: String,
    /// Overridable for tests; defaults to the REGIONAL endpoint
    /// `https://sts.<region>.amazonaws.com`.
    pub endpoint: String,
}

impl WebIdentityConfig {
    /// Read the IRSA environment. `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE`
    /// are both required and neither has a default: their absence means the pod is
    /// not running under IRSA, which is an operator error to report, not a condition
    /// to work around.
    ///
    /// The endpoint is regional by default. The global `sts.amazonaws.com` is a
    /// single region's availability wearing a global name, and its credentials are
    /// not valid in opt-in regions.
    pub fn from_env(region: &str, endpoint: Option<String>) -> Result<Self, KeyError> {
        // Before anything else, and only on the path that derives the endpoint from it:
        // the region decides which host receives the projected token.
        if endpoint.is_none() {
            validate_region(region)?;
        }
        let role_arn = std::env::var("AWS_ROLE_ARN").map_err(|_| {
            KeyError::NotFound(
                "aws-kms: --aws-kms-use-web-identity needs AWS_ROLE_ARN (set by EKS on a \
                 service account annotated with eks.amazonaws.com/role-arn)"
                    .to_string(),
            )
        })?;
        let token_file = std::env::var("AWS_WEB_IDENTITY_TOKEN_FILE").map_err(|_| {
            KeyError::NotFound(
                "aws-kms: --aws-kms-use-web-identity needs AWS_WEB_IDENTITY_TOKEN_FILE (the \
                 projected service-account token EKS mounts under IRSA)"
                    .to_string(),
            )
        })?;
        if role_arn.is_empty() {
            return Err(KeyError::Malformed(
                "aws-kms: AWS_ROLE_ARN is set but empty".to_string(),
            ));
        }
        if token_file.is_empty() {
            return Err(KeyError::Malformed(
                "aws-kms: AWS_WEB_IDENTITY_TOKEN_FILE is set but empty".to_string(),
            ));
        }
        let session_name = std::env::var("AWS_ROLE_SESSION_NAME")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_SESSION_NAME.to_string());
        validate_session_name(&session_name)?;
        let endpoint = endpoint.unwrap_or_else(|| format!("https://sts.{region}.amazonaws.com"));
        Ok(WebIdentityConfig {
            role_arn,
            token_file,
            session_name,
            endpoint,
        })
    }
}

/// An AWS region label: lowercase letters, digits and hyphens, e.g. `eu-north-1`.
///
/// Checked before it is interpolated into the STS endpoint, because the interpolation
/// decides WHO receives the pod's OIDC assertion. A region carrying `/`, `@`, `:`, `#`
/// or `?` re-points `https://sts.{region}.amazonaws.com` at an attacker-chosen
/// authority — `evil.example.com/` alone is enough — and whoever receives that
/// assertion can assume the IRSA role and obtain KMS `Sign` on the root
/// response-signing key. The explicit `--aws-sts-endpoint` and `--gcp-kms-endpoint`
/// overrides are validated for the same reason; the region-derived URL is the one path
/// that reaches an authority without an operator having typed it.
fn validate_region(region: &str) -> Result<(), KeyError> {
    if region.is_empty() {
        return Err(KeyError::Malformed(
            "aws-kms: --aws-kms-region is empty, so the STS endpoint would resolve to \
             https://sts..amazonaws.com"
                .to_string(),
        ));
    }
    if let Some(bad) = region
        .chars()
        .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-'))
    {
        return Err(KeyError::Malformed(format!(
            "aws-kms: --aws-kms-region {region:?} is not an AWS region label \
             ([a-z0-9-]); it is interpolated into the STS endpoint, so a character \
             like {bad:?} sends this pod's web identity token to another host"
        )));
    }
    Ok(())
}

/// STS accepts `[\w+=,.@-]{2,64}` for a role session name. Rejecting here rather
/// than letting STS reject turns a silent per-call failure into one startup error,
/// and keeps an operator-supplied value out of the request body unvalidated.
fn validate_session_name(name: &str) -> Result<(), KeyError> {
    if !(2..=64).contains(&name.len()) {
        return Err(KeyError::Malformed(format!(
            "aws-kms: AWS_ROLE_SESSION_NAME must be 2-64 characters, got {}",
            name.len()
        )));
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || "+=,.@-_".contains(*c)))
    {
        return Err(KeyError::Malformed(format!(
            "aws-kms: AWS_ROLE_SESSION_NAME may only contain [A-Za-z0-9+=,.@-_], got {bad:?}"
        )));
    }
    Ok(())
}

struct CachedCredentials {
    credentials: AwsCredentials,
    expires_at: SystemTime,
}

/// Hand-written so a secret cannot reach a log through a derived `Debug`.
///
/// `AwsCredentials` holds `Zeroizing<String>`, whose own `Debug` prints the wrapped
/// string verbatim — so `#[derive(Debug)]` here would put a live KMS-signing
/// credential into any format string that touched it, including a test failure
/// message or a `KeyError` chain. The access key id is deliberately kept: it is an
/// identifier AWS itself puts in CloudTrail, and it is the field that makes a
/// "wrong credentials" report actionable.
impl std::fmt::Debug for CachedCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedCredentials")
            .field("access_key_id", &self.credentials.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &if self.credentials.session_token.is_some() {
                    "<redacted>"
                } else {
                    "<none>"
                },
            )
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// IRSA: exchange the projected service-account token for temporary credentials.
pub struct WebIdentityCredentialSource {
    agent: ureq::Agent,
    config: WebIdentityConfig,
    cache: Mutex<Option<CachedCredentials>>,
    /// Held across an exchange so concurrent callers coalesce onto one.
    ///
    /// The cache lock is deliberately NOT held across the round trip — that would put a
    /// 5-second network call under a lock every KMS operation takes. This one is, and
    /// the cache is re-read after acquiring it, so a burst of callers that all miss the
    /// cache produces a single `AssumeRoleWithWebIdentity` rather than one each.
    exchanging: Mutex<()>,
}

impl WebIdentityCredentialSource {
    pub fn new(config: WebIdentityConfig) -> Self {
        WebIdentityCredentialSource {
            agent: ureq::AgentBuilder::new().build(),
            config,
            cache: Mutex::new(None),
            exchanging: Mutex::new(()),
        }
    }

    /// The cached credentials, if they are still fresh enough to sign with.
    fn cached(&self, now: SystemTime) -> Result<Option<AwsCredentials>, KeyError> {
        let cache = self
            .cache
            .lock()
            .map_err(|e| KeyError::NotFound(format!("aws-kms: credential cache poisoned: {e}")))?;
        Ok(cache.as_ref().and_then(|c| {
            (now + CREDENTIAL_REFRESH_MARGIN < c.expires_at).then(|| c.credentials.clone())
        }))
    }

    /// Serve the cached credentials, or run ONE exchange and cache what it returns.
    ///
    /// `exchange` is a parameter so the single-flight and the reuse floor are provable
    /// without an STS endpoint.
    fn cached_or_exchange(
        &self,
        now: SystemTime,
        exchange: &dyn Fn() -> Result<CachedCredentials, KeyError>,
    ) -> Result<AwsCredentials, KeyError> {
        if let Some(credentials) = self.cached(now)? {
            return Ok(credentials);
        }
        let _flight = self.exchanging.lock().map_err(|e| {
            KeyError::NotFound(format!("aws-kms: credential exchange poisoned: {e}"))
        })?;
        // Whoever held this lock may have just filled the cache.
        if let Some(credentials) = self.cached(now)? {
            return Ok(credentials);
        }
        let mut fresh = exchange()?;
        // A credential that is already expired the instant it was issued is one whose
        // `Expiration` could not be read, not one AWS has stopped honouring. Reusing it
        // briefly is what stops a response-shape drift turning every KMS call — and so
        // every delegated-TLS handshake — into its own STS round trip.
        if fresh.expires_at <= now {
            fresh.expires_at = now + UNKNOWN_EXPIRY_REUSE;
        }
        let credentials = fresh.credentials.clone();
        let mut cache = self
            .cache
            .lock()
            .map_err(|e| KeyError::NotFound(format!("aws-kms: credential cache poisoned: {e}")))?;
        *cache = Some(fresh);
        Ok(credentials)
    }

    /// Read the projected token from disk. Done on every exchange, never cached:
    /// `kubelet` rewrites this file in place as the token approaches expiry, so the
    /// copy read at construction is the one that stops working.
    fn read_token(&self) -> Result<Zeroizing<String>, KeyError> {
        let file = std::fs::File::open(&self.config.token_file).map_err(|e| {
            KeyError::NotFound(format!(
                "aws-kms: open web identity token {}: {e}",
                self.config.token_file
            ))
        })?;
        let mut buf = String::new();
        std::io::BufReader::new(file)
            .take(MAX_TOKEN_FILE_BYTES)
            .read_to_string(&mut buf)
            .map_err(|e| {
                KeyError::NotFound(format!(
                    "aws-kms: read web identity token {}: {e}",
                    self.config.token_file
                ))
            })?;
        let token = Zeroizing::new(buf.trim().to_string());
        if token.is_empty() {
            return Err(KeyError::Malformed(format!(
                "aws-kms: web identity token {} is empty",
                self.config.token_file
            )));
        }
        Ok(token)
    }

    /// One `AssumeRoleWithWebIdentity` round trip. Unsigned by design — see the
    /// module docs.
    fn exchange(&self) -> Result<CachedCredentials, KeyError> {
        let token = self.read_token()?;
        let body = Zeroizing::new(format!(
            "Action=AssumeRoleWithWebIdentity&Version={}&DurationSeconds={}\
             &RoleArn={}&RoleSessionName={}&WebIdentityToken={}",
            STS_API_VERSION,
            REQUESTED_DURATION_SECS,
            form_encode(&self.config.role_arn),
            form_encode(&self.config.session_name),
            form_encode(&token),
        ));
        let response = self
            .agent
            .post(&self.config.endpoint)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .set("Accept", "application/xml")
            .timeout(NETWORK_TIMEOUT)
            .send_string(&body);
        let xml = match response {
            Ok(resp) => {
                let mut buf = Vec::new();
                resp.into_reader()
                    .take(MAX_STS_RESPONSE_BYTES)
                    .read_to_end(&mut buf)
                    .map_err(|e| KeyError::NotFound(format!("aws-kms: read STS response: {e}")))?;
                Zeroizing::new(String::from_utf8_lossy(&buf).into_owned())
            }
            Err(ureq::Error::Status(code, resp)) => {
                let mut buf = Vec::new();
                let _ = resp
                    .into_reader()
                    .take(MAX_ERROR_BODY_BYTES)
                    .read_to_end(&mut buf);
                return Err(KeyError::NotFound(format!(
                    "aws-kms: AssumeRoleWithWebIdentity for {} failed: HTTP {code}: {}",
                    self.config.role_arn,
                    String::from_utf8_lossy(&buf)
                )));
            }
            Err(e) => {
                return Err(KeyError::NotFound(format!(
                    "aws-kms: AssumeRoleWithWebIdentity transport: {e}"
                )))
            }
        };
        parse_assume_role_response(&xml)
    }
}

impl AwsCredentialSource for WebIdentityCredentialSource {
    fn credentials(&self) -> Result<AwsCredentials, KeyError> {
        self.cached_or_exchange(SystemTime::now(), &|| self.exchange())
    }

    fn describe(&self) -> String {
        format!(
            "web identity / IRSA (role {}, token {})",
            self.config.role_arn, self.config.token_file
        )
    }
}

/// Percent-encode for `application/x-www-form-urlencoded`.
///
/// Unreserved characters pass through; everything else — including the `+`, `/` and
/// `=` a JWT's base64url padding and an ARN's separators produce — is escaped. A
/// bare `+` in a form body decodes as a space, which would corrupt the very token
/// being presented, so this is not cosmetic.
fn form_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Pull the `<Credentials>` element out of an `AssumeRoleWithWebIdentityResponse`.
///
/// A narrow extractor rather than an XML dependency: STS's query protocol is XML
/// only, and the four values wanted are flat leaf elements inside one container. The
/// extraction is scoped to the text *between* `<Credentials>` and `</Credentials>`
/// so a value echoed elsewhere in the document (`<Audience>`, `<SubjectFrom...>`,
/// an error string) cannot be mistaken for the credential.
fn parse_assume_role_response(xml: &str) -> Result<CachedCredentials, KeyError> {
    let creds = element_text(xml, "Credentials").ok_or_else(|| {
        KeyError::Malformed(
            "aws-kms: STS response has no <Credentials> element (not an \
             AssumeRoleWithWebIdentity response?)"
                .to_string(),
        )
    })?;
    let field = |name: &str| -> Result<String, KeyError> {
        element_text(creds, name)
            .map(decode_xml_entities)
            .ok_or_else(|| {
                KeyError::Malformed(format!("aws-kms: STS credentials have no <{name}>"))
            })
    };
    let access_key_id = field("AccessKeyId")?;
    let secret_access_key = Zeroizing::new(field("SecretAccessKey")?);
    let session_token = Zeroizing::new(field("SessionToken")?);
    if access_key_id.is_empty() || secret_access_key.is_empty() || session_token.is_empty() {
        return Err(KeyError::Malformed(
            "aws-kms: STS returned an empty credential field".to_string(),
        ));
    }
    // An absent or unparseable Expiration is treated as ALREADY EXPIRED, not as
    // unlimited. That costs a re-exchange per KMS call in the degraded case — the
    // KMS path is cold, so that is affordable — and it makes the failure mode
    // "slower" rather than "signs with a credential AWS stopped honouring".
    let expires_at = field("Expiration")
        .ok()
        .and_then(|s| mcp_re_core::parse_rfc3339_utc(&s).ok())
        .and_then(|unix| u64::try_from(unix).ok())
        .map(|secs| UNIX_EPOCH + Duration::from_secs(secs))
        .unwrap_or(UNIX_EPOCH);
    Ok(CachedCredentials {
        credentials: AwsCredentials {
            access_key_id,
            secret_access_key,
            session_token: Some(session_token),
        },
        expires_at,
    })
}

/// The text between the first `<name>` and the following `</name>`, or `None`.
///
/// Deliberately does not handle attributes, namespaces or self-closing tags: STS's
/// credential elements have none, and an input that does have them is not a response
/// this function should be guessing about.
fn element_text<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(&xml[start..end])
}

/// Decode the five predefined XML entities.
///
/// Base64 and ARN characters never need escaping, so in practice this is the
/// identity function — but "in practice" is how a decoder that silently hands back
/// `&amp;` inside a secret gets written, and a corrupted secret key fails as an
/// opaque KMS `InvalidSignatureException` far from here.
fn decode_xml_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        // `&amp;` LAST: doing it first would let `&amp;lt;` decode to `<`.
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response_with(expiration: &str) -> String {
        format!(
            r#"<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Audience>sts.amazonaws.com</Audience>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::455880745808:assumed-role/mcp-re-kms-signer/mcp-re-proxy</Arn>
      <AssumedRoleId>AROAEXAMPLE:mcp-re-proxy</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>ASIAEXAMPLEKEYID</AccessKeyId>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</SecretAccessKey>
      <SessionToken>FQoGZXIvYXdzEExampleToken==</SessionToken>
      <Expiration>{expiration}</Expiration>
    </Credentials>
    <Provider>arn:aws:iam::455880745808:oidc-provider/oidc.eks.eu-north-1.amazonaws.com/id/EXAMPLE</Provider>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>"#
        )
    }

    #[test]
    fn a_well_formed_response_yields_the_credentials_and_its_expiry() {
        let parsed = parse_assume_role_response(&response_with("2026-08-03T12:34:56Z")).unwrap();
        assert_eq!(parsed.credentials.access_key_id, "ASIAEXAMPLEKEYID");
        assert_eq!(
            &*parsed.credentials.secret_access_key,
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
        assert_eq!(
            parsed.credentials.session_token.as_deref().map(|s| &**s),
            Some("FQoGZXIvYXdzEExampleToken==")
        );
        let expected = UNIX_EPOCH
            + Duration::from_secs(
                u64::try_from(mcp_re_core::parse_rfc3339_utc("2026-08-03T12:34:56Z").unwrap())
                    .unwrap(),
            );
        assert_eq!(parsed.expires_at, expected);
    }

    #[test]
    fn a_session_token_is_always_set_so_sigv4_sends_x_amz_security_token() {
        // Web-identity credentials are ALWAYS temporary. If this ever parsed to
        // `None` the SigV4 signer would omit `X-Amz-Security-Token` and every KMS
        // call would fail authentication for a reason that points nowhere near here.
        let parsed = parse_assume_role_response(&response_with("2026-08-03T12:34:56Z")).unwrap();
        assert!(parsed.credentials.session_token.is_some());
    }

    #[test]
    fn an_unparseable_expiration_reads_as_already_expired_not_as_unlimited() {
        let parsed = parse_assume_role_response(&response_with("not-a-timestamp")).unwrap();
        assert_eq!(parsed.expires_at, UNIX_EPOCH);
        // No freshness gate can ever be satisfied by it, which is why
        // `cached_or_exchange` replaces an at-or-before-now expiry with the bounded
        // `UNKNOWN_EXPIRY_REUSE` floor instead of caching the raw value.
        assert!(SystemTime::now() + CREDENTIAL_REFRESH_MARGIN >= parsed.expires_at);
    }

    #[test]
    fn a_missing_expiration_element_reads_as_already_expired() {
        let xml = r#"<Credentials>
          <AccessKeyId>A</AccessKeyId>
          <SecretAccessKey>B</SecretAccessKey>
          <SessionToken>C</SessionToken>
        </Credentials>"#;
        assert_eq!(
            parse_assume_role_response(xml).unwrap().expires_at,
            UNIX_EPOCH
        );
    }

    #[test]
    fn a_response_without_credentials_is_refused() {
        let xml = r#"<ErrorResponse><Error><Code>AccessDenied</Code>
          <Message>Not authorized to perform sts:AssumeRoleWithWebIdentity</Message>
        </Error></ErrorResponse>"#;
        let err = parse_assume_role_response(xml).unwrap_err();
        assert!(format!("{err:?}").contains("Credentials"), "got: {err:?}");
    }

    #[test]
    fn each_missing_credential_field_is_named() {
        for missing in ["AccessKeyId", "SecretAccessKey", "SessionToken"] {
            let full = response_with("2026-08-03T12:34:56Z");
            let stripped = full
                .lines()
                .filter(|l| !l.contains(&format!("<{missing}>")))
                .collect::<Vec<_>>()
                .join("\n");
            let err = parse_assume_role_response(&stripped).unwrap_err();
            assert!(format!("{err:?}").contains(missing), "got: {err:?}");
        }
    }

    #[test]
    fn an_empty_credential_field_is_refused_rather_than_signed_with() {
        let xml = r#"<Credentials>
          <AccessKeyId></AccessKeyId>
          <SecretAccessKey>B</SecretAccessKey>
          <SessionToken>C</SessionToken>
          <Expiration>2026-08-03T12:34:56Z</Expiration>
        </Credentials>"#;
        assert!(parse_assume_role_response(xml).is_err());
    }

    #[test]
    fn a_value_echoed_outside_credentials_is_not_mistaken_for_one() {
        // `<Audience>` precedes `<Credentials>` in a real response. If the extractor
        // searched the whole document per field rather than the Credentials subtree,
        // a document that echoed `<AccessKeyId>` earlier would win.
        let xml = r#"<Response>
          <Decoy><AccessKeyId>ATTACKERKEY</AccessKeyId></Decoy>
          <Credentials>
            <AccessKeyId>REALKEY</AccessKeyId>
            <SecretAccessKey>B</SecretAccessKey>
            <SessionToken>C</SessionToken>
            <Expiration>2026-08-03T12:34:56Z</Expiration>
          </Credentials>
        </Response>"#;
        let parsed = parse_assume_role_response(xml).unwrap();
        assert_eq!(parsed.credentials.access_key_id, "REALKEY");
    }

    #[test]
    fn form_encoding_escapes_what_a_jwt_and_an_arn_contain() {
        // A bare `+` decodes as a space on the server, corrupting the token.
        assert_eq!(form_encode("a+b/c=d"), "a%2Bb%2Fc%3Dd");
        assert_eq!(
            form_encode("arn:aws:iam::455880745808:role/mcp-re"),
            "arn%3Aaws%3Aiam%3A%3A455880745808%3Arole%2Fmcp-re"
        );
        // Unreserved characters are left alone.
        assert_eq!(form_encode("Az0-_.~"), "Az0-_.~");
    }

    #[test]
    fn xml_entities_decode_and_amp_is_decoded_last() {
        assert_eq!(decode_xml_entities("a&amp;b"), "a&b");
        assert_eq!(decode_xml_entities("a&lt;b&gt;c"), "a<b>c");
        // `&amp;lt;` is the ESCAPED form of the literal text `&lt;` — decoding
        // `&amp;` first would turn it into `<`, inventing a character.
        assert_eq!(decode_xml_entities("&amp;lt;"), "&lt;");
        // The no-entity fast path must not alter anything.
        assert_eq!(
            decode_xml_entities("plain/base64+value=="),
            "plain/base64+value=="
        );
    }

    fn source() -> WebIdentityCredentialSource {
        WebIdentityCredentialSource::new(WebIdentityConfig {
            role_arn: "arn:aws:iam::1:role/r".to_string(),
            token_file: "/dev/null".to_string(),
            session_name: DEFAULT_SESSION_NAME.to_string(),
            endpoint: "https://sts.eu-north-1.amazonaws.com".to_string(),
        })
    }

    fn parsed(expiration: &str) -> CachedCredentials {
        parse_assume_role_response(&response_with(expiration)).expect("parses")
    }

    /// The region is interpolated into the endpoint the pod posts its OIDC assertion
    /// to, so anything that can move the authority has to be refused before it is.
    #[test]
    fn a_region_that_could_redirect_the_token_is_refused() {
        assert!(validate_region("eu-north-1").is_ok());
        assert!(validate_region("us-gov-east-1").is_ok());
        for hostile in [
            "",
            "evil.example.com/",
            "x@evil.example.com",
            "x#",
            "x?y",
            "x:443",
            "EU-NORTH-1",
            "x\\y",
        ] {
            assert!(
                validate_region(hostile).is_err(),
                "{hostile:?} must not reach the STS endpoint"
            );
        }
    }

    /// The default endpoint is region-derived, so `from_env` is where the check has to
    /// bite; an explicit `--aws-sts-endpoint` is validated by the CLI instead.
    #[test]
    fn a_hostile_region_stops_the_default_endpoint_being_built() {
        let err = WebIdentityConfig::from_env("evil.example.com/", None)
            .expect_err("a region that moves the authority must fail closed");
        assert!(
            matches!(&err, KeyError::Malformed(m) if m.contains("region")),
            "got {err:?}"
        );
    }

    /// A credential whose `Expiration` could not be read must still be CACHED for a
    /// bounded window. Without that, the gate can never hold and every KMS operation —
    /// under delegated TLS, every unauthenticated handshake — runs its own STS
    /// exchange.
    #[test]
    fn an_unreadable_expiration_is_reused_briefly_rather_than_re_exchanged_every_call() {
        let source = source();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let exchange = || {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(parsed("not-a-timestamp"))
        };
        let now = SystemTime::now();
        for _ in 0..5 {
            source
                .cached_or_exchange(now, &exchange)
                .expect("credentials");
        }
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "an unreadable Expiration must not mean one AssumeRoleWithWebIdentity per call"
        );
        // And the reuse is bounded: past the window the next call re-exchanges.
        source
            .cached_or_exchange(now + UNKNOWN_EXPIRY_REUSE, &exchange)
            .expect("credentials");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    /// The floor must never extend a real expiry. A credential with 100 seconds left is
    /// served while it is still fresh and re-exchanged after that, not held for the
    /// unknown-expiry window.
    #[test]
    fn a_stated_expiry_is_never_extended_by_the_reuse_floor() {
        let source = source();
        let now = SystemTime::now();
        let short = CachedCredentials {
            credentials: parsed("2026-08-03T12:34:56Z").credentials,
            expires_at: now + Duration::from_secs(100),
        };
        let calls = std::sync::atomic::AtomicUsize::new(0);
        source
            .cached_or_exchange(now, &|| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(CachedCredentials {
                    credentials: short.credentials.clone(),
                    expires_at: short.expires_at,
                })
            })
            .expect("credentials");
        source
            .cached_or_exchange(now + Duration::from_secs(60), &|| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(CachedCredentials {
                    credentials: short.credentials.clone(),
                    expires_at: short.expires_at,
                })
            })
            .expect("credentials");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "a credential inside the refresh margin must be re-exchanged, not reused"
        );
    }

    /// Concurrent callers coalesce onto ONE exchange. Without the single-flight lock
    /// each thread that misses the cache posts its own token to STS, which is the
    /// amplification a handshake burst turns into an STS rate limit.
    #[test]
    fn concurrent_callers_perform_one_exchange_between_them() {
        let source = std::sync::Arc::new(source());
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let now = SystemTime::now();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let source = std::sync::Arc::clone(&source);
                let calls = std::sync::Arc::clone(&calls);
                std::thread::spawn(move || {
                    source
                        .cached_or_exchange(now, &|| {
                            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            // Long enough that every thread is in the miss path.
                            std::thread::sleep(Duration::from_millis(50));
                            Ok(parsed("2126-08-03T12:34:56Z"))
                        })
                        .expect("credentials");
                })
            })
            .collect();
        for t in threads {
            t.join().expect("joined");
        }
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "8 concurrent callers must not each post the projected token to STS"
        );
    }

    #[test]
    fn session_names_are_validated_against_the_sts_grammar() {
        assert!(validate_session_name("mcp-re-proxy").is_ok());
        assert!(validate_session_name("a").is_err(), "too short");
        assert!(validate_session_name(&"x".repeat(65)).is_err(), "too long");
        assert!(validate_session_name("has space").is_err());
        assert!(validate_session_name("has/slash").is_err());
        assert!(validate_session_name("ok+=,.@-_").is_ok());
    }
}
