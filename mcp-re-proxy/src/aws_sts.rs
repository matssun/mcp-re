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
//! * An unparseable or absent `Expiration` is parsed as **already expired** rather than
//!   as "good until further notice". It is never treated as unlimited; the cache reuses
//!   such a credential for at most [`UNKNOWN_EXPIRY_REUSE`] and then re-exchanges, so an
//!   unreadable expiry costs a bounded window, not an indefinite one.

use crate::remote_signer_call::read_error_body;
use crate::remote_signer_call::NETWORK_TIMEOUT;
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

/// How long a FAILED STS exchange suppresses the next one.
///
/// The single flight below is held across the round trip, which is right when the exchange
/// succeeds — a burst of callers coalesces onto one call. It is wrong when it FAILS,
/// because nothing is cached: the next waiter to acquire the lock repeats the whole
/// [`NETWORK_TIMEOUT`], and the one behind it repeats it again, so N waiters drain in N
/// timeouts instead of one. Under delegated TLS those waiters are handshake workers, and an
/// unauthenticated peer supplies them by opening connections.
///
/// TWO things make the record actually cover those waiters, and both are load-bearing:
///
/// * It is stamped with the clock read AFTER `exchange` returns, not with the arriving
///   caller's entry instant. A stamp taken at entry is already `NETWORK_TIMEOUT` old by the
///   time it is written, so every waiter that arrived more than one window after the
///   exchanging thread would find it expired and start its own round trip.
/// * It is at least [`NETWORK_TIMEOUT`] long, because the waiters are exactly the callers
///   that arrived during one timeout and then unblock one after another.
///
/// Deliberately the same length as the GCP metadata sibling, even though
/// [`UNKNOWN_EXPIRY_REUSE`] below argues this peer is the more trustworthy of the two. The
/// two constants answer different questions: that one asks how long a credential of unknown
/// lifetime may be REUSED, which turns on who chose it; this one asks how long a
/// proven-failing round trip need not be REPEATED, which turns only on the cost of the
/// timeout — the same 5 s on the same blocking handshake workers.
const STS_FAILURE_COOLDOWN: Duration = NETWORK_TIMEOUT;

/// The longest session an `AssumeRoleWithWebIdentity` credential is believed on.
///
/// A role's `MaxSessionDuration` cannot exceed 12 hours, so an `Expiration` beyond that is
/// not a lifetime STS can honestly have issued. Unbounded, a substituted or emulator
/// endpoint stating a far-future `Expiration` pins the credential for the process lifetime
/// — nothing re-exchanges it and nothing evicts it — which is a permanent loss of
/// AWS-rooted signing on that replica.
const MAX_SESSION_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);

/// Upper bound on an `AssumeRoleWithWebIdentity` success body. A real response is a
/// few KB; the cap stops a substituted endpoint streaming an unbounded body into the
/// blocking thread.
const MAX_STS_RESPONSE_BYTES: u64 = 256 * 1024;

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
/// The floor is not a guess at the credential's life. `AssumeRoleWithWebIdentity` refuses
/// a `DurationSeconds` below 900, so a session AWS has just issued is valid for at least
/// that long whatever the response said, and this window is well inside it. It applies
/// ONLY when the stated expiry is at or before the exchange instant: a real expiry,
/// including one about to lapse, is never extended.
///
/// That argument assumes the peer is AWS, and the branch fires precisely when the response
/// did NOT have the shape AWS produces — an emulator, or a substituted `--aws-sts-endpoint`
/// (`kms_endpoint_authority` permits `http://` only for loopback). It still holds there,
/// because the floor grants no authority: whoever answered the exchange chose the
/// credential, and reusing THAT credential rather than re-requesting an identical one from
/// the same peer adds nothing they did not already have. The bound is what matters — a
/// credential whose expiry could not be established is never held open-endedly, and each
/// lapse re-establishes it.
///
/// The window a caller actually sees is `UNKNOWN_EXPIRY_REUSE - CREDENTIAL_REFRESH_MARGIN`,
/// because the freshness gate subtracts the margin from every expiry, stamped or stated —
/// so this constant must stay strictly ABOVE the margin or the floor silently becomes a
/// no-op and every KMS operation exchanges again.
///
/// The SAME length as the GCP metadata sibling's identically-named constant, and the two
/// reach it from opposite directions. GCP's peer is an unauthenticated link-local plaintext
/// service, which argues for a short bound, and it can also afford one because
/// `UreqGcpClient` evicts a token Cloud KMS answers 401 for. This peer is an
/// operator-configured HTTPS endpoint, the stronger position — but there is NO eviction
/// here: nothing clears a cached credential when KMS rejects it.
///
/// Be exact about how little this bound covers, because the earlier wording implied more.
/// It applies ONLY to the branch where no `Expiration` could be read. A credential that
/// STATED an expiry and that AWS then stops honouring — revoked, or a role whose trust
/// policy changed — is held for its whole stated life, up to [`MAX_SESSION_LIFETIME`], with
/// nothing evicting it and nothing shortening it; every KMS operation and every
/// delegated-TLS handshake fails for that entire window. That is the uncovered case, and
/// this constant does not touch it. Closing it means giving `AwsCredentialSource` an
/// invalidation hook and classifying the KMS error in `post_kms`, the way the GCP sibling
/// evicts on a Cloud KMS 401.
///
/// The "already expired" test this floor keys on is safe HERE and would not be safe if it
/// were copied: `parse_assume_role_response` stamps the fixed constant `UNIX_EPOCH` for an
/// Expiration it cannot read, which is unconditionally before any `now`. The GCP sibling
/// once encoded the same idea as "the expiry equals the current instant", which stopped
/// firing the moment two clock readings were taken instead of one. A sentinel must be a
/// value no clock can produce, not a value a clock happened to produce a moment ago.
const UNKNOWN_EXPIRY_REUSE: Duration = Duration::from_secs(120);

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
        // Before anything else: whichever way the endpoint is arrived at, it decides which
        // host receives this pod's projected service-account token — and whoever receives
        // that token can assume the IRSA role and obtain KMS `Sign` on the root
        // response-signing key. A DERIVED endpoint is only as good as the region
        // interpolated into it; an EXPLICIT one meets the same authority rule the
        // `--aws-sts-endpoint` flag meets at parse, applied again here because
        // `AwsKmsConfig` is public and an embedder reaches this constructor without a
        // parser.
        match &endpoint {
            None => validate_region(region)?,
            Some(endpoint) => {
                crate::kms_endpoint_policy::kms_endpoint_authority(endpoint).map_err(|why| {
                    KeyError::Malformed(format!("aws-kms: --aws-sts-endpoint {why}"))
                })?;
            }
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
/// Checked before it is interpolated into a default endpoint, because the interpolation
/// decides WHO the request reaches. `--aws-kms-region` feeds TWO such interpolations —
/// `https://sts.{region}.amazonaws.com` here and `https://kms.{region}.amazonaws.com` in
/// [`crate::aws_kms_keysource`] — and they are the paths that reach an authority without
/// an operator having typed one, so each derives its endpoint only from a region this has
/// accepted.
///
/// A region carrying `/`, `@`, `:`, `#` or `?` re-points either URL at an attacker-chosen
/// authority — `evil.example.com/` alone is enough for the STS form, and `x@evil.example.
/// com#` for the KMS one. Whoever receives the STS assertion can assume the IRSA role and
/// obtain KMS `Sign` on the root response-signing key; whoever receives the KMS traffic
/// gets the `X-Amz-Security-Token` header outright and supplies the root public key at
/// construction. An explicitly supplied endpoint skips this check and meets
/// [`crate::kms_endpoint_policy::kms_endpoint_authority`] instead — the same rule the `--aws-sts-endpoint`,
/// `--aws-kms-endpoint` and `--gcp-kms-endpoint` flags meet at parse, applied again at
/// [`WebIdentityConfig::from_env`] because that is where an endpoint reaches this module.
pub(crate) fn validate_region(region: &str) -> Result<(), KeyError> {
    if region.is_empty() {
        return Err(KeyError::Malformed(
            "aws-kms: --aws-kms-region is empty, so the default AWS endpoints would resolve \
             to https://sts..amazonaws.com and https://kms..amazonaws.com"
                .to_string(),
        ));
    }
    if let Some(bad) = region
        .chars()
        .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-'))
    {
        return Err(KeyError::Malformed(format!(
            "aws-kms: --aws-kms-region {region:?} is not an AWS region label \
             ([a-z0-9-]); it is interpolated into the default STS and KMS endpoints, so a \
             character like {bad:?} sends this pod's web identity token, or its KMS \
             traffic and session credential, to another host"
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
    state: Mutex<CredentialState>,
    /// Held across an exchange so concurrent callers coalesce onto one.
    ///
    /// The state lock is deliberately NOT held across the round trip — that would put a
    /// 5-second network call under a lock every KMS operation takes. This one is, and
    /// the state is re-read after acquiring it, so a burst of callers that all miss the
    /// cache produces a single `AssumeRoleWithWebIdentity` rather than one each.
    exchanging: Mutex<()>,
}

/// The cached credentials and the last failed exchange, under one lock.
#[derive(Default)]
struct CredentialState {
    credentials: Option<CachedCredentials>,
    /// See [`STS_FAILURE_COOLDOWN`]: an exchange that just timed out is the reason NOT to
    /// start another one, and nothing else here records that it happened.
    last_failure: Option<FailedExchange>,
}

/// An exchange that failed, kept only long enough for waiters inside the cool-off to be
/// given the error rather than paying their own [`NETWORK_TIMEOUT`] to rediscover it.
struct FailedExchange {
    at: SystemTime,
    /// [`KeyError`] is not `Clone`, so the replay is rebuilt from its parts and is
    /// byte-identical to what the exchanging thread returned, variant included.
    malformed: bool,
    message: String,
}

impl FailedExchange {
    fn replay(&self) -> KeyError {
        if self.malformed {
            KeyError::Malformed(self.message.clone())
        } else {
            KeyError::NotFound(self.message.clone())
        }
    }

    fn of(error: &KeyError, at: SystemTime) -> Self {
        let (malformed, message) = match error {
            KeyError::Malformed(message) => (true, message.clone()),
            KeyError::NotFound(message) => (false, message.clone()),
        };
        FailedExchange {
            at,
            malformed,
            message,
        }
    }
}

impl WebIdentityCredentialSource {
    /// Build the source, holding its endpoint to the KMS/STS authority rule.
    ///
    /// This is the constructor an embedder actually reaches: `WebIdentityConfig` is public
    /// with public fields, so a caller can assemble one and arrive here without passing
    /// [`WebIdentityConfig::from_env`] — which is the same reason the three key-source
    /// constructors check their endpoints rather than trusting the CLI to have done it.
    /// Whoever this endpoint names receives the pod's projected service-account token and
    /// can assume the IRSA role. `from_env` checks too, so an operator sees the refusal at
    /// the earliest point with the flag named; both call the one decision, so they cannot
    /// drift.
    pub fn new(config: WebIdentityConfig) -> Result<Self, KeyError> {
        crate::kms_endpoint_policy::kms_endpoint_authority(&config.endpoint).map_err(|why| {
            KeyError::Malformed(format!("aws-kms: web identity STS endpoint {why}"))
        })?;
        Ok(WebIdentityCredentialSource {
            agent: ureq::AgentBuilder::new().build(),
            config,
            state: Mutex::new(CredentialState::default()),
            exchanging: Mutex::new(()),
        })
    }

    /// The credential state, recovering a poisoned lock rather than propagating the panic.
    ///
    /// Poison is sticky for the process lifetime, so propagating it would turn one panic
    /// anywhere in an exchange into a PERMANENT loss of AWS KMS signing on this replica:
    /// every delegated-TLS handshake fails and the cold-path rotor cannot mint a successor,
    /// so the replica fails closed on `delegated_signing_unavailable` at the current
    /// delegated key's `exp` with nothing that recovers it. Nothing here can be observed
    /// half-written — both fields are whole-value swaps — so there is no invariant for the
    /// poison to protect. Matches the GCP sibling, `delegated_server_signer` and
    /// `reloading_trust`.
    fn state(&self) -> std::sync::MutexGuard<'_, CredentialState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The cached credentials, if they are still fresh enough to sign with.
    fn fresh(state: &CredentialState, now: SystemTime) -> Option<AwsCredentials> {
        state.credentials.as_ref().and_then(|c| {
            (now + CREDENTIAL_REFRESH_MARGIN < c.expires_at).then(|| c.credentials.clone())
        })
    }

    /// The cached credentials if they are fresh, or the error of an exchange that failed
    /// inside [`STS_FAILURE_COOLDOWN`] — so no caller starts a round trip that a thread just
    /// ahead of it has already proved will fail.
    ///
    /// A clock that has moved BACKWARDS closes the window instead of extending it:
    /// `duration_since` is an error when `now` precedes the recorded instant, and a
    /// suppression window that outlived a clock jump would be a signing outage.
    fn fresh_or_recent_failure(&self, now: SystemTime) -> Result<Option<AwsCredentials>, KeyError> {
        let state = self.state();
        if let Some(credentials) = Self::fresh(&state, now) {
            return Ok(Some(credentials));
        }
        match &state.last_failure {
            Some(failure)
                if now
                    .duration_since(failure.at)
                    .is_ok_and(|elapsed| elapsed < STS_FAILURE_COOLDOWN) =>
            {
                Err(failure.replay())
            }
            _ => Ok(None),
        }
    }

    /// Serve the cached credentials, or run ONE exchange and cache what it returns.
    ///
    /// `clock` and `exchange` are parameters so the single-flight, the reuse floor and the
    /// failure cool-off are provable without an STS endpoint. `clock` is read THREE times —
    /// on entry, again after the flight lock is acquired (this thread may have been blocked
    /// there for a whole [`NETWORK_TIMEOUT`]), and once more after a failed `exchange`, to
    /// stamp the record with the instant the failure was PROVED.
    fn cached_or_exchange(
        &self,
        clock: &dyn Fn() -> SystemTime,
        exchange: &dyn Fn() -> Result<CachedCredentials, KeyError>,
    ) -> Result<AwsCredentials, KeyError> {
        if let Some(credentials) = self.fresh_or_recent_failure(clock())? {
            return Ok(credentials);
        }
        let _flight = self.exchanging.lock().unwrap_or_else(|p| p.into_inner());
        // Whoever held this lock may have just filled the cache — or just failed, in which
        // case repeating their exchange costs this thread a whole NETWORK_TIMEOUT and the
        // waiter behind it another one. Re-read the clock: the entry reading is up to one
        // timeout stale by now, and comparing a fresh record against it is what let every
        // late-arriving waiter through.
        let now = clock();
        if let Some(credentials) = self.fresh_or_recent_failure(now)? {
            return Ok(credentials);
        }
        let mut fresh = match exchange() {
            Ok(fresh) => fresh,
            Err(error) => {
                // Stamped with the instant the failure was PROVED, not the instant this
                // caller arrived.
                self.state().last_failure = Some(FailedExchange::of(&error, clock()));
                return Err(error);
            }
        };
        // A credential that is already expired the instant it was issued is one whose
        // `Expiration` could not be read, not one AWS has stopped honouring. Reusing it
        // briefly is what stops a response-shape drift turning every KMS call — and so
        // every delegated-TLS handshake — into its own STS round trip.
        if fresh.expires_at <= now {
            fresh.expires_at = now + UNKNOWN_EXPIRY_REUSE;
        }
        let credentials = fresh.credentials.clone();
        let mut state = self.state();
        state.credentials = Some(fresh);
        state.last_failure = None;
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
                return Err(KeyError::NotFound(format!(
                    "aws-kms: AssumeRoleWithWebIdentity for {} failed: HTTP {code}: {}",
                    self.config.role_arn,
                    read_error_body(resp)
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
        self.cached_or_exchange(&SystemTime::now, &|| self.exchange())
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
    parse_assume_role_response_at(xml, SystemTime::now())
}

/// As [`parse_assume_role_response`], at an explicit instant so the lifetime ceiling is
/// provable without waiting on a clock.
fn parse_assume_role_response_at(
    xml: &str,
    now: SystemTime,
) -> Result<CachedCredentials, KeyError> {
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
    // An absent or unparseable Expiration parses to UNIX_EPOCH — already expired, never
    // unlimited. This function establishes only that no expiry could be read; how long
    // such a credential may then be reused is `cached_or_exchange`'s decision, and it is
    // bounded by UNKNOWN_EXPIRY_REUSE rather than open-ended. What must not exist is a
    // path where an unreadable Expiration becomes a credential held indefinitely.
    //
    // The TOP is bounded too, and for the same reason the GCP sibling clamps `expires_in`:
    // an `Expiration` of year 9999 parses cleanly and pins the credential for the process
    // lifetime, so CREDENTIAL_REFRESH_MARGIN never fires again and nothing re-exchanges —
    // and nothing evicts a cached credential when KMS rejects it either, so that state is
    // permanent until a restart. `AssumeRoleWithWebIdentity` cannot issue a session longer
    // than the role's MaxSessionDuration, whose own ceiling is 12 hours, so a longer claim
    // is not a lifetime the peer can honestly promise. Truncating is a truthful bound, not
    // a guess.
    let expires_at = field("Expiration")
        .ok()
        .and_then(|s| mcp_re_core::parse_rfc3339_utc(&s).ok())
        .and_then(|unix| u64::try_from(unix).ok())
        .map(|secs| UNIX_EPOCH + Duration::from_secs(secs))
        .map(|stated| stated.min(now + MAX_SESSION_LIFETIME))
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
        .expect("a regional STS endpoint is admissible")
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

    /// The default endpoint is region-derived, so `from_env` is where that check has to
    /// bite.
    #[test]
    fn a_hostile_region_stops_the_default_endpoint_being_built() {
        let err = WebIdentityConfig::from_env("evil.example.com/", None)
            .expect_err("a region that moves the authority must fail closed");
        assert!(
            matches!(&err, KeyError::Malformed(m) if m.contains("region")),
            "got {err:?}"
        );
    }

    /// R9-C001 — an EXPLICIT endpoint skips the region check, so it has to meet the
    /// authority rule here.
    ///
    /// Whoever receives this pod's projected service-account token can assume the IRSA role
    /// and obtain KMS `Sign` on the root response-signing key. `ureq` connects to the host
    /// `url::Url::parse` reads, which for every string below is `evil.example.com`. Checked
    /// in `from_env` as well as at the CLI because `AwsKmsConfig` is public and an embedder
    /// reaches `from_web_identity` without meeting a parser.
    #[test]
    fn an_explicit_sts_endpoint_that_re_points_the_projected_token_is_refused() {
        for hostile in [
            "https://sts.eu-north-1.amazonaws.com@evil.example.com",
            "http://localhost:80@evil.example.com",
            "http://127.0.0.1:4566@evil.example.com",
            "https://user:pass@evil.example.com",
            "http://sts.attacker.example",
            "ftp://sts.eu-north-1.amazonaws.com",
            "https://",
        ] {
            let err = WebIdentityConfig::from_env("eu-north-1", Some(hostile.to_string()))
                .expect_err("an endpoint that moves the authority must fail closed");
            assert!(
                matches!(&err, KeyError::Malformed(m) if m.contains("--aws-sts-endpoint")),
                "{hostile:?}: got {err:?}"
            );
        }
    }

    /// POSITIVE CONTROL: the endpoints an operator legitimately sets are admitted, so
    /// whatever `from_env` goes on to report is about the IRSA environment and never about
    /// the endpoint. Asserted that way rather than on `is_ok` because the environment this
    /// reads is process-wide and other tests in this file write it.
    #[test]
    fn the_sts_endpoints_an_operator_legitimately_sets_are_still_admitted() {
        for endpoint in [
            "https://sts.eu-north-1.amazonaws.com",
            "https://sts.amazonaws.com",
            "https://vpce-0abc123-xy1z.sts.eu-north-1.vpce.amazonaws.com",
            "https://sts.emulator.svc.cluster.local:8443",
            // The loopback emulator lane the IRSA tests themselves run against.
            "http://127.0.0.1:4566/",
            "http://localhost:4566",
            "http://[::1]:4566",
        ] {
            if let Err(err) = WebIdentityConfig::from_env("eu-north-1", Some(endpoint.to_string()))
            {
                let rendered = format!("{err:?}");
                assert!(
                    !rendered.contains("--aws-sts-endpoint"),
                    "{endpoint} is an endpoint an operator sets and must be admitted, got \
                     {rendered}"
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // The AWS twins of the GCP single-flight and mutex-poison findings
    // (R9-C057/C058/C059 and R9-C091). Same shape, same caller chain: the STS
    // exchange is reached from a delegated-TLS handshake an unauthenticated peer
    // opens, so an attacker supplies the waiters.
    // ------------------------------------------------------------------

    /// A clock with NO wall-time component at all — the GCP sibling's harness, verbatim in
    /// intent.
    ///
    /// One shared `now` erased the dispersion the property is about; scaling the wall clock
    /// restored it but left the outcome dependent on CI scheduling. The logical time is
    /// therefore scripted: caller `i` arrives at `base + i` seconds, and every reading it
    /// takes after the in-flight exchange has resolved returns the completion instant —
    /// which is the ordering the real code produces, since a caller blocked on the flight
    /// lock cannot observe a time earlier than the exchange holding it. Real threads and
    /// real blocking are unchanged; only the clock is scripted.
    struct LogicalClock {
        base: SystemTime,
        completed: Mutex<Option<Duration>>,
    }

    /// How long the in-flight exchange occupies, in logical seconds — longer than the
    /// cool-off, so the waiters are still queued behind it when it resolves.
    const EXCHANGE_SECONDS: u64 = 20;
    /// Real time each caller waits before entering, purely to make the threads contend.
    /// Nothing asserted depends on its value.
    const CONTENTION_DELAY: Duration = Duration::from_millis(3);

    impl LogicalClock {
        fn new() -> std::sync::Arc<Self> {
            std::sync::Arc::new(LogicalClock {
                base: SystemTime::now(),
                completed: Mutex::new(None),
            })
        }
        fn read(&self, entered_at: Duration) -> SystemTime {
            match *self.completed.lock().unwrap_or_else(|p| p.into_inner()) {
                Some(completed) if completed > entered_at => self.base + completed,
                _ => self.base + entered_at,
            }
        }
        fn finish_exchange(&self) {
            *self.completed.lock().unwrap_or_else(|p| p.into_inner()) =
                Some(Duration::from_secs(EXCHANGE_SECONDS));
        }
    }

    /// Run 8 callers against `exchange`, each arriving one logical second after the last
    /// and each reading the clock ITSELF, and report how many reached `exchange`.
    fn staggered_callers(
        source: &std::sync::Arc<WebIdentityCredentialSource>,
        exchange: impl Fn() -> Result<CachedCredentials, KeyError> + Send + Sync + 'static,
        expect: impl Fn(Result<AwsCredentials, KeyError>) + Send + Sync + 'static,
    ) -> usize {
        let clock = LogicalClock::new();
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let exchange = std::sync::Arc::new(exchange);
        let expect = std::sync::Arc::new(expect);
        let threads: Vec<_> = (0..8u64)
            .map(|i| {
                let source = std::sync::Arc::clone(source);
                let clock = std::sync::Arc::clone(&clock);
                let attempts = std::sync::Arc::clone(&attempts);
                let exchange = std::sync::Arc::clone(&exchange);
                let expect = std::sync::Arc::clone(&expect);
                std::thread::spawn(move || {
                    let entered_at = Duration::from_secs(i);
                    std::thread::sleep(CONTENTION_DELAY * i as u32);
                    let outcome = source.cached_or_exchange(&|| clock.read(entered_at), &|| {
                        attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        std::thread::sleep(CONTENTION_DELAY * 12);
                        let outcome = exchange();
                        clock.finish_exchange();
                        outcome
                    });
                    expect(outcome);
                })
            })
            .collect();
        for t in threads {
            t.join().expect("joined");
        }
        attempts.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// An STS exchange that FAILS must not be repeated by every waiter behind the flight.
    ///
    /// The lock is held across the round trip, so before the cool-off each waiter re-entered
    /// the miss path and paid its own [`NETWORK_TIMEOUT`]: N waiters drained in N timeouts.
    ///
    /// The callers arrive one logical second apart and each reads the clock itself, which is
    /// what makes this sensitive to WHICH instant the failure is stamped with. Stamped at
    /// the arriving caller's entry, the record is a whole timeout old the moment it is
    /// written and every later waiter runs its own round trip. Counted at the exchange, not
    /// inferred from the error: the property is "STS was called once".
    #[test]
    fn a_failed_sts_exchange_is_not_repeated_by_every_waiter() {
        let source = std::sync::Arc::new(source());
        let attempts = staggered_callers(
            &source,
            || {
                Err(KeyError::NotFound(
                    "aws-kms: AssumeRoleWithWebIdentity transport: timed out".to_string(),
                ))
            },
            |outcome| {
                let err = outcome.expect_err("STS is unreachable");
                assert!(
                    matches!(&err, KeyError::NotFound(m) if m.contains("timed out")),
                    "the replayed failure must carry the exchanging thread's diagnosis, got \
                     {err:?}"
                );
            },
        );
        assert_eq!(
            attempts, 1,
            "8 waiters spread over 7 logical seconds behind one failing flight must not each \
             pay a NETWORK_TIMEOUT"
        );
    }

    /// POSITIVE CONTROL: coalescing a SUCCESSFUL exchange is the behaviour the cool-off must
    /// not disturb — the same 8 staggered callers still produce exactly one exchange and all
    /// get credentials.
    #[test]
    fn concurrent_callers_perform_one_sts_exchange_between_them() {
        let source = std::sync::Arc::new(source());
        let attempts = staggered_callers(
            &source,
            || Ok(parsed("2999-01-01T00:00:00Z")),
            |outcome| assert!(!outcome.expect("credentials").access_key_id.is_empty()),
        );
        assert_eq!(
            attempts, 1,
            "8 concurrent callers must not each run an AssumeRoleWithWebIdentity"
        );
    }

    /// The cool-off must be at least as long as the timeout it suppresses, and the reuse
    /// floor must outlast the refresh margin the freshness gate subtracts from it.
    ///
    /// Pinned here because neither is visible to the tests around them: with the failure
    /// stamped at completion every waiter unblocks at essentially the recorded instant, so
    /// any positive window passes; and a floor at or below the margin is a silent no-op that
    /// restores one exchange per KMS operation.
    #[test]
    fn the_sts_windows_must_outlast_what_they_are_measured_against() {
        assert!(
            STS_FAILURE_COOLDOWN >= NETWORK_TIMEOUT,
            "a {STS_FAILURE_COOLDOWN:?} window cannot cover the waiters that queued during a \
             {NETWORK_TIMEOUT:?} exchange"
        );
        assert!(
            UNKNOWN_EXPIRY_REUSE > CREDENTIAL_REFRESH_MARGIN,
            "a credential stamped {UNKNOWN_EXPIRY_REUSE:?} ahead is never fresh under a \
             {CREDENTIAL_REFRESH_MARGIN:?} refresh margin, so the floor would do nothing"
        );
    }

    /// POSITIVE CONTROL: the cool-off is a bound, not a circuit breaker that latches. Past
    /// [`STS_FAILURE_COOLDOWN`] the next caller retries for real, and a success clears the
    /// record so the one after that is served from cache.
    #[test]
    fn the_sts_failure_cool_off_expires_and_a_success_clears_it() {
        let source = source();
        let now = SystemTime::now();
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let failing = || {
            attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(KeyError::NotFound("aws-kms: STS unreachable".to_string()))
        };
        source
            .cached_or_exchange(&|| now, &failing)
            .expect_err("down");
        source
            .cached_or_exchange(&|| now + Duration::from_millis(1), &failing)
            .expect_err("suppressed");
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
        source
            .cached_or_exchange(&|| now + STS_FAILURE_COOLDOWN, &failing)
            .expect_err("retried and still down");
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "the cool-off must expire, not latch"
        );
        let recovered_at = now + STS_FAILURE_COOLDOWN * 2;
        source
            .cached_or_exchange(&|| recovered_at, &|| {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(parsed("2999-01-01T00:00:00Z"))
            })
            .expect("credentials");
        source
            .cached_or_exchange(&|| recovered_at, &failing)
            .expect("served from cache, no exchange");
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "a success must clear the failure record and repopulate the cache"
        );
    }

    /// A clock that jumps BACKWARDS must close the suppression window, not extend it — a
    /// window keyed on `now < at + cooldown` alone would suppress every exchange for the
    /// size of the jump, which is a signing outage produced by an NTP step.
    #[test]
    fn a_backwards_clock_step_does_not_extend_the_sts_failure_cool_off() {
        let source = source();
        let now = SystemTime::now();
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let failing = || {
            attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(KeyError::NotFound("aws-kms: STS unreachable".to_string()))
        };
        source
            .cached_or_exchange(&|| now, &failing)
            .expect_err("down");
        source
            .cached_or_exchange(&|| now - Duration::from_secs(3600), &failing)
            .expect_err("down");
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "a failure recorded in the FUTURE must not suppress the exchange"
        );
    }

    /// Panic while holding a lock, so the next taker meets a poisoned guard.
    fn poison<T>(lock: &Mutex<T>) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = lock.lock().expect("not yet poisoned");
            panic!("poisoning the lock on purpose");
        }));
        assert!(lock.lock().is_err(), "the lock must now be poisoned");
    }

    /// One panic anywhere under these locks must not remove AWS KMS signing from the
    /// replica for the rest of the process.
    ///
    /// Poison is sticky. Propagating it turned every later `credentials()` into an error,
    /// so every delegated-TLS handshake failed AND the cold-path rotor could not mint a
    /// successor — the replica fails closed at the current delegated key's `exp` with
    /// nothing that recovers it. Neither lock protects an invariant: `exchanging` guards
    /// `()`, and `CredentialState`'s fields are whole-value swaps.
    #[test]
    fn a_poisoned_credential_lock_still_serves_credentials() {
        let source = source();
        poison(&source.state);
        poison(&source.exchanging);
        let now = SystemTime::now();
        let credentials = source
            .cached_or_exchange(&|| now, &|| Ok(parsed("2999-01-01T00:00:00Z")))
            .expect("a poisoned lock must not brick AWS KMS signing");
        assert!(!credentials.access_key_id.is_empty());
        // And the cache written under the recovered guard is readable.
        source
            .cached_or_exchange(&|| now, &|| panic!("must be served from cache"))
            .expect("cached");
    }

    /// The endpoint rule has to hold at the constructor an EMBEDDER reaches, not only at
    /// the factory that reads the environment.
    ///
    /// `WebIdentityConfig` is public with public fields, so a caller can assemble one and
    /// call `WebIdentityCredentialSource::new` without ever passing `from_env` — the same
    /// reason the three key-source constructors check their endpoints instead of trusting
    /// the CLI. Whoever this endpoint names receives the pod's projected service-account
    /// token and can assume the IRSA role.
    #[test]
    fn a_hand_built_web_identity_config_cannot_re_point_the_projected_token() {
        for hostile in [
            "https://sts.eu-north-1.amazonaws.com@evil.example.com",
            "http://localhost:80@evil.example.com",
            "http://sts.attacker.example",
            "ftp://sts.eu-north-1.amazonaws.com",
            "https://",
        ] {
            let built = WebIdentityCredentialSource::new(WebIdentityConfig {
                role_arn: "arn:aws:iam::1:role/r".to_string(),
                token_file: "/dev/null".to_string(),
                session_name: DEFAULT_SESSION_NAME.to_string(),
                endpoint: hostile.to_string(),
            });
            let Err(err) = built else {
                panic!("{hostile:?} must not be accepted at the public constructor");
            };
            assert!(
                matches!(&err, KeyError::Malformed(m) if m.contains("STS endpoint")),
                "{hostile:?}: got {err:?}"
            );
        }
        // POSITIVE CONTROL: the endpoints an operator sets, including the loopback lane the
        // IRSA suite's fake STS binds, still construct.
        for allowed in [
            "https://sts.eu-north-1.amazonaws.com",
            "https://sts.amazonaws.com",
            "https://sts.emulator.svc.cluster.local:8443",
            "http://127.0.0.1:4566/",
            "http://localhost:4566",
        ] {
            assert!(
                WebIdentityCredentialSource::new(WebIdentityConfig {
                    role_arn: "arn:aws:iam::1:role/r".to_string(),
                    token_file: "/dev/null".to_string(),
                    session_name: DEFAULT_SESSION_NAME.to_string(),
                    endpoint: allowed.to_string(),
                })
                .is_ok(),
                "{allowed} is an endpoint an operator sets and must construct"
            );
        }
    }

    /// A stated `Expiration` is bounded above, so no response can pin a credential for the
    /// process lifetime.
    ///
    /// Nothing here evicts a cached credential when KMS rejects it, so an unbounded
    /// `Expiration` is not merely a long cache — it is a permanent one: the refresh margin
    /// never fires, no exchange ever runs again, and AWS-rooted signing is lost on that
    /// replica until it restarts. `AssumeRoleWithWebIdentity` cannot issue past a role's
    /// MaxSessionDuration, whose ceiling is 12 hours, so a longer claim is not a lifetime
    /// STS can honestly have issued.
    #[test]
    fn a_far_future_expiration_is_truncated_to_the_real_session_ceiling() {
        let now = SystemTime::now();
        let pinned = parse_assume_role_response_at(&response_with("9999-01-01T00:00:00Z"), now)
            .expect("parses");
        assert_eq!(
            pinned.expires_at,
            now + MAX_SESSION_LIFETIME,
            "a year-9999 Expiration must be truncated, not trusted"
        );
        // POSITIVE CONTROL: an ordinary one-hour session is passed through untouched, and
        // an unreadable one still lands on the already-expired sentinel that the reuse
        // floor keys on.
        let real = mcp_re_core::parse_rfc3339_utc("2026-08-03T12:34:56Z").expect("fixture");
        let ordinary = parse_assume_role_response_at(&response_with("2026-08-03T12:34:56Z"), now)
            .expect("parses");
        assert_eq!(
            ordinary.expires_at,
            UNIX_EPOCH + Duration::from_secs(real as u64),
            "a real Expiration must be used exactly as stated"
        );
        assert_eq!(
            parse_assume_role_response_at(&response_with("not-a-timestamp"), now)
                .expect("parses")
                .expires_at,
            UNIX_EPOCH,
            "an unreadable Expiration must stay the already-expired sentinel"
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
                .cached_or_exchange(&|| now, &exchange)
                .expect("credentials");
        }
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "an unreadable Expiration must not mean one AssumeRoleWithWebIdentity per call"
        );
        // And the reuse is bounded: past the window the next call re-exchanges.
        source
            .cached_or_exchange(&|| now + UNKNOWN_EXPIRY_REUSE, &exchange)
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
            .cached_or_exchange(&|| now, &|| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(CachedCredentials {
                    credentials: short.credentials.clone(),
                    expires_at: short.expires_at,
                })
            })
            .expect("credentials");
        source
            .cached_or_exchange(&|| now + Duration::from_secs(60), &|| {
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
                        .cached_or_exchange(&|| now, &|| {
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
