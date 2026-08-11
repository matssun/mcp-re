//! Native GCP Cloud KMS Ed25519 response signer (ADR-MCPS-028 §C).
//!
//! A non-exporting [`KmsEd25519Backend`] backed by GCP Cloud KMS over blocking
//! HTTPS (`ureq`) with an OAuth2 bearer token. The response-signing key lives in
//! Cloud KMS and is NEVER exported; the adapter uses ONLY two operations —
//! `cryptoKeyVersions.getPublicKey` and `cryptoKeyVersions.asymmetricSign` — against
//! an `EC_SIGN_ED25519` key version (raw `data`, NOT `digest`; PureEdDSA, no
//! pre-hash). As with the AWS adapter (ADR-028 §B.1), the async google-cloud SDK /
//! tokio stack is intentionally NOT used (ADR-MCPS-018 lean-sync firewall); the
//! OCSP/AWS blocking-`ureq` path is the model.
//!
//! Credentials are an OAuth2 access token from a NARROW, explicit set of sources
//! ([`GcpAccessTokenSource`]): an operator-supplied token (`MCP_RE_GCP_ACCESS_TOKEN`)
//! or the GCE/GKE metadata server (workload identity). The service-account
//! JWT-file→token exchange (which needs RSA signing) is a deliberately deferred
//! follow-up, not a hidden default.
//!
//! Fail-closed posture (ADR-MCPS-028 §D): a key version whose algorithm is not
//! `EC_SIGN_ED25519`, or a public key that is not an RFC 8410 Ed25519 SPKI, is
//! rejected at construction; EVERY signature is verified locally against the
//! advertised public key (under the unmodified `mcp-re-core` verifier) BEFORE it is
//! emitted — a non-verifying signature is an error, never returned.
//!
//! Protection level — honest labeling (ADR-MCPS-028 §L, MCPS-59). This adapter
//! pins the key ALGORITHM (`EC_SIGN_ED25519`) but asserts NOTHING about the KMS
//! protection LEVEL. A Cloud KMS `EC_SIGN_ED25519` key version may be `SOFTWARE`-
//! or `HSM`-protected, and the REST operations used here (`getPublicKey` /
//! `asymmetricSign`) do not establish which. This adapter is therefore honestly
//! labeled **software-protection custody** and MUST NOT be presented as
//! FIPS-140-2 Level 3 / HSM-backed. A FIPS-L3 custody claim requires PROVING HSM
//! protection for the specific key version — a live-infra fact still to be
//! verified (ADR-MCPS-028 §L) — and the established HSM-Ed25519 custody path is
//! the PKCS#11 `CKM_EDDSA` token (`pkcs11_keysource`), NOT this native REST
//! adapter. The wire profile stays Ed25519-only (ADR-MCPS-004): if a deployment
//! cannot obtain an HSM-protected Ed25519 key, the high-assurance claim is scoped
//! OUT for that deployment rather than met by adding a second curve (P-256).

use std::io::Read;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use mcp_re_core::b64url_encode;
use mcp_re_core::verify_ed25519;
use mcp_re_core::VerificationKey;
use zeroize::Zeroizing;

use crate::delegated_tls::RawEd25519TlsSigner;
use crate::key_source::KeyError;
use crate::kms_keysource::ed25519_raw_point_from_spki;
use crate::kms_keysource::KmsEd25519Backend;

/// The only Cloud KMS key algorithm this adapter accepts.
const ALGORITHM_ED25519: &str = "EC_SIGN_ED25519";
const ED25519_SIGNATURE_LEN: usize = 64;
/// Default Cloud KMS + metadata-server endpoints (overridable for emulators/tests).
const DEFAULT_KMS_ENDPOINT: &str = "https://cloudkms.googleapis.com";
const DEFAULT_METADATA_ENDPOINT: &str = "http://metadata.google.internal";
/// Refresh a metadata-server token this long before its stated expiry.
const TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(60);
/// Bound on the reuse of a token whose response carried NO usable `expires_in`.
///
/// A response that establishes no lifetime at all ([`stated_expiry`] answers `None`) leaves
/// nothing for the freshness gate to measure against — so without a floor every use would
/// perform its own metadata fetch. That matters because this token is not only on the cold KMS path:
/// [`GcpKmsEd25519Backend`] is a [`RawEd25519TlsSigner`], so under delegated TLS an
/// unauthenticated handshake reaches it, and one blocking metadata round trip per
/// handshake throttles the metadata server.
///
/// The floor applies ONLY when the response stated no usable lifetime; a stated expiry,
/// including one about to lapse, is used exactly as stated and never extended.
///
/// The window a caller actually sees is `UNKNOWN_EXPIRY_REUSE - TOKEN_REFRESH_MARGIN`,
/// because [`MetadataServerTokenSource::fresh`] subtracts the margin from every expiry,
/// stamped or stated. So this constant must stay strictly ABOVE the margin, or the floor
/// silently becomes a no-op and every signature fetches again;
/// `the_unknown_expiry_floor_must_outlast_the_refresh_margin` fails the build if it stops
/// being true.
///
/// It is the SAME length as the AWS STS sibling's identically-named constant, and the two
/// reach it from opposite directions. This peer is an unauthenticated link-local PLAINTEXT
/// service, which argues for a short bound — but a pinned token Cloud KMS will not honour
/// also costs less than the window, because [`UreqGcpClient`] discards it on an HTTP 401
/// and retries once. The AWS peer is an operator-configured HTTPS endpoint, the stronger
/// position, but nothing there evicts a rejected credential, so its bound carries alone
/// what two mechanisms carry here. Equal length, opposite reasons; each doc states its own.
const UNKNOWN_EXPIRY_REUSE: Duration = Duration::from_secs(120);
/// How long a FAILED metadata fetch suppresses the next one, measured from the instant the
/// failure was PROVED.
///
/// The single flight below is held across the round trip, which is right when the fetch
/// succeeds — a burst of callers coalesces onto one call. It is wrong when the fetch
/// FAILS, because nothing is cached: the next waiter to acquire the lock repeats the whole
/// [`NETWORK_TIMEOUT`], and the one behind it repeats it again, so N waiters drain in N
/// timeouts instead of one. Under delegated TLS those waiters are handshake workers, and
/// an unauthenticated peer supplies them by opening connections.
///
/// TWO things make the record actually cover those waiters, and both are load-bearing:
///
/// * It is stamped with the clock read AFTER `fetch` returns, not with the arriving
///   caller's entry instant. A stamp taken at entry is already `NETWORK_TIMEOUT` old by the
///   time it is written, so every waiter that arrived more than one window after the
///   fetching thread would find it expired and start its own round trip — the queue this
///   exists to prevent, with a record that certifies it is prevented.
/// * It is at least [`NETWORK_TIMEOUT`] long. The waiters are exactly the callers that
///   arrived during one timeout and then unblock one after another, so a window shorter
///   than the timeout can lapse part-way through draining them.
///
/// So at most ONE thread per window pays a network timeout. Be precise about what the rest
/// pay: a caller that arrives while the fetch is in flight still blocks on the flight lock
/// until that fetch resolves — up to one `NETWORK_TIMEOUT` — and only then reads the record
/// and returns. What it does NOT do is start a second round trip and wait another timeout
/// on top. A caller arriving after the record is written returns without blocking at all.
/// The cost is therefore bounded at one timeout for the whole cohort rather than one per
/// caller, which is the difference between a flat degradation and a queue that grows with
/// the connection rate.
const METADATA_FAILURE_COOLDOWN: Duration = NETWORK_TIMEOUT;
/// How long the refused-token RETRY is suspended after a freshly-fetched token was ALSO
/// refused.
///
/// A 401 that a new token fixes is a rotation: it costs one extra Cloud KMS call and one
/// metadata fetch, once. A 401 that a new token does NOT fix is a revoked or unbound
/// identity, and it is permanent until an operator acts — so retrying it per call turns
/// EVERY handshake into a metadata round trip plus a second Cloud KMS call. That is the
/// same unbounded amplification the 403 exclusion closes, on the other status, and an
/// unauthenticated peer supplies the connections that drive it.
///
/// Inside this window the refusal is reported directly: the token is not evicted and the
/// call is not repeated, so a persistent 401 degrades FLAT — one Cloud KMS call per
/// handshake, which is what the handshake costs anyway — instead of once per connection. A
/// retry that succeeds closes the window immediately, so a genuine rotation is never slowed
/// by it.
const TOKEN_REFUSAL_RETRY_COOLDOWN: Duration = NETWORK_TIMEOUT;
/// MANDATORY per-request network timeout. The serve loop is blocking, so an
/// unbounded fetch (stalled connect/TLS handshake) would wedge the serving thread
/// indefinitely; every `ureq` call below carries this (mirrors the AWS/OCSP paths).
const NETWORK_TIMEOUT: Duration = Duration::from_secs(5);
/// Bound on an HTTP *error* body read for diagnostics — never an unbounded read.
const MAX_ERROR_BODY_BYTES: u64 = 8 * 1024;

/// GCP Cloud KMS connection configuration. `key_version_name` is the full resource
/// path `projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V`;
/// `endpoint` overrides the default Cloud KMS host for an emulator/test endpoint.
pub struct GcpKmsConfig {
    pub key_version_name: String,
    pub endpoint: Option<String>,
}

/// A source of a currently-valid OAuth2 access token (bearer). Kept narrow and
/// explicit (ADR-MCPS-028 credential scope) — no silent application-default-
/// credentials discovery chain.
pub(crate) trait GcpAccessTokenSource {
    fn access_token(&self) -> Result<Zeroizing<String>, KeyError>;

    /// Discard the cached token IF it is still `refused`, reporting whether it was.
    ///
    /// A cached token can stop being honoured before the expiry it was cached under —
    /// revoked, or stamped with the [`UNKNOWN_EXPIRY_REUSE`] floor because its real
    /// lifetime could not be read. Nothing else evicts it, so without this the whole reuse
    /// window is one solid block of failed signatures.
    ///
    /// `refused` is the token the caller actually presented, and eviction is conditional on
    /// the cache still holding THAT token. An unconditional `take()` has no such identity:
    /// during a rotation, N threads each holding the old token would discard, one after
    /// another, the successor the thread ahead of them had just minted, turning N refusals
    /// into N serialized metadata fetches. Comparing makes the second and later threads
    /// report `false` — their refusal was about a token that is already gone.
    ///
    /// The boolean also bounds the retry: a source with nothing cached reports `false` and
    /// its caller does not spend a second Cloud KMS call proving the same refusal.
    ///
    /// The default is "nothing of mine was discarded" — correct for any source that mints
    /// or reads its token per call.
    fn invalidate(&self, _refused: &str) -> bool {
        false
    }
}

/// An operator-supplied access token read from `MCP_RE_GCP_ACCESS_TOKEN`. The
/// operator is responsible for refreshing it (tokens are ~1h); documented, not
/// silently managed.
pub(crate) struct EnvAccessTokenSource;

impl GcpAccessTokenSource for EnvAccessTokenSource {
    fn access_token(&self) -> Result<Zeroizing<String>, KeyError> {
        match std::env::var("MCP_RE_GCP_ACCESS_TOKEN") {
            Ok(t) if !t.is_empty() => Ok(Zeroizing::new(t)),
            _ => Err(KeyError::NotFound(
                "gcp-kms: MCP_RE_GCP_ACCESS_TOKEN not set".to_string(),
            )),
        }
    }
}

/// The longest lifetime a metadata-server token is believed on.
///
/// A GCE/GKE workload-identity access token lives one hour. A response claiming more is not
/// stating a lifetime the peer can honestly promise, so the claim is truncated rather than
/// trusted — this is a truthful ceiling, not a guess at the real value.
///
/// Unbounded, it was a permanent loss of GCP-rooted signing: `expires_in: 10000000000` is
/// 317 years, passes `checked_add` cleanly, and pins the token for the process lifetime, so
/// [`TOKEN_REFRESH_MARGIN`] never fires again. Nothing else recovers from that — eviction
/// is 401-only by design, and a token Cloud KMS AUTHENTICATES but does not AUTHORIZE
/// answers 403, so a token pinned this way is never re-fetched, the rotor cannot mint a
/// successor, and the replica fails closed at the current credential's `exp` until it is
/// restarted. The metadata endpoint is plaintext link-local, so one answered request from a
/// transient on-node position is enough; an emulator that overstates a lifetime does the
/// same with no attacker at all.
const MAX_TOKEN_LIFETIME_SECS: u64 = 3600;

/// The expiry the response STATED, `expires_in` seconds after `now` (truncated at
/// [`MAX_TOKEN_LIFETIME_SECS`]) — or `None` when no lifetime could be established at all.
///
/// `None` is a FACT the response carried, returned explicitly rather than encoded as a
/// value the caller is expected to recognise. That distinction is load-bearing on this
/// path: the caller reads its own clock and this function is given another, so any encoding
/// of "unknown" as an expiry EQUAL to some current instant is decided by whether two
/// independent clock readings happen to match — true at microsecond granularity, false on
/// the nanosecond `CLOCK_REALTIME` of the Linux targets. A floor gated that way silently
/// never applies, and every caller then misses the cache and runs its own metadata round
/// trip, which is the per-handshake amplification [`UNKNOWN_EXPIRY_REUSE`] exists to
/// prevent. A fact cannot be lost to clock granularity; a value coincidence can.
///
/// Two inputs produce `None`. A zero `expires_in` — which is also what
/// [`token_from_metadata_response`] yields for an absent, non-numeric or negative field, so
/// every unreadable response lands here. And an overflow: `SystemTime`'s `Add<Duration>`
/// panics, and `expires_in` comes from the metadata server over PLAINTEXT http (the
/// endpoint is fixed at [`DEFAULT_METADATA_ENDPOINT`] on every production path — the
/// constructor's parameter exists for this module's tests), so a hostile near-`u64::MAX`
/// value must not panic the blocking serve thread.
fn stated_expiry(now: SystemTime, expires_in: u64) -> Option<SystemTime> {
    if expires_in == 0 {
        return None;
    }
    now.checked_add(Duration::from_secs(expires_in.min(MAX_TOKEN_LIFETIME_SECS)))
}

/// The GCE/GKE metadata server (workload identity). Fetches a token and caches it
/// until shortly before its stated expiry.
pub(crate) struct MetadataServerTokenSource {
    agent: ureq::Agent,
    endpoint: String,
    state: Mutex<TokenState>,
    /// Held across a fetch so concurrent callers coalesce onto one.
    ///
    /// The state lock is deliberately NOT held across the round trip — that would put a
    /// 5-second network call under a lock every signature takes. This one is, and the
    /// state is re-read after acquiring it, so a burst of callers that all miss the cache
    /// produces a single metadata fetch rather than one each. Mirrors the AWS STS
    /// sibling's `exchanging` lock, and for the same reason: the trigger is an
    /// unauthenticated TLS handshake.
    ///
    /// What it coalesces is one source's callers. Each [`GcpKmsEd25519Backend`] builds its
    /// own source, and the composition root builds a separate backend for object signing
    /// and for delegated TLS, so those two paths do NOT share this lock or its cached
    /// token — they share only the metadata server's own quota. A handshake burst is
    /// bounded to one in-flight fetch on the TLS backend, which is what keeps that quota
    /// from being spent, not a coalescing that spans both backends.
    fetching: Mutex<()>,
}

/// The cached token and the last failed fetch, under one lock.
#[derive(Default)]
struct TokenState {
    token: Option<CachedToken>,
    /// See [`METADATA_FAILURE_COOLDOWN`]: a fetch that just timed out is the reason NOT to
    /// start another one, and nothing else in this struct records that it happened.
    last_failure: Option<FailedFetch>,
}

/// A fetch that failed, kept only long enough for waiters inside the cool-off to be given
/// the error rather than paying their own [`NETWORK_TIMEOUT`] to rediscover it.
struct FailedFetch {
    at: SystemTime,
    /// [`KeyError`] is not `Clone`, so the replay is rebuilt from its parts and is
    /// byte-identical to what the fetching thread returned — including the variant, which
    /// callers match on.
    malformed: bool,
    message: String,
}

impl FailedFetch {
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
        FailedFetch {
            at,
            malformed,
            message,
        }
    }
}

/// A token as the metadata server handed it over.
struct FetchedToken {
    token: Zeroizing<String>,
    /// The expiry the response STATED, or `None` when no lifetime could be established —
    /// see [`stated_expiry`]. An explicit fact, because the value-coincidence encoding it
    /// replaced stopped firing the moment two clocks were read instead of one.
    expires_at: Option<SystemTime>,
}

/// A token in the cache, with the expiry the freshness gate measures against — the stated
/// one, or the [`UNKNOWN_EXPIRY_REUSE`] bound when there was none.
struct CachedToken {
    token: Zeroizing<String>,
    expires_at: SystemTime,
}

impl MetadataServerTokenSource {
    pub(crate) fn new(endpoint: Option<String>) -> Self {
        MetadataServerTokenSource {
            agent: ureq::AgentBuilder::new().build(),
            endpoint: endpoint.unwrap_or_else(|| DEFAULT_METADATA_ENDPOINT.to_string()),
            state: Mutex::new(TokenState::default()),
            fetching: Mutex::new(()),
        }
    }

    /// The token state, recovering a poisoned lock rather than propagating the panic.
    ///
    /// Poison is sticky for the process lifetime, so propagating it would turn one panic
    /// anywhere in a fetch into a PERMANENT loss of GCP KMS signing on this replica: every
    /// delegated-TLS handshake fails and the cold-path rotor cannot mint a successor, so
    /// the replica fails closed on `delegated_signing_unavailable` at the current delegated
    /// key's `exp` with nothing that recovers it. Nothing here can be observed
    /// half-written — both fields are whole-value swaps — so there is no invariant for the
    /// poison to protect. Matches `delegated_server_signer` and `reloading_trust`.
    fn state(&self) -> std::sync::MutexGuard<'_, TokenState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The cached token, if it is still fresh enough to authorize a call with.
    ///
    /// [`TOKEN_REFRESH_MARGIN`] is subtracted from EVERY expiry, including one the
    /// [`UNKNOWN_EXPIRY_REUSE`] floor stamped — which is why that floor has to exceed the
    /// margin to have any effect at all.
    fn fresh(state: &TokenState, now: SystemTime) -> Option<Zeroizing<String>> {
        state
            .token
            .as_ref()
            .and_then(|c| (now + TOKEN_REFRESH_MARGIN < c.expires_at).then(|| c.token.clone()))
    }

    /// The cached token if it is fresh, or the error of a fetch that failed inside
    /// [`METADATA_FAILURE_COOLDOWN`] — so no caller starts a round trip that a thread just
    /// ahead of it has already proved will fail.
    ///
    /// A clock that has moved BACKWARDS closes the window instead of extending it:
    /// `duration_since` is an error when `now` precedes the recorded instant, and a
    /// suppression window that outlived a clock jump would be a signing outage.
    fn fresh_or_recent_failure(
        &self,
        now: SystemTime,
    ) -> Result<Option<Zeroizing<String>>, KeyError> {
        let state = self.state();
        if let Some(token) = Self::fresh(&state, now) {
            return Ok(Some(token));
        }
        match &state.last_failure {
            Some(failure)
                if now
                    .duration_since(failure.at)
                    .is_ok_and(|elapsed| elapsed < METADATA_FAILURE_COOLDOWN) =>
            {
                Err(failure.replay())
            }
            _ => Ok(None),
        }
    }

    /// Serve the cached token, or run ONE fetch and cache what it returns.
    ///
    /// `clock` and `fetch` are parameters so the single-flight, the reuse floor and the
    /// failure cool-off are provable without a metadata server. `clock` is read THREE
    /// times, and which reading is used where is the whole correctness of the cool-off:
    /// once on entry, again after the flight lock is acquired — this thread may have been
    /// blocked there for a whole [`NETWORK_TIMEOUT`], and both the cache and the failure
    /// record may have been written while it was — and once more after a failed `fetch`,
    /// to stamp the record with the instant the failure was PROVED rather than the instant
    /// this caller arrived.
    fn cached_or_fetch(
        &self,
        clock: &dyn Fn() -> SystemTime,
        fetch: &dyn Fn() -> Result<FetchedToken, KeyError>,
    ) -> Result<Zeroizing<String>, KeyError> {
        if let Some(token) = self.fresh_or_recent_failure(clock())? {
            return Ok(token);
        }
        let _flight = self.fetching.lock().unwrap_or_else(|p| p.into_inner());
        // Whoever held this lock may have just filled the cache — or just failed, in which
        // case repeating their fetch costs this thread a whole NETWORK_TIMEOUT and the
        // waiter behind it another one. Re-read the clock: the entry reading is up to one
        // timeout stale by now, and comparing a fresh record against it is what let every
        // late-arriving waiter through.
        let now = clock();
        if let Some(token) = self.fresh_or_recent_failure(now)? {
            return Ok(token);
        }
        let fresh = match fetch() {
            Ok(fresh) => fresh,
            Err(error) => {
                self.state().last_failure = Some(FailedFetch::of(&error, clock()));
                return Err(error);
            }
        };
        // Decided from what the response SAID, never from a comparison between two clock
        // readings: a token whose lifetime could not be established is bounded at
        // UNKNOWN_EXPIRY_REUSE, and a stated lifetime — including one about to lapse — is
        // used exactly as stated and never extended.
        let expires_at = match fresh.expires_at {
            Some(stated) => stated,
            None => now + UNKNOWN_EXPIRY_REUSE,
        };
        let token = fresh.token.clone();
        let mut state = self.state();
        state.token = Some(CachedToken {
            token: fresh.token,
            expires_at,
        });
        state.last_failure = None;
        Ok(token)
    }

    /// One metadata-server round trip, returning the token and the expiry it STATED.
    fn fetch_token(&self, now: SystemTime) -> Result<FetchedToken, KeyError> {
        let url = format!(
            "{}/computeMetadata/v1/instance/service-accounts/default/token",
            self.endpoint
        );
        let body = match self
            .agent
            .get(&url)
            .set("Metadata-Flavor", "Google")
            .timeout(NETWORK_TIMEOUT)
            .call()
        {
            Ok(resp) => {
                // The response body IS the credential. Held in `Zeroizing` from the
                // first allocation, like the AWS sibling's STS body: a live bearer
                // token that authorizes Cloud KMS `asymmetricSign` on the root key must
                // not be left in freed heap for a core dump or a swapped page to yield,
                // and scrubbing only the final copy leaves the raw JSON behind.
                let mut buf = Zeroizing::new(String::new());
                resp.into_reader()
                    .take(64 * 1024)
                    .read_to_string(&mut buf)
                    .map_err(|e| KeyError::NotFound(format!("gcp-kms: read token: {e}")))?;
                buf
            }
            Err(e) => {
                return Err(KeyError::NotFound(format!(
                    "gcp-kms: metadata-server token fetch: {e}"
                )))
            }
        };
        let (token, expires_in) = token_from_metadata_response(&body)?;
        // `expires_in` is attacker-influenceable — the metadata endpoint is plaintext HTTP,
        // so anyone on the link-local path can choose it. `stated_expiry` answers with
        // `None` for a value it cannot turn into a lifetime (absent, zero, non-numeric, or
        // overflowing `SystemTime`), which `cached_or_fetch` reads as the fact it is rather
        // than inferring it from a clock comparison.
        Ok(FetchedToken {
            token,
            expires_at: stated_expiry(now, expires_in),
        })
    }
}

/// Take the access token and its stated lifetime out of a workload-identity token
/// response.
///
/// Every copy of the credential this makes is scrubbed on drop. The token is MOVED out
/// of the parsed document rather than read from it: `as_str().to_string()` would leave
/// the `Value`'s own owned `String` — a second copy of a live bearer credential that
/// authorizes Cloud KMS `asymmetricSign` on the root key — to drop unprotected into
/// freed heap, where a core dump, a swapped page or a later memory-disclosure primitive
/// recovers it. Disclosure of THIS credential is a root-authority compromise, not a
/// session one, because it is what mints delegation credentials.
fn token_from_metadata_response(
    body: &Zeroizing<String>,
) -> Result<(Zeroizing<String>, u64), KeyError> {
    let mut document: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| KeyError::Malformed(format!("gcp-kms: token JSON: {e}")))?;
    let expires_in = document
        .get("expires_in")
        .and_then(|s| s.as_u64())
        .unwrap_or(0);
    Ok((take_access_token(&mut document)?, expires_in))
}

/// Move the `access_token` string out of a parsed token response, leaving the document
/// holding no copy of it.
fn take_access_token(document: &mut serde_json::Value) -> Result<Zeroizing<String>, KeyError> {
    let token = match document.get_mut("access_token") {
        Some(serde_json::Value::String(s)) => Zeroizing::new(std::mem::take(s)),
        _ => {
            return Err(KeyError::Malformed(
                "gcp-kms: token has no access_token".to_string(),
            ))
        }
    };
    if token.is_empty() {
        return Err(KeyError::Malformed(
            "gcp-kms: metadata server returned an empty access_token".to_string(),
        ));
    }
    Ok(token)
}

impl GcpAccessTokenSource for MetadataServerTokenSource {
    fn access_token(&self) -> Result<Zeroizing<String>, KeyError> {
        self.cached_or_fetch(&SystemTime::now, &|| self.fetch_token(SystemTime::now()))
    }

    fn invalidate(&self, refused: &str) -> bool {
        let mut state = self.state();
        // Only if the cache still holds the very token that was refused. Another thread may
        // have replaced it already, and discarding ITS successor would make a rotation cost
        // one metadata fetch per concurrent refusal.
        //
        // The failure record is left alone either way: it is about the metadata server, and
        // Cloud KMS refusing a token says nothing about whether the metadata server is
        // answering.
        match state.token.as_ref() {
            Some(cached) if cached.token.as_str() == refused => {
                state.token = None;
                true
            }
            _ => false,
        }
    }
}

/// The blocking-HTTPS seam to Cloud KMS: the two KMS operations as raw-JSON-body
/// calls. A trait so the adapter's parsing + verify-before-return logic is
/// unit-testable with a local-key fake and no network.
pub(crate) trait GcpKmsTransport {
    fn get_public_key(&self) -> Result<Vec<u8>, KeyError>;
    fn asymmetric_sign(&self, body: &[u8]) -> Result<Vec<u8>, KeyError>;
}

/// Production [`GcpKmsTransport`]: bearer-authed `ureq` (rustls HTTPS).
pub(crate) struct UreqGcpClient {
    agent: ureq::Agent,
    token_source: Box<dyn GcpAccessTokenSource + Send + Sync>,
    sign_url: String,
    public_key_url: String,
    /// When the refused-token retry may fire again, set after a FRESH token was refused
    /// too. `None` outside a suspension, which is the steady state.
    /// See [`TOKEN_REFUSAL_RETRY_COOLDOWN`].
    token_retry_suspended_until: Mutex<Option<Instant>>,
}

/// One Cloud KMS call's failure, with the HTTP status kept separable from the rendered
/// message so the bearer-token retry keys on 401/403 rather than on message text.
enum KmsCallError {
    /// A failure that carries its own rendered diagnosis — no bearer token could be
    /// produced, or the response body could not be read — passed through unchanged.
    Rendered(KeyError),
    Status(u16, String),
    Transport(String),
}

impl KmsCallError {
    /// The rendered error. [`is_kms_throttling`] classifies Cloud KMS failures out of this
    /// text, so the two shapes it matches are produced here and nowhere else.
    fn into_key_error(self, operation: &str) -> KeyError {
        match self {
            KmsCallError::Rendered(error) => error,
            KmsCallError::Status(code, body) => {
                KeyError::NotFound(format!("gcp-kms: {operation} HTTP {code}: {body}"))
            }
            KmsCallError::Transport(error) => {
                KeyError::NotFound(format!("gcp-kms: {operation}: {error}"))
            }
        }
    }

    /// Did Cloud KMS reject the BEARER TOKEN itself, rather than what the caller may do
    /// with it?
    ///
    /// ONLY 401. Cloud KMS answers 401 `UNAUTHENTICATED` for a credential it will not read
    /// — missing, malformed, expired, revoked — and that is the one state a fresh token
    /// can fix.
    ///
    /// 403 is deliberately NOT here, and was a defect while it was: Cloud KMS returns 403
    /// for `PERMISSION_DENIED` (the service account is authenticated fine but has no
    /// `cloudkms.cryptoKeyVersions.useToSign` binding), for `SERVICE_DISABLED`, and for
    /// billing failures. Those are the most common Cloud KMS misconfigurations, the token
    /// is perfectly valid in all of them, and evicting on 403 turned every handshake into
    /// KMS call -> 403 -> throw away a good token -> real metadata round trip -> KMS call
    /// -> 403. That is exactly the per-handshake metadata amplification
    /// [`UNKNOWN_EXPIRY_REUSE`] exists to prevent, re-entered through a different door and
    /// drivable by an unauthenticated peer — and [`is_kms_throttling`] excludes 403, so the
    /// handshake cooldown is no backstop for it.
    fn rejected_the_bearer_token(&self) -> bool {
        matches!(self, KmsCallError::Status(401, _))
    }

    /// The rendered text, for chaining a first failure onto the retry's.
    fn describe(&self, operation: &str) -> String {
        match self {
            KmsCallError::Rendered(error) => format!("{error}"),
            KmsCallError::Status(code, body) => format!("{operation} HTTP {code}: {body}"),
            KmsCallError::Transport(error) => format!("{operation}: {error}"),
        }
    }
}

impl UreqGcpClient {
    pub(crate) fn new(
        token_source: Box<dyn GcpAccessTokenSource + Send + Sync>,
        config: &GcpKmsConfig,
    ) -> Result<Self, KeyError> {
        let base = config
            .endpoint
            .clone()
            .unwrap_or_else(|| DEFAULT_KMS_ENDPOINT.to_string());
        // The endpoint decides who receives a live workload-identity bearer token that
        // authorizes `asymmetricSign` on the ROOT response-signing key, and who answers
        // `getPublicKey` with the SPKI that BECOMES the root verify key — so a substituted
        // endpoint substitutes the root authority self-consistently and every local
        // verify-before-return check then passes against the attacker's key. Checked here
        // as well as at the CLI because `GcpKmsConfig::endpoint` is public and an embedder
        // reaches this constructor without meeting a parser.
        crate::kms_endpoint_policy::kms_endpoint_authority(&base)
            .map_err(|why| KeyError::Malformed(format!("gcp-kms: --gcp-kms-endpoint {why}")))?;
        // A trailing slash is a spelling of the same endpoint, and the gate admits it — so
        // it must not survive into the per-operation URLs, where `{base}/v1/...` on
        // `https://cloudkms.googleapis.com/` would build a doubled `//v1/` path that Cloud
        // KMS does not serve.
        let base = base.trim_end_matches('/');
        let name = &config.key_version_name;
        Ok(UreqGcpClient {
            agent: ureq::AgentBuilder::new().build(),
            token_source,
            sign_url: format!("{base}/v1/{name}:asymmetricSign"),
            public_key_url: format!("{base}/v1/{name}/publicKey"),
            token_retry_suspended_until: Mutex::new(None),
        })
    }

    /// The `Authorization` header value for `token`, held in `Zeroizing` so the bearer
    /// token is scrubbed from memory on drop (repo secret-hygiene posture).
    fn bearer(token: &str) -> Zeroizing<String> {
        Zeroizing::new(format!("Bearer {token}"))
    }

    /// Run `call` with the current bearer token; if Cloud KMS answered 401, discard THAT
    /// token and run it once more with a fresh one.
    ///
    /// A cached token can stop being honoured before the expiry it was cached under, and
    /// nothing else evicts it — so without this a token that Cloud KMS refuses fails EVERY
    /// signature, every delegated-credential issuance and every delegated-TLS handshake
    /// for the whole reuse window, with no path back.
    ///
    /// Bounded to one extra call, and suppressed entirely in three cases. The token
    /// presented is passed to [`GcpAccessTokenSource::invalidate`], which evicts only if
    /// the cache still holds it, so a source with nothing cached — and every thread whose
    /// refusal concerned a token another thread has already replaced — spends no second
    /// call re-proving the same refusal. And a refusal that a FRESH token did not fix opens
    /// a [`TOKEN_REFUSAL_RETRY_COOLDOWN`], during which no eviction and no retry happen at
    /// all, because a permanent refusal retried per call is a metadata round trip per
    /// handshake.
    ///
    /// If the retry fails too, BOTH failures are reported. The 401 is the cause and the
    /// retry's error is the symptom; rendering only the second left an operator reading a
    /// metadata-server error with nothing to say why a token was being fetched at all.
    fn with_token_retry(
        &self,
        operation: &str,
        call: impl Fn(&str) -> Result<Vec<u8>, KmsCallError>,
    ) -> Result<Vec<u8>, KeyError> {
        self.with_token_retry_at(operation, Instant::now(), call)
    }

    /// As [`Self::with_token_retry`], at an explicit instant so the suspension is provable
    /// without waiting on a clock.
    fn with_token_retry_at(
        &self,
        operation: &str,
        now: Instant,
        call: impl Fn(&str) -> Result<Vec<u8>, KmsCallError>,
    ) -> Result<Vec<u8>, KeyError> {
        let token = self
            .token_source
            .access_token()
            .map_err(|error| KmsCallError::Rendered(error).into_key_error(operation))?;
        let refused = match call(&Self::bearer(&token)) {
            Ok(body) => return Ok(body),
            Err(error) => error,
        };
        if !refused.rejected_the_bearer_token() || self.token_retry_suspended(now) {
            return Err(refused.into_key_error(operation));
        }
        if !self.token_source.invalidate(&token) {
            return Err(refused.into_key_error(operation));
        }
        let cause = refused.describe(operation);
        let fresh = match self.token_source.access_token() {
            Ok(fresh) => fresh,
            Err(error) => {
                self.suspend_token_retry(now);
                return Err(KeyError::NotFound(format!(
                    "gcp-kms: {error} (after Cloud KMS refused the cached token with: \
                     gcp-kms: {cause})"
                )));
            }
        };
        match call(&Self::bearer(&fresh)) {
            Ok(body) => {
                // The refusal WAS a stale token. Whatever suspension a previous permanent
                // refusal opened is over.
                *self
                    .token_retry_suspended_until
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = None;
                Ok(body)
            }
            Err(error) => {
                if error.rejected_the_bearer_token() {
                    // A FRESH token was refused too, so this is not a rotation and no
                    // number of retries will fix it. Stop paying for them.
                    self.suspend_token_retry(now);
                }
                Err(KeyError::NotFound(format!(
                    "gcp-kms: {} (after Cloud KMS refused the cached token with: gcp-kms: \
                     {cause})",
                    error.describe(operation)
                )))
            }
        }
    }

    /// Is the refused-token retry suspended at `now`? Clears a lapsed suspension so the
    /// next refusal probes once more.
    fn token_retry_suspended(&self, now: Instant) -> bool {
        let mut suspended = self
            .token_retry_suspended_until
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        match *suspended {
            Some(until) if now < until => true,
            Some(_) => {
                *suspended = None;
                false
            }
            None => false,
        }
    }

    fn suspend_token_retry(&self, now: Instant) {
        let mut suspended = self
            .token_retry_suspended_until
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let until = now + TOKEN_REFUSAL_RETRY_COOLDOWN;
        // Never shorten: a straggler holding an older `now` must not replace a window a
        // later thread just opened with one that has already elapsed.
        *suspended = Some(suspended.map_or(until, |current| current.max(until)));
    }

    fn get_public_key_once(&self, auth: &str) -> Result<Vec<u8>, KmsCallError> {
        match self
            .agent
            .get(&self.public_key_url)
            .set("Authorization", auth)
            .timeout(NETWORK_TIMEOUT)
            .call()
        {
            Ok(resp) => read_body(resp).map_err(KmsCallError::Rendered),
            Err(ureq::Error::Status(code, resp)) => {
                Err(KmsCallError::Status(code, read_error_body(resp)))
            }
            Err(e) => Err(KmsCallError::Transport(e.to_string())),
        }
    }

    fn asymmetric_sign_once(&self, auth: &str, body: &[u8]) -> Result<Vec<u8>, KmsCallError> {
        match self
            .agent
            .post(&self.sign_url)
            .set("Authorization", auth)
            .set("Content-Type", "application/json")
            .timeout(NETWORK_TIMEOUT)
            .send_bytes(body)
        {
            Ok(resp) => read_body(resp).map_err(KmsCallError::Rendered),
            Err(ureq::Error::Status(code, resp)) => {
                Err(KmsCallError::Status(code, read_error_body(resp)))
            }
            Err(e) => Err(KmsCallError::Transport(e.to_string())),
        }
    }
}

impl GcpKmsTransport for UreqGcpClient {
    fn get_public_key(&self) -> Result<Vec<u8>, KeyError> {
        self.with_token_retry("getPublicKey", |auth| self.get_public_key_once(auth))
    }

    fn asymmetric_sign(&self, body: &[u8]) -> Result<Vec<u8>, KeyError> {
        self.with_token_retry("asymmetricSign", |auth| {
            self.asymmetric_sign_once(auth, body)
        })
    }
}

fn read_body(resp: ureq::Response) -> Result<Vec<u8>, KeyError> {
    let mut buf = Vec::new();
    resp.into_reader()
        .take(256 * 1024)
        .read_to_end(&mut buf)
        .map_err(|e| KeyError::NotFound(format!("gcp-kms: read response: {e}")))?;
    Ok(buf)
}

/// Read a bounded, lossy string from an HTTP *error* response body (diagnostics
/// only). An emulator/overridden endpoint could otherwise return an arbitrarily
/// large body; cap it rather than `into_string()`'s unbounded read.
fn read_error_body(resp: ureq::Response) -> String {
    let mut buf = Vec::new();
    let _ = resp
        .into_reader()
        .take(MAX_ERROR_BODY_BYTES)
        .read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// The `asymmetricSign` request body for an Ed25519 (`EC_SIGN_ED25519`) key — raw
/// `data` (PureEdDSA), never `digest`.
fn sign_request_body(preimage: &[u8]) -> Vec<u8> {
    serde_json::json!({ "data": STANDARD.encode(preimage) })
        .to_string()
        .into_bytes()
}

/// Strip a PEM wrapper to the base64 body and standard-decode it to DER.
fn spki_der_from_pem(pem: &str) -> Result<Vec<u8>, KeyError> {
    let mut b64 = String::new();
    let mut in_body = false;
    for line in pem.lines() {
        let t = line.trim();
        if t.starts_with("-----BEGIN") {
            in_body = true;
        } else if t.starts_with("-----END") {
            break;
        } else if in_body {
            b64.push_str(t);
        }
    }
    if b64.is_empty() {
        return Err(KeyError::Malformed(
            "gcp-kms: public-key PEM has no body".to_string(),
        ));
    }
    STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| KeyError::Malformed(format!("gcp-kms: PEM base64: {e}")))
}

/// Parse a `getPublicKey` response: `algorithm` MUST be `EC_SIGN_ED25519` and `pem`
/// is the RFC 8410 Ed25519 SPKI. Fails closed on any other algorithm so a
/// non-Ed25519 key version can never be admitted.
fn parse_public_key_response(body: &[u8]) -> Result<Vec<u8>, KeyError> {
    let v: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| KeyError::Malformed(format!("gcp-kms: getPublicKey JSON: {e}")))?;
    let algorithm = v
        .get("algorithm")
        .and_then(|s| s.as_str())
        .ok_or_else(|| KeyError::Malformed("gcp-kms: getPublicKey has no algorithm".to_string()))?;
    if algorithm != ALGORITHM_ED25519 {
        return Err(KeyError::Malformed(format!(
            "gcp-kms: key algorithm is '{algorithm}', not {ALGORITHM_ED25519}; the KMS key MUST be \
             an Ed25519 key"
        )));
    }
    let pem = v
        .get("pem")
        .and_then(|s| s.as_str())
        .ok_or_else(|| KeyError::Malformed("gcp-kms: getPublicKey has no pem".to_string()))?;
    spki_der_from_pem(pem)
}

/// Parse an `asymmetricSign` response: `signature` is the standard-base64 raw
/// Ed25519 signature.
fn parse_sign_response(body: &[u8]) -> Result<Vec<u8>, KeyError> {
    let v: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| KeyError::Malformed(format!("gcp-kms: asymmetricSign JSON: {e}")))?;
    let sig_b64 = v.get("signature").and_then(|s| s.as_str()).ok_or_else(|| {
        KeyError::Malformed("gcp-kms: asymmetricSign response has no signature".to_string())
    })?;
    STANDARD
        .decode(sig_b64)
        .map_err(|e| KeyError::Malformed(format!("gcp-kms: signature base64: {e}")))
}

/// How long the delegated-TLS path stops calling Cloud KMS after Cloud KMS has
/// reported that the project is over its cryptographic-operations quota.
///
/// The handshake path and the root-issuance path share one project quota, and only the
/// handshake path can be driven by an unauthenticated peer: TLS 1.3 emits the server
/// `CertificateVerify` — one `asymmetricSign` — before it has seen a client
/// certificate, and with session resumption refused every connection is a full
/// handshake. Left alone, a connection flood spends the project's quota, and the
/// cold-path rotor's sign for the next delegated credential fails with it; the replica
/// then fails closed on `delegated_signing_unavailable` when the current credential's
/// TTL runs out. A handshake flood becomes a signing outage.
///
/// So the throttle is treated as a signal about the shared quota, not as one request's
/// bad luck: for this window the handshake path refuses locally WITHOUT calling Cloud
/// KMS, leaving the quota to the issuance path. Refusing handshakes is the cheap
/// failure — a peer retries a connection; a replica that has lost response signing does
/// not recover until a credential can be minted. Matches the AWS sibling's
/// `TLS_SIGN_THROTTLE_COOLDOWN`.
///
/// It is at least [`NETWORK_TIMEOUT`] long, for the same reason
/// [`METADATA_FAILURE_COOLDOWN`] is. The window is opened in reaction to a call that may
/// have taken a whole timeout, so a window shorter than that timeout can be installed
/// already elapsed — and it would be exactly in the regime the window exists for, an
/// overloaded Cloud KMS answering slowly, that the mitigation degenerated to no throttle at
/// all. `the_throttle_window_must_outlast_the_network_timeout` fails the build if that
/// stops being true.
const TLS_SIGN_THROTTLE_COOLDOWN: Duration = NETWORK_TIMEOUT;

/// Does this Cloud KMS failure say the PROJECT is over its quota, rather than that one
/// request was malformed?
///
/// Classified from the rendered error because [`KeyError`] carries no machine-readable
/// status and its taxonomy is frozen. The text it matches is produced by
/// [`UreqGcpClient::asymmetric_sign`] in this module, which renders the HTTP status and
/// interpolates the Cloud KMS JSON error body verbatim — `RESOURCE_EXHAUSTED` and
/// `UNAVAILABLE` are the two statuses that mean the project, not the request.
fn is_kms_throttling(error: &KeyError) -> bool {
    let rendered = format!("{error:?}");
    ["RESOURCE_EXHAUSTED", "UNAVAILABLE", "HTTP 429", "HTTP 503"]
        .iter()
        .any(|marker| rendered.contains(marker))
}

/// A non-exporting [`KmsEd25519Backend`] backed by GCP Cloud KMS.
pub struct GcpKmsEd25519Backend {
    transport: Box<dyn GcpKmsTransport + Send + Sync>,
    spki_der: Vec<u8>,
    verify_key: VerificationKey,
    /// When the delegated-TLS path may call Cloud KMS again, set after Cloud KMS
    /// reported throttling. `None` outside a cooldown, which is the steady state.
    tls_cooldown_until: Mutex<Option<Instant>>,
}

impl GcpKmsEd25519Backend {
    /// Build over an explicit transport — fetches and validates the public key once
    /// (Ed25519 SPKI, correct algorithm) and caches it for verify-before-return.
    pub(crate) fn with_transport(
        transport: Box<dyn GcpKmsTransport + Send + Sync>,
    ) -> Result<Self, KeyError> {
        let resp = transport.get_public_key()?;
        let spki_der = parse_public_key_response(&resp)?;
        let raw = ed25519_raw_point_from_spki(&spki_der)?;
        let verify_key = VerificationKey::from_bytes(&raw).map_err(|e| {
            KeyError::Malformed(format!("gcp-kms: invalid Ed25519 public key: {e}"))
        })?;
        Ok(GcpKmsEd25519Backend {
            transport,
            spki_der,
            verify_key,
            tls_cooldown_until: Mutex::new(None),
        })
    }

    /// Open a throttle window ending [`TLS_SIGN_THROTTLE_COOLDOWN`] after `now`, never
    /// SHORTENING one already in force.
    ///
    /// `now` MUST be a clock reading taken AFTER the call being reacted to. That is what
    /// keeps the window from being installed stale: it was previously the handshake's ENTRY
    /// instant, so a Cloud KMS call slower than the cooldown opened a window that had
    /// already elapsed — no throttle at all, precisely when Cloud KMS was slow enough to
    /// need one.
    ///
    /// `max` is a narrower guarantee than it looks and the two are easy to confuse: it
    /// stops a thread REPLACING a longer window with a shorter one, which is what plain
    /// assignment did when two threads reported failures out of order. It does NOT sanitise
    /// a stale reading — on the `None` branch, which is the steady state and the state a
    /// successful probe leaves behind, whatever `until` it is handed is installed outright.
    /// Freshness comes from the caller reading the clock here, not from `max`.
    fn arm_cooldown(&self, now: Instant) {
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
    /// Inside a cooldown this refuses WITHOUT reaching Cloud KMS. See
    /// [`TLS_SIGN_THROTTLE_COOLDOWN`]: the handshake path is the one an unauthenticated
    /// peer can drive, and it shares a project quota with the delegated-credential issuance
    /// that keeps the replica able to sign responses at all.
    ///
    /// `clock` is read TWICE and the distinction is load-bearing: once at the gate, to
    /// decide whether this handshake may reach Cloud KMS, and again AFTER the call, to open
    /// a window that reacts to when the call finished rather than to when the handshake
    /// arrived.
    fn tls_sign_at(
        &self,
        message: &[u8],
        clock: &dyn Fn() -> Instant,
    ) -> Result<Vec<u8>, KeyError> {
        let now = clock();
        // Whether THIS thread is the one probing a lapsed window. Only the thread that
        // observes the lapse takes the probe: it re-arms the window before releasing the
        // lock, so the rest of a concurrent handshake cohort at the boundary is still
        // refused instead of all calling Cloud KMS at once — which is the flood the
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
                        "gcp-kms: Cloud KMS is throttling this project; the delegated-TLS \
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

    /// Build a production GCP Cloud KMS backend (ureq HTTPS + bearer token).
    /// `use_metadata_server` selects the workload-identity metadata token source;
    /// otherwise an operator-supplied `MCP_RE_GCP_ACCESS_TOKEN` is used.
    pub fn new(config: &GcpKmsConfig, use_metadata_server: bool) -> Result<Self, KeyError> {
        let token_source: Box<dyn GcpAccessTokenSource + Send + Sync> = if use_metadata_server {
            Box::new(MetadataServerTokenSource::new(None))
        } else {
            Box::new(EnvAccessTokenSource)
        };
        let client = UreqGcpClient::new(token_source, config)?;
        Self::with_transport(Box::new(client))
    }

    /// TEST-ONLY (issue #61): build a backend over an in-memory FAKE Cloud KMS
    /// transport backed by the LOCAL Ed25519 key with the given 32-byte `seed`, so an
    /// integration test (`tests/tls_test.rs`) can drive the full delegated-TLS mTLS
    /// handshake against a GCP backend with NO network and NO GCP credentials. The
    /// fake transport answers `getPublicKey` with the key's RFC 8410 Ed25519 SPKI
    /// (PEM-wrapped) and `asymmetricSign` with a PureEdDSA RAW signature over the raw
    /// `data` — exactly what a real Cloud KMS `EC_SIGN_ED25519` key version returns.
    /// There is NO production code path into this; it exists only to make the
    /// crate-internal fake-transport reachable from the integration test that mints a
    /// matching server certificate from the same `seed`.
    #[doc(hidden)]
    pub fn for_test_with_local_seed(seed: &[u8; 32]) -> Result<Self, KeyError> {
        let transport = LocalKeyGcpTransport {
            key: mcp_re_core::SigningKey::from_seed_bytes(seed),
        };
        Self::with_transport(Box::new(transport))
    }
}

/// TEST-ONLY in-memory [`GcpKmsTransport`] backed by a LOCAL Ed25519 key — the same
/// fake-Cloud-KMS shape used by this module's unit tests, exposed (only via the
/// `#[doc(hidden)]` [`GcpKmsEd25519Backend::for_test_with_local_seed`]) so the
/// delegated-TLS handshake integration test can use a real GCP backend with no
/// network. NOT reachable from any production path.
#[doc(hidden)]
struct LocalKeyGcpTransport {
    key: mcp_re_core::SigningKey,
}

impl GcpKmsTransport for LocalKeyGcpTransport {
    fn get_public_key(&self) -> Result<Vec<u8>, KeyError> {
        let mut der = crate::kms_keysource::ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(&self.key.public_key().to_bytes());
        let b64 = STANDARD.encode(&der);
        let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(&String::from_utf8_lossy(chunk));
            pem.push('\n');
        }
        pem.push_str("-----END PUBLIC KEY-----\n");
        Ok(serde_json::json!({
            "algorithm": ALGORITHM_ED25519,
            "pem": pem,
        })
        .to_string()
        .into_bytes())
    }

    fn asymmetric_sign(&self, body: &[u8]) -> Result<Vec<u8>, KeyError> {
        let v: serde_json::Value = serde_json::from_slice(body)
            .map_err(|e| KeyError::Malformed(format!("fake gcp kms: sign body: {e}")))?;
        let data = STANDARD
            .decode(v.get("data").and_then(|d| d.as_str()).unwrap_or(""))
            .map_err(|e| KeyError::Malformed(format!("fake gcp kms: data b64: {e}")))?;
        let raw = mcp_re_core::b64url_decode(&self.key.sign(&data))
            .map_err(|e| KeyError::Malformed(format!("fake gcp kms: sign: {e}")))?;
        Ok(serde_json::json!({ "signature": STANDARD.encode(&raw) })
            .to_string()
            .into_bytes())
    }
}

impl KmsEd25519Backend for GcpKmsEd25519Backend {
    fn sign_raw_ed25519(&self, preimage: &[u8]) -> Result<Vec<u8>, KeyError> {
        let resp = self
            .transport
            .asymmetric_sign(&sign_request_body(preimage))?;
        let signature = parse_sign_response(&resp)?;
        if signature.len() != ED25519_SIGNATURE_LEN {
            return Err(KeyError::Malformed(format!(
                "gcp-kms: asymmetricSign returned a {}-byte signature; expected a raw \
                 {ED25519_SIGNATURE_LEN}-byte Ed25519 signature",
                signature.len()
            )));
        }
        // VERIFY-BEFORE-RETURN (ADR-MCPS-028 §D): the signature MUST verify against
        // the advertised public key under the unmodified mcp-re-core verifier — fail
        // closed on any mismatch, never emit a non-verifying signature.
        verify_ed25519(preimage, &b64url_encode(&signature), &self.verify_key).map_err(|e| {
            KeyError::Malformed(format!(
                "gcp-kms: KMS signature did NOT verify against the advertised public key: {e}"
            ))
        })?;
        Ok(signature)
    }

    fn public_key_spki_der(&self) -> Result<Vec<u8>, KeyError> {
        Ok(self.spki_der.clone())
    }
}

/// Delegated TLS handshake signing through GCP Cloud KMS (issue #61, ADR-MCPS-028 §G).
///
/// The TLS *server* key is a SECOND, DISTINCT Cloud KMS key VERSION (a separate
/// `key_version_name` and — the operator SHOULD give it — a distinct IAM policy)
/// from the object-signing key, custodied by its own [`GcpKmsEd25519Backend`]. The
/// TLS handshake signature is produced by the SAME RAW-Ed25519 `asymmetricSign` path
/// used for response signing (`EC_SIGN_ED25519`, PureEdDSA over the raw `data`, NOT a
/// digest), so the TLS private key never leaves Cloud KMS.
///
/// rustls verifies the handshake `CertificateVerify` it gets back, and the validated
/// delegated build path (#58) both enforces the 64-byte length and fails closed when
/// the (exportable, cached) public key here does not match the leaf TLS certificate —
/// so verify-before-return is NOT repeated on this path (it stays on the
/// object-signing `sign_raw_ed25519` path, which is reused unchanged).
impl RawEd25519TlsSigner for GcpKmsEd25519Backend {
    fn sign_tls_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        self.tls_sign_at(message, &Instant::now)
    }

    fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, KeyError> {
        // The advertised Cloud KMS public key, fetched + validated as Ed25519 at
        // construction; the #58 build path matches it against the leaf TLS cert.
        Ok(self.spki_der.clone())
    }
}

#[cfg(test)]
mod tests {
    use mcp_re_core::b64url_decode;
    use mcp_re_core::InMemoryTrustResolver;
    use mcp_re_core::SigningKey;
    use mcp_re_core::TrustResolver;
    use mcp_re_core::TrustResolverError;

    use super::*;
    use crate::kms_keysource::ED25519_SPKI_PREFIX;

    /// Build a PEM-wrapped RFC 8410 Ed25519 SPKI from a raw point (what GCP returns).
    fn pem_from_raw(raw: &[u8; 32]) -> String {
        let mut der = ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(raw);
        let b64 = STANDARD.encode(&der);
        let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END PUBLIC KEY-----\n");
        pem
    }

    /// The parsed document must be left holding NO copy of the bearer credential.
    ///
    /// Reading it out with `as_str().to_string()` leaves the `Value`'s own owned
    /// `String` to drop unscrubbed — a second copy of a token that authorizes Cloud KMS
    /// `asymmetricSign` on the root key, sitting in freed heap for the process lifetime.
    #[test]
    fn the_access_token_is_moved_out_of_the_parsed_document() {
        let mut document: serde_json::Value =
            serde_json::from_str(r#"{"access_token":"ya29.SECRET","expires_in":3599}"#)
                .expect("parses");
        let token = take_access_token(&mut document).expect("token");
        assert_eq!(&*token, "ya29.SECRET");
        assert_eq!(
            document.get("access_token").and_then(|v| v.as_str()),
            Some(""),
            "the document must not still own a copy of the credential"
        );
    }

    /// The body is the credential, so the whole response is held scrubbed — and the
    /// stated lifetime still comes back with it.
    #[test]
    fn a_token_response_yields_the_credential_and_its_lifetime() {
        let body = Zeroizing::new(
            r#"{"access_token":"ya29.SECRET","expires_in":3599,"token_type":"Bearer"}"#.to_string(),
        );
        let (token, expires_in) = token_from_metadata_response(&body).expect("parses");
        assert_eq!(&*token, "ya29.SECRET");
        assert_eq!(expires_in, 3599);
    }

    /// An empty or absent token is refused rather than used as a bearer credential.
    #[test]
    fn an_empty_or_absent_access_token_is_refused() {
        for body in [
            r#"{"expires_in":3599}"#,
            r#"{"access_token":"","expires_in":3599}"#,
            r#"{"access_token":42}"#,
        ] {
            assert!(
                token_from_metadata_response(&Zeroizing::new(body.to_string())).is_err(),
                "{body} must not yield a credential"
            );
        }
    }

    /// A hostile near-`u64::MAX` `expires_in` from the metadata server must NOT
    /// panic `SystemTime + Duration`; it clamps to `now` (already-expired), and a
    /// sane value adds normally. Regression for the panic-on-overflow finding.
    #[test]
    fn stated_expiry_reports_an_unestablishable_lifetime_as_a_fact() {
        let now = SystemTime::now();
        // Absent / non-numeric / zero all arrive here as 0.
        assert_eq!(stated_expiry(now, 0), None);
        // A sane value is stated exactly.
        assert_eq!(
            stated_expiry(now, 3600),
            Some(now + Duration::from_secs(3600))
        );
        // Even a one-second lifetime is a STATED one and is never confused with "unknown".
        assert_eq!(stated_expiry(now, 1), Some(now + Duration::from_secs(1)));
        // A claim beyond the real one-hour token lifetime is TRUNCATED, not trusted and
        // not rejected: an unbounded claim pins the token for the process lifetime, so
        // TOKEN_REFRESH_MARGIN never fires and nothing re-fetches it again. `expires_in`
        // comes from a plaintext link-local peer, and eviction is 401-only, so a token
        // Cloud KMS authenticates but does not authorize would never be replaced.
        let ceiling = Some(now + Duration::from_secs(MAX_TOKEN_LIFETIME_SECS));
        assert_eq!(stated_expiry(now, MAX_TOKEN_LIFETIME_SECS + 1), ceiling);
        assert_eq!(stated_expiry(now, 10_000_000_000), ceiling);
        // Overflow is unreachable once clamped, and still must not panic.
        assert_eq!(stated_expiry(now, u64::MAX), ceiling);
        assert_eq!(stated_expiry(now, u64::MAX - 1), ceiling);
    }

    fn token_source() -> MetadataServerTokenSource {
        // Never reached: every test below supplies its own `fetch`.
        MetadataServerTokenSource::new(Some("http://127.0.0.1:1".to_string()))
    }

    /// A fetch result carrying a STATED expiry.
    fn cached(token: &str, expires_at: SystemTime) -> FetchedToken {
        FetchedToken {
            token: Zeroizing::new(token.to_string()),
            expires_at: Some(expires_at),
        }
    }

    /// A fetch result whose lifetime could NOT be established — the fact, not a sentinel.
    fn no_stated_expiry(token: &str) -> FetchedToken {
        FetchedToken {
            token: Zeroizing::new(token.to_string()),
            expires_at: None,
        }
    }

    /// A token whose `expires_in` could not be read — `stated_expiry` answers `None` —
    /// must still be CACHED for a bounded
    /// window. Without that the freshness gate can never hold, so every use — under
    /// delegated TLS, every unauthenticated handshake — runs its own metadata fetch.
    #[test]
    fn an_unreadable_expires_in_is_reused_briefly_rather_than_refetched_every_call() {
        let source = token_source();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let now = SystemTime::now();
        let fetch = || {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(no_stated_expiry("ya29.SECRET"))
        };
        for _ in 0..5 {
            assert_eq!(
                &*source.cached_or_fetch(&|| now, &fetch).expect("token"),
                "ya29.SECRET"
            );
        }
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "an unreadable expires_in must not mean one metadata fetch per signature"
        );
        // And the reuse is bounded: past the window the next call re-fetches.
        source
            .cached_or_fetch(&|| now + UNKNOWN_EXPIRY_REUSE, &fetch)
            .expect("token");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    /// THE REGRESSION: the floor must survive every clock reading being different.
    ///
    /// `access_token` reads the clock twice — once for `cached_or_fetch` and once inside
    /// `fetch_token` — so encoding "no lifetime could be established" as `expires_at ==
    /// now` compared two independent readings for equality. On Linux's ns-resolution
    /// `CLOCK_REALTIME`, the GKE target, they never match: the floor never applied, the
    /// freshness gate could never be satisfied, and EVERY caller took the flight lock and
    /// ran its own metadata round trip. That is the per-handshake amplification
    /// R9-C057/C059 were about, reintroduced by the fix for R9-C060/C108.
    ///
    /// So this drives the REAL wiring: a clock that advances on every single read, and a
    /// fetch that computes its expiry from its OWN reading, exactly as `fetch_token` does.
    /// No fixture can collapse the two instants again.
    #[test]
    fn an_unreadable_expires_in_is_reused_when_every_clock_read_differs() {
        let source = token_source();
        let base = SystemTime::now();
        // Advances one nanosecond per read — the coarsest clock that still never repeats.
        let reads = std::sync::atomic::AtomicU64::new(0);
        let clock =
            || base + Duration::from_nanos(reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
        let fetches = std::sync::atomic::AtomicUsize::new(0);
        let fetch = || {
            fetches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // What `fetch_token` does: its own clock read, and `stated_expiry` on an
            // `expires_in` of 0 — the value an absent, non-numeric or zero field yields.
            Ok(FetchedToken {
                token: Zeroizing::new("ya29.SECRET".to_string()),
                expires_at: stated_expiry(clock(), 0),
            })
        };
        for _ in 0..5 {
            assert_eq!(
                &*source.cached_or_fetch(&clock, &fetch).expect("token"),
                "ya29.SECRET"
            );
        }
        assert_eq!(
            fetches.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a token whose lifetime could not be established must be reused for a bounded \
             window, not re-fetched on every call because two clock reads differed"
        );
    }

    /// POSITIVE CONTROL for the same wiring: a token that DOES state a lifetime is used
    /// exactly as stated, and a one-second lifetime is a stated one — never mistaken for
    /// "unknown" and never extended to the reuse bound.
    #[test]
    fn a_stated_lifetime_is_never_read_as_an_unestablishable_one() {
        let source = token_source();
        let base = SystemTime::now();
        let reads = std::sync::atomic::AtomicU64::new(0);
        let clock =
            || base + Duration::from_nanos(reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
        let fetches = std::sync::atomic::AtomicUsize::new(0);
        let fetch = || {
            fetches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(FetchedToken {
                token: Zeroizing::new("ya29.SECRET".to_string()),
                expires_at: stated_expiry(clock(), 1),
            })
        };
        // A one-second life is inside the refresh margin, so every call re-fetches. If the
        // floor had swallowed it as "unknown", the second call would have been served from
        // cache and this would read 1.
        source.cached_or_fetch(&clock, &fetch).expect("token");
        source.cached_or_fetch(&clock, &fetch).expect("token");
        assert_eq!(
            fetches.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "a stated one-second lifetime must be honoured, not floored to the reuse bound"
        );
        // And an hour-long stated lifetime is served from cache.
        let long = || {
            fetches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(FetchedToken {
                token: Zeroizing::new("ya29.SECRET".to_string()),
                expires_at: stated_expiry(clock(), 3600),
            })
        };
        source.cached_or_fetch(&clock, &long).expect("token");
        source.cached_or_fetch(&clock, &long).expect("token");
        assert_eq!(
            fetches.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "a stated hour-long lifetime must be cached"
        );
    }

    /// The floor must never extend a real expiry: a token with 100 seconds left is inside
    /// the refresh margin and is re-fetched, not held for the unknown-expiry window.
    #[test]
    fn a_stated_expiry_is_never_extended_by_the_reuse_floor() {
        let source = token_source();
        let now = SystemTime::now();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let fetch = || {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(cached("ya29.SECRET", now + Duration::from_secs(100)))
        };
        source.cached_or_fetch(&|| now, &fetch).expect("token");
        source
            .cached_or_fetch(&|| now + Duration::from_secs(60), &fetch)
            .expect("token");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "a token inside the refresh margin must be re-fetched, not reused"
        );
    }

    /// A clock with NO wall-time component at all.
    ///
    /// The properties below are about SECONDS — waiters arriving seconds apart, behind a
    /// fetch that occupies a whole `NETWORK_TIMEOUT`, against a cool-off of the same
    /// length. Two earlier attempts to express that failed in opposite ways. One shared
    /// `now` handed to every thread erased the dispersion the property is about, so a
    /// cool-off stamped with the caller's ENTRY instant passed. Scaling the wall clock
    /// restored the dispersion but left the outcome dependent on scheduling: on a loaded
    /// runner a late thread reads a later logical instant, and these are exactly the tests
    /// we now depend on. A flake here would retrain us to ignore the one test that caught
    /// a real defect.
    ///
    /// So the logical time is scripted, not measured. Caller `i` arrives at `base + i`
    /// seconds. Every reading it takes after the in-flight fetch has resolved returns the
    /// completion instant instead — which is exactly the ordering the real code produces,
    /// because a caller blocked on the flight lock cannot observe a time earlier than the
    /// fetch that was holding it. Real threads and real blocking are unchanged; only the
    /// clock is scripted, so no amount of scheduling noise can change the outcome.
    struct LogicalClock {
        base: SystemTime,
        /// Set once, by the thread whose fetch resolves.
        completed: Mutex<Option<Duration>>,
    }

    /// How long the in-flight fetch occupies, in logical seconds. Longer than the cool-off,
    /// so the waiters are still queued behind it when it resolves.
    const FETCH_SECONDS: u64 = 20;
    /// Real time each caller waits before entering, purely to make the threads actually
    /// contend. Nothing asserted depends on its value.
    const CONTENTION_DELAY: Duration = Duration::from_millis(3);

    impl LogicalClock {
        fn new() -> std::sync::Arc<Self> {
            std::sync::Arc::new(LogicalClock {
                base: SystemTime::now(),
                completed: Mutex::new(None),
            })
        }
        /// The reading caller `entered_at` seconds sees now.
        fn read(&self, entered_at: Duration) -> SystemTime {
            match *self.completed.lock().unwrap_or_else(|p| p.into_inner()) {
                Some(completed) if completed > entered_at => self.base + completed,
                _ => self.base + entered_at,
            }
        }
        fn finish_fetch(&self) {
            *self.completed.lock().unwrap_or_else(|p| p.into_inner()) =
                Some(Duration::from_secs(FETCH_SECONDS));
        }
    }

    /// Run 8 callers against `fetch`, each arriving one logical second after the last and
    /// each reading the clock ITSELF, and report how many reached `fetch`.
    fn staggered_callers(
        source: &std::sync::Arc<MetadataServerTokenSource>,
        fetch: impl Fn() -> Result<FetchedToken, KeyError> + Send + Sync + 'static,
        expect: impl Fn(Result<Zeroizing<String>, KeyError>) + Send + Sync + 'static,
    ) -> usize {
        let clock = LogicalClock::new();
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let fetch = std::sync::Arc::new(fetch);
        let expect = std::sync::Arc::new(expect);
        let threads: Vec<_> = (0..8u64)
            .map(|i| {
                let source = std::sync::Arc::clone(source);
                let clock = std::sync::Arc::clone(&clock);
                let attempts = std::sync::Arc::clone(&attempts);
                let fetch = std::sync::Arc::clone(&fetch);
                let expect = std::sync::Arc::clone(&expect);
                std::thread::spawn(move || {
                    let entered_at = Duration::from_secs(i);
                    std::thread::sleep(CONTENTION_DELAY * i as u32);
                    let outcome = source.cached_or_fetch(&|| clock.read(entered_at), &|| {
                        attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        // Hold the flight long enough that the others really do queue.
                        std::thread::sleep(CONTENTION_DELAY * 12);
                        let outcome = fetch();
                        clock.finish_fetch();
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

    /// A metadata fetch that FAILS must not be repeated by every waiter behind the flight.
    ///
    /// The lock is held across the round trip, so before the cool-off each waiter
    /// re-entered the miss path and paid its own `NETWORK_TIMEOUT`: N waiters drained in N
    /// timeouts, and under delegated TLS those waiters are handshake workers an
    /// unauthenticated peer supplies by opening connections.
    ///
    /// The callers arrive one logical second apart and each reads the clock itself, which
    /// is what makes this sensitive to WHICH instant the failure is stamped with. Stamped
    /// at the arriving caller's entry, the record is a whole `NETWORK_TIMEOUT` old the
    /// moment it is written, and every waiter that arrived more than one window after the
    /// fetching thread runs its own round trip. Counted at the fetch, not inferred from the
    /// error: the property is "the metadata server was called once".
    #[test]
    fn a_failed_metadata_fetch_is_not_repeated_by_every_waiter() {
        let source = std::sync::Arc::new(token_source());
        let attempts = staggered_callers(
            &source,
            || {
                Err(KeyError::NotFound(
                    "gcp-kms: metadata-server token fetch: timed out".to_string(),
                ))
            },
            |outcome| {
                let err = outcome.expect_err("the metadata server is down");
                // Every waiter still learns WHY, byte-identically.
                assert!(
                    matches!(&err, KeyError::NotFound(m) if m.contains("timed out")),
                    "the replayed failure must carry the fetching thread's diagnosis, got \
                     {err:?}"
                );
            },
        );
        assert_eq!(
            attempts, 1,
            "8 waiters spread over 7 logical seconds behind one failing flight must not \
             each pay a NETWORK_TIMEOUT"
        );
    }

    /// POSITIVE CONTROL: coalescing a SUCCESSFUL fetch is the behaviour the cool-off must
    /// not disturb — the same 8 staggered callers still produce exactly one fetch and all
    /// get the token.
    #[test]
    fn concurrent_callers_perform_one_metadata_fetch_between_them() {
        let source = std::sync::Arc::new(token_source());
        let expires_at = SystemTime::now() + Duration::from_secs(86_400);
        let attempts = staggered_callers(
            &source,
            move || Ok(cached("ya29.SECRET", expires_at)),
            |outcome| assert_eq!(&*outcome.expect("token"), "ya29.SECRET"),
        );
        assert_eq!(
            attempts, 1,
            "8 concurrent callers must not each fetch a token from the metadata server"
        );
    }

    /// The cool-off must be at least as long as the timeout it suppresses.
    ///
    /// The waiters are exactly the callers that arrived during one `NETWORK_TIMEOUT` and
    /// then unblock one after another, so a shorter window can lapse part-way through
    /// draining them and the tail starts fetching again. Pinned here because the
    /// concurrency test above cannot see it: with the failure stamped at completion, every
    /// waiter unblocks at essentially the recorded instant, so any positive window passes.
    #[test]
    fn the_failure_cool_off_must_outlast_the_network_timeout() {
        assert!(
            METADATA_FAILURE_COOLDOWN >= NETWORK_TIMEOUT,
            "a {METADATA_FAILURE_COOLDOWN:?} window cannot cover the waiters that queued \
             during a {NETWORK_TIMEOUT:?} fetch"
        );
    }

    /// POSITIVE CONTROL: the cool-off is a bound, not a circuit breaker that latches. Past
    /// [`METADATA_FAILURE_COOLDOWN`] the very next caller DOES re-fetch, and a success
    /// clears the record so the one after that is served from cache.
    ///
    /// Without this, a fail-closed cool-off that never reopened would satisfy the test
    /// above while taking GCP-rooted signing out of the replica for good.
    #[test]
    fn the_failure_cool_off_expires_and_a_success_clears_it() {
        let source = token_source();
        let now = SystemTime::now();
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let failing = || {
            attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(KeyError::NotFound("gcp-kms: metadata down".to_string()))
        };
        source.cached_or_fetch(&|| now, &failing).expect_err("down");
        // Inside the window: suppressed.
        source
            .cached_or_fetch(&|| now + Duration::from_millis(1), &failing)
            .expect_err("suppressed");
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
        // Past the window: the next caller retries for real.
        source
            .cached_or_fetch(&|| now + METADATA_FAILURE_COOLDOWN, &failing)
            .expect_err("retried and still down");
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "the cool-off must expire, not latch"
        );
        // And once the metadata server answers, the record is gone and the token serves.
        let recovered_at = now + METADATA_FAILURE_COOLDOWN * 2;
        let recovered = source.cached_or_fetch(&|| recovered_at, &|| {
            attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(cached("ya29.SECRET", now + Duration::from_secs(3600)))
        });
        assert_eq!(&*recovered.expect("token"), "ya29.SECRET");
        source
            .cached_or_fetch(&|| recovered_at, &failing)
            .expect("served from cache, no fetch");
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "a success must clear the failure record and repopulate the cache"
        );
    }

    /// A clock that jumps BACKWARDS must close the suppression window, not extend it. A
    /// window keyed on `now < at + cooldown` alone would suppress every fetch for the size
    /// of the jump — a signing outage produced by an NTP step.
    #[test]
    fn a_backwards_clock_step_does_not_extend_the_failure_cool_off() {
        let source = token_source();
        let now = SystemTime::now();
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let failing = || {
            attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(KeyError::NotFound("gcp-kms: metadata down".to_string()))
        };
        source.cached_or_fetch(&|| now, &failing).expect_err("down");
        source
            .cached_or_fetch(&|| now - Duration::from_secs(3600), &failing)
            .expect_err("down");
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "a failure recorded in the FUTURE must not suppress the fetch"
        );
    }

    // ------------------------------------------------------------------
    // R9-C091 — poison recovery on every lock in this module.
    // ------------------------------------------------------------------

    /// Panic while holding a lock, so the next taker meets a poisoned guard.
    fn poison<T>(lock: &Mutex<T>) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = lock.lock().expect("not yet poisoned");
            panic!("poisoning the lock on purpose");
        }));
        assert!(lock.lock().is_err(), "the lock must now be poisoned");
    }

    /// One panic anywhere under these locks must not remove GCP KMS signing from the
    /// replica for the rest of the process.
    ///
    /// Poison is sticky. Propagating it turned every later `access_token` into an error,
    /// so every delegated-TLS handshake failed AND the cold-path rotor could not mint a
    /// successor — the replica fails closed at the current delegated key's `exp` with
    /// nothing that recovers it. Neither lock protects an invariant: `fetching` guards
    /// `()`, and `TokenState`'s fields are whole-value swaps.
    #[test]
    fn a_poisoned_token_lock_still_serves_tokens() {
        let source = token_source();
        poison(&source.state);
        poison(&source.fetching);
        let now = SystemTime::now();
        let token = source
            .cached_or_fetch(&|| now, &|| {
                Ok(cached("ya29.SECRET", now + Duration::from_secs(3600)))
            })
            .expect("a poisoned lock must not brick GCP KMS signing");
        assert_eq!(&*token, "ya29.SECRET");
        // And the cache written under the recovered guard is readable.
        assert_eq!(
            &*source
                .cached_or_fetch(&|| now, &|| panic!("must be served from cache"))
                .expect("cached"),
            "ya29.SECRET"
        );
    }

    /// The same property on the handshake path's own lock: a poisoned cooldown must not
    /// refuse every later TLS signature.
    #[test]
    fn a_poisoned_tls_cooldown_lock_still_signs() {
        let backend =
            GcpKmsEd25519Backend::with_transport(Box::new(FakeGcp::good(17))).expect("construct");
        poison(&backend.tls_cooldown_until);
        let sig = backend
            .tls_sign_at(b"transcript", &Instant::now)
            .expect("a poisoned cooldown lock must not refuse the handshake");
        assert_eq!(sig.len(), 64);
    }

    // ------------------------------------------------------------------
    // R9-C060 / R9-C108 — the unknown-expiry floor's real bound.
    // ------------------------------------------------------------------

    /// The floor is applied to `expires_at`, and the freshness gate then subtracts
    /// [`TOKEN_REFRESH_MARGIN`] from it — so a floor at or below the margin is a silent
    /// no-op that restores one metadata fetch per signature. Pins the arithmetic the
    /// constant's doc states, so tuning it downward fails here instead of in production.
    #[test]
    fn the_unknown_expiry_floor_must_outlast_the_refresh_margin() {
        assert!(
            UNKNOWN_EXPIRY_REUSE > TOKEN_REFRESH_MARGIN,
            "an unknown-expiry token stamped {UNKNOWN_EXPIRY_REUSE:?} ahead is never fresh \
             under a {TOKEN_REFRESH_MARGIN:?} refresh margin, so the floor would do nothing"
        );
        let source = token_source();
        let now = SystemTime::now();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let fetch = || {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(no_stated_expiry("ya29.SECRET"))
        };
        source.cached_or_fetch(&|| now, &fetch).expect("token");
        // The last instant the stamped token is still served, and the first it is not.
        let window = UNKNOWN_EXPIRY_REUSE - TOKEN_REFRESH_MARGIN;
        source
            .cached_or_fetch(&|| now + window - Duration::from_secs(1), &fetch)
            .expect("token");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the floor must serve the token for UNKNOWN_EXPIRY_REUSE - TOKEN_REFRESH_MARGIN"
        );
        source
            .cached_or_fetch(&|| now + window, &fetch)
            .expect("token");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "and no longer: past that instant the next caller re-fetches"
        );
    }

    // ------------------------------------------------------------------
    // R9-C107 — what the single flight actually spans.
    // ------------------------------------------------------------------

    /// Two backends do NOT share a token source, so the flight coalesces one backend's
    /// callers and nothing more.
    ///
    /// `GcpKmsEd25519Backend::new` builds a fresh `MetadataServerTokenSource` per call and
    /// the composition root builds one backend for object signing and a second for
    /// delegated TLS, so the two paths share only the metadata server's own quota. Pinned
    /// here because the lock's doc used to claim they share the token.
    #[test]
    fn two_token_sources_do_not_share_a_cache_or_a_flight() {
        let object_signing = token_source();
        let delegated_tls = token_source();
        let now = SystemTime::now();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let fetch = || {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(cached("ya29.SECRET", now + Duration::from_secs(3600)))
        };
        object_signing
            .cached_or_fetch(&|| now, &fetch)
            .expect("token");
        delegated_tls
            .cached_or_fetch(&|| now, &fetch)
            .expect("token");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "each backend holds its own token source: the flight cannot span them"
        );
    }

    #[test]
    fn pem_roundtrips_to_spki_der() {
        let raw = SigningKey::from_seed_bytes(&[5u8; 32])
            .public_key()
            .to_bytes();
        let mut der = ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(&raw);
        assert_eq!(spki_der_from_pem(&pem_from_raw(&raw)).unwrap(), der);
    }

    /// A non-Ed25519 key version is rejected at parse time (guardrail #4).
    #[test]
    fn non_ed25519_algorithm_fails_closed() {
        let body = br#"{"algorithm":"RSA_SIGN_PSS_2048_SHA256","pem":"-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n"}"#;
        assert!(matches!(
            parse_public_key_response(body),
            Err(KeyError::Malformed(_))
        ));
    }

    #[test]
    fn get_public_key_parses_ed25519_pem() {
        let raw = SigningKey::from_seed_bytes(&[6u8; 32])
            .public_key()
            .to_bytes();
        let body = serde_json::json!({
            "algorithm": "EC_SIGN_ED25519",
            "pem": pem_from_raw(&raw),
        })
        .to_string();
        let mut der = ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(&raw);
        assert_eq!(parse_public_key_response(body.as_bytes()).unwrap(), der);
    }

    /// A fake Cloud KMS transport backed by a LOCAL Ed25519 key — exercises the full
    /// getPublicKey→construct→asymmetricSign→verify-before-return path with no
    /// network. `prehash` flips the sign side to a forbidden DIGEST-style signature.
    struct FakeGcp {
        key: SigningKey,
        prehash: bool,
        /// Simulate a KMS key version whose public key can no longer be downloaded
        /// (destroyed / disabled): `getPublicKey` fails, so `with_transport`
        /// construction fails closed (ADR-MCPS-028 §Verification negative 4).
        fail_get_public_key: bool,
        /// Simulate a DISABLED KMS key version: `asymmetricSign` is denied, so the
        /// signer fails closed with no local-key fallback (negative 1).
        fail_sign: bool,
    }
    impl FakeGcp {
        /// A well-behaved fake Cloud KMS transport keyed by `seed`.
        fn good(seed: u8) -> Self {
            FakeGcp {
                key: SigningKey::from_seed_bytes(&[seed; 32]),
                prehash: false,
                fail_get_public_key: false,
                fail_sign: false,
            }
        }
    }
    impl GcpKmsTransport for FakeGcp {
        fn get_public_key(&self) -> Result<Vec<u8>, KeyError> {
            if self.fail_get_public_key {
                return Err(KeyError::Malformed(
                    "fake gcp kms: getPublicKey unavailable (key version destroyed/disabled)"
                        .into(),
                ));
            }
            Ok(serde_json::json!({
                "algorithm": ALGORITHM_ED25519,
                "pem": pem_from_raw(&self.key.public_key().to_bytes()),
            })
            .to_string()
            .into_bytes())
        }
        fn asymmetric_sign(&self, body: &[u8]) -> Result<Vec<u8>, KeyError> {
            if self.fail_sign {
                return Err(KeyError::Malformed(
                    "fake gcp kms: asymmetricSign denied (key version disabled)".into(),
                ));
            }
            let v: serde_json::Value = serde_json::from_slice(body).unwrap();
            let data = STANDARD
                .decode(v.get("data").unwrap().as_str().unwrap())
                .unwrap();
            let to_sign = if self.prehash {
                let mut d = b"DIGEST:".to_vec();
                d.extend_from_slice(&data);
                d
            } else {
                data
            };
            let raw = b64url_decode(&self.key.sign(&to_sign)).unwrap();
            Ok(serde_json::json!({ "signature": STANDARD.encode(&raw) })
                .to_string()
                .into_bytes())
        }
    }

    /// LOAD-BEARING: the full adapter path produces a signature that verifies, and
    /// the SPKI it reports is the advertised key.
    #[test]
    fn gcp_backend_signs_and_verifies_end_to_end() {
        let backend =
            GcpKmsEd25519Backend::with_transport(Box::new(FakeGcp::good(12))).expect("construct");
        let preimage = b"mcp-re canonical response preimage";
        let sig = backend.sign_raw_ed25519(preimage).expect("sign");
        assert_eq!(sig.len(), 64);
        let raw = ed25519_raw_point_from_spki(&backend.public_key_spki_der().unwrap()).unwrap();
        let key = VerificationKey::from_bytes(&raw).unwrap();
        verify_ed25519(preimage, &b64url_encode(&sig), &key).expect("verifies");
    }

    /// A DIGEST/prehash misconfiguration is caught by verify-before-return — the
    /// adapter NEVER returns a non-verifying signature (guardrail #5).
    #[test]
    fn prehash_signature_is_rejected_before_return() {
        let backend = GcpKmsEd25519Backend::with_transport(Box::new(FakeGcp {
            prehash: true,
            ..FakeGcp::good(12)
        }))
        .expect("construct");
        let err = backend
            .sign_raw_ed25519(b"mcp-re canonical response preimage")
            .expect_err("must fail closed");
        assert!(matches!(err, KeyError::Malformed(_)));
    }

    /// Issue #61 (test a): the GCP backend AS a [`RawEd25519TlsSigner`] signs a TLS
    /// handshake transcript over the fake Cloud KMS transport, returning a raw
    /// 64-byte signature that VERIFIES under the SPKI it reports — the exact
    /// assertion the validated #58 build path and rustls rely on. The TLS sign path
    /// reuses the object-signing RAW-Ed25519 `asymmetricSign`.
    #[test]
    fn gcp_backend_tls_sign_verifies_under_reported_spki() {
        let backend =
            GcpKmsEd25519Backend::with_transport(Box::new(FakeGcp::good(24))).expect("construct");
        let transcript = b"tls handshake transcript bytes";
        let sig = backend.sign_tls_ed25519(transcript).expect("tls sign");
        assert_eq!(
            sig.len(),
            64,
            "delegated TLS signature is a raw 64-byte Ed25519 sig"
        );
        // The reported SPKI is the advertised Cloud KMS public key and verifies it.
        let raw = ed25519_raw_point_from_spki(&backend.tls_public_key_spki_der().unwrap()).unwrap();
        let key = VerificationKey::from_bytes(&raw).unwrap();
        verify_ed25519(transcript, &b64url_encode(&sig), &key).expect("tls sig verifies");
    }

    /// A Cloud KMS transport that always reports the project is over quota, counting
    /// how many times it was actually reached.
    struct ThrottlingGcp {
        key: SigningKey,
        signs: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }
    impl GcpKmsTransport for ThrottlingGcp {
        fn get_public_key(&self) -> Result<Vec<u8>, KeyError> {
            Ok(serde_json::json!({
                "algorithm": ALGORITHM_ED25519,
                "pem": pem_from_raw(&self.key.public_key().to_bytes()),
            })
            .to_string()
            .into_bytes())
        }
        fn asymmetric_sign(&self, _body: &[u8]) -> Result<Vec<u8>, KeyError> {
            self.signs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // The shape `UreqGcpClient::asymmetric_sign` renders for an error response.
            Err(KeyError::NotFound(
                "gcp-kms: asymmetricSign HTTP 429: {\"error\":{\"status\":\
                 \"RESOURCE_EXHAUSTED\"}}"
                    .to_string(),
            ))
        }
    }

    /// A Cloud KMS throttle on the HANDSHAKE path must stop that path calling Cloud KMS
    /// for a window, so the project quota it shares with delegated-credential issuance
    /// is not spent by a flood of unauthenticated connections. Counted at the transport,
    /// not inferred from the error: the property is "Cloud KMS was not called", not "the
    /// handshake failed".
    #[test]
    fn a_throttled_tls_sign_stops_calling_kms_for_the_cooldown() {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let backend = GcpKmsEd25519Backend::with_transport(Box::new(ThrottlingGcp {
            key: SigningKey::from_seed_bytes(&[41u8; 32]),
            signs: std::sync::Arc::clone(&counter),
        }))
        .expect("construct");
        let signs = || counter.load(std::sync::atomic::Ordering::SeqCst);

        let start = Instant::now();
        backend
            .tls_sign_at(b"transcript", &|| start)
            .expect_err("Cloud KMS is throttling");
        assert_eq!(signs(), 1, "the first handshake does reach Cloud KMS");

        for _ in 0..20 {
            backend
                .tls_sign_at(b"transcript", &|| start + Duration::from_millis(1))
                .expect_err("refused locally");
        }
        assert_eq!(
            signs(),
            1,
            "a handshake flood inside the cooldown must not convert into Cloud KMS calls"
        );

        backend
            .tls_sign_at(b"transcript", &|| start + TLS_SIGN_THROTTLE_COOLDOWN)
            .expect_err("Cloud KMS is still throttling");
        assert_eq!(
            signs(),
            2,
            "past the cooldown the path probes Cloud KMS again"
        );
    }

    /// A throttling transport whose call TAKES TIME, so a cohort of handshakes really is
    /// inside the probe when it runs. With an instantaneous fake the prober finishes before
    /// the next thread takes the lock, and the race the window exists to close never opens
    /// — which is why the first version of this test passed against the defect.
    struct SlowThrottlingGcp {
        key: SigningKey,
        signs: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        call_time: Duration,
    }
    impl GcpKmsTransport for SlowThrottlingGcp {
        fn get_public_key(&self) -> Result<Vec<u8>, KeyError> {
            Ok(serde_json::json!({
                "algorithm": ALGORITHM_ED25519,
                "pem": pem_from_raw(&self.key.public_key().to_bytes()),
            })
            .to_string()
            .into_bytes())
        }
        fn asymmetric_sign(&self, _body: &[u8]) -> Result<Vec<u8>, KeyError> {
            self.signs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(self.call_time);
            Err(KeyError::NotFound(
                "gcp-kms: asymmetricSign HTTP 429: RESOURCE_EXHAUSTED".to_string(),
            ))
        }
    }

    /// The window must be armed from a reading taken AFTER the call, and must outlast the
    /// call it reacts to.
    ///
    /// Armed from the handshake's ENTRY instant with a 2s window against a 5s timeout, any
    /// Cloud KMS call slower than 2s installed a window that had ALREADY elapsed — no
    /// throttle at all, in exactly the regime the throttle exists for: an overloaded Cloud
    /// KMS answering slowly, with an unauthenticated peer still driving one
    /// `asymmetricSign` per handshake against the quota the rotor needs.
    #[test]
    fn a_slow_throttled_call_still_opens_a_live_window() {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let slow = TLS_SIGN_THROTTLE_COOLDOWN + Duration::from_millis(20);
        let backend = GcpKmsEd25519Backend::with_transport(Box::new(SlowThrottlingGcp {
            key: SigningKey::from_seed_bytes(&[46u8; 32]),
            signs: std::sync::Arc::clone(&counter),
            call_time: slow,
        }))
        .expect("construct");
        let entry = Instant::now();
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
            .expect_err("Cloud KMS is throttling");
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
        // A handshake arriving just after that call finished must be REFUSED. Armed from
        // the entry instant, the window would already have expired and this would reach
        // Cloud KMS.
        backend
            .tls_sign_at(b"transcript", &|| entry + slow + Duration::from_millis(1))
            .expect_err("the window opened by the slow call must still be in force");
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a window armed from the entry instant is dead on arrival after a slow call"
        );
    }

    /// The window must outlast the call it reacts to, or it can be installed already
    /// elapsed. Pinned as a build guard, exactly like the metadata cool-off's.
    #[test]
    fn the_throttle_window_must_outlast_the_network_timeout() {
        assert!(
            TLS_SIGN_THROTTLE_COOLDOWN >= NETWORK_TIMEOUT,
            "a {TLS_SIGN_THROTTLE_COOLDOWN:?} window cannot survive a call that may take \
             {NETWORK_TIMEOUT:?}"
        );
    }

    /// At the cooldown boundary exactly ONE handshake probes Cloud KMS.
    ///
    /// Clearing the window before probing made every concurrent handshake at the boundary
    /// call Cloud KMS at once — the flood the window exists to stop, arriving one cooldown
    /// late. Re-arming INSIDE the same critical section as the read is what makes the
    /// cohort behind the prober see a closed window instead of an open one.
    #[test]
    fn only_one_handshake_probes_at_the_cooldown_boundary() {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let backend = std::sync::Arc::new(
            GcpKmsEd25519Backend::with_transport(Box::new(SlowThrottlingGcp {
                key: SigningKey::from_seed_bytes(&[43u8; 32]),
                signs: std::sync::Arc::clone(&counter),
                // LONGER than the window it is probing: the previous 40ms was 50x shorter
                // than the cooldown, so the test only covered calls faster than it.
                call_time: TLS_SIGN_THROTTLE_COOLDOWN + Duration::from_millis(20),
            }))
            .expect("construct"),
        );
        let start = Instant::now();
        backend
            .tls_sign_at(b"transcript", &|| start)
            .expect_err("Cloud KMS is throttling");
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);

        // 16 handshakes arrive together at the instant the window lapses, and stay inside
        // the prober's call for its whole duration.
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
    ///
    /// Two handshakes can both pass a `None` gate and then fail; whichever wrote last used
    /// to win outright, so a thread holding an earlier `now` could replace a later thread's
    /// window with one that has already elapsed. Driven through `arm_cooldown` directly
    /// because the ordering that produces it is a race, and a test that has to win a race
    /// in order to fail is not a test.
    #[test]
    fn a_straggler_cannot_shorten_the_cooldown_window() {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let backend = GcpKmsEd25519Backend::with_transport(Box::new(ThrottlingGcp {
            key: SigningKey::from_seed_bytes(&[45u8; 32]),
            signs: std::sync::Arc::clone(&counter),
        }))
        .expect("construct");
        let start = Instant::now();
        let later = start + Duration::from_secs(10);

        // The later thread reports first and opens a window to later + COOLDOWN.
        backend.arm_cooldown(later);
        // The straggler, holding `start`, reports second. Its window has already elapsed.
        backend.arm_cooldown(start);

        // Between the two windows: the straggler's has passed, the real one has not.
        let between = start + TLS_SIGN_THROTTLE_COOLDOWN + Duration::from_secs(1);
        backend
            .tls_sign_at(b"transcript", &|| between)
            .expect_err("still inside the window the later thread opened");
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a straggler's stale window must not reopen the handshake path"
        );
        // POSITIVE CONTROL: past the REAL window the path probes again, so the rule bounds
        // the window rather than pinning it open.
        backend
            .tls_sign_at(b"transcript", &|| later + TLS_SIGN_THROTTLE_COOLDOWN)
            .expect_err("Cloud KMS is still throttling");
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "past the real window the path must probe"
        );
    }

    /// POSITIVE CONTROL: a probe that SUCCEEDS reopens the path immediately, rather than
    /// leaving the window it armed to run its course.
    ///
    /// Without this, re-arming before probing would turn one throttle into a permanent
    /// stutter — the recovery case is the whole point of probing at all.
    #[test]
    fn a_successful_probe_reopens_the_handshake_path_at_once() {
        /// Throttles until `heal` is set, then signs normally.
        struct HealingGcp {
            key: SigningKey,
            healed: std::sync::Arc<std::sync::atomic::AtomicBool>,
            signs: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        }
        impl GcpKmsTransport for HealingGcp {
            fn get_public_key(&self) -> Result<Vec<u8>, KeyError> {
                Ok(serde_json::json!({
                    "algorithm": ALGORITHM_ED25519,
                    "pem": pem_from_raw(&self.key.public_key().to_bytes()),
                })
                .to_string()
                .into_bytes())
            }
            fn asymmetric_sign(&self, body: &[u8]) -> Result<Vec<u8>, KeyError> {
                self.signs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if !self.healed.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err(KeyError::NotFound(
                        "gcp-kms: asymmetricSign HTTP 429: RESOURCE_EXHAUSTED".to_string(),
                    ));
                }
                let v: serde_json::Value = serde_json::from_slice(body).expect("body");
                let data = STANDARD
                    .decode(v.get("data").and_then(|d| d.as_str()).unwrap_or(""))
                    .expect("b64");
                let raw = b64url_decode(&self.key.sign(&data)).expect("sign");
                Ok(serde_json::json!({ "signature": STANDARD.encode(&raw) })
                    .to_string()
                    .into_bytes())
            }
        }
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let healed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let transport = Box::new(HealingGcp {
            key: SigningKey::from_seed_bytes(&[44u8; 32]),
            healed: std::sync::Arc::clone(&healed),
            signs: std::sync::Arc::clone(&counter),
        });
        let backend = GcpKmsEd25519Backend::with_transport(transport).expect("construct");
        let start = Instant::now();
        backend
            .tls_sign_at(b"transcript", &|| start)
            .expect_err("throttled");
        // The quota comes back; the probe past the window must reopen the path for
        // everyone, not just for itself.
        healed.store(true, std::sync::atomic::Ordering::SeqCst);
        let boundary = start + TLS_SIGN_THROTTLE_COOLDOWN;
        backend
            .tls_sign_at(b"transcript", &|| boundary)
            .expect("the probe succeeds");
        let before = counter.load(std::sync::atomic::Ordering::SeqCst);
        for _ in 0..5 {
            backend
                .tls_sign_at(b"transcript", &|| boundary + Duration::from_millis(1))
                .expect("the path is open again");
        }
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            before + 5,
            "after a successful probe every handshake must reach Cloud KMS again"
        );
    }

    /// The classifier must fire on the project-quota statuses and NOT on an ordinary
    /// per-request refusal, which says nothing about the shared quota.
    #[test]
    fn only_quota_failures_open_the_cooldown() {
        for throttling in [
            "gcp-kms: asymmetricSign HTTP 429: {\"error\":{\"status\":\"RESOURCE_EXHAUSTED\"}}",
            "gcp-kms: asymmetricSign HTTP 503: {\"error\":{\"status\":\"UNAVAILABLE\"}}",
        ] {
            assert!(
                is_kms_throttling(&KeyError::NotFound(throttling.to_string())),
                "{throttling}"
            );
        }
        for other in [
            "gcp-kms: asymmetricSign HTTP 403: {\"error\":{\"status\":\"PERMISSION_DENIED\"}}",
            "gcp-kms: asymmetricSign: connection refused",
        ] {
            assert!(
                !is_kms_throttling(&KeyError::NotFound(other.to_string())),
                "{other}"
            );
        }
    }

    // ------------------------------------------------------------------
    // R9-C001 — the Cloud KMS endpoint's authority.
    // ------------------------------------------------------------------

    fn gcp_config(endpoint: Option<&str>) -> GcpKmsConfig {
        GcpKmsConfig {
            key_version_name: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
                .to_string(),
            endpoint: endpoint.map(str::to_string),
        }
    }

    /// An endpoint whose authority a URL parser reads differently from the text must never
    /// reach a Cloud KMS request.
    ///
    /// `ureq` resolves the URL with `url::Url::parse` and connects to its `host_str()`, so
    /// `https://cloudkms.googleapis.com@evil.example.com` reaches `evil.example.com` while
    /// reading as Cloud KMS. That host receives a live workload-identity bearer token
    /// authorizing `asymmetricSign` on the ROOT response-signing key, and answers
    /// `getPublicKey` with an SPKI that BECOMES the root verify key — so every local
    /// verify-before-return check then passes self-consistently against its key.
    ///
    /// Checked at construction, not only at the CLI: `GcpKmsConfig::endpoint` is public and
    /// an embedder reaches here without meeting a parser.
    #[test]
    fn a_gcp_kms_endpoint_that_re_points_the_request_is_refused_at_construction() {
        for hostile in [
            "https://cloudkms.googleapis.com@evil.example.com",
            "https://cloudkms.googleapis.com@evil.example.com/v1",
            // Defeats the "http:// only to loopback" rule: the loopback text is userinfo.
            "http://localhost:80@evil.example.com",
            "http://127.0.0.1:8080@evil.example.com",
            "https://user:pass@evil.example.com",
            // Plaintext to a host that is not loopback puts the bearer token on the wire.
            "http://cloudkms.attacker.example",
            "ftp://cloudkms.googleapis.com",
            "https://",
        ] {
            let Err(err) =
                UreqGcpClient::new(Box::new(EnvAccessTokenSource), &gcp_config(Some(hostile)))
            else {
                panic!("{hostile:?} must not be accepted as a Cloud KMS endpoint");
            };
            assert!(
                matches!(&err, KeyError::Malformed(m) if m.contains("--gcp-kms-endpoint")),
                "{hostile:?}: the refusal must name the flag, got {err:?}"
            );
        }
    }

    /// POSITIVE CONTROL: every endpoint an operator legitimately sets still builds a
    /// client, and the default still addresses the real Cloud KMS operations.
    ///
    /// This is the assertion round 8 skipped three times. A check that refused every
    /// endpoint would satisfy the test above.
    #[test]
    fn the_gcp_kms_endpoints_an_operator_legitimately_sets_are_still_accepted() {
        for endpoint in [
            None,
            Some("https://cloudkms.googleapis.com"),
            Some("https://cloudkms.googleapis.com/"),
            // A regional Cloud KMS endpoint, and an in-cluster emulator with a port.
            Some("https://us-east1-cloudkms.googleapis.com"),
            Some("https://cloudkms.emulator.svc.cluster.local:8443"),
            // The loopback emulator lane, in all three spellings, with and without a port.
            Some("http://localhost:8443"),
            Some("http://127.0.0.1:8443/"),
            Some("http://[::1]:8443"),
            Some("http://localhost"),
        ] {
            let client = UreqGcpClient::new(Box::new(EnvAccessTokenSource), &gcp_config(endpoint));
            assert!(
                client.is_ok(),
                "{endpoint:?} is an endpoint an operator sets and must be accepted: {:?}",
                client.err()
            );
        }
        let default = UreqGcpClient::new(Box::new(EnvAccessTokenSource), &gcp_config(None))
            .expect("the default endpoint builds");
        assert_eq!(
            default.sign_url,
            "https://cloudkms.googleapis.com/v1/projects/p/locations/l/keyRings/r/cryptoKeys/k/\
             cryptoKeyVersions/1:asymmetricSign"
        );
        assert_eq!(
            default.public_key_url,
            "https://cloudkms.googleapis.com/v1/projects/p/locations/l/keyRings/r/cryptoKeys/k/\
             cryptoKeyVersions/1/publicKey"
        );
    }

    /// A trailing slash is a spelling of the same endpoint, so it must build the same URLs.
    ///
    /// The gate admits `https://cloudkms.googleapis.com/` — operators type it, and three
    /// positive controls certify it — but `format!("{base}/v1/…")` on it built a doubled
    /// `//v1/` path Cloud KMS does not serve. A positive control that admits an endpoint the
    /// client then malforms is worse than no control, so the client normalises it.
    #[test]
    fn a_trailing_slash_on_the_endpoint_builds_the_same_urls() {
        let plain = UreqGcpClient::new(
            Box::new(EnvAccessTokenSource),
            &gcp_config(Some("https://cloudkms.googleapis.com")),
        )
        .expect("admissible");
        for spelling in [
            "https://cloudkms.googleapis.com/",
            "https://cloudkms.googleapis.com//",
        ] {
            let slashed =
                UreqGcpClient::new(Box::new(EnvAccessTokenSource), &gcp_config(Some(spelling)))
                    .expect("admissible");
            assert_eq!(slashed.sign_url, plain.sign_url, "{spelling}");
            assert_eq!(slashed.public_key_url, plain.public_key_url, "{spelling}");
        }
        assert!(
            !plain.sign_url.contains("com//"),
            "the operation path must not be doubled: {}",
            plain.sign_url
        );
        // And an emulator base PATH is still carried through, which is why the endpoint
        // rule allows one at all.
        let based = UreqGcpClient::new(
            Box::new(EnvAccessTokenSource),
            &gcp_config(Some("http://localhost:8443/kms/")),
        )
        .expect("admissible");
        assert!(
            based.sign_url.starts_with("http://localhost:8443/kms/v1/"),
            "got {}",
            based.sign_url
        );
    }

    // ------------------------------------------------------------------
    // R9-C060 / R9-C058 — a token Cloud KMS has stopped honouring.
    // ------------------------------------------------------------------

    /// A token source that records how it was used and whether it had a token to discard.
    #[derive(Clone, Default)]
    struct CountingTokenSource {
        invalidations: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        holds_a_token: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl CountingTokenSource {
        fn with_a_cached_token() -> Self {
            let source = CountingTokenSource::default();
            source
                .holds_a_token
                .store(true, std::sync::atomic::Ordering::SeqCst);
            source
        }
        fn invalidations(&self) -> usize {
            self.invalidations.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl GcpAccessTokenSource for CountingTokenSource {
        fn access_token(&self) -> Result<Zeroizing<String>, KeyError> {
            // Handing a token out means the source now holds one, exactly as the real
            // metadata source caches what it fetched — otherwise the fake would report
            // "nothing to discard" from the second refusal onward and hide the retry.
            self.holds_a_token
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(Zeroizing::new("ya29.SECRET".to_string()))
        }
        fn invalidate(&self, refused: &str) -> bool {
            self.invalidations
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(
                refused, "ya29.SECRET",
                "the token that was PRESENTED must be the one offered for eviction"
            );
            self.holds_a_token
                .swap(false, std::sync::atomic::Ordering::SeqCst)
        }
    }

    fn counting_client(source: &CountingTokenSource) -> UreqGcpClient {
        UreqGcpClient::new(Box::new(source.clone()), &gcp_config(None))
            .expect("the default endpoint is admissible")
    }

    /// Cloud KMS answering 401 means the BEARER TOKEN is not honoured — so that token is
    /// discarded and the call retried once.
    ///
    /// Nothing else evicts a cached token, and the unknown-expiry floor stamps a synthetic
    /// expiry on any token whose lifetime could not be read. Without this, one such token
    /// fails every signature, every delegated-credential issuance and every delegated-TLS
    /// handshake for the whole reuse window with no self-heal — while the constant's doc
    /// claimed it cost "one failed KMS call".
    #[test]
    fn a_cloud_kms_401_discards_the_token_and_retries_once() {
        let source = CountingTokenSource::with_a_cached_token();
        let client = counting_client(&source);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let err = client
            .with_token_retry("asymmetricSign", |auth| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                assert_eq!(auth, "Bearer ya29.SECRET");
                Err(KmsCallError::Status(
                    401,
                    "{\"error\":{\"status\":\"UNAUTHENTICATED\"}}".to_string(),
                ))
            })
            .expect_err("Cloud KMS refused the token twice");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "HTTP 401 must discard the token and try once more"
        );
        assert_eq!(source.invalidations(), 1);
        // BOTH failures are reported: the 401 is the cause, the retry's error the symptom.
        let rendered = format!("{err:?}");
        assert!(
            rendered.matches("asymmetricSign HTTP 401").count() == 2,
            "the retry error must carry the 401 that caused it, got {rendered}"
        );
    }

    /// 403 is NOT a token refusal, and evicting on it re-creates the per-handshake metadata
    /// fetch the reuse floor exists to prevent.
    ///
    /// Cloud KMS answers 403 for `PERMISSION_DENIED` (no `useToSign` binding on the key),
    /// `SERVICE_DISABLED` and billing failures — the most common Cloud KMS
    /// misconfigurations, in every one of which the bearer token is perfectly valid. On the
    /// delegated-TLS path an unauthenticated peer drives that, and `is_kms_throttling`
    /// excludes 403 so the handshake cooldown is no backstop.
    #[test]
    fn a_cloud_kms_403_does_not_discard_a_valid_token() {
        for body in [
            "{\"error\":{\"status\":\"PERMISSION_DENIED\"}}",
            "{\"error\":{\"status\":\"SERVICE_DISABLED\"}}",
            "{\"error\":{\"status\":\"PERMISSION_DENIED\",\"message\":\"billing\"}}",
        ] {
            let source = CountingTokenSource::with_a_cached_token();
            let client = counting_client(&source);
            let calls = std::sync::atomic::AtomicUsize::new(0);
            let err = client
                .with_token_retry("asymmetricSign", |_auth| {
                    calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Err(KmsCallError::Status(403, body.to_string()))
                })
                .expect_err("permission denied");
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "{body}: a 403 must cost ONE Cloud KMS call, not two"
            );
            assert_eq!(
                source.invalidations(),
                0,
                "{body}: a 403 says nothing about the token and must not evict it"
            );
            assert!(
                matches!(&err, KeyError::NotFound(m) if m.contains("asymmetricSign HTTP 403")),
                "got {err:?}"
            );
        }
    }

    /// Eviction is keyed on the token that was PRESENTED, so concurrent refusals during a
    /// rotation do not each discard the successor the thread ahead of them just minted.
    ///
    /// An unconditional `take()` has no identity: N threads holding the old token would
    /// throw away N successive fresh tokens, turning N refusals into N serialized metadata
    /// fetches — on the handshake path, one per connection.
    #[test]
    fn invalidating_a_token_another_thread_has_already_replaced_is_a_no_op() {
        let source = token_source();
        let now = SystemTime::now();
        let fetches = std::sync::atomic::AtomicUsize::new(0);
        let fetch = || {
            let n = fetches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(cached(
                &format!("ya29.GENERATION-{n}"),
                now + Duration::from_secs(3600),
            ))
        };
        source.cached_or_fetch(&|| now, &fetch).expect("token");
        // The thread that actually held generation 0 evicts it.
        assert!(
            source.invalidate("ya29.GENERATION-0"),
            "the presented token was the cached one"
        );
        source.cached_or_fetch(&|| now, &fetch).expect("successor");
        // A second thread, still holding generation 0, must NOT discard generation 1.
        assert!(
            !source.invalidate("ya29.GENERATION-0"),
            "a refusal about a superseded token must not evict its successor"
        );
        source
            .cached_or_fetch(&|| now, &fetch)
            .expect("still cached");
        assert_eq!(
            fetches.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "the successor must survive a stale thread's invalidation"
        );
    }

    /// POSITIVE CONTROL, and the bound on the retry.
    ///
    /// A success costs one call and discards nothing; a quota refusal (429/503) discards
    /// nothing either — throwing the token away there would re-fetch from the metadata
    /// server on every throttled handshake, and `is_kms_throttling` still has to classify
    /// the error it renders; and a 401 with NOTHING cached does not spend a second Cloud
    /// KMS call re-proving the same refusal.
    #[test]
    fn only_a_token_refusal_with_a_token_to_discard_costs_a_second_call() {
        let source = CountingTokenSource::with_a_cached_token();
        let client = counting_client(&source);

        let calls = std::sync::atomic::AtomicUsize::new(0);
        let body = client
            .with_token_retry("asymmetricSign", |_auth| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(b"{\"signature\":\"\"}".to_vec())
            })
            .expect("a signature");
        assert_eq!(body, b"{\"signature\":\"\"}");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(source.invalidations(), 0, "a success must not evict");

        let err = client
            .with_token_retry("asymmetricSign", |_auth| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Err(KmsCallError::Status(
                    429,
                    "{\"error\":{\"status\":\"RESOURCE_EXHAUSTED\"}}".to_string(),
                ))
            })
            .expect_err("over quota");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(source.invalidations(), 0, "a quota refusal must not evict");
        assert!(
            is_kms_throttling(&err),
            "the throttle classifier must still see the rendered error, got {err:?}"
        );

        // A source that CACHES nothing — the shape of `EnvAccessTokenSource`, which reads
        // its token per call. There is nothing for a refusal to discard, so the retry must
        // not fire: a second call would only re-prove the same refusal.
        #[derive(Clone, Default)]
        struct MintsPerCall(std::sync::Arc<std::sync::atomic::AtomicUsize>);
        impl GcpAccessTokenSource for MintsPerCall {
            fn access_token(&self) -> Result<Zeroizing<String>, KeyError> {
                Ok(Zeroizing::new("ya29.SECRET".to_string()))
            }
            fn invalidate(&self, _refused: &str) -> bool {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                false // nothing was cached, so nothing was discarded
            }
        }
        let empty = MintsPerCall::default();
        let client = UreqGcpClient::new(Box::new(empty.clone()), &gcp_config(None))
            .expect("the default endpoint is admissible");
        let calls = std::sync::atomic::AtomicUsize::new(0);
        client
            .with_token_retry("getPublicKey", |_auth| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Err(KmsCallError::Status(401, String::new()))
            })
            .expect_err("refused");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "with no token to discard the retry must not fire"
        );
        assert_eq!(
            empty.0.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "it still asked"
        );
    }

    /// A PERSISTENT 401 must degrade flat, not cost a metadata round trip per handshake.
    ///
    /// A 401 a fresh token fixes is a rotation and costs one extra call, once. A 401 a
    /// fresh token does NOT fix is a revoked or unbound identity and is permanent, so
    /// retrying it per call turns every handshake into a metadata fetch plus a second Cloud
    /// KMS call — the same unbounded amplification the 403 exclusion closes, on the other
    /// status, and driven by an unauthenticated peer.
    #[test]
    fn a_persistent_401_stops_costing_a_refetch_per_call() {
        let source = CountingTokenSource::with_a_cached_token();
        let client = counting_client(&source);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let always_401 = |_auth: &str| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(KmsCallError::Status(401, "revoked".to_string()))
        };
        let start = Instant::now();

        // The first refusal probes: two Cloud KMS calls and one eviction.
        client
            .with_token_retry_at("asymmetricSign", start, always_401)
            .expect_err("refused");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(source.invalidations(), 1);

        // Every handshake inside the window costs ONE call and no eviction.
        for _ in 0..20 {
            client
                .with_token_retry_at(
                    "asymmetricSign",
                    start + Duration::from_millis(1),
                    always_401,
                )
                .expect_err("refused");
        }
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            22,
            "a flood inside the window must cost one Cloud KMS call each, not two"
        );
        assert_eq!(
            source.invalidations(),
            1,
            "and must not re-fetch a token per handshake"
        );

        // Past the window it probes once more, in case an operator fixed the binding.
        client
            .with_token_retry_at(
                "asymmetricSign",
                start + TOKEN_REFUSAL_RETRY_COOLDOWN,
                always_401,
            )
            .expect_err("refused");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 24);
    }

    /// POSITIVE CONTROL: a rotation — a 401 that a fresh token DOES fix — is never slowed
    /// by the suspension, and clears it.
    ///
    /// Without this, a bound that simply stopped retrying would satisfy the test above
    /// while breaking the self-healing the retry exists for.
    #[test]
    fn a_401_a_fresh_token_fixes_is_retried_every_time() {
        let source = CountingTokenSource::with_a_cached_token();
        let client = counting_client(&source);
        let start = Instant::now();
        for round in 0..5 {
            let calls = std::sync::atomic::AtomicUsize::new(0);
            let body = client
                .with_token_retry_at("asymmetricSign", start, |_auth| {
                    // First call refused, retry with the fresh token succeeds.
                    if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                        Err(KmsCallError::Status(401, "stale".to_string()))
                    } else {
                        Ok(b"ok".to_vec())
                    }
                })
                .unwrap_or_else(|e| panic!("round {round}: a rotation must self-heal: {e:?}"));
            assert_eq!(body, b"ok");
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        }
        assert_eq!(
            source.invalidations(),
            5,
            "every rotation evicts and retries; the suspension must never open"
        );
    }

    /// The metadata source's half of the same property: invalidation really does drop the
    /// cached token, and reports whether there was one.
    #[test]
    fn invalidating_the_metadata_source_forces_the_next_call_to_re_fetch() {
        let source = token_source();
        let now = SystemTime::now();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let fetch = || {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(cached("ya29.SECRET", now + Duration::from_secs(3600)))
        };
        assert!(!source.invalidate("ya29.SECRET"), "nothing is cached yet");
        source.cached_or_fetch(&|| now, &fetch).expect("token");
        source.cached_or_fetch(&|| now, &fetch).expect("cached");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(
            source.invalidate("ya29.SECRET"),
            "there was a token to discard"
        );
        assert!(!source.invalidate("ya29.SECRET"), "and only one");
        source.cached_or_fetch(&|| now, &fetch).expect("re-fetched");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "a discarded token must be re-fetched, not served from a stale cache"
        );
    }

    // -----------------------------------------------------------------------
    // MCPS-56 — KMS-lifecycle-vs-trust-policy offline evidence spine
    // (ADR-MCPS-028 §Verification negatives; ADR-MCPS-021 §M–O).
    //
    // The boundary these negatives pin, offline and with NO live KMS:
    //
    //   KMS lifecycle controls signing authority. MCP-RE trust policy controls
    //   evidence acceptance.
    //
    // A KMS key-version disable/destroy stops NEW signatures; it does NOT, by
    // itself, make a verifier reject already-signed evidence. Acceptance is
    // trust-policy-driven: the (signer, key_id) mapping — where key_id is the KMS
    // cryptoKeyVersion (ADR-MCPS-028 §H) — is what the verifier consults. The verify
    // path has no KMS transport at all, so a KMS outage cannot break verification of
    // retained evidence.
    // -----------------------------------------------------------------------

    /// Sign `preimage` with a GOOD KMS-backed signer keyed by `seed`, returning the
    /// advertised verification key and the base64url signature — a stand-in for
    /// retained KMS-signed evidence.
    fn kms_sign(seed: u8, preimage: &[u8]) -> (VerificationKey, String) {
        let backend =
            GcpKmsEd25519Backend::with_transport(Box::new(FakeGcp::good(seed))).expect("construct");
        let sig = backend.sign_raw_ed25519(preimage).expect("sign");
        let raw = ed25519_raw_point_from_spki(&backend.public_key_spki_der().unwrap()).unwrap();
        let key = VerificationKey::from_bytes(&raw).unwrap();
        (key, b64url_encode(&sig))
    }

    // (1) KMS disable → new signing fails closed, with no local-key fallback.
    #[test]
    fn kms_disable_stops_new_signing() {
        let backend = GcpKmsEd25519Backend::with_transport(Box::new(FakeGcp {
            fail_sign: true,
            ..FakeGcp::good(31)
        }))
        .expect("construction still succeeds — getPublicKey works");
        let err = backend
            .sign_raw_ed25519(b"mcp-re canonical response preimage")
            .expect_err("a disabled key version must fail closed on sign");
        assert!(matches!(err, KeyError::Malformed(_)));
    }

    // (4) KMS destroy → getPublicKey unavailable → a FRESH backend fails closed at
    // construction (a signer cannot pin an unresolvable key).
    #[test]
    fn kms_destroy_public_key_unavailable_fails_closed_at_construction() {
        let result = GcpKmsEd25519Backend::with_transport(Box::new(FakeGcp {
            fail_get_public_key: true,
            ..FakeGcp::good(32)
        }));
        assert!(
            matches!(result, Err(KeyError::Malformed(_))),
            "an unresolvable public key must fail closed at construction"
        );
    }

    // (2)+(5) KMS disable ALONE is not verifier revocation: evidence signed while
    // the (signer, key_id) mapping is trusted STILL verifies against the PINNED key,
    // through a verify path that has no KMS transport.
    #[test]
    fn kms_disable_alone_is_not_verifier_revocation() {
        let preimage = b"retained mcp-re response evidence";
        let (key, sig) = kms_sign(33, preimage);
        let mut trust = InMemoryTrustResolver::new();
        let signer = "did:example:server-1";
        let key_id = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1";
        trust.insert(signer, key_id, key);
        // Verify via the pinned trust bundle only — no KMS transport in this path,
        // so a subsequent KMS disable cannot affect it.
        let pinned = trust.resolve(signer, key_id).expect("pinned key resolves");
        verify_ed25519(preimage, &sig, &pinned)
            .expect("retained evidence still verifies while (signer, key_id) is trusted");
    }

    // (3) Trust-policy revoke → the SAME cryptographically-valid evidence is now
    // rejected. Acceptance flipped with no change to the signature or the KMS.
    #[test]
    fn trust_policy_revoke_rejects_kms_signed_evidence() {
        let preimage = b"retained mcp-re response evidence";
        let (key, sig) = kms_sign(34, preimage);
        // The signature is cryptographically valid on its own...
        verify_ed25519(preimage, &sig, &key).expect("signature is valid bytes");
        let mut trust = InMemoryTrustResolver::new();
        let signer = "did:example:server-1";
        let key_id = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1";
        trust.insert(signer, key_id, key);
        assert!(
            trust.resolve(signer, key_id).is_ok(),
            "trusted before revoke"
        );
        // ...but a trust-policy revoke makes the verifier reject it: acceptance is
        // trust-policy-driven, not signature-driven.
        trust.revoke(signer, key_id);
        assert_eq!(
            trust.resolve(signer, key_id).unwrap_err(),
            TrustResolverError::Revoked,
            "after trust-policy revoke the (signer, key_id) no longer resolves"
        );
    }

    // (6) Rotation overlap: two key versions are trusted at once (old + new); both
    // verify during the overlap. After the old version is removed/revoked, its
    // evidence is rejected while the new version keeps verifying.
    #[test]
    fn rotation_overlap_old_and_new_then_old_revoked() {
        let preimage = b"rotation overlap evidence";
        let (key_v1, sig_v1) = kms_sign(35, preimage);
        let (key_v2, sig_v2) = kms_sign(36, preimage);
        let signer = "did:example:server-1";
        let kid1 = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1";
        let kid2 = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/2";
        let mut trust = InMemoryTrustResolver::new();
        trust.insert(signer, kid1, key_v1);
        trust.insert(signer, kid2, key_v2);
        // Overlap window: both versions verify.
        verify_ed25519(preimage, &sig_v1, &trust.resolve(signer, kid1).unwrap())
            .expect("old version verifies during overlap");
        verify_ed25519(preimage, &sig_v2, &trust.resolve(signer, kid2).unwrap())
            .expect("new version verifies during overlap");
        // Rotation completes: the old version is removed/revoked.
        trust.revoke(signer, kid1);
        assert_eq!(
            trust.resolve(signer, kid1).unwrap_err(),
            TrustResolverError::Revoked,
            "old version rejected after rotation completes"
        );
        verify_ed25519(preimage, &sig_v2, &trust.resolve(signer, kid2).unwrap())
            .expect("new version still verifies after the old is removed");
    }
}
