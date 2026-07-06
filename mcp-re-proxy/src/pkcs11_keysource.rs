//! PKCS#11-backed response-signing [`KeySource`] — the real, non-exporting
//! backend behind the issue #3838 delegation seam (issue #4034).
//!
//! # What this delivers
//! A vendor-neutral [`Pkcs11KeySource`] that drives the proxy's full
//! response-signing path while the Ed25519 **response-signing private key never
//! leaves the token**. It speaks standard PKCS#11 (Cryptoki v2.40+ `CKM_EDDSA`)
//! through a small OWNED safe wrapper ([`crate::pkcs11_native`]) over the raw
//! `cryptoki-sys` FFI bindings — the high-level `cryptoki` crate was dropped
//! because it transitively pulled the UNMAINTAINED `paste` crate
//! (RUSTSEC-2024-0436). It references NO host security system — it is tested
//! against an in-tree mock PKCS#11 provider (see
//! `tests/pkcs11_keysource_e2e_test.rs`, which builds and loads a hermetic
//! `cdylib` implementing exactly the Cryptoki surface this source calls — no
//! external token or tooling required).
//!
//! The private key is located ON the token by label and used ONLY via `C_Sign`
//! with `CKM_EDDSA`; the 64-byte raw Ed25519 signature comes back from the
//! device and is Base64URL-no-pad encoded to match exactly what
//! [`SigningKey::sign`](mcp_re_core::SigningKey::sign) produces, so a signature it
//! makes verifies under [`response_public_key`](ResponseSigner::response_public_key)
//! with no special-casing on the verifier side. The PUBLIC key IS exportable even
//! from a non-exporting token (it is what relying parties verify against), so its
//! raw 32-byte Edwards point is read via `CKA_EC_POINT`.
//!
//! # TLS material (scope)
//! This source holds an inner [`FileKeySource`] for the TLS server certificate
//! chain, TLS server private key, and client-CA trust anchors: in THIS change the
//! token custodies ONLY the response-signing key, and the TLS cert/key/CA still
//! come from files. Delegated TLS signing — fronting the token behind a custom
//! [`rustls::sign::SigningKey`] so the TLS private key also never leaves the
//! device — is the remaining OUT-OF-SCOPE sub-item of #4034 and is deliberately
//! NOT implemented here; the existing file-backed TLS path is reused unchanged.
//!
//! # Fail-closed posture
//! Every Cryptoki/library failure (module load, slot/token selection, login,
//! object lookup, sign, attribute read, malformed key bytes) maps to a
//! [`KeyError::NotFound`]/[`KeyError::Malformed`] with context. There is no
//! panic, no fallback to an in-process key, and never a fabricated signature on
//! any error path.
//!
//! This entire module compiles ONLY under the non-default `pkcs11_keysource`
//! cargo feature, so a default build is byte-for-byte unchanged and gains zero
//! dependencies.

use std::sync::Arc;
use std::sync::Mutex;

use cryptoki_sys::CK_OBJECT_HANDLE;
use cryptoki_sys::CK_SESSION_HANDLE;
use cryptoki_sys::CK_SLOT_ID;
use cryptoki_sys::CKR_DEVICE_ERROR;
use cryptoki_sys::CKR_DEVICE_REMOVED;
use cryptoki_sys::CKR_SESSION_CLOSED;
use cryptoki_sys::CKR_SESSION_COUNT;
use cryptoki_sys::CKR_SESSION_HANDLE_INVALID;
use cryptoki_sys::CKR_USER_NOT_LOGGED_IN;
use mcp_re_core::b64url_encode;
use mcp_re_core::verify_ed25519;
use mcp_re_core::VerificationKey;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use zeroize::Zeroizing;

use crate::delegated_tls::RawEd25519TlsSigner;
use crate::key_source::FileKeySource;
use crate::key_source::KeyError;
use crate::key_source::KeySource;
use crate::key_source::ResponseSigner;
use crate::pkcs11_native::AttributeTemplate;
use crate::pkcs11_native::ObjectClass;
use crate::pkcs11_native::Pkcs11Context;
use crate::pkcs11_native::Pkcs11Error;
use crate::pkcs11_native::SessionCloser;
use crate::pkcs11_native::SessionRef;

/// Raw Ed25519 public-key length (the Edwards point), in bytes.
const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// Raw Ed25519 signature length, in bytes.
const ED25519_SIGNATURE_LEN: usize = 64;

/// Outcome of running an operation on a (possibly stale) cached session.
///
/// The amortization layer ([`AmortizedSession`]) distinguishes a *transient*
/// session fault (the cached session went invalid/closed or login lapsed —
/// re-open ONCE and retry) from a *fatal* error (a genuine
/// [`KeyError`] that re-opening would not fix — propagate, fail closed). This is
/// what keeps the fail-closed posture intact while still amortizing logins: a real
/// signing/lookup failure is NEVER masked by a reconnect-and-retry loop.
enum SessionOpError {
    /// The cached session is no longer usable (handle invalid / closed / not
    /// logged in / device hiccup). Re-open a fresh logged-in session and retry the
    /// operation exactly once.
    SessionInvalid(KeyError),
    /// A genuine failure that a fresh session would not cure — propagate as-is.
    Fatal(KeyError),
}

/// Open a fresh logged-in session of type `S`. Implemented for the real
/// [`Pkcs11KeySource`] (opens a Cryptoki R/W session + `C_Login`) and, in tests,
/// by a counting fake — so the amortization decision is provable WITHOUT a live
/// token (no PKCS#11 provider dependency for the unit proof).
trait LoginSessionFactory {
    /// The session handle type this factory produces.
    type Session;
    /// Open a NEW session and authenticate it (one `C_Login`). Every call here is
    /// one login — the whole point of [`AmortizedSession`] is to make this run far
    /// fewer than once per signed response.
    fn open_logged_in(&self) -> Result<Self::Session, KeyError>;
}

/// Amortizes the PKCS#11 LOGIN across operations (audit M16): instead of opening a
/// fresh session and performing a `C_Login` on EVERY signed response — which makes
/// signing latency/availability hostage to token login throughput and is a
/// boundary DoS amplification — this holds ONE logged-in session behind a `Mutex`
/// and reuses it. A fresh login happens only on first use or when the cached
/// session has gone invalid (handle closed / token re-inserted / login lapsed), so
/// N sequential signs perform far fewer than N logins.
///
/// Fail-closed is preserved: a *fatal* [`SessionOpError::Fatal`] (a real sign /
/// lookup failure) is propagated immediately and never retried; only a
/// [`SessionOpError::SessionInvalid`] triggers a single re-open-and-retry. If the
/// re-open itself fails, that error is surfaced (no in-process fallback, no
/// fabricated signature).
struct AmortizedSession<S> {
    /// The cached logged-in session, lazily opened on first use and re-opened on a
    /// transient session fault. `None` until the first successful login.
    cached: Mutex<Option<S>>,
}

impl<S> AmortizedSession<S> {
    /// Start with no cached session; the first [`Self::with_session`] call opens
    /// and logs one in.
    fn new() -> Self {
        AmortizedSession {
            cached: Mutex::new(None),
        }
    }

    /// Run `op` against a logged-in session, reusing the cached one when possible.
    ///
    /// 1. Ensure a cached session exists (open + login once if absent).
    /// 2. Run `op` on it. On success, return — NO new login.
    /// 3. On [`SessionOpError::SessionInvalid`], drop the dead session, open a
    ///    fresh logged-in one, and run `op` ONE more time. A second transient
    ///    failure (or a re-open failure) is surfaced — no unbounded retry loop.
    /// 4. On [`SessionOpError::Fatal`], propagate immediately (fail closed).
    fn with_session<F, T, Op>(&self, factory: &F, op: Op) -> Result<T, KeyError>
    where
        F: LoginSessionFactory<Session = S>,
        Op: Fn(&S) -> Result<T, SessionOpError>,
    {
        let mut guard = self
            .cached
            .lock()
            .map_err(|e| KeyError::NotFound(format!("pkcs11: session mutex poisoned: {e}")))?;

        // Ensure a session is cached (first use, or after a prior invalidation
        // cleared it).
        if guard.is_none() {
            *guard = Some(factory.open_logged_in()?);
        }

        // First attempt on the (reused) cached session.
        let first = {
            let session = guard
                .as_ref()
                .ok_or_else(|| KeyError::NotFound("pkcs11: session cache empty".to_string()))?;
            op(session)
        };
        match first {
            Ok(value) => Ok(value),
            Err(SessionOpError::Fatal(e)) => Err(e),
            Err(SessionOpError::SessionInvalid(_)) => {
                // Transient: the cached session is dead. Drop it, open exactly ONE
                // fresh logged-in session, and retry the op once. Re-open failure
                // (or a second transient failure) fails closed.
                *guard = None;
                let session = factory.open_logged_in()?;
                // Cache the fresh session ONLY if the retried op SUCCEEDS (issue
                // #25). A session whose op returned Fatal or SessionInvalid must
                // NOT be cached — leaving the cache empty so the next call re-opens
                // a clean session — otherwise a dead/invalid handle would be reused
                // and every subsequent op would fail until eviction.
                match op(&session) {
                    Ok(value) => {
                        *guard = Some(session);
                        Ok(value)
                    }
                    Err(SessionOpError::Fatal(e)) | Err(SessionOpError::SessionInvalid(e)) => {
                        // `guard` stays None; `session` is dropped (closed) here.
                        Err(e)
                    }
                }
            }
        }
    }
}

/// A cached, logged-in PKCS#11 session reduced to its raw `CK_SESSION_HANDLE`.
///
/// This is the lifetime-free `S` that [`AmortizedSession`] caches for the real
/// source. The wrapper's [`crate::pkcs11_native::Session`] carries a phantom
/// lifetime tying it to its [`Pkcs11Context`], which makes it impossible to store
/// alongside that same context in one struct (self-referential). Because a session
/// is really just a `Copy` handle, we amortize on the HANDLE: open+login once,
/// keep the handle here, and run each op through a non-owning
/// [`SessionRef`](crate::pkcs11_native::SessionRef) against the live context.
///
/// The handle is closed explicitly when this holder is retired (on a transient
/// invalidation, via [`Pkcs11Context::close_session`]); `C_Finalize` on context
/// drop is the backstop for the one currently-cached handle.
struct LoggedInSession {
    /// The raw open+logged-in session handle (owned: closed on retirement).
    handle: CK_SESSION_HANDLE,
    /// Lifetime-free closer for `handle`'s parent context; closes the handle on
    /// drop (retirement by [`AmortizedSession`], or when the source is dropped).
    closer: SessionCloser,
}

impl Drop for LoggedInSession {
    fn drop(&mut self) {
        // Retire the cached handle. A close error on teardown has nowhere
        // meaningful to go (and `C_Finalize` on the context is the backstop), so it
        // is intentionally ignored — but we never call a null pointer (the closer
        // guards that) and we never leak silently while the context lives.
        let _ = self.closer.close(self.handle);
    }
}

/// Classify a wrapper [`Pkcs11Error`]: `true` when re-opening a fresh logged-in
/// session could plausibly cure it (the current session handle is invalid/closed,
/// the login lapsed, or the device had a transient fault). A `false` here means the
/// error is intrinsic to the operation (bad mechanism, malformed object, …) and a
/// reconnect would not help — fail closed (a real sign/lookup error is NOT retried).
fn is_session_invalid(error: &Pkcs11Error) -> bool {
    match error {
        Pkcs11Error::Ck { rv, .. } => matches!(
            *rv,
            CKR_SESSION_HANDLE_INVALID
                | CKR_SESSION_CLOSED
                | CKR_SESSION_COUNT
                | CKR_USER_NOT_LOGGED_IN
                | CKR_DEVICE_ERROR
                | CKR_DEVICE_REMOVED
        ),
        // Load / missing-function / protocol shape errors are not transient session
        // faults — re-opening would not cure them. Fail closed.
        Pkcs11Error::Load(_)
        | Pkcs11Error::MissingFunction(_)
        | Pkcs11Error::Protocol(_) => false,
    }
}

/// Map a wrapper [`Pkcs11Error`] from a token op into a [`SessionOpError`]: a
/// session-fault CK_RV becomes [`SessionOpError::SessionInvalid`] (retry once),
/// everything else [`SessionOpError::Fatal`] (propagate, fail closed). `make_fatal`
/// builds the contextual [`KeyError`] for the fatal/propagated case (matching the
/// pre-amortization error text exactly).
fn classify_op_error(
    error: Pkcs11Error,
    make_fatal: impl FnOnce(&Pkcs11Error) -> KeyError,
) -> SessionOpError {
    if is_session_invalid(&error) {
        // Retryable: surface a NotFound carrying the transient cause; the retry
        // path discards the message, so the text is diagnostic only.
        SessionOpError::SessionInvalid(KeyError::NotFound(format!(
            "pkcs11: transient session fault: {error}"
        )))
    } else {
        SessionOpError::Fatal(make_fatal(&error))
    }
}

/// A PKCS#11-backed [`KeySource`] whose Ed25519 response-signing key lives on a
/// hardware/software token and is exercised only via `C_Sign` — the private key
/// never leaves the device. TLS material is delegated to an inner
/// [`FileKeySource`] (see the module doc for the delegated-TLS-signing follow-up).
///
/// The PIN is held in [`Zeroizing`] so it is scrubbed from memory on drop.
///
/// A single logged-in session is AMORTIZED across operations (audit M16): rather
/// than a `C_Login` per signed response — which makes signing latency/availability
/// hostage to the token's login throughput, a boundary DoS amplification — the
/// source keeps one logged-in session in [`AmortizedSession`] and reuses it,
/// re-logging in only when that session goes invalid. The authenticated window is
/// the proxy's lifetime, which is the intended posture for a sidecar that signs
/// every response; fail-closed behaviour on genuine login/sign errors is preserved.
pub struct Pkcs11KeySource {
    /// The shared, logged-in token (one `C_Initialize` + ONE amortized `C_Login` per
    /// process). Shared via `Arc` with the optional delegated TLS signer so BOTH the
    /// response-signing key object and the TLS key object are reached over the SAME
    /// login — PKCS#11 login is per-token-per-application, so a second independent
    /// `C_Login` on the same token returns `CKR_USER_ALREADY_LOGGED_IN`.
    token: Arc<Pkcs11Token>,
    /// Optional DELEGATED TLS handshake signer (issue #59). Holds its own `Arc` clone
    /// of `token`; on drop it releases that clone, and the shared token (session +
    /// context) is torn down only when the LAST `Arc<Pkcs11Token>` drops.
    tls_signer: Option<Arc<Pkcs11TlsSigner>>,
    /// The CKA_LABEL of the Ed25519 PRIVATE key object (used via `C_Sign` only).
    key_label: String,
    /// File-backed source for the TLS cert chain / TLS key / client-CA roots.
    tls: FileKeySource,
}

/// A loaded, logged-in PKCS#11 token shared between the response-signing source and
/// the delegated TLS signer. Owns the one module context and the one amortized login
/// session; each consumer differs ONLY in which object label it finds and signs with.
///
/// FIELD ORDER IS LOAD-BEARING. Rust drops fields in declaration order, so `session`
/// MUST precede `context`: the cached [`LoggedInSession`] closes its handle
/// (`C_CloseSession`, via its [`SessionCloser`]) on drop, dereferencing `context`'s
/// function list — which [`Pkcs11Context::drop`] FINALIZES (`C_Finalize`). Dropping
/// `context` first would call into a finalized module (use-after-finalize → crash).
/// With `session` first, the cached handle is closed BEFORE `C_Finalize` runs.
struct Pkcs11Token {
    /// ONE logged-in session reused across response signs, TLS handshake signs, and
    /// public-key reads (M16): a fresh login happens only on first use or after a
    /// transient session invalidation. Declared first so it drops before `context`.
    session: AmortizedSession<LoggedInSession>,
    /// The loaded Cryptoki context (owns the module handle; finalized on drop, after
    /// `session`). One `C_Initialize` per process.
    context: Pkcs11Context,
    /// The id of the slot whose token holds the key objects.
    slot: CK_SLOT_ID,
    /// The token User PIN, scrubbed on drop.
    pin: Zeroizing<String>,
}

// SAFETY (Send + Sync): the shared token is held inside an `Arc` reachable from the
// delegated [`RawEd25519TlsSigner`], which rustls requires to be `Send + Sync`.
// `Pkcs11Token` is otherwise `!Send`/`!Sync` only because [`Pkcs11Context`] carries
// the module's raw `CK_FUNCTION_LIST_PTR`. Sharing it across threads is sound:
//   * the module is initialized with `CKF_OS_LOCKING_OK`, so the PKCS#11 provider is
//     thread-safe and may be called concurrently;
//   * the function-list pointer is set ONCE at load and never mutated afterwards —
//     every later access is a read used purely to dispatch an FFI call;
//   * the only mutable shared state, the cached logged-in session handle, lives
//     behind the `AmortizedSession`'s `Mutex`, serializing the token operations.
// The slot and PIN (`Zeroizing<String>`) are ordinary `Send + Sync` values.
unsafe impl Send for Pkcs11Token {}
unsafe impl Sync for Pkcs11Token {}

/// The token opens ONE logged-in session per [`open_logged_in`] call — exactly the
/// login that [`AmortizedSession`] makes rare. Shared by the response-signing source
/// and the delegated TLS signer, so both ride a SINGLE `C_Login`.
impl LoginSessionFactory for Pkcs11Token {
    type Session = LoggedInSession;

    fn open_logged_in(&self) -> Result<LoggedInSession, KeyError> {
        let handle = self
            .context
            .open_logged_in_handle(self.slot, &self.pin)
            .map_err(|e| KeyError::NotFound(format!("pkcs11: open+login session: {e}")))?;
        Ok(LoggedInSession {
            handle,
            closer: self.context.session_closer(),
        })
    }
}

impl Pkcs11KeySource {
    /// Open a PKCS#11 token and bind to the named Ed25519 signing key.
    ///
    /// Loads the Cryptoki module at `module_path`, initializes it, selects the
    /// token whose label equals `token_label`, opens a logged-in User session to
    /// confirm the PIN and locate the Ed25519 PRIVATE and PUBLIC key objects by
    /// `key_label`, then closes that probe session (each later operation opens its
    /// own). The TLS cert chain, TLS key, and client-CA roots are loaded from the
    /// given file paths via an inner [`FileKeySource`].
    ///
    /// Every failure maps to a [`KeyError`] with context (fail closed); this never
    /// panics and never substitutes an in-process key.
    /// `tls_key_label` (issue #59): when `Some(label)`, a SECOND Ed25519 token
    /// object (distinct from `key_label` — a separate security principal) custodies
    /// the TLS server key, and a [`Pkcs11TlsSigner`] is opened over it so the TLS
    /// handshake is signed ON the token (the TLS private key never leaves the
    /// device, `tls_key_path` is then NOT read from disk). `None` keeps the
    /// file-backed TLS path. The object-signing label and TLS label are independent:
    /// neither requires the other, and a label resolving to multiple or non-Ed25519
    /// objects fails closed at `open` (proven by the live lane).
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        module_path: &str,
        pin: &str,
        token_label: &str,
        key_label: &str,
        tls_cert_path: &str,
        tls_key_path: &str,
        client_ca_path: &str,
        tls_key_label: Option<&str>,
    ) -> Result<Self, KeyError> {
        // Load the module and C_Initialize with OS locking (CKF_OS_LOCKING_OK)
        // through the owned safe wrapper over the raw cryptoki-sys FFI bindings.
        let context = Pkcs11Context::load_and_initialize(module_path).map_err(|e| {
            KeyError::NotFound(format!("pkcs11: load+initialize module '{module_path}': {e}"))
        })?;
        let slot = find_token_slot(&context, token_label)?;

        // The ONE shared, logged-in token. Both the response-signing key object and
        // the TLS key object are reached over this single login (PKCS#11 login is
        // per-token-per-application — a second independent `C_Login` on the same
        // token would be `CKR_USER_ALREADY_LOGGED_IN`).
        let token = Arc::new(Pkcs11Token {
            session: AmortizedSession::new(),
            context,
            slot,
            pin: Zeroizing::new(pin.to_string()),
        });

        // Prove, at construction, that the PIN logs in and BOTH response-signing key
        // objects exist — a misconfiguration fails closed at startup, not on the
        // first signed response. This primes the shared login the whole process
        // reuses (the one login every later op — response AND TLS — rides).
        let key_label = key_label.to_string();
        token.session.with_session(token.as_ref(), |logged_in| {
            let view = token.context.with_handle(logged_in.handle);
            find_key(&view, &key_label, ObjectClass::Private)?;
            find_key(&view, &key_label, ObjectClass::Public)?;
            Ok::<(), SessionOpError>(())
        })?;

        // Issue #59: a configured TLS-key label custodies the TLS server key in a
        // SEPARATE token object (a distinct security principal — independent of the
        // object-signing key, neither requiring the other). The signer shares this
        // token (same module + same login) but signs with the TLS-key label.
        // Constructing it here proves at startup that the TLS key object is a SINGLE
        // Ed25519 object (fail closed on zero/multiple/non-Ed25519).
        let tls_signer = match tls_key_label {
            Some(label) => Some(Arc::new(Pkcs11TlsSigner::open(token.clone(), label)?)),
            None => None,
        };

        Ok(Pkcs11KeySource {
            token,
            tls_signer,
            key_label,
            tls: FileKeySource {
                // The token custodies the response-signing key, so this inner
                // file source's signing-key path is never read; give it the TLS
                // key path as an inert, valid placeholder rather than an empty
                // string. Only the TLS accessors below are ever delegated to it.
                signing_key_seed_path: tls_key_path.to_string(),
                tls_cert_path: tls_cert_path.to_string(),
                tls_key_path: tls_key_path.to_string(),
                client_ca_path: client_ca_path.to_string(),
            },
        })
    }
}

/// Locate the single Ed25519 key object of the given class with `key_label`
/// against an open session view, classified for the amortization layer.
///
/// A transient session fault during the find is [`SessionOpError::SessionInvalid`]
/// (retry once); any other wrapper error is [`SessionOpError::Fatal`] with the SAME
/// `NotFound` context text as the pre-amortization path. The count cases are
/// intrinsic, never a session fault: zero matches is a [`KeyError::NotFound`] Fatal;
/// more than one is a [`KeyError::Malformed`] Fatal (an ambiguous token config must
/// fail closed, never silently pick one). A re-open would not change these.
fn find_key(
    view: &SessionRef<'_>,
    key_label: &str,
    class: ObjectClass,
) -> Result<CK_OBJECT_HANDLE, SessionOpError> {
    let template = AttributeTemplate::ed25519_labelled(class, key_label);
    let mut handles = view.find_objects(&template).map_err(|e| {
        classify_op_error(e, |e| {
            KeyError::NotFound(format!("pkcs11: find key '{key_label}': {e}"))
        })
    })?;
    match handles.len() {
        0 => Err(SessionOpError::Fatal(KeyError::NotFound(format!(
            "pkcs11: no Ed25519 key object labelled '{key_label}' (class {})",
            class_name(class)
        )))),
        1 => Ok(handles.remove(0)),
        n => Err(SessionOpError::Fatal(KeyError::Malformed(format!(
            "pkcs11: {n} Ed25519 key objects labelled '{key_label}' (class {}); refusing to guess",
            class_name(class)
        )))),
    }
}

/// Human-readable name for an [`ObjectClass`] in error context (the wrapper enum
/// is intentionally minimal and not `Debug`-printed onto the token path).
fn class_name(class: ObjectClass) -> &'static str {
    match class {
        ObjectClass::Private => "CKO_PRIVATE_KEY",
        ObjectClass::Public => "CKO_PUBLIC_KEY",
    }
}

/// Select the slot whose token's label equals `token_label`. Token labels are
/// stable across reboots (slot ids are not), so this is the primary selector. No
/// match is [`KeyError::NotFound`].
fn find_token_slot(context: &Pkcs11Context, token_label: &str) -> Result<CK_SLOT_ID, KeyError> {
    // `token_slots` enumerates present-token slots and reads each token's label
    // with the 32-byte 0x20 padding already trimmed.
    let slots = context
        .token_slots()
        .map_err(|e| KeyError::NotFound(format!("pkcs11: enumerate token slots: {e}")))?;
    for (slot, label) in slots {
        if label.trim_end() == token_label {
            return Ok(slot);
        }
    }
    Err(KeyError::NotFound(format!(
        "pkcs11: no token with label '{token_label}'"
    )))
}

/// Strip a DER `OCTET STRING` wrapper (`0x04 <len> <bytes>`) if present, returning
/// the raw 32-byte Ed25519 point. PKCS#11 v3 returns `CKA_EC_POINT` as a DER
/// `OCTET STRING` around the curve point; some modules return the bare 32 bytes.
/// Accept both, but reject anything that is not ultimately exactly 32 bytes (fail
/// closed — a wrong-length point cannot be a valid Ed25519 key).
fn raw_ed25519_point(ec_point: &[u8]) -> Result<[u8; ED25519_PUBLIC_KEY_LEN], KeyError> {
    let raw: &[u8] = if ec_point.len() == ED25519_PUBLIC_KEY_LEN {
        ec_point
    } else if ec_point.len() == ED25519_PUBLIC_KEY_LEN + 2
        && ec_point[0] == 0x04
        && usize::from(ec_point[1]) == ED25519_PUBLIC_KEY_LEN
    {
        // DER OCTET STRING: tag 0x04, length 0x20, then the 32-byte point.
        &ec_point[2..]
    } else {
        return Err(KeyError::Malformed(format!(
            "pkcs11: CKA_EC_POINT is {} bytes; expected a raw or OCTET-STRING-wrapped \
             32-byte Ed25519 point",
            ec_point.len()
        )));
    };
    let mut bytes = [0u8; ED25519_PUBLIC_KEY_LEN];
    bytes.copy_from_slice(raw);
    Ok(bytes)
}

/// Build the RFC 8410 Ed25519 `SubjectPublicKeyInfo` DER from a token's raw
/// `CKA_EC_POINT` (issue #59, ADR-MCPS-028 §G). The point is first normalized to
/// the bare 32-byte Edwards point (stripping a DER `OCTET STRING` wrapper if the
/// module returned one), then prefixed with the shared 12-byte RFC 8410 Ed25519
/// SPKI header used by the KMS public-key path — so the result feeds the same
/// [`crate::kms_keysource::ed25519_raw_point_from_spki`] guard that the validated
/// delegated-TLS build path (#58) uses to fail closed on a cert/key mismatch. A
/// wrong-length / non-Ed25519 point fails closed via [`raw_ed25519_point`].
fn ed25519_spki_from_ec_point(ec_point: &[u8]) -> Result<Vec<u8>, KeyError> {
    let raw = raw_ed25519_point(ec_point)?;
    let mut der = crate::kms_keysource::ED25519_SPKI_PREFIX.to_vec();
    der.extend_from_slice(&raw);
    Ok(der)
}

/// Emit-guard for a token `C_Sign` result (ADR-MCPS-028 §D verify-before-return).
///
/// Encodes the raw signature exactly as [`mcp_re_core::SigningKey::sign`] would
/// (Base64URL-no-pad) and confirms it verifies against `verify_key` — the token's
/// OWN advertised Ed25519 public point — under the unmodified mcp-re-core verifier
/// BEFORE the proxy is allowed to emit it. A 64-byte blob that does not verify (a
/// mis-bound key, a prehash/over-hashing `CKM_*` mechanism, or corruption) is a
/// [`KeyError::Malformed`] — fail closed, never emitted. This is the pure,
/// token-free core mirroring the AWS/GCP `sign_raw_ed25519` guardrail, so it is
/// unit-testable without a live token.
fn verify_before_emit(
    preimage: &[u8],
    signature: &[u8],
    verify_key: &VerificationKey,
) -> Result<String, KeyError> {
    // Match SigningKey::sign EXACTLY: Base64URL-no-pad of the raw 64 bytes.
    let signature_b64url = b64url_encode(signature);
    verify_ed25519(preimage, &signature_b64url, verify_key).map_err(|e| {
        KeyError::Malformed(format!(
            "pkcs11: C_Sign signature did NOT verify against the token's advertised \
             public key (mis-bound key or prehash/over-hashing CKM mechanism?): {e}"
        ))
    })?;
    Ok(signature_b64url)
}

/// Read the token's Ed25519 PUBLIC point for `key_label` and parse it into a
/// [`VerificationKey`], classified for the amortization layer.
///
/// Shared by [`ResponseSigner::response_public_key`] (what relying parties verify
/// against) and the verify-before-return guard in
/// [`ResponseSigner::sign_response`] (which checks each `C_Sign` result against
/// this SAME advertised point before emitting it). A transient session fault on
/// the `CKA_EC_POINT` read is [`SessionOpError::SessionInvalid`] (retry once); a
/// wrong-length / non-canonical / off-curve point is a [`SessionOpError::Fatal`]
/// [`KeyError::Malformed`] (intrinsic trust-binding failure — fail closed).
fn verification_key(
    view: &SessionRef<'_>,
    key_label: &str,
) -> Result<VerificationKey, SessionOpError> {
    let public = find_key(view, key_label, ObjectClass::Public)?;
    let ec_point = view.get_ec_point(public).map_err(|e| {
        classify_op_error(e, |e| {
            KeyError::Malformed(format!("pkcs11: read CKA_EC_POINT: {e}"))
        })
    })?;
    let bytes = raw_ed25519_point(&ec_point).map_err(SessionOpError::Fatal)?;
    // A non-canonical / off-curve point is a trust-binding failure in mcp-re-core;
    // surface it as malformed key material here. Intrinsic — not a session fault.
    VerificationKey::from_bytes(&bytes).map_err(|e| {
        SessionOpError::Fatal(KeyError::Malformed(format!(
            "pkcs11: invalid Ed25519 public key: {e}"
        )))
    })
}

/// Signs over the token (`C_Sign` with `CKM_EDDSA`) — the private key never
/// leaves the device — and reads the exportable public point for verification.
impl ResponseSigner for Pkcs11KeySource {
    fn sign_response(&self, preimage: &[u8]) -> Result<String, KeyError> {
        // Run the find+sign through the AMORTIZED logged-in session (M16): the
        // login is reused; only a transient session fault triggers ONE re-login.
        self.token.session.with_session(self.token.as_ref(), |logged_in| {
            let view = self.token.context.with_handle(logged_in.handle);
            let private = find_key(&view, &self.key_label, ObjectClass::Private)?;
            // CKM_EDDSA over the raw preimage (NO pre-hash), matching MCP-RE's
            // direct Ed25519 signing rule. The token returns the raw 64-byte sig.
            let signature = view.sign_eddsa(private, preimage).map_err(|e| {
                classify_op_error(e, |e| {
                    KeyError::Malformed(format!("pkcs11: C_Sign (CKM_EDDSA): {e}"))
                })
            })?;
            if signature.len() != ED25519_SIGNATURE_LEN {
                // A wrong-length signature is intrinsic (not a session fault) —
                // fail closed, never retry.
                return Err(SessionOpError::Fatal(KeyError::Malformed(format!(
                    "pkcs11: token returned a {}-byte signature; expected {ED25519_SIGNATURE_LEN}",
                    signature.len()
                ))));
            }
            // VERIFY-BEFORE-RETURN (ADR-MCPS-028 §D / guardrail): mirror the AWS
            // (`aws_kms_keysource.rs`) and GCP (`gcp_kms_keysource.rs`) backends —
            // the 64-byte length is necessary but NOT sufficient. Read the token's
            // own Ed25519 public point (the SAME object relying parties verify
            // against via `response_public_key`) and confirm the signature verifies
            // under the unmodified mcp-re-core verifier BEFORE emitting it. This
            // catches a mis-bound key, a prehash/over-hashing `CKM_*` mechanism, or
            // any corruption that still yields a 64-byte blob — fail closed, never
            // emit an unverifiable signature. Reading the public point is intrinsic
            // to this signed response; a transient session fault on the read still
            // routes through the amortization retry via `verification_key`.
            let verify_key = verification_key(&view, &self.key_label)?;
            verify_before_emit(preimage, &signature, &verify_key)
                .map_err(SessionOpError::Fatal)
        })
    }

    fn response_public_key(&self) -> Result<VerificationKey, KeyError> {
        self.token.session.with_session(self.token.as_ref(), |logged_in| {
            let view = self.token.context.with_handle(logged_in.handle);
            verification_key(&view, &self.key_label)
        })
    }
}

/// TLS material is delegated to the inner [`FileKeySource`] (see the module doc:
/// delegated TLS signing through the token is the remaining #4034 sub-item).
impl KeySource for Pkcs11KeySource {
    fn tls_server_cert_chain(&self) -> Result<Vec<CertificateDer<'static>>, KeyError> {
        self.tls.tls_server_cert_chain()
    }
    fn tls_server_key(&self) -> Result<PrivateKeyDer<'static>, KeyError> {
        self.tls.tls_server_key()
    }
    fn client_ca_roots(&self) -> Result<Vec<CertificateDer<'static>>, KeyError> {
        self.tls.client_ca_roots()
    }

    /// Issue #59 (ADR-MCPS-028 §G): when a TLS-key label was configured the TLS
    /// handshake is DELEGATED to the token-resident TLS key, so the proxy drives the
    /// handshake signature through the device and NEVER reads an exported TLS key
    /// from disk. `None` (no TLS-key label) preserves the file-backed TLS path. The
    /// validated build path (#58) feeds this signer's `tls_public_key_spki_der` into
    /// the cert↔signer match check, failing closed before any server starts.
    fn tls_delegated_signer(&self) -> Option<Arc<dyn RawEd25519TlsSigner>> {
        self.tls_signer
            .clone()
            .map(|signer| signer as Arc<dyn RawEd25519TlsSigner>)
    }
}

/// A PKCS#11-backed DELEGATED TLS handshake signer (issue #59, ADR-MCPS-028 §G):
/// the Ed25519 TLS *server* key lives on the token as a SEPARATE object (a distinct
/// security principal from the response-signing key) and is exercised ONLY via
/// `C_Sign` with `CKM_EDDSA` — the TLS private key never leaves the device. rustls
/// drives the handshake signature through [`RawEd25519TlsSigner::sign_tls_ed25519`];
/// the (exportable) TLS public point feeds [`RawEd25519TlsSigner::tls_public_key_spki_der`]
/// so the validated build path (#58) fails closed on a cert/key mismatch.
///
/// This signer SHARES the owning [`Pkcs11KeySource`]'s [`Pkcs11Token`] via `Arc` —
/// one `C_Initialize` and one amortized `C_Login` per process — and signs with the
/// TLS-key label. It is an independent signing PRINCIPAL (a separate token object,
/// ADR-MCPS-028 §G) that rides the same module + login as the response-signing key.
/// (The ADR allows the TLS key to carry distinct PKCS#11 auth; the CLI wires the
/// same token PIN. A future flag could route a separate credential without changing
/// the `RawEd25519TlsSigner` surface.)
pub struct Pkcs11TlsSigner {
    /// The shared, logged-in token (see [`Pkcs11Token`]). All TLS handshake signs and
    /// public-key reads go through its one amortized login.
    token: Arc<Pkcs11Token>,
    /// The CKA_LABEL of the Ed25519 TLS PRIVATE key object (used via `C_Sign` only).
    tls_key_label: String,
}

// `Pkcs11TlsSigner` is `Send + Sync` automatically: its only fields are an
// `Arc<Pkcs11Token>` (the token is `Send + Sync` — see its `unsafe impl` above) and
// a `String`. rustls requires the delegated `RawEd25519TlsSigner` to be `Send + Sync`,
// which this satisfies without a further `unsafe impl`.

impl Pkcs11TlsSigner {
    /// Bind to the named Ed25519 TLS key on the shared `token`, proving at
    /// construction that BOTH the PRIVATE and PUBLIC TLS key objects exist, are
    /// Ed25519, and are UNAMBIGUOUS — a misconfigured TLS credential fails closed
    /// here, before any server starts, never at the first handshake. Every failure
    /// maps to a [`KeyError`] with context; this never panics and never fabricates a
    /// signature or public key.
    fn open(token: Arc<Pkcs11Token>, tls_key_label: &str) -> Result<Self, KeyError> {
        let tls_key_label = tls_key_label.to_string();

        // Prove BOTH TLS key objects exist + are single Ed25519 objects (fail closed
        // on zero/multiple/non-Ed25519), reusing the token's already-primed login.
        token.session.with_session(token.as_ref(), |logged_in| {
            let view = token.context.with_handle(logged_in.handle);
            find_key(&view, &tls_key_label, ObjectClass::Private)?;
            find_key(&view, &tls_key_label, ObjectClass::Public)?;
            Ok::<(), SessionOpError>(())
        })?;

        Ok(Pkcs11TlsSigner {
            token,
            tls_key_label,
        })
    }
}

/// Signs the raw TLS handshake transcript ON the token (`C_Sign` / `CKM_EDDSA`) and
/// exports the TLS public point as an RFC 8410 Ed25519 SPKI — the TLS private key
/// never leaves the device. Runs through the SHARED token's one amortized login.
impl RawEd25519TlsSigner for Pkcs11TlsSigner {
    fn sign_tls_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        self.token.session.with_session(self.token.as_ref(), |logged_in| {
            let view = self.token.context.with_handle(logged_in.handle);
            let private = find_key(&view, &self.tls_key_label, ObjectClass::Private)?;
            // CKM_EDDSA over the raw handshake transcript (NO pre-hash): exactly the
            // PureEdDSA signature rustls expects for SignatureScheme::ED25519. The
            // token returns the raw 64-byte signature; the delegated signer wrapper
            // (delegated_tls.rs) enforces the 64-byte length before it hits the wire.
            let signature = view.sign_eddsa(private, message).map_err(|e| {
                classify_op_error(e, |e| {
                    KeyError::Malformed(format!("pkcs11 tls: C_Sign (CKM_EDDSA): {e}"))
                })
            })?;
            if signature.len() != ED25519_SIGNATURE_LEN {
                return Err(SessionOpError::Fatal(KeyError::Malformed(format!(
                    "pkcs11 tls: token returned a {}-byte signature; expected \
                     {ED25519_SIGNATURE_LEN}",
                    signature.len()
                ))));
            }
            Ok(signature)
        })
    }

    fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, KeyError> {
        self.token.session.with_session(self.token.as_ref(), |logged_in| {
            let view = self.token.context.with_handle(logged_in.handle);
            let public = find_key(&view, &self.tls_key_label, ObjectClass::Public)?;
            let ec_point = view.get_ec_point(public).map_err(|e| {
                classify_op_error(e, |e| {
                    KeyError::Malformed(format!("pkcs11 tls: read CKA_EC_POINT: {e}"))
                })
            })?;
            // Build the RFC 8410 SPKI from the raw point; a wrong-length / non-Ed25519
            // point fails closed (intrinsic — not a session fault).
            ed25519_spki_from_ec_point(&ec_point).map_err(SessionOpError::Fatal)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use mcp_re_core::b64url_decode;
    use mcp_re_core::b64url_encode;
    use mcp_re_core::SigningKey;

    use super::ed25519_spki_from_ec_point;
    use super::verify_before_emit;
    use super::AmortizedSession;
    use super::KeyError;
    use super::LoginSessionFactory;
    use super::SessionOpError;
    use super::ED25519_PUBLIC_KEY_LEN;
    use super::ED25519_SIGNATURE_LEN;

    /// Issue #59 (test b, no token): the SPKI the TLS signer exports from a token's
    /// raw `CKA_EC_POINT` is a well-formed RFC 8410 Ed25519 `SubjectPublicKeyInfo`
    /// (12-byte prefix + 32-byte point = 44 bytes) AND it round-trips through the
    /// SAME guard the validated delegated-TLS build path (#58) uses, yielding the
    /// original 32-byte point. Both the bare-32-byte and DER-OCTET-STRING-wrapped
    /// token encodings are accepted; a wrong-length point fails closed.
    #[test]
    fn tls_spki_is_well_formed_rfc8410_and_round_trips() {
        let point = [7u8; ED25519_PUBLIC_KEY_LEN];

        // Bare 32-byte point (some modules) and OCTET-STRING-wrapped (PKCS#11 v3)
        // must both yield the identical 44-byte RFC 8410 SPKI.
        let wrapped: Vec<u8> = {
            let mut v = vec![0x04, ED25519_PUBLIC_KEY_LEN as u8];
            v.extend_from_slice(&point);
            v
        };
        let spki_bare = ed25519_spki_from_ec_point(&point).expect("bare point → SPKI");
        let spki_wrapped = ed25519_spki_from_ec_point(&wrapped).expect("wrapped point → SPKI");
        assert_eq!(spki_bare, spki_wrapped, "both encodings yield the same SPKI");
        assert_eq!(spki_bare.len(), 44, "RFC 8410 Ed25519 SPKI is 12 + 32 bytes");
        assert_eq!(
            &spki_bare[..super::super::kms_keysource::ED25519_SPKI_PREFIX.len()],
            &super::super::kms_keysource::ED25519_SPKI_PREFIX,
            "the 12-byte RFC 8410 prefix is present"
        );

        // The exported SPKI feeds the SAME parser the #58 validated build path uses;
        // it must recover exactly the original raw point (cert↔signer match basis).
        let recovered = crate::kms_keysource::ed25519_raw_point_from_spki(&spki_bare)
            .expect("exported SPKI parses under the #58 delegated-build guard");
        assert_eq!(recovered, point, "round-trips to the original Edwards point");

        // Fail closed on a wrong-length point (cannot be a valid Ed25519 key).
        assert!(matches!(
            ed25519_spki_from_ec_point(&[0u8; 31]),
            Err(KeyError::Malformed(_))
        ));
    }

    /// Finding #137 (ADR-MCPS-028 §D verify-before-return): a 64-byte signature that
    /// does NOT verify against the token's advertised public key — modelling a
    /// mis-bound key or a prehash/over-hashing `CKM_*` mechanism that still returns a
    /// well-formed-length blob — is REJECTED before emit, mirroring the AWS/GCP
    /// `sign_raw_ed25519` guardrail. A correctly-bound signature passes.
    ///
    /// RED without the fix: before this change `sign_response` checked ONLY the
    /// 64-byte length and then emitted `b64url_encode(signature)` unconditionally, so
    /// `verify_before_emit` (the guard) did not exist and an unverifiable 64-byte
    /// signature would be returned. With the guard, it fails closed as `Malformed`.
    #[test]
    fn unverifiable_64byte_signature_is_rejected_before_emit() {
        let preimage = b"mcp-re-response-preimage";

        // The token's advertised response-signing key (what relying parties verify
        // against, read in-band via `verification_key`).
        let signing_key = SigningKey::from_seed_bytes(&[3u8; 32]);
        let verify_key = signing_key.public_key();

        // Good path: the genuine 64-byte signature from THIS key verifies and is
        // emitted as Base64URL-no-pad — byte-for-byte what `SigningKey::sign`
        // produces, so the verifier accepts it with no special-casing.
        let good_sig = b64url_decode(&signing_key.sign(preimage)).expect("64-byte raw sig");
        assert_eq!(good_sig.len(), ED25519_SIGNATURE_LEN);
        let emitted = verify_before_emit(preimage, &good_sig, &verify_key)
            .expect("a correctly-bound signature passes verify-before-emit");
        assert_eq!(
            emitted,
            b64url_encode(&good_sig),
            "the emitted string is the Base64URL-no-pad of the raw 64 bytes"
        );

        // Mis-bound key: the token returns a 64-byte signature made by a DIFFERENT
        // key (or over a prehash) — it passes the length check the old code relied on
        // but does NOT verify under the advertised public key. Must fail closed.
        let wrong_key = SigningKey::from_seed_bytes(&[4u8; 32]);
        let wrong_sig = b64url_decode(&wrong_key.sign(preimage)).expect("64-byte raw sig");
        assert_eq!(
            wrong_sig.len(),
            ED25519_SIGNATURE_LEN,
            "the wrong-key signature is still 64 bytes — the length check alone is NOT enough"
        );
        assert!(
            matches!(
                verify_before_emit(preimage, &wrong_sig, &verify_key),
                Err(KeyError::Malformed(_))
            ),
            "a 64-byte signature that does not verify against the token's public key \
             must be rejected before emit (fail closed), never returned"
        );

        // Over-prehash variant: a signature over SHA-512(preimage) instead of the raw
        // preimage — the canonical mis-configured prehash CKM — is 64 bytes but does
        // not verify against the raw preimage. Must also fail closed.
        let prehashed = {
            use sha2::Digest;
            use sha2::Sha512;
            let digest = Sha512::digest(preimage);
            b64url_decode(&signing_key.sign(&digest)).expect("64-byte raw sig")
        };
        assert_eq!(prehashed.len(), ED25519_SIGNATURE_LEN);
        assert!(
            matches!(
                verify_before_emit(preimage, &prehashed, &verify_key),
                Err(KeyError::Malformed(_))
            ),
            "an over-prehashed (SHA-512) signature must be rejected before emit"
        );
    }

    /// A fake logged-in session standing in for a Cryptoki `Session` — carries the
    /// login generation that produced it so a test can prove the SAME session
    /// (same generation) is reused across operations.
    struct FakeSession {
        generation: u32,
    }

    /// A counting [`LoginSessionFactory`] fake: every `open_logged_in` is one
    /// "login" (incrementing `logins`), modelling the per-operation `C_Login` the
    /// M16 amortization must eliminate. No provider, no live token — runs everywhere.
    struct CountingFactory {
        /// Total logins performed (each `open_logged_in` call).
        logins: Cell<u32>,
        /// If true, the NEXT `open_logged_in` fails (models a token whose re-login
        /// fails — the amortized layer must surface this, fail closed).
        fail_next_open: Cell<bool>,
    }

    impl CountingFactory {
        fn new() -> Self {
            CountingFactory {
                logins: Cell::new(0),
                fail_next_open: Cell::new(false),
            }
        }
    }

    impl LoginSessionFactory for CountingFactory {
        type Session = FakeSession;

        fn open_logged_in(&self) -> Result<FakeSession, KeyError> {
            if self.fail_next_open.replace(false) {
                return Err(KeyError::NotFound("fake: re-login failed".to_string()));
            }
            let generation = self.logins.get() + 1;
            self.logins.set(generation);
            Ok(FakeSession { generation })
        }
    }

    /// M16 — the load-bearing proof, runs EVERYWHERE (no live token): driving the sign
    /// path N times through the amortized session performs FAR FEWER than N logins.
    /// With the per-operation-login bug this would be N logins; with amortization it
    /// is exactly one (first use), and every op observes the SAME reused session.
    ///
    /// RED without the fix: a `with_session` that called `open_logged_in` on every
    /// invocation (the old `login_session()`-per-op shape) makes `logins == N`,
    /// failing the `< N` assertion below.
    #[test]
    fn sequential_signs_amortize_to_one_login() {
        let factory = CountingFactory::new();
        let amortized: AmortizedSession<FakeSession> = AmortizedSession::new();

        const N: u32 = 50;
        let mut generations = Vec::new();
        for _ in 0..N {
            let gen = amortized
                .with_session(&factory, |session| Ok::<u32, SessionOpError>(session.generation))
                .expect("amortized op succeeds");
            generations.push(gen);
        }

        assert_eq!(
            factory.logins.get(),
            1,
            "N sequential ops must perform exactly ONE login (amortized), not N"
        );
        assert!(
            factory.logins.get() < N,
            "logins ({}) must be far fewer than the {N} operations",
            factory.logins.get()
        );
        // Every op observed the SAME session generation — proof of reuse, not a
        // fresh per-op session.
        assert!(
            generations.iter().all(|g| *g == 1),
            "every operation must reuse the SAME logged-in session, got {generations:?}"
        );
    }

    /// M16 fail-closed preservation: a FATAL op error is propagated IMMEDIATELY and
    /// NEVER triggers a re-login/retry — a genuine sign failure must not be masked
    /// by the amortization loop.
    #[test]
    fn fatal_error_is_not_retried() {
        let factory = CountingFactory::new();
        let amortized: AmortizedSession<FakeSession> = AmortizedSession::new();

        let result: Result<(), KeyError> = amortized.with_session(&factory, |_session| {
            Err(SessionOpError::Fatal(KeyError::Malformed(
                "fatal sign failure".to_string(),
            )))
        });

        assert!(matches!(result, Err(KeyError::Malformed(_))));
        assert_eq!(
            factory.logins.get(),
            1,
            "a Fatal error must NOT trigger a re-login (no retry); exactly the one \
             initial login occurred"
        );
    }

    /// M16 transient recovery: a SessionInvalid error on the cached session triggers
    /// exactly ONE re-open-and-retry; the retried op runs on a FRESH session
    /// (next generation) and succeeds. Two logins total: the initial one and the
    /// one re-login — bounded, no loop.
    #[test]
    fn session_invalid_reopens_once_and_retries() {
        let factory = CountingFactory::new();
        let amortized: AmortizedSession<FakeSession> = AmortizedSession::new();
        let attempt = Cell::new(0u32);

        let gen = amortized
            .with_session(&factory, |session| {
                let n = attempt.replace(attempt.get() + 1);
                if n == 0 {
                    // First attempt on the cached gen-1 session: simulate the
                    // handle having gone invalid.
                    Err(SessionOpError::SessionInvalid(KeyError::NotFound(
                        "fake: session handle invalid".to_string(),
                    )))
                } else {
                    // Retry, now on the re-opened gen-2 session.
                    Ok::<u32, SessionOpError>(session.generation)
                }
            })
            .expect("retry on the re-opened session succeeds");

        assert_eq!(attempt.get(), 2, "op must run exactly twice (try + one retry)");
        assert_eq!(gen, 2, "the retry must run on the FRESH (re-opened) session");
        assert_eq!(
            factory.logins.get(),
            2,
            "exactly two logins: the initial one and the single re-login"
        );
    }

    /// M16 fail-closed on re-open failure: if the cached session is invalid AND the
    /// re-login itself fails, the original re-open error is surfaced — no infinite
    /// retry, no in-process fallback.
    #[test]
    fn reopen_failure_after_invalid_fails_closed() {
        let factory = CountingFactory::new();
        let amortized: AmortizedSession<FakeSession> = AmortizedSession::new();
        // Prime a cached session (one login), then arm the next open to fail.
        amortized
            .with_session(&factory, |_s| Ok::<(), SessionOpError>(()))
            .expect("prime");
        factory.fail_next_open.set(true);

        let result: Result<(), KeyError> = amortized.with_session(&factory, |_session| {
            Err(SessionOpError::SessionInvalid(KeyError::NotFound(
                "fake: session handle invalid".to_string(),
            )))
        });

        assert!(
            matches!(result, Err(KeyError::NotFound(_))),
            "a failed re-open after invalidation must surface the re-open error"
        );
    }

    /// Issue #25: if the single re-open-and-retry ALSO fails (here, Fatal), the
    /// freshly-opened session must NOT be cached — a session whose op failed must
    /// never be reused. The proof: a SUBSEQUENT op must re-open (a fresh login and
    /// generation), which it can only do if the failed-retry session was dropped
    /// rather than cached.
    #[test]
    fn failed_retry_does_not_cache_the_session() {
        let factory = CountingFactory::new();
        let amortized: AmortizedSession<FakeSession> = AmortizedSession::new();

        // Op A: open gen-1; first attempt SessionInvalid → re-open gen-2; the retry
        // returns Fatal. Two logins so far. gen-2 must NOT be cached.
        let attempt = Cell::new(0u32);
        let result: Result<(), KeyError> = amortized.with_session(&factory, |_s| {
            let n = attempt.replace(attempt.get() + 1);
            if n == 0 {
                Err(SessionOpError::SessionInvalid(KeyError::NotFound(
                    "fake: session handle invalid".to_string(),
                )))
            } else {
                Err(SessionOpError::Fatal(KeyError::Malformed(
                    "fake: retry also fails".to_string(),
                )))
            }
        });
        assert!(matches!(result, Err(KeyError::Malformed(_))));
        assert_eq!(factory.logins.get(), 2, "initial open + one re-open");

        // Op B: because the failed-retry session was NOT cached, the cache is empty
        // and this op must open a THIRD session — proving no dead handle was reused.
        let gen = amortized
            .with_session(&factory, |s| Ok::<u32, SessionOpError>(s.generation))
            .expect("subsequent op succeeds on a freshly opened session");
        assert_eq!(
            factory.logins.get(),
            3,
            "the failed-retry session must not be cached; the next op must re-open"
        );
        assert_eq!(
            gen, 3,
            "the next op must run on a freshly opened session, not the failed one"
        );
    }
}
