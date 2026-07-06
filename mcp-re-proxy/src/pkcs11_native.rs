//! Minimal, owned safe wrapper over the raw `cryptoki-sys` FFI bindings (issue
//! #4034 supply-chain follow-up).
//!
//! # Why this exists
//! The high-level `cryptoki` crate transitively pulls the UNMAINTAINED `paste`
//! crate (RUSTSEC-2024-0436), which fails the cargo-deny gate. `cryptoki-sys`
//! carries only the raw PKCS#11 bindings and depends solely on `libloading` — no
//! `paste`. This module is the SMALL safe surface that
//! [`crate::pkcs11_keysource`] needs, built directly on those raw bindings:
//! load+initialize a module, enumerate token slots and read their labels, open an
//! RW session, log in as the User, find objects by template, sign with
//! `CKM_EDDSA`, and read `CKA_EC_POINT`. Nothing more.
//!
//! # Function-list dispatch
//! PKCS#11 modules reliably export only `C_GetFunctionList`; the individual
//! `C_*` symbols are NOT guaranteed to be exported. So this wrapper loads the
//! module with `cryptoki_sys::Pkcs11::new` (libloading), calls
//! `C_GetFunctionList` ONCE to obtain the `CK_FUNCTION_LIST`, and invokes EVERY
//! subsequent PKCS#11 call through that list's function pointers — checking each
//! pointer is `Some` and failing closed (never calling a null pointer) if not.
//!
//! # Fail-closed posture
//! Every `CK_RV != CKR_OK`, every null function pointer, and every load failure
//! becomes an [`Pkcs11Error`] with context. There is no panic, no `unwrap`/
//! `expect`/`assert` on any token or FFI path, and never a fabricated result.
//!
//! # RAII
//! [`Pkcs11Context`] calls `C_Finalize` on drop; [`Session`] calls
//! `C_CloseSession` on drop. Each signing / public-key read opens its own
//! session (this is the pre-amortization variant — no session caching here).
//!
//! Compiled ONLY under the non-default `pkcs11_keysource` feature.
#![cfg(feature = "pkcs11_keysource")]

use std::ffi::c_void;
use std::ptr;

use cryptoki_sys::CKA_CLASS;
use cryptoki_sys::CKA_EC_POINT;
use cryptoki_sys::CKA_KEY_TYPE;
use cryptoki_sys::CKA_LABEL;
use cryptoki_sys::CKF_OS_LOCKING_OK;
use cryptoki_sys::CKF_RW_SESSION;
use cryptoki_sys::CKF_SERIAL_SESSION;
use cryptoki_sys::CKK_EC_EDWARDS;
use cryptoki_sys::CKM_EDDSA;
use cryptoki_sys::CKO_PRIVATE_KEY;
use cryptoki_sys::CKO_PUBLIC_KEY;
use cryptoki_sys::CKR_OK;
use cryptoki_sys::CKU_USER;
use cryptoki_sys::CK_ATTRIBUTE;
use cryptoki_sys::CK_ATTRIBUTE_TYPE;
use cryptoki_sys::CK_C_INITIALIZE_ARGS;
use cryptoki_sys::CK_FUNCTION_LIST_PTR;
use cryptoki_sys::CK_KEY_TYPE;
use cryptoki_sys::CK_MECHANISM;
use cryptoki_sys::CK_OBJECT_CLASS;
use cryptoki_sys::CK_OBJECT_HANDLE;
use cryptoki_sys::CK_RV;
use cryptoki_sys::CK_SESSION_HANDLE;
use cryptoki_sys::CK_SLOT_ID;
use cryptoki_sys::CK_TOKEN_INFO;
use cryptoki_sys::CK_ULONG;
use cryptoki_sys::Pkcs11 as RawLoader;

/// Length, in bytes, of a PKCS#11 token label field (`CK_TOKEN_INFO.label`).
const CK_TOKEN_LABEL_LEN: usize = 32;

/// A failure on the PKCS#11 / FFI path. Carries human-readable context only —
/// never any secret material. The keysource maps these onto its own `KeyError`.
#[derive(Debug)]
pub enum Pkcs11Error {
    /// The module could not be loaded, or `C_GetFunctionList` was unavailable /
    /// returned a null list. (Module-bootstrap failures.)
    Load(String),
    /// A required function-list entry was a null pointer (the module does not
    /// implement that PKCS#11 function). Fail closed rather than call null.
    MissingFunction(String),
    /// A PKCS#11 call returned a non-`CKR_OK` status. Carries the operation and
    /// the raw `CK_RV` for diagnosis.
    Ck { op: String, rv: CK_RV },
    /// A returned value had an unexpected shape (e.g. a length that does not fit
    /// the two-call idiom). Fail closed.
    Protocol(String),
}

impl std::fmt::Display for Pkcs11Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Pkcs11Error::Load(msg) => write!(f, "{msg}"),
            Pkcs11Error::MissingFunction(name) => {
                write!(f, "module does not export {name} (null function-list entry)")
            }
            Pkcs11Error::Ck { op, rv } => write!(f, "{op}: CK_RV 0x{rv:08x}"),
            Pkcs11Error::Protocol(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for Pkcs11Error {}

/// Upper bound on a `C_Sign`-reported signature length before we allocate a
/// buffer for it (audit LOW, ledger `8af4c26be9bccb3e`). This module only ever
/// signs with `CKM_EDDSA` (Ed25519 → 64 bytes); 256 is a generous ceiling that
/// still covers any Edwards variant while refusing an outsized allocation a
/// faulty/hostile module could request via the two-call length idiom.
const MAX_SIGNATURE_LEN: usize = 256;

/// Upper bound on a `CKA_EC_POINT` attribute length before allocation (same
/// ledger id). A DER-wrapped Edwards/EC point is tens of bytes (Ed25519 ≈ 34);
/// 4 KiB is far above any real curve while bounding the module-returned length.
const MAX_EC_POINT_LEN: usize = 4096;

/// Map a raw `CK_RV` to `Ok(())` on `CKR_OK`, else a contextual [`Pkcs11Error`].
fn check(rv: CK_RV, op: &str) -> Result<(), Pkcs11Error> {
    if rv == CKR_OK {
        Ok(())
    } else {
        Err(Pkcs11Error::Ck {
            op: op.to_string(),
            rv,
        })
    }
}

/// Pull a `Some` function pointer out of the function list or fail closed. The
/// function-list members are `Option<unsafe extern "C" fn(...)>`; a `None` means
/// the module did not provide that entry, so calling it would be a null deref.
macro_rules! func {
    ($list:expr, $field:ident) => {
        (*$list).$field.ok_or_else(|| {
            Pkcs11Error::MissingFunction(stringify!($field).to_string())
        })?
    };
}

/// A loaded + initialized PKCS#11 module. Owns the `libloading` library (kept
/// alive for the lifetime of every call through the function list) and the
/// `CK_FUNCTION_LIST` pointer the module handed back. Calls `C_Finalize` on drop.
pub struct Pkcs11Context {
    /// The raw libloading loader. Held ONLY to keep the dynamic library mapped;
    /// all PKCS#11 calls go through `function_list`, never through this loader's
    /// per-symbol entries (those are not reliably exported by every module).
    _loader: RawLoader,
    /// The module's function list — the dispatch table for every `C_*` call.
    function_list: CK_FUNCTION_LIST_PTR,
}

impl Pkcs11Context {
    /// Load the module at `module_path`, call `C_GetFunctionList`, then
    /// `C_Initialize` with `CKF_OS_LOCKING_OK` (let the module use OS locking for
    /// thread safety). Fails closed on any load / null-list / `CK_RV` error.
    pub fn load_and_initialize(module_path: &str) -> Result<Self, Pkcs11Error> {
        // SAFETY: `RawLoader::new` is unsafe purely because it `dlopen`s an
        // arbitrary shared object and calls its initializers; `module_path` is an
        // operator-supplied trusted module path. No Rust invariants are at stake
        // in the call itself.
        let loader = unsafe { RawLoader::new(module_path) }.map_err(|e| {
            Pkcs11Error::Load(format!("load module '{module_path}': {e}"))
        })?;

        let mut function_list: CK_FUNCTION_LIST_PTR = ptr::null_mut();
        // SAFETY: `C_GetFunctionList` is the one symbol PKCS#11 modules must
        // export; we pass a valid `*mut CK_FUNCTION_LIST_PTR` for it to fill. The
        // loader's `C_GetFunctionList` entry is checked for load error first.
        let get_list = loader.C_GetFunctionList.as_ref().map_err(|e| {
            Pkcs11Error::Load(format!(
                "module '{module_path}' does not export C_GetFunctionList: {e}"
            ))
        })?;
        // SAFETY: single FFI call; `&mut function_list` is a valid out-pointer.
        let rv = unsafe { get_list(&mut function_list) };
        check(rv, "C_GetFunctionList")?;
        if function_list.is_null() {
            return Err(Pkcs11Error::Load(format!(
                "module '{module_path}' returned a null CK_FUNCTION_LIST"
            )));
        }

        // C_Initialize with OS locking so the module may be used from multiple
        // threads (CKF_OS_LOCKING_OK == OsThreads in the high-level crate).
        // SAFETY: CK_C_INITIALIZE_ARGS is a plain C struct of nullable function
        // pointers + a flags word + a reserved pointer; an all-zero bit pattern is
        // its valid "no custom mutexes, no reserved" form, which is exactly what
        // we want before setting `flags`.
        let mut args: CK_C_INITIALIZE_ARGS = unsafe { std::mem::zeroed() };
        args.flags = CKF_OS_LOCKING_OK;
        // SAFETY: `function_list` is non-null (checked); `C_Initialize` is pulled
        // from it and checked non-null by `func!`. `&mut args` outlives the call.
        unsafe {
            let init = func!(function_list, C_Initialize);
            let rv = init(&mut args as *mut CK_C_INITIALIZE_ARGS as *mut c_void);
            check(rv, "C_Initialize")?;
        }

        Ok(Pkcs11Context {
            _loader: loader,
            function_list,
        })
    }

    /// Enumerate token slots and return `(slot_id, trimmed_label)` for each slot
    /// that has a token present, using the two-call length idiom for
    /// `C_GetSlotList` and reading each token's 32-byte label via
    /// `C_GetTokenInfo` (trailing 0x20 padding trimmed).
    pub fn token_slots(&self) -> Result<Vec<(CK_SLOT_ID, String)>, Pkcs11Error> {
        // First call (null buffer) learns the count; second fills it.
        let mut count: CK_ULONG = 0;
        // SAFETY: function-list pointer non-null; `C_GetSlotList` checked non-null
        // by `func!`. token_present=1, null slot buffer, `&mut count` out-param.
        unsafe {
            let get_slots = func!(self.function_list, C_GetSlotList);
            let rv = get_slots(1, ptr::null_mut(), &mut count);
            check(rv, "C_GetSlotList (count)")?;
        }
        let mut slots: Vec<CK_SLOT_ID> = vec![0; count as usize];
        // SAFETY: `slots` has capacity `count`; we pass its base pointer and the
        // SAME count we sized it to, and `C_GetSlotList` writes at most `count`.
        unsafe {
            let get_slots = func!(self.function_list, C_GetSlotList);
            let rv = get_slots(1, slots.as_mut_ptr(), &mut count);
            check(rv, "C_GetSlotList (fill)")?;
        }
        // The module may report fewer than the first count; honour the second.
        slots.truncate(count as usize);

        let mut out = Vec::with_capacity(slots.len());
        for slot in slots {
            // SAFETY: CK_TOKEN_INFO is a plain C struct of fixed byte arrays and
            // integer words; an all-zero bit pattern is a valid (empty) value to
            // hand to C_GetTokenInfo, which overwrites it.
            let mut info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
            // SAFETY: function-list pointer non-null; `C_GetTokenInfo` checked
            // non-null by `func!`; `&mut info` is a valid CK_TOKEN_INFO out-param.
            unsafe {
                let get_info = func!(self.function_list, C_GetTokenInfo);
                let rv = get_info(slot, &mut info);
                check(rv, "C_GetTokenInfo")?;
            }
            out.push((slot, trim_ck_label(&info.label)));
        }
        Ok(out)
    }

    /// Open a serial RW session on `slot`. The returned [`Session`] closes itself
    /// on drop (`C_CloseSession`).
    pub fn open_rw_session(&self, slot: CK_SLOT_ID) -> Result<Session<'_>, Pkcs11Error> {
        let mut handle: CK_SESSION_HANDLE = 0;
        // SAFETY: function-list non-null; `C_OpenSession` checked non-null by
        // `func!`. PKCS#11 requires CKF_SERIAL_SESSION; we add CKF_RW_SESSION for
        // login + signing. No app pointer / notify callback; `&mut handle` filled.
        unsafe {
            let open = func!(self.function_list, C_OpenSession);
            let rv = open(
                slot,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                ptr::null_mut(),
                None,
                &mut handle,
            );
            check(rv, "C_OpenSession")?;
        }
        Ok(Session {
            function_list: self.function_list,
            handle,
            _marker: std::marker::PhantomData,
        })
    }

    /// Open an RW session on `slot` and log in as the User with `pin`, returning
    /// the raw `CK_SESSION_HANDLE` WITHOUT closing it — the caller becomes
    /// responsible for that handle's lifetime (close it with
    /// [`Self::close_session`]; [`Pkcs11Context`]'s `C_Finalize` on drop is the
    /// backstop). This is the ONE login that the keysource's session amortization
    /// (audit M16) eliminates per-operation: the handle is cached and reused.
    ///
    /// Implemented by opening a normal RAII [`Session`], logging in, then
    /// [`Session::into_handle`]-ing it so the `Drop` close is suppressed.
    pub fn open_logged_in_handle(
        &self,
        slot: CK_SLOT_ID,
        pin: &str,
    ) -> Result<CK_SESSION_HANDLE, Pkcs11Error> {
        let session = self.open_rw_session(slot)?;
        session.login_user(pin)?;
        Ok(session.into_handle())
    }

    /// Borrow a NON-owning view over an already-open session `handle` (typically
    /// one from [`Self::open_logged_in_handle`]). [`SessionRef`] exposes the same
    /// `find_objects` / `sign_eddsa` / `get_ec_point` operations as [`Session`] but
    /// does NOT close the handle on drop — the caller owns the handle's lifetime.
    /// The returned view borrows `self`, so it cannot outlive the loaded module.
    pub fn with_handle(&self, handle: CK_SESSION_HANDLE) -> SessionRef<'_> {
        SessionRef {
            function_list: self.function_list,
            handle,
            _marker: std::marker::PhantomData,
        }
    }

    /// Explicitly close a session `handle` previously obtained from
    /// [`Self::open_logged_in_handle`]. Used to retire a cached session that was
    /// replaced (invalidated). Fails closed on a non-`CKR_OK` status; a missing
    /// `C_CloseSession` entry is a [`Pkcs11Error::MissingFunction`] (never a null
    /// call). `C_Finalize` on context drop is the backstop if this is skipped.
    pub fn close_session(&self, handle: CK_SESSION_HANDLE) -> Result<(), Pkcs11Error> {
        self.session_closer().close(handle)
    }

    /// A small, `Copy`, lifetime-free closer for this context's sessions. It
    /// carries only the function-list pointer, so a caller can store it next to a
    /// cached raw `CK_SESSION_HANDLE` and close that handle on retirement WITHOUT a
    /// borrow of the context — the keysource uses this to make its handle cache an
    /// RAII type while sidestepping the self-referential `Session<'ctx>` lifetime.
    ///
    /// Soundness contract: a [`SessionCloser`] must NOT be used after its parent
    /// [`Pkcs11Context`] has been dropped (the function list is finalized then). The
    /// keysource enforces this by FIELD ORDER — it declares its cached session
    /// before its `Pkcs11Context`, so the session's closer runs `C_CloseSession`
    /// strictly before the context's `C_Finalize`. Using a closer after its context
    /// is finalized is undefined behaviour (use-after-finalize).
    pub fn session_closer(&self) -> SessionCloser {
        SessionCloser {
            function_list: self.function_list,
        }
    }
}

/// A `Copy`, lifetime-free handle to a context's `C_CloseSession`. See
/// [`Pkcs11Context::session_closer`] for the soundness contract.
#[derive(Clone, Copy)]
pub struct SessionCloser {
    function_list: CK_FUNCTION_LIST_PTR,
}

impl SessionCloser {
    /// Close `handle`. Fails closed on a non-`CKR_OK` status or a missing
    /// `C_CloseSession` entry (never a null call).
    pub fn close(&self, handle: CK_SESSION_HANDLE) -> Result<(), Pkcs11Error> {
        if self.function_list.is_null() {
            return Err(Pkcs11Error::Load(
                "session closer has a null function list".to_string(),
            ));
        }
        // SAFETY: function-list non-null (checked); `C_CloseSession` checked
        // non-null by `func!`. It takes only the session handle. The caller's
        // contract guarantees the parent context is still alive (function list not
        // yet finalized).
        unsafe {
            let close = func!(self.function_list, C_CloseSession);
            check(close(handle), "C_CloseSession")
        }
    }
}

impl Drop for Pkcs11Context {
    fn drop(&mut self) {
        if self.function_list.is_null() {
            return;
        }
        // SAFETY: `function_list` non-null (checked); if `C_Finalize` is present
        // we call it once with the spec-mandated null reserved arg. A finalize
        // error on teardown has nowhere meaningful to go, so it is ignored — but
        // we never call a null pointer.
        unsafe {
            if let Some(finalize) = (*self.function_list).C_Finalize {
                let _ = finalize(ptr::null_mut());
            }
        }
    }
}

/// An open PKCS#11 session bound to a context's function list. Closes itself on
/// drop. Borrows the context so it cannot outlive the loaded module.
pub struct Session<'ctx> {
    function_list: CK_FUNCTION_LIST_PTR,
    handle: CK_SESSION_HANDLE,
    #[allow(dead_code)]
    _marker: std::marker::PhantomData<&'ctx Pkcs11Context>,
}

impl<'ctx> Session<'ctx> {
    /// Log in as the User with `pin`. The PIN bytes are passed straight to
    /// `C_Login` and are NOT copied or retained by this wrapper.
    pub fn login_user(&self, pin: &str) -> Result<(), Pkcs11Error> {
        let pin_bytes = pin.as_bytes();
        // SAFETY: function-list non-null; `C_Login` checked non-null by `func!`.
        // PKCS#11 takes the PIN as a (ptr,len) pair; we pass the borrowed bytes
        // and their exact length. `C_Login` does not retain the pointer past the
        // call. The cast to *mut is required by the C signature but the module
        // treats the buffer as read-only.
        unsafe {
            let login = func!(self.function_list, C_Login);
            let rv = login(
                self.handle,
                CKU_USER,
                pin_bytes.as_ptr() as *mut u8,
                pin_bytes.len() as CK_ULONG,
            );
            check(rv, "C_Login (CKU_USER)")
        }
    }

    /// Find all object handles matching `template`. See [`find_objects_raw`].
    pub fn find_objects(
        &self,
        template: &AttributeTemplate,
    ) -> Result<Vec<CK_OBJECT_HANDLE>, Pkcs11Error> {
        find_objects_raw(self.function_list, self.handle, template)
    }

    /// Sign `data` under `key` with `CKM_EDDSA`. See [`sign_eddsa_raw`].
    pub fn sign_eddsa(
        &self,
        key: CK_OBJECT_HANDLE,
        data: &[u8],
    ) -> Result<Vec<u8>, Pkcs11Error> {
        sign_eddsa_raw(self.function_list, self.handle, key, data)
    }

    /// Read the raw `CKA_EC_POINT` attribute of `key`. See [`get_ec_point_raw`].
    pub fn get_ec_point(&self, key: CK_OBJECT_HANDLE) -> Result<Vec<u8>, Pkcs11Error> {
        get_ec_point_raw(self.function_list, self.handle, key)
    }

    /// Consume this session WITHOUT closing it, returning its raw
    /// `CK_SESSION_HANDLE`. The caller becomes responsible for the handle's
    /// lifetime (close it via [`Pkcs11Context::close_session`]; `C_Finalize` on
    /// context drop is the backstop). Used by
    /// [`Pkcs11Context::open_logged_in_handle`] to hand out a cacheable handle.
    pub fn into_handle(self) -> CK_SESSION_HANDLE {
        let handle = self.handle;
        // SAFETY: forgetting suppresses this `Session`'s `Drop` (the
        // `C_CloseSession`), transferring ownership of `handle` to the caller. The
        // `Session` holds only `Copy` fields + a `PhantomData`, so there is no
        // owned resource leaked OTHER than the (now caller-owned) session handle;
        // the `_loader` library and function list live in `Pkcs11Context`, not here.
        std::mem::forget(self);
        handle
    }
}

/// A NON-owning view over an already-open session handle. Exposes the SAME token
/// operations as [`Session`] but does NOT close the handle on drop — the handle's
/// lifetime is owned elsewhere (the keysource's amortized session cache). Obtained
/// via [`Pkcs11Context::with_handle`]; borrows the context so it cannot outlive the
/// loaded module.
pub struct SessionRef<'ctx> {
    function_list: CK_FUNCTION_LIST_PTR,
    handle: CK_SESSION_HANDLE,
    #[allow(dead_code)]
    _marker: std::marker::PhantomData<&'ctx Pkcs11Context>,
}

impl<'ctx> SessionRef<'ctx> {
    /// Find all object handles matching `template`. See [`find_objects_raw`].
    pub fn find_objects(
        &self,
        template: &AttributeTemplate,
    ) -> Result<Vec<CK_OBJECT_HANDLE>, Pkcs11Error> {
        find_objects_raw(self.function_list, self.handle, template)
    }

    /// Sign `data` under `key` with `CKM_EDDSA`. See [`sign_eddsa_raw`].
    pub fn sign_eddsa(
        &self,
        key: CK_OBJECT_HANDLE,
        data: &[u8],
    ) -> Result<Vec<u8>, Pkcs11Error> {
        sign_eddsa_raw(self.function_list, self.handle, key, data)
    }

    /// Read the raw `CKA_EC_POINT` attribute of `key`. See [`get_ec_point_raw`].
    pub fn get_ec_point(&self, key: CK_OBJECT_HANDLE) -> Result<Vec<u8>, Pkcs11Error> {
        get_ec_point_raw(self.function_list, self.handle, key)
    }
}

/// Find all object handles matching `template` against the open session `handle`
/// (init / iterate / final). Drives the standard `C_FindObjectsInit` →
/// `C_FindObjects` (paged) → `C_FindObjectsFinal` sequence and always finalizes,
/// even on an iterate error. Shared by [`Session`] and [`SessionRef`].
fn find_objects_raw(
    function_list: CK_FUNCTION_LIST_PTR,
    handle: CK_SESSION_HANDLE,
    template: &AttributeTemplate,
) -> Result<Vec<CK_OBJECT_HANDLE>, Pkcs11Error> {
    let attrs = template.as_ck_attributes();
    // SAFETY: function-list non-null; `C_FindObjectsInit` checked non-null by
    // `func!`. `attrs` is a live slice of CK_ATTRIBUTE for the duration of the
    // call; we pass its base pointer and exact length.
    unsafe {
        let init = func!(function_list, C_FindObjectsInit);
        let rv = init(
            handle,
            attrs.as_ptr() as *mut CK_ATTRIBUTE,
            attrs.len() as CK_ULONG,
        );
        check(rv, "C_FindObjectsInit")?;
    }

    let result = find_objects_collect(function_list, handle);

    // Always finalize the find operation, regardless of the iterate result.
    // SAFETY: function-list non-null; `C_FindObjectsFinal` checked non-null by
    // `func!`. Finalize takes only the session handle.
    let final_rv = unsafe {
        match (*function_list).C_FindObjectsFinal {
            Some(finalize) => finalize(handle),
            None => {
                return Err(Pkcs11Error::MissingFunction(
                    "C_FindObjectsFinal".to_string(),
                ))
            }
        }
    };
    let handles = result?;
    check(final_rv, "C_FindObjectsFinal")?;
    Ok(handles)
}

/// Iterate `C_FindObjects` in pages until it reports zero new handles.
/// (Helper for [`find_objects_raw`]; the caller finalizes.)
fn find_objects_collect(
    function_list: CK_FUNCTION_LIST_PTR,
    handle: CK_SESSION_HANDLE,
) -> Result<Vec<CK_OBJECT_HANDLE>, Pkcs11Error> {
    const PAGE: usize = 16;
    let mut handles: Vec<CK_OBJECT_HANDLE> = Vec::new();
    loop {
        let mut page: [CK_OBJECT_HANDLE; PAGE] = [0; PAGE];
        let mut found: CK_ULONG = 0;
        // SAFETY: function-list non-null; `C_FindObjects` checked non-null by
        // `func!`. `page` is a fixed PAGE-element buffer; we pass its pointer,
        // PAGE as the max, and `&mut found` for the count actually written.
        unsafe {
            let find = func!(function_list, C_FindObjects);
            let rv = find(handle, page.as_mut_ptr(), PAGE as CK_ULONG, &mut found);
            check(rv, "C_FindObjects")?;
        }
        let found = found as usize;
        if found > PAGE {
            return Err(Pkcs11Error::Protocol(format!(
                "C_FindObjects reported {found} handles into a {PAGE}-slot page"
            )));
        }
        if found == 0 {
            break;
        }
        handles.extend_from_slice(&page[..found]);
        if found < PAGE {
            break;
        }
    }
    Ok(handles)
}

/// Sign `data` under `key` with `CKM_EDDSA` (no pre-hash) against the open session
/// `handle`, returning the raw signature bytes via the two-call length idiom for
/// `C_Sign`. Shared by [`Session`] and [`SessionRef`].
fn sign_eddsa_raw(
    function_list: CK_FUNCTION_LIST_PTR,
    handle: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
    data: &[u8],
) -> Result<Vec<u8>, Pkcs11Error> {
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_EDDSA,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    // SAFETY: function-list non-null; `C_SignInit` checked non-null by `func!`.
    // `&mut mechanism` is a valid CK_MECHANISM for the call; `key` is a handle.
    unsafe {
        let sign_init = func!(function_list, C_SignInit);
        let rv = sign_init(handle, &mut mechanism, key);
        check(rv, "C_SignInit (CKM_EDDSA)")?;
    }

    // First C_Sign (null signature buffer) learns the signature length.
    let mut sig_len: CK_ULONG = 0;
    // SAFETY: function-list non-null; `C_Sign` checked non-null by `func!`.
    // data ptr+len describe the borrowed preimage; null out-buffer + `&mut
    // sig_len` requests the length only (standard PKCS#11 length query).
    unsafe {
        let sign = func!(function_list, C_Sign);
        let rv = sign(
            handle,
            data.as_ptr() as *mut u8,
            data.len() as CK_ULONG,
            ptr::null_mut(),
            &mut sig_len,
        );
        check(rv, "C_Sign (length query)")?;
    }

    // Bound the module-returned length before allocating: a faulty/hostile module
    // must not be able to trigger an outsized allocation on this trusted boundary.
    if sig_len as usize > MAX_SIGNATURE_LEN {
        return Err(Pkcs11Error::Protocol(format!(
            "C_Sign reported an implausible signature length {sig_len} (> {MAX_SIGNATURE_LEN}); \
             refusing to allocate"
        )));
    }
    let mut signature: Vec<u8> = vec![0u8; sig_len as usize];
    // SAFETY: `signature` has capacity `sig_len`; we pass its pointer and the
    // SAME `sig_len`, which `C_Sign` may shrink (it writes the final length
    // back). data ptr+len unchanged from the query call.
    unsafe {
        let sign = func!(function_list, C_Sign);
        let rv = sign(
            handle,
            data.as_ptr() as *mut u8,
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut sig_len,
        );
        check(rv, "C_Sign")?;
    }
    let written = sig_len as usize;
    if written > signature.len() {
        return Err(Pkcs11Error::Protocol(format!(
            "C_Sign reported {written} bytes into a {}-byte buffer",
            signature.len()
        )));
    }
    signature.truncate(written);
    Ok(signature)
}

/// Read the raw `CKA_EC_POINT` attribute of `key` against the open session
/// `handle` via the two-call length idiom for `C_GetAttributeValue` (query length,
/// allocate, fill). Shared by [`Session`] and [`SessionRef`].
fn get_ec_point_raw(
    function_list: CK_FUNCTION_LIST_PTR,
    handle: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
) -> Result<Vec<u8>, Pkcs11Error> {
    // First call: null pValue, learn ulValueLen.
    let mut probe = CK_ATTRIBUTE {
        type_: CKA_EC_POINT,
        pValue: ptr::null_mut(),
        ulValueLen: 0,
    };
    // SAFETY: function-list non-null; `C_GetAttributeValue` checked non-null by
    // `func!`. One-element attribute array; null pValue requests the length.
    unsafe {
        let get_attr = func!(function_list, C_GetAttributeValue);
        let rv = get_attr(handle, key, &mut probe, 1);
        check(rv, "C_GetAttributeValue (CKA_EC_POINT length)")?;
    }
    // ulValueLen == CK_UNAVAILABLE_INFORMATION (all-ones) signals the attribute
    // is absent / unreadable; an enormous length cannot be a 32-ish-byte point.
    let len = probe.ulValueLen;
    if len == CK_ULONG::MAX {
        return Err(Pkcs11Error::Protocol(
            "CKA_EC_POINT is unavailable on this object".to_string(),
        ));
    }
    // Bound the module-returned length before allocating (see MAX_EC_POINT_LEN):
    // a real point is tens of bytes, so a multi-KiB+ length is a faulty/hostile
    // module and must not drive an outsized allocation.
    if len as usize > MAX_EC_POINT_LEN {
        return Err(Pkcs11Error::Protocol(format!(
            "CKA_EC_POINT reported an implausible length {len} (> {MAX_EC_POINT_LEN}); \
             refusing to allocate"
        )));
    }

    let mut value: Vec<u8> = vec![0u8; len as usize];
    let mut fill = CK_ATTRIBUTE {
        type_: CKA_EC_POINT,
        pValue: value.as_mut_ptr() as *mut c_void,
        ulValueLen: len,
    };
    // SAFETY: `value` has capacity `len`; `fill.pValue` points at it with the
    // matching `ulValueLen`. `C_GetAttributeValue` writes at most `len` bytes
    // and sets the actual length back into `fill.ulValueLen`.
    unsafe {
        let get_attr = func!(function_list, C_GetAttributeValue);
        let rv = get_attr(handle, key, &mut fill, 1);
        check(rv, "C_GetAttributeValue (CKA_EC_POINT)")?;
    }
    let written = fill.ulValueLen as usize;
    if written > value.len() {
        return Err(Pkcs11Error::Protocol(format!(
            "CKA_EC_POINT reported {written} bytes into a {}-byte buffer",
            value.len()
        )));
    }
    value.truncate(written);
    Ok(value)
}

impl<'ctx> Drop for Session<'ctx> {
    fn drop(&mut self) {
        if self.function_list.is_null() {
            return;
        }
        // SAFETY: `function_list` non-null (checked); if `C_CloseSession` is
        // present we call it once with this session's handle. A close error on
        // teardown has nowhere to go, so it is ignored — but we never call null.
        unsafe {
            if let Some(close) = (*self.function_list).C_CloseSession {
                let _ = close(self.handle);
            }
        }
    }
}

/// Object class selector for [`AttributeTemplate`], mirroring the two PKCS#11
/// object classes this wrapper needs.
#[derive(Clone, Copy)]
pub enum ObjectClass {
    /// `CKO_PRIVATE_KEY`.
    Private,
    /// `CKO_PUBLIC_KEY`.
    Public,
}

impl ObjectClass {
    fn ck_value(self) -> CK_OBJECT_CLASS {
        match self {
            ObjectClass::Private => CKO_PRIVATE_KEY,
            ObjectClass::Public => CKO_PUBLIC_KEY,
        }
    }
}

/// An OWNED Ed25519 object-lookup template: `CKA_CLASS` + `CKA_KEY_TYPE`
/// (`CKK_EC_EDWARDS`) + `CKA_LABEL`. It owns the backing scalar/byte storage so
/// the `CK_ATTRIBUTE` array it lends out via [`as_ck_attributes`] points at
/// memory that lives at least as long as `self` — the borrow checker enforces the
/// `C_FindObjectsInit` call cannot outlive this template.
pub struct AttributeTemplate {
    class: CK_OBJECT_CLASS,
    key_type: CK_KEY_TYPE,
    label: Vec<u8>,
}

impl AttributeTemplate {
    /// Build the Ed25519 lookup template for `class` objects labelled `label`.
    pub fn ed25519_labelled(class: ObjectClass, label: &str) -> Self {
        AttributeTemplate {
            class: class.ck_value(),
            key_type: CKK_EC_EDWARDS,
            label: label.as_bytes().to_vec(),
        }
    }

    /// Borrow the three attributes as a `CK_ATTRIBUTE` array. Each entry points
    /// into `self`'s owned fields, so the returned `Vec` must not outlive `self`
    /// (it borrows `&self`, so it cannot).
    fn as_ck_attributes(&self) -> Vec<CK_ATTRIBUTE> {
        vec![
            ck_attr(CKA_CLASS, &self.class),
            ck_attr(CKA_KEY_TYPE, &self.key_type),
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: self.label.as_ptr() as *mut c_void,
                ulValueLen: self.label.len() as CK_ULONG,
            },
        ]
    }
}

/// Build a `CK_ATTRIBUTE` whose value is a single borrowed scalar (`CK_ULONG`-
/// width: object class or key type). The pointer borrows `value`, so the caller
/// must keep `value` alive for as long as the attribute is used.
fn ck_attr<T>(type_: CK_ATTRIBUTE_TYPE, value: &T) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_,
        pValue: value as *const T as *mut c_void,
        ulValueLen: std::mem::size_of::<T>() as CK_ULONG,
    }
}

/// Trim the trailing 0x20 (space) padding PKCS#11 uses for the fixed 32-byte
/// `CK_TOKEN_INFO.label`, returning it as a `String` (lossy on non-UTF-8, which a
/// label should never be). A non-space NUL is also trimmed defensively.
fn trim_ck_label(label: &[u8; CK_TOKEN_LABEL_LEN]) -> String {
    let end = label
        .iter()
        .rposition(|&b| b != b' ' && b != 0)
        .map(|i| i + 1)
        .unwrap_or(0);
    String::from_utf8_lossy(&label[..end]).into_owned()
}
