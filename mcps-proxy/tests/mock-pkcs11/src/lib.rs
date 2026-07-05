//! A hermetic MOCK PKCS#11 (Cryptoki) provider for the `mcps-proxy` PKCS#11
//! response-signing / delegated-TLS e2e test.
//!
//! This `cdylib` exports `C_GetFunctionList` and implements EXACTLY the Cryptoki
//! surface that `mcps-proxy`'s PKCS#11 client (`pkcs11_native.rs`) calls — nothing
//! more:
//!   `C_Initialize` / `C_Finalize`, `C_GetSlotList` / `C_GetTokenInfo`,
//!   `C_OpenSession` / `C_CloseSession`, `C_Login`,
//!   `C_FindObjectsInit` / `C_FindObjects` / `C_FindObjectsFinal`,
//!   `C_SignInit` / `C_Sign` (`CKM_EDDSA`), `C_GetAttributeValue` (`CKA_EC_POINT`).
//! Every other function-list slot is left NULL, so if the client ever reached for
//! one the client's own `func!` guard would surface a `MissingFunction` error.
//!
//! It is a TEST DOUBLE, not a key store: keys live only in this process's memory
//! for the duration of the test, seeded DETERMINISTICALLY from `SHA-256(label ||
//! id)` so a public point read off a mock object always matches the signature the
//! mock produces for it — across `C_Finalize` → `C_Initialize` cycles. The object
//! set and token label are supplied by the test via two environment variables read
//! at `C_Initialize`:
//!   * `MOCK_PKCS11_TOKEN_LABEL` — the label reported by `C_GetTokenInfo`.
//!   * `MOCK_PKCS11_OBJECTS`     — `;`-separated `label,keytype,id` entries, where
//!     `keytype` is `ed25519` (a signable `CKK_EC_EDWARDS` key pair) or `ec` (a
//!     `CKK_EC` object used only to prove a non-Ed25519 TLS key is rejected).
//! Each entry materialises BOTH a `CKO_PRIVATE_KEY` and a `CKO_PUBLIC_KEY` object
//! sharing that label/id, mirroring how a real token stores a generated key pair.

use std::collections::HashMap;
use std::os::raw::c_uchar;
use std::os::raw::c_ulong;
use std::os::raw::c_void;
use std::ptr;
use std::sync::Mutex;
use std::sync::OnceLock;

use cryptoki_sys::CKA_CLASS;
use cryptoki_sys::CKA_EC_POINT;
use cryptoki_sys::CKA_KEY_TYPE;
use cryptoki_sys::CKA_LABEL;
use cryptoki_sys::CKK_EC;
use cryptoki_sys::CKK_EC_EDWARDS;
use cryptoki_sys::CKM_EDDSA;
use cryptoki_sys::CKO_PRIVATE_KEY;
use cryptoki_sys::CKO_PUBLIC_KEY;
use cryptoki_sys::CKR_ARGUMENTS_BAD;
use cryptoki_sys::CKR_BUFFER_TOO_SMALL;
use cryptoki_sys::CKR_GENERAL_ERROR;
use cryptoki_sys::CKR_KEY_HANDLE_INVALID;
use cryptoki_sys::CKR_MECHANISM_INVALID;
use cryptoki_sys::CKR_OBJECT_HANDLE_INVALID;
use cryptoki_sys::CKR_OK;
use cryptoki_sys::CKR_SLOT_ID_INVALID;
use cryptoki_sys::CK_ATTRIBUTE_TYPE;
use cryptoki_sys::CK_KEY_TYPE;
use cryptoki_sys::CK_MECHANISM_TYPE;
use cryptoki_sys::CK_OBJECT_CLASS;
use cryptoki_sys::CK_OBJECT_HANDLE;
use cryptoki_sys::CK_RV;
use cryptoki_sys::CK_SESSION_HANDLE;
use cryptoki_sys::CK_SLOT_ID;
use cryptoki_sys::CK_ULONG;
use cryptoki_sys::CK_USER_TYPE;
use cryptoki_sys::CK_VERSION;
use cryptoki_sys::_CK_ATTRIBUTE;
use cryptoki_sys::_CK_FUNCTION_LIST;
use cryptoki_sys::_CK_MECHANISM;
use cryptoki_sys::_CK_TOKEN_INFO;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use sha2::Digest;
use sha2::Sha256;

/// The single slot id this mock exposes.
const SLOT_ID: CK_SLOT_ID = 0;

/// A key object resident on the mock token.
struct KeyObject {
    handle: CK_OBJECT_HANDLE,
    class: CK_OBJECT_CLASS,
    key_type: CK_KEY_TYPE,
    label: Vec<u8>,
    /// Present only for signable (`CKK_EC_EDWARDS`) objects.
    signing: Option<SigningKey>,
    /// The `CKA_EC_POINT` value returned for this object: a DER `OCTET STRING`
    /// wrapping the 32-byte Edwards point (`0x04 0x20 || point`), matching what a
    /// real token returns and what the client's `raw_ed25519_point` accepts.
    ec_point: Vec<u8>,
}

/// In-progress `C_FindObjects` iteration state for a session.
struct FindState {
    matches: Vec<CK_OBJECT_HANDLE>,
    pos: usize,
}

/// An open session.
struct Session {
    find: Option<FindState>,
    sign_key: Option<CK_OBJECT_HANDLE>,
}

/// The whole mock token state, rebuilt from the environment on each `C_Initialize`.
struct State {
    token_label: String,
    objects: Vec<KeyObject>,
    sessions: HashMap<CK_SESSION_HANDLE, Session>,
    next_session: CK_SESSION_HANDLE,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

impl State {
    /// Build the token from `MOCK_PKCS11_TOKEN_LABEL` + `MOCK_PKCS11_OBJECTS`.
    fn from_env() -> State {
        let token_label =
            std::env::var("MOCK_PKCS11_TOKEN_LABEL").unwrap_or_else(|_| "mcps-test".to_string());
        let spec = std::env::var("MOCK_PKCS11_OBJECTS").unwrap_or_default();

        let mut objects: Vec<KeyObject> = Vec::new();
        let mut next_handle: CK_OBJECT_HANDLE = 1;
        for entry in spec.split(';').filter(|e| !e.trim().is_empty()) {
            let parts: Vec<&str> = entry.split(',').collect();
            assert!(
                parts.len() == 3,
                "MOCK_PKCS11_OBJECTS entry must be `label,keytype,id`, got {entry:?}"
            );
            let label = parts[0].as_bytes().to_vec();
            let keytype = parts[1];
            let id = parts[2];

            let (key_type, signing, point32) = match keytype {
                "ed25519" => {
                    let sk = derive_signing_key(parts[0], id);
                    let point = sk.verifying_key().to_bytes().to_vec();
                    (CKK_EC_EDWARDS, Some(sk), point)
                }
                // A non-Ed25519 object: it exists so the client's Ed25519-typed
                // find never matches it (proving a non-Ed25519 TLS key is rejected).
                // It is never signed with, so no key material is needed.
                "ec" => (CKK_EC, None, vec![0u8; 32]),
                other => panic!("MOCK_PKCS11_OBJECTS unknown keytype {other:?}"),
            };
            let ec_point = der_octet_string(&point32);

            // A generated key pair is TWO objects (private + public) sharing label/id.
            for class in [CKO_PRIVATE_KEY, CKO_PUBLIC_KEY] {
                objects.push(KeyObject {
                    handle: next_handle,
                    class,
                    key_type,
                    label: label.clone(),
                    // Only the private object needs to sign; the public one carries
                    // the point. Cloning the signer keeps both self-consistent.
                    signing: signing.clone(),
                    ec_point: ec_point.clone(),
                });
                next_handle += 1;
            }
        }

        State {
            token_label,
            objects,
            sessions: HashMap::new(),
            next_session: 1,
        }
    }

    fn object(&self, handle: CK_OBJECT_HANDLE) -> Option<&KeyObject> {
        self.objects.iter().find(|o| o.handle == handle)
    }
}

/// Deterministic Ed25519 key from `SHA-256(label || 0x00 || id)`. Distinct
/// (label, id) pairs yield distinct keys; the same pair is stable across re-inits.
fn derive_signing_key(label: &str, id: &str) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update([0u8]);
    hasher.update(id.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

/// Wrap a 32-byte Edwards point as the DER `OCTET STRING` a token returns for
/// `CKA_EC_POINT`: `0x04 <len> <point>`.
fn der_octet_string(point: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(point.len() + 2);
    out.push(0x04);
    out.push(point.len() as u8);
    out.extend_from_slice(point);
    out
}

// ===========================================================================
// Cryptoki entry point + function list
// ===========================================================================

/// Leaked, process-lifetime function list. `C_GetFunctionList` hands back its
/// address on every call.
fn function_list_ptr() -> *mut _CK_FUNCTION_LIST {
    static LIST: OnceLock<usize> = OnceLock::new();
    let addr = *LIST.get_or_init(|| {
        // SAFETY: `_CK_FUNCTION_LIST` is all `Option<fn>` (null == None) plus a
        // `CK_VERSION` (two bytes) — an all-zero bit pattern is a valid, fully-NULL
        // function list. We then fill in only the slots this mock implements.
        let mut list: _CK_FUNCTION_LIST = unsafe { std::mem::zeroed() };
        list.version = CK_VERSION { major: 2, minor: 40 };
        list.C_Initialize = Some(c_initialize);
        list.C_Finalize = Some(c_finalize);
        list.C_GetFunctionList = Some(c_get_function_list);
        list.C_GetSlotList = Some(c_get_slot_list);
        list.C_GetTokenInfo = Some(c_get_token_info);
        list.C_OpenSession = Some(c_open_session);
        list.C_CloseSession = Some(c_close_session);
        list.C_Login = Some(c_login);
        list.C_FindObjectsInit = Some(c_find_objects_init);
        list.C_FindObjects = Some(c_find_objects);
        list.C_FindObjectsFinal = Some(c_find_objects_final);
        list.C_SignInit = Some(c_sign_init);
        list.C_Sign = Some(c_sign);
        list.C_GetAttributeValue = Some(c_get_attribute_value);
        Box::into_raw(Box::new(list)) as usize
    });
    addr as *mut _CK_FUNCTION_LIST
}

/// The one symbol a PKCS#11 module MUST export. `#[no_mangle] extern "C"`.
///
/// # Safety
/// `pp_list` must be a valid, writable `*mut *mut CK_FUNCTION_LIST` (the loader's
/// out-parameter), per the Cryptoki ABI.
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(pp_list: *mut *mut _CK_FUNCTION_LIST) -> CK_RV {
    if pp_list.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    *pp_list = function_list_ptr();
    CKR_OK
}

/// Function-list slot variant of the above (same behaviour).
unsafe extern "C" fn c_get_function_list(pp_list: *mut *mut _CK_FUNCTION_LIST) -> CK_RV {
    C_GetFunctionList(pp_list)
}

unsafe extern "C" fn c_initialize(_args: *mut c_void) -> CK_RV {
    let mut guard = STATE.lock().expect("mock state lock");
    *guard = Some(State::from_env());
    CKR_OK
}

unsafe extern "C" fn c_finalize(_reserved: *mut c_void) -> CK_RV {
    let mut guard = STATE.lock().expect("mock state lock");
    *guard = None;
    CKR_OK
}

unsafe extern "C" fn c_get_slot_list(
    _token_present: c_uchar,
    slot_list: *mut CK_SLOT_ID,
    count: *mut c_ulong,
) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    // Length-query call: report we have one slot.
    if slot_list.is_null() {
        *count = 1;
        return CKR_OK;
    }
    if *count < 1 {
        *count = 1;
        return CKR_BUFFER_TOO_SMALL;
    }
    *slot_list = SLOT_ID;
    *count = 1;
    CKR_OK
}

unsafe extern "C" fn c_get_token_info(slot: CK_SLOT_ID, info: *mut _CK_TOKEN_INFO) -> CK_RV {
    if slot != SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let guard = STATE.lock().expect("mock state lock");
    let Some(state) = guard.as_ref() else {
        return CKR_GENERAL_ERROR;
    };
    // Zero the whole struct, then write the space-padded 32-byte label (the client
    // trims trailing spaces). Other fields are irrelevant to the client.
    ptr::write_bytes(info as *mut u8, 0, std::mem::size_of::<_CK_TOKEN_INFO>());
    let mut label = [b' '; 32];
    let bytes = state.token_label.as_bytes();
    let n = bytes.len().min(32);
    label[..n].copy_from_slice(&bytes[..n]);
    (*info).label = label;
    CKR_OK
}

unsafe extern "C" fn c_open_session(
    slot: CK_SLOT_ID,
    _flags: c_ulong,
    _application: *mut c_void,
    _notify: cryptoki_sys::CK_NOTIFY,
    session: *mut CK_SESSION_HANDLE,
) -> CK_RV {
    if slot != SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    if session.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut guard = STATE.lock().expect("mock state lock");
    let Some(state) = guard.as_mut() else {
        return CKR_GENERAL_ERROR;
    };
    let handle = state.next_session;
    state.next_session += 1;
    state.sessions.insert(
        handle,
        Session {
            find: None,
            sign_key: None,
        },
    );
    *session = handle;
    CKR_OK
}

unsafe extern "C" fn c_close_session(session: CK_SESSION_HANDLE) -> CK_RV {
    let mut guard = STATE.lock().expect("mock state lock");
    let Some(state) = guard.as_mut() else {
        return CKR_GENERAL_ERROR;
    };
    state.sessions.remove(&session);
    CKR_OK
}

unsafe extern "C" fn c_login(
    _session: CK_SESSION_HANDLE,
    _user_type: CK_USER_TYPE,
    _pin: *mut c_uchar,
    _pin_len: c_ulong,
) -> CK_RV {
    // The mock accepts any PIN; login is a no-op that always succeeds.
    CKR_OK
}

unsafe extern "C" fn c_find_objects_init(
    session: CK_SESSION_HANDLE,
    templ: *mut _CK_ATTRIBUTE,
    count: c_ulong,
) -> CK_RV {
    let mut guard = STATE.lock().expect("mock state lock");
    let Some(state) = guard.as_mut() else {
        return CKR_GENERAL_ERROR;
    };

    // Read the (class, key_type, label) selector out of the template.
    let attrs: &[_CK_ATTRIBUTE] = if templ.is_null() || count == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(templ, count as usize)
    };
    let mut want_class: Option<CK_OBJECT_CLASS> = None;
    let mut want_key_type: Option<CK_KEY_TYPE> = None;
    let mut want_label: Option<Vec<u8>> = None;
    for attr in attrs {
        match attr.type_ as CK_ATTRIBUTE_TYPE {
            t if t == CKA_CLASS => {
                if !attr.pValue.is_null() {
                    want_class = Some(*(attr.pValue as *const CK_OBJECT_CLASS));
                }
            }
            t if t == CKA_KEY_TYPE => {
                if !attr.pValue.is_null() {
                    want_key_type = Some(*(attr.pValue as *const CK_KEY_TYPE));
                }
            }
            t if t == CKA_LABEL => {
                if !attr.pValue.is_null() {
                    let bytes =
                        std::slice::from_raw_parts(attr.pValue as *const u8, attr.ulValueLen as usize);
                    want_label = Some(bytes.to_vec());
                }
            }
            _ => {}
        }
    }

    let matches: Vec<CK_OBJECT_HANDLE> = state
        .objects
        .iter()
        .filter(|o| want_class.map_or(true, |c| c == o.class))
        .filter(|o| want_key_type.map_or(true, |k| k == o.key_type))
        .filter(|o| want_label.as_ref().map_or(true, |l| l.as_slice() == o.label.as_slice()))
        .map(|o| o.handle)
        .collect();

    let Some(sess) = state.sessions.get_mut(&session) else {
        return CKR_GENERAL_ERROR;
    };
    sess.find = Some(FindState { matches, pos: 0 });
    CKR_OK
}

unsafe extern "C" fn c_find_objects(
    session: CK_SESSION_HANDLE,
    object: *mut CK_OBJECT_HANDLE,
    max_object_count: c_ulong,
    object_count: *mut c_ulong,
) -> CK_RV {
    if object.is_null() || object_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut guard = STATE.lock().expect("mock state lock");
    let Some(state) = guard.as_mut() else {
        return CKR_GENERAL_ERROR;
    };
    let Some(sess) = state.sessions.get_mut(&session) else {
        return CKR_GENERAL_ERROR;
    };
    let Some(find) = sess.find.as_mut() else {
        return CKR_GENERAL_ERROR;
    };
    let remaining = &find.matches[find.pos..];
    let n = remaining.len().min(max_object_count as usize);
    for (i, h) in remaining[..n].iter().enumerate() {
        *object.add(i) = *h;
    }
    find.pos += n;
    *object_count = n as c_ulong;
    CKR_OK
}

unsafe extern "C" fn c_find_objects_final(session: CK_SESSION_HANDLE) -> CK_RV {
    let mut guard = STATE.lock().expect("mock state lock");
    let Some(state) = guard.as_mut() else {
        return CKR_GENERAL_ERROR;
    };
    if let Some(sess) = state.sessions.get_mut(&session) {
        sess.find = None;
    }
    CKR_OK
}

unsafe extern "C" fn c_sign_init(
    session: CK_SESSION_HANDLE,
    mechanism: *mut _CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    if mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if (*mechanism).mechanism as CK_MECHANISM_TYPE != CKM_EDDSA {
        return CKR_MECHANISM_INVALID;
    }
    let mut guard = STATE.lock().expect("mock state lock");
    let Some(state) = guard.as_mut() else {
        return CKR_GENERAL_ERROR;
    };
    // The key must exist and be signable.
    match state.object(key) {
        Some(o) if o.signing.is_some() => {}
        Some(_) => return CKR_KEY_HANDLE_INVALID,
        None => return CKR_KEY_HANDLE_INVALID,
    }
    let Some(sess) = state.sessions.get_mut(&session) else {
        return CKR_GENERAL_ERROR;
    };
    sess.sign_key = Some(key);
    CKR_OK
}

unsafe extern "C" fn c_sign(
    session: CK_SESSION_HANDLE,
    data: *mut c_uchar,
    data_len: c_ulong,
    signature: *mut c_uchar,
    signature_len: *mut c_ulong,
) -> CK_RV {
    if signature_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let guard = STATE.lock().expect("mock state lock");
    let Some(state) = guard.as_ref() else {
        return CKR_GENERAL_ERROR;
    };
    let Some(sess) = state.sessions.get(&session) else {
        return CKR_GENERAL_ERROR;
    };
    let Some(key) = sess.sign_key else {
        return CKR_GENERAL_ERROR;
    };
    let Some(obj) = state.object(key) else {
        return CKR_KEY_HANDLE_INVALID;
    };
    let Some(sk) = obj.signing.as_ref() else {
        return CKR_KEY_HANDLE_INVALID;
    };

    let msg: &[u8] = if data.is_null() || data_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(data, data_len as usize)
    };
    let sig = sk.sign(msg).to_bytes(); // 64-byte pure Ed25519 signature

    // Length-query call: report the signature length only.
    if signature.is_null() {
        *signature_len = sig.len() as c_ulong;
        return CKR_OK;
    }
    if (*signature_len as usize) < sig.len() {
        *signature_len = sig.len() as c_ulong;
        return CKR_BUFFER_TOO_SMALL;
    }
    ptr::copy_nonoverlapping(sig.as_ptr(), signature, sig.len());
    *signature_len = sig.len() as c_ulong;
    CKR_OK
}

unsafe extern "C" fn c_get_attribute_value(
    _session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    templ: *mut _CK_ATTRIBUTE,
    count: c_ulong,
) -> CK_RV {
    if templ.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let guard = STATE.lock().expect("mock state lock");
    let Some(state) = guard.as_ref() else {
        return CKR_GENERAL_ERROR;
    };
    let Some(obj) = state.object(object) else {
        return CKR_OBJECT_HANDLE_INVALID;
    };
    let attrs: &mut [_CK_ATTRIBUTE] = std::slice::from_raw_parts_mut(templ, count as usize);
    for attr in attrs {
        // The client only ever asks for CKA_EC_POINT; anything else is unsupported.
        if attr.type_ as CK_ATTRIBUTE_TYPE != CKA_EC_POINT {
            attr.ulValueLen = CK_ULONG::MAX; // CK_UNAVAILABLE_INFORMATION
            continue;
        }
        let value = &obj.ec_point;
        // Length-query call: report the length only.
        if attr.pValue.is_null() {
            attr.ulValueLen = value.len() as CK_ULONG;
            continue;
        }
        if (attr.ulValueLen as usize) < value.len() {
            attr.ulValueLen = CK_ULONG::MAX;
            return CKR_BUFFER_TOO_SMALL;
        }
        ptr::copy_nonoverlapping(value.as_ptr(), attr.pValue as *mut u8, value.len());
        attr.ulValueLen = value.len() as CK_ULONG;
    }
    CKR_OK
}
