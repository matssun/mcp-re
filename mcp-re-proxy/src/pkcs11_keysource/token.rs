// SPDX-License-Identifier: Apache-2.0
//! Finding things ON the token, and reading what comes back.
//!
//! Two mechanism operations that decide nothing about signing: which slot holds the named
//! token and which object is the named key, and how an Ed25519 public point is read out of a
//! `CKA_EC_POINT` attribute.
//!
//! The second is a decoding grammar, and it is exact on purpose. A token may return the
//! point wrapped in a DER OCTET STRING or bare, and a reader that guessed would either
//! refuse a conformant token or accept 32 bytes that are not a point. The public key IS
//! exportable even from a non-exporting token — it is what relying parties verify against —
//! so this is the one thing that legitimately leaves the device.

use cryptoki_sys::CK_OBJECT_HANDLE;
use cryptoki_sys::CK_SLOT_ID;

use crate::communication_assurance::ED25519_PUBLIC_KEY_LEN;
use crate::key_source::KeyError;
use crate::pkcs11_native::AttributeTemplate;
use crate::pkcs11_native::ObjectClass;
use crate::pkcs11_native::Pkcs11Context;
use crate::pkcs11_native::SessionRef;

use super::session::classify_op_error;
use super::session::SessionOpError;

/// fail closed, never silently pick one). A re-open would not change these.
pub(crate) fn find_key(
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
pub(crate) fn class_name(class: ObjectClass) -> &'static str {
    match class {
        ObjectClass::Private => "CKO_PRIVATE_KEY",
        ObjectClass::Public => "CKO_PUBLIC_KEY",
    }
}

/// Select the slot whose token's label equals `token_label`. Token labels are
/// stable across reboots (slot ids are not), so this is the primary selector. No
/// match is [`KeyError::NotFound`].
pub(crate) fn find_token_slot(
    context: &Pkcs11Context,
    token_label: &str,
) -> Result<CK_SLOT_ID, KeyError> {
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
pub(crate) fn raw_ed25519_point(ec_point: &[u8]) -> Result<[u8; ED25519_PUBLIC_KEY_LEN], KeyError> {
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
/// [`crate::kms_keysource::Ed25519SpkiDer`] guard that the validated
/// delegated-TLS build path (#58) uses to fail closed on a cert/key mismatch. A
/// wrong-length / non-Ed25519 point fails closed via [`raw_ed25519_point`].
pub(crate) fn ed25519_spki_from_ec_point(ec_point: &[u8]) -> Result<Vec<u8>, KeyError> {
    let raw = raw_ed25519_point(ec_point)?;
    let der = crate::communication_assurance::Ed25519PublicKeyValue::spki_der_for_point(raw);
    Ok(der)
}
