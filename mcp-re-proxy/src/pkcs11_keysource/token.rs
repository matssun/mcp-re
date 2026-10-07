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
use crate::pkcs11_native::TokenIdentity;

use super::session::classify_op_error;
use super::session::SessionOpError;

/// Locate the single Ed25519 key object of the given class with `key_label`
/// against an open session view, classified for the amortization layer.
///
/// A transient session fault during the find is [`SessionOpError::SessionInvalid`]
/// (retry once); any other wrapper error is [`SessionOpError::Fatal`] with the SAME
/// `NotFound` context text as the pre-amortization path. The count cases are
/// intrinsic, never a session fault: zero matches is a [`KeyError::NotFound`] Fatal;
/// more than one is a [`KeyError::Malformed`] Fatal (an ambiguous token config must
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

/// Locate the single private key object labelled `key_label` and refuse it unless the token
/// reports it `CKA_SENSITIVE` and not `CKA_EXTRACTABLE`.
///
/// The custody claim — the private key never leaves the token — is checked here rather than
/// left to whoever provisioned the object: a key the token itself reports as exportable is
/// refused at startup. What remains trusted is that the token reports these attributes
/// truthfully and enforces them (ASM-0052).
pub(crate) fn find_token_bound_private_key(
    view: &SessionRef<'_>,
    key_label: &str,
) -> Result<CK_OBJECT_HANDLE, SessionOpError> {
    let key = find_key(view, key_label, ObjectClass::Private)?;
    let custody = view.key_custody(key).map_err(|e| {
        classify_op_error(e, |e| {
            KeyError::Malformed(format!(
                "pkcs11: read the custody attributes of key '{key_label}': {e}"
            ))
        })
    })?;
    if !custody.is_token_bound() {
        return Err(SessionOpError::Fatal(KeyError::Malformed(format!(
            "pkcs11: private key '{key_label}' can leave the token (CKA_SENSITIVE={}, \
             CKA_EXTRACTABLE={}); refusing a key the token does not bind",
            custody.sensitive, custody.extractable
        ))));
    }
    Ok(key)
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
/// match is [`KeyError::NotFound`]; more than one present token under the label is
/// [`KeyError::Malformed`], because this selector decides which device receives the
/// User PIN and an ambiguity fails closed rather than taking the first match.
pub(crate) fn find_token_slot(
    context: &Pkcs11Context,
    token_label: &str,
) -> Result<(CK_SLOT_ID, TokenIdentity), KeyError> {
    // `token_slots` enumerates present-token slots and reads each token's label
    // with the 32-byte 0x20 padding already trimmed. The comparison is over those
    // BYTES: this is what decides which physical device receives the User PIN, so
    // two labels are the same label only when the token reported the same bytes.
    let slots = context
        .token_slots()
        .map_err(|e| KeyError::NotFound(format!("pkcs11: enumerate token slots: {e}")))?;
    select_token_slot(slots, token_label, TokenIdentity::label)
}

/// The selection decision over enumerated `(slot, token)` pairs: exactly one
/// byte-equal label selects its slot and token, none is `NotFound`, several are
/// `Malformed`.
fn select_token_slot<T>(
    slots: Vec<(CK_SLOT_ID, T)>,
    token_label: &str,
    label_of: impl Fn(&T) -> &[u8],
) -> Result<(CK_SLOT_ID, T), KeyError> {
    let mut matching: Vec<(CK_SLOT_ID, T)> = slots
        .into_iter()
        .filter(|(_, token)| label_of(token) == token_label.as_bytes())
        .collect();
    match matching.len() {
        0 => Err(KeyError::NotFound(format!(
            "pkcs11: no token with label '{token_label}'"
        ))),
        1 => matching.pop().ok_or_else(|| {
            KeyError::Malformed("pkcs11: token selection lost its single match".to_string())
        }),
        n => {
            let ids: Vec<CK_SLOT_ID> = matching.iter().map(|(slot, _)| *slot).collect();
            Err(KeyError::Malformed(format!(
                "pkcs11: {n} present tokens labelled '{token_label}' (slots {ids:?}); refusing to guess which receives the User PIN"
            )))
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_present_tokens_under_the_configured_label_are_refused_not_first_matched() {
        let slots = vec![
            (1, b"prod".to_vec()),
            (2, b"other".to_vec()),
            (5, b"prod".to_vec()),
        ];
        assert!(matches!(
            select_token_slot(slots, "prod", |l: &Vec<u8>| l.as_slice()),
            Err(KeyError::Malformed(_))
        ));
    }

    #[test]
    fn exactly_one_present_token_under_the_label_is_selected() {
        let slots = vec![
            (1, b"other".to_vec()),
            (4, b"prod".to_vec()),
            (6, b"x".to_vec()),
        ];
        assert!(matches!(
            select_token_slot(slots, "prod", |l: &Vec<u8>| l.as_slice()),
            Ok((4, _))
        ));
        assert!(matches!(
            select_token_slot(Vec::<(CK_SLOT_ID, Vec<u8>)>::new(), "prod", |l| l
                .as_slice()),
            Err(KeyError::NotFound(_))
        ));
        assert!(matches!(
            select_token_slot(vec![(1, b"other".to_vec())], "prod", |l: &Vec<u8>| l
                .as_slice()),
            Err(KeyError::NotFound(_))
        ));
    }

    /// The point grammar is exact on purpose: a token may return `CKA_EC_POINT` bare or
    /// wrapped in a DER OCTET STRING, and both are conformant.
    #[test]
    fn both_conformant_ec_point_encodings_yield_the_same_32_byte_point() {
        let point = [7u8; ED25519_PUBLIC_KEY_LEN];
        let mut wrapped = vec![0x04, ED25519_PUBLIC_KEY_LEN as u8];
        wrapped.extend_from_slice(&point);
        assert_eq!(raw_ed25519_point(&point).expect("bare point"), point);
        assert_eq!(raw_ed25519_point(&wrapped).expect("wrapped point"), point);
    }

    /// The 32-byte length is what discriminates Ed25519 from the rest of `CKK_EC_EDWARDS`
    /// — the lookup template cannot, since `CKK_EC_EDWARDS` covers Ed448 too. An Ed448
    /// point is 57 bytes, and it must not be accepted as this deployment's signing key.
    #[test]
    fn a_point_that_is_not_32_bytes_is_refused() {
        for length in [0usize, 31, 33, 57] {
            let point = vec![7u8; length];
            assert!(
                raw_ed25519_point(&point).is_err(),
                "a {length}-byte point is not an Ed25519 point"
            );
        }
        // A 34-byte value that is not the OCTET STRING encoding is refused too: the
        // wrapper is recognised by its tag and length, never by its size alone.
        let mut mistagged = vec![0x05, ED25519_PUBLIC_KEY_LEN as u8];
        mistagged.extend_from_slice(&[7u8; ED25519_PUBLIC_KEY_LEN]);
        assert!(raw_ed25519_point(&mistagged).is_err());
    }

    /// The SPKI the relying party verifies against is built from a point that passed the
    /// grammar, so a refused point never reaches an SPKI.
    #[test]
    fn an_spki_is_only_built_from_an_accepted_point() {
        let point = [7u8; ED25519_PUBLIC_KEY_LEN];
        let der = ed25519_spki_from_ec_point(&point).expect("a 32-byte point");
        assert!(
            der.len() > ED25519_PUBLIC_KEY_LEN && der.ends_with(&point),
            "the RFC 8410 SPKI carries the point after its header: {der:?}"
        );
        assert!(ed25519_spki_from_ec_point(&[7u8; 57]).is_err());
    }

    /// The class name is what the refusal messages say; an object-class mix-up in a
    /// startup failure sends an operator to the wrong token object.
    #[test]
    fn each_object_class_names_itself() {
        assert_eq!(class_name(ObjectClass::Private), "CKO_PRIVATE_KEY");
        assert_eq!(class_name(ObjectClass::Public), "CKO_PUBLIC_KEY");
    }
}
