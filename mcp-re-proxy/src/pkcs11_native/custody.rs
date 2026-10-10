// SPDX-License-Identifier: Apache-2.0
//! Whether a private key object can leave the token, as the token reports it.
//!
//! `CKA_SENSITIVE` says the key's value is never revealed in plaintext; `CKA_EXTRACTABLE` says
//! it may be wrapped out. PKCS#11 makes both one-way — sensitive cannot be cleared, extractable
//! cannot be set again — so a key reported sensitive and non-extractable stays so. The read is
//! one `C_GetAttributeValue` over the same session view the rest of the wrapper drives.

use std::ffi::c_void;

use cryptoki_sys::CKA_EXTRACTABLE;
use cryptoki_sys::CKA_SENSITIVE;
use cryptoki_sys::CK_ATTRIBUTE;
use cryptoki_sys::CK_BBOOL;
use cryptoki_sys::CK_OBJECT_HANDLE;
use cryptoki_sys::CK_ULONG;

use super::check;
use super::Pkcs11Error;
use super::SessionRef;

/// What a token reports about whether a private key object can leave it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyCustody {
    pub sensitive: bool,
    pub extractable: bool,
}

impl KeyCustody {
    /// Whether the token reports the key as unable to leave it.
    pub fn is_token_bound(self) -> bool {
        self.sensitive && !self.extractable
    }
}

impl SessionRef<'_> {
    /// Read `CKA_SENSITIVE` and `CKA_EXTRACTABLE` of `key` in one `C_GetAttributeValue`. A
    /// token that cannot report either is refused: an unknown custody is not a bound one.
    pub fn key_custody(&self, key: CK_OBJECT_HANDLE) -> Result<KeyCustody, Pkcs11Error> {
        let mut sensitive: CK_BBOOL = 0;
        let mut extractable: CK_BBOOL = 0;
        let width = std::mem::size_of::<CK_BBOOL>() as CK_ULONG;
        let mut attrs = [
            CK_ATTRIBUTE {
                type_: CKA_SENSITIVE,
                pValue: (&mut sensitive as *mut CK_BBOOL).cast::<c_void>(),
                ulValueLen: width,
            },
            CK_ATTRIBUTE {
                type_: CKA_EXTRACTABLE,
                pValue: (&mut extractable as *mut CK_BBOOL).cast::<c_void>(),
                ulValueLen: width,
            },
        ];
        // SAFETY: function-list non-null; `C_GetAttributeValue` checked non-null by `func!`.
        // Each attribute points at a live one-byte `CK_BBOOL` with the matching length, and the
        // count passed is the array's length.
        unsafe {
            let get_attr = func!(self.function_list, C_GetAttributeValue);
            let rv = get_attr(
                self.handle,
                key,
                attrs.as_mut_ptr(),
                attrs.len() as CK_ULONG,
            );
            check(rv, "C_GetAttributeValue (CKA_SENSITIVE, CKA_EXTRACTABLE)")?;
        }
        if attrs.iter().any(|a| a.ulValueLen != width) {
            return Err(Pkcs11Error::Protocol(
                "CKA_SENSITIVE or CKA_EXTRACTABLE is unavailable on this key object".to_string(),
            ));
        }
        Ok(KeyCustody {
            sensitive: sensitive != 0,
            extractable: extractable != 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_sensitive_non_extractable_key_is_token_bound() {
        let bound = |sensitive, extractable| {
            KeyCustody {
                sensitive,
                extractable,
            }
            .is_token_bound()
        };
        assert!(bound(true, false));
        assert!(!bound(true, true));
        assert!(!bound(false, false));
        assert!(!bound(false, true));
    }
}
