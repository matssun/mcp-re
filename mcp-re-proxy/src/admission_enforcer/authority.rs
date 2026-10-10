// SPDX-License-Identifier: Apache-2.0
//! The admission authority a process was started with.

use std::sync::Arc;

use mcp_re_core::VerificationKey;

use crate::http_profile_serve::AdmissionAuthorityResolver;

/// The resolver for the one admission authority this process was started with: it answers
/// its own kid with its own key and every other kid with `None`. It owns both values, so no
/// caller holds a handle that could change them while the process runs.
pub(crate) fn fixed_authority_resolver(
    kid: String,
    key: VerificationKey,
) -> AdmissionAuthorityResolver {
    Arc::new(move |presented: &str| (presented == kid).then(|| key.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RFC 8032 section 7.1 public key of test vector 1.
    const KEY_1: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    fn key(hex: &str) -> VerificationKey {
        let mut bytes = [0u8; 32];
        for (slot, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks(2)) {
            let pair = std::str::from_utf8(pair).expect("ascii hex");
            *slot = u8::from_str_radix(pair, 16).expect("hex digits");
        }
        VerificationKey::from_bytes(&bytes).expect("a valid key")
    }

    #[test]
    fn the_admission_authority_is_the_kid_and_key_the_process_started_with() {
        let started_with = key(KEY_1);
        let resolve = fixed_authority_resolver("authority-1".to_string(), started_with.clone());
        for _ in 0..3 {
            let resolved = resolve("authority-1").expect("the configured kid resolves");
            assert_eq!(resolved.to_bytes(), started_with.to_bytes());
        }
        assert!(resolve("authority-2").is_none());
        assert!(resolve("").is_none());
    }
}
