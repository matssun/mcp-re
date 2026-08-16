// SPDX-License-Identifier: Apache-2.0
//! A string whose value must not reach a log, a panic message or a debug print.

/// A secret string that does not leak through `Debug` and is scrubbed on drop.
///
/// [`DeploymentRequest`] derives `Debug`, so any structured log, panic message, or debug print of
/// the config would otherwise carry the PKCS#11 User PIN verbatim. The PIN is the
/// credential that unlocks a token holding the response-signing and (optionally) TLS
/// private keys, so it belongs in the same custody class as the keys themselves.
///
/// `Zeroizing` wipes the heap allocation when the value drops. That is a best effort
/// against a core dump or a freed-page read, not a guarantee: the string was already
/// copied by whatever read it in, and `Clone` (needed because `DeploymentRequest` is `Clone`)
/// makes another copy. It removes the copies this code controls.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(zeroize::Zeroizing<String>);

impl SecretString {
    /// Wrap a secret value.
    pub fn new(value: impl Into<String>) -> Self {
        SecretString(zeroize::Zeroizing::new(value.into()))
    }

    /// Borrow the secret. Every call site is a place the value can escape — keep them
    /// few and close to the API that consumes it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No length either: a PIN's length is worth guessing with.
        f.write_str("SecretString(redacted)")
    }
}

#[cfg(test)]
mod tests {
    use super::SecretString;

    #[test]
    fn the_debug_rendering_carries_no_part_of_the_secret() {
        let secret = SecretString::new("s3cr3t-pin-value");
        let rendered = format!("{secret:?}");
        assert!(
            !rendered.contains("s3cr3t"),
            "Debug must not carry the secret, got: {rendered}"
        );
        assert_eq!(rendered, "SecretString(redacted)");
    }

    #[test]
    fn the_value_is_still_readable_where_it_is_needed() {
        assert_eq!(SecretString::new("pin").expose(), "pin");
    }
}
