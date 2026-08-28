// SPDX-License-Identifier: Apache-2.0
//! The mechanism payloads for keys held on a PKCS#11 token.
//!
//! Two payloads, because a token holding two key objects is holding two key objects: the
//! response-signing key and the channel-establishment key are different security
//! principals that happen to share a device (ADR-MCPRE-067 §10). Neither payload is
//! reachable from the other role's selection.

/// The token, the credential that unlocks it, and the response-signing key object on it.
///
/// Every field is `Option` because absence is a meaningful input state the configuration
/// boundary refuses with a per-flag diagnostic (ADR-MCPRE-067 §7.2). What absence can no
/// longer mean is "this belongs to a different mechanism": a request that did not select
/// PKCS#11 has no place to put these at all.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Pkcs11SigningSourceRequest {
    /// Path to the PKCS#11 provider library (`.so`/`.dylib`).
    pub module: Option<String>,
    /// Path the token User PIN is read from.
    ///
    /// The PIN itself is deliberately not a field. A process command line is
    /// world-readable on every platform this runs on (`ps`, `/proc/<pid>/cmdline`), and
    /// [`DeploymentRequest`](crate::deployment_request::DeploymentRequest) derives `Debug`
    /// and is cloned freely — so a PIN held here would ride into any structured log or
    /// panic message. Keeping only the path means there is nothing to redact. The file is
    /// read once, at key-source construction, into a short-lived
    /// [`SecretString`](crate::deployment_request::SecretString), and is held to the same
    /// permission floor as a key file: it unlocks the token holding the keys.
    pub pin_file: Option<String>,
    /// Label of the token holding the key. Token labels are stable across reboots; slot
    /// ids are not.
    pub token_label: Option<String>,
    /// `CKA_LABEL` of the Ed25519 response-signing key object.
    pub key_label: Option<String>,
}

/// The second, distinct key object on the token that establishes the communication
/// channel.
///
/// Its own type rather than a fifth field above, because it is a different ROLE. An
/// operator should be able to scope it separately, and nothing here lets a consumer read
/// one where it meant the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkcs11ChannelKeyRequest {
    /// `CKA_LABEL` of the Ed25519 channel key object. Its presence is what selects
    /// non-exporting channel custody; the handshake signature is made through the token
    /// and the private key never leaves it.
    pub key_label: String,
}
