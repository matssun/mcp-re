// SPDX-License-Identifier: Apache-2.0
//! WHICH private-key files this deployment causes the proxy to read.
//!
//! One fact: **the scope of the permission floor is every key file that will be read, and
//! it is assembled from each custody owner's own answer.**
//!
//! # The rule, and the two ways it has been broken
//!
//! **The rule follows the FILES, not the key-source name.** It was written after gating the
//! whole check on `key_source == File` had skipped the one private key that DOES land in
//! the pod in precisely the modes advertised as "no key material ever lands in the pod": a
//! TLS server key mounted with Kubernetes' default 0644 booted silently.
//!
//! The response-signing custody and the channel custody are separate machines
//! (ADR-MCPRE-067 §10) and nothing makes them agree (r12 R12-620). So this role is phrased
//! as a CONCATENATION of per-owner answers, and no owner's answer is allowed to
//! short-circuit another's contribution.

use crate::config_state::ChannelCredentialCustodyState;
use crate::config_state::CustodyState;

/// Every private-key file this configuration causes the proxy to READ from disk.
///
/// Pure, so the scope is testable on its own — the defect this replaces was never in the
/// permission predicate but in which files it was pointed at.
///
/// The signing seed is read only under `file` custody; a PKCS#11/KMS source never
/// surrenders it. The PKCS#11 User PIN is here because it unlocks the token holding the
/// signing and TLS keys: a group- or world-readable PIN file is as good as a readable key
/// file. The TLS server private key is read under EVERY custody mode unless TLS signing is
/// itself delegated — and `cli::parse_args` leaves `tls_key` empty in exactly that case,
/// which is why emptiness is the right test rather than the mode.
pub(super) fn key_files_read_from_disk<'a>(
    custody: &'a CustodyState,
    channel_credential_custody: &'a ChannelCredentialCustodyState,
) -> Vec<&'a str> {
    // EACH OWNER ANSWERS FOR ITS OWN LOCATORS, and neither can suppress the other's.
    let mut paths = custody.disk_secret_paths();
    // And the handshake key, only where the CHANNEL machine exports one. Non-exporting
    // custody keeps it on the device, and the tagged request carries no file beside it.
    paths.extend(channel_credential_custody.material().exported_key_path());
    paths
}

#[cfg(test)]
mod tests {
    use super::key_files_read_from_disk;
    use crate::config_state::test_support::config_with;
    use crate::config_state::test_support::custody_states;

    /// C048: the PKCS#11 PIN file unlocks the token holding the signing keys, so it must
    /// be among the files the startup permission check covers — otherwise the credential
    /// protecting the keys sits behind a weaker floor than the keys themselves.
    #[test]
    fn the_pkcs11_pin_file_is_permission_checked() {
        let config = config_with("pkcs11", "", "/tls.key");
        let (custody, channel_credential_custody) = custody_states(&config);
        let files = key_files_read_from_disk(&custody, &channel_credential_custody);
        assert!(
            files.contains(&"/etc/mcp-re/pin"),
            "the PIN file must be checked; got {files:?}"
        );
        // And it is NOT claimed for a source that reads no PIN.
        let file_config = config_with("file", "/seed", "/tls.key");
        let (custody, channel_credential_custody) = custody_states(&file_config);
        assert!(
            !key_files_read_from_disk(&custody, &channel_credential_custody)
                .iter()
                .any(|p| p.contains("pin")),
            "file custody reads no PIN file"
        );
    }

    /// The load-bearing property, on the pure predicate `run` actually uses: the TLS
    /// server key is read from disk under EVERY custody mode unless TLS signing is
    /// itself delegated — including the KMS modes advertised as "no key material ever
    /// lands in the pod" — so it must always be among the files checked.
    #[test]
    fn the_tls_key_is_checked_under_every_custody_mode() {
        for source in ["file", "pkcs11", "aws-kms", "gcp-kms"] {
            let config = config_with(
                source,
                if source == "file" { "/seed" } else { "" },
                "/tls.key",
            );
            let (custody, channel_credential_custody) = custody_states(&config);
            let checked = key_files_read_from_disk(&custody, &channel_credential_custody);
            assert!(
                checked.contains(&"/tls.key"),
                "{source}: the TLS key lands on disk and must be permission-checked"
            );
            // The SEED is read only where custody is file-based.
            assert_eq!(
                checked.contains(&"/seed"),
                source == "file",
                "{source}: the seed is checked iff it is actually read"
            );
        }
    }

    /// Delegated TLS leaves `tls_key` empty — that emptiness is how the wiring says "no
    /// key file is read", so nothing must be checked for it.
    #[test]
    fn a_delegated_tls_key_contributes_no_file_to_check() {
        let config = config_with("gcp-kms", "", "");
        let (custody, channel_credential_custody) = custody_states(&config);
        assert!(
            key_files_read_from_disk(&custody, &channel_credential_custody).is_empty(),
            "delegated TLS + KMS custody reads no private key from disk"
        );
    }
}
