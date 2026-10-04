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
//! It then came back one level up (r12 R12-620). An EARLY RETURN on the RESPONSE-signing
//! custody's answer about ITS OWN locators ran before the CHANNEL machine's file was
//! appended, so an `EnvSeed` response custody beside an exported channel key produced an
//! EMPTY list while the TLS key was read anyway. The two are separate machines
//! (ADR-MCPRE-067 §10) and nothing makes them agree.
//!
//! So this role is phrased as a CONCATENATION of per-owner answers, and no owner's answer
//! is allowed to short-circuit another's contribution.

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
    // `locators_are_filesystem_paths` is the RESPONSE custody's statement about ITS
    // locators — under `EnvSeed` they name environment variables, and stat'ing a variable
    // NAME as a path is a check that passes for the wrong reason.
    let mut paths = if custody.locators_are_filesystem_paths() {
        custody.disk_secret_paths()
    } else {
        Vec::new()
    };
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

    /// LOAD-BEARING (r12 R12-620): the RESPONSE-signing custody's answer about ITS
    /// locators must not suppress the CHANNEL machine's file.
    ///
    /// The two are separate machines and nothing makes them agree, so an `EnvSeed`
    /// response custody — every locator an environment variable — beside an exported
    /// channel key is representable. The guard's early return on
    /// `locators_are_filesystem_paths()` then produced an EMPTY check list while
    /// `key_source.tls_server_key()` read that key file anyway, so a TLS server private
    /// key mounted at Kubernetes' default 0644 booted silently — with the deployment
    /// advertising a hardened key-custody posture.
    ///
    /// Built by setting `response_signing.source` directly rather than through
    /// `--key-source env`, which `cli::parse_args` admits only under
    /// `dev_env_key_source`: the state is what this projection is wrong about, and the
    /// flag that reaches it is not part of the claim.
    #[test]
    fn an_env_seed_response_custody_does_not_suppress_the_channel_key_file() {
        use crate::deployment_request::EnvironmentSigningSourceRequest;
        use crate::deployment_request::SigningSourceRequest;

        let mut config = config_with("file", "/seed", "/tls.key");
        config.response_signing.source =
            SigningSourceRequest::Environment(EnvironmentSigningSourceRequest {
                seed_var: "MCP_RE_SEED".to_string(),
            });
        let (custody, channel_credential_custody) = custody_states(&config);
        assert!(
            !custody.locators_are_filesystem_paths(),
            "the fixture must be the state the defect turned on"
        );
        let files = key_files_read_from_disk(&custody, &channel_credential_custody);
        // EXACT, not `contains`: this is simultaneously the other direction. The fix is
        // not "check everything always" — the env-var seed name is absent, because
        // stat'ing a variable NAME as a path is a check that passes for the wrong reason,
        // which is what the early return was written to prevent.
        assert_eq!(
            files,
            vec!["/tls.key"],
            "the channel machine's exported key is read from disk whatever the response \
             custody says about its own locators, and an env-var name is not a path"
        );
    }

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
        // `env` is omitted: it is rejected by the parser outside a
        // `dev_env_key_source` build, so it cannot be constructed here.
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
