// SPDX-License-Identifier: Apache-2.0
//! The `Custody` configuration machine — `work/CONFIG-STATE-ATLAS.md` §C.3.
//!
//! Where the Ed25519 response-signing key lives, and therefore what an operator is
//! entitled to believe about it. Five states:
//!
//! | State | Required | Forbidden | Guards |
//! |---|---|---|---|
//! | `FileSeed` | seed | every other state's parameters | — |
//! | `EnvSeed` | seed | every other state's parameters | — |
//! | `Pkcs11` | module, pin file, token label, key label | AWS/GCP parameters and flags | — |
//! | `AwsKms` | region, key id | PKCS#11/GCP parameters, GCP flag | endpoint authority |
//! | `GcpKms` | key version | PKCS#11/AWS parameters, AWS flag | endpoint authority |
//!
//! **Which state a binary can ESTABLISH is layer B and not decided here.** `Pkcs11` is a
//! coherent request in a build without `pkcs11_keysource`; `build_key_source` refuses it,
//! and that refusal is a statement about the executable rather than about the request
//! (CF-05).
//!
//! **The forbidden column is load-bearing, not tidiness (CF-04).** `--key-source gcp-kms`
//! together with `--aws-kms-region` states two conflicting intents: a selected custody
//! path and a parameter belonging to a different one. Accepting it silently hides a typo,
//! a stale fragment, or an operator who believes both apply. Only parameters whose
//! presence is semantically observable are refused — `signing_key_seed` is a `String` the
//! parser leaves empty in the device states, so its emptiness carries no intent and it is
//! ignored there rather than forbidden.

use crate::cli::{Config, KeySourceKind};

/// Which custody state a configuration requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyState {
    /// A seed file on disk.
    FileSeed,
    /// A seed in an environment variable — dev/CI only.
    EnvSeed,
    /// A PKCS#11 token; the key is exercised via `C_Sign` and never leaves the device.
    Pkcs11,
    /// AWS KMS; the key is exercised via `Sign` and never leaves KMS.
    AwsKms,
    /// GCP Cloud KMS; the key is exercised via `asymmetricSign`.
    GcpKms,
}

impl CustodyState {
    /// Whether the key material is held by a device or KMS rather than by this process.
    ///
    /// The property the three device states share and the two seed states do not, and the
    /// one downstream stages actually ask about.
    pub fn is_non_exporting_device(&self) -> bool {
        matches!(self, Self::Pkcs11 | Self::AwsKms | Self::GcpKms)
    }
}

/// Recognise the requested state. Total: `key_source` names one directly.
fn classify(config: &Config) -> CustodyState {
    match config.key_source {
        KeySourceKind::File => CustodyState::FileSeed,
        KeySourceKind::Env => CustodyState::EnvSeed,
        KeySourceKind::Pkcs11 => CustodyState::Pkcs11,
        KeySourceKind::AwsKms => CustodyState::AwsKms,
        KeySourceKind::GcpKms => CustodyState::GcpKms,
    }
}

/// What the selected state cannot start without.
fn required_violations(state: CustodyState, config: &Config) -> Vec<String> {
    let mut out = Vec::new();
    let mut require = |present: bool, message: &str| {
        if !present {
            out.push(message.to_string());
        }
    };
    match state {
        CustodyState::FileSeed => require(
            !config.signing_key_seed.is_empty(),
            "--key-source file requires --signing-key-seed <path>: the response-signing key \
             has no other source in this state",
        ),
        CustodyState::EnvSeed => require(
            !config.signing_key_seed.is_empty(),
            "--key-source env requires --signing-key-seed <env-var-name>",
        ),
        CustodyState::Pkcs11 => {
            require(
                config.pkcs11_module.is_some(),
                "--key-source pkcs11 requires --pkcs11-module <path>",
            );
            require(
                config.pkcs11_pin_file.is_some(),
                "--key-source pkcs11 requires --pkcs11-pin-file <path>; the User PIN is \
                 never accepted on argv, which is world-readable via ps and \
                 /proc/<pid>/cmdline",
            );
            require(
                config.pkcs11_token_label.is_some(),
                "--key-source pkcs11 requires --pkcs11-token-label <label>",
            );
            require(
                config.pkcs11_key_label.is_some(),
                "--key-source pkcs11 requires --pkcs11-key-label <label>",
            );
        }
        CustodyState::AwsKms => {
            require(
                config.aws_kms_region.is_some(),
                "--key-source aws-kms requires --aws-kms-region <region>",
            );
            require(
                config.aws_kms_key_id.is_some(),
                "--key-source aws-kms requires --aws-kms-key-id <key-id|arn|alias>",
            );
        }
        CustodyState::GcpKms => require(
            config.gcp_kms_key_version.is_some(),
            "--key-source gcp-kms requires --gcp-kms-key-version \
             <projects/.../cryptoKeyVersions/N>",
        ),
    }
    out
}

/// Parameters and capability flags that belong to a state this configuration is not in.
///
/// Every entry is `Option`-typed or an explicitly-passed flag, so presence is an operator
/// statement rather than a default (CF-04's qualification).
fn forbidden_violations(state: CustodyState, config: &Config) -> Vec<String> {
    let mut out = Vec::new();
    let mut forbid = |present: bool, owner: CustodyState, flag: &str, owning_source: &str| {
        if present && state != owner {
            out.push(format!(
                "{flag} belongs to --key-source {owning_source} and this configuration \
                 selects a different custody source; the value would be ignored, leaving a \
                 deployment that believes it applies. Remove {flag}, or select \
                 --key-source {owning_source}"
            ));
        }
    };
    for (present, flag) in [
        (config.pkcs11_module.is_some(), "--pkcs11-module"),
        (config.pkcs11_pin_file.is_some(), "--pkcs11-pin-file"),
        (config.pkcs11_token_label.is_some(), "--pkcs11-token-label"),
        (config.pkcs11_key_label.is_some(), "--pkcs11-key-label"),
    ] {
        forbid(present, CustodyState::Pkcs11, flag, "pkcs11");
    }
    for (present, flag) in [
        (config.aws_kms_region.is_some(), "--aws-kms-region"),
        (config.aws_kms_key_id.is_some(), "--aws-kms-key-id"),
        (
            config.aws_kms_use_web_identity,
            "--aws-kms-use-web-identity",
        ),
    ] {
        forbid(present, CustodyState::AwsKms, flag, "aws-kms");
    }
    for (present, flag) in [
        (
            config.gcp_kms_key_version.is_some(),
            "--gcp-kms-key-version",
        ),
        (config.gcp_kms_use_metadata, "--gcp-kms-use-metadata"),
    ] {
        forbid(present, CustodyState::GcpKms, flag, "gcp-kms");
    }
    // Intra-machine: the STS endpoint parameterizes the IRSA credential mode, not the
    // custody state, so it dangles on a state that has the right source but not that mode.
    if config.aws_sts_endpoint.is_some() && !config.aws_kms_use_web_identity {
        out.push("--aws-sts-endpoint has no effect without --aws-kms-use-web-identity".to_string());
    }
    out
}

/// Classify the requested custody state and check its four columns.
///
/// The endpoint-authority guards come first, matching the order an operator already read
/// them in: an overridden KMS endpoint substitutes the root verify key the
/// verify-before-return guardrail is measured against, so it is the graver statement.
///
/// Every violation in the columns is reported, not the first. That is a deliberate change
/// from the predicate this replaces, and it matches every other clause at this boundary;
/// a configuration with one violation still reads exactly as before.
pub fn classify_and_validate(config: &Config) -> (CustodyState, Vec<String>) {
    let state = classify(config);
    let mut violations = crate::cli::kms_endpoint_refusals(config);
    violations.extend(required_violations(state, config));
    violations.extend(forbidden_violations(state, config));
    (state, violations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;

    fn pkcs11(config: &mut Config) {
        config.key_source = KeySourceKind::Pkcs11;
        config.pkcs11_module = Some("/lib/softhsm.so".to_string());
        config.pkcs11_pin_file = Some("/pin".to_string());
        config.pkcs11_token_label = Some("token".to_string());
        config.pkcs11_key_label = Some("signing".to_string());
    }

    fn aws(config: &mut Config) {
        config.key_source = KeySourceKind::AwsKms;
        config.aws_kms_region = Some("eu-north-1".to_string());
        config.aws_kms_key_id = Some("alias/signing".to_string());
    }

    fn gcp(config: &mut Config) {
        config.key_source = KeySourceKind::GcpKms;
        config.gcp_kms_key_version =
            Some("projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1".to_string());
    }

    /// A state this machine must recognise, and how to request it.
    type Form = (CustodyState, fn(&mut Config));
    /// A flag a case must name in its refusal, and the configuration that provokes it.
    type Case = (&'static str, fn(&mut Config));

    fn run(mutate: impl FnOnce(&mut Config)) -> (CustodyState, Vec<String>) {
        let mut config = legal_config();
        mutate(&mut config);
        classify_and_validate(&config)
    }

    #[test]
    fn every_legal_state_form_is_classified_and_accepted() {
        let cases: Vec<Form> = vec![
            (CustodyState::FileSeed, |c| {
                c.key_source = KeySourceKind::File;
            }),
            (CustodyState::EnvSeed, |c| {
                c.key_source = KeySourceKind::Env;
            }),
            (CustodyState::Pkcs11, pkcs11),
            (CustodyState::AwsKms, aws),
            (CustodyState::GcpKms, gcp),
        ];
        for (expected, mutate) in cases {
            let (state, violations) = run(mutate);
            assert_eq!(state, expected, "classified as the wrong state");
            assert!(
                violations.is_empty(),
                "{expected:?} refused: {violations:?}"
            );
        }
    }

    #[test]
    fn only_the_device_states_hold_the_key_off_this_process() {
        assert!(!run(|c| c.key_source = KeySourceKind::File)
            .0
            .is_non_exporting_device());
        for mutate in [pkcs11 as fn(&mut Config), aws, gcp] {
            assert!(run(mutate).0.is_non_exporting_device());
        }
    }

    #[test]
    fn each_state_names_every_parameter_it_cannot_start_without() {
        // One case per required cell, cleared from an otherwise complete state.
        let cases: Vec<Case> = vec![
            ("--signing-key-seed", |c| {
                c.key_source = KeySourceKind::File;
                c.signing_key_seed = String::new();
            }),
            ("--pkcs11-module", |c| {
                pkcs11(c);
                c.pkcs11_module = None;
            }),
            ("--pkcs11-pin-file", |c| {
                pkcs11(c);
                c.pkcs11_pin_file = None;
            }),
            ("--pkcs11-token-label", |c| {
                pkcs11(c);
                c.pkcs11_token_label = None;
            }),
            ("--pkcs11-key-label", |c| {
                pkcs11(c);
                c.pkcs11_key_label = None;
            }),
            ("--aws-kms-region", |c| {
                aws(c);
                c.aws_kms_region = None;
            }),
            ("--aws-kms-key-id", |c| {
                aws(c);
                c.aws_kms_key_id = None;
            }),
            ("--gcp-kms-key-version", |c| {
                gcp(c);
                c.gcp_kms_key_version = None;
            }),
        ];
        for (flag, mutate) in cases {
            let (_, violations) = run(mutate);
            assert!(
                violations.iter().any(|v| v.contains(flag)),
                "a state missing {flag} was accepted: {violations:?}"
            );
        }
    }

    /// CF-04, and the half that was missing: a dangling TLS selector or capability flag
    /// was already refused, a dangling *required parameter of another state* was not.
    #[test]
    fn a_parameter_belonging_to_another_custody_state_is_refused() {
        let cases: Vec<Case> = vec![
            ("--aws-kms-region", |c| {
                gcp(c);
                c.aws_kms_region = Some("eu-north-1".to_string());
            }),
            ("--aws-kms-key-id", |c| {
                pkcs11(c);
                c.aws_kms_key_id = Some("alias/signing".to_string());
            }),
            ("--pkcs11-module", |c| {
                aws(c);
                c.pkcs11_module = Some("/lib/softhsm.so".to_string());
            }),
            ("--gcp-kms-key-version", |c| {
                aws(c);
                c.gcp_kms_key_version = Some("projects/p/..".to_string());
            }),
            ("--aws-kms-use-web-identity", |c| {
                gcp(c);
                c.aws_kms_use_web_identity = true;
            }),
            ("--gcp-kms-use-metadata", |c| {
                aws(c);
                c.gcp_kms_use_metadata = true;
            }),
        ];
        for (flag, mutate) in cases {
            let (_, violations) = run(mutate);
            assert!(
                violations.iter().any(|v| v.contains(flag)),
                "a dangling {flag} was accepted: {violations:?}"
            );
        }
    }

    /// The qualification on the ruling: a defaulted scalar that every configuration
    /// carries is not evidence of intent, so it is ignored rather than forbidden.
    #[test]
    fn a_seed_path_left_over_on_a_device_state_is_not_forbidden() {
        let (_, violations) = run(|c| {
            pkcs11(c);
            c.signing_key_seed = "/seed".to_string();
        });
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn the_sts_endpoint_needs_the_credential_mode_it_parameterizes() {
        let (_, violations) = run(|c| {
            aws(c);
            c.aws_sts_endpoint = Some("https://sts.eu-north-1.amazonaws.com".to_string());
        });
        assert!(
            violations.iter().any(|v| v.contains("--aws-sts-endpoint")),
            "{violations:?}"
        );
    }
}
