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
//! **Each state carries the material it requires.** The columns above are what the state
//! is inhabited BY, not merely what is checked before it is named — so `build_key_source`
//! has nothing to reconstruct, and a state that could not be built is not built. The
//! widest variant holds four values: the twenty custody flags are twenty because they are
//! flat in the request, not because any one custody path is wide.
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

use crate::deployment_request::{DeploymentRequest, KeySourceKind};

/// How the AWS KMS states obtain the credentials they call KMS with.
///
/// A sub-posture of `AwsKms` rather than a machine: credentials to reach KMS mean nothing
/// without a KMS key to reach. Its legality was already complete before it was typed —
/// `--aws-sts-endpoint` is refused without `--aws-kms-use-web-identity`, and both are
/// forbidden outside the AWS state — so this encodes a rule rather than inventing one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AwsCredentialMode {
    /// `EnvCredentialSource`: long-lived IAM key material read from the process
    /// environment. One concrete source, named for what it is — not an SDK discovery
    /// chain, and not a fallback from anything.
    StaticEnv,
    /// IRSA: the projected service-account token is exchanged for temporary credentials,
    /// so no long-lived IAM key material exists in the pod. Chosen by an explicit
    /// operator flag, never by discovery.
    WebIdentity {
        /// Overrides the regional STS default. Held here because it parameterizes THIS
        /// mode: it is refused beside `StaticEnv`, where it would name an endpoint
        /// nothing contacts.
        sts_endpoint: Option<String>,
    },
}

/// Which custody state a configuration requests, and what that state is inhabited by.
///
/// Each variant carries the material its own column requires — nothing downstream re-reads
/// the request for it, and no `require(...)`/`ok_or_else` reconstruction survives past this
/// boundary. The widest variant needs four values: the twenty flags are twenty because they
/// are flat, not because any one custody path is wide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyState {
    /// A seed file on disk.
    FileSeed {
        /// Path to the 32-byte seed.
        seed_path: String,
    },
    /// A seed in an environment variable — dev/CI only.
    EnvSeed {
        /// Name of the variable holding the seed, NOT a path.
        env_var: String,
    },
    /// A PKCS#11 token; the key is exercised via `C_Sign` and never leaves the device.
    Pkcs11 {
        /// Path to the PKCS#11 provider library.
        module: String,
        /// Path to the file holding the User PIN. Never argv: that is world-readable.
        pin_file: String,
        /// The token holding the key.
        token_label: String,
        /// The signing key object on it.
        key_label: String,
    },
    /// AWS KMS; the key is exercised via `Sign` and never leaves KMS.
    AwsKms {
        /// The region the key lives in.
        region: String,
        /// Key id, ARN or alias.
        key_id: String,
        /// A non-default KMS endpoint, already held to the endpoint-authority guard.
        endpoint: Option<String>,
        /// How this deployment authenticates to KMS.
        credentials: AwsCredentialMode,
    },
    /// GCP Cloud KMS; the key is exercised via `asymmetricSign`.
    GcpKms {
        /// Fully-qualified `projects/.../cryptoKeyVersions/N`.
        key_version: String,
        /// A non-default KMS endpoint, already held to the endpoint-authority guard.
        endpoint: Option<String>,
        /// Take credentials from the metadata server rather than the environment.
        use_metadata: bool,
    },
}

impl CustodyState {
    /// Whether the key material is held by a device or KMS rather than by this process.
    ///
    /// The property the three device states share and the two seed states do not, and the
    /// one downstream stages actually ask about.
    pub fn is_non_exporting_device(&self) -> bool {
        matches!(
            self,
            Self::Pkcs11 { .. } | Self::AwsKms { .. } | Self::GcpKms { .. }
        )
    }
}

/// Build the requested state from the material its column requires.
///
/// `None` when a required value is absent — which is exactly when `required_violations`
/// below pushes a refusal, so a caller never sees one without the other.
fn classify(config: &DeploymentRequest) -> Option<CustodyState> {
    let seed = |value: &str| (!value.is_empty()).then(|| value.to_string());
    Some(match config.key_source {
        KeySourceKind::File => CustodyState::FileSeed {
            seed_path: seed(&config.signing_key_seed)?,
        },
        KeySourceKind::Env => CustodyState::EnvSeed {
            env_var: seed(&config.signing_key_seed)?,
        },
        KeySourceKind::Pkcs11 => CustodyState::Pkcs11 {
            module: config.pkcs11_module.clone()?,
            pin_file: config.pkcs11_pin_file.clone()?,
            token_label: config.pkcs11_token_label.clone()?,
            key_label: config.pkcs11_key_label.clone()?,
        },
        KeySourceKind::AwsKms => CustodyState::AwsKms {
            region: config.aws_kms_region.clone()?,
            key_id: config.aws_kms_key_id.clone()?,
            endpoint: config.aws_kms_endpoint.clone(),
            credentials: if config.aws_kms_use_web_identity {
                AwsCredentialMode::WebIdentity {
                    sts_endpoint: config.aws_sts_endpoint.clone(),
                }
            } else {
                AwsCredentialMode::StaticEnv
            },
        },
        KeySourceKind::GcpKms => CustodyState::GcpKms {
            key_version: config.gcp_kms_key_version.clone()?,
            endpoint: config.gcp_kms_endpoint.clone(),
            use_metadata: config.gcp_kms_use_metadata,
        },
    })
}

/// What the selected state cannot start without.
///
/// Takes the requested KIND rather than the built state: this is what runs when the state
/// could NOT be built, so it cannot depend on one existing.
fn required_violations(kind: KeySourceKind, config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    let mut require = |present: bool, message: &str| {
        if !present {
            out.push(message.to_string());
        }
    };
    match kind {
        KeySourceKind::File => require(
            !config.signing_key_seed.is_empty(),
            "--key-source file requires --signing-key-seed <path>: the response-signing key \
             has no other source in this state",
        ),
        KeySourceKind::Env => require(
            !config.signing_key_seed.is_empty(),
            "--key-source env requires --signing-key-seed <env-var-name>",
        ),
        KeySourceKind::Pkcs11 => {
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
        KeySourceKind::AwsKms => {
            require(
                config.aws_kms_region.is_some(),
                "--key-source aws-kms requires --aws-kms-region <region>",
            );
            require(
                config.aws_kms_key_id.is_some(),
                "--key-source aws-kms requires --aws-kms-key-id <key-id|arn|alias>",
            );
        }
        KeySourceKind::GcpKms => require(
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
fn forbidden_violations(kind: KeySourceKind, config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    let mut forbid = |present: bool, owner: KeySourceKind, flag: &str, owning_source: &str| {
        if present && kind != owner {
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
        forbid(present, KeySourceKind::Pkcs11, flag, "pkcs11");
    }
    for (present, flag) in [
        (config.aws_kms_region.is_some(), "--aws-kms-region"),
        (config.aws_kms_key_id.is_some(), "--aws-kms-key-id"),
        (
            config.aws_kms_use_web_identity,
            "--aws-kms-use-web-identity",
        ),
    ] {
        forbid(present, KeySourceKind::AwsKms, flag, "aws-kms");
    }
    for (present, flag) in [
        (
            config.gcp_kms_key_version.is_some(),
            "--gcp-kms-key-version",
        ),
        (config.gcp_kms_use_metadata, "--gcp-kms-use-metadata"),
    ] {
        forbid(present, KeySourceKind::GcpKms, flag, "gcp-kms");
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
pub fn classify_and_validate(config: &DeploymentRequest) -> (Option<CustodyState>, Vec<String>) {
    let mut violations = kms_endpoint_refusals(config);
    violations.extend(required_violations(config.key_source, config));
    violations.extend(forbidden_violations(config.key_source, config));
    (classify(config), violations)
}

/// The KMS/STS endpoint overrides a [`DeploymentRequest`] carries, held to the rule wherever the
/// config came from.
///
/// [`validated_kms_endpoint`] is the decision; this is only how a `DeploymentRequest` answers it, so
/// the two call sites cannot drift into disagreeing about the rule. The three fields are
/// public, and they carry the ROOT-KEY trust bootstrap — on GCP every request to them also
/// carries a live workload-identity bearer token — so a config built in code must not be
/// able to name a plaintext or attacker-chosen authority for them.
pub(crate) fn kms_endpoint_refusals(config: &DeploymentRequest) -> Vec<String> {
    [
        ("--aws-kms-endpoint", config.aws_kms_endpoint.as_deref()),
        ("--aws-sts-endpoint", config.aws_sts_endpoint.as_deref()),
        ("--gcp-kms-endpoint", config.gcp_kms_endpoint.as_deref()),
    ]
    .into_iter()
    .filter_map(|(flag, value)| validated_kms_endpoint(flag, value?).err())
    .collect()
}

/// Validate an operator-supplied KMS endpoint override before anything is sent to it.
///
/// The decision itself is [`crate::kms_endpoint_policy::kms_endpoint_authority`]; this only prefixes the offending
/// flag onto its refusal, so the command line, the validation boundary
/// ([`kms_endpoint_refusals`]) and the three key-source constructors cannot drift into
/// disagreeing about the rule.
pub(crate) fn validated_kms_endpoint(flag: &str, value: &str) -> Result<String, String> {
    crate::kms_endpoint_policy::kms_endpoint_authority(value)
        .map(|_| value.to_string())
        .map_err(|why| format!("{flag} {why}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;

    fn pkcs11(config: &mut DeploymentRequest) {
        config.key_source = KeySourceKind::Pkcs11;
        config.pkcs11_module = Some("/lib/softhsm.so".to_string());
        config.pkcs11_pin_file = Some("/pin".to_string());
        config.pkcs11_token_label = Some("token".to_string());
        config.pkcs11_key_label = Some("signing".to_string());
    }

    fn aws(config: &mut DeploymentRequest) {
        config.key_source = KeySourceKind::AwsKms;
        config.aws_kms_region = Some("eu-north-1".to_string());
        config.aws_kms_key_id = Some("alias/signing".to_string());
    }

    fn gcp(config: &mut DeploymentRequest) {
        config.key_source = KeySourceKind::GcpKms;
        config.gcp_kms_key_version =
            Some("projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1".to_string());
    }

    /// A state this machine must recognise, and how to request it.
    type Form = (
        fn(&CustodyState) -> bool,
        &'static str,
        fn(&mut DeploymentRequest),
    );
    /// A flag a case must name in its refusal, and the configuration that provokes it.
    type Case = (&'static str, fn(&mut DeploymentRequest));

    fn run(mutate: impl FnOnce(&mut DeploymentRequest)) -> (Option<CustodyState>, Vec<String>) {
        let mut config = legal_config();
        mutate(&mut config);
        classify_and_validate(&config)
    }

    #[test]
    fn every_legal_state_form_is_classified_and_accepted() {
        let cases: Vec<Form> = vec![
            (
                |s| matches!(s, CustodyState::FileSeed { .. }),
                "FileSeed",
                |c: &mut DeploymentRequest| c.key_source = KeySourceKind::File,
            ),
            (
                |s| matches!(s, CustodyState::EnvSeed { .. }),
                "EnvSeed",
                |c: &mut DeploymentRequest| c.key_source = KeySourceKind::Env,
            ),
            (
                |s| matches!(s, CustodyState::Pkcs11 { .. }),
                "Pkcs11",
                pkcs11,
            ),
            (|s| matches!(s, CustodyState::AwsKms { .. }), "AwsKms", aws),
            (|s| matches!(s, CustodyState::GcpKms { .. }), "GcpKms", gcp),
        ];
        for (is_expected, name, mutate) in cases {
            let (state, violations) = run(mutate);
            assert!(violations.is_empty(), "{name} refused: {violations:?}");
            let state = state.unwrap_or_else(|| panic!("{name} recognised no state"));
            assert!(is_expected(&state), "{name}: classified as {state:?}");
        }
    }

    #[test]
    fn only_the_device_states_hold_the_key_off_this_process() {
        let built = |mutate: fn(&mut DeploymentRequest)| run(mutate).0.expect("a legal state");
        assert!(!built(|c| c.key_source = KeySourceKind::File).is_non_exporting_device());
        for mutate in [pkcs11 as fn(&mut DeploymentRequest), aws, gcp] {
            assert!(built(mutate).is_non_exporting_device());
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

    /// Every state carries the material it cannot start without, so `build_key_source` has
    /// nothing left to reconstruct. One case per variant, asserting the values rather than
    /// only the shape — a variant that carried the right number of empty strings would
    /// satisfy the type and fail this.
    #[test]
    fn each_state_carries_the_material_that_made_it_inhabitable() {
        let seed = run(|c| {
            c.key_source = KeySourceKind::File;
            c.signing_key_seed = "/seed".to_string();
        })
        .0;
        assert_eq!(
            seed,
            Some(CustodyState::FileSeed {
                seed_path: "/seed".to_string()
            })
        );

        assert_eq!(
            run(|c| {
                c.key_source = KeySourceKind::Env;
                c.signing_key_seed = "MCP_RE_SEED".to_string();
            })
            .0,
            Some(CustodyState::EnvSeed {
                env_var: "MCP_RE_SEED".to_string()
            })
        );

        assert_eq!(
            run(pkcs11).0,
            Some(CustodyState::Pkcs11 {
                module: "/lib/softhsm.so".to_string(),
                pin_file: "/pin".to_string(),
                token_label: "token".to_string(),
                key_label: "signing".to_string(),
            })
        );

        assert_eq!(
            run(aws).0,
            Some(CustodyState::AwsKms {
                region: "eu-north-1".to_string(),
                key_id: "alias/signing".to_string(),
                endpoint: None,
                credentials: AwsCredentialMode::StaticEnv,
            })
        );

        assert_eq!(
            run(gcp).0,
            Some(CustodyState::GcpKms {
                key_version: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
                    .to_string(),
                endpoint: None,
                use_metadata: false,
            })
        );
    }

    /// A refused configuration yields NO state, in exact correspondence with the required
    /// column: a custody state that could be built beside a refusal would be a signer
    /// assembled from material validation rejected.
    #[test]
    fn a_state_missing_its_material_is_not_built() {
        for mutate in [
            (|c: &mut DeploymentRequest| {
                pkcs11(c);
                c.pkcs11_pin_file = None;
            }) as fn(&mut DeploymentRequest),
            |c: &mut DeploymentRequest| {
                aws(c);
                c.aws_kms_key_id = None;
            },
            |c: &mut DeploymentRequest| {
                gcp(c);
                c.gcp_kms_key_version = None;
            },
            |c: &mut DeploymentRequest| {
                c.key_source = KeySourceKind::File;
                c.signing_key_seed = String::new();
            },
        ] {
            let (state, violations) = run(mutate);
            assert!(state.is_none(), "a state was built over a refusal");
            assert!(!violations.is_empty());
        }
    }

    /// The credential mode is CLASSIFIED, so nothing downstream recombines a bool with an
    /// endpoint. `StaticEnv` is one concrete source — `EnvCredentialSource` — rather than
    /// the absence of web identity, and it cannot carry an STS endpoint at all.
    #[test]
    fn the_aws_credential_mode_is_a_posture_and_not_a_flag_beside_an_endpoint() {
        let Some(CustodyState::AwsKms { credentials, .. }) = run(|c| {
            aws(c);
            c.aws_kms_use_web_identity = true;
            c.aws_sts_endpoint = Some("https://sts.eu-north-1.amazonaws.com".to_string());
        })
        .0
        else {
            panic!("a complete AWS custody configuration selects the AWS state");
        };
        assert_eq!(
            credentials,
            AwsCredentialMode::WebIdentity {
                sts_endpoint: Some("https://sts.eu-north-1.amazonaws.com".to_string()),
            }
        );

        // IRSA without an override is still IRSA, and still not `StaticEnv`.
        let Some(CustodyState::AwsKms { credentials, .. }) = run(|c| {
            aws(c);
            c.aws_kms_use_web_identity = true;
        })
        .0
        else {
            panic!("a complete AWS custody configuration selects the AWS state");
        };
        assert_eq!(
            credentials,
            AwsCredentialMode::WebIdentity { sts_endpoint: None }
        );
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
