// SPDX-License-Identifier: Apache-2.0
//! The `Custody` configuration machine — `work/CONFIG-STATE-ATLAS.md` §C.3.
//!
//! Where the Ed25519 response-signing key lives, and therefore what an operator is
//! entitled to believe about it. Five states:
//!
//! | State | Required | Guards |
//! |---|---|---|
//! | `FileSeed` | seed | — |
//! | `EnvSeed` | seed | — |
//! | `Pkcs11` | module, pin file, token label, key label | — |
//! | `AwsKms` | region, key id | endpoint authority |
//! | `GcpKms` | key version | endpoint authority |
//!
//! **Each state carries the material it requires.** The columns above are what the state
//! is inhabited BY, not merely what is checked before it is named — so `build_key_source`
//! has nothing to reconstruct, and a state that could not be built is not built.
//!
//! **Which state a binary can ESTABLISH is layer B and not decided here.** `Pkcs11` is a
//! coherent request in a build without `pkcs11_keysource`; `build_key_source` refuses it,
//! and that refusal is a statement about the executable rather than about the request
//! (CF-05).
//!
//! **The forbidden column is gone because the request no longer has one.** It carried nine
//! refusals of the form *"`--aws-kms-region` belongs to a different custody source"*,
//! which existed because `key_source` was a selector beside every provider's parameters.
//! [`SigningSourceRequest`](crate::deployment_request::SigningSourceRequest) is a tagged
//! union, so a GCP selection has nowhere to put an AWS region (ADR-MCPRE-067 §7). What
//! survives is the one refusal that is INTRA-mechanism — an STS endpoint beside the
//! credential mode it does not parameterize — because both of those belong to one payload.
//!
//! **What this machine decides and what it merely carries are different projections.**
//! [`CustodyState::exposure`] is the durable proposition — whether private key material
//! can enter this process — and it is what downstream policy consumes; it would survive
//! every mechanism here being replaced. [`CustodyState::material`] is the mechanism
//! payload and names its provider, because selecting a backend is materialization's own
//! job (ADR-MCPRE-067 §6, §8).

use crate::config_state::kms_endpoint::guarded_endpoint;
use crate::deployment_request::{
    AwsKmsSigningSourceRequest, DeploymentRequest, SigningSourceRequest,
};

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
        /// Overrides the regional STS default, already held to the endpoint-authority
        /// guard. Held here because it parameterizes THIS mode: it is refused beside
        /// `StaticEnv`, where it would name an endpoint nothing contacts.
        sts_endpoint: Option<String>,
    },
}

/// What may be believed about the response-signing key, and what it is inhabited by.
///
/// Each variant carries the material its own row requires, so nothing downstream re-reads
/// the request for it. Two projections, at two altitudes: [`Self::exposure`] is the
/// durable proposition and names no provider; [`Self::material`] is the mechanism payload
/// and names one, because its consumer is the materializer that must pick a backend.
/// Whether private signing-key material can enter this process.
///
/// The durable proposition custody establishes, and the one downstream policy asks about.
/// It would survive every mechanism below it being replaced: a threshold signer, a
/// hardware enclave or a mechanism not yet invented establishes `NonExporting` exactly as
/// today's three do, and no consumer of this fact changes (ADR-MCPRE-067 §5, §8).
///
/// This is deliberately NOT a list of products. A consumer that asked *"is this AWS?"*
/// would be asking a question whose answer stops being the one it wanted the moment a
/// fourth mechanism arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateKeyExposure {
    /// The private key is readable by this process: it is loaded from a seed and held in
    /// memory, so anything that can read this process's memory or its seed can sign.
    ProcessReadable,
    /// The private key stays behind a signer that will not export it. This process can ask
    /// for a signature and can never obtain the key.
    NonExporting,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyState {
    kind: CustodyKind,
}

/// The five states, as the owner's own representation.
///
/// Private to this module: every consumer lives in this crate, so `pub` variants would let
/// any of them assemble a custody state whose material no validator saw — a PKCS#11 token
/// with an arbitrary PIN file, or a KMS key in a region the deployment never named.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CustodyKind {
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

/// What custody a key source must be built from, as a borrowed view of the state.
///
/// Matchable, because selecting a backend is materialization's own job, and borrowed,
/// because it is a way to READ a custody state and not a way to assemble one. A consumer
/// holding this cannot construct a [`CustodyState`], so the material it reads is the
/// material the validator accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyMaterial<'a> {
    /// A seed file on disk.
    FileSeed {
        /// Path to the 32-byte seed.
        seed_path: &'a str,
    },
    /// A seed in an environment variable — dev/CI only.
    EnvSeed {
        /// Name of the variable holding the seed, NOT a path.
        env_var: &'a str,
    },
    /// A PKCS#11 token; the key is exercised via `C_Sign` and never leaves the device.
    Pkcs11 {
        /// Path to the PKCS#11 provider library.
        module: &'a str,
        /// Path to the file holding the User PIN.
        pin_file: &'a str,
        /// The token holding the key.
        token_label: &'a str,
        /// The signing key object on it.
        key_label: &'a str,
    },
    /// AWS KMS; the key is exercised via `Sign` and never leaves KMS.
    AwsKms {
        /// The region the key lives in.
        region: &'a str,
        /// Key id, ARN or alias.
        key_id: &'a str,
        /// A non-default KMS endpoint, already held to the endpoint-authority guard.
        endpoint: Option<&'a str>,
        /// How this deployment authenticates to KMS.
        credentials: &'a AwsCredentialMode,
    },
    /// GCP Cloud KMS; the key is exercised via `asymmetricSign`.
    GcpKms {
        /// Fully-qualified `projects/.../cryptoKeyVersions/N`.
        key_version: &'a str,
        /// A non-default KMS endpoint, already held to the endpoint-authority guard.
        endpoint: Option<&'a str>,
        /// Take credentials from the metadata server rather than the environment.
        use_metadata: bool,
    },
}

impl CustodyState {
    /// The material a key source must be built from.
    ///
    /// The projection replaces a match on the representation performed where the key
    /// source is built. Which backend a state names, and which values that backend needs,
    /// is this machine's semantics.
    pub fn material(&self) -> CustodyMaterial<'_> {
        match &self.kind {
            CustodyKind::FileSeed { seed_path } => CustodyMaterial::FileSeed { seed_path },
            CustodyKind::EnvSeed { env_var } => CustodyMaterial::EnvSeed { env_var },
            CustodyKind::Pkcs11 {
                module,
                pin_file,
                token_label,
                key_label,
            } => CustodyMaterial::Pkcs11 {
                module,
                pin_file,
                token_label,
                key_label,
            },
            CustodyKind::AwsKms {
                region,
                key_id,
                endpoint,
                credentials,
            } => CustodyMaterial::AwsKms {
                region,
                key_id,
                endpoint: endpoint.as_deref(),
                credentials,
            },
            CustodyKind::GcpKms {
                key_version,
                endpoint,
                use_metadata,
            } => CustodyMaterial::GcpKms {
                key_version,
                endpoint: endpoint.as_deref(),
                use_metadata: *use_metadata,
            },
        }
    }

    /// Whether this state's locators name filesystem paths at all.
    ///
    /// False only under the environment-seed state, where every locator this deployment
    /// carries names an environment variable — the TLS ones included, which is why the
    /// answer is custody's and not the TLS machine's. A consumer that stat'ed an env-var
    /// NAME as a path got a check that passed for the wrong reason.
    pub fn locators_are_filesystem_paths(&self) -> bool {
        !matches!(self.kind, CustodyKind::EnvSeed { .. })
    }

    /// Every secret this state keeps on local disk.
    ///
    /// The question a permissions floor is enforced against, answered by the machine that
    /// knows which of its states put a secret on disk. The PKCS#11 User PIN file is here
    /// because it is the credential that unlocks the token holding the signing and TLS
    /// keys: a group- or world-readable PIN file is as good as a readable key file. The
    /// KMS states keep the signing key in KMS and hold no local secret.
    pub fn disk_secret_paths(&self) -> Vec<&str> {
        match &self.kind {
            CustodyKind::FileSeed { seed_path } => vec![seed_path.as_str()],
            CustodyKind::Pkcs11 { pin_file, .. } => vec![pin_file.as_str()],
            CustodyKind::EnvSeed { .. }
            | CustodyKind::AwsKms { .. }
            | CustodyKind::GcpKms { .. } => Vec::new(),
        }
    }

    /// What may be believed about this deployment's private signing-key material.
    ///
    /// The one semantic projection downstream stages consume. The match is here, in the
    /// owner of the mechanism selection, precisely so that no consumer performs one: a
    /// stage that matched `Pkcs11 | AwsKms | GcpKms` for itself would be rediscovering a
    /// fact this machine already decided, and would need editing for a fourth mechanism
    /// that changes nothing about what it does (ADR-MCPRE-067 §9, §20).
    pub fn exposure(&self) -> PrivateKeyExposure {
        match self.kind {
            CustodyKind::FileSeed { .. } | CustodyKind::EnvSeed { .. } => {
                PrivateKeyExposure::ProcessReadable
            }
            CustodyKind::Pkcs11 { .. }
            | CustodyKind::AwsKms { .. }
            | CustodyKind::GcpKms { .. } => PrivateKeyExposure::NonExporting,
        }
    }
}

/// Build the requested state from the material its row requires.
///
/// `None` when a required value is absent — which is exactly when [`required_violations`]
/// pushes a refusal, so a caller never sees one without the other.
///
/// One arm per mechanism, and each arm reads only its own payload. There is no arm that
/// can read another mechanism's value, because the request has no such value to read.
fn classify(source: &SigningSourceRequest) -> Option<CustodyState> {
    let named = |value: &str| (!value.is_empty()).then(|| value.to_string());
    let kind = match source {
        SigningSourceRequest::File(file) => CustodyKind::FileSeed {
            seed_path: named(&file.seed_path)?,
        },
        SigningSourceRequest::Environment(env) => CustodyKind::EnvSeed {
            env_var: named(&env.seed_var)?,
        },
        SigningSourceRequest::Pkcs11(token) => CustodyKind::Pkcs11 {
            module: token.module.clone()?,
            pin_file: token.pin_file.clone()?,
            token_label: token.token_label.clone()?,
            key_label: token.key_label.clone()?,
        },
        SigningSourceRequest::AwsKms(kms) => CustodyKind::AwsKms {
            region: kms.region.clone()?,
            key_id: kms.key_id.clone()?,
            endpoint: guarded_endpoint("--aws-kms-endpoint", kms.endpoint.as_deref()),
            credentials: aws_credential_mode(kms),
        },
        SigningSourceRequest::GcpKms(kms) => CustodyKind::GcpKms {
            key_version: kms.key_version.clone()?,
            endpoint: guarded_endpoint("--gcp-kms-endpoint", kms.endpoint.as_deref()),
            use_metadata: kms.use_metadata,
        },
    };
    Some(CustodyState { kind })
}

/// Which credential posture an AWS payload names.
///
/// The two inputs are alternatives at the STATE level and not at the request level: the
/// request must be able to hold an STS endpoint beside the static mode in order for
/// [`dangling_sts_endpoint`] to refuse it. Reading them into the sum is this machine's job.
fn aws_credential_mode(kms: &AwsKmsSigningSourceRequest) -> AwsCredentialMode {
    if kms.use_web_identity {
        AwsCredentialMode::WebIdentity {
            sts_endpoint: guarded_endpoint("--aws-sts-endpoint", kms.sts_endpoint.as_deref()),
        }
    } else {
        AwsCredentialMode::StaticEnv
    }
}

/// What the selected mechanism cannot start without.
///
/// Takes the request rather than the built state: this is what runs when the state could
/// NOT be built, so it cannot depend on one existing.
fn required_violations(source: &SigningSourceRequest) -> Vec<String> {
    let mut out = Vec::new();
    let mut require = |present: bool, message: &str| {
        if !present {
            out.push(message.to_string());
        }
    };
    match source {
        SigningSourceRequest::File(file) => require(
            !file.seed_path.is_empty(),
            "--key-source file requires --signing-key-seed <path>: the response-signing key \
             has no other source in this state",
        ),
        SigningSourceRequest::Environment(env) => require(
            !env.seed_var.is_empty(),
            "--key-source env requires --signing-key-seed <env-var-name>",
        ),
        SigningSourceRequest::Pkcs11(token) => {
            require(
                token.module.is_some(),
                "--key-source pkcs11 requires --pkcs11-module <path>",
            );
            require(
                token.pin_file.is_some(),
                "--key-source pkcs11 requires --pkcs11-pin-file <path>; the User PIN is \
                 never accepted on argv, which is world-readable via ps and \
                 /proc/<pid>/cmdline",
            );
            require(
                token.token_label.is_some(),
                "--key-source pkcs11 requires --pkcs11-token-label <label>",
            );
            require(
                token.key_label.is_some(),
                "--key-source pkcs11 requires --pkcs11-key-label <label>",
            );
        }
        SigningSourceRequest::AwsKms(kms) => {
            require(
                kms.region.is_some(),
                "--key-source aws-kms requires --aws-kms-region <region>",
            );
            require(
                kms.key_id.is_some(),
                "--key-source aws-kms requires --aws-kms-key-id <key-id|arn|alias>",
            );
        }
        SigningSourceRequest::GcpKms(kms) => require(
            kms.key_version.is_some(),
            "--key-source gcp-kms requires --gcp-kms-key-version \
             <projects/.../cryptoKeyVersions/N>",
        ),
    }
    out
}

/// An STS endpoint beside the credential mode it does not parameterize.
///
/// The last survivor of the nine-entry forbidden table. It survives because it is
/// INTRA-mechanism: both values belong to the AWS payload, so the tagged union does not
/// make the combination unrepresentable and something still has to refuse it. The other
/// eight were cross-mechanism and are now unstatable.
fn dangling_sts_endpoint(source: &SigningSourceRequest) -> Vec<String> {
    let SigningSourceRequest::AwsKms(kms) = source else {
        return Vec::new();
    };
    if kms.sts_endpoint.is_some() && !kms.use_web_identity {
        return vec![
            "--aws-sts-endpoint has no effect without --aws-kms-use-web-identity".to_string(),
        ];
    }
    Vec::new()
}

/// Classify the requested custody state and check the columns it still has.
///
/// The endpoint-authority guards come first, matching the order an operator already read
/// them in: an overridden KMS endpoint substitutes the root verify key the
/// verify-before-return guardrail is measured against, so it is the graver statement.
///
/// Every violation is reported, not the first.
pub fn classify_and_validate(config: &DeploymentRequest) -> (Option<CustodyState>, Vec<String>) {
    let source = &config.response_signing.source;
    let mut violations = crate::config_state::kms_endpoint::kms_endpoint_refusals(config);
    violations.extend(required_violations(source));
    violations.extend(dangling_sts_endpoint(source));
    (classify(source), violations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_state::test_support::legal_config;
    use crate::deployment_request::{
        EnvironmentSigningSourceRequest, FileSigningSourceRequest, GcpKmsSigningSourceRequest,
        Pkcs11SigningSourceRequest,
    };

    const GCP_KEY_VERSION: &str =
        "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1";

    fn select(config: &mut DeploymentRequest, source: SigningSourceRequest) {
        config.response_signing.source = source;
    }

    fn file_seed(path: &str) -> SigningSourceRequest {
        SigningSourceRequest::File(FileSigningSourceRequest {
            seed_path: path.to_string(),
        })
    }

    fn pkcs11(config: &mut DeploymentRequest) {
        select(
            config,
            SigningSourceRequest::Pkcs11(Pkcs11SigningSourceRequest {
                module: Some("/lib/softhsm.so".to_string()),
                pin_file: Some("/pin".to_string()),
                token_label: Some("token".to_string()),
                key_label: Some("signing".to_string()),
            }),
        );
    }

    fn aws(config: &mut DeploymentRequest) {
        select(
            config,
            SigningSourceRequest::AwsKms(AwsKmsSigningSourceRequest {
                region: Some("eu-north-1".to_string()),
                key_id: Some("alias/signing".to_string()),
                ..AwsKmsSigningSourceRequest::default()
            }),
        );
    }

    fn gcp(config: &mut DeploymentRequest) {
        select(
            config,
            SigningSourceRequest::GcpKms(GcpKmsSigningSourceRequest {
                key_version: Some(GCP_KEY_VERSION.to_string()),
                ..GcpKmsSigningSourceRequest::default()
            }),
        );
    }

    /// The selected PKCS#11 payload, so a case can clear ONE of its values.
    fn token_of(config: &mut DeploymentRequest) -> &mut Pkcs11SigningSourceRequest {
        match &mut config.response_signing.source {
            SigningSourceRequest::Pkcs11(token) => token,
            other => panic!("the fixture selected {other:?}, not PKCS#11"),
        }
    }

    /// The selected AWS KMS payload.
    fn aws_of(config: &mut DeploymentRequest) -> &mut AwsKmsSigningSourceRequest {
        match &mut config.response_signing.source {
            SigningSourceRequest::AwsKms(kms) => kms,
            other => panic!("the fixture selected {other:?}, not AWS KMS"),
        }
    }

    /// The selected GCP Cloud KMS payload.
    fn gcp_of(config: &mut DeploymentRequest) -> &mut GcpKmsSigningSourceRequest {
        match &mut config.response_signing.source {
            SigningSourceRequest::GcpKms(kms) => kms,
            other => panic!("the fixture selected {other:?}, not GCP Cloud KMS"),
        }
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
                |s| matches!(s.material(), CustodyMaterial::FileSeed { .. }),
                "FileSeed",
                |c: &mut DeploymentRequest| select(c, file_seed("/seed")),
            ),
            (
                |s| matches!(s.material(), CustodyMaterial::EnvSeed { .. }),
                "EnvSeed",
                |c: &mut DeploymentRequest| {
                    select(
                        c,
                        SigningSourceRequest::Environment(EnvironmentSigningSourceRequest {
                            seed_var: "MCP_RE_SEED".to_string(),
                        }),
                    );
                },
            ),
            (
                |s| matches!(s.material(), CustodyMaterial::Pkcs11 { .. }),
                "Pkcs11",
                pkcs11,
            ),
            (
                |s| matches!(s.material(), CustodyMaterial::AwsKms { .. }),
                "AwsKms",
                aws,
            ),
            (
                |s| matches!(s.material(), CustodyMaterial::GcpKms { .. }),
                "GcpKms",
                gcp,
            ),
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
        assert_eq!(
            built(|c| select(c, file_seed("/seed"))).exposure(),
            PrivateKeyExposure::ProcessReadable
        );
        for mutate in [pkcs11 as fn(&mut DeploymentRequest), aws, gcp] {
            assert_eq!(built(mutate).exposure(), PrivateKeyExposure::NonExporting);
        }
    }

    /// The generic projection control (ADR-MCPRE-067 §21.4): five unrelated mechanisms
    /// establish ONE semantic fact, and the consumer of that fact is written without
    /// naming any of them. A sixth mechanism joins the left-hand column and
    /// [`may_the_key_be_read_here`] is unchanged.
    #[test]
    fn a_consumer_of_the_exposure_fact_names_no_mechanism() {
        let built = |mutate: fn(&mut DeploymentRequest)| run(mutate).0.expect("a legal state");
        for mutate in [pkcs11 as fn(&mut DeploymentRequest), aws, gcp] {
            assert!(!may_the_key_be_read_here(built(mutate).exposure()));
        }
        assert!(may_the_key_be_read_here(
            built(|c| select(c, file_seed("/seed"))).exposure()
        ));
    }

    /// The consumer under test above and below: it reads the semantic fact and nothing
    /// else, so its text contains no mechanism at all.
    fn may_the_key_be_read_here(exposure: PrivateKeyExposure) -> bool {
        exposure == PrivateKeyExposure::ProcessReadable
    }

    /// The replacement negative control (ADR-MCPRE-067 §21.5).
    ///
    /// A mechanism that exists only in this test — a hypothetical threshold signer and a
    /// hypothetical in-process software vault — drives the SAME consumer through the same
    /// semantic projection. The point is not to support a fake provider; it is that
    /// `may_the_key_be_read_here` cannot be depending on the names of today's five,
    /// because it answers correctly for two it has never heard of.
    ///
    /// If the semantic fact were ever replaced by a provider discriminator, this test
    /// stops compiling — there would be no variant to give a threshold signer.
    #[test]
    fn a_mechanism_that_does_not_exist_drives_the_same_consumer() {
        /// A signer this repository does not have. Its adapter would establish the
        /// generic custody fact exactly as the real ones do.
        enum HypotheticalMechanism {
            ThresholdSigner,
            SoftwareVault,
        }

        impl HypotheticalMechanism {
            /// What a future adapter would report. This is the only line a new mechanism
            /// contributes to the semantic layer.
            fn exposure(&self) -> PrivateKeyExposure {
                match self {
                    HypotheticalMechanism::ThresholdSigner => PrivateKeyExposure::NonExporting,
                    HypotheticalMechanism::SoftwareVault => PrivateKeyExposure::ProcessReadable,
                }
            }
        }

        assert!(!may_the_key_be_read_here(
            HypotheticalMechanism::ThresholdSigner.exposure()
        ));
        assert!(may_the_key_be_read_here(
            HypotheticalMechanism::SoftwareVault.exposure()
        ));
    }

    #[test]
    fn each_state_names_every_parameter_it_cannot_start_without() {
        // One case per required cell, cleared from an otherwise complete state.
        let cases: Vec<Case> = vec![
            ("--signing-key-seed", |c| select(c, file_seed(""))),
            ("--pkcs11-module", |c| {
                pkcs11(c);
                token_of(c).module = None;
            }),
            ("--pkcs11-pin-file", |c| {
                pkcs11(c);
                token_of(c).pin_file = None;
            }),
            ("--pkcs11-token-label", |c| {
                pkcs11(c);
                token_of(c).token_label = None;
            }),
            ("--pkcs11-key-label", |c| {
                pkcs11(c);
                token_of(c).key_label = None;
            }),
            ("--aws-kms-region", |c| {
                aws(c);
                aws_of(c).region = None;
            }),
            ("--aws-kms-key-id", |c| {
                aws(c);
                aws_of(c).key_id = None;
            }),
            ("--gcp-kms-key-version", |c| {
                gcp(c);
                gcp_of(c).key_version = None;
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

    /// The tagged-union disjointness control (ADR-MCPRE-067 §21.3).
    ///
    /// This machine no longer refuses a parameter belonging to another mechanism, because
    /// there is no such request to refuse: a selection carries exactly one payload, and
    /// reading it yields only that mechanism's values. The six cases this test used to
    /// enumerate — an AWS region under a GCP selection and so on — are now rejected by the
    /// compiler rather than by a table, so what remains testable is that a selection is
    /// projected as itself and never as a neighbour.
    ///
    /// The command line can still NAME a stray flag, and that refusal moved to the one
    /// place that can still see both the selection and the stray value: the parser's
    /// `SigningSourceFlags::stray_value_refusal`, which is where its test lives.
    #[test]
    fn a_selection_projects_its_own_material_and_no_neighbours() {
        for (name, mutate) in [
            ("Pkcs11", pkcs11 as fn(&mut DeploymentRequest)),
            ("AwsKms", aws),
            ("GcpKms", gcp),
        ] {
            let state = run(mutate).0.expect("a legal state");
            let projected = matches!(
                (name, state.material()),
                ("Pkcs11", CustodyMaterial::Pkcs11 { .. })
                    | ("AwsKms", CustodyMaterial::AwsKms { .. })
                    | ("GcpKms", CustodyMaterial::GcpKms { .. })
            );
            assert!(projected, "{name} projected {:?}", state.material());
        }
    }

    /// The intra-mechanism refusal the tagged union does NOT make unrepresentable: both
    /// values belong to the AWS payload, so something still has to say that one
    /// parameterizes the other.
    #[test]
    fn an_sts_endpoint_without_the_mode_it_parameterizes_is_refused() {
        let (_, violations) = run(|c| {
            aws(c);
            aws_of(c).sts_endpoint = Some("https://sts.eu-north-1.amazonaws.com".to_string());
        });
        assert!(
            violations
                .iter()
                .any(|v| v.contains("--aws-sts-endpoint")
                    && v.contains("--aws-kms-use-web-identity")),
            "a dangling STS endpoint was accepted: {violations:?}"
        );
    }

    /// Every state carries the material it cannot start without, so `build_key_source` has
    /// nothing left to reconstruct. One case per variant, asserting the values rather than
    /// only the shape — a variant that carried the right number of empty strings would
    /// satisfy the type and fail this.
    #[test]
    fn each_state_carries_the_material_that_made_it_inhabitable() {
        let seed = run(|c| select(c, file_seed("/seed"))).0;
        assert_eq!(
            seed.as_ref().map(CustodyState::material),
            Some(CustodyMaterial::FileSeed { seed_path: "/seed" })
        );

        assert_eq!(
            run(|c| {
                select(
                    c,
                    SigningSourceRequest::Environment(EnvironmentSigningSourceRequest {
                        seed_var: "MCP_RE_SEED".to_string(),
                    }),
                );
            })
            .0
            .as_ref()
            .map(CustodyState::material),
            Some(CustodyMaterial::EnvSeed {
                env_var: "MCP_RE_SEED"
            })
        );

        assert_eq!(
            run(pkcs11).0.as_ref().map(CustodyState::material),
            Some(CustodyMaterial::Pkcs11 {
                module: "/lib/softhsm.so",
                pin_file: "/pin",
                token_label: "token",
                key_label: "signing",
            })
        );

        assert_eq!(
            run(aws).0.as_ref().map(CustodyState::material),
            Some(CustodyMaterial::AwsKms {
                region: "eu-north-1",
                key_id: "alias/signing",
                endpoint: None,
                credentials: &AwsCredentialMode::StaticEnv,
            })
        );

        assert_eq!(
            run(gcp).0.as_ref().map(CustodyState::material),
            Some(CustodyMaterial::GcpKms {
                key_version: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
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
                token_of(c).pin_file = None;
            }) as fn(&mut DeploymentRequest),
            |c: &mut DeploymentRequest| {
                aws(c);
                aws_of(c).key_id = None;
            },
            |c: &mut DeploymentRequest| {
                gcp(c);
                gcp_of(c).key_version = None;
            },
            |c: &mut DeploymentRequest| select(c, file_seed("")),
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
        let state = run(|c| {
            aws(c);
            let kms = aws_of(c);
            kms.use_web_identity = true;
            kms.sts_endpoint = Some("https://sts.eu-north-1.amazonaws.com".to_string());
        })
        .0
        .expect("a complete AWS custody configuration selects the AWS state");
        let CustodyMaterial::AwsKms { credentials, .. } = state.material() else {
            panic!("the AWS state names AWS material");
        };
        assert_eq!(
            credentials,
            &AwsCredentialMode::WebIdentity {
                sts_endpoint: Some("https://sts.eu-north-1.amazonaws.com".to_string()),
            }
        );

        // IRSA without an override is still IRSA, and still not `StaticEnv`.
        let state = run(|c| {
            aws(c);
            aws_of(c).use_web_identity = true;
        })
        .0
        .expect("a complete AWS custody configuration selects the AWS state");
        let CustodyMaterial::AwsKms { credentials, .. } = state.material() else {
            panic!("the AWS state names AWS material");
        };
        assert_eq!(
            credentials,
            &AwsCredentialMode::WebIdentity { sts_endpoint: None }
        );
    }

    /// The qualification on the ruling: a defaulted scalar that every configuration
    /// carries is not evidence of intent, so it is ignored rather than forbidden.
    #[test]
    fn a_seed_path_left_over_on_a_device_state_is_not_forbidden() {
        // The qualification is now structural rather than a decision this machine makes:
        // a PKCS#11 selection has no seed field, so a leftover seed path is not something
        // that can reach here to be ignored.
        let (_, violations) = run(pkcs11);
        assert!(violations.is_empty(), "{violations:?}");
    }

    /// The endpoint fields state a guarantee about the TYPE: an override that failed the
    /// endpoint-authority guard is refused AND absent from the state, so a holder that
    /// keeps the state and drops the violations still cannot reach the named host. The
    /// state itself is still classified — the cross-machine relations need a custody
    /// classification even for a configuration that will be refused.
    #[test]
    fn an_endpoint_the_authority_guard_refused_is_not_carried_by_the_built_state() {
        let hostile = "http://evil.example.com";

        let (state, violations) = run(|c| {
            aws(c);
            aws_of(c).endpoint = Some(hostile.to_string());
        });
        assert!(
            violations.iter().any(|v| v.contains("--aws-kms-endpoint")),
            "{violations:?}"
        );
        let state = state.expect("the AWS state is classified even when its endpoint is refused");
        let CustodyMaterial::AwsKms { endpoint, .. } = state.material() else {
            panic!("the state names AwsKms material");
        };
        assert_eq!(endpoint, None, "a refused KMS authority was carried");

        let (state, violations) = run(|c| {
            aws(c);
            let kms = aws_of(c);
            kms.use_web_identity = true;
            kms.sts_endpoint = Some(hostile.to_string());
        });
        assert!(
            violations.iter().any(|v| v.contains("--aws-sts-endpoint")),
            "{violations:?}"
        );
        let state =
            state.expect("the AWS state is classified even when its STS endpoint is refused");
        let CustodyMaterial::AwsKms { credentials, .. } = state.material() else {
            panic!("the state names AwsKms material");
        };
        assert_eq!(
            credentials,
            &AwsCredentialMode::WebIdentity { sts_endpoint: None },
            "a refused STS authority was carried"
        );

        let (state, violations) = run(|c| {
            gcp(c);
            gcp_of(c).endpoint = Some(hostile.to_string());
        });
        assert!(
            violations.iter().any(|v| v.contains("--gcp-kms-endpoint")),
            "{violations:?}"
        );
        let state = state.expect("the GCP state is classified even when its endpoint is refused");
        let CustodyMaterial::GcpKms { endpoint, .. } = state.material() else {
            panic!("the state names GcpKms material");
        };
        assert_eq!(endpoint, None, "a refused KMS authority was carried");
    }

    /// The other direction of the same field: an override that PASSES the guard reaches
    /// the state, so the guarantee is "validated", not "discarded".
    #[test]
    fn an_admissible_endpoint_override_reaches_the_state_it_parameterizes() {
        let (state, violations) = run(|c| {
            aws(c);
            aws_of(c).endpoint = Some("https://kms.eu-north-1.amazonaws.com".to_string());
        });
        assert!(violations.is_empty(), "{violations:?}");
        let state = state.expect("a complete AWS custody configuration selects the AWS state");
        let CustodyMaterial::AwsKms { endpoint, .. } = state.material() else {
            panic!("the state names AwsKms material");
        };
        assert_eq!(endpoint, Some("https://kms.eu-north-1.amazonaws.com"));

        let (state, violations) = run(|c| {
            gcp(c);
            gcp_of(c).endpoint = Some("https://cloudkms.googleapis.com".to_string());
        });
        assert!(violations.is_empty(), "{violations:?}");
        let state = state.expect("a complete GCP custody configuration selects the GCP state");
        let CustodyMaterial::GcpKms { endpoint, .. } = state.material() else {
            panic!("the state names GcpKms material");
        };
        assert_eq!(endpoint, Some("https://cloudkms.googleapis.com"));
    }
}
