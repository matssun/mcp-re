// SPDX-License-Identifier: Apache-2.0
//! Turning a validated deployment's plans into the capabilities that serve it.
//!
//! ADR-MCPRE-067 §23 Phase 8. These functions used to live in `cli.rs`, beside argument
//! parsing, which put two unrelated authorities in one file: reading a flat command line,
//! and opening a token or a KMS client. They are here because THIS is the layer they
//! belong to, and the direction the ADR asks for runs one way:
//!
//! ```text
//! semantic request
//!         ↓
//! validated semantic state / plan
//!         ↓
//! mechanism materializer          ← this module
//!         ↓
//! AWS / GCP / PKCS#11 / TLS / OCSP adapters
//! ```
//!
//! **The live materializers re-read no raw CLI value and re-decide no legality.**
//! `build_key_source` and `admit_key_files` take a CLASSIFIED state or a projection of one,
//! so the questions they could have re-asked — which mechanism, whether the request was
//! coherent, whether a key file may be group-readable — were answered above them. What they
//! add is the part only this layer can do: fail because THIS BUILD has no backend, or because
//! the token or the KMS did not answer.
//!
//! Two materializers are the exception: `build_attested_ingress_binding` and
//! `build_ocsp_checker` take the `DeploymentRequest`. The validation boundary refuses their
//! modes (Mode C attested ingress, `--client-ocsp require`) in every build, so no classified
//! state exists for them and neither has a production caller; they are retained deferred
//! capabilities. `build_attested_ingress_binding` therefore re-checks the audience shape
//! locally. `build_ocsp_checker` is gated on the `online_ocsp` feature.

pub mod ingress;
/// The environmental half of key-file custody: observe the real objects and apply the
/// policy `config_state::key_file_access` owns.
pub mod key_file_custody;
pub mod key_source;
#[cfg(feature = "online_ocsp")]
pub mod revocation;

pub use ingress::build_attested_ingress_binding;
pub use key_file_custody::admit_key_files;
pub use key_file_custody::AdmittedKeyFiles;
pub use key_source::{build_key_source, MaterializedSigningRoles};
#[cfg(feature = "online_ocsp")]
pub use revocation::build_ocsp_checker;
