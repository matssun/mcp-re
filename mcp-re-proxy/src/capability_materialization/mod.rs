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
//! **Nothing here re-reads a raw CLI value, and nothing here re-decides legality.** Every
//! materializer takes a CLASSIFIED state or a projection of one, so the questions it could
//! have re-asked — which mechanism, whether the request was coherent, whether a key file may
//! be group-readable — were all answered above it. What is left is the part only this layer
//! can do: fail because THIS BUILD has no backend, or because the token, the KMS or the
//! responder did not answer.

pub mod ingress;
pub mod key_source;
#[cfg(feature = "online_ocsp")]
pub mod revocation;

pub use ingress::build_attested_ingress_binding;
pub use key_source::{build_key_source, read_pkcs11_pin, MaterializedSigningRoles};
#[cfg(feature = "online_ocsp")]
pub use revocation::build_ocsp_checker;
