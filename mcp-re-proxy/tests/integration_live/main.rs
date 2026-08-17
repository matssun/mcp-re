// SPDX-License-Identifier: Apache-2.0
//! The live cloud-KMS suites, in one binary.
//!
//! The fourth companion of `tests/integration/main.rs`, which carries the full argument for
//! grouping. These suites are the most expensive to build and the cheapest to run: each one
//! links the AWS and Google SDKs, and each is `#[ignore]`d, so an ordinary run pays the
//! whole link and executes nothing. Paying it once is the entire point of this file.
//!
//! # Selection is unchanged
//!
//! Every suite keeps both of its guards — its own `#![cfg(feature = "aws_kms_keysource")]`
//! or `#![cfg(feature = "gcp_kms_keysource")]`, and `#[ignore]` on the tests that reach a
//! real cloud. Grouping changes what is linked together, never what is selected, and these
//! still run only when named explicitly with live credentials present.
//!
//! `gcp_kms_live_test` is NOT here: it mutates process environment, and this binary shares
//! one.

#[path = "../common/mod.rs"]
mod common;

mod aws_kms_delegated_required_live_test;
mod aws_kms_delegated_signing_live_test;
mod aws_kms_delegated_tls_live_test;
mod aws_kms_http_profile_live_test;
mod aws_kms_live_test;
mod aws_kms_root_rotation_live_test;
mod gcp_kms_delegated_required_live_test;
mod gcp_kms_delegated_signing_live_test;
mod gcp_kms_delegated_tls_live_test;
mod gcp_kms_http_profile_live_test;
mod gcp_kms_root_rotation_live_test;
