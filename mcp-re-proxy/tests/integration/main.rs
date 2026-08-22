// SPDX-License-Identifier: Apache-2.0
//! Integration suites that link the PLAIN proxy library, in one binary.
//!
//! Cargo compiles every `tests/*.rs` into a SEPARATE executable, and every executable
//! statically links the whole graph — rustls, ring, tokio, hyper. On this workspace that
//! link costs about sixteen seconds per binary and is the dominant cost of the gate: the
//! suites below run in well under a second combined, and took minutes to become runnable.
//! Grouping them pays that link once.
//!
//! # Why grouping follows the crate variant
//!
//! The group is not "whichever tests happened to be cheap to move". Bazel builds the proxy
//! library in several variants — plain, `async_serve`, and the extended backends — and a
//! `rust_test` links exactly ONE of them. Cargo hides this by unifying features across the
//! build; Bazel does not, and the `async_serve` lane is the only place some tests run at
//! all. So a merged binary may only contain suites that link the same variant, and this
//! one holds the plain-library suites. The `async_serve` suites live in
//! `tests/integration_async/`.
//!
//! # What may live here
//!
//! Only tests that are indifferent to sharing a process. Everything in this directory runs
//! in one address space, on the shared libtest thread pool, so a test that sets a process
//! environment variable, installs a global default, or re-executes itself does NOT belong
//! here — it belongs in its own `tests/*.rs`, where the process boundary it depends on is
//! real. That boundary is the reason those files stay separate, not an oversight.

#[path = "../serving_fixtures/mod.rs"]
mod serving_fixtures;
#[path = "../startup_transcript/mod.rs"]
mod startup_transcript;

mod app_startup_characterization_test;
mod certificate_identity_no_fallback_test;
mod composition_raw_read_test;
mod config_legality_characterization_test;
mod config_refusal_precedence_test;
mod documented_cli_test;
mod exchange_transition_ownership_test;
mod http_profile_dispatch_test;
mod mtls_transport_binding_test;
mod plane_config_reachback_test;
mod revocation_serving_wiring_test;
mod tls_test;
