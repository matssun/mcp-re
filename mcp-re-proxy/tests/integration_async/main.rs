// SPDX-License-Identifier: Apache-2.0
//! Integration suites that link the `async_serve` proxy library, in one binary.
//!
//! The companion of `tests/integration/main.rs`; that file carries the full argument for
//! why these suites are grouped and why the grouping follows the crate variant rather than
//! convenience. The short form: a `rust_test` links one variant of the proxy library, and
//! these link the `async_serve` one.
//!
//! Membership is subject to the same rule: everything here shares one process, so a suite
//! that mutates process environment, installs a global default, or re-executes itself
//! stays in its own `tests/*.rs`. `async_drain_test` is the standing example — it runs
//! under `RUST_TEST_THREADS=1`, which is a property of a binary, not of a test.

#[path = "../common/mod.rs"]
mod common;

mod admission_currency_serving_test;
mod async_replay_test;
mod config_snapshot_hot_reload_test;
mod delegated_client_server_e2e_test;
mod delegated_production_wiring_test;
mod delegated_serving_test;
mod forwarded_body_fidelity_test;
mod http_inner_test;
mod mrt_continuation_serving_test;
mod mtls_client_leg_e2e_test;
mod per_request_revocation_test;
mod replay_race_harness_test;
mod rfc9421_round_trip_test;
mod root_authority_manifest_test;
mod root_key_lifecycle_test;
mod transparency_e2e_test;
mod verified_context_carrier_test;
