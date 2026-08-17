// SPDX-License-Identifier: Apache-2.0
//! Integration suites that link the extended-backend proxy library, in one binary.
//!
//! The third companion of `tests/integration/main.rs`, which carries the full argument.
//! These link `:mcp_re_proxy_ext` — the variant carrying the Redis, etcd and online-OCSP
//! backends.
//!
//! Each suite keeps its own `#![cfg(feature = …)]`, so the feature that selects a backend
//! still selects exactly its own suite: with `redis_replay` off, the three Redis modules
//! compile to nothing and the binary links without the Redis client. Grouping changes what
//! is LINKED TOGETHER, never what is SELECTED.
//!
//! Membership requires indifference to sharing a process, so `pkcs11_keysource_e2e_test`
//! (which installs a global provider and re-executes itself) and `aws_irsa_web_identity_test`
//! (which mutates process environment) stay in their own binaries.
//!
//! `admission_propagation_measure_test` links this same variant and is nonetheless
//! excluded, for a different reason: it MEASURES a wall-clock interval — the delay from a
//! revoking write returning to a sibling replica refusing — and asserts it against the
//! declared P bound. Sharing a binary means sharing the libtest thread pool AND, here, the
//! very Redis the interval is measured through, so a co-tenant suite's load would land
//! inside the measured window. A number produced under a neighbour's load bounds the
//! neighbour, not the mechanism. It stays separate on the same grounds as
//! `tls_load_harness_bench`.

mod cpstore_etcd_e2e_test;
mod ocsp_e2e_test;
mod redis_continuation_e2e_test;
mod redis_replay_e2e_test;
mod redis_trust_epoch_e2e_test;
