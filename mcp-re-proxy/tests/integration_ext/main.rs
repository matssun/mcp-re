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

mod cpstore_etcd_e2e_test;
mod ocsp_e2e_test;
mod redis_continuation_e2e_test;
mod redis_replay_e2e_test;
mod redis_trust_epoch_e2e_test;
