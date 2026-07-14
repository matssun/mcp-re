// SPDX-License-Identifier: Apache-2.0
//! Root-authority rotation through a SIGNED trust-anchor manifest, with roots
//! AUTO-PROVISIONED by a `TestRootAuthorityProvider` — the hermetic (in-memory)
//! analogue of the live Cloud KMS lane. Proves the "no human creates a root" path end
//! to end: a provider mints Root B on the fly, an org-signed manifest carries the
//! rotation (A → A+B overlap → B, then A revoked), and credentials verify/reject
//! exactly per the manifest — including manifest rollback protection.
//!
//! The IDENTICAL scenario runs against real Cloud KMS roots in
//! `gcp_kms_root_rotation_live_test.rs` (both call `common::run_rotation_scenario`).

mod common;

use common::run_rotation_scenario;
use common::InMemoryTestRootAuthorityProvider;
use common::TestRootAuthorityProvider;

use mcp_re_core::SigningKey;

#[test]
fn root_rotation_via_signed_manifest_with_auto_provisioned_roots() {
    // The provider mints both roots — Root B is created ON THE FLY, no human/console step.
    let mut provider = InMemoryTestRootAuthorityProvider::new();
    let root_a = provider.create_root("A");
    let root_b = provider.create_root("B");
    // The org/admin manifest-signing key (the higher authority that governs which
    // issuer roots are trusted). Pinned by the verifier; a serving proxy cannot forge it.
    let org_key = SigningKey::from_seed_bytes(&[7u8; 32]);

    run_rotation_scenario(&root_a, &root_b, &org_key);
}
