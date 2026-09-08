// SPDX-License-Identifier: Apache-2.0
//! Registering an attestation with an external Transparency Service.
//!
//! The last hop of ADR-MCPRE-054, and the externalization census's G-1: everything either
//! side of it was already real — the archive, the reconstruction, the Signed Statement,
//! the offline verification of a receipt about it — and the hop itself did not exist. The
//! only producer of a Receipt anywhere in this workspace was an in-process prototype log.
//!
//! ## Two layers, and the reason the boundary is where it is
//!
//! ```text
//! auditor
//!   ↓
//! TransparencyRegistration        semantic capability — "this statement was registered,
//!   ↓                             and here is a receipt that verifies against it"
//!   ├─ Scrapi11RegistrationClient      mechanism leaf — one draft revision's state machine
//!   └─ CapsuleAnchorRegistrationClient mechanism leaf — one operated service's contract
//! ```
//!
//! **Two leaves, not one leaf with a path flag.** The second peer differs from the first on
//! every axis a leaf owns — resource, request media type, success shape, and whether there
//! is any polling at all — so it is a second leaf. A `--registration-path` would have let
//! one client reach the other service by coincidence of shape while calling a different
//! contract by SCRAPI's name. The operator therefore NAMES the protocol
//! ([`protocol::RegistrationProtocol`]), the selection is made once in [`target`], and it
//! travels into the artifact so a claim can never exceed the peer that answered.
//!
//! **SCRAPI is a DRAFT.** As of this writing the protocol is
//! `draft-ietf-scitt-scrapi-11` — an Internet-Draft, **not** a published RFC. Drafts are
//! renumbered, restructured and withdrawn, and this one names its own media types and
//! status semantics. That is precisely why the revision is a leaf: the version pin belongs
//! to the thing that speaks it.
//!
//! So no SCRAPI term crosses upward. Not into retained evidence, not into the attestation,
//! not into receipt semantics, and not into the auditor's durable products. What the layer
//! above sees is a capability and a refusal vocabulary that would read the same against a
//! successor protocol; what changes when the draft moves is one module.
//!
//! ## A receipt is not accepted because HTTP succeeded
//!
//! A mechanism can return receipt BYTES and nothing more — [`TransparencyRegistration`]'s
//! signature says so. The only thing that produces a [`RegisteredStatement`] is
//! [`register_and_verify`], which puts those bytes through the existing OFFLINE verifier
//! against the exact statement submitted and the operator's already-loaded trust pin. A
//! `201 Created` establishes that a server said yes; it establishes nothing about the
//! bytes it said yes with.
//!
//! No key is fetched or refreshed during that verification. The pin was loaded before the
//! audit began, and a verifier that reached out for a key while checking a receipt would
//! be verifying against whatever the network offered at that moment.
//!
//! ## Certainty is preserved, not collapsed
//!
//! The one thing this layer must never do is report *did not register* for *may have
//! registered*. A `202 Accepted` whose polling budget runs out, a transport failure after
//! the statement went out, a `201` whose body will not parse — in every one of those the
//! service may hold the statement. They are [`RegistrationError::Indeterminate`], and only
//! an explicit refusal status is [`RegistrationError::Refused`].

/// WHAT registering establishes, and what it refuses in.
mod capability;

/// ONE HTTP EXCHANGE — the seam both mechanism leaves are built on.
///
/// Here rather than inside either leaf because it carries no protocol vocabulary: its
/// types are `method`, `url`, `headers`, `body` and `status`, which is what HTTP is. It sat
/// inside the SCRAPI leaf while that was the only mechanism, and the second one reaching
/// across for it would have made a sibling's internals a dependency.
mod exchange;

/// The `capsule-anchor` mechanism leaf — one operated service's contract.
mod capsule_anchor;

/// WHICH registration protocol this run speaks.
mod protocol;

/// HOW LONG a registration may take, and how often it may ask.
mod policy;

/// The SCRAPI mechanism leaf — one draft revision's state machine.
mod scrapi;

/// The `ureq` transport. Behind the feature that links an HTTP client, for the reason
/// `outbound_fetch::binding` states: the default serving closure links none.
#[cfg(feature = "scitt_registration")]
mod ureq_exchange;

/// WHERE this run registers, admitted — and the mechanism that selection picks.
///
/// The module is `endpoint`, not `target`: a source directory named `target` is swallowed by
/// this repository's `target/` build-output ignore, silently, and `scripts/bazel_srcs_gate.py`
/// is what found the file that never got committed.
mod endpoint;

// Only three names leave this subtree, and each one has a caller outside it: the
// attestation artifact takes a `RegisteredStatement` as proof that a receipt verified, the
// audit's refusal type carries a `RegistrationError`, and the invocation holds a
// `RegistrationTarget`. Everything else — the capability trait, the budget, the seam and
// the mechanism leaf itself — is reachable only from inside, which is what keeps the
// mechanism a selection made here rather than a type the layer above can name.
pub use capability::RegisteredStatement;
pub use capability::RegistrationError;
pub(super) use endpoint::RegistrationTarget;
pub(super) use protocol::RegistrationProtocol;

#[cfg(test)]
mod fixtures {
    //! Test fixtures shared by this subtree's owners.
    //!
    //! Inline rather than a file, for the reason `scitt`'s are: `scripts/module_size_gate.py`
    //! reads FILES and cannot see a `#[cfg(test)]` on a `mod` line, so a fixture file would
    //! be counted as production code. The module is the same either way.
    //!
    //! It exists because every proposition here is about a REGISTERED statement, and
    //! reaching that state costs a signing key, a log key, a pin and a statement. Building
    //! them per owner would let the owners disagree about what a fixture is.
    //!
    //! Nothing here asserts anything.

    use mcp_re_core::SigningKey;
    use mcp_re_http_profile::scitt::ScittServiceTrustPin;
    use mcp_re_http_profile::scitt::SignedStatement;
    use mcp_re_http_profile::HttpProfileError;

    pub(super) const TS_KID: &str = "hermetic-ts-1";
    pub(super) const ISSUER_KID: &str = "auditor-1";

    pub(super) fn issuer() -> SigningKey {
        SigningKey::from_seed_bytes(&[77_u8; 32])
    }

    pub(super) fn ts() -> SigningKey {
        SigningKey::from_seed_bytes(&[88_u8; 32])
    }

    /// The external-signer seam COSE issuance takes: raw signature bytes.
    pub(super) fn sign_with(
        key: SigningKey,
    ) -> impl Fn(&[u8]) -> Result<Vec<u8>, HttpProfileError> {
        move |preimage: &[u8]| {
            mcp_re_core::b64url_decode(&key.sign(preimage))
                .map_err(|_| HttpProfileError::InvalidSignature)
        }
    }

    /// A pin naming the log key, with the profiles the prototype log actually uses.
    pub(super) fn pin() -> ScittServiceTrustPin {
        let document = serde_json::json!({
            "schema": mcp_re_http_profile::scitt::TRUST_PIN_SCHEMA,
            "service_identifier": "hermetic-service",
            "discovery_method": "well-known-scitt-keys",
            "discovery_uri": "https://ts.example.test/.well-known/scitt-keys",
            "fetched_at": "2026-09-08T00:00:00Z",
            "kid": TS_KID,
            "algorithm": "EdDSA",
            "public_key": { "x": ts().public_key().to_b64url() },
            "public_key_thumbprint": "unused-by-these-tests",
            "discovery_document_digest": "unused-by-these-tests",
            "leaf_profile": "statement-bytes",
            "position_profile": "bound",
        });
        serde_json::from_value(document).expect("a legal pin")
    }

    /// A Signed Statement about a record with `hops` hops, issued at `at`.
    pub(super) fn statement(label: mcp_re_http_profile::ChainLabel, at: i64) -> SignedStatement {
        let reconstruction =
            mcp_re_http_profile::ChainReconstruction::from_retained_handles(label, Vec::new());
        let commitment = mcp_re_http_profile::scitt::EvidenceCommitment::from_reconstruction(
            &reconstruction,
            None,
            None,
        );
        mcp_re_http_profile::scitt::issue_signed_statement(
            ISSUER_KID,
            commitment,
            at,
            sign_with(issuer()),
        )
        .expect("a statement")
    }

    /// The statement every lane starts from.
    pub(super) fn a_statement() -> SignedStatement {
        statement(mcp_re_http_profile::ChainLabel::Complete, 1_700_000_100)
    }

    /// A DIFFERENT statement, for the lanes that must not confuse two.
    pub(super) fn another_statement() -> SignedStatement {
        statement(
            mcp_re_http_profile::ChainLabel::Incomplete {
                hop: 2,
                reason: mcp_re_http_profile::IncompleteReason::TerminalExpected,
            },
            1_700_000_200,
        )
    }

    /// A receipt the prototype log really issued for `statement`.
    pub(super) fn receipt_for(statement: &SignedStatement) -> Vec<u8> {
        let mut service = mcp_re_http_profile::scitt::PrototypeTransparencyService::new(TS_KID);
        service
            .register(statement, sign_with(ts()))
            .expect("the prototype log registers it")
            .to_cose()
            .to_vec()
    }
}
