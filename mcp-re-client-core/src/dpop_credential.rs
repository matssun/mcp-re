// SPDX-License-Identifier: Apache-2.0
//! The OAuth credential a signed request is bound to, and the one place the binding and
//! the covered header are derived from it.
//!
//! One fact: **a request that carries a DPoP binding carries a credential.**
//!
//! # The defect this module exists to remove
//!
//! Both published SDK bindings minted the DPoP artifact binding unconditionally from a
//! `&str` and covered `Authorization: Bearer {token}` from the same variable. For an empty
//! token that is a signed statement that the request is bound to a credential which does
//! not exist: the digest is the well-known digest of zero bytes, the covered header reads
//! exactly `Bearer `, and `ArtifactBinding::validate` accepts it because the digest of
//! nothing is still a well-formed base64url token.
//!
//! Measured (r12 R12-1460/1461/1462): **nothing downstream refuses it.** Not
//! `ArtifactBinding::opaque_digest`, not `validate`, not the serving-side binding check. A
//! caller whose token fetch returned `""` — an unset variable, a failed refresh returning
//! an empty body, a default-constructed config field — therefore shipped fully valid
//! RFC 9421 signatures whose authorization binding attested to nothing, and the client's
//! own evidence handle was indistinguishable from a properly bound request's.
//!
//! # Why a type and not a check
//!
//! A check at one call site quantifies over that site. There were two — one per SDK — with
//! nothing relating them, which is the shape two independently authored implementations
//! always take. [`DpopCredential`] is the value both bindings now hold: its only
//! constructor is fallible, and the binding and the header are projections OF it rather
//! than two derivations FROM a string. So they still cannot disagree with each other, and
//! now they cannot agree on nothing either.

use mcp_re_http_profile::ArtifactBinding;
use mcp_re_http_profile::ArtifactType;

/// An OAuth credential that exists.
///
/// The representation is private and [`DpopCredential::present`] is the only producer, so
/// holding one means the token was non-empty. There is no `Default`, no `From<&str>` and
/// no accessor returning the raw token — what leaves is the binding and the header value,
/// which is everything a signed request needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpopCredential(String);

/// Why a presented OAuth credential was refused.
///
/// One variant, because there is one rule. It carries no part of the token: a credential
/// is a secret, and a refusal is a diagnostic a caller logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyDpopCredential;

impl std::fmt::Display for EmptyDpopCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "the DPoP credential is empty: a request cannot be bound to a credential it \
             does not carry. Pass the token your provider returned, or sign without a DPoP \
             binding",
        )
    }
}

impl std::error::Error for EmptyDpopCredential {}

impl DpopCredential {
    /// The credential, or a refusal if there is none.
    ///
    /// Emptiness is the whole test, deliberately. A token's SHAPE is the issuer's
    /// business — an opaque handle, a JWT, a reference — and a client that guessed at it
    /// would refuse credentials its own provider issued. What a client can know is whether
    /// it was given one.
    pub fn present(token: &str) -> Result<Self, EmptyDpopCredential> {
        if token.is_empty() {
            return Err(EmptyDpopCredential);
        }
        Ok(DpopCredential(token.to_owned()))
    }

    /// The artifact binding this credential mints.
    pub fn binding(&self) -> ArtifactBinding {
        ArtifactBinding::opaque_digest(ArtifactType::OauthDpop, self.0.as_bytes())
    }

    /// The `Authorization` header value the signature covers.
    ///
    /// Derived from the same private field as [`Self::binding`], which is what keeps the
    /// covered header and the binding describing one credential.
    pub fn authorization_header_value(&self) -> String {
        format!("Bearer {}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// LOAD-BEARING: the reason this type exists. An empty token is not a credential, and
    /// no binding is minted from one.
    #[test]
    fn an_empty_credential_is_refused_rather_than_bound_over_nothing() {
        assert_eq!(DpopCredential::present(""), Err(EmptyDpopCredential));
    }

    /// The refusal tells a caller what to do and does not print the credential — which on
    /// this path is the one value that must not reach a log.
    #[test]
    fn the_refusal_names_the_rule_without_carrying_a_credential() {
        let why = EmptyDpopCredential.to_string();
        assert!(why.contains("empty"), "{why}");
        assert!(why.contains("DPoP"), "{why}");
    }

    /// POSITIVE CONTROL: an ordinary credential still binds, and the binding is the same
    /// one the previous unconditional mint produced — this closes a hole, it does not
    /// change what a correctly-bound request looks like on the wire.
    #[test]
    fn a_present_credential_mints_the_binding_it_always_did() {
        let credential = DpopCredential::present("access-token").expect("a real token");
        assert_eq!(
            credential.binding(),
            ArtifactBinding::opaque_digest(ArtifactType::OauthDpop, b"access-token")
        );
        assert_eq!(
            credential.authorization_header_value(),
            "Bearer access-token"
        );
    }

    /// THE PROPERTY THE TWO PROJECTIONS HAVE TOGETHER: they read one private field, so a
    /// binding and a covered header that came from the same value describe the same
    /// credential. Two different credentials produce two different bindings AND two
    /// different headers — never one of each.
    #[test]
    fn the_binding_and_the_covered_header_cannot_describe_different_credentials() {
        let a = DpopCredential::present("token-a").expect("a real token");
        let b = DpopCredential::present("token-b").expect("a real token");
        assert_ne!(a.binding(), b.binding());
        assert_ne!(
            a.authorization_header_value(),
            b.authorization_header_value()
        );
    }

    /// A single space is a credential as far as this owner is concerned, and that is the
    /// honest limit: only EMPTINESS is decidable here. A client that inspected the token's
    /// shape would refuse credentials its own provider issued.
    #[test]
    fn only_emptiness_is_decided_here() {
        assert!(DpopCredential::present(" ").is_ok());
        assert!(DpopCredential::present("not-a-jwt").is_ok());
    }
}
