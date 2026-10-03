// SPDX-License-Identifier: Apache-2.0
//! The credential a bodyless acknowledgement is signed under: read, chained, and scoped.
//!
//! Everything here is about the `mcp-re-delegation` header rather than about the message
//! carrying it. Three facts, and the third is the one that would be easy to lose.
//!
//! There is no body-declared `server_signer` to cross-check — there is no body — so the
//! credential's own root-signed `mcp_re_server_signer` is the only value available, and
//! feeding it back in as `expected_server_signer` makes the §3 step-5 scope comparison
//! `x != x`, a check that cannot fail. The root-signed scope is therefore bound to two
//! facts it does not get to choose: the root the trust seam resolved (the scope's role,
//! trust domain and subject must be that root's principal) and the delegated kid the
//! response actually signed under ([`check_scope_names_the_signing_key`]).

use crate::block::ActorIdentity;
use crate::block::ResolverOutcome;
use crate::block::SignerSlot;
use crate::error::HttpProfileError;
use crate::ids::PROFILE_TAG;
use crate::message::single_header;
use crate::verify::full::delegated::speaks_for;

/// The delegation credential: present EXACTLY once and size-bounded.
///
/// `single_header` fails closed on a duplicate, and the bound is checked before any parsing
/// — a header this profile cannot carry is refused rather than decoded.
pub(super) fn read_credential(headers: &[(String, String)]) -> Result<String, HttpProfileError> {
    let credential = single_header(headers, crate::ids::MCP_RE_DELEGATION_HEADER)?
        .ok_or(HttpProfileError::DelegationCredentialMissing)?;
    if credential.len() > crate::ids::MAX_DELEGATION_HEADER_LEN {
        return Err(HttpProfileError::MalformedEvidence(
            "delegation header too large",
        ));
    }
    Ok(credential.to_owned())
}

/// Chain the credential to a root this deployment trusts.
///
/// Root resolution goes through the SAME seam every other path uses, so a trust-store
/// OUTAGE is reported as `mcp-re.trust_resolver_unavailable` rather than collapsed into
/// "issuer untrusted", and a resolver returning a Request-slot actor for a Response-slot
/// question is refused. See the matching note in `verify.rs`.
pub(super) fn verify_credential<R: Into<ResolverOutcome>>(
    credential: &str,
    verifier: &crate::verifier::Verifier<'_, R>,
    expect: &crate::verify::DelegationExpectations<'_>,
    is_revoked: &dyn Fn(&str) -> bool,
    now: i64,
) -> Result<(crate::delegation::VerifiedDelegation, ActorIdentity), HttpProfileError> {
    let server_signer = credential_server_signer(credential)?;
    let params = crate::delegation::DelegationVerifyParams {
        now,
        max_clock_skew: expect.max_clock_skew,
        verifier_audiences: expect.verifier_audiences,
        expected_profile: PROFILE_TAG,
        expected_audience_hash: expect.expected_audience_hash,
        expected_server_signer: &server_signer,
        accepted_epochs: expect.accepted_epochs,
    };
    let resolve_failure: std::cell::RefCell<Option<HttpProfileError>> =
        std::cell::RefCell::new(None);
    let resolved_root: std::cell::RefCell<Option<ActorIdentity>> = std::cell::RefCell::new(None);
    let verified = crate::delegation::verify_delegation_credential(
        credential,
        &params,
        |issuer_kid| {
            match verifier.resolve_for_slot(issuer_kid, SignerSlot::Response) {
                Ok(actor) => {
                    *resolved_root.borrow_mut() = Some(actor.identity);
                    Some(actor.verification_key)
                }
                // A definitive "not trusted" stays the credential layer's verdict; only
                // an outage and a wrong-slot actor are propagated. See `verify.rs`.
                Err(HttpProfileError::UnresolvedKeyId) => None,
                Err(e) => {
                    *resolve_failure.borrow_mut() = Some(e);
                    None
                }
            }
        },
        |id| is_revoked(id),
    );
    let verified = verified.map_err(|e| resolve_failure.into_inner().unwrap_or(e))?;
    let scoped = scoped_signer(&server_signer)?;
    if !resolved_root
        .into_inner()
        .is_some_and(|root| speaks_for(&root, &scoped))
    {
        return Err(HttpProfileError::DelegationIssuerUntrusted);
    }
    Ok((verified, scoped))
}

/// Parse the root-signed `mcp_re_server_signer` into the [`ActorIdentity`] it denotes.
///
/// Exactly four `:`-separated fields, each read through the actor-field escape, and the
/// result must re-encode to the same string so a non-canonical escape is refused.
fn scoped_signer(server_signer: &str) -> Result<ActorIdentity, HttpProfileError> {
    let fields: Vec<&str> = server_signer.split(':').collect();
    let [role, trust_domain, subject, keyid] = fields.as_slice() else {
        return Err(HttpProfileError::DelegationCredentialInvalid);
    };
    let identity = ActorIdentity {
        role: unescape_actor_field(role),
        trust_domain: unescape_actor_field(trust_domain),
        subject: unescape_actor_field(subject),
        keyid: unescape_actor_field(keyid),
    };
    if identity.actor_id() != server_signer {
        return Err(HttpProfileError::DelegationCredentialInvalid);
    }
    Ok(identity)
}

/// The credential's scope names the key the response actually signed under.
///
/// Two comparisons, both against the delegated kid. The response's own `keyid` must be the
/// delegated key; and the keyid of the credential's ROOT-SIGNED scope must name that same
/// key — the bodied path gets this from the block
/// (`block.server_signer.keyid != verified.delegated_kid`).
///
/// A credential scoped to one server signer but presented for a different delegated key is
/// refused, which is the property the scope gate exists for and which comparing the value
/// against itself could never establish.
pub(super) fn check_scope_names_the_signing_key(
    key_id: &str,
    server_signer: &ActorIdentity,
    delegated_kid: &str,
) -> Result<(), HttpProfileError> {
    if key_id != delegated_kid || server_signer.keyid != delegated_kid {
        return Err(HttpProfileError::DelegationKeyMismatch);
    }
    Ok(())
}

/// Reverse `block::field_escape` for one `actor_id` field.
fn unescape_actor_field(field: &str) -> String {
    field
        .replace("%1F", "\u{1F}")
        .replace("%3A", ":")
        .replace("%25", "%")
}

/// Read the `mcp_re_server_signer` claim from a compact-JWS credential's payload WITHOUT
/// verifying it.
///
/// The value is used only as the `expected_server_signer` the full verification then
/// re-derives and roots. Reading it here does not trust it;
/// [`crate::delegation::verify_delegation_credential`] proves the whole payload against the
/// root.
fn credential_server_signer(compact_jws: &str) -> Result<String, HttpProfileError> {
    let payload_seg = compact_jws
        .split('.')
        .nth(1)
        .ok_or(HttpProfileError::DelegationCredentialInvalid)?;
    let bytes = mcp_re_core::b64url_decode(payload_seg)
        .map_err(|_| HttpProfileError::DelegationCredentialInvalid)?;
    let v: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| HttpProfileError::DelegationCredentialInvalid)?;
    v.get("mcp_re_server_signer")
        .and_then(|s| s.as_str())
        .map(str::to_owned)
        .ok_or(HttpProfileError::DelegationCredentialInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The substantive scope check compares the credential's SCOPE against the key the
    /// response signed under. Comparing the credential's own server-signer claim against
    /// itself is `x != x` and can never fail, which is why this comparison — against a
    /// field the credential does not choose freely — is the one that carries the property.
    #[test]
    fn a_credential_scoped_to_another_signer_is_refused() {
        let scoped = scoped_signer("mcp-re:server:example.org:delegated-a").expect("canonical");
        assert!(check_scope_names_the_signing_key("delegated-a", &scoped, "delegated-a").is_ok());
        assert!(matches!(
            check_scope_names_the_signing_key("delegated-b", &scoped, "delegated-b"),
            Err(HttpProfileError::DelegationKeyMismatch)
        ));
        assert!(matches!(
            check_scope_names_the_signing_key("delegated-b", &scoped, "delegated-a"),
            Err(HttpProfileError::DelegationKeyMismatch)
        ));
    }

    /// The scope must be the canonical four-field actor id its documentation says it is.
    #[test]
    fn a_scope_that_is_not_a_canonical_four_field_actor_id_is_refused() {
        for bad in [
            "delegated-a",
            "a:b:c:d:e",
            "server:example.org:did%3aexample:k",
        ] {
            assert!(matches!(
                scoped_signer(bad),
                Err(HttpProfileError::DelegationCredentialInvalid)
            ));
        }
        let id = ActorIdentity {
            role: "server".into(),
            trust_domain: "example.org".into(),
            subject: "did:example:s".into(),
            keyid: "k".into(),
        };
        assert_eq!(scoped_signer(&id.actor_id()).expect("canonical"), id);
    }

    /// The scoped keyid is read through the actor-field escape, so a keyid containing a
    /// literal `:` still compares as the one value it is rather than as its tail.
    #[test]
    fn the_scoped_keyid_is_read_through_the_actor_field_escape() {
        assert_eq!(unescape_actor_field("a%3Ab"), "a:b");
        assert_eq!(unescape_actor_field("a%25b"), "a%b");
        assert_eq!(unescape_actor_field("a%1Fb"), "a\u{1F}b");
    }

    /// A duplicated credential header fails closed rather than picking one, and one over
    /// the carried bound is refused before any parsing.
    #[test]
    fn the_credential_header_is_present_exactly_once_and_bounded() {
        let header = crate::ids::MCP_RE_DELEGATION_HEADER;
        let one = vec![(header.to_owned(), "a.b.c".to_owned())];
        assert_eq!(read_credential(&one).expect("single"), "a.b.c");

        let duplicated = vec![
            (header.to_owned(), "a.b.c".to_owned()),
            (header.to_owned(), "d.e.f".to_owned()),
        ];
        assert!(read_credential(&duplicated).is_err());

        let oversized = vec![(
            header.to_owned(),
            "x".repeat(crate::ids::MAX_DELEGATION_HEADER_LEN + 1),
        )];
        assert!(matches!(
            read_credential(&oversized),
            Err(HttpProfileError::MalformedEvidence(
                "delegation header too large"
            ))
        ));

        assert!(matches!(
            read_credential(&[]),
            Err(HttpProfileError::DelegationCredentialMissing)
        ));
    }
}
