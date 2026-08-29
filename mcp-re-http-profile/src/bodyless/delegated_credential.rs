// SPDX-License-Identifier: Apache-2.0
//! The credential a bodyless acknowledgement is signed under: read, chained, and scoped.
//!
//! Everything here is about the `mcp-re-delegation` header rather than about the message
//! carrying it. Three facts, and the third is the one that would be easy to lose.
//!
//! There is no body-declared `server_signer` to cross-check — there is no body — so the
//! credential's own root-signed `mcp_re_server_signer` is the only value available, and
//! feeding it back in as `expected_server_signer` makes the §3 step-5 scope comparison
//! `x != x`, a check that cannot fail. The SUBSTANTIVE cross-check is
//! [`check_scope_names_the_signing_key`], against a field the credential does not get to
//! choose freely: the delegated kid the response actually signed under.

use crate::block::ResolverOutcome;
use crate::block::SignerSlot;
use crate::error::HttpProfileError;
use crate::ids::PROFILE_TAG;
use crate::message::single_header;
use crate::verify::floor::trust_slot::resolve_actor_for_slot;

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
) -> Result<(crate::delegation::VerifiedDelegation, String), HttpProfileError> {
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
    let verified = crate::delegation::verify_delegation_credential(
        credential,
        &params,
        |issuer_kid| {
            match resolve_actor_for_slot(verifier.resolve_actor(), issuer_kid, SignerSlot::Response)
            {
                Ok(actor) => Some(actor.verification_key),
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
    Ok((verified, server_signer))
}

/// The credential's scope names the key the response actually signed under.
///
/// Two comparisons, both against the delegated kid. The response's own `keyid` must be the
/// delegated key; and the credential's SCOPE must name that same key — the bodied path gets
/// this from the block (`block.server_signer.keyid != verified.delegated_kid`), but here the
/// actor id is the credential's own, so the check is on its keyid field, the last
/// `:`-separated component of the ROOT-SIGNED `mcp_re_server_signer`.
///
/// A credential scoped to one server signer but presented for a different delegated key is
/// refused, which is the property the scope gate exists for and which comparing the value
/// against itself could never establish.
pub(super) fn check_scope_names_the_signing_key(
    key_id: &str,
    server_signer: &str,
    delegated_kid: &str,
) -> Result<(), HttpProfileError> {
    if key_id != delegated_kid {
        return Err(HttpProfileError::DelegationKeyMismatch);
    }
    let scoped_keyid = server_signer
        .rsplit(':')
        .next()
        .ok_or(HttpProfileError::DelegationProfileMismatch)?;
    if unescape_actor_field(scoped_keyid) != delegated_kid {
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
        let scoped = "mcp-re:server:example.org:delegated-a";
        assert!(check_scope_names_the_signing_key("delegated-a", scoped, "delegated-a").is_ok());
        assert!(matches!(
            check_scope_names_the_signing_key("delegated-b", scoped, "delegated-b"),
            Err(HttpProfileError::DelegationKeyMismatch)
        ));
        assert!(matches!(
            check_scope_names_the_signing_key("delegated-b", scoped, "delegated-a"),
            Err(HttpProfileError::DelegationKeyMismatch)
        ));
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
