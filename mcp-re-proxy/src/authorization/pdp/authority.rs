// SPDX-License-Identifier: Apache-2.0
//! An authorization authority as THIS DEPLOYMENT enrolled it.

use mcp_re_core::VerificationKey;

/// The name and the root key a trust document enrols together for the
/// `authorization-issuer` slot.
///
/// # Why the name travels with the key
///
/// A decision document carries an `iss` claim and its signer chooses what that says. The
/// deployment's enrolment says which KEY may decide; on its own it says nothing about the
/// NAME an audit record will carry. Resolving a `kid` to a bare key therefore leaves the
/// enforcement point with no enrolled name to attribute a grant to, and the only string in
/// reach is the one the signed document asserts about itself.
///
/// Carrying both in one value is what removes that: the attribution
/// [`crate::authorization::pdp::relation`] records is read from the same enrolment entry
/// that supplied the verifying key, so an operator asking *which authority permitted this*
/// is answered with a name their own trust document binds.
///
/// It is the same discipline the request side already keeps — `request_signers` maps a
/// `key_id` to the enrolled SIGNER, never to whatever a request claims about itself.
///
/// # What this owns, and what it does not
///
/// The fields are private, so a consumer cannot destructure one and re-form it with a
/// different name beside the same key; the pair is taken or left whole. That is the whole
/// of the invariant this type owns.
///
/// It is **not** sealed. [`EnrolledAuthority::enrolled`] is `pub`, because
/// [`crate::authorization::pdp::policy::AuthorizationAuthorityResolver`] is a public seam
/// that a composition root — or the unit's own serving battery — supplies. The sole
/// legitimate producer in this crate is
/// `TrustDocument::authorization_issuers`, which is a sibling module rather than a
/// descendant, so no visibility level available here makes this type's construction the
/// document's alone. Possessing one therefore establishes nothing about enrolment; what
/// establishes it is where the value came from.
#[derive(Debug, Clone)]
pub struct EnrolledAuthority {
    name: String,
    key: VerificationKey,
}

impl EnrolledAuthority {
    /// Pair an enrolled authority's name with the root key enrolled under it.
    pub fn enrolled(name: impl Into<String>, key: VerificationKey) -> Self {
        EnrolledAuthority {
            name: name.into(),
            key,
        }
    }

    /// The name this deployment enrolled the authority under.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The root key a decision from this authority is authenticated under.
    pub fn key(&self) -> &VerificationKey {
        &self.key
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::EnrolledAuthority;
    use mcp_re_core::SigningKey;

    fn key(seed: u8) -> mcp_re_core::VerificationKey {
        SigningKey::from_seed_bytes(&[seed; 32]).public_key()
    }

    #[test]
    fn an_enrolled_authority_answers_with_the_name_it_was_enrolled_under() {
        let authority = EnrolledAuthority::enrolled("did:example:pdp", key(7));
        assert_eq!(authority.name(), "did:example:pdp");
        assert_eq!(authority.key().to_b64url(), key(7).to_b64url());
    }

    /// The pair is taken or left whole: there is no projection that yields the key without
    /// the name it was enrolled beside, so a consumer cannot reach one and attribute the
    /// other.
    #[test]
    fn the_name_and_the_key_are_one_value() {
        let authority = EnrolledAuthority::enrolled("did:example:pdp", key(9));
        let cloned = authority.clone();
        assert_eq!(cloned.name(), authority.name());
        assert_eq!(cloned.key().to_b64url(), authority.key().to_b64url());
    }
}
