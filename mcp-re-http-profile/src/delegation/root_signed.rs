// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPRE-052 §3 steps 2–3, read by the ISSUING side.
//!
//! An issuance adopts a credential only if the root it is configured with signed it. The
//! check is the verifier's own [`check_root_signature`](super::verify), not a restatement:
//! an issuer and a verifier that disagreed on what "the root signed this" means would mint
//! credentials every verifier in the fleet refuses.

use mcp_re_core::VerificationKey;

use super::decode_json;
use super::split_compact_jws;
use super::verify::check_root_signature;
use crate::error::HttpProfileError;

/// `Ok` iff `jws` is a delegation credential the root `root`, named `kid`, signed.
pub(crate) fn root_signed(
    jws: &str,
    kid: &str,
    root: &VerificationKey,
) -> Result<(), HttpProfileError> {
    let segments = split_compact_jws(jws)?;
    let (header, claims) = (decode_json(segments.0)?, decode_json(segments.1)?);
    check_root_signature(segments, &header, &claims, |k: &str| {
        (k == kid).then(|| root.clone())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation::issue_delegation_credential;
    use crate::delegation::tests::good_claims;
    use crate::delegation::tests::good_header;
    use crate::delegation::tests::ISSUER_KID;
    use mcp_re_core::SigningKey;

    fn credential(signer: &SigningKey) -> String {
        let delegated = SigningKey::from_seed_bytes(&[9u8; 32]).public_key();
        issue_delegation_credential(signer, &good_header(), &good_claims(&delegated))
    }

    /// The root the issuance is configured with is the only one whose signature counts, and
    /// it counts only under the name it was configured with.
    #[test]
    fn only_the_configured_root_under_its_own_name_has_signed() {
        let root = SigningKey::from_seed_bytes(&[1u8; 32]);
        let impostor = SigningKey::from_seed_bytes(&[2u8; 32]);
        assert!(root_signed(&credential(&root), ISSUER_KID, &root.public_key()).is_ok());
        assert!(root_signed(&credential(&impostor), ISSUER_KID, &root.public_key()).is_err());
        assert!(root_signed(&credential(&root), "another-root", &root.public_key()).is_err());
    }
}
