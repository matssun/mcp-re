// SPDX-License-Identifier: Apache-2.0
//! The request evidence block at the signing boundary.
//!
//! [`HttpRequestEvidenceBlock`] keeps public fields: the continuation-unbypassability proof
//! reads `request_block.continuation` directly, and sealing the type would replace that
//! proved read with a getter assumption. Its boundary is enforced here instead: no profile
//! signer emits a signature over a body carrying a block that fails
//! [`HttpRequestEvidenceBlock::validate`] or whose continuation fails
//! [`HttpContinuation::validate_shape`], and no response signer binds to a request carrying
//! one. A verifier refuses such a block anyway; refusing at the signer means the
//! profile never produces signed evidence its own verifier rejects.

use crate::block::HttpContinuation;
use crate::block::HttpRequestEvidenceBlock;
use crate::error::HttpProfileError;
use crate::ids::PROFILE_TAG;
use crate::ids::REQUEST_EVIDENCE_BLOCK_KEY;
use crate::message::HttpRequest;

const WHAT: &str = "request evidence block";

/// Refuse `body` if it carries a request evidence block that does not validate. A body
/// with no block — a floor-profile message, or one that is not a JSON object — passes:
/// whether a block is required is the caller's decision, not this check's.
pub(crate) fn validate_carried(body: &[u8]) -> Result<(), HttpProfileError> {
    match carried(body) {
        Some(block) => validated(block),
        None => Ok(()),
    }
}

/// Refuse `request` unless it carries a request evidence block that validates. For a
/// full-profile response, which binds to that block's request.
pub(crate) fn require_valid(request: &HttpRequest) -> Result<(), HttpProfileError> {
    validated(carried(&request.body).ok_or(HttpProfileError::MissingEvidence(WHAT))?)
}

/// The block value at `_meta[REQUEST_EVIDENCE_BLOCK_KEY]`, as a JSON reader sees it. Whether
/// the rest of the body is one this profile could re-serialize is the body's own check, at
/// the verifier; this one is about the block.
fn carried(body: &[u8]) -> Option<serde_json::Value> {
    let mut root = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    root.get_mut("_meta")?
        .as_object_mut()?
        .remove(REQUEST_EVIDENCE_BLOCK_KEY)
}

fn validated(block: serde_json::Value) -> Result<(), HttpProfileError> {
    let block: HttpRequestEvidenceBlock =
        serde_json::from_value(block).map_err(|_| HttpProfileError::MalformedEvidence(WHAT))?;
    block.validate(PROFILE_TAG)?;
    block
        .continuation
        .as_ref()
        .map_or(Ok(()), HttpContinuation::validate_shape)
}

#[cfg(test)]
pub(crate) fn with_valid_block(body: &[u8]) -> Vec<u8> {
    crate::body::insert_meta_block(body, REQUEST_EVIDENCE_BLOCK_KEY, &tests::valid_block())
        .expect("a JSON object body")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::block::ArtifactBinding;
    use crate::block::ArtifactType;
    use crate::block::AudienceTuple;
    use crate::body::insert_meta_block;
    use crate::evidence::EvidenceRole;
    use crate::evidence::RequestEvidenceDigest;

    pub(crate) fn valid_block() -> HttpRequestEvidenceBlock {
        HttpRequestEvidenceBlock {
            profile: PROFILE_TAG.into(),
            audience: AudienceTuple {
                audience_id: "did:example:server".into(),
                target_uri: "https://mcp.example.test/mcp".into(),
                route: None,
            },
            artifact_bindings: vec![ArtifactBinding::opaque_from_digest(
                ArtifactType::OauthDpop,
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )
            .expect("a legal binding")],
            continuation: None,
            admission: None,
            admission_assertion: None,
            authorization_decision: None,
        }
    }

    pub(crate) fn with_continuation(c: HttpContinuation) -> HttpRequestEvidenceBlock {
        HttpRequestEvidenceBlock {
            continuation: Some(c),
            ..valid_block()
        }
    }

    #[test]
    fn a_valid_block_and_a_valid_continuation_pass() {
        let body = with_valid_block(br#"{"jsonrpc":"2.0","id":1}"#);
        validate_carried(&body).expect("valid");
        let c = HttpContinuation::build(b"prev", b"irr", b"state");
        let body = body_with(&serde_json::to_value(with_continuation(c)).unwrap());
        validate_carried(&body).expect("valid continuation");
    }

    #[test]
    fn a_continuation_of_another_type_is_refused() {
        let mut c = HttpContinuation::build(b"prev", b"irr", b"state");
        c.continuation_type = "mcp-mrt-v0".into();
        let body = body_with(&serde_json::to_value(with_continuation(c)).unwrap());
        assert_eq!(
            validate_carried(&body).unwrap_err(),
            HttpProfileError::MalformedEvidence("continuation type")
        );
    }

    /// Each handle slot in turn: a corrupted handle can bind to no retained one.
    #[test]
    fn a_continuation_with_a_corrupted_handle_is_refused() {
        let corruptions: [fn(&mut HttpContinuation); 4] = [
            |c| c.previous_request_evidence.digest_value.truncate(10),
            |c| c.input_required_response_evidence.digest_alg = "sha-256".into(),
            |c| c.request_state_digest.digest_value.push('='),
            |c| {
                c.previous_request_evidence = RequestEvidenceDigest {
                    digest_alg: "none".into(),
                    digest_value: String::new(),
                }
            },
        ];
        for corrupt in corruptions {
            let mut c = HttpContinuation::build(b"prev", b"irr", b"state");
            corrupt(&mut c);
            let body = body_with(&serde_json::to_value(with_continuation(c)).unwrap());
            assert_eq!(
                validate_carried(&body).unwrap_err(),
                HttpProfileError::MalformedEvidence("continuation handle")
            );
        }
    }

    /// Shape is all the signer can see: a continuation over the wrong bytes, or with its
    /// handles in swapped slots, is well-shaped and is the verifier's to refuse.
    #[test]
    fn a_well_shaped_continuation_is_not_judged_on_its_binding() {
        let swapped = HttpContinuation::from_handles(
            RequestEvidenceDigest::over_labeled(EvidenceRole::Response, b"irr"),
            RequestEvidenceDigest::over_labeled(EvidenceRole::Request, b"prev"),
            b"state",
        );
        let body = body_with(&serde_json::to_value(with_continuation(swapped)).unwrap());
        validate_carried(&body).expect("well-shaped");
    }

    fn body_with(block: &serde_json::Value) -> Vec<u8> {
        insert_meta_block(
            br#"{"jsonrpc":"2.0","id":1}"#,
            REQUEST_EVIDENCE_BLOCK_KEY,
            block,
        )
        .expect("insert")
    }

    #[test]
    fn a_body_without_a_block_passes_validate_carried_and_fails_require_valid() {
        validate_carried(br#"{"jsonrpc":"2.0","id":1}"#).expect("floor body");
        validate_carried(b"not json").expect("non-JSON body carries no block");
        let request = HttpRequest {
            method: "POST".into(),
            target_uri: "https://mcp.example.com/mcp".into(),
            headers: Vec::new(),
            body: br#"{"jsonrpc":"2.0","id":1}"#.to_vec(),
        };
        assert!(matches!(
            require_valid(&request),
            Err(HttpProfileError::MissingEvidence(WHAT))
        ));
    }

    #[test]
    fn a_carried_block_that_does_not_parse_is_refused() {
        let body = body_with(&serde_json::json!({ "profile": PROFILE_TAG }));
        assert!(matches!(
            validate_carried(&body),
            Err(HttpProfileError::MalformedEvidence(WHAT))
        ));
    }

    #[test]
    fn a_carried_block_under_another_profile_is_refused() {
        let body = body_with(&serde_json::json!({
            "profile": "other-profile",
            "audience": { "audience_id": "a", "target_uri": "https://x/mcp" },
            "artifact_bindings": [],
        }));
        assert!(matches!(
            validate_carried(&body),
            Err(HttpProfileError::UnknownProfileTag)
        ));
    }
}
