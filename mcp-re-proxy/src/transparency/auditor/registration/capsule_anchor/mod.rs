// SPDX-License-Identifier: Apache-2.0
//! The CAPSULE-ANCHOR MECHANISM LEAF — one external service's registration contract.
//!
//! One fact: **what `capsule-anchor` does with a Signed Statement, and what its answer
//! means.**
//!
//! ```text
//! TransparencyRegistration           semantic capability — unchanged by this file
//!   ├─ Scrapi11RegistrationClient    one Internet-Draft's state machine
//!   └─ CapsuleAnchorRegistrationClient   one operated service's contract
//! ```
//!
//! # Why a second leaf and not a path flag
//!
//! Because the two protocols agree on nothing the leaf owns. Measured against the
//! service's published OpenAPI document:
//!
//! | | `draft-ietf-scitt-scrapi-11` | capsule-anchor |
//! |---|---|---|
//! | path | `POST <base>/entries` | `POST <base>/transparency/register-statement` |
//! | request | the statement's octets, `application/cose` | JSON `{"signed_statement_b64": …}` |
//! | success | `201` + Receipt, or `202` + `Location` and a poll | `200` + JSON `{"receipt_b64": …}` |
//! | polling | part of the protocol | none; registration is synchronous |
//!
//! A `--registration-path` flag would let the SCRAPI client reach this service by
//! coincidence of shape while calling a different contract by SCRAPI's name. That is the
//! laundering the mechanism-leaf boundary exists to prevent, and it is why the operator
//! NAMES the protocol rather than describing it.
//!
//! # What crosses upward: bytes, and a refusal in the neutral vocabulary
//!
//! Nothing else. Not the JSON, not the log coordinates beside the receipt, not the
//! service's name for its own entry-hash scheme. In particular this leaf reads ONLY
//! `receipt_b64` from a successful answer: the receipt commits to its own position or it
//! does not, and taking `leaf_index` and `tree_size` from the unsigned JSON next to it
//! would supply from a document nobody signed what the verifier must get from one somebody
//! did.
//!
//! # What a successful run earns
//!
//! *External Transparency Service interoperability* — a real, externally operated service
//! accepted our exact octets and returned a receipt that verifies offline against a
//! previously pinned identity. It does **not** earn *SCRAPI interoperability*; this service
//! does not speak SCRAPI, and only a run against a SCRAPI peer earns that. The artifact
//! records which mechanism ran so the claim cannot exceed the peer.

use base64::Engine;

use super::capability::RegistrationError;
use super::capability::RegistrationResponse;
use super::capability::TransparencyRegistration;
use super::exchange::HttpExchange;
use super::exchange::HttpRequest;

use fault::fault_for_status;
use fault::fault_to_error;
use fault::CapsuleAnchorFault;

/// WHAT can go wrong here, and how certain each one is.
mod fault;
/// WHAT this contract puts on the wire.
mod wire;

use wire::CAPSULE_ANCHOR_CONTRACT;

/// Registering a Signed Statement with a `capsule-anchor` Transparency Service.
pub struct CapsuleAnchorRegistrationClient<E> {
    exchange: E,
    /// The operator-configured service base URL, without a trailing separator.
    base_url: String,
}

impl<E: HttpExchange> CapsuleAnchorRegistrationClient<E> {
    /// A client for the service at `base_url`.
    ///
    /// No budget: this contract has no `202` and no polling, so there is nothing for a
    /// deadline to bound beyond the one the transport already holds. A policy taken and
    /// unused would be a knob that selects nothing.
    pub fn new(exchange: E, base_url: &str) -> Self {
        CapsuleAnchorRegistrationClient {
            exchange,
            base_url: base_url.trim_end_matches('/').to_owned(),
        }
    }

    /// POST the statement, and read what the service made of it.
    fn submit(&self, signed_statement: &[u8]) -> Result<Vec<u8>, CapsuleAnchorFault> {
        let body = serde_json::to_vec(&wire::RegisterStatementRequest {
            signed_statement_b64: base64::engine::general_purpose::STANDARD
                .encode(signed_statement),
        })
        .map_err(|_| CapsuleAnchorFault::Transport {
            detail: "the submission could not be encoded".to_owned(),
        })?;
        let response = self
            .exchange
            .send(HttpRequest {
                method: "POST",
                url: wire::register_statement_url(&self.base_url),
                headers: vec![
                    ("content-type".to_owned(), wire::JSON_MEDIA_TYPE.to_owned()),
                    ("accept".to_owned(), wire::JSON_MEDIA_TYPE.to_owned()),
                ],
                body,
            })
            .map_err(|detail| CapsuleAnchorFault::Transport { detail })?;
        if response.status != 200 {
            return Err(fault_for_status(response.status));
        }
        receipt_bytes(&response.body)
    }
}

/// The receipt octets out of an accepted answer.
///
/// Every failure here is [`CapsuleAnchorFault::UnreadableAnswer`], and that is the whole
/// point of the separate variant: the service has already said `200`, so the statement is
/// in the log whatever this function makes of the body.
fn receipt_bytes(body: &[u8]) -> Result<Vec<u8>, CapsuleAnchorFault> {
    let answer: wire::RegisterStatementResponse =
        serde_json::from_slice(body).map_err(|_| CapsuleAnchorFault::UnreadableAnswer {
            detail: "the answer is not the JSON this contract defines",
        })?;
    base64::engine::general_purpose::STANDARD
        .decode(answer.receipt_b64.as_bytes())
        .map_err(|_| CapsuleAnchorFault::UnreadableAnswer {
            detail: "the receipt field is not base64",
        })
}

impl<E: HttpExchange> TransparencyRegistration for CapsuleAnchorRegistrationClient<E> {
    fn protocol(&self) -> &'static str {
        CAPSULE_ANCHOR_CONTRACT
    }

    fn register(&self, signed_statement: &[u8]) -> Result<RegistrationResponse, RegistrationError> {
        self.submit(signed_statement)
            .map(RegistrationResponse::of)
            .map_err(fault_to_error)
    }
}

#[cfg(test)]
mod tests {
    use super::super::capability::register_and_verify;
    use super::super::exchange::HttpResponse;
    use super::super::fixtures::*;
    use super::*;
    use std::cell::RefCell;

    /// A service that answers whatever it was built with, and records what it was asked.
    struct Canned {
        status: u16,
        body: Vec<u8>,
        seen: RefCell<Option<HttpRequest>>,
    }

    impl Canned {
        fn answering(status: u16, body: Vec<u8>) -> Self {
            Canned {
                status,
                body,
                seen: RefCell::new(None),
            }
        }
    }

    impl HttpExchange for Canned {
        fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
            *self.seen.borrow_mut() = Some(request);
            Ok(HttpResponse {
                status: self.status,
                headers: Vec::new(),
                body: self.body.clone(),
            })
        }
    }

    /// A transport that never completes.
    struct Dead;

    impl HttpExchange for Dead {
        fn send(&self, _: HttpRequest) -> Result<HttpResponse, String> {
            Err("connection refused".to_owned())
        }
    }

    fn answer_with(receipt: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "receipt_b64": base64::engine::general_purpose::STANDARD.encode(receipt),
            "entry_hash": "unused-by-this-leaf",
            "entry_hash_scheme": "sig_structure",
            "leaf_index": 991,
            "tree_size": 992,
        }))
        .expect("json")
    }

    /// The EXACT octets go up, base64 in the field this contract names, at its path.
    #[test]
    fn the_statement_is_submitted_verbatim_to_this_contracts_resource() {
        let statement = a_statement();
        let service = Canned::answering(200, answer_with(&receipt_for(&statement)));
        let client = CapsuleAnchorRegistrationClient::new(service, "https://ts.example.test/");

        client
            .register(statement.to_cose())
            .expect("the service accepted it");

        let seen = client.exchange.seen.borrow();
        let request = seen.as_ref().expect("a request went out");
        assert_eq!(request.method, "POST");
        assert_eq!(
            request.url,
            "https://ts.example.test/transparency/register-statement",
        );
        let sent: serde_json::Value =
            serde_json::from_slice(&request.body).expect("the body is this contract's JSON");
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(sent["signed_statement_b64"].as_str().expect("the field"))
                .expect("base64"),
            statement.to_cose(),
            "the octets submitted are the octets the receipt will be about",
        );
    }

    /// The whole point of the leaf: the receipt it brings back verifies offline against
    /// the statement submitted and the operator's pin, through the SAME verifying layer
    /// the other mechanism goes through.
    #[test]
    fn a_receipt_this_leaf_brings_back_is_accepted_only_after_it_verifies() {
        let statement = a_statement();
        let service = Canned::answering(200, answer_with(&receipt_for(&statement)));
        let client = CapsuleAnchorRegistrationClient::new(service, "https://ts.example.test");

        let registered = register_and_verify(&client, &statement, &issuer().public_key(), &pin())
            .expect("the receipt verifies");

        assert_eq!(registered.protocol(), CAPSULE_ANCHOR_CONTRACT);
    }

    /// A receipt about a DIFFERENT statement is refused however well the HTTP went — the
    /// mechanism cannot tell, and does not have to.
    #[test]
    fn a_receipt_about_another_statement_is_refused() {
        let statement = a_statement();
        let service = Canned::answering(200, answer_with(&receipt_for(&another_statement())));
        let client = CapsuleAnchorRegistrationClient::new(service, "https://ts.example.test");

        let refused = register_and_verify(&client, &statement, &issuer().public_key(), &pin())
            .expect_err("a receipt about another statement is not this one's");

        assert!(
            matches!(refused, RegistrationError::ReceiptUnverified(_)),
            "{refused:?}",
        );
    }

    /// An ACCEPTED submission whose answer cannot be read is indeterminate, never a
    /// failure to register.
    #[test]
    fn an_accepted_submission_with_an_unreadable_answer_does_not_report_a_failure() {
        let statement = a_statement();
        let client = CapsuleAnchorRegistrationClient::new(
            Canned::answering(200, b"not the JSON this contract defines".to_vec()),
            "https://ts.example.test",
        );

        let refused = client
            .register(statement.to_cose())
            .expect_err("the receipt cannot be read");

        assert!(matches!(refused, RegistrationError::Indeterminate(_)));
        assert!(refused.to_string().contains("ACCEPTED"), "{refused}");
    }

    /// The service's log coordinates are NOT read: an answer carrying none still works,
    /// because the receipt is the only thing that speaks for the receipt.
    #[test]
    fn the_unsigned_log_coordinates_beside_the_receipt_are_not_consumed() {
        let statement = a_statement();
        let body = serde_json::to_vec(&serde_json::json!({
            "receipt_b64": base64::engine::general_purpose::STANDARD
                .encode(receipt_for(&statement)),
        }))
        .expect("json");
        let client = CapsuleAnchorRegistrationClient::new(
            Canned::answering(200, body),
            "https://ts.example.test",
        );

        register_and_verify(&client, &statement, &issuer().public_key(), &pin())
            .expect("the receipt is what establishes the registration");
    }

    /// A transport failure while submitting leaves the outcome unknown.
    #[test]
    fn a_submission_that_never_went_out_is_indeterminate() {
        let statement = a_statement();
        let client = CapsuleAnchorRegistrationClient::new(Dead, "https://ts.example.test");

        let refused = client
            .register(statement.to_cose())
            .expect_err("nothing went out");

        assert!(matches!(refused, RegistrationError::Indeterminate(_)));
    }
}
