// SPDX-License-Identifier: Apache-2.0
//! The REGISTRATION CAPABILITY — what registering establishes, and what it refuses in.
//!
//! One fact: **this statement was registered with the pinned service, and the receipt for
//! it verifies offline against the exact bytes submitted.**
//!
//! Both halves, or nothing. A mechanism can only hand back bytes; the accepted product is
//! constructed in this module and nowhere else, by the one function that verifies them.
//!
//! Every name here is mechanism-neutral on purpose. The vocabulary would read the same
//! against a successor to the protocol the leaf speaks, and that is the test a term has to
//! pass to appear at this altitude.

use mcp_re_http_profile::scitt::CoseVerificationKey;
use mcp_re_http_profile::scitt::Receipt;
use mcp_re_http_profile::scitt::ScittServiceTrustPin;
use mcp_re_http_profile::scitt::SignedStatement;

/// What a mechanism produces: the bytes a service answered with, and nothing about
/// whether they are good.
///
/// Deliberately not a `Receipt`. Parsing is already a claim — that these bytes are an RFC
/// 9942 receipt — and a mechanism that returned one would have made the first half of a
/// judgement the verifying layer exists to make.
#[derive(Debug, Clone)]
pub struct RegistrationResponse {
    receipt_bytes: Vec<u8>,
}

impl RegistrationResponse {
    /// The bytes a service answered a registration with.
    pub fn of(receipt_bytes: Vec<u8>) -> Self {
        RegistrationResponse { receipt_bytes }
    }

    /// Those bytes, for the verifier.
    pub fn bytes(&self) -> &[u8] {
        &self.receipt_bytes
    }
}

/// A registration that FAILED, and — crucially — how certain that is.
///
/// The distinction the variants carry is not tidiness. Reporting *not registered* for a
/// statement a service may hold would send an operator to re-register a record that is
/// already in a log, and reporting the reverse would lose the record entirely. Only an
/// explicit refusal from the service is a definitive negative.
#[derive(Debug)]
pub enum RegistrationError {
    /// The service REFUSED the statement. Definitively not registered.
    Refused(String),
    /// The service declined to accept it right now — over capacity, or rate limiting.
    /// Definitively not registered, and worth retrying later.
    Throttled(String),
    /// The statement went out and the outcome is UNKNOWN: the polling budget ran out, the
    /// transport failed, or the service answered something this mechanism cannot read.
    ///
    /// NOT a failure to register. The service may hold the statement, and a caller that
    /// treats this as a negative will re-submit a record that is already in a log.
    Indeterminate(String),
    /// A receipt came back and did NOT verify against the statement submitted and the
    /// operator's pin.
    ///
    /// Its own variant because it is not an outage. Either the service is not the one the
    /// pin names, or the receipt is not about the statement that was sent — and both are
    /// facts about trust rather than about availability.
    ReceiptUnverified(String),
}

impl std::fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistrationError::Refused(d) => {
                write!(f, "the transparency service refused the statement: {d}")
            }
            RegistrationError::Throttled(d) => {
                write!(
                    f,
                    "the transparency service is not accepting registrations: {d}"
                )
            }
            RegistrationError::Indeterminate(d) => write!(
                f,
                "the statement was submitted and the outcome is UNKNOWN — it may be \
                 registered: {d}"
            ),
            RegistrationError::ReceiptUnverified(d) => write!(
                f,
                "a receipt came back and does not verify against the statement submitted \
                 and the pinned service: {d}"
            ),
        }
    }
}

impl std::error::Error for RegistrationError {}

/// Submitting a Signed Statement to a transparency service.
///
/// The whole seam, and it is one method wide. A mechanism owns a protocol's states,
/// media types and status codes; what it owes the layer above is bytes and a refusal in
/// this module's vocabulary.
pub trait TransparencyRegistration {
    /// Register `signed_statement` — the exact octets — and return what the service
    /// answered with.
    fn register(&self, signed_statement: &[u8]) -> Result<RegistrationResponse, RegistrationError>;
}

/// A statement whose registration was ESTABLISHED: the receipt verified offline against
/// the exact bytes submitted and the operator's pinned service.
///
/// The representation is private and [`register_and_verify`] is its only producer, so
/// holding one means the verification happened. There is no constructor that takes a
/// receipt and a promise.
#[derive(Debug, Clone)]
pub struct RegisteredStatement {
    receipt_bytes: Vec<u8>,
}

impl RegisteredStatement {
    /// The receipt, as the bytes an operator archives beside the statement.
    pub fn receipt_bytes(&self) -> &[u8] {
        &self.receipt_bytes
    }
}

/// Register `statement` through `mechanism`, and accept the answer only if it verifies.
///
/// The verification is the existing offline one, and it is offline in the strong sense:
/// `resolve_ts` is the already-loaded pin, `issuer_key` is the key this auditor signed
/// with, and nothing here fetches or refreshes either. A verifier that reached for a key
/// while checking a receipt would be verifying against whatever the network offered at
/// that moment, which is the property the pin exists to remove.
pub fn register_and_verify(
    mechanism: &dyn TransparencyRegistration,
    statement: &SignedStatement,
    issuer_key: &mcp_re_core::VerificationKey,
    pin: &ScittServiceTrustPin,
) -> Result<RegisteredStatement, RegistrationError> {
    let response = mechanism.register(statement.to_cose())?;
    let receipt = Receipt::from_cose(response.bytes()).map_err(|e| {
        RegistrationError::ReceiptUnverified(format!(
            "the answer is not a well-formed receipt ({})",
            e.wire_code()
        ))
    })?;
    let issuer_kid = statement.issuer_kid().to_owned();
    let issuer = CoseVerificationKey::Ed25519(issuer_key.clone());
    mcp_re_http_profile::scitt::verify_receipt_offline(
        statement,
        &receipt,
        |kid| (kid == issuer_kid).then(|| issuer.clone()),
        |kid| pin.resolve(kid),
    )
    .map_err(|e| RegistrationError::ReceiptUnverified(e.wire_code().to_owned()))?;
    Ok(RegisteredStatement {
        receipt_bytes: response.bytes().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transparency::auditor::registration::fixtures::*;

    /// A mechanism that answers with whatever it was built with.
    struct Canned(Result<Vec<u8>, ()>);

    impl TransparencyRegistration for Canned {
        fn register(&self, _: &[u8]) -> Result<RegistrationResponse, RegistrationError> {
            match &self.0 {
                Ok(bytes) => Ok(RegistrationResponse::of(bytes.clone())),
                Err(()) => Err(RegistrationError::Indeterminate("no answer".to_owned())),
            }
        }
    }

    /// The accepted product exists only when the receipt verified.
    #[test]
    fn a_verifying_receipt_produces_a_registered_statement() {
        let statement = a_statement();
        let receipt = receipt_for(&statement);
        let registered = register_and_verify(
            &Canned(Ok(receipt.clone())),
            &statement,
            &issuer().public_key(),
            &pin(),
        )
        .expect("the receipt verifies against the statement and the pin");
        assert_eq!(registered.receipt_bytes(), receipt.as_slice());
    }

    /// A receipt for a DIFFERENT statement is refused, however well the HTTP went.
    ///
    /// This is the whole reason the verifying layer exists: the mechanism's answer was a
    /// real, well-formed, correctly signed receipt from the right log — about something
    /// else. Nothing in the transport could have told them apart.
    #[test]
    fn a_receipt_about_another_statement_is_refused() {
        let statement = a_statement();
        let elsewhere = receipt_for(&another_statement());
        let refused = register_and_verify(
            &Canned(Ok(elsewhere)),
            &statement,
            &issuer().public_key(),
            &pin(),
        )
        .expect_err("a receipt about another statement must not be accepted");
        assert!(
            matches!(refused, RegistrationError::ReceiptUnverified(_)),
            "{refused:?}",
        );
    }

    /// A receipt from a log the operator did NOT pin is refused.
    ///
    /// The pin is the whole of what separates a transparency service from any process
    /// that can sign CBOR, so this is the property the loaded pin exists to enforce.
    #[test]
    fn a_receipt_from_an_unpinned_log_is_refused() {
        let statement = a_statement();
        let mut impostor =
            mcp_re_http_profile::scitt::PrototypeTransparencyService::new("some-other-kid");
        let receipt = impostor
            .register(&statement, sign_with(ts()))
            .expect("the impostor issues a well-formed receipt")
            .to_cose()
            .to_vec();
        let refused = register_and_verify(
            &Canned(Ok(receipt)),
            &statement,
            &issuer().public_key(),
            &pin(),
        )
        .expect_err("a log the pin does not name is not the pinned service");
        assert!(
            matches!(refused, RegistrationError::ReceiptUnverified(_)),
            "{refused:?}",
        );
    }

    /// Bytes that are not a receipt at all are refused as unverified, not as an outage.
    #[test]
    fn an_answer_that_is_not_a_receipt_is_refused() {
        let statement = a_statement();
        let refused = register_and_verify(
            &Canned(Ok(b"not cbor".to_vec())),
            &statement,
            &issuer().public_key(),
            &pin(),
        )
        .expect_err("unparseable bytes are not a receipt");
        assert!(
            matches!(refused, RegistrationError::ReceiptUnverified(_)),
            "{refused:?}",
        );
    }

    /// A mechanism's own refusal reaches the caller unchanged — in particular, an
    /// indeterminate outcome is not promoted to a definite one on the way up.
    #[test]
    fn a_mechanism_refusal_is_carried_through_with_its_certainty() {
        let statement = a_statement();
        let refused =
            register_and_verify(&Canned(Err(())), &statement, &issuer().public_key(), &pin())
                .expect_err("the mechanism refused");
        assert!(
            matches!(refused, RegistrationError::Indeterminate(_)),
            "an unknown outcome must not become a definite one: {refused:?}",
        );
        assert!(
            refused.to_string().contains("may be registered"),
            "and it must say so in words: {refused}",
        );
    }
}
