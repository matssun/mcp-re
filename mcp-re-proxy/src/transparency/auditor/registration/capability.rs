// SPDX-License-Identifier: Apache-2.0
//! The REGISTRATION CAPABILITY — what registering establishes, and what it refuses in.
//!
//! One fact: **this statement was registered with the pinned service, and the receipt for
//! it verifies offline against the exact bytes submitted, under a service key the audit
//! profile states is acceptable at the auditor's current time.**
//!
//! Both halves, or nothing. A mechanism can only hand back bytes; the accepted product is
//! constructed in this module and nowhere else, by the one function that verifies them.
//!
//! Every name here is mechanism-neutral on purpose. The vocabulary would read the same
//! against a successor to the protocol the leaf speaks, and that is the test a term has to
//! pass to appear at this altitude.

#[cfg(feature = "scitt_registration")]
use mcp_re_http_profile::scitt::CoseVerificationKey;
#[cfg(feature = "scitt_registration")]
use mcp_re_http_profile::scitt::Receipt;
#[cfg(feature = "scitt_registration")]
use mcp_re_http_profile::scitt::ScittServiceTrustPin;
#[cfg(feature = "scitt_registration")]
use mcp_re_http_profile::scitt::SignedStatement;
#[cfg(feature = "scitt_registration")]
use mcp_re_http_profile::scitt::TransparencyKeyLifecycle;

/// What a mechanism produces: the bytes a service answered with, and nothing about
/// whether they are good.
///
/// Deliberately not a `Receipt`. Parsing is already a claim — that these bytes are an RFC
/// 9942 receipt — and a mechanism that returned one would have made the first half of a
/// judgement the verifying layer exists to make.
#[cfg(feature = "scitt_registration")]
#[derive(Debug, Clone)]
pub struct RegistrationResponse {
    receipt_bytes: Vec<u8>,
}

#[cfg(feature = "scitt_registration")]
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
    /// A receipt came back and did NOT verify against the statement submitted, the
    /// operator's pin, and the lifecycle the audit profile states for its service key.
    ///
    /// Its own variant because it is not an outage. Either the service is not the one the
    /// pin names, the receipt is not about the statement that was sent, or its key is not
    /// acceptable at the auditor's current time — and all are facts about trust rather
    /// than about availability.
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
                "a receipt came back and does not verify against the statement submitted, \
                 the pinned service and its key's stated lifecycle: {d}"
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
#[cfg(feature = "scitt_registration")]
pub trait TransparencyRegistration {
    /// WHICH contract this mechanism speaks, as a durable record rather than a log line.
    ///
    /// Mechanism-NEUTRAL even though its values are not: "which one ran" is a fact about
    /// the capability, and it is the fact a claim rests on. A run against a peer speaking
    /// one contract does not license a sentence about another, so the answer travels into
    /// the artifact instead of being spent at the call site.
    fn protocol(&self) -> &'static str;

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
    protocol: &'static str,
    statement: Vec<u8>,
}

impl RegisteredStatement {
    /// The receipt, as the bytes an operator archives beside the statement.
    pub fn receipt_bytes(&self) -> &[u8] {
        &self.receipt_bytes
    }

    /// WHICH contract established this registration.
    ///
    /// Carried on the value because the value is what a claim is written from. A reader
    /// holding one of these can say what was interoperated with; a reader holding only a
    /// receipt would have to ask the invocation, which is not archived beside it.
    pub fn protocol(&self) -> &'static str {
        self.protocol
    }

    /// The exact statement octets the receipt verified against.
    pub(in crate::transparency::auditor) fn statement_bytes(&self) -> &[u8] {
        &self.statement
    }
}

/// Register `statement` through `mechanism`, and accept the answer only if it verifies.
///
/// The verification is the existing offline one, and it is offline in the strong sense:
/// `resolve_ts` is the already-loaded pin, `issuer_key` is the key this auditor signed
/// with, and nothing here fetches or refreshes either. A verifier that reached for a key
/// while checking a receipt would be verifying against whatever the network offered at
/// that moment, which is the property the pin exists to remove.
///
/// The receipt's service key is judged by `ts_key`, the lifecycle the audit profile states
/// for it, at the instant `clock` reads when the receipt is being accepted — after the
/// registration exchange, which may poll for an hour, has answered — never at a time
/// captured when it began. No time the receipt or the statement carries is an input, so
/// past a key's `revoked_at` or `valid_until` every receipt under it is refused.
#[cfg(feature = "scitt_registration")]
pub fn register_and_verify(
    mechanism: &dyn TransparencyRegistration,
    statement: &SignedStatement,
    issuer_key: &mcp_re_core::VerificationKey,
    pin: &ScittServiceTrustPin,
    ts_key: &dyn Fn(&str) -> Option<TransparencyKeyLifecycle>,
    clock: &dyn Fn() -> i64,
) -> Result<RegisteredStatement, RegistrationError> {
    let response = mechanism.register(statement.to_cose())?;
    let receipt = Receipt::from_cose(response.bytes()).map_err(|e| {
        RegistrationError::ReceiptUnverified(format!(
            "the answer is not a well-formed receipt ({})",
            e.wire_code()
        ))
    })?;
    let ts_kid = receipt.ts_kid();
    let lifecycle = ts_key(ts_kid).ok_or_else(|| {
        RegistrationError::ReceiptUnverified(format!(
            "the audit profile states no lifecycle for transparency-service key {ts_kid:?}"
        ))
    })?;
    let now = clock();
    lifecycle.admits_at(now).map_err(|refusal| {
        RegistrationError::ReceiptUnverified(format!(
            "transparency-service key {ts_kid:?} is not acceptable at {now}: {refusal}"
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
        protocol: mechanism.protocol(),
        statement: statement.to_cose().to_vec(),
    })
}

#[cfg(all(test, feature = "scitt_registration"))]
mod tests {
    use super::*;
    use crate::transparency::auditor::registration::fixtures::*;

    /// A mechanism that answers with whatever it was built with.
    struct Canned(Result<Vec<u8>, ()>);

    impl TransparencyRegistration for Canned {
        fn protocol(&self) -> &'static str {
            "canned"
        }

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
            &ts_lifecycle,
            &|| NOW,
        )
        .expect("the receipt verifies against the statement and the pin");
        assert_eq!(registered.receipt_bytes(), receipt.as_slice());
        assert_eq!(
            registered.protocol(),
            "canned",
            "the established registration records WHICH mechanism established it",
        );
    }

    /// An artifact built around `statement`, as a reader would hold it.
    fn artifact_carrying(
        statement: &SignedStatement,
    ) -> crate::transparency::auditor::AttestationArtifact {
        crate::transparency::auditor::AttestationArtifact::carrying_statement(statement.to_cose())
    }

    /// A receipt attaches to the artifact carrying the statement it verified against.
    #[test]
    fn an_attached_receipt_carries_the_protocol_that_established_it() {
        let statement = a_statement();
        let registered = register_and_verify(
            &Canned(Ok(receipt_for(&statement))),
            &statement,
            &issuer().public_key(),
            &pin(),
            &ts_lifecycle,
            &|| NOW,
        )
        .expect("the receipt verifies");
        let artifact = artifact_carrying(&statement)
            .with_verified_receipt(&registered)
            .expect("the artifact carries the registered statement");
        assert_eq!(
            artifact
                .receipt()
                .expect("a receipt is present")
                .expect("decodes"),
            registered.receipt_bytes(),
        );
        assert_eq!(artifact.registration_protocol(), Some("canned"));
    }

    /// A receipt cannot be attached to an artifact carrying a different statement.
    #[test]
    fn a_receipt_is_refused_by_an_artifact_carrying_another_statement() {
        let statement = a_statement();
        let registered = register_and_verify(
            &Canned(Ok(receipt_for(&statement))),
            &statement,
            &issuer().public_key(),
            &pin(),
            &ts_lifecycle,
            &|| NOW,
        )
        .expect("the receipt verifies");
        artifact_carrying(&another_statement())
            .with_verified_receipt(&registered)
            .expect_err("the receipt is about another statement");
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
            &ts_lifecycle,
            &|| NOW,
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
        // A lifecycle for every kid, so the refusal is the pin's and not the lifecycle's.
        let any_kid = |_: &str| TransparencyKeyLifecycle::new(1_600_000_000, None, None).ok();
        let refused = register_and_verify(
            &Canned(Ok(receipt)),
            &statement,
            &issuer().public_key(),
            &pin(),
            &any_kid,
            &|| NOW,
        )
        .expect_err("a log the pin does not name is not the pinned service");
        assert!(
            matches!(&refused, RegistrationError::ReceiptUnverified(d) if !d.contains("lifecycle")),
            "{refused:?}",
        );
    }

    /// Register a receipt the pinned log really issued, judging its key by `lifecycle` at
    /// [`NOW`].
    fn register_under(
        lifecycle: Option<TransparencyKeyLifecycle>,
    ) -> Result<RegisteredStatement, RegistrationError> {
        let statement = a_statement();
        let ts_key = move |kid: &str| (kid == TS_KID).then_some(lifecycle).flatten();
        register_and_verify(
            &Canned(Ok(receipt_for(&statement))),
            &statement,
            &issuer().public_key(),
            &pin(),
            &ts_key,
            &|| NOW,
        )
    }

    /// A receipt is refused when the audit profile states no lifecycle for its service
    /// key, however well it verifies against the pin.
    #[test]
    fn a_receipt_under_a_key_with_no_stated_lifecycle_is_refused() {
        let refused = register_under(None).expect_err("no lifecycle is stated for the key");
        assert!(
            matches!(&refused, RegistrationError::ReceiptUnverified(d)
                if d.contains("states no lifecycle") && d.contains(TS_KID)),
            "{refused:?}",
        );
    }

    /// A receipt under a key revoked at or before the auditor's current time is refused.
    #[test]
    fn a_receipt_under_a_revoked_key_is_refused() {
        for revoked_at in [NOW, NOW - 1] {
            let lifecycle = TransparencyKeyLifecycle::new(1_600_000_000, None, Some(revoked_at));
            let refused = register_under(lifecycle.ok()).expect_err("the key is revoked");
            assert!(
                matches!(&refused, RegistrationError::ReceiptUnverified(d) if d.contains("revoked")),
                "{refused:?}",
            );
        }
    }

    /// A receipt under a key whose `valid_until` is at or before the auditor's current time
    /// is refused.
    #[test]
    fn a_receipt_under_an_expired_key_is_refused() {
        for valid_until in [NOW, NOW - 1] {
            let lifecycle = TransparencyKeyLifecycle::new(1_600_000_000, Some(valid_until), None);
            let refused = register_under(lifecycle.ok()).expect_err("the key has expired");
            assert!(
                matches!(&refused, RegistrationError::ReceiptUnverified(d) if d.contains("expired")),
                "{refused:?}",
            );
        }
    }

    /// A receipt under a key not yet valid at the auditor's current time is refused.
    #[test]
    fn a_receipt_under_a_not_yet_valid_key_is_refused() {
        let lifecycle = TransparencyKeyLifecycle::new(NOW + 1, None, None);
        let refused = register_under(lifecycle.ok()).expect_err("the key is not yet valid");
        assert!(
            matches!(&refused, RegistrationError::ReceiptUnverified(d) if d.contains("not_yet_valid")),
            "{refused:?}",
        );
    }

    /// A key whose window contains the auditor's current time admits the receipt.
    #[test]
    fn a_receipt_under_a_key_admitted_at_now_is_accepted() {
        let lifecycle = TransparencyKeyLifecycle::new(NOW, Some(NOW + 1), Some(NOW + 1));
        register_under(lifecycle.ok()).expect("the key is acceptable at NOW");
    }

    /// A mechanism whose answer arrives only after the auditor's clock has moved to `to`,
    /// as a registration that polls for its receipt does.
    struct Slow {
        receipt: Vec<u8>,
        clock: std::sync::Arc<std::sync::atomic::AtomicI64>,
        to: i64,
    }

    impl TransparencyRegistration for Slow {
        fn protocol(&self) -> &'static str {
            "slow"
        }

        fn register(&self, _: &[u8]) -> Result<RegistrationResponse, RegistrationError> {
            self.clock
                .store(self.to, std::sync::atomic::Ordering::SeqCst);
            Ok(RegistrationResponse::of(self.receipt.clone()))
        }
    }

    /// The key is judged when the receipt is accepted, not when registration began: a
    /// registration started while the key was acceptable, whose receipt arrives at the
    /// revocation instant itself, is refused.
    #[test]
    fn a_registration_begun_before_the_cutoff_whose_receipt_arrives_after_it_is_refused() {
        use std::sync::atomic::{AtomicI64, Ordering};
        let statement = a_statement();
        let clock = std::sync::Arc::new(AtomicI64::new(NOW));
        let revoked_at = NOW + 10;
        let ts_key = move |kid: &str| {
            (kid == TS_KID)
                .then(|| TransparencyKeyLifecycle::new(1_600_000_000, None, Some(revoked_at)))
                .and_then(Result::ok)
        };
        let read = {
            let clock = std::sync::Arc::clone(&clock);
            move || clock.load(Ordering::SeqCst)
        };
        let mechanism = Slow {
            receipt: receipt_for(&statement),
            clock,
            to: revoked_at,
        };
        let refused = register_and_verify(
            &mechanism,
            &statement,
            &issuer().public_key(),
            &pin(),
            &ts_key,
            &read,
        )
        .expect_err("the key was revoked by the time the receipt arrived");
        assert!(
            matches!(&refused, RegistrationError::ReceiptUnverified(d) if d.contains("revoked")),
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
            &ts_lifecycle,
            &|| NOW,
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
        let refused = register_and_verify(
            &Canned(Err(())),
            &statement,
            &issuer().public_key(),
            &pin(),
            &ts_lifecycle,
            &|| NOW,
        )
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
