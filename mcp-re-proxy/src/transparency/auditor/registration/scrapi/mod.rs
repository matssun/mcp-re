// SPDX-License-Identifier: Apache-2.0
//! The SCRAPI MECHANISM LEAF — one draft revision's registration state machine.
//!
//! One fact: **what `draft-ietf-scitt-scrapi-11` does with a Signed Statement, and what
//! each of its answers means.**
//!
//! Everything version-specific stops here. The layer above holds a capability and a
//! refusal vocabulary that would read the same against a successor protocol; this module
//! holds the paths, the media types, the status semantics and the polling loop.
//!
//! # Certainty is decided here, once
//!
//! [`Scrapi11Fault`] is the protocol's own typed refusal, and [`fault_to_error`] is the
//! ONE place a protocol fault becomes a semantic one. That mapping is where *definitely
//! not registered* is separated from *may be registered*, and it is a single function so
//! there is no second opinion: only an explicit client-error refusal and an explicit rate
//! limit are definitive negatives. A transport failure while submitting, a `201` whose
//! body will not parse, a `202` with no `Location`, and an exhausted budget all leave the
//! statement possibly held by the service.
//!
//! # Where the client may be sent
//!
//! The service base URL is operator configuration. The poll URL is not — the SERVICE
//! chooses it — so a `Location` is required to sit under the configured base. Without
//! that check a service could answer `202 Location: http://169.254.169.254/` and have the
//! auditor fetch it, which is the shape of every SSRF. Redirects are refused for the same
//! reason by the transport that opens the socket.

use std::time::Instant;

use super::capability::RegistrationError;
use super::capability::RegistrationResponse;
use super::capability::TransparencyRegistration;
use super::policy::RegistrationPolicy;

use answer::Polled;
use answer::Submitted;
use fault::fault_to_error;
use fault::Phase;
use fault::Scrapi11Fault;

/// WHAT ONE ANSWER from the service says.
mod answer;
mod exchange;
/// WHAT can go wrong in this protocol, and how certain each one is.
mod fault;
mod wire;

/// The `ureq` transport. Behind the feature that links an HTTP client, for the reason
/// `outbound_fetch::binding` states: the default serving closure links none.
#[cfg(feature = "scitt_registration")]
mod ureq_exchange;

pub(super) use exchange::HttpExchange;
pub(super) use exchange::HttpRequest;

#[cfg(feature = "scitt_registration")]
pub(super) use ureq_exchange::UreqExchange;

/// Registering a Signed Statement over `draft-ietf-scitt-scrapi-11`.
pub struct Scrapi11RegistrationClient<E> {
    exchange: E,
    /// The operator-configured service base URL, without a trailing separator.
    base_url: String,
    policy: RegistrationPolicy,
}

impl<E: HttpExchange> Scrapi11RegistrationClient<E> {
    /// A client for the service at `base_url`, bounded by `policy`.
    pub fn new(exchange: E, base_url: &str, policy: RegistrationPolicy) -> Self {
        Scrapi11RegistrationClient {
            exchange,
            base_url: base_url.trim_end_matches('/').to_owned(),
            policy,
        }
    }

    /// POST the statement, and read what the service made of it.
    fn submit(&self, signed_statement: &[u8]) -> Result<Submitted, Scrapi11Fault> {
        let request = HttpRequest {
            method: "POST",
            url: wire::entries_url(&self.base_url),
            headers: vec![
                ("content-type".to_owned(), wire::COSE_MEDIA_TYPE.to_owned()),
                ("accept".to_owned(), wire::COSE_MEDIA_TYPE.to_owned()),
            ],
            body: signed_statement.to_vec(),
        };
        let response = self
            .exchange
            .send(request)
            .map_err(|detail| Scrapi11Fault::Transport {
                phase: Phase::Submitting,
                detail,
            })?;
        answer::read_submission(&response, &self.base_url)
    }

    /// Poll until the receipt is ready, the budget runs out, or the answer is unusable.
    ///
    /// A `204` is neither success nor failure and does not end the loop. A transport
    /// failure and a rate limit do not end it either — both are transient by nature, and
    /// abandoning on the first one would discard a receipt the service is still producing.
    /// What ends it is a receipt, an unreadable answer, or the budget.
    fn poll(&self, location: &str, deadline: Instant) -> Result<Vec<u8>, Scrapi11Fault> {
        while Instant::now() < deadline {
            std::thread::sleep(self.policy.interval());
            match self.poll_once(location) {
                Polled::Ready(receipt) => return Ok(receipt),
                Polled::StillWorking => (),
                Polled::Unusable(fault) => return Err(fault),
            }
        }
        Err(Scrapi11Fault::TimedOut {
            after: self.policy.timeout(),
        })
    }

    /// One poll of the receipt resource, and what it said.
    fn poll_once(&self, location: &str) -> Polled {
        let request = HttpRequest {
            method: "GET",
            url: location.to_owned(),
            headers: vec![("accept".to_owned(), wire::COSE_MEDIA_TYPE.to_owned())],
            body: Vec::new(),
        };
        // A transport failure is not an answer; the budget above decides how long to keep
        // asking, and abandoning on the first blip would discard a receipt still being
        // produced.
        let Ok(response) = self.exchange.send(request) else {
            return Polled::StillWorking;
        };
        answer::read_poll(&response)
    }
}

impl<E: HttpExchange> TransparencyRegistration for Scrapi11RegistrationClient<E> {
    fn register(&self, signed_statement: &[u8]) -> Result<RegistrationResponse, RegistrationError> {
        // Before anything is sent. A budget whose end is not representable is a run with
        // no bound, and refusing here is a definitive negative: nothing went out.
        let deadline = Instant::now()
            .checked_add(self.policy.timeout())
            .ok_or_else(|| {
                RegistrationError::Refused(
                    "the registration deadline is not representable on this host's clock"
                        .to_owned(),
                )
            })?;
        let receipt = match self.submit(signed_statement).map_err(fault_to_error)? {
            Submitted::Receipt(bytes) => bytes,
            Submitted::Pending(location) => {
                self.poll(&location, deadline).map_err(fault_to_error)?
            }
        };
        Ok(RegistrationResponse::of(receipt))
    }
}

#[cfg(test)]
mod tests {
    //! The mechanism's proofs, against a HERMETIC transparency service.
    //!
    //! The service below is not a canned-response table: it parses the Signed Statement
    //! that was submitted, registers it in a real RFC 9162 log, and answers with a real
    //! RFC 9942 receipt about those exact bytes. So the asynchronous lane ends with a
    //! receipt that verifies offline — which is the only way "the 202 path works" means
    //! anything.
    //!
    //! What it is not is a socket. That lane lives beside the client that opens one;
    //! everything about the protocol's states and refusals is establishable here, and is.

    use std::cell::Cell;
    use std::cell::RefCell;

    use super::exchange::HttpResponse;
    use super::wire::SCRAPI_REVISION;
    use super::*;
    use crate::transparency::auditor::registration::capability::register_and_verify;
    use crate::transparency::auditor::registration::fixtures::*;
    use std::time::Duration;

    const BASE: &str = "https://ts.example.test/scitt";

    fn policy() -> RegistrationPolicy {
        RegistrationPolicy::new(Duration::from_millis(200), Duration::from_millis(1))
            .expect("a bounded budget")
    }

    /// A budget that allows very few polls, for the lane about running out of them.
    fn tight_policy() -> RegistrationPolicy {
        RegistrationPolicy::new(Duration::from_millis(5), Duration::from_millis(1))
            .expect("a bounded budget")
    }

    /// How the hermetic service answers a submission.
    enum Mode {
        /// `201 Created` with the receipt.
        Synchronous,
        /// `202 Accepted`, then `n` × `204`, then `200` with the receipt.
        Asynchronous { pending: u32 },
    }

    /// A transparency service that speaks the draft's registration exchange.
    struct HermeticService {
        mode: Mode,
        pending: Cell<u32>,
        /// The receipt produced for whatever statement was submitted.
        receipt: RefCell<Vec<u8>>,
        requests: RefCell<Vec<HttpRequest>>,
        /// Fail the next `n` polls at the transport, to exercise the retry.
        poll_failures: Cell<u32>,
    }

    impl HermeticService {
        fn new(mode: Mode) -> Self {
            let pending = match mode {
                Mode::Asynchronous { pending } => pending,
                Mode::Synchronous => 0,
            };
            HermeticService {
                mode,
                pending: Cell::new(pending),
                receipt: RefCell::new(Vec::new()),
                requests: RefCell::new(Vec::new()),
                poll_failures: Cell::new(0),
            }
        }

        fn with_poll_failures(self, n: u32) -> Self {
            self.poll_failures.set(n);
            self
        }

        fn operation_url() -> String {
            format!("{BASE}/operations/1")
        }

        /// Register the submitted bytes in a real log and keep the receipt.
        fn register(&self, body: &[u8]) -> Result<(), String> {
            let statement = mcp_re_http_profile::scitt::SignedStatement::from_cose(body)
                .map_err(|_| "the submitted body is not a Signed Statement".to_owned())?;
            let mut log = mcp_re_http_profile::scitt::PrototypeTransparencyService::new(TS_KID);
            let receipt = log
                .register(&statement, sign_with(ts()))
                .map_err(|_| "the log could not register it".to_owned())?;
            *self.receipt.borrow_mut() = receipt.to_cose().to_vec();
            Ok(())
        }

        fn cose(&self, status: u16) -> HttpResponse {
            HttpResponse {
                status,
                headers: vec![("content-type".to_owned(), "application/cose".to_owned())],
                body: self.receipt.borrow().clone(),
            }
        }
    }

    impl HttpExchange for HermeticService {
        fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
            self.requests.borrow_mut().push(request.clone());
            if request.method == "POST" {
                self.register(&request.body)?;
                return Ok(match self.mode {
                    Mode::Synchronous => self.cose(200 + 1),
                    Mode::Asynchronous { .. } => HttpResponse {
                        status: 202,
                        headers: vec![("location".to_owned(), HermeticService::operation_url())],
                        body: Vec::new(),
                    },
                });
            }
            if self.poll_failures.get() > 0 {
                self.poll_failures.set(self.poll_failures.get() - 1);
                return Err("connection reset".to_owned());
            }
            if self.pending.get() > 0 {
                self.pending.set(self.pending.get() - 1);
                return Ok(HttpResponse {
                    status: 204,
                    headers: Vec::new(),
                    body: Vec::new(),
                });
            }
            Ok(self.cose(200))
        }
    }

    /// A service that answers a submission with one canned response, and never becomes ready.
    struct Canned {
        submission: Option<HttpResponse>,
        poll: Option<HttpResponse>,
        fetched: RefCell<Vec<String>>,
    }

    impl Canned {
        fn submitting(response: HttpResponse) -> Self {
            Canned {
                submission: Some(response),
                poll: None,
                fetched: RefCell::new(Vec::new()),
            }
        }
    }

    impl HttpExchange for Canned {
        fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
            self.fetched.borrow_mut().push(request.url.clone());
            let canned = if request.method == "POST" {
                self.submission.clone()
            } else {
                self.poll.clone()
            };
            canned.ok_or_else(|| "no answer".to_owned())
        }
    }

    fn register(exchange: impl HttpExchange) -> Result<Vec<u8>, RegistrationError> {
        let client = Scrapi11RegistrationClient::new(exchange, BASE, policy());
        client
            .register(a_statement().to_cose())
            .map(|response| response.bytes().to_vec())
    }

    // ---- the two success paths --------------------------------------------------

    /// `201 Created`: the receipt comes back with the answer, and it verifies.
    #[test]
    fn a_synchronous_registration_yields_a_receipt_that_verifies() {
        let statement = a_statement();
        let client = Scrapi11RegistrationClient::new(
            HermeticService::new(Mode::Synchronous),
            BASE,
            policy(),
        );
        let registered = register_and_verify(&client, &statement, &issuer().public_key(), &pin())
            .expect("the receipt the service returned verifies against the statement and the pin");
        assert!(!registered.receipt_bytes().is_empty());
    }

    /// `202 → 204 → 204 → 200`: the asynchronous path, end to end.
    ///
    /// Both halves are asserted. The receipt verifies — so the polling actually reached the
    /// service's answer about the submitted bytes — and the request sequence is what the
    /// protocol says it should be, so a client that got the receipt by some other route would
    /// fail here.
    #[test]
    fn an_asynchronous_registration_polls_until_the_receipt_is_ready() {
        let statement = a_statement();
        let service = HermeticService::new(Mode::Asynchronous { pending: 2 });
        let client = Scrapi11RegistrationClient::new(service, BASE, policy());
        let registered = register_and_verify(&client, &statement, &issuer().public_key(), &pin())
            .expect("the polled receipt verifies");
        assert!(!registered.receipt_bytes().is_empty());

        let requests = client.exchange.requests.borrow();
        let shape: Vec<(&str, &str)> = requests
            .iter()
            .map(|r| (r.method, r.url.as_str()))
            .collect();
        assert_eq!(
            shape,
            vec![
                ("POST", "https://ts.example.test/scitt/entries"),
                ("GET", "https://ts.example.test/scitt/operations/1"),
                ("GET", "https://ts.example.test/scitt/operations/1"),
                ("GET", "https://ts.example.test/scitt/operations/1"),
            ],
            "one submission, then a poll per 204 and one more that answered",
        );
    }

    /// The EXACT statement is what goes on the wire, under the media type the draft names.
    ///
    /// A registration is a claim about specific octets. A transport that re-encoded them —
    /// even into an equivalent CBOR — would produce a receipt about bytes nobody holds.
    #[test]
    fn the_submitted_body_is_the_statement_verbatim() {
        let statement = a_statement();
        let client = Scrapi11RegistrationClient::new(
            HermeticService::new(Mode::Synchronous),
            BASE,
            policy(),
        );
        client.register(statement.to_cose()).expect("registers");

        let requests = client.exchange.requests.borrow();
        let submission = requests.first().expect("a submission");
        assert_eq!(submission.body, statement.to_cose());
        assert!(submission
            .headers
            .iter()
            .any(|(k, v)| k == "content-type" && v == "application/cose"));
    }

    /// A transport blip while polling does not abandon a receipt still being produced.
    #[test]
    fn a_transport_failure_while_polling_is_retried_within_the_budget() {
        let statement = a_statement();
        let service = HermeticService::new(Mode::Asynchronous { pending: 0 }).with_poll_failures(2);
        let client = Scrapi11RegistrationClient::new(service, BASE, policy());
        register_and_verify(&client, &statement, &issuer().public_key(), &pin())
            .expect("two failed polls inside the budget are not a lost receipt");
    }

    // ---- the refusals, and their certainty --------------------------------------

    fn assert_indeterminate(outcome: Result<Vec<u8>, RegistrationError>, what: &str) {
        let refused = outcome
            .err()
            .unwrap_or_else(|| panic!("{what}: expected a refusal"));
        assert!(
            matches!(refused, RegistrationError::Indeterminate(_)),
            "{what}: the statement may be registered, so this must not read as a negative: \
             {refused:?}",
        );
    }

    fn response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> HttpResponse {
        HttpResponse {
            status,
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            body: body.to_vec(),
        }
    }

    /// A client-error answer to the submission is the ONE definitive negative.
    #[test]
    fn a_client_error_is_a_definitive_refusal() {
        for status in [400, 401, 403, 404, 409, 422] {
            let outcome = register(Canned::submitting(response(status, &[], b"")));
            assert!(
                matches!(outcome, Err(RegistrationError::Refused(_))),
                "{status}: the service read the submission and said no",
            );
        }
    }

    /// A rate limit is a definitive negative too — nothing was accepted — but it is a
    /// different one: come back later, rather than never.
    ///
    /// `503` is deliberately NOT grouped with it. A reverse proxy answers `503` over an
    /// origin that accepted the statement and then took too long, and nothing in the
    /// response separates that from a service that is simply down — so it is reported as
    /// unknown rather than as a registration that did not happen.
    #[test]
    fn a_rate_limit_is_throttled_and_a_503_is_not() {
        let throttled = register(Canned::submitting(response(429, &[], b"")));
        assert!(
            matches!(throttled, Err(RegistrationError::Throttled(_))),
            "429: not accepted, and worth retrying: {throttled:?}",
        );
        let unknown = register(Canned::submitting(response(503, &[], b"")));
        assert!(
            matches!(unknown, Err(RegistrationError::Indeterminate(_))),
            "503: a proxy answers this over an origin that accepted: {unknown:?}",
        );
    }

    /// Everything that can go wrong AFTER the bytes went out leaves the outcome unknown.
    #[test]
    fn every_post_submission_fault_is_indeterminate() {
        let cose = [("content-type", "application/cose")];

        assert_indeterminate(
            register(Canned::submitting(response(202, &[], b""))),
            "a 202 with no Location",
        );
        assert_indeterminate(
            register(Canned::submitting(response(
                202,
                &[("location", "http://169.254.169.254/")],
                b"",
            ))),
            "a Location outside the configured service",
        );
        assert_indeterminate(
            register(Canned::submitting(response(
                201,
                &[("content-type", "application/json")],
                b"{}",
            ))),
            "a receipt announced under a media type this profile does not read",
        );
        assert_indeterminate(
            register(Canned::submitting(response(201, &cose, b""))),
            "a 201 with an empty body",
        );
        assert_indeterminate(
            register(Canned::submitting(response(500, &[], b""))),
            "a server error",
        );
        assert_indeterminate(
            register(Canned {
                submission: None,
                poll: None,
                fetched: RefCell::new(Vec::new()),
            }),
            "a transport failure while submitting",
        );
    }

    /// A `Location` outside the configured service is not fetched.
    ///
    /// The base URL is operator configuration; this URL is the service's choice. A client that
    /// followed it would turn every transparency service into an SSRF primitive against its
    /// operator's network.
    #[test]
    fn a_location_outside_the_service_is_never_fetched() {
        let canned = Canned::submitting(response(
            202,
            &[("location", "http://169.254.169.254/latest/meta-data/")],
            b"",
        ));
        let client = Scrapi11RegistrationClient::new(canned, BASE, policy());
        let outcome = client.register(a_statement().to_cose());
        assert!(matches!(outcome, Err(RegistrationError::Indeterminate(_))));
        assert_eq!(
            client.exchange.fetched.borrow().as_slice(),
            ["https://ts.example.test/scitt/entries"],
            "the submission, and nothing else",
        );
    }

    /// A budget that runs out is UNKNOWN, not a failure to register.
    #[test]
    fn an_exhausted_budget_is_indeterminate() {
        let service = HermeticService::new(Mode::Asynchronous { pending: u32::MAX });
        let client = Scrapi11RegistrationClient::new(service, BASE, tight_policy());
        let refused = client
            .register(a_statement().to_cose())
            .expect_err("the receipt never became ready");
        assert!(
            matches!(refused, RegistrationError::Indeterminate(_)),
            "the service accepted the statement: {refused:?}",
        );
        assert!(
            refused.to_string().contains("may be registered"),
            "and the words must say so: {refused}",
        );
    }

    /// An unexpected status on the receipt resource ends the poll, and does so as UNKNOWN.
    ///
    /// A `404` here is not a refusal of the statement — the statement was accepted. It means
    /// the receipt cannot be collected, which is a different thing an operator must not read
    /// as "not registered".
    #[test]
    fn a_lost_receipt_resource_is_indeterminate_and_not_a_refusal() {
        let canned = Canned {
            submission: Some(response(
                202,
                &[("location", "https://ts.example.test/scitt/operations/1")],
                b"",
            )),
            poll: Some(response(404, &[], b"")),
            fetched: RefCell::new(Vec::new()),
        };
        let refused = Scrapi11RegistrationClient::new(canned, BASE, policy())
            .register(a_statement().to_cose())
            .expect_err("the receipt resource is gone");
        assert!(
            matches!(refused, RegistrationError::Indeterminate(_)),
            "{refused:?}",
        );
    }

    /// The revision is pinned, and it says what it is.
    #[test]
    fn the_protocol_revision_is_a_draft_and_names_itself() {
        assert_eq!(SCRAPI_REVISION, "draft-ietf-scitt-scrapi-11");
        let refused = register(Canned::submitting(response(400, &[], b"")))
            .expect_err("a refusal names the revision it was performed under");
        assert!(refused.to_string().contains(SCRAPI_REVISION), "{refused}");
    }
}
