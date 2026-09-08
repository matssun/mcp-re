// SPDX-License-Identifier: Apache-2.0
//! WHAT ONE ANSWER from the service says.
//!
//! One fact: **the meaning of a single response, read under this draft's contract.**
//!
//! Separate from the exchange sequence because the two go wrong differently. Sending is
//! about sockets and order; reading is about statuses, media types and a `Location` header,
//! and every judgement it makes is a pure function of one response. That is what lets the
//! whole contract be stated as two functions with no client, no budget and no clock in
//! sight.

use super::super::exchange::HttpResponse;
use super::fault::Phase;
use super::fault::Scrapi11Fault;
use super::wire;

/// What a submission turned into.
#[derive(Debug)]
pub(super) enum Submitted {
    /// The receipt, synchronously.
    Receipt(Vec<u8>),
    /// Accepted; poll here.
    Pending(String),
}

/// What one poll of the receipt resource said.
#[derive(Debug)]
pub(super) enum Polled {
    /// The receipt.
    Ready(Vec<u8>),
    /// Not yet — ask again if the budget allows.
    StillWorking,
    /// An answer this reader cannot use. Polling ends here.
    Unusable(Scrapi11Fault),
}

/// The COSE body of a response that must carry one.
pub(super) fn cose_body(response: &HttpResponse, phase: Phase) -> Result<Vec<u8>, Scrapi11Fault> {
    let media_type = response.header("content-type").unwrap_or_default();
    if !wire::is_cose(media_type) {
        return Err(Scrapi11Fault::UnsupportedMediaType {
            phase,
            media_type: media_type.to_owned(),
        });
    }
    if response.body.is_empty() {
        return Err(Scrapi11Fault::MalformedResponse {
            phase,
            detail: "a receipt was announced and the body is empty",
        });
    }
    Ok(response.body.clone())
}

/// The URL a `202` named, checked to be under the configured service.
fn poll_target(response: &HttpResponse, base_url: &str) -> Result<String, Scrapi11Fault> {
    let location = response
        .header("location")
        .ok_or(Scrapi11Fault::MissingLocation)?
        .to_owned();
    // The base is operator configuration; this URL is the service's choice. Requiring
    // it to sit under the base is what stops an answer of
    // `Location: http://169.254.169.254/` from being fetched.
    if !location.starts_with(&format!("{base_url}/")) {
        return Err(Scrapi11Fault::LocationOutsideService { location });
    }
    Ok(location)
}

/// What the SUBMISSION's answer says.
///
/// `base_url` is here for one reason: a `202` names where to poll, and that URL is the
/// SERVICE's choice rather than the operator's. Reading the answer is where that choice is
/// checked, because there is no later point at which the URL is still just data.
pub(super) fn read_submission(
    response: &HttpResponse,
    base_url: &str,
) -> Result<Submitted, Scrapi11Fault> {
    let phase = Phase::Submitting;
    match response.status {
        wire::STATUS_CREATED => cose_body(response, phase).map(Submitted::Receipt),
        wire::STATUS_ACCEPTED => poll_target(response, base_url).map(Submitted::Pending),
        wire::STATUS_TOO_MANY_REQUESTS => Err(Scrapi11Fault::RateLimited {
            status: response.status,
        }),
        wire::STATUS_UNAVAILABLE => Err(Scrapi11Fault::Unavailable {
            status: response.status,
        }),
        status if wire::is_refusal(status) => Err(Scrapi11Fault::Refused { status }),
        status => Err(Scrapi11Fault::ProtocolError { phase, status }),
    }
}

/// What a POLL of the receipt resource says.
pub(super) fn read_poll(response: &HttpResponse) -> Polled {
    let phase = Phase::Polling;
    match response.status {
        wire::STATUS_READY => match cose_body(response, phase) {
            Ok(receipt) => Polled::Ready(receipt),
            Err(fault) => Polled::Unusable(fault),
        },
        // Still working. `204` is the draft's spelling; a service that keeps answering
        // `202` on the operation resource is saying the same thing, and so — for a loop
        // that is waiting — is one asking us to slow down.
        wire::STATUS_PENDING
        | wire::STATUS_ACCEPTED
        | wire::STATUS_TOO_MANY_REQUESTS
        | wire::STATUS_UNAVAILABLE => Polled::StillWorking,
        status => Polled::Unusable(Scrapi11Fault::ProtocolError { phase, status }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "https://ts.example.test/scitt";

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

    /// A `202` naming an authority outside the configured service is refused, and the
    /// refusal names the location so an operator can see what was offered.
    #[test]
    fn a_location_outside_the_service_is_refused_by_the_reader() {
        for location in [
            "http://169.254.169.254/latest/meta-data/",
            "https://ts.example.test.evil/scitt/operations/1",
            "https://ts.example.test/other/operations/1",
        ] {
            let fault = read_submission(&response(202, &[("location", location)], b""), BASE)
                .expect_err("outside the service");
            assert!(
                matches!(fault, Scrapi11Fault::LocationOutsideService { .. }),
                "{location}: {fault:?}",
            );
        }
        let accepted = read_submission(
            &response(
                202,
                &[("location", "https://ts.example.test/scitt/operations/1")],
                b"",
            ),
            BASE,
        )
        .expect("under the configured service");
        assert!(matches!(accepted, Submitted::Pending(_)));
    }

    /// A `202` with no `Location` has nothing to poll, and says so as its own fault.
    #[test]
    fn a_202_without_a_location_is_its_own_fault() {
        let fault = read_submission(&response(202, &[], b""), BASE).expect_err("no location");
        assert_eq!(fault, Scrapi11Fault::MissingLocation);
    }

    /// A body announced as a receipt must arrive as one: the right media type, non-empty.
    #[test]
    fn a_receipt_body_is_read_only_under_the_cose_media_type() {
        let cose = [("content-type", "application/cose")];
        assert!(matches!(
            read_submission(&response(201, &cose, b"\xd2\x84"), BASE),
            Ok(Submitted::Receipt(_)),
        ));
        assert!(matches!(
            read_submission(
                &response(201, &[("content-type", "application/json")], b"{}"),
                BASE
            ),
            Err(Scrapi11Fault::UnsupportedMediaType { .. }),
        ));
        assert!(matches!(
            read_submission(&response(201, &cose, b""), BASE),
            Err(Scrapi11Fault::MalformedResponse { .. }),
        ));
    }

    /// A `429` on the submission is the rate limiter; a `503` is not knowable that way.
    #[test]
    fn a_submission_rate_limit_and_a_503_are_different_faults() {
        assert_eq!(
            read_submission(&response(429, &[], b""), BASE).expect_err("rate limited"),
            Scrapi11Fault::RateLimited { status: 429 },
        );
        assert_eq!(
            read_submission(&response(503, &[], b""), BASE).expect_err("unavailable"),
            Scrapi11Fault::Unavailable { status: 503 },
        );
    }

    /// The poll reader keeps `204` as *still working* — not success, and not failure.
    #[test]
    fn a_pending_answer_is_neither_success_nor_failure() {
        for status in [204, 202, 429, 503] {
            assert!(
                matches!(read_poll(&response(status, &[], b"")), Polled::StillWorking),
                "{status}",
            );
        }
        assert!(matches!(
            read_poll(&response(
                200,
                &[("content-type", "application/cose")],
                b"\xd2\x84",
            )),
            Polled::Ready(_),
        ));
        assert!(matches!(
            read_poll(&response(404, &[], b"")),
            Polled::Unusable(Scrapi11Fault::ProtocolError { status: 404, .. }),
        ));
    }
}
