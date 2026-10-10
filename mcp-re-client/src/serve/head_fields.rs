// SPDX-License-Identifier: Apache-2.0
//! What the head says, and the ORDER the refusals run in.
//!
//! Four fields are read and the rest are ignored. Three of them refuse a DUPLICATE rather
//! than picking one: a repeated `Content-Length` is a request-smuggling primitive, not a
//! formatting quirk — two lengths let a reader and a writer disagree about where the message
//! ends — a repeated `Host` is the routing analogue, where the loopback guard and
//! whatever reads the head next could pick different ones, and a repeated `Content-Type`
//! would make the JSON guard depend on which of two values is read last.
//!
//! Then the order. FRAMING is settled first, so a message with no boundary is refused as one
//! whatever else it carries: a head that cannot be framed says nothing reliable about its
//! headers. Only then the three caller-shape guards, and all three run before a single byte
//! is signed.

use super::accepted_authority::AcceptedHttpAuthority;
use super::guards::is_json_content_type;
use super::MAX_BODY_BYTES;

/// The four header fields this listener reads, and the duplicates it refuses.
///
/// A repeated `Content-Length` is a request-smuggling primitive, not a formatting quirk:
/// two lengths let a reader and a writer disagree about where the message ends. A repeated
/// `Host` is the routing analogue — the loopback guard and whatever reads the head next
/// could pick different ones. A repeated `Content-Type` has no single answer either: the
/// JSON guard would depend on which of two values is read last.
pub(super) struct HeadFields<'a> {
    content_length: Option<usize>,
    origin: Option<&'a str>,
    host: Option<&'a str>,
    content_type: Option<&'a str>,
}

/// One head line as a field: `None` for a line that is not one, a refusal for a line a
/// front parser may read differently.
///
/// An obs-fold continuation (leading space or tab) and whitespace between the field name and
/// the colon are the Content-Length smuggling class, so both are refused rather than read;
/// a continuation is refused whether or not it has a colon.
fn field_line(line: &str) -> Result<Option<(&str, &str)>, u16> {
    if line.starts_with([' ', '\t']) {
        return Err(400);
    }
    let Some((name, value)) = line.split_once(':') else {
        return Ok(None);
    };
    if name.contains([' ', '\t']) {
        return Err(400);
    }
    Ok(Some((name, value.trim())))
}

impl<'a> HeadFields<'a> {
    pub(super) fn read(lines: impl Iterator<Item = &'a str>) -> Result<Self, u16> {
        let mut content_length: Option<usize> = None;
        let mut origin: Option<&str> = None;
        let mut host: Option<&str> = None;
        let mut content_type: Option<&str> = None;
        for line in lines {
            let Some((name, value)) = field_line(line)? else {
                continue;
            };
            if name.eq_ignore_ascii_case("content-length") {
                // A repeated Content-Length is a request-smuggling primitive, not a
                // formatting quirk: two lengths let a reader and a writer disagree about
                // where the message ends.
                if content_length.is_some() {
                    return Err(400);
                }
                content_length = Some(value.parse::<usize>().map_err(|_| 400u16)?);
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                return Err(411);
            } else if name.eq_ignore_ascii_case("origin") {
                origin = Some(value);
            } else if name.eq_ignore_ascii_case("host") {
                // A repeated Host is the routing analogue of a repeated Content-Length:
                // the guard below and whatever reads the head next could pick different
                // ones.
                if host.is_some() {
                    return Err(400);
                }
                host = Some(value);
            } else if name.eq_ignore_ascii_case("content-type") {
                // A caller-shape guard field with two values has no single answer.
                if content_type.is_some() {
                    return Err(400);
                }
                content_type = Some(value);
            }
        }
        Ok(HeadFields {
            content_length,
            origin,
            host,
            content_type,
        })
    }
}

/// Framing, then the three caller-shape guards, and the ORDER is the point.
///
/// A message with no boundary is refused as one whatever else it carries — a head that
/// cannot be framed says nothing reliable about its headers. All three guards then run
/// before a single byte is signed. Returns the body length the framing settled.
pub(super) fn check_framing_and_caller_shape(
    head: &HeadFields<'_>,
    accepted_authority: &AcceptedHttpAuthority,
) -> Result<usize, u16> {
    // FRAMING first, so a message with no boundary is refused as one whatever else it
    // carries — a head that cannot be framed says nothing reliable about its headers.
    let length = head.content_length.ok_or(411u16)?;
    if length > MAX_BODY_BYTES {
        return Err(413);
    }

    // Then the caller-shape guards. All three run before a single byte is signed.
    //
    // A browser sends `Origin` on every cross-origin request and no MCP client sends
    // one at all, so its mere presence identifies the caller as one this socket does
    // not serve. Refused rather than compared against an allowlist: there is no origin
    // that should be able to drive this signing key.
    if head.origin.is_some() {
        return Err(403);
    }
    // The rebinding half. A page served from `evil.example` whose name resolves to
    // `127.0.0.1` is SAME-origin to the browser, so it sends no `Origin` — but it does
    // send that name as `Host`, and a loopback literal is what it cannot forge.
    if !accepted_authority.admits(head.host.ok_or(400u16)?) {
        return Err(421);
    }
    // A CORS-"simple" POST may carry only `text/plain`, `application/x-www-form-
    // urlencoded` or `multipart/form-data`; anything else costs the page a preflight
    // this listener never answers. Requiring JSON therefore costs a real MCP client
    // nothing and removes the no-preflight path entirely.
    if !is_json_content_type(head.content_type.ok_or(415u16)?) {
        return Err(415);
    }
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BindScope;

    fn authority(bind: &str, declared: bool) -> AcceptedHttpAuthority {
        AcceptedHttpAuthority::for_listener(
            &BindScope::decide(bind.parse().expect("an address"), declared).expect("a legal bind"),
        )
    }

    fn head(lines: &[&str]) -> HeadFields<'static> {
        // The borrow is of the leaked slice, which outlives the assertion.
        let leaked: &'static [String] = Box::leak(
            lines
                .iter()
                .map(|l| (*l).to_owned())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        HeadFields::read(leaked.iter().map(String::as_str)).expect("a readable head")
    }

    const WELL_FORMED: &[&str] = &[
        "Content-Length: 2",
        "Host: 127.0.0.1:8640",
        "Content-Type: application/json",
    ];

    #[test]
    fn a_well_formed_local_request_passes_every_guard() {
        assert_eq!(
            check_framing_and_caller_shape(&head(WELL_FORMED), &authority("127.0.0.1:8640", false)),
            Ok(2),
        );
    }

    /// THE WIRING, not the predicate. `check_framing_and_caller_shape` used to take a
    /// boolean derived from `local.allow_non_loopback`, so an operator who bound off-host
    /// reached this line with the rebinding guard switched off. It takes the authority
    /// itself now, and there is no boolean to be wrong about.
    #[test]
    fn a_rebound_host_is_refused_on_an_exposed_listener_too() {
        let rebound = &[
            "Content-Length: 2",
            "Host: rebound.evil.example",
            "Content-Type: application/json",
        ];
        for (bind, declared) in [("127.0.0.1:8640", false), ("198.51.100.7:8640", true)] {
            assert_eq!(
                check_framing_and_caller_shape(&head(rebound), &authority(bind, declared)),
                Err(421),
                "a rebound name must not reach the signing key on a {bind} listener",
            );
        }
    }

    /// The mirror: the exposed listener still serves the deployment that asked for it.
    #[test]
    fn an_exposed_listener_serves_its_own_authority() {
        let own = &[
            "Content-Length: 2",
            "Host: 198.51.100.7:8640",
            "Content-Type: application/json",
        ];
        assert_eq!(
            check_framing_and_caller_shape(&head(own), &authority("198.51.100.7:8640", true)),
            Ok(2),
        );
    }

    /// Framing is settled before the caller-shape guards, so a head with no boundary is
    /// refused as one whatever else it carries.
    #[test]
    fn framing_is_refused_before_the_caller_shape_guards() {
        let unframed = &["Host: rebound.evil.example", "Origin: https://evil.example"];
        assert_eq!(
            check_framing_and_caller_shape(&head(unframed), &authority("127.0.0.1:8640", false)),
            Err(411),
        );
    }

    #[test]
    fn the_three_caller_shape_guards_each_refuse_with_their_own_status() {
        let cases: [(&[&str], u16); 3] = [
            (
                &[
                    "Content-Length: 2",
                    "Host: 127.0.0.1",
                    "Origin: https://evil.example",
                    "Content-Type: application/json",
                ],
                403,
            ),
            (
                &["Content-Length: 2", "Content-Type: application/json"],
                400,
            ),
            (
                &[
                    "Content-Length: 2",
                    "Host: 127.0.0.1",
                    "Content-Type: text/plain",
                ],
                415,
            ),
        ];
        for (lines, status) in cases {
            assert_eq!(
                check_framing_and_caller_shape(&head(lines), &authority("127.0.0.1:8640", false)),
                Err(status),
            );
        }
    }

    fn read_err(lines: &[&str]) -> Option<u16> {
        let leaked: &'static [String] = Box::leak(
            lines
                .iter()
                .map(|l| (*l).to_owned())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        HeadFields::read(leaked.iter().map(String::as_str)).err()
    }

    #[test]
    fn a_transfer_encoding_is_refused_rather_than_parsed() {
        for lines in [
            &[
                "Transfer-Encoding: chunked",
                "Host: 127.0.0.1",
                "Content-Type: application/json",
            ][..],
            &[
                "Content-Length: 2",
                "Transfer-Encoding: chunked",
                "Host: 127.0.0.1",
                "Content-Type: application/json",
            ][..],
            &[
                "transfer-encoding: chunked",
                "Content-Length: 2",
                "Host: 127.0.0.1",
                "Content-Type: application/json",
            ][..],
        ] {
            assert_eq!(read_err(lines), Some(411));
        }
    }

    #[test]
    fn the_body_ceiling_admits_its_own_size_and_refuses_one_byte_past_it() {
        let at = format!("Content-Length: {MAX_BODY_BYTES}");
        let past = format!("Content-Length: {}", MAX_BODY_BYTES + 1);
        let guard = authority("127.0.0.1:8640", false);
        assert_eq!(
            check_framing_and_caller_shape(
                &head(&[
                    &at,
                    "Host: 127.0.0.1:8640",
                    "Content-Type: application/json"
                ]),
                &guard,
            ),
            Ok(MAX_BODY_BYTES),
        );
        assert_eq!(
            check_framing_and_caller_shape(
                &head(&[
                    &past,
                    "Host: 127.0.0.1:8640",
                    "Content-Type: application/json"
                ]),
                &guard,
            ),
            Err(413),
        );
    }

    #[test]
    fn a_duplicate_content_type_is_refused_rather_than_resolved() {
        for lines in [
            &[
                "Content-Length: 2",
                "Host: 127.0.0.1",
                "Content-Type: application/json",
                "Content-Type: text/plain",
            ][..],
            &[
                "Content-Length: 2",
                "Host: 127.0.0.1",
                "Content-Type: text/plain",
                "Content-Type: application/json",
            ][..],
        ] {
            assert_eq!(read_err(lines), Some(400));
        }
    }

    #[test]
    fn a_duplicate_length_or_host_is_refused_rather_than_resolved() {
        for lines in [
            &["Content-Length: 2", "Content-Length: 3", "Host: 127.0.0.1"][..],
            &["Content-Length: 2", "Host: 127.0.0.1", "Host: evil.example"][..],
        ] {
            let leaked: &'static [String] = Box::leak(
                lines
                    .iter()
                    .map(|l| (*l).to_owned())
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            );
            assert_eq!(
                HeadFields::read(leaked.iter().map(String::as_str)).err(),
                Some(400)
            );
        }
    }
}
