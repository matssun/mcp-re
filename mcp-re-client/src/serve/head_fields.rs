// SPDX-License-Identifier: Apache-2.0
//! What the head says, and the ORDER the refusals run in.
//!
//! Four fields are read and the rest are ignored. Two of them refuse a DUPLICATE rather
//! than picking one: a repeated `Content-Length` is a request-smuggling primitive, not a
//! formatting quirk — two lengths let a reader and a writer disagree about where the message
//! ends — and a repeated `Host` is the routing analogue, where the loopback guard and
//! whatever reads the head next could pick different ones.
//!
//! Then the order. FRAMING is settled first, so a message with no boundary is refused as one
//! whatever else it carries: a head that cannot be framed says nothing reliable about its
//! headers. Only then the three caller-shape guards, and all three run before a single byte
//! is signed.

use super::guards::is_json_content_type;
use super::guards::is_loopback_host;
use super::MAX_BODY_BYTES;

/// The four header fields this listener reads, and the duplicates it refuses.
///
/// A repeated `Content-Length` is a request-smuggling primitive, not a formatting quirk:
/// two lengths let a reader and a writer disagree about where the message ends. A repeated
/// `Host` is the routing analogue — the loopback guard and whatever reads the head next
/// could pick different ones.
pub(super) struct HeadFields<'a> {
    content_length: Option<usize>,
    origin: Option<&'a str>,
    host: Option<&'a str>,
    content_type: Option<&'a str>,
}

impl<'a> HeadFields<'a> {
    pub(super) fn read(lines: impl Iterator<Item = &'a str>) -> Result<Self, u16> {
        let mut content_length: Option<usize> = None;
        let mut origin: Option<&str> = None;
        let mut host: Option<&str> = None;
        let mut content_type: Option<&str> = None;
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim();
            let value = value.trim();
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
    allow_any_host: bool,
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
    if !allow_any_host && !is_loopback_host(head.host.ok_or(400u16)?) {
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
