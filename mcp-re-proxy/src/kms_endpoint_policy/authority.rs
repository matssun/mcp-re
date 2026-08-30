// SPDX-License-Identifier: Apache-2.0
//! Where a KMS endpoint's authority DIVIDES into host and port.
//!
//! Grammar, not policy — which is why it is its own module. An IPv6 literal carries colons
//! of its own, so splitting on the first one would read `[::1]:4566`'s host as `[` and its
//! port as `:1]:4566`. The bracket is what says where the literal ends, and getting it
//! wrong would let the policy next door judge a host nobody wrote.

/// Where the host ends and the port begins.
///
/// An IPv6 literal keeps its brackets, because that is the form both the request line and
/// a `Host` header carry. Splitting on the bracket rather than on the first `:` is what
/// makes `[::1]:4566` divide where a parser divides it.
pub(super) fn split_authority<'a>(
    authority: &'a str,
    value: &str,
) -> Result<(&'a str, Option<&'a str>), String> {
    if !authority.starts_with('[') {
        return Ok(match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        });
    }
    let end = authority
        .find(']')
        .ok_or_else(|| format!("has an unterminated IPv6 literal: {value:?}"))?;
    // Class C: `end` is an ASCII `]`'s byte offset, so `end + 1` is a char boundary at
    // most `authority.len()`. A position, not `split_once`: the literal keeps its bracket.
    #[allow(clippy::arithmetic_side_effects)]
    match &authority[end + 1..] {
        "" => Ok((&authority[..=end], None)),
        after => Ok((
            &authority[..=end],
            Some(after.strip_prefix(':').ok_or_else(|| {
                format!("has junk after its IPv6 literal ({after:?}): {value:?}")
            })?),
        )),
    }
}
