// SPDX-License-Identifier: Apache-2.0
//! WHAT the operator's registration flags say.
//!
//! One fact: **whether this invocation asked for a registration, and under what terms.**
//!
//! Separate from [`super::RegistrationTarget`] because the two answer different questions.
//! That one is *an admitted endpoint*: it exists only if the URL passed the outbound
//! policy, is HTTPS off loopback, and carries a terminating budget. This one is *what was
//! typed*, and its whole job is to turn four independent optional strings into either one
//! coherent request or a refusal naming the flag that was wrong.
//!
//! The refusals are the reason it is worth an owner. A budget given with no `--register-to`
//! is REFUSED rather than ignored: an operator who wrote down how long a registration may
//! take has said they expect one, and a run that quietly performed none under that budget
//! would be answering a question they did not ask. The same holds for a protocol named with
//! nothing to speak it to.

use std::time::Duration;

use super::super::RegistrationProtocol;
use super::RegistrationTarget;

impl RegistrationTarget {
    /// The target the auditor's registration FLAGS name, if they name one.
    ///
    /// A budget given without `--register-to` is REFUSED rather than ignored. An operator who
    /// wrote down how long a registration may take has said they expect one, and a run that
    /// quietly performed no registration under that budget would be answering a question they
    /// did not ask.
    pub(in crate::transparency::auditor) fn from_flags(
        url: Option<String>,
        protocol: Option<String>,
        timeout: Option<String>,
        interval: Option<String>,
    ) -> Result<Option<RegistrationTarget>, String> {
        let Some(url) = url else {
            return no_registration(timeout.is_some() || interval.is_some() || protocol.is_some());
        };
        let protocol = match protocol {
            Some(token) => RegistrationProtocol::parse(&token)?,
            None => RegistrationProtocol::default(),
        };
        let timeout = seconds(
            "--registration-timeout-secs",
            timeout,
            DEFAULT_REGISTRATION_TIMEOUT_SECS,
        )?;
        let interval = seconds(
            "--registration-poll-interval-secs",
            interval,
            DEFAULT_POLL_INTERVAL_SECS,
        )?;
        RegistrationTarget::new(&url, protocol, timeout, interval).map(Some)
    }
}

/// The default whole-registration budget, in seconds.
const DEFAULT_REGISTRATION_TIMEOUT_SECS: u64 = 300;

/// The default wait between polls, in seconds.
const DEFAULT_POLL_INTERVAL_SECS: u64 = 2;

/// The answer when no `--register-to` was given: no target, unless a bound was.
///
/// A bound with nothing to bound is refused rather than ignored. An operator who wrote
/// down how long a registration may take has said they expect one, and a run that quietly
/// performed none under that budget would be answering a question they did not ask.
fn no_registration(bounded: bool) -> Result<Option<RegistrationTarget>, String> {
    if bounded {
        return Err(
            "--registration-timeout-secs and --registration-poll-interval-secs \
                    bound a registration, and this invocation has no --register-to"
                .to_owned(),
        );
    }
    Ok(None)
}

/// A duration in whole seconds, or the default.
fn seconds(flag: &str, stated: Option<String>, default: u64) -> Result<Duration, String> {
    let Some(text) = stated else {
        return Ok(Duration::from_secs(default));
    };
    text.parse::<u64>()
        .map(Duration::from_secs)
        .map_err(|_| format!("{flag} {text:?}: not a whole number of seconds"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from(
        url: Option<&str>,
        protocol: Option<&str>,
        timeout: Option<&str>,
        interval: Option<&str>,
    ) -> Result<Option<RegistrationTarget>, String> {
        RegistrationTarget::from_flags(
            url.map(str::to_owned),
            protocol.map(str::to_owned),
            timeout.map(str::to_owned),
            interval.map(str::to_owned),
        )
    }

    /// No `--register-to` and no bounds is a run that registers nothing — the default.
    #[test]
    fn an_invocation_that_names_no_service_registers_nothing() {
        assert!(from(None, None, None, None).expect("legal").is_none());
    }

    /// A term given with nothing to apply it to is REFUSED, never ignored. An operator who
    /// wrote it down expected a registration.
    #[test]
    fn a_term_without_a_service_is_refused_rather_than_ignored() {
        for (protocol, timeout, interval) in [
            (Some("capsule-anchor"), None, None),
            (None, Some("60"), None),
            (None, None, Some("1")),
        ] {
            let refused = from(None, protocol, timeout, interval)
                .expect_err("a term with nothing to bound must refuse");
            assert!(refused.contains("--register-to"), "{refused}");
        }
    }

    /// The protocol is the operator's word. An unknown one refuses before any socket.
    #[test]
    fn an_unknown_protocol_refuses_before_anything_is_submitted() {
        let refused = from(
            Some("https://ts.example.test"),
            Some("scrapi-12"),
            None,
            None,
        )
        .expect_err("not a protocol this auditor speaks");
        assert!(refused.contains("--registration-protocol"), "{refused}");
    }

    /// Both mechanisms are reachable from the command line, and a run that names none
    /// gets the one that was the only one.
    #[test]
    fn each_named_protocol_produces_a_target_and_the_default_is_scrapi() {
        for protocol in [None, Some("scrapi-11"), Some("capsule-anchor")] {
            assert!(
                from(Some("https://ts.example.test"), protocol, None, None)
                    .expect("a legal target")
                    .is_some(),
                "{protocol:?}",
            );
        }
    }

    /// A budget that is not a whole number of seconds names the flag it came from.
    #[test]
    fn a_budget_that_is_not_a_number_names_its_flag() {
        let refused = from(Some("https://ts.example.test"), None, Some("soon"), None)
            .expect_err("not a whole number of seconds");
        assert!(refused.contains("--registration-timeout-secs"), "{refused}");
    }
}
