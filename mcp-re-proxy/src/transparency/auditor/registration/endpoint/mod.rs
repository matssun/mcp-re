// SPDX-License-Identifier: Apache-2.0
//! WHICH transparency service this run will register with, and under what budget.
//!
//! One fact: **the operator-configured registration endpoint, admitted.**
//!
//! It is a configuration fact and never request input: nothing a client sent, and nothing
//! a retained record contains, can influence where this auditor connects. That is why the
//! endpoint arrives on the command line beside the pin rather than being read out of the
//! archive.
//!
//! Selecting the mechanism is also here, and deliberately: this is the one place that
//! knows a target means SCRAPI, so the layer above holds a target and the layer below
//! holds a protocol.

use std::time::Duration;

use mcp_re_http_profile::scitt::ScittServiceTrustPin;
use mcp_re_http_profile::scitt::SignedStatement;
use mcp_re_http_profile::scitt::TransparencyKeyLifecycle;

use super::policy::RegistrationPolicy;
use super::RegisteredStatement;
use super::RegistrationError;
use super::RegistrationProtocol;

/// WHAT the operator's registration flags say.
mod flags;

/// Where this run registers, and how long it may take doing it.
///
/// # What construction proved
///
/// The URL passed this workspace's outbound-network policy as an operator-configured
/// destination, it is `https` (or plaintext to the loopback interface, where there is no
/// network to observe), and the budget terminates.
#[derive(Debug, Clone)]
pub struct RegistrationTarget {
    base_url: String,
    // Read only by the transport. Without `scitt_registration` the target is still
    // constructed and validated — an unusable budget or protocol is refused in every
    // build — but `register` refuses before reading it.
    #[cfg_attr(not(feature = "scitt_registration"), allow(dead_code))]
    policy: RegistrationPolicy,
    /// WHICH contract the operator said this endpoint speaks.
    ///
    /// Named, never inferred from the URL: reaching a service by coincidence of shape
    /// while calling a different contract by another's name is the laundering the
    /// mechanism-leaf boundary exists to prevent.
    // Read only by the transport. Without `scitt_registration` the target is still
    // constructed and validated — an unusable budget or protocol is refused in every
    // build — but `register` refuses before reading it.
    #[cfg_attr(not(feature = "scitt_registration"), allow(dead_code))]
    protocol: RegistrationProtocol,
}

/// Whether `url` names the loopback interface, the one host plaintext is admitted to:
/// the authority is exactly a loopback host and an optional numeric port, no userinfo.
fn is_loopback(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    ["127.0.0.1", "[::1]", "localhost"]
        .iter()
        .filter_map(|host| authority.strip_prefix(host))
        .any(is_port_suffix)
}

/// Whether `rest`, the authority after its host, is empty or `:` and one or more digits.
fn is_port_suffix(rest: &str) -> bool {
    rest.is_empty()
        || rest
            .strip_prefix(':')
            .is_some_and(|port| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
}

impl RegistrationTarget {
    /// A target, or the first rule it breaks.
    ///
    /// Plaintext is refused off the loopback interface. A registration is a claim about
    /// specific octets reaching a specific service, and a receipt is only worth what
    /// knowing who answered is worth; over plaintext an operator knows neither, and the
    /// pin cannot recover it because the pin is checked against whatever came back.
    pub fn new(
        base_url: &str,
        protocol: RegistrationProtocol,
        timeout: Duration,
        interval: Option<Duration>,
    ) -> Result<Self, String> {
        // Owner Ruling 6: `--register-to` is operator-supplied and BOTH refusals below fire
        // on a WELL-FORMED URL — the scheme verdict and the plaintext rule each admit a
        // string carrying `user:password@`. The configured text is therefore named through
        // the one projection that cannot carry it, never echoed.
        let locator = crate::deployment_request::RedactedLocator::of(base_url);
        if crate::outbound_fetch::VettedDestination::operator_configured(base_url).is_none() {
            return Err(format!(
                "--register-to {locator}: not a destination this proxy may fetch from",
            ));
        }
        if !base_url.starts_with("https://") && !is_loopback(base_url) {
            return Err(format!(
                "--register-to {locator}: registration is HTTPS. Plaintext is admitted \
                 only to the loopback interface, where there is no network to observe it",
            ));
        }
        let policy = match (protocol, interval) {
            (RegistrationProtocol::Scrapi11, Some(interval)) => {
                RegistrationPolicy::new(timeout, interval)?
            }
            (RegistrationProtocol::CapsuleAnchor, None) => {
                RegistrationPolicy::single_exchange(timeout)?
            }
            (RegistrationProtocol::CapsuleAnchor, Some(_)) => {
                return Err(
                    "--registration-poll-interval-secs does not apply to --registration-protocol \
                     capsule-anchor: that contract has no polling, so the term would select \
                     nothing"
                        .to_owned(),
                );
            }
            (RegistrationProtocol::Scrapi11, None) => {
                return Err(
                    "--registration-protocol scrapi-11 polls, so its budget needs a poll interval"
                        .to_owned(),
                );
            }
        };
        Ok(RegistrationTarget {
            base_url: base_url.trim_end_matches('/').to_owned(),
            policy,
            protocol,
        })
    }

    /// The service this run registers with.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Register `statement` with this target, and accept the answer only if it verifies.
    ///
    /// The whole cfg is here, in one function, so every caller is unconditional. Without
    /// the transport this build refuses rather than pretending: a binary that cannot open
    /// a socket has definitively not registered anything, which is what
    /// [`RegistrationError::Refused`] means.
    #[cfg(feature = "scitt_registration")]
    pub fn register(
        &self,
        statement: &SignedStatement,
        issuer_key: &mcp_re_core::VerificationKey,
        pin: &ScittServiceTrustPin,
        ts_key: &dyn Fn(&str) -> Option<TransparencyKeyLifecycle>,
        now: i64,
    ) -> Result<RegisteredStatement, RegistrationError> {
        let exchange = super::ureq_exchange::UreqExchange::operator_configured(&self.base_url)
            .ok_or_else(|| {
                // Defence in depth, and unreachable under the current legality model: `new`
                // already put this value through the same vetting. Redacted regardless — a
                // branch that cannot fire today is the one nobody re-reads when it can.
                RegistrationError::Refused(format!(
                    "{} is not a destination this proxy may fetch from",
                    crate::deployment_request::RedactedLocator::of(&self.base_url),
                ))
            })?;
        // The one place a target becomes a protocol. Which arm runs is the operator's
        // stated choice, and both arms hand the SAME verifying function a mechanism —
        // there is no second path to a `RegisteredStatement`.
        match self.protocol {
            RegistrationProtocol::Scrapi11 => super::capability::register_and_verify(
                &super::scrapi::Scrapi11RegistrationClient::new(
                    exchange,
                    &self.base_url,
                    self.policy,
                ),
                statement,
                issuer_key,
                pin,
                ts_key,
                now,
            ),
            RegistrationProtocol::CapsuleAnchor => super::capability::register_and_verify(
                &super::capsule_anchor::CapsuleAnchorRegistrationClient::new(
                    exchange,
                    &self.base_url,
                    self.policy,
                ),
                statement,
                issuer_key,
                pin,
                ts_key,
                now,
            ),
        }
    }

    /// The build with no registration transport refuses, and says which build it is.
    ///
    /// Compile-completeness, and no shipped binary reaches it — so it has no test, which is
    /// stated here rather than left to be looked for. `mcp-re-auditor` links the flavor
    /// that turns the transport on, and the only flavor without it is the serving library,
    /// which constructs no `RegistrationTarget` at all. What the arm exists for is that the
    /// module compiles in that flavor; `Refused` is the honest verdict because a process
    /// that cannot open a socket has definitively submitted nothing.
    #[cfg(not(feature = "scitt_registration"))]
    pub fn register(
        &self,
        _statement: &SignedStatement,
        _issuer_key: &mcp_re_core::VerificationKey,
        _pin: &ScittServiceTrustPin,
        _ts_key: &dyn Fn(&str) -> Option<TransparencyKeyLifecycle>,
        _now: i64,
    ) -> Result<RegisteredStatement, RegistrationError> {
        Err(RegistrationError::Refused(
            "this build has no registration transport (feature `scitt_registration` is \
             off), so nothing was submitted"
                .to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(url: &str) -> Result<RegistrationTarget, String> {
        RegistrationTarget::new(
            url,
            RegistrationProtocol::default(),
            Duration::from_secs(60),
            Some(Duration::from_secs(1)),
        )
    }

    #[test]
    fn an_https_endpoint_is_a_target_and_loses_its_trailing_separator() {
        let target = target("https://ts.example.test/scitt/").expect("a legal target");
        assert_eq!(target.base_url(), "https://ts.example.test/scitt");
    }

    /// Plaintext is admitted only to the loopback interface.
    #[test]
    fn plaintext_is_refused_off_the_loopback_interface() {
        for url in [
            "http://ts.example.test",
            "http://10.0.0.1:8080",
            "http://127.0.0.1.evil.test",
            "http://localhost.evil.test",
            "http://localhost:8600@evil.test/",
            "http://127.0.0.1:1@attacker.example/",
            "http://[::1]:1@evil.test/",
            "http://http://localhost:1/",
            "http://localhost:8600\\@evil.test/",
            "http://127.0.0.1:86x0",
        ] {
            let refused = target(url).expect_err("plaintext off loopback");
            assert!(refused.contains("HTTPS"), "{url}: {refused}");
        }
        for url in [
            "http://127.0.0.1:8600",
            "http://[::1]:8600/scitt",
            "http://localhost:8600",
            "http://127.0.0.1",
            "http://localhost/scitt",
        ] {
            assert!(target(url).is_ok(), "{url}");
        }
    }

    #[test]
    fn a_scheme_the_network_policy_refuses_is_not_a_target() {
        for url in [
            "file:///etc/passwd",
            "gopher://ts.example/",
            "",
            "not-a-url",
        ] {
            assert!(target(url).is_err(), "{url:?}");
        }
    }

    /// The budget's own refusals reach the operator through this constructor rather than
    /// being discovered mid-run.
    #[test]
    fn an_unterminating_budget_is_not_a_target() {
        assert!(RegistrationTarget::new(
            "https://ts.example.test",
            RegistrationProtocol::default(),
            Duration::from_secs(60),
            Some(Duration::ZERO),
        )
        .is_err());
        assert!(RegistrationTarget::new(
            "https://ts.example.test",
            RegistrationProtocol::default(),
            Duration::from_secs(7_200),
            Some(Duration::from_secs(1)),
        )
        .is_err());
    }

    #[test]
    fn a_budget_shape_the_protocol_does_not_use_is_not_a_target() {
        let url = "https://ts.example.test";
        let second = Duration::from_secs(1);
        let refused = RegistrationTarget::new(
            url,
            RegistrationProtocol::CapsuleAnchor,
            second,
            Some(second),
        )
        .expect_err("capsule-anchor has no polling");
        assert!(
            refused.contains("--registration-poll-interval-secs"),
            "{refused}"
        );
        assert!(RegistrationTarget::new(
            url,
            RegistrationProtocol::Scrapi11,
            Duration::from_secs(60),
            None,
        )
        .is_err());
        assert!(
            RegistrationTarget::new(url, RegistrationProtocol::CapsuleAnchor, second, None).is_ok()
        );
    }

    /// LOAD-BEARING (Owner Ruling 6): `--register-to` is operator-supplied, and BOTH
    /// refusals in `new` fire on a WELL-FORMED URL — the scheme verdict and the plaintext
    /// rule each admit a string carrying `user:password@`, which is the whole point of the
    /// ruling: the shape check is not the boundary. Neither the credential nor the complete
    /// configured string may reach the message, on either branch.
    #[test]
    fn a_register_to_refusal_leaks_neither_the_credential_nor_the_configured_url() {
        for configured in [
            // refused by the scheme allowlist
            "ftp://ops:hunter2@transparency.example.test/",
            // ADMITTED by the allowlist, then refused as off-loopback plaintext
            "http://ops:hunter2@transparency.example.test/",
        ] {
            let why = RegistrationTarget::new(
                configured,
                RegistrationProtocol::default(),
                Duration::from_secs(1),
                Some(Duration::from_secs(1)),
            )
            .expect_err("a credential-bearing endpoint on a refused branch");
            assert!(!why.contains("hunter2"), "credential echoed: {why}");
            assert!(
                !why.contains(configured),
                "the complete configured endpoint was echoed: {why}"
            );
            assert!(
                why.contains("transparency.example.test"),
                "an operator still learns which endpoint was refused: {why}"
            );
        }
    }
}
