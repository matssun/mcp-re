// SPDX-License-Identifier: Apache-2.0
//! The capacity of the listener's delegated TLS handshake-signature budget.
//!
//! Two inputs to ONE value: each flag replaces one term of a
//! [`HandshakeSignCapacity`](crate::delegated_tls::HandshakeSignCapacity), and the type checks
//! the term it receives. The bounds are the type's; this module owns only the spelling.

use crate::tls::ServerLimits;

/// Whether this flag is one of the budget's two terms.
pub(super) fn owns(flag: &str) -> bool {
    matches!(
        flag,
        "--tls-handshake-sign-rate" | "--tls-handshake-sign-burst"
    )
}

/// Read one term into `limits`. [`owns`] decided it is one.
pub(super) fn take(limits: &mut ServerLimits, flag: &str, value: &str) -> Result<(), String> {
    let n: u32 = value
        .parse()
        .map_err(|_| format!("invalid {flag} (expected a whole number of signatures)"))?;
    let current = limits.tls_handshake_signing;
    let next = if flag == "--tls-handshake-sign-rate" {
        current.with_rate_per_sec(n)
    } else {
        current.with_burst(n)
    };
    limits.tls_handshake_signing = next.map_err(|why| format!("{flag}: {why}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{owns, take};
    use crate::delegated_tls::HandshakeSignCapacity;
    use crate::tls::ServerLimits;

    #[test]
    fn each_flag_replaces_its_own_term_and_leaves_the_other() {
        let mut limits = ServerLimits::default();
        take(&mut limits, "--tls-handshake-sign-rate", "250").expect("in bounds");
        take(&mut limits, "--tls-handshake-sign-burst", "40").expect("in bounds");
        assert_eq!(
            limits.tls_handshake_signing,
            HandshakeSignCapacity::new(250, 40).expect("in bounds")
        );
    }

    #[test]
    fn an_out_of_bounds_or_unparsable_term_is_refused_naming_the_flag() {
        for (flag, value) in [
            ("--tls-handshake-sign-rate", "0"),
            ("--tls-handshake-sign-rate", "1001"),
            ("--tls-handshake-sign-burst", "0"),
            ("--tls-handshake-sign-burst", "2001"),
            ("--tls-handshake-sign-burst", "-1"),
        ] {
            let mut limits = ServerLimits::default();
            let err = take(&mut limits, flag, value).expect_err("must refuse");
            assert!(err.contains(flag), "the refusal must name {flag}: {err}");
            assert_eq!(
                limits.tls_handshake_signing,
                HandshakeSignCapacity::default(),
                "a refused term must leave the capacity untouched"
            );
        }
    }

    #[test]
    fn only_the_two_terms_are_owned() {
        assert!(owns("--tls-handshake-sign-rate"));
        assert!(owns("--tls-handshake-sign-burst"));
        assert!(!owns("--max-connections"));
    }
}
