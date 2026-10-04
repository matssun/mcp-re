//! Which argv token is a flag, which is its value, and how often a flag may be stated.
//!
//! One fact lives here: the shape of the argument list. The families own what each flag
//! means; this reader owns where one statement ends and the next begins, so a missing
//! value is a refusal and a second statement of a single-valued flag is a refusal, never
//! a silent precedence.

use super::Flags;

/// The flags whose family accumulates every statement into a list.
const REPEATABLE: [&str; 7] = [
    "--inner-http-url",
    "--client-crl",
    "--mcp-protocol-version",
    "--ingress-lb-key",
    "--ingress-attestor-key",
    "--ingress-identity",
    "--revocation-list",
];

/// Read an argument list (excluding argv[0]) into the flag families.
pub(super) fn read(args: &[String]) -> Result<Flags, String> {
    let mut flags = Flags::default();
    let mut stated: Vec<(&str, &str)> = Vec::new();
    let mut tokens = args.iter().map(String::as_str);
    while let Some(flag) = tokens.next() {
        if flags.take_switch(flag) {
            continue;
        }
        let value = tokens
            .next()
            .ok_or_else(|| format!("flag {flag} requires a value"))?;
        if names_a_flag(value) {
            return Err(format!(
                "flag {flag} requires a value; {value} is a flag, not its value"
            ));
        }
        flags.take(flag, value)?;
        if REPEATABLE.contains(&flag) {
            continue;
        }
        if let Some((_, first)) = stated.iter().find(|(seen, _)| *seen == flag) {
            return Err(format!(
                "{flag} is stated twice ('{first}', then '{value}'); a single-valued flag is \
                 refused rather than resolved by precedence - state it once"
            ));
        }
        stated.push((flag, value));
    }
    Ok(flags)
}

/// Whether a token is a spelling some family owns, switch or value-taking.
///
/// A scratch accumulator probes the switch set, so the switch spellings stay single-sourced
/// in their families. A leading `--` alone is not enough: a raw base64url key can begin
/// with it.
fn names_a_flag(token: &str) -> bool {
    Flags::default().take_switch(token) || Flags::owns(token)
}

/// A flag no family owns.
///
/// One spelling is recognised only to REFUSE it with the reason and the replacement.
/// Falling through to "unknown flag" would be a worse error for the one operator who most
/// needs to understand what changed — and worse, it would report a secret-handling decision
/// as a typo.
pub(super) fn refused_or_unknown(flag: &str) -> String {
    if flag == "--pkcs11-pin" {
        // The PIN has already been exposed at this point (it is in this process's argv,
        // which is world-readable): the refusal is about not making it a standing exposure,
        // and the operator should treat that PIN as compromised and change it.
        return "--pkcs11-pin is refused: a process command line is world-readable \
                (ps, /proc/<pid>/cmdline), so the PIN unlocking the token that holds the \
                signing keys would be published to every local user for the lifetime of the \
                process. Use --pkcs11-pin-file <path> with a 0600 file. Treat any PIN \
                previously passed this way as compromised."
            .to_string();
    }
    format!("unknown flag {flag}")
}

#[cfg(test)]
mod tests {
    use super::read;

    fn argv(tokens: &[&str]) -> Vec<String> {
        tokens.iter().map(|t| (*t).to_string()).collect()
    }

    #[test]
    fn a_flag_spelling_in_a_value_position_is_a_missing_value() {
        for tok in [
            "--fleet",
            "--ingress-pinned-mtls",
            "--allow-group-readable-key-files",
            "--trust-domain",
        ] {
            let err = read(&argv(&["--audience", tok])).err().expect("refused");
            assert!(err.contains("--audience") && err.contains(tok), "{err}");
        }
    }

    #[test]
    fn a_value_that_is_not_a_flag_spelling_is_read_as_a_value() {
        assert!(read(&argv(&["--audience", "--not-a-flag", "--fleet"])).is_ok());
        assert!(read(&argv(&["--audience", "did:example:s", "--fleet"])).is_ok());
    }

    #[test]
    fn a_single_valued_flag_stated_twice_is_refused_naming_both() {
        for flag in [
            "--client-ca",
            "--trust",
            "--tls-cert",
            "--audience",
            "--server-signer",
        ] {
            let err = read(&argv(&[flag, "/a", flag, "/b"]))
                .err()
                .expect("refused");
            assert!(
                err.contains(flag) && err.contains("/a") && err.contains("/b"),
                "{err}"
            );
        }
    }

    #[test]
    fn a_repeatable_flag_stated_twice_accumulates() {
        let key = "lb-1:1i8Bah79Hk_feT60LNhEceG6nwzwTRKHtcxx9hYofLg";
        let key2 = "lb-2:1i8Bah79Hk_feT60LNhEceG6nwzwTRKHtcxx9hYofLg";
        let cases: [(&str, &str, &str); 7] = [
            (
                "--inner-http-url",
                "http://127.0.0.1:8080/mcp",
                "http://127.0.0.1:8081/mcp",
            ),
            ("--client-crl", "/a", "/b"),
            ("--mcp-protocol-version", "2026-07-28", "2025-06-18"),
            ("--ingress-lb-key", key, key2),
            ("--ingress-attestor-key", key, key2),
            ("--ingress-identity", "/a", "/b"),
            ("--revocation-list", "/a", "/b"),
        ];
        for (flag, v, v2) in cases {
            assert!(read(&argv(&[flag, v, flag, v2])).is_ok(), "{flag}");
        }
    }
}
