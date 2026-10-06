// SPDX-License-Identifier: Apache-2.0
//! Who this deployment is — the coordinates a verifier tells it apart by.
//!
//! Four required strings, and the one acknowledgement that lets them hold the shipped
//! placeholders. They are a family because they answer one question and because
//! `ServerIdentity` consumes them as one value; the CLI's job is to read them and to say
//! which one is missing, and nothing more.

/// The identity coordinates, as they accumulate across the argument list.
#[derive(Default)]
pub(super) struct IdentityFlags {
    audience: Option<String>,
    server_signer: Option<String>,
    server_key_id: Option<String>,
    trust_domain: Option<String>,
    allow_example_fixtures: bool,
}

/// What one deployment answers to.
#[derive(Debug)]
pub(super) struct DeploymentIdentity {
    pub(super) audience: String,
    pub(super) server_signer: String,
    pub(super) server_key_id: String,
    pub(super) trust_domain: String,
    pub(super) allow_example_fixtures: bool,
}

impl IdentityFlags {
    /// The coordinate a flag of the family writes, or `None` for any other flag.
    fn slot(&mut self, flag: &str) -> Option<&mut Option<String>> {
        match flag {
            "--audience" => Some(&mut self.audience),
            "--server-signer" => Some(&mut self.server_signer),
            "--server-key-id" => Some(&mut self.server_key_id),
            "--trust-domain" => Some(&mut self.trust_domain),
            _ => None,
        }
    }

    /// Whether this value-taking flag belongs to the family.
    pub(super) fn owns(flag: &str) -> bool {
        Self::default().slot(flag).is_some()
    }

    /// Read one valueless flag of the family, reporting whether it was one.
    ///
    /// `--allow-example-fixtures` acknowledges a fenced fixture run; whether the identity
    /// it describes may run is `ServerIdentity`'s decision, not this parser's.
    pub(super) fn take_switch(&mut self, flag: &str) -> bool {
        let owned = flag == "--allow-example-fixtures";
        self.allow_example_fixtures |= owned;
        owned
    }

    /// Read one flag of the family. Ownership and routing are the same table, so a flag
    /// outside the family writes no coordinate.
    pub(super) fn take(&mut self, flag: &str, value: &str) {
        if let Some(held) = self.slot(flag) {
            *held = Some(value.to_string());
        }
    }

    /// The four coordinates, or the first one this command line did not give.
    ///
    /// `--trust-domain` is required and has no default. It used to default to the
    /// placeholder `example.com`, which the Helm chart refuses outright as a
    /// shared-identity hazard — so the binary silently accepted the one value the chart
    /// exists to reject, and a hand-rolled deployment inherited an identity coordinate
    /// shared with every other install that also never set it.
    pub(super) fn finish(self) -> Result<DeploymentIdentity, String> {
        Ok(DeploymentIdentity {
            audience: super::require(self.audience, "--audience")?,
            server_signer: super::require(self.server_signer, "--server-signer")?,
            server_key_id: super::require(self.server_key_id, "--server-key-id")?,
            trust_domain: super::require(self.trust_domain, "--trust-domain")?,
            allow_example_fixtures: self.allow_example_fixtures,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete() -> IdentityFlags {
        let mut flags = IdentityFlags::default();
        for (flag, value) in [
            ("--audience", "did:example:server-1"),
            ("--server-signer", "did:example:server-1"),
            ("--server-key-id", "server-key-1"),
            ("--trust-domain", "mcp.example.com"),
        ] {
            assert!(IdentityFlags::owns(flag), "{flag}");
            flags.take(flag, value);
        }
        flags
    }

    /// Each coordinate is required, and the refusal names the one that is missing rather
    /// than the set.
    #[test]
    fn every_coordinate_is_required_and_named_when_absent() {
        for flag in [
            "--audience",
            "--server-signer",
            "--server-key-id",
            "--trust-domain",
        ] {
            let mut flags = IdentityFlags::default();
            for (other, value) in [
                ("--audience", "a"),
                ("--server-signer", "s"),
                ("--server-key-id", "k"),
                ("--trust-domain", "d"),
            ] {
                if other != flag {
                    flags.take(other, value);
                }
            }
            let err = flags.finish().expect_err("one coordinate is missing");
            assert!(err.contains(flag), "{flag}: {err}");
        }
    }

    /// The negative control: a complete set is accepted and carries what it read.
    #[test]
    fn a_complete_set_is_accepted() {
        let identity = complete().finish().expect("a complete set");
        assert_eq!(identity.trust_domain, "mcp.example.com");
        assert_eq!(identity.server_key_id, "server-key-1");
    }

    /// Each flag lands on the coordinate named after it, and a flag outside the family
    /// lands on none.
    #[test]
    fn each_flag_reaches_the_coordinate_named_after_it_and_no_other() {
        let mut flags = IdentityFlags::default();
        for (flag, value) in [
            ("--audience", "aud"),
            ("--server-signer", "signer"),
            ("--server-key-id", "kid"),
            ("--trust-domain", "domain"),
        ] {
            flags.take(flag, value);
        }
        let identity = flags.finish().expect("all four given");
        assert_eq!(identity.audience, "aud");
        assert_eq!(identity.server_signer, "signer");
        assert_eq!(identity.server_key_id, "kid");
        assert_eq!(identity.trust_domain, "domain");

        let mut flags = complete();
        flags.take("--trust", "elsewhere");
        assert!(!IdentityFlags::owns("--trust"));
        assert_eq!(
            flags.finish().expect("complete").trust_domain,
            "mcp.example.com"
        );
    }

    /// The fixture acknowledgement is valueless, off unless given, and carried as read;
    /// no other flag is taken as it.
    #[test]
    fn the_fixture_acknowledgement_is_off_unless_given() {
        assert!(
            !complete()
                .finish()
                .expect("complete")
                .allow_example_fixtures
        );
        let mut flags = complete();
        assert!(!flags.take_switch("--trust-domain"));
        assert!(flags.take_switch("--allow-example-fixtures"));
        assert!(flags.finish().expect("complete").allow_example_fixtures);
    }
}
