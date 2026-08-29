// SPDX-License-Identifier: Apache-2.0
//! Who this deployment is — the coordinates a verifier tells it apart by.
//!
//! Four required strings. They are a family because they answer one question and because
//! `ServerIdentity` consumes them as one value; the CLI's job is to read them and to say
//! which one is missing, and nothing more.

/// The identity coordinates, as they accumulate across the argument list.
#[derive(Default)]
pub(super) struct IdentityFlags {
    audience: Option<String>,
    server_signer: Option<String>,
    server_key_id: Option<String>,
    trust_domain: Option<String>,
}

/// What one deployment answers to.
#[derive(Debug)]
pub(super) struct DeploymentIdentity {
    pub(super) audience: String,
    pub(super) server_signer: String,
    pub(super) server_key_id: String,
    pub(super) trust_domain: String,
}

impl IdentityFlags {
    /// Whether this value-taking flag belongs to the family.
    pub(super) fn owns(flag: &str) -> bool {
        matches!(
            flag,
            "--audience" | "--server-signer" | "--server-key-id" | "--trust-domain"
        )
    }

    /// Read one flag of the family. [`Self::owns`] decided it is one.
    pub(super) fn take(&mut self, flag: &str, value: &str) {
        let held = || Some(value.to_string());
        match flag {
            "--audience" => self.audience = held(),
            "--server-signer" => self.server_signer = held(),
            "--server-key-id" => self.server_key_id = held(),
            _ => self.trust_domain = held(),
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
}
