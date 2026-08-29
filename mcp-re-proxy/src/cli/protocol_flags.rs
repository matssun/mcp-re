// SPDX-License-Identifier: Apache-2.0
//! The request contract this deployment verifies against.
//!
//! The RFC 9421 `@target-uri` a signature base is reconstructed against, the accepted
//! `Mcp-Protocol-Version` set, and the clock skew a freshness window tolerates. Three
//! parameters of one question — *what does a well-formed request to this deployment look
//! like* — and none of them is a mechanism.

/// The protocol-contract inputs, as they accumulate across the argument list.
#[derive(Default)]
pub(super) struct ProtocolFlags {
    target_uri: Option<String>,
    versions: Vec<String>,
    max_clock_skew: Option<i64>,
}

/// The contract one deployment states.
#[derive(Debug)]
pub(super) struct ProtocolContract {
    pub(super) target_uri: String,
    pub(super) versions: Vec<String>,
    pub(super) max_clock_skew: i64,
}

impl ProtocolFlags {
    /// Whether this value-taking flag belongs to the family.
    pub(super) fn owns(flag: &str) -> bool {
        matches!(
            flag,
            "--target-uri" | "--mcp-protocol-version" | "--max-clock-skew"
        )
    }

    /// Read one flag of the family. [`Self::owns`] decided it is one.
    pub(super) fn take(&mut self, flag: &str, value: &str) -> Result<(), String> {
        match flag {
            "--target-uri" => self.target_uri = Some(value.to_string()),
            // §4.1 MCP transport contract. Repeatable; each occurrence adds an accepted
            // `Mcp-Protocol-Version`. Absent = no transport contract.
            "--mcp-protocol-version" => self.versions.push(value.to_string()),
            _ => {
                self.max_clock_skew = Some(
                    value
                        .parse()
                        .map_err(|_| "invalid --max-clock-skew".to_string())?,
                );
            }
        }
        Ok(())
    }

    /// The contract, or the coordinate this command line did not give.
    ///
    /// `--target-uri` is REQUIRED; what shape it must have is the configuration boundary's.
    /// The skew keeps its historical default, because an omitted tolerance has always meant
    /// the default one rather than none.
    pub(super) fn finish(self, default_skew: i64) -> Result<ProtocolContract, String> {
        Ok(ProtocolContract {
            target_uri: super::require(self.target_uri, "--target-uri")?,
            versions: self.versions,
            max_clock_skew: self.max_clock_skew.unwrap_or(default_skew),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The target URI is required; the other two have meanings for their own absence.
    #[test]
    fn the_target_uri_is_required_and_the_others_default() {
        let err = ProtocolFlags::default()
            .finish(300)
            .expect_err("no target uri");
        assert!(err.contains("--target-uri"), "{err}");

        let mut flags = ProtocolFlags::default();
        flags
            .take("--target-uri", "https://mcp/x")
            .expect("a value");
        let contract = flags.finish(300).expect("a target uri");
        assert_eq!(contract.max_clock_skew, 300);
        assert!(contract.versions.is_empty(), "no contract is a posture");
    }

    /// The version flag is repeatable, and the order it was given in is preserved.
    #[test]
    fn each_protocol_version_adds_to_the_accepted_set() {
        let mut flags = ProtocolFlags::default();
        flags
            .take("--target-uri", "https://mcp/x")
            .expect("a value");
        for version in ["2026-07-28", "2025-06-18"] {
            flags
                .take("--mcp-protocol-version", version)
                .expect("a value");
        }
        assert_eq!(
            flags.finish(300).expect("a contract").versions,
            vec!["2026-07-28".to_string(), "2025-06-18".to_string()]
        );
    }
}
