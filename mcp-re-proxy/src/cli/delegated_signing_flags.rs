// SPDX-License-Identifier: Apache-2.0
//! What the delegated response-signing credential is minted with — ADR-MCPRE-052.

use crate::deployment_request::DelegatedSigningRequest;

/// The delegated-signing inputs, as they accumulate across the argument list.
#[derive(Default)]
pub(super) struct DelegatedSigningFlags {
    ttl_secs: Option<i64>,
    overlap_secs: Option<i64>,
    trust_epoch: Option<String>,
    issuer_kid: Option<String>,
    audience_hash: Option<String>,
}

impl DelegatedSigningFlags {
    /// Whether this value-taking flag belongs to the family.
    pub(super) fn owns(flag: &str) -> bool {
        matches!(
            flag,
            "--delegated-ttl-secs"
                | "--delegated-overlap-secs"
                | "--delegated-trust-epoch"
                | "--delegated-issuer-kid"
                | "--delegated-audience-hash"
        )
    }

    /// Read one flag of the family. [`Self::owns`] decided it is one.
    pub(super) fn take(&mut self, flag: &str, value: &str) -> Result<(), String> {
        let seconds = || -> Result<i64, String> {
            value
                .parse()
                .map_err(|_| format!("invalid {flag} (expected a positive integer)"))
        };
        match flag {
            "--delegated-ttl-secs" => self.ttl_secs = Some(seconds()?),
            "--delegated-overlap-secs" => self.overlap_secs = Some(seconds()?),
            "--delegated-trust-epoch" => self.trust_epoch = Some(value.to_string()),
            "--delegated-issuer-kid" => self.issuer_kid = Some(value.to_string()),
            _ => self.audience_hash = Some(value.to_string()),
        }
        Ok(())
    }

    /// What the credential is minted with.
    ///
    /// The rotation window an operator did not state is applied HERE — a default is what an
    /// omitted flag means — but the values are not chosen here: they are `DelegatedSigning`'s
    /// constants, checked there against the same `0 < overlap < ttl` guard they have to
    /// survive (ADR-MCPRE-052 §4). The three coordinates stay `None` when unnamed, so their
    /// owner can still tell an omitted value from a stated one.
    pub(super) fn finish(self, default_ttl: i64, default_overlap: i64) -> DelegatedSigningRequest {
        DelegatedSigningRequest {
            ttl_secs: self.ttl_secs.unwrap_or(default_ttl),
            overlap_secs: self.overlap_secs.unwrap_or(default_overlap),
            trust_epoch: self.trust_epoch,
            issuer_kid: self.issuer_kid,
            audience_hash: self.audience_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An omitted window takes the owner's constants; a stated one wins. The coordinates
    /// stay unnamed, which is what lets the owner default them from the deployment's own
    /// identity rather than from a value the parser invented.
    #[test]
    fn the_window_defaults_and_the_coordinates_stay_unnamed() {
        let minted = DelegatedSigningFlags::default().finish(600, 120);
        assert_eq!((minted.ttl_secs, minted.overlap_secs), (600, 120));
        assert_eq!(minted.issuer_kid, None);
        assert_eq!(minted.audience_hash, None);

        let mut flags = DelegatedSigningFlags::default();
        flags
            .take("--delegated-ttl-secs", "300")
            .expect("an integer");
        assert_eq!(flags.finish(600, 120).ttl_secs, 300);
    }

    /// A window that is not a number is refused by name rather than defaulted.
    #[test]
    fn a_window_that_is_not_a_number_is_refused_by_name() {
        let err = DelegatedSigningFlags::default()
            .take("--delegated-overlap-secs", "soon")
            .expect_err("not an integer");
        assert!(err.contains("--delegated-overlap-secs"), "{err}");
    }
}
