// SPDX-License-Identifier: Apache-2.0
//! The argv-level coherence rule: a value belonging to a mechanism this command line did
//! not select.
//!
//! It lives here rather than at the configuration boundary because after assembly there is
//! no longer a request that states it — a tagged
//! [`SigningSourceRequest`](crate::deployment_request::SigningSourceRequest) has nowhere to
//! put a value belonging to another mechanism, which is the point of the migration
//! (ADR-MCPRE-067 §7). The parser is the last place that can still see both the selection
//! and the stray value, so the refusal moved here with the values it is about.

use super::mechanism::Mechanism;
use super::SigningSourceFlags;

impl SigningSourceFlags {
    /// Refuse a value belonging to a mechanism this command line did not select.
    ///
    /// Accepting it would hide a typo, a stale fragment, or an operator who believes both
    /// apply. The refusal is the one the configuration boundary used to make; it moved
    /// here with the values it is about, because after assembly there is no longer a
    /// request that states it.
    ///
    /// Only RESPONSE-SIGNING payload values are here. The channel key objects are a
    /// different role and are carried into the request whatever the response-signing
    /// selection, so their mismatch is still refused at the boundary by X2a.
    pub(super) fn stray_value_refusal(&self) -> Result<(), String> {
        for (present, flag, owner) in self.values_by_owner() {
            if present && self.mechanism != owner {
                return Err(format!(
                    "{flag} belongs to --key-source {owner_spelling} and this configuration \
                     selects a different custody source; the value would be ignored, leaving a \
                     deployment that believes it applies. Remove {flag}, or select \
                     --key-source {owner_spelling}",
                    owner_spelling = owner.spelling()
                ));
            }
        }
        Ok(())
    }

    /// Every response-signing value this command line carries, with the mechanism it
    /// belongs to.
    ///
    /// Endpoint overrides are absent on purpose, exactly as they were from the table this
    /// replaces: `--aws-kms-endpoint` beside `--key-source gcp-kms` was not refused before
    /// and is not refused now. What each of them IS held to, wherever it appears, is the
    /// endpoint-authority rule — applied by [`guarded_endpoint`] as the flag is read, so a
    /// hostile authority is refused whatever mechanism the command line selects.
    fn values_by_owner(&self) -> [(bool, &'static str, Mechanism); 10] {
        [
            (
                self.pkcs11.module.is_some(),
                "--pkcs11-module",
                Mechanism::Pkcs11,
            ),
            (
                self.pkcs11.pin_file.is_some(),
                "--pkcs11-pin-file",
                Mechanism::Pkcs11,
            ),
            (
                self.pkcs11.token_label.is_some(),
                "--pkcs11-token-label",
                Mechanism::Pkcs11,
            ),
            (
                self.pkcs11.key_label.is_some(),
                "--pkcs11-key-label",
                Mechanism::Pkcs11,
            ),
            (
                self.aws.region.is_some(),
                "--aws-kms-region",
                Mechanism::AwsKms,
            ),
            (
                self.aws.key_id.is_some(),
                "--aws-kms-key-id",
                Mechanism::AwsKms,
            ),
            (
                self.aws.use_web_identity,
                "--aws-kms-use-web-identity",
                Mechanism::AwsKms,
            ),
            (
                self.gcp.key_version.is_some(),
                "--gcp-kms-key-version",
                Mechanism::GcpKms,
            ),
            (
                self.gcp.use_metadata,
                "--gcp-kms-use-metadata",
                Mechanism::GcpKms,
            ),
            (
                self.aws.sts_endpoint.is_some(),
                "--aws-sts-endpoint",
                Mechanism::AwsKms,
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::super::SigningSourceFlags;

    /// The flag a case must name in its refusal, the value-taking flags that provoke it,
    /// and the valueless ones.
    type Case = (
        &'static str,
        &'static [(&'static str, &'static str)],
        &'static [&'static str],
    );

    /// Read a signing-source command line and assemble it.
    fn parse(pairs: &[(&str, &str)], switches: &[&str]) -> Result<(), String> {
        let mut flags = SigningSourceFlags::default();
        for (flag, value) in pairs {
            flags.take(flag, value)?;
        }
        for switch in switches {
            assert!(flags.take_switch(switch), "{switch} is not a family switch");
        }
        flags.finish().map(|_| ())
    }

    /// Every case the configuration boundary's nine-entry forbidden table used to refuse.
    ///
    /// They are not refused there any more, because a tagged request cannot state them.
    /// This is where they went — the command line can still NAME a stray flag, and naming
    /// one must still be an error rather than a value that quietly disappears.
    #[test]
    fn a_value_belonging_to_an_unselected_mechanism_is_refused() {
        let cases: &[Case] = &[
            (
                "--pkcs11-module",
                &[
                    ("--key-source", "aws-kms"),
                    ("--pkcs11-module", "/lib/softhsm.so"),
                ],
                &[],
            ),
            (
                "--pkcs11-pin-file",
                &[("--key-source", "gcp-kms"), ("--pkcs11-pin-file", "/pin")],
                &[],
            ),
            (
                "--pkcs11-token-label",
                &[("--key-source", "file"), ("--pkcs11-token-label", "t")],
                &[],
            ),
            (
                "--pkcs11-key-label",
                &[("--key-source", "file"), ("--pkcs11-key-label", "k")],
                &[],
            ),
            (
                "--aws-kms-region",
                &[
                    ("--key-source", "gcp-kms"),
                    ("--aws-kms-region", "eu-north-1"),
                ],
                &[],
            ),
            (
                "--aws-kms-key-id",
                &[("--key-source", "pkcs11"), ("--aws-kms-key-id", "alias/k")],
                &[],
            ),
            (
                "--gcp-kms-key-version",
                &[
                    ("--key-source", "aws-kms"),
                    ("--gcp-kms-key-version", "projects/p/.."),
                ],
                &[],
            ),
            (
                "--aws-sts-endpoint",
                &[
                    ("--key-source", "gcp-kms"),
                    ("--aws-sts-endpoint", "https://sts.eu-north-1.amazonaws.com"),
                ],
                &[],
            ),
            (
                "--aws-kms-use-web-identity",
                &[("--key-source", "gcp-kms")],
                &["--aws-kms-use-web-identity"],
            ),
            (
                "--gcp-kms-use-metadata",
                &[("--key-source", "aws-kms")],
                &["--gcp-kms-use-metadata"],
            ),
        ];
        for (flag, pairs, switches) in cases {
            let err = parse(pairs, switches)
                .expect_err("a value belonging to another mechanism must be refused");
            assert!(
                err.contains(flag) && err.contains("belongs to --key-source"),
                "the refusal must name {flag} and where it belongs, got: {err}"
            );
        }
    }

    /// The positive control: the same values under the mechanism that owns them are not
    /// refused. A rule that refused every mechanism-specific flag would satisfy the test
    /// above.
    #[test]
    fn a_value_under_the_mechanism_that_owns_it_is_accepted() {
        parse(
            &[
                ("--key-source", "aws-kms"),
                ("--aws-kms-region", "eu-north-1"),
                ("--aws-kms-key-id", "alias/k"),
                ("--aws-sts-endpoint", "https://sts.eu-north-1.amazonaws.com"),
            ],
            &["--aws-kms-use-web-identity"],
        )
        .expect("an AWS command line naming only AWS values is coherent");
        parse(
            &[
                ("--key-source", "pkcs11"),
                ("--pkcs11-module", "/lib/softhsm.so"),
                ("--pkcs11-pin-file", "/pin"),
                ("--pkcs11-token-label", "t"),
                ("--pkcs11-key-label", "k"),
            ],
            &[],
        )
        .expect("a PKCS#11 command line naming only PKCS#11 values is coherent");
    }

    /// A channel key object is NOT refused here, whatever the response-signing selection.
    ///
    /// The two are separate roles, so the request carries both and relation X2a reports the
    /// mismatch at the configuration boundary — alongside every other violation, rather
    /// than cutting the parse short at the first one.
    #[test]
    fn a_channel_key_for_another_mechanism_is_carried_not_refused_here() {
        parse(
            &[
                ("--key-source", "file"),
                ("--signing-key-seed", "/seed"),
                ("--aws-kms-tls-key-id", "alias/tls"),
            ],
            &[],
        )
        .expect("the parser carries it; X2a is the one that refuses it");
    }
}
