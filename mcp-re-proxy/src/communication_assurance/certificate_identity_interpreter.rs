// SPDX-License-Identifier: Apache-2.0
//! The certificate identity interpreter: interpreted certificate fields, plus an explicit
//! selection policy, become peer-identity evidence or a refusal.
//!
//! This is the semantic authority of ADR-MCPRE-063 Slice 1, and it is a pure total
//! function. It sees no bytes, no parser, no socket, no connection, no request, and no
//! policy beyond which field is authoritative — so its properties are properties of the
//! transformation itself, not of the deployment that invoked it.
//!
//! # The no-fallback law
//!
//! The configured field is authoritative. If it is absent, interpretation refuses. If its
//! FIRST value is not a well-formed identity, interpretation refuses. It never reads
//! another field, and it never reads a later value of the same field. Both halves matter
//! and they fail differently: searching another field silently downgrades a URI SAN
//! deployment to a CN one, while searching a later value of the same field lets an issuer
//! that can mint two SANs choose which identity the proxy binds to by making the first one
//! unusable.
//!
//! Structurally, the law holds because the selector projects exactly ONE candidate per
//! policy and then interprets it. There is no loop to search and no second candidate in
//! scope to fall back to — the tests pin the behaviour, and the shape is what makes the
//! behaviour hard to lose.

use super::certificate_identity_fields::CertificateIdentityFields;
use super::certificate_identity_policy::CertificateIdentityPolicy;
use super::certificate_identity_refusal::CertificateIdentityRefusal;
use super::certificate_peer_identity_evidence::CertificatePeerIdentityEvidence;
use super::peer_identity_value::PeerIdentityValue;

/// Interpret the configured identity field of one certificate's fields as peer-identity
/// evidence.
///
/// Establishes only that the selected field denoted this well-formed identity value. It
/// does not establish trust, revocation status, freshness, authentication, admission, or
/// authorization.
pub fn interpret_certificate_identity(
    fields: &CertificateIdentityFields,
    policy: CertificateIdentityPolicy,
) -> Result<CertificatePeerIdentityEvidence, CertificateIdentityRefusal> {
    // ONE candidate. The authoritative value of the configured field, or nothing —
    // there is deliberately no iterator here for a later value to be drawn from.
    let candidate = match policy {
        CertificateIdentityPolicy::UriSan => fields.first_uri_san(),
        CertificateIdentityPolicy::DnsSan => fields.first_dns_san(),
        CertificateIdentityPolicy::CommonNameLegacy => fields.common_name(),
    };

    let candidate =
        candidate.ok_or(CertificateIdentityRefusal::SelectedFieldAbsent { selected: policy })?;

    let value = PeerIdentityValue::interpret(candidate).map_err(|reason| {
        CertificateIdentityRefusal::SelectedFieldMalformed {
            selected: policy,
            reason,
        }
    })?;

    // The source comes from the POLICY, not from which projection returned a value: the
    // interpreter cannot label a value with a field it did not read from.
    Ok(CertificatePeerIdentityEvidence::new(
        value,
        policy.selects(),
    ))
}

#[cfg(test)]
mod tests {
    use super::interpret_certificate_identity;
    use super::CertificateIdentityFields;
    use super::CertificateIdentityPolicy;
    use super::CertificateIdentityRefusal;
    use crate::communication_assurance::certificate_identity_policy::CertificateIdentitySource;
    use crate::communication_assurance::peer_identity_value::PeerIdentityValueRefusal;

    const EVERY_POLICY: [CertificateIdentityPolicy; 3] = [
        CertificateIdentityPolicy::UriSan,
        CertificateIdentityPolicy::DnsSan,
        CertificateIdentityPolicy::CommonNameLegacy,
    ];

    /// A field set in which every field carries a distinct well-formed value, so a
    /// selector that reads the wrong one is caught by the VALUE, not only by the source.
    fn all_fields_distinct() -> CertificateIdentityFields {
        CertificateIdentityFields::new(
            vec!["spiffe://example.org/uri-value".to_string()],
            vec!["dns-value.example.org".to_string()],
            Some("cn-value.example.org".to_string()),
        )
    }

    #[test]
    fn each_policy_reads_its_own_field_and_reports_its_own_source() {
        let fields = all_fields_distinct();
        for (policy, expected_value, expected_source) in [
            (
                CertificateIdentityPolicy::UriSan,
                "spiffe://example.org/uri-value",
                CertificateIdentitySource::UriSan,
            ),
            (
                CertificateIdentityPolicy::DnsSan,
                "dns-value.example.org",
                CertificateIdentitySource::DnsSan,
            ),
            (
                CertificateIdentityPolicy::CommonNameLegacy,
                "cn-value.example.org",
                CertificateIdentitySource::CommonName,
            ),
        ] {
            let evidence =
                interpret_certificate_identity(&fields, policy).expect("every field is present");
            assert_eq!(evidence.value().as_str(), expected_value);
            assert_eq!(evidence.source(), expected_source);
        }
    }

    #[test]
    fn a_successful_source_always_equals_the_configured_policy() {
        let fields = all_fields_distinct();
        for policy in EVERY_POLICY {
            let evidence = interpret_certificate_identity(&fields, policy).expect("present");
            assert_eq!(
                evidence.source(),
                policy.selects(),
                "success under {policy:?} must report the configured field as its source"
            );
        }
    }

    #[test]
    fn an_absent_selected_field_refuses_while_the_other_fields_are_populated() {
        // One field missing at a time; the other two hold well-formed decoys.
        let cases = [
            (
                CertificateIdentityPolicy::UriSan,
                CertificateIdentityFields::new(
                    Vec::new(),
                    vec!["dns-value.example.org".to_string()],
                    Some("cn-value.example.org".to_string()),
                ),
            ),
            (
                CertificateIdentityPolicy::DnsSan,
                CertificateIdentityFields::new(
                    vec!["spiffe://example.org/uri-value".to_string()],
                    Vec::new(),
                    Some("cn-value.example.org".to_string()),
                ),
            ),
            (
                CertificateIdentityPolicy::CommonNameLegacy,
                CertificateIdentityFields::new(
                    vec!["spiffe://example.org/uri-value".to_string()],
                    vec!["dns-value.example.org".to_string()],
                    None,
                ),
            ),
        ];
        for (policy, fields) in cases {
            assert_eq!(
                interpret_certificate_identity(&fields, policy),
                Err(CertificateIdentityRefusal::SelectedFieldAbsent { selected: policy }),
                "under {policy:?} the present decoy fields must not be read"
            );
        }
    }

    #[test]
    fn a_malformed_first_value_refuses_and_the_later_valid_value_is_not_reached() {
        let fields = CertificateIdentityFields::new(
            vec![
                "spiffe://example.org/fi\rrst".to_string(),
                "spiffe://example.org/second".to_string(),
            ],
            Vec::new(),
            None,
        );
        assert_eq!(
            interpret_certificate_identity(&fields, CertificateIdentityPolicy::UriSan),
            Err(CertificateIdentityRefusal::SelectedFieldMalformed {
                selected: CertificateIdentityPolicy::UriSan,
                reason: PeerIdentityValueRefusal::ControlCharacter,
            }),
            "the second URI SAN is well-formed and must not be promoted over the refused \
             first one"
        );
    }

    #[test]
    fn a_trailing_control_character_is_trimmed_rather_than_refused() {
        // The value rules trim FIRST and judge second, so a trailing CR is surrounding
        // whitespace and disappears. Pinned because it is the one place where "contains a
        // control character" and "is refused" come apart, and a reader checking the
        // no-fallback tests needs to know which of the two the fixtures rely on.
        let fields = CertificateIdentityFields::new(
            vec!["spiffe://example.org/agent-1\r\n".to_string()],
            Vec::new(),
            None,
        );
        let evidence = interpret_certificate_identity(&fields, CertificateIdentityPolicy::UriSan)
            .expect("a trailing CRLF is trimmed away");
        assert_eq!(evidence.value().as_str(), "spiffe://example.org/agent-1");
    }

    #[test]
    fn the_refusal_reason_distinguishes_how_the_first_value_was_malformed() {
        for (first, expected) in [
            ("   ", PeerIdentityValueRefusal::Empty),
            ("bad\rvalue", PeerIdentityValueRefusal::ControlCharacter),
        ] {
            let fields = CertificateIdentityFields::new(
                vec![first.to_string(), "spiffe://example.org/valid".to_string()],
                Vec::new(),
                None,
            );
            assert_eq!(
                interpret_certificate_identity(&fields, CertificateIdentityPolicy::UriSan),
                Err(CertificateIdentityRefusal::SelectedFieldMalformed {
                    selected: CertificateIdentityPolicy::UriSan,
                    reason: expected,
                })
            );
        }
    }

    #[test]
    fn interpretation_is_deterministic_over_the_same_fields_and_policy() {
        let fields = all_fields_distinct();
        for policy in EVERY_POLICY {
            let first = interpret_certificate_identity(&fields, policy);
            for _ in 0..8 {
                assert_eq!(
                    interpret_certificate_identity(&fields, policy),
                    first,
                    "the same field set and policy must interpret to the same result"
                );
            }
        }
    }

    #[test]
    fn an_empty_field_set_refuses_under_every_policy_as_absence() {
        let fields = CertificateIdentityFields::default();
        for policy in EVERY_POLICY {
            assert_eq!(
                interpret_certificate_identity(&fields, policy),
                Err(CertificateIdentityRefusal::SelectedFieldAbsent { selected: policy })
            );
        }
    }
}
