// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPRE-063 Slice 1 — the no-fallback law of certificate identity interpretation.
//!
//! The proposition under test is the one the certificate identity authority owns and
//! nothing more: **the configured identity field is authoritative**. When that field is
//! absent, or present but malformed, interpretation REFUSES. It does not consult another
//! field, and it does not consult a later value of the same field.
//!
//! These are the controls the law needs, and they are the ones that were missing. The
//! existing `tls_test.rs` suite pins that a valid selected field is read and that an
//! empty-SAN certificate yields nothing; neither of those goes red if the selector starts
//! searching on after a failure, because in both of them there is nothing to search on to.
//! Each test here mints a certificate that CARRIES a tempting weaker answer, so a selector
//! that falls back returns it and the test fails.
//!
//! Selection happens over the certificate's interpreted fields, so these vectors are
//! expressed as real DER through the mechanism adapter. The value rules the refusals rest
//! on (non-empty, bounded, no control characters) are the generic peer-identity value
//! invariant, not an X.509 rule.
//!
//! Every assertion goes through `CertificateChainEvidence::interpret_identity` — the
//! block's one public entrance — and names the EXACT refusal. Asserting `is_none()` on the
//! legacy facade would pass equally for a certificate that was never parsed, and the whole
//! point of the refusal algebra is that those are different answers.

use mcp_re_proxy::communication_assurance::CertificateChainEvidence;
use mcp_re_proxy::communication_assurance::CertificateIdentityPolicy;
use mcp_re_proxy::communication_assurance::CertificateIdentityRefusal;
use mcp_re_proxy::communication_assurance::LeafIdentityRefusal;
use mcp_re_proxy::communication_assurance::PeerIdentityValueRefusal;
use mcp_re_proxy::transport::MAX_ASSERTED_IDENTITY_LEN;

use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::SanType;
use rustls_pki_types::CertificateDer;

// ---------------------------------------------------------------------------
// Minting. Deliberately local to this suite: these certificates are hostile on
// purpose (control characters, oversized values, decoy fields), and the shared
// helpers in `tls_test.rs` mint well-formed ones for round-trip use.
// ---------------------------------------------------------------------------

struct Ca {
    key: KeyPair,
    params: CertificateParams,
}

impl Ca {
    fn issuer(&self) -> rcgen::Issuer<'_, &KeyPair> {
        rcgen::Issuer::from_params(&self.params, &self.key)
    }
}

fn make_ca() -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
        .distinguished_name
        .push(DnType::CommonName, "mcp-re-no-fallback-ca");
    Ca { key, params }
}

fn leaf(ca: &Ca, sans: Vec<SanType>, common_name: Option<&str>) -> CertificateDer<'static> {
    let key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params.subject_alt_names = sans;
    if let Some(cn) = common_name {
        params.distinguished_name.push(DnType::CommonName, cn);
    }
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params
        .signed_by(&key, &ca.issuer())
        .expect("leaf signed by ca");
    cert.der().clone()
}

fn uri(value: &str) -> SanType {
    SanType::URI(value.try_into().expect("ia5 uri"))
}

fn dns(value: &str) -> SanType {
    SanType::DnsName(value.try_into().expect("ia5 dns"))
}

// ---------------------------------------------------------------------------
// Control 1 — cross-field. The selected field is absent; a weaker field is present.
// ---------------------------------------------------------------------------

#[test]
fn uri_selected_and_absent_does_not_fall_back_to_a_present_dns_san() {
    let ca = make_ca();
    let cert = leaf(
        &ca,
        vec![dns("agent.example.org")],
        Some("agent.example.org"),
    );

    assert_eq!(
        CertificateChainEvidence::from_leaf_der(cert.as_ref())
            .interpret_identity(CertificateIdentityPolicy::UriSan),
        Err(CertificateIdentityRefusal::Leaf(
            LeafIdentityRefusal::SelectedFieldAbsent {
                selected: CertificateIdentityPolicy::UriSan
            }
        )),
        "URI SAN is the configured field and this certificate has none; a DNS SAN and a \
         CN are present as decoys, and reading either is the fallback the policy disclaims"
    );
}

#[test]
fn dns_selected_and_absent_does_not_fall_back_to_a_present_common_name() {
    let ca = make_ca();
    let cert = leaf(
        &ca,
        vec![uri("spiffe://example.org/agent-1")],
        Some("agent.example.org"),
    );

    assert_eq!(
        CertificateChainEvidence::from_leaf_der(cert.as_ref())
            .interpret_identity(CertificateIdentityPolicy::DnsSan),
        Err(CertificateIdentityRefusal::Leaf(
            LeafIdentityRefusal::SelectedFieldAbsent {
                selected: CertificateIdentityPolicy::DnsSan
            }
        )),
        "DNS SAN is the configured field and this certificate has none; the CN carries a \
         DNS-shaped value that a falling-back selector would happily return"
    );
}

// ---------------------------------------------------------------------------
// Control 2 — same-field, later value. The FIRST value of the selected field is
// malformed and a LATER value of the SAME field is valid.
//
// This is the control that separates "reads the first matching field" from
// "searches the selected field for something acceptable". A selector written as
// `general_names.iter().filter(URI).find_map(|u| validate(u).ok())` passes every
// other test in the tree and fails this one.
// ---------------------------------------------------------------------------

#[test]
fn malformed_first_uri_san_does_not_fall_back_to_a_valid_later_uri_san() {
    let ca = make_ca();
    let cert = leaf(
        &ca,
        vec![
            // A control character (CR) makes the FIRST URI SAN a malformed identity
            // value: it is a log-injection and header-smuggling shape, and the value
            // invariant refuses it.
            uri("spiffe://example.org/agent-\rFIRST"),
            uri("spiffe://example.org/agent-SECOND"),
        ],
        None,
    );

    assert_eq!(
        CertificateChainEvidence::from_leaf_der(cert.as_ref())
            .interpret_identity(CertificateIdentityPolicy::UriSan),
        Err(CertificateIdentityRefusal::Leaf(
            LeafIdentityRefusal::SelectedFieldMalformed {
                selected: CertificateIdentityPolicy::UriSan,
                reason: PeerIdentityValueRefusal::ControlCharacter,
            }
        )),
        "the first URI SAN is the authoritative one and it is malformed; the second is \
         valid, and returning it would be a fallback within the selected field"
    );
}

#[test]
fn empty_first_uri_san_does_not_fall_back_to_a_valid_later_uri_san() {
    let ca = make_ca();
    let cert = leaf(
        &ca,
        vec![
            // Empty after trimming — the value invariant's other absence shape.
            uri("   "),
            uri("spiffe://example.org/agent-SECOND"),
        ],
        None,
    );

    assert_eq!(
        CertificateChainEvidence::from_leaf_der(cert.as_ref())
            .interpret_identity(CertificateIdentityPolicy::UriSan),
        Err(CertificateIdentityRefusal::Leaf(
            LeafIdentityRefusal::SelectedFieldMalformed {
                selected: CertificateIdentityPolicy::UriSan,
                reason: PeerIdentityValueRefusal::Empty,
            }
        )),
        "a whitespace-only first URI SAN is not a value; the later valid one must not be \
         promoted in its place"
    );
}

#[test]
fn oversized_first_uri_san_does_not_fall_back_to_a_valid_later_uri_san() {
    let ca = make_ca();
    let mut oversized = String::from("spiffe://example.org/");
    oversized.push_str(&"a".repeat(MAX_ASSERTED_IDENTITY_LEN));
    let cert = leaf(
        &ca,
        vec![uri(&oversized), uri("spiffe://example.org/agent-SECOND")],
        None,
    );

    assert_eq!(
        CertificateChainEvidence::from_leaf_der(cert.as_ref())
            .interpret_identity(CertificateIdentityPolicy::UriSan),
        Err(CertificateIdentityRefusal::Leaf(
            LeafIdentityRefusal::SelectedFieldMalformed {
                selected: CertificateIdentityPolicy::UriSan,
                reason: PeerIdentityValueRefusal::TooLong,
            }
        )),
        "an over-length first URI SAN is refused, and the bounded later value must not be \
         substituted for it"
    );
}

#[test]
fn malformed_first_dns_san_does_not_fall_back_to_a_valid_later_dns_san() {
    let ca = make_ca();
    let cert = leaf(
        &ca,
        vec![dns("agent\r.example.org"), dns("second-agent.example.org")],
        None,
    );

    assert_eq!(
        CertificateChainEvidence::from_leaf_der(cert.as_ref())
            .interpret_identity(CertificateIdentityPolicy::DnsSan),
        Err(CertificateIdentityRefusal::Leaf(
            LeafIdentityRefusal::SelectedFieldMalformed {
                selected: CertificateIdentityPolicy::DnsSan,
                reason: PeerIdentityValueRefusal::ControlCharacter,
            }
        )),
        "the same law holds for the DNS SAN field: the first value is authoritative, and \
         a later well-formed one is not a repair"
    );
}

// ---------------------------------------------------------------------------
// Control 3 — the adapter's absence arm, through real DER.
//
// A certificate with no SAN extension at all is a certificate that does not carry
// the field: the reading SUCCEEDED and found nothing. The adapter's other arm — a
// SAN extension present but uninterpretable — is not reachable through this
// encoder, so its property is pinned at the seam instead, over an interpreted
// field set. A property is not weakened to match what a fixture can express.
// ---------------------------------------------------------------------------

#[test]
fn a_certificate_with_no_san_extension_refuses_as_absent_under_both_san_policies() {
    let ca = make_ca();
    let cert = leaf(&ca, Vec::new(), Some("only-a-common-name.example.org"));

    for policy in [
        CertificateIdentityPolicy::UriSan,
        CertificateIdentityPolicy::DnsSan,
    ] {
        assert_eq!(
            CertificateChainEvidence::from_leaf_der(cert.as_ref()).interpret_identity(policy),
            Err(CertificateIdentityRefusal::Leaf(
                LeafIdentityRefusal::SelectedFieldAbsent { selected: policy }
            )),
            "no SAN extension is an absent field, not an unreadable one — and the CN that \
             IS present is not a fallback"
        );
    }
}

#[test]
fn a_peer_that_presented_no_certificate_is_not_a_peer_whose_field_is_missing() {
    assert_eq!(
        CertificateChainEvidence::absent().interpret_identity(CertificateIdentityPolicy::UriSan),
        Err(CertificateIdentityRefusal::NoLeaf)
    );
}
