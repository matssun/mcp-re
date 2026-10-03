// SPDX-License-Identifier: Apache-2.0
//! PER-REQUEST client-certificate revocation, so a warm connection is not a hole.
//!
//! rustls consults the CRLs during client authentication, and client authentication
//! runs on a FULL handshake only. Every later request on a keep-alive or HTTP/2
//! connection is served without the verifier being consulted again — so a peer whose
//! certificate appears in a reloaded CRL keeps full authenticated access for as long
//! as it holds the connection open. `--client-crl-reload-secs` rebuilds the verifier,
//! but the rebuilt verifier only ever reaches NEW connections.
//!
//! Bounding that with [`ServerLimits::max_connection_age`](crate::tls::ServerLimits)
//! makes the exposure finite, and binding session resumption to the trust epoch
//! ([`tls_auth_epoch`](crate::tls_auth_epoch)) stops a resumed handshake from restoring
//! a peer chain built under trust that has since changed. Neither
//! makes revocation take effect on the connection the revoked peer is already using.
//! This module does: the serving path checks the peer's serial against the CURRENT
//! CRLs on every request, at the same point it checks the certificate's validity
//! window.
//!
//! ## A CRL is authenticated before it can be indexed
//!
//! The handshake verifier authenticates a CRL against the chain it is checking, but this
//! index is built separately and read on requests the verifier never sees, so nothing the
//! handshake did vouches for it. [`ClientRevocationIndex::from_crl_ders`] therefore takes the
//! client CA anchors and refuses any CRL whose signature no configured CA key verifies: an
//! index has no inhabitant carrying a CRL that was merely parsed. The entry is keyed by the
//! CA KEY that signed it, not by the issuer name the document asserts about itself, so two
//! CAs that share a subject `Name` — a rotation keeps it — never answer for each other.
//!
//! A CRL signed by an intermediate is authentic only if that intermediate certificate is in
//! the client CA bundle; the bundle is the one place a CRL signer is named.
//!
//! ## Same posture as the handshake
//!
//! For ONE certificate, named by its issuer `Name` DER, its serial and its DER:
//!
//!   * a serial listed in a CRL for the issuer ⇒ [`RevocationVerdict::Revoked`];
//!   * an issuer no CRL covers, or whose CRL is past its `nextUpdate` ⇒
//!     [`RevocationVerdict::Unknown`], the same fail-closed direction as the handshake
//!     verifier;
//!   * [`ClientRevocationIndex::admits`] refuses `Revoked` and `Unknown`.
//!
//! The chain policy (leaf: `admits`; issuers: explicit `Revoked` only) belongs to
//! `communication_assurance::credential_currency::evaluation`.
//!
//! A production index always carries at least one CRL and every CRL states a
//! `nextUpdate`; "revocation not configured" is the absence of an index upstream.
//!
//! ## Cost
//!
//! One hash-set lookup per request, on a serial and issuer already extracted from the
//! leaf parse the validity check performs anyway. That is what makes it affordable to
//! run on every request instead of once per connection — and running it on every
//! request is what makes a warm connection safe to keep.

use std::collections::HashMap;
use std::collections::HashSet;

use self::issuer_key::CaKey;

/// Which CA key stands behind a CRL, and which of several same-named keys issued a leaf.
mod issuer_key;

/// Building the index: parsing each CRL and authenticating it against the client CA keys.
mod build;

/// WHICH index a request reads: the cell a reload publishes into.
mod shared;

/// What the index answers about one certificate, and how a certificate is named to it.
mod verdict;

pub use shared::ClientRevocationPublisher;
pub use shared::SharedClientRevocation;
pub use verdict::CertificateCoordinate;
pub use verdict::RevocationVerdict;

use self::verdict::normalize_serial;

/// One issuer's revoked serials, and the instant the list stops being in force.
#[derive(Debug, Clone, PartialEq, Eq)]
struct IssuerCrl {
    /// Revoked serials, each with leading zero bytes stripped so the two DER INTEGER
    /// spellings of the same number compare equal.
    revoked: HashSet<Vec<u8>>,
    /// `nextUpdate`; the index refuses a CRL that omits it, so it is always present.
    next_update_unix: i64,
}

impl IssuerCrl {
    /// Fold a second list from the same key into this one: union the serials, keep the
    /// EARLIER `nextUpdate`.
    fn absorb(&mut self, other: IssuerCrl) {
        self.revoked.extend(other.revoked);
        self.next_update_unix = self.next_update_unix.min(other.next_update_unix);
    }
}

/// One CA key that signed a CRL, and what that CRL says.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyedCrl {
    key: CaKey,
    crl: IssuerCrl,
}

/// The revoked-serial index the serving path consults per request, built from the
/// SAME CRL bytes handed to the handshake verifier — each authenticated against the
/// configured client CA keys first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRevocationIndex {
    /// Keyed by the CRL issuer's raw DER `Name`, compared byte-for-byte against the
    /// leaf's raw issuer `Name`; each name holds one entry per CA KEY that signed a CRL
    /// under it.
    ///
    /// Byte equality is stricter than RFC 5280 §7.1 name comparison, and it is strict
    /// in the safe direction: an issuer whose DN is spelled differently in the CRL
    /// than in the certificate simply fails to match, which yields `Unknown` and a
    /// refusal, never a missed revocation.
    per_issuer: HashMap<Vec<u8>, Vec<KeyedCrl>>,
}

impl ClientRevocationIndex {
    /// An index built from no CRLs, which admits every certificate. Test fixtures only:
    /// no production code can construct an admit-everything index.
    #[cfg(test)]
    pub fn empty() -> Self {
        ClientRevocationIndex {
            per_issuer: HashMap::new(),
        }
    }

    /// Whether this index carries no CRLs at all; only the test-only `empty`
    /// yields one.
    pub fn is_empty(&self) -> bool {
        self.per_issuer.is_empty()
    }

    /// The CRL entry that speaks for this certificate's issuer, if any.
    ///
    /// By issuer `Name`, then by KEY. Where one configured CA key carries the name, that is
    /// the entry. Where several do — a rotation keeps the subject — the certificate is
    /// read and the entry is the key that signed it, so one CA's list never answers for
    /// another's certificates. No key signed it ⇒ no entry ⇒ `Unknown`.
    fn issuer_for(&self, cert: &CertificateCoordinate<'_>) -> Option<&IssuerCrl> {
        match self.per_issuer.get(cert.issuer_der)?.as_slice() {
            [only] => Some(&only.crl),
            several => several
                .iter()
                .find(|k| k.key.issued(cert.certificate_der))
                .map(|k| &k.crl),
        }
    }

    /// The verdict for a certificate.
    pub fn verdict(&self, cert: &CertificateCoordinate<'_>, now: i64) -> RevocationVerdict {
        let Some(crl) = self.issuer_for(cert) else {
            return RevocationVerdict::Unknown;
        };
        // Past nextUpdate the list is no longer in force, so it can no longer say a
        // certificate is good — but it can still say one is revoked, and honouring
        // that is strictly safer than discarding it.
        if crl.revoked.contains(normalize_serial(cert.serial)) {
            return RevocationVerdict::Revoked;
        }
        if now >= crl.next_update_unix {
            RevocationVerdict::Unknown
        } else {
            RevocationVerdict::Good
        }
    }

    /// Whether a leaf is admitted.
    ///
    /// An index carrying no lists admits everything, and that admission is the ONLY one
    /// this type grants without a `Good` verdict; a production index always carries a
    /// list, so only the test-only empty index reaches it.
    ///
    /// Otherwise `Unknown` is refused. There is no parameter, field
    /// or policy object that could make it acceptable — the arm below is a literal
    /// `false`, so fail-closed is a property of the type rather than of what a caller
    /// remembered to pass. Restoring an operator opt-out means changing this function,
    /// which is the point.
    pub fn admits(&self, cert: &CertificateCoordinate<'_>, now: i64) -> bool {
        if self.is_empty() {
            return true;
        }
        match self.verdict(cert, now) {
            RevocationVerdict::Good => true,
            RevocationVerdict::Revoked => false,
            RevocationVerdict::Unknown => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::TlsError;
    use rustls_pki_types::CertificateDer;
    use x509_parser::prelude::FromDer;

    pub(super) const ISSUER: &[u8] = b"\x30\x0a\x31\x08\x30\x06\x06\x03\x55\x04\x03";
    const OTHER_ISSUER: &[u8] = b"\x30\x0a\x31\x08\x30\x06\x06\x03\x55\x04\x04";

    /// A CA held as its `CertificateParams` rather than its signed certificate: rcgen
    /// derives the issuer DN and key-identifier method from the params, and both a leaf
    /// and a CRL must be signed under the SAME derivation for the issuer DER to match.
    struct TestCa {
        key: rcgen::KeyPair,
        params: rcgen::CertificateParams,
    }

    fn test_ca(common_name: &str) -> TestCa {
        let key = rcgen::KeyPair::generate().expect("ca key");
        let mut params = rcgen::CertificateParams::new(Vec::new()).expect("ca params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        TestCa { key, params }
    }

    impl TestCa {
        fn issuer(&self) -> rcgen::Issuer<'_, &rcgen::KeyPair> {
            rcgen::Issuer::from_params(&self.params, &self.key)
        }

        /// The CA certificate a deployment lists in its client CA bundle.
        fn anchor(&self) -> CertificateDer<'static> {
            self.params
                .self_signed(&self.key)
                .expect("ca certificate")
                .der()
                .clone()
        }

        /// A leaf with an explicit serial, so a CRL can name exactly this certificate.
        fn leaf(&self, serial: u64) -> Vec<u8> {
            let key = rcgen::KeyPair::generate().expect("leaf key");
            let mut params = rcgen::CertificateParams::new(Vec::new()).expect("leaf params");
            params.serial_number = Some(rcgen::SerialNumber::from(serial));
            params
                .signed_by(&key, &self.issuer())
                .expect("leaf signed")
                .der()
                .to_vec()
        }

        /// A real signed CRL naming `revoked`, in force until 1 January `next_update_year`.
        fn crl(&self, revoked: &[u64], next_update_year: i32) -> Vec<u8> {
            let params = rcgen::CertificateRevocationListParams {
                this_update: rcgen::date_time_ymd(2020, 1, 1),
                next_update: rcgen::date_time_ymd(next_update_year, 1, 1),
                crl_number: rcgen::SerialNumber::from(1u64),
                issuing_distribution_point: None,
                revoked_certs: revoked
                    .iter()
                    .map(|serial| rcgen::RevokedCertParams {
                        serial_number: rcgen::SerialNumber::from(*serial),
                        revocation_time: rcgen::date_time_ymd(2021, 1, 1),
                        reason_code: Some(rcgen::RevocationReason::KeyCompromise),
                        invalidity_date: None,
                    })
                    .collect(),
                key_identifier_method: rcgen::KeyIdMethod::Sha256,
            };
            params
                .signed_by(&self.issuer())
                .expect("crl signed")
                .der()
                .to_vec()
        }
    }

    /// A leaf's coordinate exactly as the serving path derives it from a peer leaf
    /// (`tls::leaf_facts`), so the lookup key under test is the production one rather than
    /// one the test chose to match.
    struct Leaf {
        der: Vec<u8>,
        issuer: Vec<u8>,
        serial: Vec<u8>,
    }

    impl Leaf {
        fn of(der: Vec<u8>) -> Leaf {
            let (_, cert) =
                x509_parser::certificate::X509Certificate::from_der(&der).expect("leaf parses");
            Leaf {
                issuer: cert.tbs_certificate.issuer.as_raw().to_vec(),
                serial: cert.tbs_certificate.raw_serial().to_vec(),
                der,
            }
        }

        fn coordinate(&self) -> CertificateCoordinate<'_> {
            CertificateCoordinate {
                issuer_der: &self.issuer,
                serial: &self.serial,
                certificate_der: &self.der,
            }
        }
    }

    /// A coordinate for a synthetic issuer, whose certificate is never read because only one
    /// key stands behind the name.
    pub(super) fn coord<'a>(issuer: &'a [u8], serial: &'a [u8]) -> CertificateCoordinate<'a> {
        CertificateCoordinate {
            issuer_der: issuer,
            serial,
            certificate_der: &[],
        }
    }

    pub(super) fn index(revoked: &[&[u8]], next_update: i64) -> ClientRevocationIndex {
        let mut per_issuer = HashMap::new();
        per_issuer.insert(
            ISSUER.to_vec(),
            vec![KeyedCrl {
                key: CaKey {
                    name_der: ISSUER.to_vec(),
                    spki_der: Vec::new(),
                },
                crl: IssuerCrl {
                    revoked: revoked
                        .iter()
                        .map(|s| normalize_serial(s).to_vec())
                        .collect(),
                    next_update_unix: next_update,
                },
            }],
        );
        ClientRevocationIndex { per_issuer }
    }

    #[test]
    fn a_listed_serial_is_revoked_and_an_unlisted_one_is_good() {
        let idx = index(&[b"\x01\x02\x03"], 9_000);
        assert_eq!(
            idx.verdict(&coord(ISSUER, b"\x01\x02\x03"), 1_000),
            RevocationVerdict::Revoked
        );
        assert!(!idx.admits(&coord(ISSUER, b"\x01\x02\x03"), 1_000));
        assert_eq!(
            idx.verdict(&coord(ISSUER, b"\x09\x09\x09"), 1_000),
            RevocationVerdict::Good
        );
        assert!(idx.admits(&coord(ISSUER, b"\x09\x09\x09"), 1_000));
    }

    /// A positive serial whose high bit is set is encoded with a leading zero pad, and
    /// the certificate and the CRL need not agree on whether to emit it. Comparing raw
    /// bytes would miss the revocation — the one direction this must never fail in.
    #[test]
    fn a_zero_padded_serial_still_matches() {
        let idx = index(&[b"\x00\x80\x01"], 9_000);
        assert_eq!(
            idx.verdict(&coord(ISSUER, b"\x80\x01"), 1_000),
            RevocationVerdict::Revoked
        );
        let idx = index(&[b"\x80\x01"], 9_000);
        assert_eq!(
            idx.verdict(&coord(ISSUER, b"\x00\x80\x01"), 1_000),
            RevocationVerdict::Revoked
        );
    }

    /// The handshake refuses a leaf whose revocation status no CRL can determine
    /// (`UnknownStatusPolicy::Deny`). A per-request check that admitted it would let
    /// request 2 through the door request 1 was refused at.
    #[test]
    fn an_uncovered_issuer_is_unknown_and_refused() {
        let idx = index(&[], 9_000);
        assert_eq!(
            idx.verdict(&coord(OTHER_ISSUER, b"\x01"), 1_000),
            RevocationVerdict::Unknown
        );
        assert!(!idx.admits(&coord(OTHER_ISSUER, b"\x01"), 1_000));
    }

    /// `enforce_revocation_expiration` makes a stale CRL fail new handshakes closed.
    /// Past `nextUpdate` the list can no longer certify anything as good here either —
    /// but a revocation it already carries is still honoured, which is strictly safer
    /// than discarding it.
    #[test]
    fn a_stale_crl_certifies_nothing_but_still_revokes() {
        let idx = index(&[b"\x01\x02\x03"], 5_000);
        assert_eq!(
            idx.verdict(&coord(ISSUER, b"\x09"), 4_999),
            RevocationVerdict::Good,
            "in force right up to nextUpdate"
        );
        assert_eq!(
            idx.verdict(&coord(ISSUER, b"\x09"), 5_000),
            RevocationVerdict::Unknown,
            "nextUpdate itself is out of force"
        );
        assert_eq!(
            idx.verdict(&coord(ISSUER, b"\x01\x02\x03"), 9_999),
            RevocationVerdict::Revoked,
            "a stale list still knows what it revoked"
        );
    }

    /// PREMISE OF `tls_plane`'s POST-OWNER CONTRACT (ADR-MCPRE-056 §I.5.1).
    ///
    /// This is not ordinary revocation coverage. `TlsPlane` lets its serving snapshot
    /// outlive the plane and perform NO fail-closed transition on drop, unlike the trust
    /// and signing planes. That is only safe because an unrefreshed CRL converges on
    /// REFUSING its issuer rather than on admitting it — which is what this asserts.
    ///
    /// This used to carry a counterfactual second half — build the same index with
    /// unknown-status admissible and watch the expired CRL start ADMITTING — to show what
    /// the contract rested on. That half can no longer be written: the type has no such
    /// input, so no inhabitant of `ClientRevocationIndex` admits an `Unknown` verdict.
    /// The contract now rests on the type rather than on a value production remembered to
    /// set, which is a stronger premise than the counterfactual documented.
    ///
    /// **If an operator knob for unknown status is ever introduced, `TlsPlane`'s
    /// post-owner contract must be re-derived before that change lands** — a surviving
    /// snapshot would otherwise become exactly the frozen authorization state
    /// `trust_plane` fails closed to avoid. See
    /// [`unknown_status_is_refused_with_no_policy_input_that_could_admit_it`].
    #[test]
    fn an_expired_crl_refuses_its_issuer_rather_than_admitting_it() {
        let unrefreshed = index(&[], 5_000);
        assert!(
            unrefreshed.admits(&coord(ISSUER, b"\x09"), 4_999),
            "in force before nextUpdate, so an unlisted serial is admitted"
        );
        assert!(
            !unrefreshed.admits(&coord(ISSUER, b"\x09"), 5_000),
            "past nextUpdate an unrefreshed CRL must refuse its issuer, not admit it — \
             this is what lets a TLS snapshot safely outlive its reload worker"
        );
    }

    /// The property control for the deny-unknown invariant.
    ///
    /// It asserts the two halves that together mean fail-closed is structural: every input
    /// that yields `Unknown` is refused, and it is refused by an index built through the
    /// PUBLIC constructor, which takes no policy argument. There is no second call shape
    /// to try — `from_crl_ders` accepts CRL bytes and nothing else — so the refusal cannot
    /// be configured away without editing this crate.
    ///
    /// The distinction this pins is `is_empty()` vs. configured: an index carrying no CRLs
    /// admits (revocation is not configured), while a configured index refuses everything
    /// it cannot vouch for. Those are different questions and only the second is a policy.
    #[test]
    fn unknown_status_is_refused_with_no_policy_input_that_could_admit_it() {
        let covered = test_ca("covered-ca");
        let uncovered = test_ca("uncovered-ca");

        // Built the way production builds it: CRL bytes and the client CA anchors in, no
        // policy argument to pass.
        let configured =
            ClientRevocationIndex::from_crl_ders(&[covered.crl(&[], 2035)], &[covered.anchor()])
                .expect("a well-formed CRL parses");
        assert!(
            !configured.is_empty(),
            "this index IS configured for revocation"
        );

        // The two independent routes to Unknown, each through a real leaf's coordinate.
        let covered_leaf = Leaf::of(covered.leaf(0x11));
        let uncovered_leaf = Leaf::of(uncovered.leaf(0x22));
        let in_force = 1_600_000_000; // well before the 2035 nextUpdate
        let cases = [
            ("issuer covered by no CRL", &uncovered_leaf, in_force),
            ("CRL past its nextUpdate", &covered_leaf, i64::MAX),
        ];

        for (label, leaf, now) in cases {
            assert_eq!(
                configured.verdict(&leaf.coordinate(), now),
                RevocationVerdict::Unknown,
                "{label} must yield Unknown"
            );
            assert!(
                !configured.admits(&leaf.coordinate(), now),
                "{label} yielded Unknown and MUST be refused; there is no policy input \
                 that could make it admissible"
            );
        }

        // The control on the control: the same index DOES admit while it can vouch.
        assert!(
            configured.admits(&covered_leaf.coordinate(), in_force),
            "an in-force CRL that does not list the serial admits — otherwise the refusals \
             above would prove nothing but a uniformly closed door"
        );
    }

    /// No CRLs configured means rustls performs no revocation checking, so the index
    /// must admit rather than refuse — otherwise installing it would take down every
    /// deployment that configures none.
    #[test]
    fn an_empty_index_admits_everything() {
        let idx = ClientRevocationIndex::empty();
        assert!(idx.is_empty());
        assert!(idx.admits(&coord(ISSUER, b"\x01"), 1_000));
        assert!(idx.admits(&coord(OTHER_ISSUER, b"\xff"), i64::MAX));
    }

    /// The whole design rests on the raw issuer `Name` DER x509-parser yields from a CRL
    /// being byte-identical to the one the serving path reads off a leaf that CA issued.
    /// If the two spellings differed, every lookup would miss and every issuer would be
    /// `Unknown` — a total outage under deny-unknown, a total bypass under allow.
    #[test]
    fn a_crl_revokes_a_leaf_of_the_same_ca_and_says_nothing_about_another_ca() {
        let ca = test_ca("mcp-re-client-revocation-ca");
        let stranger = test_ca("mcp-re-client-revocation-stranger-ca");
        let idx = ClientRevocationIndex::from_crl_ders(&[ca.crl(&[0x4242], 2035)], &[ca.anchor()])
            .expect("index builds");

        let leaf = Leaf::of(ca.leaf(0x4242));
        assert_eq!(
            idx.verdict(&leaf.coordinate(), 1_600_000_000),
            RevocationVerdict::Revoked,
            "the CRL's issuer key must match the issuer DER read off the leaf"
        );

        let leaf = Leaf::of(ca.leaf(0x1337));
        assert_eq!(
            idx.verdict(&leaf.coordinate(), 1_600_000_000),
            RevocationVerdict::Good,
            "the issuer is covered and this serial is not listed"
        );

        let leaf = Leaf::of(stranger.leaf(0x4242));
        assert_eq!(
            idx.verdict(&leaf.coordinate(), 1_600_000_000),
            RevocationVerdict::Unknown,
            "the same serial under an uncovered issuer is not revoked by this CRL"
        );
    }

    /// A list that has fallen out of force must not be held in force by a fresher
    /// sibling, or a revocation published only on the stale one would silently stop
    /// being enforced.
    #[test]
    fn two_crls_for_one_issuer_union_their_serials_and_keep_the_earliest_next_update() {
        let ca = test_ca("mcp-re-client-revocation-merge-ca");
        let idx = ClientRevocationIndex::from_crl_ders(
            &[ca.crl(&[0x4242], 2030), ca.crl(&[0x1337], 2035)],
            &[ca.anchor()],
        )
        .expect("index builds");

        for revoked in [0x4242_u64, 0x1337] {
            let leaf = Leaf::of(ca.leaf(revoked));
            assert_eq!(
                idx.verdict(&leaf.coordinate(), 1_600_000_000),
                RevocationVerdict::Revoked,
                "a serial named by either list is revoked"
            );
        }

        let leaf = Leaf::of(ca.leaf(0x9999));
        assert_eq!(
            idx.verdict(&leaf.coordinate(), 1_800_000_000),
            RevocationVerdict::Good,
            "in force while both lists are"
        );
        assert_eq!(
            idx.verdict(&leaf.coordinate(), 2_000_000_000),
            RevocationVerdict::Unknown,
            "past the EARLIER nextUpdate the merged entry is out of force"
        );
    }

    #[test]
    fn a_crl_without_next_update_is_refused_at_construction() {
        use der::Encode;
        use x509_cert::der::Decode;
        let ca = test_ca("mcp-re-client-revocation-no-next-update-ca");
        let mut list =
            x509_cert::crl::CertificateList::from_der(&ca.crl(&[], 2035)).expect("fixture decodes");
        list.tbs_cert_list.next_update = None;
        let stripped = list.to_der().expect("re-encodes");
        let err = ClientRevocationIndex::from_crl_ders(&[stripped], &[ca.anchor()])
            .expect_err("a CRL without nextUpdate is refused");
        assert!(matches!(err, TlsError::Verifier(_)));
    }

    #[test]
    fn no_crls_build_no_index() {
        let err = ClientRevocationIndex::from_crl_ders(&[] as &[Vec<u8>], &[])
            .expect_err("no CRLs is refused");
        assert!(matches!(err, TlsError::Verifier(_)));
    }

    #[test]
    fn a_crl_with_trailing_bytes_is_refused() {
        let ca = test_ca("mcp-re-client-revocation-trailing-ca");
        let mut bundle = ca.crl(&[0x4242], 2035);
        bundle.extend(ca.crl(&[0x1337], 2035));
        let err = ClientRevocationIndex::from_crl_ders(&[bundle], &[ca.anchor()])
            .expect_err("trailing bytes are refused");
        assert!(matches!(err, TlsError::Verifier(_)));
    }

    /// The same bytes are handed to rustls, which refuses them. Skipping a malformed CRL
    /// here would leave the request path enforcing a smaller revoked set than the
    /// handshake.
    #[test]
    fn a_malformed_crl_is_refused_rather_than_skipped() {
        let ca = test_ca("mcp-re-client-revocation-malformed-ca");
        let err = ClientRevocationIndex::from_crl_ders(
            &[ca.crl(&[0x4242], 2035), b"not der".to_vec()],
            &[ca.anchor()],
        )
        .expect_err("a malformed CRL is a hard error");
        assert!(matches!(err, TlsError::Verifier(_)));
    }

    /// A CRL is bytes somebody wrote. One that names a configured CA as its issuer but is
    /// signed by another key — the document asserting a name about itself — is refused, and
    /// so is a CRL altered after it was signed.
    #[test]
    fn a_crl_no_configured_ca_key_signed_is_refused() {
        let ca = test_ca("mcp-re-client-revocation-forged-ca");
        // The same Name, a different key: exactly what a forger who can write the CRL file
        // but does not hold the CA key can produce.
        let forger = TestCa {
            key: rcgen::KeyPair::generate().expect("forger key"),
            params: ca.params.clone(),
        };
        let forged = forger.crl(&[0x4242], 2035);
        let err = ClientRevocationIndex::from_crl_ders(&[forged], &[ca.anchor()])
            .expect_err("a CRL signed by another key is refused even under the right Name");
        assert!(
            err.to_string()
                .contains("not signed by any configured client CA"),
            "{err}"
        );

        // Altered after signing: the serial list is covered by the signature.
        let mut tampered = ca.crl(&[0x4242], 2035);
        let at = tampered
            .windows(2)
            .rposition(|w| w == [0x42, 0x42])
            .expect("serial bytes");
        tampered[at] = 0x43;
        assert!(ClientRevocationIndex::from_crl_ders(&[tampered], &[ca.anchor()]).is_err());

        // And the control: the genuine CRL under the same anchor is accepted.
        assert!(
            ClientRevocationIndex::from_crl_ders(&[ca.crl(&[0x4242], 2035)], &[ca.anchor()])
                .is_ok()
        );
    }

    /// A CRL from a CA that is not in the bundle at all has nothing to verify under.
    #[test]
    fn a_crl_from_a_ca_outside_the_bundle_is_refused() {
        let ca = test_ca("mcp-re-client-revocation-bundle-ca");
        let outsider = test_ca("mcp-re-client-revocation-outsider-ca");
        assert!(
            ClientRevocationIndex::from_crl_ders(&[outsider.crl(&[], 2035)], &[ca.anchor()])
                .is_err()
        );
        assert!(
            ClientRevocationIndex::from_crl_ders(&[ca.crl(&[], 2035)], &[]).is_err(),
            "with no anchors nothing authenticates"
        );
    }

    /// An anchor whose `keyUsage` omits `cRLSign` cannot stand behind a CRL (RFC 5280
    /// §6.3.3), however valid the signature.
    #[test]
    fn an_anchor_that_may_not_sign_crls_authenticates_none() {
        let ca = test_ca("mcp-re-client-revocation-no-crl-sign-ca");
        // The CRL is signed by the real key; the anchor the deployment configured for that
        // key states no `cRLSign`.
        let mut restricted = ca.params.clone();
        restricted.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let anchor = restricted
            .self_signed(&ca.key)
            .expect("restricted anchor")
            .der()
            .clone();
        let crl = ca.crl(&[], 2035);
        assert!(
            ClientRevocationIndex::from_crl_ders(std::slice::from_ref(&crl), &[anchor]).is_err()
        );
        assert!(
            ClientRevocationIndex::from_crl_ders(&[crl], &[ca.anchor()]).is_ok(),
            "the control: the same CRL under an anchor that may sign CRLs is accepted"
        );
    }

    /// Two CAs may share a subject `Name` — a rotation keeps it — and are told apart by key.
    /// A revocation one of them published must not revoke the other's certificate, and one's
    /// in-force list must not certify the other's leaves.
    #[test]
    fn two_cas_sharing_a_name_never_answer_for_each_other() {
        let old = test_ca("mcp-re-client-revocation-rotated-ca");
        let new = TestCa {
            key: rcgen::KeyPair::generate().expect("rotated key"),
            params: old.params.clone(),
        };
        // Serial 0x77 means a different certificate under each key. Only the OLD key
        // revoked it; the NEW key's list is shorter-lived.
        let idx = ClientRevocationIndex::from_crl_ders(
            &[old.crl(&[0x77], 2035), new.crl(&[], 2030)],
            &[old.anchor(), new.anchor()],
        )
        .expect("both keys are configured anchors");

        let old_leaf = Leaf::of(old.leaf(0x77));
        let new_leaf = Leaf::of(new.leaf(0x77));
        let now = 1_600_000_000;
        assert_eq!(
            idx.verdict(&old_leaf.coordinate(), now),
            RevocationVerdict::Revoked,
            "the old key's own list revokes the old key's certificate"
        );
        assert_eq!(
            idx.verdict(&new_leaf.coordinate(), now),
            RevocationVerdict::Good,
            "the same serial under the new key is a different certificate and is not revoked"
        );
        // Past the new key's list but inside the old key's: the new key's leaf is Unknown,
        // not certified by the longer-lived list of a CA that did not issue it.
        assert_eq!(
            idx.verdict(&new_leaf.coordinate(), 1_900_000_000),
            RevocationVerdict::Unknown
        );
    }
}
