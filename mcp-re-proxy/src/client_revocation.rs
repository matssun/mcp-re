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
//! ## Same posture as the handshake, deliberately
//!
//! The verdict rules mirror [`build_client_verifier`](crate::tls), because a
//! per-request check that is more permissive than the handshake would admit on
//! request 2 what was refused on request 1:
//!
//!   * a serial listed in a CRL for the certificate's issuer ⇒
//!     [`RevocationVerdict::Revoked`];
//!   * a certificate whose issuer no CRL covers ⇒ [`RevocationVerdict::Unknown`],
//!     refused unless the operator set `allow_unknown_revocation_status` (rustls'
//!     `UnknownStatusPolicy::Deny` is the default this follows);
//!   * a CRL past its `nextUpdate` covers nothing, so its issuer's certificates
//!     become `Unknown` — the same fail-closed direction as
//!     `enforce_revocation_expiration`.
//!
//! ## One certificate per call; the CHAIN is the caller's to walk
//!
//! [`ClientRevocationIndex::verdict`] and [`ClientRevocationIndex::admits`] each judge
//! ONE certificate, named by its issuer `Name` DER and its serial. The handshake
//! verifier checks revocation to the trust anchor (rustls' default
//! `RevocationCheckDepth::Chain`), so a caller that asks about the leaf alone has a
//! per-request check WEAKER than the handshake: an intermediate CA published on its
//! parent's CRL would be refused at every new handshake and still admitted on every
//! request of a connection the peer already holds open. Whoever calls this must
//! therefore hand it every certificate the peer presented, not just the first — see
//! `tls::cert_lifetime_rejection_for_chain`.
//!
//! With NO CRLs configured, rustls performs no revocation checking at all. An index
//! built from no CRLs therefore admits everything ([`ClientRevocationIndex::is_empty`]),
//! and `app.rs` installs none — the request path is byte-for-byte unchanged for
//! deployments that configure no CRLs.
//!
//! ## Cost
//!
//! One hash-set lookup per request, on a serial and issuer already extracted from the
//! leaf parse the validity check performs anyway. That is what makes it affordable to
//! run on every request instead of once per connection — and running it on every
//! request is what makes a warm connection safe to keep.

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::RwLock;

use x509_parser::prelude::FromDer;

use crate::tls::TlsError;

/// What the current CRLs say about one client certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationVerdict {
    /// The issuer is covered by a CRL that is in force, and this serial is not on it.
    Good,
    /// This serial is listed as revoked by a CRL for its issuer.
    Revoked,
    /// No CRL in force covers this leaf's issuer — either none was configured for it,
    /// or the one that was is past its `nextUpdate`. Refused unless the operator
    /// allowed unknown status.
    Unknown,
}

/// One issuer's revoked serials, and the instant the list stops being in force.
#[derive(Debug)]
struct IssuerCrl {
    /// Revoked serials, each with leading zero bytes stripped so the two DER INTEGER
    /// spellings of the same number compare equal.
    revoked: HashSet<Vec<u8>>,
    /// `nextUpdate`. RFC 5280 permits its omission, but a CRL without one is refused
    /// at load — at startup and on every reload — so no index reaches this type
    /// without it. The `Option` is the parse result, not an admissible state.
    next_update_unix: Option<i64>,
}

/// The revoked-serial index the serving path consults per request, built from the
/// SAME CRL bytes handed to the handshake verifier.
#[derive(Debug)]
pub struct ClientRevocationIndex {
    /// Keyed by the CRL issuer's raw DER `Name`, compared byte-for-byte against the
    /// leaf's raw issuer `Name`.
    ///
    /// Byte equality is stricter than RFC 5280 §7.1 name comparison, and it is strict
    /// in the safe direction: an issuer whose DN is spelled differently in the CRL
    /// than in the certificate simply fails to match, which yields `Unknown` and a
    /// refusal, never a missed revocation.
    per_issuer: HashMap<Vec<u8>, IssuerCrl>,
    /// The operator opt-out, carried so the verdict-to-decision rule is the handshake's.
    allow_unknown_status: bool,
}

/// Strip leading zero bytes from a DER INTEGER's content octets.
///
/// A positive integer whose high bit is set is encoded with a leading `0x00` pad, and
/// a certificate and a CRL are free to encode the same serial with or without it. A
/// raw byte comparison would then miss the revocation, which is the one direction this
/// must never fail in.
///
/// Borrows rather than allocating: this runs on the request path, and the lookup below
/// queries a `HashSet<Vec<u8>>` through `Borrow<[u8]>`, so the normalized form never
/// needs to own its bytes to be compared.
fn normalize_serial(serial: &[u8]) -> &[u8] {
    let first_significant = serial
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(serial.len());
    &serial[first_significant..]
}

impl ClientRevocationIndex {
    /// Build the index from DER-encoded CRLs.
    ///
    /// A malformed CRL is a hard error, matching the verifier build and
    /// [`crl_posture`](crate::tls::crl_posture): the same bytes are about to be given
    /// to rustls, which would refuse them, so accepting them here would leave the two
    /// disagreeing about what is enforced.
    pub fn from_crl_ders(
        crls: &[impl AsRef<[u8]>],
        allow_unknown_status: bool,
    ) -> Result<Self, TlsError> {
        // x509-parser for BOTH sides of the issuer comparison — the same crate the
        // leaf is parsed with. Decoding the name and RE-ENCODING it (x509-cert's
        // `Name::to_der()`) would compare a round-tripped spelling against the leaf's
        // original bytes, so a CA whose DER is not exactly what the encoder emits would
        // fail to match. Under deny-unknown that is not a missed revocation, it is a
        // refusal of every request — fail-closed, and an outage. Raw bytes on both
        // sides cannot drift.
        let mut per_issuer: HashMap<Vec<u8>, IssuerCrl> = HashMap::new();
        for crl_der in crls {
            let (_, crl) =
                x509_parser::revocation_list::CertificateRevocationList::from_der(crl_der.as_ref())
                    .map_err(|e| TlsError::Verifier(format!("malformed client CRL: {e}")))?;
            let issuer = crl.issuer().as_raw().to_vec();
            let next_update_unix = crl.next_update().map(|t| t.timestamp());
            let serials = crl
                .iter_revoked_certificates()
                .map(|entry| normalize_serial(entry.raw_serial()).to_vec());

            // Several CRLs may cover one issuer. Union their serials, and keep the
            // EARLIEST nextUpdate: a list that has fallen out of force must not be
            // held in force by a fresher sibling, or a revocation published only on
            // the stale one would silently stop being enforced.
            let slot = per_issuer.entry(issuer).or_insert_with(|| IssuerCrl {
                revoked: HashSet::new(),
                next_update_unix,
            });
            slot.revoked.extend(serials);
            slot.next_update_unix = match (slot.next_update_unix, next_update_unix) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, b) => b,
            };
        }
        Ok(ClientRevocationIndex {
            per_issuer,
            allow_unknown_status,
        })
    }

    /// An index built from no CRLs. Admits every certificate, which is what rustls
    /// does when no CRLs are configured.
    pub fn empty() -> Self {
        ClientRevocationIndex {
            per_issuer: HashMap::new(),
            allow_unknown_status: false,
        }
    }

    /// Whether this index carries no CRLs at all — the "revocation not configured"
    /// case, which admits everything rather than refusing everything.
    pub fn is_empty(&self) -> bool {
        self.per_issuer.is_empty()
    }

    /// The verdict for a leaf, by its raw issuer `Name` DER and raw serial.
    pub fn verdict(&self, issuer_der: &[u8], serial: &[u8], now: i64) -> RevocationVerdict {
        let Some(crl) = self.per_issuer.get(issuer_der) else {
            return RevocationVerdict::Unknown;
        };
        // Past nextUpdate the list is no longer in force, so it can no longer say a
        // certificate is good — but it can still say one is revoked, and honouring
        // that is strictly safer than discarding it.
        if crl.revoked.contains(normalize_serial(serial)) {
            return RevocationVerdict::Revoked;
        }
        match crl.next_update_unix {
            Some(next_update) if now >= next_update => RevocationVerdict::Unknown,
            _ => RevocationVerdict::Good,
        }
    }

    /// Whether a leaf is admitted, applying the operator's unknown-status policy.
    ///
    /// An index with no CRLs admits everything: revocation is not configured, and
    /// refusing every request would turn "no CRL" into a total outage.
    pub fn admits(&self, issuer_der: &[u8], serial: &[u8], now: i64) -> bool {
        if self.is_empty() {
            return true;
        }
        match self.verdict(issuer_der, serial, now) {
            RevocationVerdict::Good => true,
            RevocationVerdict::Revoked => false,
            RevocationVerdict::Unknown => self.allow_unknown_status,
        }
    }
}

/// The index behind an atomic swap, so a reloaded CRL reaches requests already being
/// served on OPEN connections.
///
/// Same shape and same reason as the reloading trust store: the read path clones an
/// `Arc` under a short read lock, so a request in flight never blocks on the reloader
/// and keeps the index it captured.
#[derive(Debug)]
pub struct SharedClientRevocation {
    current: RwLock<Arc<ClientRevocationIndex>>,
}

impl SharedClientRevocation {
    /// Seed the snapshot with the index built from the CRLs read at startup.
    pub fn new(index: ClientRevocationIndex) -> Self {
        SharedClientRevocation {
            current: RwLock::new(Arc::new(index)),
        }
    }

    /// The index in force right now.
    pub fn load(&self) -> Arc<ClientRevocationIndex> {
        match self.current.read() {
            Ok(guard) => Arc::clone(&guard),
            // A poisoned lock still yields the last value: a request must not panic
            // because a reloader paniced mid-swap, and the last-good index is the
            // fail-closed-correct answer — it still carries every revocation it knew.
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// Publish a rebuilt index. Requests already in flight keep the one they captured.
    pub fn store(&self, index: ClientRevocationIndex) {
        match self.current.write() {
            Ok(mut guard) => *guard = Arc::new(index),
            Err(poisoned) => *poisoned.into_inner() = Arc::new(index),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &[u8] = b"\x30\x0a\x31\x08\x30\x06\x06\x03\x55\x04\x03";
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

    /// The `(issuer, serial)` coordinate exactly as the serving path derives it from a
    /// peer leaf (`tls::leaf_facts`), so the lookup key under test is the production one
    /// rather than one the test chose to match.
    fn leaf_coordinate(leaf_der: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (_, cert) =
            x509_parser::certificate::X509Certificate::from_der(leaf_der).expect("leaf parses");
        (
            cert.tbs_certificate.issuer.as_raw().to_vec(),
            cert.tbs_certificate.raw_serial().to_vec(),
        )
    }

    fn index(
        revoked: &[&[u8]],
        next_update: Option<i64>,
        allow_unknown: bool,
    ) -> ClientRevocationIndex {
        let mut per_issuer = HashMap::new();
        per_issuer.insert(
            ISSUER.to_vec(),
            IssuerCrl {
                revoked: revoked
                    .iter()
                    .map(|s| normalize_serial(s).to_vec())
                    .collect(),
                next_update_unix: next_update,
            },
        );
        ClientRevocationIndex {
            per_issuer,
            allow_unknown_status: allow_unknown,
        }
    }

    #[test]
    fn a_listed_serial_is_revoked_and_an_unlisted_one_is_good() {
        let idx = index(&[b"\x01\x02\x03"], Some(9_000), false);
        assert_eq!(
            idx.verdict(ISSUER, b"\x01\x02\x03", 1_000),
            RevocationVerdict::Revoked
        );
        assert!(!idx.admits(ISSUER, b"\x01\x02\x03", 1_000));
        assert_eq!(
            idx.verdict(ISSUER, b"\x09\x09\x09", 1_000),
            RevocationVerdict::Good
        );
        assert!(idx.admits(ISSUER, b"\x09\x09\x09", 1_000));
    }

    /// A positive serial whose high bit is set is encoded with a leading zero pad, and
    /// the certificate and the CRL need not agree on whether to emit it. Comparing raw
    /// bytes would miss the revocation — the one direction this must never fail in.
    #[test]
    fn a_zero_padded_serial_still_matches() {
        let idx = index(&[b"\x00\x80\x01"], Some(9_000), false);
        assert_eq!(
            idx.verdict(ISSUER, b"\x80\x01", 1_000),
            RevocationVerdict::Revoked
        );
        let idx = index(&[b"\x80\x01"], Some(9_000), false);
        assert_eq!(
            idx.verdict(ISSUER, b"\x00\x80\x01", 1_000),
            RevocationVerdict::Revoked
        );
    }

    /// The handshake refuses a leaf whose revocation status no CRL can determine
    /// (`UnknownStatusPolicy::Deny`). A per-request check that admitted it would let
    /// request 2 through the door request 1 was refused at.
    #[test]
    fn an_uncovered_issuer_is_unknown_and_refused_unless_allowed() {
        let idx = index(&[], Some(9_000), false);
        assert_eq!(
            idx.verdict(OTHER_ISSUER, b"\x01", 1_000),
            RevocationVerdict::Unknown
        );
        assert!(!idx.admits(OTHER_ISSUER, b"\x01", 1_000));

        let permissive = index(&[], Some(9_000), true);
        assert!(permissive.admits(OTHER_ISSUER, b"\x01", 1_000));
    }

    /// `enforce_revocation_expiration` makes a stale CRL fail new handshakes closed.
    /// Past `nextUpdate` the list can no longer certify anything as good here either —
    /// but a revocation it already carries is still honoured, which is strictly safer
    /// than discarding it.
    #[test]
    fn a_stale_crl_certifies_nothing_but_still_revokes() {
        let idx = index(&[b"\x01\x02\x03"], Some(5_000), false);
        assert_eq!(
            idx.verdict(ISSUER, b"\x09", 4_999),
            RevocationVerdict::Good,
            "in force right up to nextUpdate"
        );
        assert_eq!(
            idx.verdict(ISSUER, b"\x09", 5_000),
            RevocationVerdict::Unknown,
            "nextUpdate itself is out of force"
        );
        assert_eq!(
            idx.verdict(ISSUER, b"\x01\x02\x03", 9_999),
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
    /// The second half shows what the contract rests on: flip `allow_unknown_status` and
    /// the same expired CRL starts ADMITTING. Production wires it to a hard `false` on
    /// every verifier builder, with no operator knob.
    ///
    /// **If a knob for `allow_unknown_status` is introduced, `TlsPlane`'s post-owner
    /// contract must be re-derived before that change lands** — a surviving snapshot would
    /// otherwise become exactly the frozen authorization state `trust_plane` fails closed
    /// to avoid.
    #[test]
    fn an_expired_crl_refuses_its_issuer_rather_than_admitting_it() {
        let unrefreshed = index(&[], Some(5_000), false);
        assert!(
            unrefreshed.admits(ISSUER, b"\x09", 4_999),
            "in force before nextUpdate, so an unlisted serial is admitted"
        );
        assert!(
            !unrefreshed.admits(ISSUER, b"\x09", 5_000),
            "past nextUpdate an unrefreshed CRL must refuse its issuer, not admit it — \
             this is what lets a TLS snapshot safely outlive its reload worker"
        );

        // The counterfactual, stated so the dependency is visible rather than implied.
        let if_unknown_were_admissible = index(&[], Some(5_000), true);
        assert!(
            if_unknown_were_admissible.admits(ISSUER, b"\x09", 5_000),
            "with unknown status admissible the same expired CRL admits — the premise \
             behind TlsPlane's post-owner contract would no longer hold"
        );
    }

    /// No CRLs configured means rustls performs no revocation checking, so the index
    /// must admit rather than refuse — otherwise installing it would take down every
    /// deployment that configures none.
    #[test]
    fn an_empty_index_admits_everything() {
        let idx = ClientRevocationIndex::empty();
        assert!(idx.is_empty());
        assert!(idx.admits(ISSUER, b"\x01", 1_000));
        assert!(idx.admits(OTHER_ISSUER, b"\xff", i64::MAX));
    }

    #[test]
    fn the_snapshot_swaps_atomically() {
        let shared = SharedClientRevocation::new(index(&[], Some(9_000), false));
        assert!(shared.load().admits(ISSUER, b"\x01\x02\x03", 1_000));
        shared.store(index(&[b"\x01\x02\x03"], Some(9_000), false));
        assert!(
            !shared.load().admits(ISSUER, b"\x01\x02\x03", 1_000),
            "a reloaded CRL must reach a request being served on an already-open connection"
        );
    }

    /// The recovery arms run in exactly the situation nobody rehearses: a reload worker
    /// that panicked mid-swap. A `load` that answered with a default index instead of the
    /// last-good one would silently disable revocation process-wide.
    #[test]
    fn a_poisoned_lock_still_yields_the_last_good_index_and_still_accepts_a_swap() {
        let shared = Arc::new(SharedClientRevocation::new(index(
            &[b"\x01\x02\x03"],
            Some(9_000),
            false,
        )));

        let poisoner = Arc::clone(&shared);
        let outcome = std::thread::spawn(move || {
            let _guard = poisoner.current.write().expect("write lock");
            panic!("reload worker panicked mid-swap");
        })
        .join();
        assert!(outcome.is_err(), "the worker must have panicked");
        assert!(shared.current.is_poisoned(), "the lock must be poisoned");

        assert!(
            !shared.load().admits(ISSUER, b"\x01\x02\x03", 1_000),
            "a poisoned lock must still yield the last-good index, which still carries \
             every revocation it knew"
        );
        assert_eq!(
            shared.load().verdict(ISSUER, b"\x09", 1_000),
            RevocationVerdict::Good,
            "and it must be the last-good index, not an empty or default one"
        );

        shared.store(index(&[], Some(9_000), false));
        assert!(
            shared.load().admits(ISSUER, b"\x01\x02\x03", 1_000),
            "a later reload must still be able to publish through a poisoned lock"
        );
    }

    /// The whole design rests on the raw issuer `Name` DER x509-parser yields from a CRL
    /// being byte-identical to the one the serving path reads off a leaf that CA issued.
    /// If the two spellings differed, every lookup would miss and every issuer would be
    /// `Unknown` — a total outage under deny-unknown, a total bypass under allow.
    #[test]
    fn a_crl_revokes_a_leaf_of_the_same_ca_and_says_nothing_about_another_ca() {
        let ca = test_ca("mcp-re-client-revocation-ca");
        let stranger = test_ca("mcp-re-client-revocation-stranger-ca");
        let idx = ClientRevocationIndex::from_crl_ders(&[ca.crl(&[0x4242], 2035)], false)
            .expect("index builds");

        let (issuer, serial) = leaf_coordinate(&ca.leaf(0x4242));
        assert_eq!(
            idx.verdict(&issuer, &serial, 1_600_000_000),
            RevocationVerdict::Revoked,
            "the CRL's issuer key must match the issuer DER read off the leaf"
        );

        let (issuer, serial) = leaf_coordinate(&ca.leaf(0x1337));
        assert_eq!(
            idx.verdict(&issuer, &serial, 1_600_000_000),
            RevocationVerdict::Good,
            "the issuer is covered and this serial is not listed"
        );

        let (issuer, serial) = leaf_coordinate(&stranger.leaf(0x4242));
        assert_eq!(
            idx.verdict(&issuer, &serial, 1_600_000_000),
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
            false,
        )
        .expect("index builds");

        for revoked in [0x4242_u64, 0x1337] {
            let (issuer, serial) = leaf_coordinate(&ca.leaf(revoked));
            assert_eq!(
                idx.verdict(&issuer, &serial, 1_600_000_000),
                RevocationVerdict::Revoked,
                "a serial named by either list is revoked"
            );
        }

        let (issuer, serial) = leaf_coordinate(&ca.leaf(0x9999));
        assert_eq!(
            idx.verdict(&issuer, &serial, 1_800_000_000),
            RevocationVerdict::Good,
            "in force while both lists are"
        );
        assert_eq!(
            idx.verdict(&issuer, &serial, 2_000_000_000),
            RevocationVerdict::Unknown,
            "past the EARLIER nextUpdate the merged entry is out of force"
        );
    }

    /// The same bytes are handed to rustls, which refuses them. Skipping a malformed CRL
    /// here would leave the request path enforcing a smaller revoked set than the
    /// handshake.
    #[test]
    fn a_malformed_crl_is_refused_rather_than_skipped() {
        let ca = test_ca("mcp-re-client-revocation-malformed-ca");
        let err = ClientRevocationIndex::from_crl_ders(
            &[ca.crl(&[0x4242], 2035), b"not der".to_vec()],
            false,
        )
        .expect_err("a malformed CRL is a hard error");
        assert!(matches!(err, TlsError::Verifier(_)));
    }
}
