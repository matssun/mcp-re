// SPDX-License-Identifier: Apache-2.0
//! The PUBLISHED client CRL: reading it, and what it says about its own currency.
//!
//! A different authority from [`crate::client_revocation`], which matches a peer's serial
//! a loaded index per request. This one never looks at a peer: it reads the RFC 5280
//! document, extracts the facts the document asserts about itself — its digest, its
//! `thisUpdate`, its `nextUpdate` — and classifies how close it is to falling out of force.
//!
//! Its consumer is not the serving path. [`crate::tls_plane`] reads it at startup and on
//! reload, which is why it lived in the listener module without the listener ever calling
//! it. A CRL's own freshness is a property of the published document, not of a handshake.

use crate::tls::TlsError;
use rustls_pki_types::CertificateRevocationListDer;

/// The freshness of a configured client CRL relative to a verification instant
/// (ADR-MCPS-023 §A1, MCPS-58).
///
/// The client verifier ([`crate::tls_listener_state`]) now enforces `nextUpdate` at handshake time, so a
/// `Stale` CRL fails every new handshake closed. This startup gate surfaces that
/// condition **loudly at boot**: under strict the proxy refuses to start, rather
/// than coming up and silently rejecting every client at the first handshake, and
/// it warns while a CRL is `NearExpiry` so the operator can reload/restart with a
/// refreshed CRL before the cutover (the "restart before `nextUpdate`" contract;
/// the in-process hot-reloader is a v0.10 follow-up).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrlFreshness {
    /// `now < nextUpdate - warn_window` — comfortably valid.
    Fresh,
    /// `nextUpdate - warn_window <= now < nextUpdate` — still valid, but a
    /// refreshed CRL must be in place before `next_update_unix` or new handshakes
    /// will start failing closed.
    NearExpiry { next_update_unix: i64 },
    /// `now >= nextUpdate` — expired; the verifier fails all new handshakes closed.
    Stale { next_update_unix: i64 },
    /// The CRL carries no `nextUpdate` at all, so it never falls out of force.
    ///
    /// Neither rustls' expiration enforcement nor
    /// [`client_revocation`](crate::client_revocation) has anything to compare against,
    /// so such a CRL would be honoured — and its issuer answered `Good` for — for the
    /// whole process lifetime, however long the reload has been failing. That is the
    /// exact opposite of the self-bounding property the TLS plane's fail-closed argument
    /// rests on, so it is a refusal rather than a freshness class the caller may ignore.
    NoNextUpdate,
}

/// Refuse a client CRL that omits `nextUpdate`.
///
/// RFC 5280 §5.1.2.5 requires a conforming CRL issuer to include it, and every
/// self-bounding claim this proxy makes about revocation is a claim about it: past
/// `nextUpdate` the handshake verifier fails closed and the per-request index downgrades
/// the issuer to `Unknown`, which is refused. A CRL without one reaches neither point,
/// so it is refused where it is read — at startup and on every reload — rather than
/// admitted into a posture that says it bounds itself.
pub fn crl_next_update_required(crl_der: &[u8], index: usize) -> Result<(), TlsError> {
    if crl_freshness(crl_der, 0, 0)? == CrlFreshness::NoNextUpdate {
        return Err(TlsError::Verifier(format!(
            "client CRL #{index} omits nextUpdate. It would never fall out of force, so a \
             reload that stops working (unreadable mount, dead reload thread) would leave \
             this replica admitting certificates revoked afterwards for the rest of its \
             lifetime. RFC 5280 §5.1.2.5 requires conforming CRL issuers to include \
             nextUpdate; publish a CRL that does."
        )));
    }
    Ok(())
}

/// Classify a DER-encoded client CRL's `nextUpdate` against `now_unix`, warning
/// `warn_window_secs` ahead of expiry. Pure and offline-testable.
///
/// A CRL with no `nextUpdate` is classified [`CrlFreshness::NoNextUpdate`], which
/// [`crl_next_update_required`] turns into a refusal: nothing in the stack can age such
/// a CRL out. A CRL that cannot be parsed is a hard error — the verifier build would
/// reject it too, so this fails closed rather than silently skipping the gate.
pub fn crl_freshness(
    crl_der: &[u8],
    now_unix: i64,
    warn_window_secs: i64,
) -> Result<CrlFreshness, TlsError> {
    use der::Decode;
    use x509_cert::crl::CertificateList;
    let crl = CertificateList::from_der(crl_der)
        .map_err(|e| TlsError::Verifier(format!("malformed client CRL: {e}")))?;
    let next_update = match crl.tbs_cert_list.next_update {
        Some(t) => t.to_unix_duration().as_secs() as i64,
        None => return Ok(CrlFreshness::NoNextUpdate),
    };
    Ok(if now_unix >= next_update {
        CrlFreshness::Stale {
            next_update_unix: next_update,
        }
    } else if now_unix >= next_update - warn_window_secs {
        CrlFreshness::NearExpiry {
            next_update_unix: next_update,
        }
    } else {
        CrlFreshness::Fresh
    })
}

/// The startup revocation-posture facts for a configured client CRL
/// (ADR-MCPS-023 §A1, MCPS-58).
///
/// These feed the operator-visible `mcp-re.revocation.posture` diagnostic line. That
/// line is a **posture diagnostic, not a structured per-request audit guarantee** —
/// the structured evidence/audit vocabulary lands with Mode C attested ingress
/// (MCPS-62), where `delegated_attestor_crl` actually exists. The field names here
/// (`crl_digest`, `crl_this_update`, `crl_next_update`) are the canonical ones so a
/// future structured audit sink can reuse them verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlPosture {
    /// `sha256:<base64url>` over the CRL DER (the MCP-RE hash-identifier format).
    pub crl_digest: String,
    /// `thisUpdate` as a Unix timestamp.
    pub this_update_unix: i64,
    /// `nextUpdate` as a Unix timestamp, if present (RFC 5280 permits omission).
    pub next_update_unix: Option<i64>,
}

/// Extract the [`CrlPosture`] facts from a DER-encoded client CRL. Pure and
/// offline-testable. A malformed CRL is a hard error (fail closed), consistent
/// with [`crl_freshness`] and the verifier build.
pub fn crl_posture(crl_der: &[u8]) -> Result<CrlPosture, TlsError> {
    use der::Decode;
    use x509_cert::crl::CertificateList;
    let crl = CertificateList::from_der(crl_der)
        .map_err(|e| TlsError::Verifier(format!("malformed client CRL: {e}")))?;
    let this_update = crl.tbs_cert_list.this_update.to_unix_duration().as_secs() as i64;
    let next_update_unix = crl
        .tbs_cert_list
        .next_update
        .map(|t| t.to_unix_duration().as_secs() as i64);
    Ok(CrlPosture {
        crl_digest: mcp_re_core::sha256_hash_id(crl_der),
        this_update_unix: this_update,
        next_update_unix,
    })
}

/// Load the configured offline client-certificate revocation lists (#3839) into
/// the DER form rustls' `WebPkiClientVerifier` consumes. Each path may hold one or
/// more CRLs in PEM (`-----BEGIN X509 CRL-----`) or a single raw DER CRL. Fails
/// closed: a missing or malformed CRL file is a hard startup error (`Err`) rather
/// than a silently-skipped revocation check. An empty `paths` yields an empty vec
/// (revocation checking disabled — the pre-#3839 behavior).
///
/// OFFLINE only: these bytes are read once at startup and never refreshed over the
/// network. Online OCSP / CRL-distribution-point fetching is deliberately NOT done
/// here and is deferred to a follow-up (it needs an HTTP client + a live
/// responder, which would expand the firewalled supply chain).
pub fn load_client_crls(
    paths: &[String],
) -> Result<Vec<rustls_pki_types::CertificateRevocationListDer<'static>>, String> {
    use rustls_pki_types::pem::PemObject;

    let mut crls: Vec<CertificateRevocationListDer<'static>> = Vec::new();
    for path in paths {
        let bytes = std::fs::read(path).map_err(|e| format!("client CRL {path}: {e}"))?;
        // Try PEM first (one file may carry several `X509 CRL` blocks). If the file
        // contains no PEM CRL block, treat the whole file as a single DER CRL.
        let pem: Vec<CertificateRevocationListDer<'static>> =
            CertificateRevocationListDer::pem_slice_iter(&bytes)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("client CRL {path}: malformed PEM: {e}"))?;
        if pem.is_empty() {
            // No PEM CRL block found → interpret the bytes as one DER CRL. Empty
            // input cannot be a valid DER CRL, so reject it (fail closed) rather
            // than load a no-op file.
            if bytes.is_empty() {
                return Err(format!("client CRL {path}: file is empty"));
            }
            crls.push(CertificateRevocationListDer::from(bytes));
        } else {
            crls.extend(pem);
        }
    }
    Ok(crls)
}

#[cfg(test)]
mod crl_next_update_tests {
    //! The TLS plane performs no security transition on `Drop` and gives its CRL reload
    //! loop no failure budget, both on the ground that a CRL bounds ITSELF. That argument
    //! holds only while every loaded CRL states a `nextUpdate`, so a CRL without one is
    //! refused where it is read rather than admitted into a posture that claims it
    //! self-bounds.

    use super::*;
    use der::Decode;
    use der::Encode;
    use x509_cert::crl::CertificateList;

    fn crl_with_next_update() -> Vec<u8> {
        let key = rcgen::KeyPair::generate().expect("ca key");
        let mut params = rcgen::CertificateParams::new(Vec::new()).expect("ca params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "crl-gate-ca");
        let _ca = params.self_signed(&key).expect("ca");
        let crl_params = rcgen::CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2024, 1, 1),
            next_update: rcgen::date_time_ymd(2999, 1, 1),
            crl_number: rcgen::SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        crl_params
            .signed_by(&rcgen::Issuer::from_params(&params, &key))
            .expect("crl")
            .der()
            .to_vec()
    }

    /// The same CRL with its `nextUpdate` removed. RFC 5280 permits the encoding, which
    /// is exactly why the gate has to refuse it rather than assume no CA emits one.
    fn crl_without_next_update() -> Vec<u8> {
        let mut list = CertificateList::from_der(&crl_with_next_update()).expect("parse");
        list.tbs_cert_list.next_update = None;
        list.to_der().expect("re-encode")
    }

    #[test]
    fn a_crl_that_states_its_next_update_is_accepted() {
        let der = crl_with_next_update();
        assert_eq!(
            crl_freshness(&der, 0, 0).expect("parse"),
            CrlFreshness::Fresh
        );
        assert!(crl_next_update_required(&der, 0).is_ok());
    }

    /// The broken implementation this catches: classifying a `nextUpdate`-less CRL as
    /// `Fresh`. Nothing downstream can age it out — rustls' expiration enforcement has
    /// no field to compare and `ClientRevocationIndex::verdict` answers `Good` for its
    /// issuer at any `now` — so a permanently failing reload would leave the replica
    /// admitting certificates revoked afterwards for the rest of its lifetime.
    #[test]
    fn a_crl_that_never_falls_out_of_force_is_refused() {
        let der = crl_without_next_update();
        assert_eq!(
            crl_freshness(&der, 0, 0).expect("parse"),
            CrlFreshness::NoNextUpdate
        );
        let err = crl_next_update_required(&der, 3).expect_err("must be refused");
        let message = err.to_string();
        assert!(message.contains("#3"), "names the offending CRL: {message}");
        assert!(
            message.contains("nextUpdate"),
            "names what is missing: {message}"
        );
    }
}

#[cfg(test)]
mod client_crl_loading_tests {
    #[test]
    fn missing_client_crl_file_fails_closed() {
        // A configured-but-unreadable CRL path is a hard error, never a silently
        // skipped revocation check.
        let err =
            super::load_client_crls(&["/no/such/MCPS3839_MISSING.crl".to_string()]).unwrap_err();
        assert!(err.contains("MCPS3839_MISSING"), "got: {err}");
    }

    #[test]
    fn no_crl_paths_loads_empty_vec() {
        // The no-CRL path: empty input → empty vec (revocation disabled), no error.
        let crls = super::load_client_crls(&[]).expect("empty load");
        assert!(crls.is_empty());
    }
}
