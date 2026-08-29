// SPDX-License-Identifier: Apache-2.0
//! The client-revocation posture: loading it, indexing it, and keeping it fresh.
//!
//! OFFLINE revocation only — there is no online OCSP or distribution-point fetching. Three
//! things follow from one set of CRL bytes, and they reach different parts of the request
//! path:
//!
//! * the HANDSHAKE verifier, which rustls consults on a full handshake alone;
//! * a PER-REQUEST index, because a peer added to a reloaded CRL otherwise keeps serving
//!   every request on the connection it already holds;
//! * the reload worker, which re-reads the files and swaps a rebuilt verifier in.
//!
//! The freshness rule is what makes the posture honest. The verifier enforces `nextUpdate`,
//! so a stale CRL fails every NEW handshake closed — a proxy that starts and then refuses
//! every client is an outage nobody attributes to a CRL. It is therefore surfaced at BOOT
//! instead, with near-expiry warning early enough to install a refreshed CRL before the
//! cutover. A failed reload keeps the last-good config, which still fails closed once its
//! own `nextUpdate` passes, so a bad reload never widens what is accepted.

use std::sync::Arc;

use super::client_revocation;
use super::ClientCrlEvidence;

/// Load the offline client-cert CRLs and hold them to their own `nextUpdate` (#3839).
///
/// OFFLINE revocation only — there is no online OCSP or distribution-point fetching. The
/// verifier enforces `nextUpdate`, so a stale CRL fails every NEW handshake closed; that is
/// surfaced at BOOT instead, because a proxy that starts and then refuses every client is
/// an outage nobody attributed to a CRL. Near-expiry warns so a refreshed CRL can be
/// installed before the cutover, and a malformed CRL is a hard startup error.
///
/// Freshness is checked before posture is read, so a stale CRL refuses startup with its own
/// diagnostic rather than being reported as posture.
pub(super) fn load_and_check_crls(
    crl_paths: &[String],
    startup_now_unix: i64,
) -> Result<
    (
        Vec<rustls_pki_types::CertificateRevocationListDer<'static>>,
        ClientCrlEvidence,
    ),
    String,
> {
    let client_crls = crate::client_crl_publication::load_client_crls(crl_paths)?;
    let mut postures = Vec::with_capacity(client_crls.len());
    if !client_crls.is_empty() {
        eprintln!(
            "mcp-re-proxy: offline client-cert revocation enabled — {} CRL file(s), unknown \
             status DENIED (fail closed) (OFFLINE only; no online OCSP/CRL-DP fetching)",
            crl_paths.len(),
        );
        // ADR-MCPS-023 §A1 (MCPS-58): the verifier enforces CRL nextUpdate, so a
        // stale CRL fails every new handshake closed. Surface that at BOOT — refuse
        // to start on a stale CRL — and warn while a CRL is near expiry so a
        // refreshed CRL can be installed before the cutover. A malformed CRL is a
        // hard startup error (fail closed).
        const CRL_NEAR_EXPIRY_WARN_SECS: i64 = 6 * 3600;
        for (i, crl) in client_crls.iter().enumerate() {
            match crate::client_crl_publication::crl_freshness(
                crl.as_ref(),
                startup_now_unix,
                CRL_NEAR_EXPIRY_WARN_SECS,
            )
            .map_err(|e| e.to_string())?
            {
                crate::client_crl_publication::CrlFreshness::Fresh => {}
                crate::client_crl_publication::CrlFreshness::NoNextUpdate => {
                    crate::client_crl_publication::crl_next_update_required(crl.as_ref(), i)
                        .map_err(|e| {
                            format!(
                                "mcp-re-proxy refuses to start with a client CRL that never \
                             falls out of force: {e}"
                            )
                        })?;
                }
                crate::client_crl_publication::CrlFreshness::NearExpiry { next_update_unix } => {
                    eprintln!(
                        "mcp-re-proxy: WARNING: client CRL #{i} is near expiry \
                     (nextUpdate={next_update_unix}); install a refreshed CRL and restart \
                     before then, or new handshakes will fail closed."
                    )
                }
                crate::client_crl_publication::CrlFreshness::Stale { next_update_unix } => {
                    let msg = format!(
                        "client CRL #{i} is STALE (nextUpdate={next_update_unix} <= \
                         now={startup_now_unix}): with CRL expiration enforced, every new \
                         client handshake fails closed. Install a CRL published within its \
                         nextUpdate window."
                    );
                    return Err(format!(
                        "mcp-re-proxy refuses to start with a stale client CRL: {msg}"
                    ));
                }
            }
        }
        // Parsed here, once, and carried as facts. Freshness is checked first, above,
        // so a stale CRL still refuses startup with its own diagnostic rather than
        // being reported as posture.
        for crl in &client_crls {
            postures.push(
                crate::client_crl_publication::crl_posture(crl.as_ref())
                    .map_err(|e| e.to_string())?,
            );
        }
    }
    Ok((client_crls, ClientCrlEvidence { postures }))
}

/// The PER-REQUEST revocation index, built from the same CRL bytes the handshake verifier
/// is about to be given.
///
/// Without it revocation reaches only NEW connections: rustls runs client authentication on
/// a full handshake alone, so a peer added to a reloaded CRL keeps serving every request on
/// the connection it already holds.
pub(super) fn build_revocation_index(
    client_crls: &[rustls_pki_types::CertificateRevocationListDer<'static>],
) -> Result<Option<Arc<client_revocation::SharedClientRevocation>>, String> {
    if client_crls.is_empty() {
        return Ok(None);
    }
    let index = client_revocation::ClientRevocationIndex::from_crl_ders(
        &client_crls
            .iter()
            .map(|crl| crl.as_ref().to_vec())
            .collect::<Vec<_>>(),
    )
    .map_err(|e| e.to_string())?;
    Ok(Some(Arc::new(
        client_revocation::SharedClientRevocation::new(index),
    )))
}
