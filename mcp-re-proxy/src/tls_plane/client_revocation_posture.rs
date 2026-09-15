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
//! Rendering the posture is here too, and for the same reason the loading is: what an
//! operator is told about revocation and what was actually loaded are one authority, and
//! splitting them is how a posture line came to describe a CRL that had been superseded.
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
    if !client_crls.is_empty() {
        eprintln!(
            "mcp-re-proxy: offline client-cert revocation enabled — {} CRL file(s), unknown \
             status DENIED (fail closed) (OFFLINE only; no online OCSP/CRL-DP fetching)",
            crl_paths.len(),
        );
    }
    // The classification is the evidence's own constructor, so startup and reload run the
    // same gate by construction rather than by two call sites agreeing. What startup adds
    // is the CONSEQUENCE: here a refusal means the deployment does not come up, because a
    // proxy that starts and then fails every handshake is an outage nobody attributes to a
    // CRL; on reload the same refusal keeps last-good, which still ages out on its own.
    let evidence = ClientCrlEvidence::from_checked(&client_crls, startup_now_unix)
        .map_err(|e| format!("mcp-re-proxy refuses to start with a bad client CRL: {e}"))?;
    Ok((client_crls, evidence))
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

/// ADR-MCPS-023 §A1 (MCPS-58) — the operator-visible revocation posture, as lines.
///
/// A posture DIAGNOSTIC, not a structured per-request audit guarantee: the structured
/// evidence vocabulary (including `delegated_attestor_crl`, which does not exist yet)
/// lands with Mode C attested ingress (MCPS-62). The canonical ADR field names are used
/// deliberately so that future audit surface can reuse them verbatim. OCSP posture is
/// per-request — no-AIA is a per-cert fact, not a config-load one — and likewise belongs
/// to the MCPS-62 surface rather than to a startup line.
///
/// Returns lines instead of printing them, which is the whole reason it is here: these
/// were ~50 lines of `eprintln!` inside the composition root, where the only way to check
/// what an operator is told was to read a transcript. Rendering the facts the plane
/// already parsed makes the posture assertable (`posture_tests` below) and takes
/// domain-specific posture construction off the root (ADR-MCPRE-058 §7.1).
///
/// Takes the plan AND the evidence, and the split is not incidental: the exposure window
/// is a statement about what was CONFIGURED, while `per_request_crl_check` is a statement
/// about what was actually LOADED and is being enforced. Rendering the second from the
/// plan would report a mechanism as enforced because it was asked for.
///
/// The currency is the third fact, and it is there for the same reason: the cadence is what
/// the deployment PROMISED, and whether anything is still keeping it is a separate thing
/// that only the worker knows. Rendered here rather than left to a FATAL line so the
/// retraction reaches an operator in the vocabulary the promise was made in — a line a log
/// collector already greps, rather than prose it does not.
///
/// Taken as the OWNER rather than as its two facts, so the composition root cannot pair a
/// set of CRLs with a maintenance verdict about a different moment. That pairing is the
/// whole content of the claim.
pub(crate) fn revocation_posture_lines(
    plan: &crate::startup_plan::ChannelEstablishmentPlan,
    currency: &super::ClientRevocationCurrency,
) -> Vec<String> {
    let crls = currency.evidence();
    let maintenance = currency.maintenance();
    // Both durations come from ONE owned window, so the exposure window is never reported
    // beside a connection age that outlives it. There is no `unbounded` arm because there
    // is no such deployment: disabling either bound is refused at layer A, and a window
    // exists only where both are set and the age respects the lifetime.
    let exposure_window = format!("{}s", plan.credential_window.exposure_window().as_secs());
    // The exposure window above is only true because these two bounds hold: the
    // certificate is re-checked against the clock on EVERY request (not just at the
    // handshake), and a connection is closed at a bounded age so the peer must
    // re-handshake through the current CRL. Stated alongside the window it makes honest.
    let mut lines = vec![format!(
        "mcp-re.revocation.posture connection_max_age={}s per_request_cert_validity=enforced \
         per_request_crl_check={} crl_reload={} tls_session_resumption=epoch-bound",
        plan.credential_window.connection_age().as_secs(),
        // The claim the CRL lines below rest on. rustls consults the CRLs during client
        // authentication, which runs on a full handshake only, so without this a revoked
        // peer serves every later request on the connection it already holds and the
        // reload cadence below describes new connections alone.
        if crls.is_empty() {
            "not_configured"
        } else {
            "enforced"
        },
        maintenance.wire(plan.client_revocation.reload_cadence_secs()),
    )];
    if crls.is_empty() {
        let max_lifetime = plan.credential_window.cert_lifetime().as_secs();
        lines.push(format!(
            "mcp-re.revocation.posture revocation_mode=short_lived_cert dynamic_revocation=false \
             exposure_window={exposure_window} max_client_cert_lifetime={max_lifetime}s"
        ));
    } else {
        // Facts parsed once by the plane that loaded the CRLs, rendered here.
        for (i, posture) in crls.postures().iter().enumerate() {
            let next_update = posture
                .next_update_unix
                .map(|n| n.to_string())
                .unwrap_or_else(|| "none".to_string());
            lines.push(format!(
                "mcp-re.revocation.posture revocation_mode=static_crl_snapshot \
                 dynamic_revocation=false stale_crl_policy=fail_closed crl_index={i} \
                 crl_digest={} crl_this_update={} crl_next_update={} \
                 exposure_window={exposure_window}",
                posture.crl_digest, posture.this_update_unix, next_update
            ));
        }
    }
    lines
}

/// What the revocation posture actually tells an operator.
///
/// These lines were `eprintln!`s in the composition root, which meant the only way to
/// check them was to start a proxy and read stderr — so nothing checked them. The
/// extraction is what makes the assertions below possible, and each one pins a claim that
/// would be materially misleading if it drifted.
#[cfg(test)]
mod revocation_posture_tests {
    use super::super::ClientRevocationCurrency;
    use super::revocation_posture_lines;
    use super::ClientCrlEvidence;
    use crate::client_crl_publication::CrlPosture;
    use crate::startup_plan::ChannelEstablishmentPlan;

    /// A plan with no CRLs and the given client-cert lifetime.
    ///
    /// The credential window comes through its classifier, so a lifetime the boundary
    /// refuses — disabled, over the ceiling, or shorter than the connection age — cannot be
    /// written here at all. The `Option<Duration>` this took could name every one of them.
    fn plan(cert_lifetime_secs: u64) -> ChannelEstablishmentPlan {
        ChannelEstablishmentPlan {
            custody: crate::config_state::test_support::channel_custody_exported("/key"),
            client_revocation: crate::config_state::test_support::crl_plan(&[], None),
            credential_window: crate::config_state::test_support::credential_window(
                cert_lifetime_secs,
                300,
            ),
        }
    }

    fn no_crls() -> ClientCrlEvidence {
        ClientCrlEvidence::default()
    }

    /// Without a CRL the posture must say `per_request_crl_check=not_configured`.
    ///
    /// The broken implementation this catches: reporting `enforced` whenever the field is
    /// emitted at all. `enforced` is the claim the exposure-window line rests on — that a
    /// peer holding an open connection is still re-checked — and asserting it with no CRL
    /// loaded would describe a mechanism that is not running.
    #[test]
    fn with_no_crl_the_per_request_check_is_reported_as_not_configured() {
        let lines = revocation_posture_lines(
            &plan(3600),
            &ClientRevocationCurrency::new(no_crls(), false),
        );
        assert!(
            lines[0].contains("per_request_crl_check=not_configured"),
            "got: {}",
            lines[0]
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("revocation_mode=short_lived_cert")),
            "with no CRL the only mechanism is the certificate lifetime: {lines:?}"
        );
    }

    /// One line per loaded CRL, each carrying that CRL's own digest and validity window.
    ///
    /// The broken implementation this catches: rendering only the first CRL, or reusing
    /// one digest across all of them. An operator reading the transcript is checking that
    /// the index they published is the index this replica loaded, and a collapsed list
    /// answers that question wrongly rather than not at all.
    #[test]
    fn every_loaded_crl_reports_its_own_digest_and_window() {
        let crls = ClientCrlEvidence::from_postures(vec![
            CrlPosture {
                crl_digest: "sha256:AAAA".to_string(),
                this_update_unix: 1_700_000_000,
                next_update_unix: Some(1_700_086_400),
            },
            CrlPosture {
                crl_digest: "sha256:BBBB".to_string(),
                this_update_unix: 1_700_000_001,
                // RFC 5280 permits omission, and the line must not invent one.
                next_update_unix: None,
            },
        ]);
        let lines =
            revocation_posture_lines(&plan(3600), &ClientRevocationCurrency::new(crls, true));
        assert!(
            lines[0].contains("per_request_crl_check=enforced"),
            "got: {}",
            lines[0]
        );
        let crl_lines: Vec<&String> = lines
            .iter()
            .filter(|l| l.contains("revocation_mode=static_crl_snapshot"))
            .collect();
        assert_eq!(crl_lines.len(), 2, "one line per CRL: {lines:?}");
        assert!(crl_lines[0].contains("crl_index=0") && crl_lines[0].contains("sha256:AAAA"));
        assert!(crl_lines[1].contains("crl_index=1") && crl_lines[1].contains("sha256:BBBB"));
        assert!(
            crl_lines[1].contains("crl_next_update=none"),
            "an absent nextUpdate must say so, not be invented: {}",
            crl_lines[1]
        );
    }
}
