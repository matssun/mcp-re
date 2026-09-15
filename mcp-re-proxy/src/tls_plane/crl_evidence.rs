// SPDX-License-Identifier: Apache-2.0
//! Which client CRLs may be installed at all, and what they say.
//!
//! One fact: **a set of CRLs is installable exactly when every one of them is inside its own
//! `nextUpdate` window.** Statable with no mention of a worker, a cadence or a posture line,
//! which is why it is not in [`super::revocation_currency`] — that module owns whether
//! anything is still refreshing these, and the two go wrong independently.
//!
//! # The gate is the constructor
//!
//! Startup refuses to boot on a CRL past its `nextUpdate`, because the verifier enforces
//! expiration and a proxy that starts and then fails every handshake is an outage nobody
//! attributes to a CRL. The reload path ran a weaker check — the never-expires rule alone —
//! so a CRL that startup refuses could be re-read, indexed, built into a verifier and
//! swapped in, after which every new handshake against that issuer failed closed and the
//! worker reported success.
//!
//! The correction is not a second call to the same checker at the second site. It is that
//! [`ClientCrlEvidence`] has one constructor and that constructor performs the
//! classification, so a set of CRLs that fails it has no inhabitant to install. Deleting the
//! check does not leave a path that skips it; it leaves nothing that compiles.

use crate::client_crl_publication::CrlFreshness;
use crate::client_crl_publication::CrlPosture;

/// How near a CRL's `nextUpdate` an operator is warned, so a refreshed CRL can be installed
/// before the cutover rather than after every handshake has started failing.
const CRL_NEAR_EXPIRY_WARN_SECS: i64 = 6 * 3600;

/// The parsed facts about the client CRLs this replica is enforcing.
///
/// Sealed: the representation is private and [`from_checked`](Self::from_checked) is the
/// only constructor, so possessing one means every CRL in it was inside its own
/// `nextUpdate` window when it was built. That is what makes the startup gate and the
/// reload gate the same gate rather than two checks that agreed for a while.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientCrlEvidence {
    /// One entry per loaded CRL. Empty when offline client-cert revocation is not
    /// configured, which is a different posture — not an empty one.
    postures: Vec<CrlPosture>,
}

impl ClientCrlEvidence {
    /// Classify every CRL against `now_unix`, then parse what the posture reports.
    ///
    /// `Stale` is refused: with expiration enforced, installing one fails every new
    /// handshake closed. `NoNextUpdate` is refused because a CRL that never falls out of
    /// force makes keeping last-good unsafe — last-good is only tolerable while it ages out
    /// on its own. `NearExpiry` warns, which is the one signal that exists to let an
    /// operator install a refresh before the cutover, and it was absent from the reload
    /// path entirely.
    pub(super) fn from_checked(
        crls: &[rustls_pki_types::CertificateRevocationListDer<'static>],
        now_unix: i64,
    ) -> Result<Self, String> {
        let mut postures = Vec::with_capacity(crls.len());
        for (index, crl) in crls.iter().enumerate() {
            require_in_force(crl.as_ref(), index, now_unix)?;
            postures.push(
                crate::client_crl_publication::crl_posture(crl.as_ref())
                    .map_err(|e| e.to_string())?,
            );
        }
        Ok(ClientCrlEvidence { postures })
    }

    /// Whether offline client-cert revocation is configured at all.
    pub fn is_empty(&self) -> bool {
        self.postures.is_empty()
    }

    /// The per-CRL facts, in load order.
    pub(crate) fn postures(&self) -> &[CrlPosture] {
        &self.postures
    }

    /// Synthetic postures for the renderer's own tests.
    ///
    /// `#[cfg(test)]`, so it is absent from every production build and the seal's claim —
    /// that every inhabitant the serving path can hold passed [`from_checked`](Self::from_checked)
    /// — is unaffected. It exists because the posture RENDERER's subject is a list of
    /// digests and windows, and pinning "one line per CRL, each with its own digest" needs
    /// two distinguishable ones rather than two real signed CRLs that say the same thing.
    #[cfg(test)]
    pub(super) fn from_postures(postures: Vec<CrlPosture>) -> Self {
        ClientCrlEvidence { postures }
    }
}

/// Whether one CRL may be installed, as its own predicate.
///
/// Separate from the loop so that "which classes are admissible" is one readable statement
/// rather than a nest, and so that adding a class is an edit to a match with one arm per
/// outcome.
///
/// NOT named `admit`: `tools/verification`'s escape-hatch detector reads that identifier as
/// Verus' proof-discharge `admit()` and refuses the build, which is the conservative
/// direction and the right one — a security predicate sharing a name with a way to delete a
/// proof obligation is worth renaming whether or not a tool objects.
fn require_in_force(crl_der: &[u8], index: usize, now_unix: i64) -> Result<(), String> {
    match crate::client_crl_publication::crl_freshness(crl_der, now_unix, CRL_NEAR_EXPIRY_WARN_SECS)
        .map_err(|e| e.to_string())?
    {
        CrlFreshness::Fresh => Ok(()),
        CrlFreshness::NoNextUpdate => {
            crate::client_crl_publication::crl_next_update_required(crl_der, index)
                .map_err(|e| format!("client CRL that never falls out of force: {e}"))
        }
        CrlFreshness::NearExpiry { next_update_unix } => {
            eprintln!(
                "mcp-re-proxy: WARNING: client CRL #{index} is near expiry \
                 (nextUpdate={next_update_unix}); install a refreshed CRL before then, or new \
                 handshakes will fail closed."
            );
            Ok(())
        }
        CrlFreshness::Stale { next_update_unix } => Err(format!(
            "client CRL #{index} is STALE (nextUpdate={next_update_unix} <= now={now_unix}): \
             with CRL expiration enforced, every new client handshake fails closed. Install a \
             CRL published within its nextUpdate window."
        )),
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::*;

    /// A stale CRL has no inhabitant, so no path can install one.
    ///
    /// The reload used to run only the never-expires rule, so a CRL startup refuses could
    /// be swapped in and reported as success. It is not a second check that stops that now;
    /// it is that the value the reload must produce cannot be built from those bytes.
    #[test]
    fn a_stale_crl_produces_no_evidence_to_install() {
        let crl = crate::client_crl_publication::test_support::crl_with_next_update();
        let next_update = crate::client_crl_publication::crl_posture(crl.as_ref())
            .expect("posture")
            .next_update_unix
            .expect("the fixture states one");
        assert!(
            ClientCrlEvidence::from_checked(std::slice::from_ref(&crl), next_update - 1).is_ok(),
            "inside its window it is installable"
        );
        let refusal = ClientCrlEvidence::from_checked(std::slice::from_ref(&crl), next_update + 1)
            .expect_err("past its nextUpdate it is not");
        assert!(refusal.contains("STALE"), "{refusal}");
    }

    /// An empty set is a configured-off posture, not a failed one.
    #[test]
    fn no_crls_is_evidence_of_a_deployment_without_them() {
        let evidence = ClientCrlEvidence::from_checked(&[], 0).expect("no CRLs is legal");
        assert!(evidence.is_empty());
        assert!(evidence.postures().is_empty());
    }
}
