// SPDX-License-Identifier: Apache-2.0
//! The delegated certificate resolver, and the correspondence gate that is the only way to
//! obtain one.
//!
//! ADR-MCPRE-063 Slice 3. This is the first place the architecture shows a semantic product
//! gating a concrete RUNTIME CAPABILITY rather than composing with another semantic product.
//!
//! The file exists so that privacy can do the work. `construct` and the witness field are
//! private to this module, so "assemble a resolver without consulting the authority" is not
//! something a sibling can express — including a sibling added later by someone who has not
//! read this comment.

use std::sync::Arc;

use rustls::server::ClientHello;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls_pki_types::CertificateDer;

use crate::communication_assurance::certificate_chain_evidence::CertificateChainEvidence;
use crate::communication_assurance::credential_key_correspondence::establish_credential_key_correspondence;
use crate::communication_assurance::credential_key_correspondence::CredentialKeyCorrespondenceFacts;
use crate::communication_assurance::credential_key_correspondence::CredentialKeyCorrespondenceRefusal;
use crate::communication_assurance::signing_key_evidence::SigningKeyExportEvidence;

use super::DelegatedEd25519SigningKey;
use super::RawEd25519TlsSigner;
use super::TlsHandshakeSignBudget;

#[derive(Debug)]
pub struct DelegatedCertResolver {
    certified: Arc<CertifiedKey>,
    budget: Arc<TlsHandshakeSignBudget>,
    /// The construction witness (ADR-MCPRE-063 Slice 3).
    ///
    /// Never read, and that is the point: it is not data the resolver uses, it is proof of
    /// how the resolver came to exist. The only way to obtain one is
    /// [`DelegatedCertResolver::materialize`], which establishes correspondence over the
    /// very operands it then moves in here — so possessing this resolver means its
    /// credential and its signer presented the same public key, of the required profile.
    ///
    /// It is deliberately not projected. A consumer that could read it would be a consumer
    /// that could compare keys again, which is the re-derivation the authority exists to
    /// own; and a caller that could SUPPLY it would put us back to pairing facts with
    /// operands by hand.
    _correspondence: CredentialKeyCorrespondenceFacts,
}

impl DelegatedCertResolver {
    /// Materialize a delegated certificate resolver from a credential chain and the signer
    /// for its key, refusing unless the two correspond.
    ///
    /// **The gate.** Correspondence is established here, over `cert_chain` and `signer`
    /// themselves, and the resolver is built from those same values without them leaving
    /// this function. That is what makes the guarantee structural rather than remembered:
    /// there is no window in which a caller holds facts about one pair and material from
    /// another, because the facts are never handed to a caller at all.
    ///
    /// Establishes correspondence and nothing above it. A resolver existing does NOT mean
    /// its certificate is trusted, current, or unrevoked, that the signer is authorized or
    /// holds the private half, or that any handshake will succeed.
    ///
    /// The budget is supplied by the listener that owns it and is installed unchanged —
    /// correspondence is one relation and budget continuity across rebuilds is another,
    /// and neither is derived from the other.
    pub fn materialize(
        cert_chain: Vec<CertificateDer<'static>>,
        signer: Arc<dyn RawEd25519TlsSigner>,
        budget: Arc<TlsHandshakeSignBudget>,
    ) -> Result<Arc<Self>, CredentialKeyCorrespondenceRefusal> {
        let credential = cert_chain
            .first()
            .map_or_else(CertificateChainEvidence::absent, |leaf| {
                CertificateChainEvidence::from_leaf_der(leaf.as_ref())
            });
        // The signer's own failure vocabulary stops here: the authority needs to know that
        // no key was produced, not why the device could not produce one.
        let exported = signer.tls_public_key_spki_der().ok();
        let export_evidence = exported.as_deref().map_or_else(
            SigningKeyExportEvidence::unavailable,
            SigningKeyExportEvidence::exported,
        );
        let correspondence = establish_credential_key_correspondence(credential, export_evidence)?;

        Ok(Self::construct(cert_chain, signer, budget, correspondence))
    }

    /// Assemble the resolver. Private, and reachable only from [`Self::materialize`]:
    /// a sibling that took the same operands without the witness would be exactly the
    /// unchecked constructor this slice removed.
    fn construct(
        cert_chain: Vec<CertificateDer<'static>>,
        signer: Arc<dyn RawEd25519TlsSigner>,
        budget: Arc<TlsHandshakeSignBudget>,
        correspondence: CredentialKeyCorrespondenceFacts,
    ) -> Arc<Self> {
        let key = Arc::new(DelegatedEd25519SigningKey::with_budget(
            signer,
            Arc::clone(&budget),
        ));
        Arc::new(DelegatedCertResolver {
            certified: Arc::new(CertifiedKey::new(cert_chain, key)),
            budget,
            _correspondence: correspondence,
        })
    }

    /// The budget bounding how fast unauthenticated peers can drive the remote signer.
    pub fn budget(&self) -> &Arc<TlsHandshakeSignBudget> {
        &self.budget
    }

    /// The certified key this resolver would present, for tests that need to observe that
    /// a resolver exists at all without driving a handshake.
    #[cfg(test)]
    fn resolve_for_test(&self) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.certified))
    }
}

impl ResolvesServerCert for DelegatedCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.certified.clone())
    }
}

#[cfg(test)]
mod budget_continuity {
    //! The listener-lifetime budget invariant (#597), measured through the materialization
    //! path production uses. It lives beside the resolver because it is a claim about what
    //! the resolver was built with, and because reading that requires the resolver's own
    //! internals.

    use super::super::tests::leaf_for_seed;
    use super::super::tests::CountingSigner;
    use super::super::tests::COUNTING_SIGNER_SEED;
    use super::*;
    use rustls::SignatureScheme;
    use std::sync::atomic::Ordering;

    /// Two resolvers built around ONE budget draw from one bucket.
    ///
    /// This is what makes the budget survive a `ServerConfig` rebuild: the TLS plane
    /// creates the budget once and hands the same one to every build, including the
    /// `--client-crl-reload-secs` rebuild. The broken implementation this catches is
    /// `DelegatedCertResolver::new` on the reload path, which mints a fresh full bucket
    /// on every cadence — turning a sustained rate limit into a per-interval window.
    #[test]
    fn resolvers_sharing_a_budget_share_one_bucket() {
        // Both resolvers are materialized through the correspondence gate, over REAL
        // corresponding material. Budget continuity is a different relation from
        // correspondence, and this control has to keep measuring it through the path
        // production actually uses — not through a constructor production no longer has.
        let counting = Arc::new(CountingSigner::default());
        let chain = vec![leaf_for_seed(&COUNTING_SIGNER_SEED)];
        let signer: Arc<dyn RawEd25519TlsSigner> = counting.clone();
        let budget = Arc::new(TlsHandshakeSignBudget::new(1, 2));
        let first = DelegatedCertResolver::materialize(
            chain.clone(),
            Arc::clone(&signer),
            Arc::clone(&budget),
        )
        .expect("corresponding material");
        let second = DelegatedCertResolver::materialize(chain, signer, Arc::clone(&budget))
            .expect("corresponding material");
        assert!(Arc::ptr_eq(first.budget(), second.budget()));
        // Spend the whole burst through the first resolver's key.
        assert!(budget.try_acquire());
        assert!(budget.try_acquire());
        // The rebuilt resolver must NOT start from a full bucket.
        let signer = second
            .certified
            .key
            .choose_scheme(&[SignatureScheme::ED25519])
            .expect("signer");
        assert!(
            signer.sign(b"transcript").is_err(),
            "a rebuilt resolver must inherit the spent bucket, not a fresh one"
        );
        assert_eq!(
            counting.calls.load(Ordering::Relaxed),
            0,
            "a refused handshake must never reach the remote signer"
        );
    }
}

#[cfg(test)]
mod correspondence_gate {
    //! ADR-MCPRE-063 Slice 3 — correspondence is a structural precondition of the resolver.
    //!
    //! These controls replace a characterization test that asserted the defect: before this
    //! slice, `DelegatedCertResolver::with_budget` was public and took the credential and
    //! the signer as independent operands, so a mismatched pair materialized a resolver and
    //! the only consequence was an opaque handshake failure later. The production path
    //! established correspondence, discarded the fact, and passed the same two operands to
    //! a constructor that never asked for it.
    //!
    //! What is asserted now is the property that replaced it: **no correspondence-bound
    //! resolver can come into existence for material that does not correspond.**
    //!
    //! The controls deliberately do NOT drive a handshake. "The handshake eventually fails"
    //! is the outcome-shaped assertion that has already missed a property twice in this
    //! architecture — it holds equally when nothing is checked at all.

    use super::super::tests::corresponding_material;
    use super::*;
    use crate::key_source::KeyError;
    use mcp_re_core::SigningKey as McpReSigningKey;

    /// A signer for a key of its own choosing — used to present material that does not
    /// correspond to a given certificate.
    struct OtherKeySigner(McpReSigningKey);
    impl RawEd25519TlsSigner for OtherKeySigner {
        fn sign_tls_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
            Ok(mcp_re_core::b64url_decode(&self.0.sign(message)).expect("valid b64url"))
        }
        fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, KeyError> {
            Ok(
                crate::communication_assurance::Ed25519PublicKeyValue::spki_der_for_point(
                    self.0.public_key().to_bytes(),
                ),
            )
        }
    }

    #[test]
    fn a_mismatched_credential_and_signer_cannot_materialize_a_resolver() {
        let (chain, _) = corresponding_material();
        let other = Arc::new(OtherKeySigner(McpReSigningKey::from_seed_bytes(&[9u8; 32])));

        let refusal = DelegatedCertResolver::materialize(
            chain,
            other,
            Arc::new(TlsHandshakeSignBudget::new(8, 8)),
        )
        .expect_err("a signer for another key must not yield a resolver");

        assert!(
            matches!(
                refusal,
                crate::communication_assurance::CredentialKeyCorrespondenceRefusal::Mismatch(_)
            ),
            "and it must refuse ON the relation, not incidentally: {refusal:?}"
        );
    }

    #[test]
    fn a_credential_that_is_not_a_certificate_cannot_materialize_a_resolver() {
        // The other side of the gate. Before the slice this produced a resolver too — the
        // constructor never looked at the bytes it was handed.
        let (_, signer) = corresponding_material();
        assert!(DelegatedCertResolver::materialize(
            vec![CertificateDer::from(vec![1u8; 8])],
            signer,
            Arc::new(TlsHandshakeSignBudget::new(8, 8)),
        )
        .is_err());
    }

    #[test]
    fn an_absent_credential_cannot_materialize_a_resolver() {
        let (_, signer) = corresponding_material();
        assert!(DelegatedCertResolver::materialize(
            Vec::new(),
            signer,
            Arc::new(TlsHandshakeSignBudget::new(8, 8)),
        )
        .is_err());
    }

    #[test]
    fn corresponding_material_materializes_and_installs_the_listener_budget() {
        // The positive control, and the one that keeps Slice 3 from swallowing #597's
        // invariant. Correspondence is one relation; budget continuity across rebuilds is
        // another. The resolver must carry the budget it was GIVEN — not a fresh one, and
        // not one derived from the credential.
        let (chain, signer) = corresponding_material();
        let budget = Arc::new(TlsHandshakeSignBudget::new(3, 5));
        let resolver = DelegatedCertResolver::materialize(chain, signer, Arc::clone(&budget))
            .expect("corresponding material materializes");

        assert!(resolver.resolve_for_test().is_some());
        assert!(
            Arc::ptr_eq(resolver.budget(), &budget),
            "the listener's own budget must be the one installed, by identity and not \
             merely by equal capacity"
        );
    }

    #[test]
    fn the_only_way_to_obtain_a_resolver_is_through_the_gate() {
        // A structural claim, asserted the only way a test can assert one: this module can
        // see every constructor `DelegatedCertResolver` has, and `materialize` is the sole
        // one that is reachable — `construct` is private and takes a witness no caller can
        // produce. If a sibling constructor is ever added that takes the credential and the
        // signer as independent operands, this comment is the thing that was wrong, and the
        // compile-time reachability below is what a reviewer should re-check.
        //
        // What it CAN measure is that the gate is not optional on the path production uses.
        let (chain, signer) = corresponding_material();
        let budget = Arc::new(TlsHandshakeSignBudget::new(1, 1));
        let through_the_facade = crate::tls::validated_delegated_resolver(
            chain.clone(),
            Arc::clone(&signer),
            Arc::clone(&budget),
        );
        assert!(through_the_facade.is_ok());

        let other = Arc::new(OtherKeySigner(McpReSigningKey::from_seed_bytes(&[3u8; 32])));
        assert!(
            crate::tls::validated_delegated_resolver(chain, other, budget).is_err(),
            "the TLS-vocabulary facade is a rendering of the gate's refusal, not a second \
             path around it"
        );
    }
}
