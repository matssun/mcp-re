// SPDX-License-Identifier: Apache-2.0
//! The credential a communication-establishment mechanism associated with an established
//! relationship — ADR-MCPRE-063, Slice 4.
//!
//! # The proposition
//!
//! Possession of [`ChannelAssociatedCertificateCredentialEvidence`] means exactly one
//! thing:
//!
//! > The communication-establishment mechanism associated this certificate credential
//! > evidence with this successfully established communication relationship.
//!
//! It does NOT mean the credential was freshly verified during this establishment, that it
//! is currently valid, that it is unrevoked, that it is trusted under current policy, that
//! it has been interpreted as any identity, that the peer is admitted or authorized, or
//! that it is bound to the actor that signed any request.
//!
//! Those are separate authorities. Two of them — the certificate's validity window and,
//! where CRLs are configured, revocation — are recovered per request elsewhere precisely
//! because this product does not carry them.
//!
//! # Why the claim stops at association
//!
//! A resumed relationship restores its stored peer chain verbatim and re-runs neither
//! chain building, nor the CRL consultation, nor the validity window (ADR-MCPRE-055).
//! Resumed relationships are legal here, so *this chain was verified in this handshake* is
//! a sentence the product must not carry. Measured: a full handshake and its resumption
//! report byte-identical credential evidence, and the association proposition is the same
//! one on both paths. `rustls` can also report WHICH path a relationship took; no
//! authority needs that distinction to establish a later proposition, so the product does
//! not carry it. It enters the representation when a consumer does.
//!
//! # Establishment is a predecessor, not a refusal
//!
//! Whether establishment succeeded is not this authority's decision. The mechanism decides
//! it, at its own boundary, before anything here runs — see [`rustls_adapter`], the
//! subordinate that is the only module knowing what a `rustls` connection is.
//!
//! # Where the producer boundary is drawn, and why it is drawn HERE
//!
//! The mechanism adapter is a CHILD of this module rather than a sibling next door, and
//! that placement is half the seal. Rust privacy is *the defining module and its
//! descendants*, so a private constructor here is reachable from this module and from
//! [`rustls_adapter`], and from nowhere else in the crate. As a sibling the adapter would
//! have needed `pub(super)`, which opens construction to every module of
//! `communication_assurance` — present and future — and this product's entire semantic
//! content is provenance. A neighbouring authority able to manufacture it from an arbitrary
//! chain would make the claim false while every control stayed green.
//!
//! The other half is the CALL SITES, because what privacy bounds is a set rather than one
//! caller. In the production configuration that set has exactly one member that constructs:
//! the adapter. This module's own tests are the set's other member and construct synthetic
//! inhabitants deliberately, which is why THM-0028 is scoped to the production
//! configuration instead of quantifying over every inhabitant a build can produce.

pub(crate) mod rustls_adapter;

/// The certificate credential evidence a communication-establishment mechanism associated
/// with one successfully established relationship.
///
/// Sealed: the representation is private to this module and there is no public
/// constructor, so a value of this type cannot be manufactured beside a relationship the
/// way the historical `TransportIdentity` — public fields, a total constructor — could be.
/// Its one production producer is the subordinate mechanism adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelAssociatedCertificateCredentialEvidence {
    /// The associated chain in DER, leaf first, exactly as the mechanism reported it.
    /// Never empty: an empty chain is refused at construction.
    chain_der: Vec<Vec<u8>>,
}

impl ChannelAssociatedCertificateCredentialEvidence {
    /// Associate a mechanism-reported credential chain with the established relationship
    /// it was reported for.
    ///
    /// PRIVATE to this authority: reachable by this module and its descendants, and by
    /// nothing else in the crate. That is a set, not a single caller — [`rustls_adapter`],
    /// the subordinate that is its one PRODUCTION call site, and this module's own tests,
    /// which construct synthetic inhabitants to exercise the refusal below. THM-0028 is
    /// scoped to the production configuration for exactly that reason.
    ///
    /// Not `pub(super)`: that would publish construction to every module of
    /// `communication_assurance`, and a caller that can say *a mechanism associated this*
    /// holds evidence of nothing.
    fn associate(chain_der: Vec<Vec<u8>>) -> Result<Self, ChannelCredentialAssociationRefusal> {
        if chain_der.is_empty() {
            return Err(ChannelCredentialAssociationRefusal::NoCredentialAssociated);
        }
        Ok(ChannelAssociatedCertificateCredentialEvidence { chain_der })
    }

    /// The associated credential chain in DER, leaf first.
    ///
    /// A COMPATIBILITY projection, `pub(crate)` and narrow on purpose. The authorities
    /// that consume a peer chain today — the certificate-lifetime and revocation gates,
    /// and the historical identity facade — have not been migrated to consume semantic
    /// products, and until they are they need the representation. Each migration removes a
    /// caller; the projection goes when the last one does.
    pub(crate) fn credential_chain_der(&self) -> Vec<&[u8]> {
        self.chain_der.iter().map(Vec::as_slice).collect()
    }

    /// The leaf of the associated chain — the certificate the PEER presented, as opposed
    /// to the ones that signed it.
    ///
    /// A NAMED SEMANTIC PROJECTION, `pub(super)` for the identity authority next door.
    /// Which position of the chain is the peer's own certificate is this authority's
    /// knowledge — leaf-first is the mechanism's order, measured by its own controls — so
    /// a consumer receives *the leaf*, not an index into the compatibility projection.
    ///
    /// Projecting is not constructing. The constructor stays private to this module, so
    /// widening a projection does not widen the set of modules that can produce the
    /// evidence, which is what THM-0028 claims.
    ///
    /// The chain is non-empty by construction, so the empty case is unreachable; it maps
    /// to the empty slice rather than panicking, which the interpreter refuses as a
    /// malformed certificate. An unreachable state that fails closed needs no `expect`.
    pub(super) fn associated_leaf_der(&self) -> &[u8] {
        self.chain_der.first().map_or(&[], Vec::as_slice)
    }
}

/// The credential chain of an OPTIONAL association, leaf first — an absent credential is
/// the empty chain.
///
/// The same compatibility projection as
/// [`ChannelAssociatedCertificateCredentialEvidence::credential_chain_der`], for the two
/// serving paths, which hold the association as an `Option`: both refusals mean the same
/// thing to the unmigrated fail-closed core, and passing the empty chain keeps that
/// decision in the one place that owns it rather than adding a second one per path.
pub(crate) fn associated_chain_der(
    credential: Option<&ChannelAssociatedCertificateCredentialEvidence>,
) -> Vec<&[u8]> {
    credential.map_or_else(
        Vec::new,
        ChannelAssociatedCertificateCredentialEvidence::credential_chain_der,
    )
}

/// Why a mechanism's report could not be turned into channel-associated credential
/// evidence.
///
/// Both variants are **mechanism-boundary inconsistencies, not legal domain states**, and
/// the distinction matters: this is not an algebra of things a peer can legitimately do.
/// Characterization measured that neither is reachable through a supported production
/// establishment path, so the type does not invent a reachable-looking domain state for
/// either — it names the inconsistency it refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelCredentialAssociationRefusal {
    /// The mechanism reports that establishment has not completed.
    ///
    /// Unreachable from either production call site: each sits after its mechanism's own
    /// successful-establishment boundary. Refused rather than assumed, because a
    /// `rustls::ServerConnection` exists before its handshake and so proves nothing on its
    /// own.
    EstablishmentIncomplete,

    /// The mechanism reports an established relationship with no associated credential.
    ///
    /// Unreachable under every supported production establishment path: every serving
    /// config is built with a `WebPkiClientVerifier` whose `client_auth_mandatory` stands,
    /// and a peer presenting no certificate is refused DURING establishment — measured, it
    /// fails with *peer sent no certificates* and no relationship exists to associate
    /// anything with. The one build that reaches this state is the deliberately-broken
    /// `fault_accept_any_client` fault-injection lane, which exists to demonstrate that
    /// client-auth controls are load-bearing; refusing here keeps that lane failing closed
    /// at this authority too.
    NoCredentialAssociated,
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
//
// The mechanism harness sits at the authority root rather than inside one adapter because
// BOTH children establish real relationships to measure their own proposition: the adapter
// asks what a relationship associates, and the identity derivation asks which certificate
// of that association an identity comes from. `pub(crate)` here grants nothing in a
// production build — the module does not exist in one.
#[cfg(test)]
pub(crate) mod mechanism_harness {
    //! Real handshakes, for the reason `tls_listener_state::resumption_acceptance` drives
    //! them: what a synthetic `Vec<Vec<u8>>` proves about association is nothing. The
    //! question is what the MECHANISM associates, on each path a production relationship
    //! can take, and only a handshake answers it.

    use std::sync::Arc;

    use rcgen::BasicConstraints;
    use rcgen::CertificateParams;
    use rcgen::DnType;
    use rcgen::ExtendedKeyUsagePurpose;
    use rcgen::IsCa;
    use rcgen::KeyPair;
    use rcgen::KeyUsagePurpose;
    use rcgen::SanType;
    use rustls::client::Resumption;
    use rustls::crypto::ring;
    use rustls::server::WebPkiClientVerifier;
    use rustls::ClientConfig;
    use rustls::ClientConnection;
    use rustls::RootCertStore;
    use rustls::ServerConfig;
    use rustls::ServerConnection;
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::PrivateKeyDer;
    use rustls_pki_types::PrivatePkcs8KeyDer;
    use rustls_pki_types::ServerName;

    pub(crate) struct Ca {
        pub(crate) cert: rcgen::Certificate,
        pub(crate) key: KeyPair,
        pub(crate) params: CertificateParams,
    }

    impl Ca {
        pub(crate) fn issuer(&self) -> rcgen::Issuer<'_, &KeyPair> {
            rcgen::Issuer::from_params(&self.params, &self.key)
        }
        pub(crate) fn der(&self) -> CertificateDer<'static> {
            self.cert.der().clone()
        }
    }

    pub(crate) fn make_ca(cn: &str) -> Ca {
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(Vec::new()).expect("ca params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.distinguished_name.push(DnType::CommonName, cn);
        let cert = params.self_signed(&key).expect("ca self-signed");
        Ca { cert, key, params }
    }

    pub(crate) fn make_leaf(
        ca: &Ca,
        san: &str,
        client_auth: bool,
    ) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
        params.subject_alt_names = vec![SanType::DnsName(san.try_into().expect("dns san"))];
        params.extended_key_usages = vec![if client_auth {
            ExtendedKeyUsagePurpose::ClientAuth
        } else {
            ExtendedKeyUsagePurpose::ServerAuth
        }];
        let cert = params.signed_by(&key, &ca.issuer()).expect("leaf signed");
        (
            cert.der().clone(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
    }

    /// The production client-auth posture: a `WebPkiClientVerifier` over the anchors, with
    /// a session store so a second connection can resume. The verifier is what makes
    /// *established with no credential* unreachable, so the control must use it rather
    /// than a permissive stand-in.
    pub(crate) fn server_config(
        anchors: &[CertificateDer<'static>],
        server_chain: Vec<CertificateDer<'static>>,
        server_key: PrivateKeyDer<'static>,
    ) -> Arc<ServerConfig> {
        let provider = Arc::new(ring::default_provider());
        let mut roots = RootCertStore::empty();
        for anchor in anchors {
            roots.add(anchor.clone()).expect("anchor");
        }
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .expect("client verifier");
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_chain, server_key)
            .expect("server cert");
        config.session_storage = rustls::server::ServerSessionMemoryCache::new(64);
        config.max_early_data_size = 0;
        Arc::new(config)
    }

    pub(crate) fn client_config(
        server_ca: &CertificateDer<'static>,
        client_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    ) -> Arc<ClientConfig> {
        let provider = Arc::new(ring::default_provider());
        let mut roots = RootCertStore::empty();
        roots.add(server_ca.clone()).expect("server ca");
        let builder = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_root_certificates(roots);
        let mut config = match client_auth {
            Some((chain, key)) => builder
                .with_client_auth_cert(chain, key)
                .expect("client cert"),
            None => builder.with_no_client_auth(),
        };
        // Without a client-side cache no second connection can offer a ticket, and the
        // resumed-path control would silently be a second full handshake.
        config.resumption = Resumption::in_memory_sessions(16);
        Arc::new(config)
    }

    /// Drive one in-memory handshake and hand back the server connection, whatever state
    /// it reached. Errors are not asserted here: one control's subject is a handshake that
    /// FAILS, and a helper that panicked on it could not express that.
    pub(crate) fn handshake(
        client: &Arc<ClientConfig>,
        server: &Arc<ServerConfig>,
    ) -> ServerConnection {
        let name = ServerName::try_from("localhost").expect("server name");
        let mut c = ClientConnection::new(Arc::clone(client), name).expect("client conn");
        let mut s = ServerConnection::new(Arc::clone(server)).expect("server conn");

        for _ in 0..16 {
            let mut buf = Vec::new();
            if c.wants_write() {
                c.write_tls(&mut buf).expect("client write");
                if !buf.is_empty() {
                    s.read_tls(&mut buf.as_slice()).expect("server read");
                    if s.process_new_packets().is_err() {
                        break;
                    }
                }
            }
            let mut buf = Vec::new();
            if s.wants_write() {
                s.write_tls(&mut buf).expect("server write");
                if !buf.is_empty() {
                    c.read_tls(&mut buf.as_slice()).expect("client read");
                    if c.process_new_packets().is_err() {
                        break;
                    }
                }
            }
            if !c.wants_write() && !s.wants_write() && !c.is_handshaking() && !s.is_handshaking() {
                break;
            }
        }
        s
    }

    pub(crate) struct Peers {
        pub(crate) client: Arc<ClientConfig>,
        pub(crate) server: Arc<ServerConfig>,
        pub(crate) client_leaf: CertificateDer<'static>,
    }

    pub(crate) fn mutually_authenticated_peers() -> Peers {
        let client_ca = make_ca("peer-client-ca");
        let server_ca = make_ca("peer-server-ca");
        let (server_leaf, server_key) = make_leaf(&server_ca, "localhost", false);
        let (client_leaf, client_key) = make_leaf(&client_ca, "client", true);
        let server = server_config(&[client_ca.der()], vec![server_leaf], server_key);
        let client = client_config(
            &server_ca.der(),
            Some((vec![client_leaf.clone()], client_key)),
        );
        Peers {
            client,
            server,
            client_leaf,
        }
    }

    /// A CA certificate issued BY another CA, carrying its own identity-bearing field.
    ///
    /// The decoy in the provenance controls: an intermediate whose URI SAN names a different
    /// identity from the leaf's, so a derivation that reads "some certificate in the chain"
    /// rather than "the leaf" returns the wrong identity instead of merely a different-looking
    /// success.
    pub(crate) fn make_intermediate(root: &Ca, cn: &str, uri_san: &str) -> Ca {
        let key = KeyPair::generate().expect("intermediate key");
        let mut params = CertificateParams::new(Vec::new()).expect("intermediate params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.distinguished_name.push(DnType::CommonName, cn);
        params.subject_alt_names = vec![SanType::URI(uri_san.try_into().expect("uri san"))];
        let cert = params
            .signed_by(&key, &root.issuer())
            .expect("intermediate signed");
        Ca { cert, key, params }
    }

    /// A client leaf whose identity is a URI SAN — the field the default policy configures.
    pub(crate) fn make_uri_leaf(
        ca: &Ca,
        uri_san: &str,
    ) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
        params.subject_alt_names = vec![SanType::URI(uri_san.try_into().expect("uri san"))];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = params.signed_by(&key, &ca.issuer()).expect("leaf signed");
        (
            cert.der().clone(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_associated_chain_is_carried_leaf_first() {
        let evidence = ChannelAssociatedCertificateCredentialEvidence::associate(vec![
            vec![0x30, 0x01],
            vec![0x30, 0x02],
        ])
        .expect("a reported chain associates");
        assert_eq!(
            evidence.credential_chain_der(),
            vec![[0x30, 0x01].as_slice(), [0x30, 0x02].as_slice()],
            "order is the mechanism's; the leaf must stay first"
        );
    }

    #[test]
    fn an_empty_chain_is_not_a_credential() {
        assert_eq!(
            ChannelAssociatedCertificateCredentialEvidence::associate(Vec::new()),
            Err(ChannelCredentialAssociationRefusal::NoCredentialAssociated),
            "possession must mean a credential was associated, not that a chain was reported"
        );
    }
}
