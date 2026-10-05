// SPDX-License-Identifier: Apache-2.0
//! Test support for the KMS adapters' delegated-TLS controls: one full-WebPKI mTLS
//! handshake, in memory, whose server `CertificateVerify` is produced by a
//! [`RawEd25519TlsSigner`].
//!
//! The client validates the server certificate chain, the `localhost` name AND the
//! signature over the transcript, so the handshake completes only when the signer's
//! output is a valid PureEdDSA signature under the key the leaf certificate carries.
//! Each adapter calls [`complete_handshake`] with its own signer over its own fake
//! transport; the adapter-independent cases (certificate/signer mismatch, non-Ed25519
//! leaf) belong to the TLS listener's own tests.

use std::sync::Arc;

use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::SanType;
use rustls::crypto::ring;
use rustls::ClientConfig;
use rustls::ClientConnection;
use rustls::RootCertStore;
use rustls::ServerConnection;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::PrivatePkcs8KeyDer;
use rustls_pki_types::ServerName;

use crate::delegated_tls::RawEd25519TlsSigner;
use crate::tls_listener_state::TlsListenerSecurityState;

/// RFC 8410 PKCS#8 v1 header for an Ed25519 private key; the 32-byte seed follows.
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
    params: CertificateParams,
}

impl Ca {
    fn new() -> Self {
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(Vec::new()).expect("ca params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(DnType::CommonName, "mcp-re-test-ca");
        let cert = params.self_signed(&key).expect("ca self-signed");
        Ca { cert, key, params }
    }

    fn issuer(&self) -> rcgen::Issuer<'_, &KeyPair> {
        rcgen::Issuer::from_params(&self.params, &self.key)
    }

    fn leaf(&self, key: &KeyPair, usage: ExtendedKeyUsagePurpose) -> CertificateDer<'static> {
        let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
        params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().expect("dns"))];
        params.extended_key_usages = vec![usage];
        params
            .signed_by(key, &self.issuer())
            .expect("leaf signed")
            .der()
            .clone()
    }
}

/// Drive one in-memory mTLS handshake against a server whose leaf certificate carries the
/// Ed25519 key of `seed` and whose handshake signature comes from `signer`.
///
/// `Ok` only when both ends finished the handshake, which requires the client to have
/// verified the `signer`-produced signature; otherwise the refusal's text.
pub(crate) fn complete_handshake(
    seed: &[u8; 32],
    signer: Arc<dyn RawEd25519TlsSigner>,
) -> Result<(), String> {
    let (server_ca, client_ca) = (Ca::new(), Ca::new());
    let mut pkcs8 = ED25519_PKCS8_PREFIX.to_vec();
    pkcs8.extend_from_slice(seed);
    let server_key = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(pkcs8),
        &rcgen::PKCS_ED25519,
    )
    .expect("ed25519 key from seed");
    let server_cert = server_ca.leaf(&server_key, ExtendedKeyUsagePurpose::ServerAuth);
    let client_key = KeyPair::generate().expect("client key");
    let client_cert = client_ca.leaf(&client_key, ExtendedKeyUsagePurpose::ClientAuth);

    let server_config = TlsListenerSecurityState::new(
        vec![client_ca.cert.der().clone()],
        crate::delegated_tls::HandshakeSignCapacity::default(),
    )
    .build_delegated_config(vec![server_cert], signer, Vec::new())
    .map_err(|e| format!("delegated config: {e:?}"))?;
    let mut roots = RootCertStore::empty();
    roots.add(server_ca.cert.der().clone()).expect("server ca");
    let client_config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("client protocol versions")
        .with_root_certificates(roots)
        .with_client_auth_cert(
            vec![client_cert],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialize_der())),
        )
        .expect("client auth cert");

    let mut client = ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from("localhost").expect("server name"),
    )
    .map_err(|e| e.to_string())?;
    let mut server = ServerConnection::new(Arc::new(server_config)).map_err(|e| e.to_string())?;
    for _ in 0..16 {
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
        let to_server = take_tls(&mut client)?;
        give_tls(&mut server, &to_server)?;
        let to_client = take_tls(&mut server)?;
        give_tls(&mut client, &to_client)?;
    }
    Err("the handshake did not settle".to_string())
}

fn take_tls<D: rustls::SideData>(
    conn: &mut rustls::ConnectionCommon<D>,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut out).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

fn give_tls<D: rustls::SideData>(
    conn: &mut rustls::ConnectionCommon<D>,
    mut bytes: &[u8],
) -> Result<(), String> {
    while !bytes.is_empty() {
        conn.read_tls(&mut bytes).map_err(|e| e.to_string())?;
        conn.process_new_packets().map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use mcp_re_core::b64url_decode;
    use mcp_re_core::SigningKey;

    use super::*;
    use crate::communication_assurance::Ed25519PublicKeyValue;

    /// A local-key signer; `corrupt` flips one bit of every signature it returns.
    struct LocalSigner {
        key: SigningKey,
        corrupt: bool,
    }

    impl RawEd25519TlsSigner for LocalSigner {
        fn sign_tls_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, crate::key_source::KeyError> {
            let mut sig = b64url_decode(&self.key.sign(message)).expect("signature encoding");
            if self.corrupt {
                sig[0] ^= 0x01;
            }
            Ok(sig)
        }

        fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, crate::key_source::KeyError> {
            Ok(Ed25519PublicKeyValue::spki_der_for_point(
                self.key.public_key().to_bytes(),
            ))
        }
    }

    fn signer(seed: &[u8; 32], corrupt: bool) -> Arc<dyn RawEd25519TlsSigner> {
        Arc::new(LocalSigner {
            key: SigningKey::from_seed_bytes(seed),
            corrupt,
        })
    }

    /// The harness is load-bearing in both directions: a valid signature completes the
    /// handshake, and the same signer with one corrupted bit does not.
    #[test]
    fn the_handshake_completes_only_for_a_valid_delegated_signature() {
        let seed = [0x42u8; 32];
        complete_handshake(&seed, signer(&seed, false)).expect("a valid signature completes");
        complete_handshake(&seed, signer(&seed, true))
            .expect_err("a corrupted signature must fail the validating client");
    }
}
