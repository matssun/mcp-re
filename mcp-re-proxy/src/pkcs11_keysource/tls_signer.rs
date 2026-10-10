// SPDX-License-Identifier: Apache-2.0
//! Delegated TLS handshake signing: the SECOND key the token custodies.
//!
//! A different custody surface from response signing, and it is worth saying why they are
//! not one. The TLS server key and the response-signing key are distinct objects on the
//! token, reached over the SAME `C_Login` — PKCS#11 login is per-token-per-application, so a
//! second independent login on the same token returns `CKR_USER_ALREADY_LOGGED_IN` — but
//! they are exercised by different callers under different concurrency.
//!
//! `CertificateVerify` is signed inside rustls'' SYNCHRONOUS `Signer::sign`, on a handshake
//! worker, which is why this path takes its sessions from a POOL rather than the single
//! amortized one: a blocking `C_Sign` occupies its worker for the whole call, and one shared
//! session would make every handshake on every core queue behind one token operation.

use std::sync::Arc;

use mcp_re_core::VerificationKey;

use crate::communication_assurance::ED25519_SIGNATURE_LEN;
use crate::delegated_tls::RawEd25519TlsSigner;
use crate::key_source::KeyError;

use crate::pkcs11_native::ObjectClass;

use super::session::classify_op_error;
use super::session::SessionOpError;
use super::token::ed25519_spki_from_ec_point;
use super::token::find_key;
use super::token::find_token_bound_private_key;
use super::token::raw_ed25519_point;
use super::verify_before_emit;
use super::Pkcs11Token;

/// A PKCS#11-backed DELEGATED TLS handshake signer (issue #59, ADR-MCPS-028 §G):
/// the Ed25519 TLS *server* key lives on the token as a SEPARATE object (a distinct
/// security principal from the response-signing key) and is exercised ONLY via
/// `C_Sign` with `CKM_EDDSA` — the TLS private key never leaves the device. rustls
/// drives the handshake signature through [`RawEd25519TlsSigner::sign_tls_ed25519`];
/// the (exportable) TLS public point feeds [`RawEd25519TlsSigner::tls_public_key_spki_der`]
/// so the validated build path (#58) fails closed on a cert/key mismatch.
///
/// This signer SHARES the owning [`Pkcs11KeySource`]'s [`Pkcs11Token`] via `Arc` —
/// one `C_Initialize` and one amortized `C_Login` per process — and signs with the
/// TLS-key label. It is an independent signing PRINCIPAL (a separate token object,
/// ADR-MCPS-028 §G) that rides the same module + login as the response-signing key.
/// (The ADR allows the TLS key to carry distinct PKCS#11 auth; the CLI wires the
/// same token PIN. A future flag could route a separate credential without changing
/// the `RawEd25519TlsSigner` surface.)
pub struct Pkcs11TlsSigner {
    /// The shared, logged-in token (see [`Pkcs11Token`]). TLS handshake signs take their
    /// sessions from its pool.
    token: Arc<Pkcs11Token>,
    /// The CKA_LABEL of the Ed25519 TLS PRIVATE key object (used via `C_Sign` only).
    tls_key_label: String,
    /// The TLS public key read at `open`; every signature is verified against it before
    /// it is returned.
    tls_key: VerificationKey,
    /// The RFC 8410 SPKI of the same `CKA_EC_POINT` read that produced `tls_key`.
    tls_spki: Vec<u8>,
}

// `Pkcs11TlsSigner` is `Send + Sync` automatically: its only fields are an
// `Arc<Pkcs11Token>` (the token is `Send + Sync` — see its `unsafe impl` above) and
// a `String`. rustls requires the delegated `RawEd25519TlsSigner` to be `Send + Sync`,
// which this satisfies without a further `unsafe impl`.

impl Pkcs11TlsSigner {
    /// Bind to the named Ed25519 TLS key on the shared `token`, proving at
    /// construction that BOTH the PRIVATE and PUBLIC TLS key objects exist, are
    /// Ed25519, and are UNAMBIGUOUS — a misconfigured TLS credential fails closed
    /// here, before any server starts, never at the first handshake. Every failure
    /// maps to a [`KeyError`] with context; this never panics and never fabricates a
    /// signature or public key.
    pub(super) fn open(token: Arc<Pkcs11Token>, tls_key_label: &str) -> Result<Self, KeyError> {
        let tls_key_label = tls_key_label.to_string();

        // Prove BOTH TLS key objects exist and are single Ed25519 objects (fail closed
        // on zero/multiple/non-Ed25519), and that the token reports the private one as
        // unable to leave it, reusing the token's already-primed login.
        // `CKK_EC_EDWARDS` in the lookup template admits Ed448 as well, so being Ed25519
        // is established by reading the public point here, not by the template.
        let (tls_key, tls_spki) = token.session.with_session(token.as_ref(), |logged_in| {
            let view = token.context.with_handle(logged_in.handle);
            find_token_bound_private_key(&view, &tls_key_label)?;
            tls_public_key(&view, &tls_key_label)
        })?;

        Ok(Pkcs11TlsSigner {
            token,
            tls_key_label,
            tls_key,
            tls_spki,
        })
    }
}

/// Signs the raw TLS handshake transcript ON the token (`C_Sign` / `CKM_EDDSA`) and
/// serves the TLS public point pinned at `open` as an RFC 8410 Ed25519 SPKI — the TLS
/// private key never leaves the device. Signing runs through the SHARED token's login.
impl RawEd25519TlsSigner for Pkcs11TlsSigner {
    fn sign_tls_ed25519(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        self.token
            .tls_sessions
            .with_session(self.token.as_ref(), |logged_in| {
                let view = self.token.context.with_handle(logged_in.handle);
                let private = find_key(&view, &self.tls_key_label, ObjectClass::Private)?;
                // CKM_EDDSA over the raw handshake transcript (NO pre-hash): exactly the
                // PureEdDSA signature rustls expects for SignatureScheme::ED25519. The
                // token returns the raw 64-byte signature; the delegated signer wrapper
                // (delegated_tls.rs) enforces the 64-byte length before it hits the wire.
                // The length check is necessary but not sufficient: the signature is
                // verified against the key pinned at `open` before it is returned.
                let signature = view.sign_eddsa(private, message).map_err(|e| {
                    classify_op_error(e, |e| {
                        KeyError::Malformed(format!("pkcs11 tls: C_Sign (CKM_EDDSA): {e}"))
                    })
                })?;
                if signature.len() != ED25519_SIGNATURE_LEN {
                    return Err(SessionOpError::Fatal(KeyError::Malformed(format!(
                        "pkcs11 tls: token returned a {}-byte signature; expected \
                     {ED25519_SIGNATURE_LEN}",
                        signature.len()
                    ))));
                }
                verify_before_emit(message, &signature, &self.tls_key)
                    .map_err(SessionOpError::Fatal)?;
                Ok(signature)
            })
    }

    fn tls_public_key_spki_der(&self) -> Result<Vec<u8>, KeyError> {
        Ok(self.tls_spki.clone())
    }
}

/// Find the TLS PUBLIC key object labelled `label` and read its point once, returning
/// the key every signature is verified against and the RFC 8410 Ed25519 SPKI served, so
/// the two cannot disagree. A wrong-length / non-Ed25519 / off-curve point is intrinsic
/// — [`SessionOpError::Fatal`], never a session fault and never retried.
fn tls_public_key(
    view: &crate::pkcs11_native::SessionRef<'_>,
    label: &str,
) -> Result<(VerificationKey, Vec<u8>), SessionOpError> {
    let public = find_key(view, label, ObjectClass::Public)?;
    let ec_point = view.get_ec_point(public).map_err(|e| {
        classify_op_error(e, |e| {
            KeyError::Malformed(format!("pkcs11 tls: read CKA_EC_POINT: {e}"))
        })
    })?;
    let spki = ed25519_spki_from_ec_point(&ec_point).map_err(SessionOpError::Fatal)?;
    let bytes = raw_ed25519_point(&ec_point).map_err(SessionOpError::Fatal)?;
    let key = VerificationKey::from_bytes(&bytes).map_err(|e| {
        SessionOpError::Fatal(KeyError::Malformed(format!(
            "pkcs11 tls: invalid Ed25519 public key: {e}"
        )))
    })?;
    Ok((key, spki))
}
