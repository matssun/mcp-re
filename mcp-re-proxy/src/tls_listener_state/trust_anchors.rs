// SPDX-License-Identifier: Apache-2.0
//! The listener's trusted client CAs, read back.
//!
//! The anchors are an input to the listener's authentication epoch and to every verifier it
//! builds; this is the one projection that lets a second consumer — the client CRL reload —
//! authenticate against the SAME set rather than a copy it was handed. A read of an
//! immutable value: there is no setter, because a different anchor set is a different
//! listener.

use rustls_pki_types::CertificateDer;

use super::TlsListenerSecurityState;

impl TlsListenerSecurityState {
    /// The trusted client-CA certificates this listener is bound to.
    ///
    /// The keys a client CRL must be signed by to be installed. Immutable for the listener's
    /// lifetime, so a reload authenticates the new CRLs against the anchors in force.
    pub(crate) fn trust_anchors(&self) -> &[CertificateDer<'static>] {
        &self.client_ca
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The anchors read back are the ones the listener was established with, in order.
    #[test]
    fn the_anchors_read_back_are_the_ones_the_listener_was_built_around() {
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("params")
            .self_signed(&key)
            .expect("cert");
        let anchors = vec![cert.der().clone()];
        let state = TlsListenerSecurityState::new(
            anchors.clone(),
            crate::delegated_tls::HandshakeSignCapacity::default(),
        );
        assert_eq!(state.trust_anchors(), anchors.as_slice());
    }
}
