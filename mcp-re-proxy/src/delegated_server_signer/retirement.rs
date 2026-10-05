// SPDX-License-Identifier: Apache-2.0
//! Withdrawing delegated signing for good, as a capability apart from publishing it.

use std::sync::Arc;

use super::DelegatedServerSigner;

/// The authority to retire one delegated signer PERMANENTLY, and nothing else.
///
/// Issued only by the [`DelegatedRotor`](super::DelegatedRotor) that publishes into the
/// signer, for the owners that must stop signing when key maintenance stops — the signing
/// plane on drop, and the rotation thread's supervisor — while the rotor itself has moved
/// onto that thread. It cannot publish, cannot read a key, and what it does is absorbing:
/// once used, no later publication restores signing.
#[derive(Clone)]
pub struct SigningRetirement(Arc<DelegatedServerSigner>);

impl SigningRetirement {
    /// The capability over `signer`; reachable only from the rotor that owns it.
    pub(super) fn of(signer: Arc<DelegatedServerSigner>) -> Self {
        SigningRetirement(signer)
    }

    /// Retire the signer permanently: the hot path fails closed from now on.
    pub fn retire_permanently(&self) {
        self.0.retire_permanently();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The capability retires the signer it was issued over, and that retirement holds
    /// against a later publication.
    #[test]
    fn a_retirement_withdraws_signing_for_good() {
        let signer = Arc::new(DelegatedServerSigner::new());
        let live = crate::delegated_wiring::test_support::issued_expiring_at(
            crate::clock::now_unix() + 3600,
            5,
        );
        signer.publish(live.clone()).expect("inside the ceiling");
        SigningRetirement::of(Arc::clone(&signer)).retire_permanently();
        assert!(signer.current(crate::clock::now_unix()).is_none());
        signer.publish(live).expect("ignored, not refused");
        assert!(signer.current(crate::clock::now_unix()).is_none());
    }
}
