// SPDX-License-Identifier: Apache-2.0
//! The read half of the delegated signing capability.

use std::sync::Arc;

use mcp_re_http_profile::ActiveDelegatedKey;

use super::DelegatedServerSigner;

/// What a serving value may do with the deployment's delegated signing key: read the
/// snapshot that is valid now.
///
/// # What it narrows
///
/// A shared [`DelegatedServerSigner`] can no longer write: publication and retirement are
/// private to the rotor's module. What it still carries beside `current` is the rotation
/// owner's view — the rotor metrics and the time to expiry — which a serving value has no
/// use for. The inner `Arc` is private to this module and no method hands it back.
#[derive(Clone)]
pub struct DelegatedSigningReader {
    signer: Arc<DelegatedServerSigner>,
}

impl DelegatedSigningReader {
    /// Narrow a shared signer to its read half. Called by
    /// [`DelegatedServerSigner::reader`], which is the only way to obtain one.
    pub(super) fn over(signer: Arc<DelegatedServerSigner>) -> Self {
        DelegatedSigningReader { signer }
    }

    /// The current delegated key snapshot IFF it is still valid at `now` — the same
    /// fail-closed answer [`DelegatedServerSigner::current`] gives, and the whole of what
    /// this capability confers.
    pub fn current(&self, now: i64) -> Option<Arc<ActiveDelegatedKey>> {
        self.signer.current(now)
    }
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::DelegatedServerSigner;
    use crate::delegated_wiring::test_support::issued_expiring_at;
    use mcp_re_http_profile::ActiveDelegatedKey;
    use std::sync::Arc;

    fn key(exp: i64) -> ActiveDelegatedKey {
        issued_expiring_at(exp, 9)
    }

    /// A reader answers exactly what the signer answers, and a clone of it does too — the
    /// per-core fleet shares one snapshot rather than one each.
    #[test]
    fn a_reader_answers_the_signers_current_snapshot() {
        let signer = Arc::new(DelegatedServerSigner::new());
        let reader = signer.reader();
        assert!(reader.current(0).is_none(), "no key is published yet");

        signer.publish(key(100)).expect("inside the ceiling");
        assert!(reader.current(50).is_some());
        assert!(reader.clone().current(50).is_some());
        assert!(reader.current(100).is_none(), "fails closed at exp");
    }

    /// A reader observes a retirement it could not itself have caused.
    #[test]
    fn a_reader_observes_a_retirement_it_cannot_perform() {
        let signer = Arc::new(DelegatedServerSigner::new());
        let reader = signer.reader();
        signer.publish(key(100)).expect("inside the ceiling");
        assert!(reader.current(50).is_some());

        signer.retire();
        assert!(reader.current(50).is_none());
    }
}
