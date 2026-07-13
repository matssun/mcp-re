// SPDX-License-Identifier: Apache-2.0
//! Hot-path delegated response signing for the async serving fleet
//! (ADR-MCPRE-052 §4/§6, ADR-MCPRE-051 §5, MCPRE-122).
//!
//! Splits the delegated-signing responsibilities across the hot/cold boundary:
//!
//! - [`DelegatedServerSigner`] is the **hot-path** half the per-core fleet shares
//!   (`Send + Sync`, generic-free). It holds only an atomically-swappable snapshot
//!   of the current delegated key + its root-signed credential. Signing a response
//!   reads the snapshot and produces an in-memory Ed25519 signature — it never
//!   touches the root and never blocks. Past the credential's `exp` it yields
//!   nothing, so the caller fails closed (ADR-MCPRE-052 §6).
//!
//! - [`DelegatedRotor`] is the **cold-path** half a single owner drives (a
//!   background thread in production; a test directly). It owns the
//!   [`DelegatedSigningCustody`] state machine — where the root issuer (KMS/HSM in
//!   production) is invoked at issuance/rotation only — and republishes the fresh
//!   snapshot after each rotation. Fail-closed issuance retires the snapshot.
//!
//! The root issuer is never on the request path: the fleet reads snapshots, the
//! rotor mints them. This is the load-bearing property of ADR-MCPRE-051 §5.

use std::sync::Arc;
use std::sync::RwLock;

use mcp_re_http_profile::ActiveDelegatedKey;
use mcp_re_http_profile::CustodyError;
use mcp_re_http_profile::DelegatedSigningCustody;
use mcp_re_http_profile::KeyLifecycleEvent;
use mcp_re_core::SigningKey;
use mcp_re_http_profile::DelegationClaims;
use mcp_re_http_profile::DelegationHeader;

/// The shared hot-path signer: an atomically-swappable delegated-key snapshot.
///
/// One instance is shared across every per-core runtime. `sign`-side callers read
/// [`current`](Self::current); the rotor writes via [`publish`](Self::publish) /
/// [`retire`](Self::retire). The `RwLock` is read-mostly — a brief write only at
/// rotation — so per-request reads are uncontended in steady state.
#[derive(Default)]
pub struct DelegatedServerSigner {
    active: RwLock<Option<Arc<ActiveDelegatedKey>>>,
}

impl DelegatedServerSigner {
    /// A signer with no key yet — every [`current`](Self::current) fails closed
    /// until the rotor publishes the first key.
    pub fn new() -> Self {
        DelegatedServerSigner {
            active: RwLock::new(None),
        }
    }

    /// Publish a freshly-issued/rotated delegated key snapshot for the hot path.
    pub fn publish(&self, active: ActiveDelegatedKey) {
        *self.active.write().expect("delegated signer lock (write)") = Some(Arc::new(active));
    }

    /// Retire the current snapshot — the hot path then fails closed until a new key
    /// is published. Used on fail-closed issuance (ADR-MCPRE-052 §6).
    pub fn retire(&self) {
        *self.active.write().expect("delegated signer lock (write)") = None;
    }

    /// The current delegated key snapshot IFF it is still valid at `now`. Returns
    /// `None` before the first issuance, after retirement, or once `now >= exp` —
    /// the fail-closed expiry bound (the credential is never honored past its
    /// window, matching the verifier, ADR-MCPRE-052 §6).
    pub fn current(&self, now: i64) -> Option<Arc<ActiveDelegatedKey>> {
        let guard = self.active.read().expect("delegated signer lock (read)");
        match guard.as_ref() {
            Some(a) if now < a.exp => Some(Arc::clone(a)),
            _ => None,
        }
    }
}

/// The cold-path rotation driver: owns the custody state machine and republishes
/// snapshots into a shared [`DelegatedServerSigner`]. A single owner drives it
/// (never the hot path), so the root issuer's blocking KMS/HSM calls stay off the
/// per-core runtimes.
pub struct DelegatedRotor<Issue, Factory> {
    custody: DelegatedSigningCustody<Issue, Factory>,
    signer: Arc<DelegatedServerSigner>,
}

impl<Issue, Factory> DelegatedRotor<Issue, Factory>
where
    Issue: FnMut(&DelegationHeader, &DelegationClaims) -> Option<String>,
    Factory: FnMut() -> SigningKey,
{
    /// Bind a custody state machine to the shared hot-path signer.
    pub fn new(
        custody: DelegatedSigningCustody<Issue, Factory>,
        signer: Arc<DelegatedServerSigner>,
    ) -> Self {
        DelegatedRotor { custody, signer }
    }

    /// Issue or rotate the delegated key as of `now`, then publish the fresh
    /// snapshot for the hot path. On fail-closed issuance (the root cannot issue and
    /// the current key has expired) the snapshot is retired so the hot path fails
    /// closed. Call this proactively inside the rotation-overlap window so a
    /// successor is ready before the predecessor expires (no signing gap).
    pub fn rotate(&mut self, now: i64) -> Result<(), CustodyError> {
        match self.custody.ensure_active(now) {
            Ok(()) => {
                let snapshot = self
                    .custody
                    .active_snapshot()
                    .expect("ensure_active guarantees an active key");
                self.signer.publish(snapshot);
                Ok(())
            }
            Err(e) => {
                self.signer.retire();
                Err(e)
            }
        }
    }

    /// The audited key-lifecycle events so far (issue / rotate / retire).
    pub fn audit(&self) -> &[KeyLifecycleEvent] {
        self.custody.audit()
    }

    /// How many times the ROOT issuer has been invoked (issuance + rotation only) —
    /// never incremented by the hot-path signing that reads published snapshots.
    pub fn root_invocations(&self) -> u64 {
        self.custody.root_invocations()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_re_http_profile::issue_delegation_credential;
    use mcp_re_http_profile::CustodyConfig;
    use mcp_re_http_profile::PROFILE_TAG;

    const ROOT_KID: &str = "root-kid";
    const T: i64 = 300;
    const O: i64 = 60;
    const NOW: i64 = 1_700_000_100;

    fn cfg() -> CustodyConfig {
        CustodyConfig {
            issuer_kid: ROOT_KID.into(),
            iss: "did:example:server".into(),
            profile: PROFILE_TAG.into(),
            aud: "verifier-1".into(),
            audience_hash: "aud-scope-1".into(),
            trust_epoch: "epoch-1".into(),
            server_role: "server".into(),
            server_trust_domain: "example.com".into(),
            server_subject: "did:example:server".into(),
            ttl: T,
            overlap: O,
        }
    }

    fn rotor() -> (DelegatedRotor<impl FnMut(&DelegationHeader, &DelegationClaims) -> Option<String>, impl FnMut() -> SigningKey>, Arc<DelegatedServerSigner>) {
        let root = SigningKey::from_seed_bytes(&[33u8; 32]);
        let issue = move |h: &DelegationHeader, c: &DelegationClaims| {
            Some(issue_delegation_credential(&root, h, c))
        };
        let mut n = 100u8;
        let factory = move || {
            n = n.wrapping_add(1);
            SigningKey::from_seed_bytes(&[n; 32])
        };
        let signer = Arc::new(DelegatedServerSigner::new());
        let custody = DelegatedSigningCustody::new(cfg(), issue, factory);
        (DelegatedRotor::new(custody, Arc::clone(&signer)), signer)
    }

    #[test]
    fn no_key_before_first_rotate_fails_closed() {
        let signer = DelegatedServerSigner::new();
        assert!(signer.current(NOW).is_none());
    }

    #[test]
    fn rotate_publishes_a_snapshot_the_hot_path_reads() {
        let (mut rotor, signer) = rotor();
        rotor.rotate(NOW).expect("issue");
        let snap = signer.current(NOW).expect("a key is published");
        assert_eq!(snap.delegated_kid, format!("{ROOT_KID}/delegated/1"));
        assert_eq!(rotor.root_invocations(), 1);
    }

    #[test]
    fn snapshot_fails_closed_past_expiry() {
        let (mut rotor, signer) = rotor();
        rotor.rotate(NOW).expect("issue");
        // At exp the snapshot is no longer honored (fail-closed bound).
        assert!(signer.current(NOW + T).is_none());
        assert!(signer.current(NOW + T - 1).is_some());
    }

    #[test]
    fn fail_closed_issuance_retires_the_snapshot() {
        // An issuer that always fails, with no prior key: rotate must retire.
        let issue = |_: &DelegationHeader, _: &DelegationClaims| None;
        let factory = || SigningKey::from_seed_bytes(&[7u8; 32]);
        let signer = Arc::new(DelegatedServerSigner::new());
        let custody = DelegatedSigningCustody::new(cfg(), issue, factory);
        let mut rotor = DelegatedRotor::new(custody, Arc::clone(&signer));
        assert_eq!(rotor.rotate(NOW), Err(CustodyError::FailClosedIssuance));
        assert!(signer.current(NOW).is_none());
    }
}
