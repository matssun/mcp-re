// SPDX-License-Identifier: Apache-2.0
//! Binding an assembled config to its listener's epoch-tagged session store.
//!
//! The last step of a build, and a different authority from [`super::assembly`], which
//! decides what the config IS. This decides whether a stored session is still a shortcut.
//! `pub(super)`: the owner is the only caller, because it is the only thing that knows
//! which store belongs to which anchors.

use std::sync::Arc;

use rustls::ServerConfig;

use super::auth_epoch::EpochBoundSessionStore;
use super::auth_epoch::TlsAuthEpoch;

/// Bind TLS session resumption to the trust epoch (ADR-MCPRE-055).
///
/// rustls runs client authentication — chain building, the CRL consultation, and the
/// certificate's own validity window — on a FULL handshake only. A resumed session
/// restores the stored peer certificate chain verbatim and skips all three, so an
/// authentication result would otherwise outlive the trust it was derived from: a peer
/// that completed one good handshake keeps an authenticated, identity-bearing channel
/// for the life of the cached session. The `ExactMatchBinding` still matches, because
/// the restored identity is the original one.
///
/// Two of the three are recovered per request — the validity window and, when CRLs are
/// configured, revocation (see [`client_revocation`](crate::client_revocation)). CHAIN
/// BUILDING is not, and cannot be cheaply: it is the ECDSA work that dominates a full
/// handshake. So resumption is gated instead on
/// [`TlsAuthEpoch`](TlsAuthEpoch), a digest of the trusted
/// client-CA set and the client-auth policy — exactly the inputs chain building depends
/// on. While that digest holds, a stored chain is still one the current trust would
/// build; when an operator withdraws a CA it changes, every stored session stops being a
/// shortcut, and the peer takes a full handshake against current trust.
///
/// A stale session is never an authorization failure — it is the absence of a shortcut.
///
/// The store is shared by every per-core worker serving through this config, which is
/// what makes resumption effective under `SO_REUSEPORT`: a reconnect landing on a
/// different worker still finds the session. It is also shared with every LATER build of
/// the same listener's config, so a CRL reload keeps the cache instead of emptying it.
///
/// Each build republishes the epoch its own trust inputs digest to. Called through
/// [`TlsListenerSecurityState`](crate::tls_listener_state::TlsListenerSecurityState) — the
/// only caller — that digest is the state's own, over anchors immutable for the listener's
/// lifetime, so republishing is an invariant-preserving no-op there.
///
/// The eviction below is therefore a property of the STORE, not a description of what a
/// production listener does. See the owner's module note: within a listener the epoch does
/// not advance, and what protects an anchor-set CHANGE is that the new anchors make a new
/// listener with a new, empty store. Do not read the store's capability as evidence that
/// production exercises it.
///
/// Early data stays disabled (rustls' default): a 0-RTT payload would be replayable and
/// is accepted before the handshake completes.
///
/// STATELESS tickets are disabled here too, and that is part of the gate rather than a
/// tuning choice. rustls offers two independent resumption mechanisms: the session store
/// installed below, and [`ProducesTickets`](rustls::server::ProducesTickets) encrypted
/// tickets. When a ticketer is enabled the server resumes straight out of the
/// client-supplied ticket and the session store is never consulted — so the epoch tag,
/// the mismatch eviction, and every claim made above would be bypassed silently. The
/// store is the ONLY resumption path only while [`NoStatelessTickets`] is the ticketer.
pub(super) fn epoch_bound_resumption(
    mut config: ServerConfig,
    resumption: &Arc<EpochBoundSessionStore>,
    epoch: TlsAuthEpoch,
) -> ServerConfig {
    if let Some(previous) = resumption.republish(epoch) {
        eprintln!(
            "mcp-re-proxy: TLS auth epoch advanced {} -> {} (trusted client CAs or the \
             client-auth policy changed); every stored session stops being a shortcut and \
             its peer takes a full handshake against current trust",
            previous.short(),
            epoch.short()
        );
    }
    config.session_storage =
        Arc::clone(resumption) as Arc<dyn rustls::server::StoresServerSessions>;
    config.ticketer = Arc::new(NoStatelessTickets);
    config.max_early_data_size = 0;
    config
}

/// The ticketer that issues no stateless session tickets, so every resumption decision
/// goes through the epoch-tagged session store.
///
/// `enabled()` is false, which is what rustls reads: a server whose ticketer is disabled
/// stores the session server-side and resumes only from that store. The remaining methods
/// refuse as well, so a caller that consults them directly cannot mint or accept a ticket
/// either.
#[derive(Debug)]
struct NoStatelessTickets;

impl rustls::server::ProducesTickets for NoStatelessTickets {
    fn enabled(&self) -> bool {
        false
    }

    fn lifetime(&self) -> u32 {
        0
    }

    fn encrypt(&self, _plain: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn decrypt(&self, _cipher: &[u8]) -> Option<Vec<u8>> {
        None
    }
}
