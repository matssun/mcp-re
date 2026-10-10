// SPDX-License-Identifier: Apache-2.0
//! A listening socket together with the names that reach it.
//!
//! The socket and the [`AcceptedHttpAuthority`] derived from the address it is actually
//! bound to are one fact: a `:0` bind is served at a port the configuration never spelled,
//! so the authority is built where the bound socket first exists and travels with it.

use std::net::SocketAddr;
use std::net::TcpListener;

use crate::config::BindScope;

use super::accepted_authority::AcceptedHttpAuthority;

/// A bound listener and the authority names that reach it.
#[derive(Debug)]
pub struct BoundListener {
    listener: TcpListener,
    local_addr: SocketAddr,
    authority: AcceptedHttpAuthority,
}

impl BoundListener {
    /// Pair a socket with the scope of the address it is bound to.
    pub(super) fn new(listener: TcpListener, bound: &BindScope) -> Self {
        Self {
            listener,
            local_addr: bound.listen_address(),
            authority: AcceptedHttpAuthority::for_listener(bound),
        }
    }

    /// The address the socket is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The socket and the authority that names it.
    pub(super) fn into_parts(self) -> (TcpListener, AcceptedHttpAuthority) {
        (self.listener, self.authority)
    }
}
