// SPDX-License-Identifier: Apache-2.0
//! One round trip's phases, in the order that keeps them separable.
//!
//! Connect, handshake, write, read — and each boundary is deliberate:
//!
//! * the connect is bounded on its own, because a peer that never completes the TCP
//!   handshake is slow-loris at a layer no TLS timeout reaches;
//! * the handshake is driven EXPLICITLY through its own aggregate deadline, so a server
//!   authentication failure is distinguishable from a later IO error and the body is never
//!   sent to an unauthenticated peer;
//! * the bare socket is reclaimed afterwards, because the request/response phase carries
//!   its OWN aggregate deadline rather than sharing the handshake's;
//! * the response is read under a size cap and that second deadline, then parsed.
//!
//! Both deadlines exist because a per-socket read timeout bounds each individual read, and
//! a peer trickling one byte just under it can extend a phase without bound.

use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream;

use rustls::ClientConnection;
use rustls::StreamOwned;

use super::io_errors::handshake_error;
use super::io_errors::write_error;
use super::limits::read_response_bounded;
use super::limits::DeadlineStream;
use super::response::parse_response;
use super::response::HttpResponseParts;
use super::MtlsClient;
use super::TransportError;

impl MtlsClient {
    /// Connect, handshake, write the prepared request, and read + parse the reply.
    pub(super) fn exchange(
        &self,
        addr: SocketAddr,
        request_head: &[u8],
        request_body: &[u8],
    ) -> Result<HttpResponseParts, TransportError> {
        // Bound the connect (slow-loris at the TCP layer) then bound every
        // subsequent blocking read/write on the socket. This mirrors the proxy's
        // apply_socket_timeouts; the read timeout in particular covers a stalled
        // handshake (reading drives complete_io) and a trickled response body.
        let tcp = match self.limits.connect_timeout {
            Some(timeout) => TcpStream::connect_timeout(&addr, timeout)?,
            None => TcpStream::connect(addr)?,
        };
        tcp.set_read_timeout(self.limits.read_timeout)?;
        tcp.set_write_timeout(self.limits.write_timeout)?;

        let mut conn = ClientConnection::new(self.config.rustls_config(), self.server_name.clone())
            .map_err(|e| TransportError::Handshake(e.to_string()))?;

        // MCPS-094 (#4081, audit M-28/M-30): drive the handshake through an
        // AGGREGATE wall-clock deadline, not only the per-socket read timeout. A
        // peer trickling raw TLS-handshake bytes one at a time — each gap UNDER the
        // per-read timeout — resets the per-read inactivity timer on every byte and
        // would otherwise keep `complete_io` reading forever (slow-loris below the
        // per-read threshold, evading the zero-byte-stall guard). The
        // `DeadlineStream` caps total handshake wall-clock at `read_timeout`,
        // mirroring the response-read aggregate deadline below and the proxy's
        // persistent-inner reader (MCPS-074). `None` (timeout disabled) yields no
        // aggregate deadline either, preserving the existing knob's semantics.
        let handshake_deadline = self
            .limits
            .read_timeout
            .and_then(|t| std::time::Instant::now().checked_add(t));
        let mut handshake_io =
            DeadlineStream::new(tcp, handshake_deadline, self.limits.read_timeout);

        // Drive the handshake explicitly so server-authentication failure is
        // distinguishable from a later IO error and so we never send the body to
        // an unauthenticated peer.
        conn.complete_io(&mut handshake_io)
            .map_err(handshake_error)?;

        // The handshake is complete; reclaim the bare socket for the request/
        // response phase (which has its OWN aggregate deadline below).
        let tcp = handshake_io.into_inner();
        let mut stream = StreamOwned::new(conn, tcp);

        stream.write_all(request_head).map_err(write_error)?;
        stream.write_all(request_body).map_err(write_error)?;
        stream.flush().map_err(write_error)?;

        // MCPS-093 (audit M-3 residual): a single Instant-based AGGREGATE read
        // deadline over the WHOLE response-read phase, mirroring the proxy's
        // persistent-inner reader (MCPS-074, `cli.rs`). The per-socket read timeout
        // bounds each individual read, but a peer trickling bytes just under that
        // per-read timeout could otherwise extend the TOTAL read time without
        // bound (slow-loris below the per-read threshold). The aggregate deadline
        // caps total wall-clock at `read_timeout`; `None` (timeout disabled) yields
        // no aggregate deadline either, preserving the existing knob's semantics.
        let read_deadline = self
            .limits
            .read_timeout
            .and_then(|t| std::time::Instant::now().checked_add(t));
        let response = read_response_bounded(
            &mut stream,
            self.limits.max_response_bytes,
            read_deadline,
            self.limits.read_timeout,
        )?;
        parse_response(&response)
    }
}
