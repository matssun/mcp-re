// SPDX-License-Identifier: Apache-2.0
//! Materialize the authoritative replay tier (ADR-MCPRE-056 §6; ADR-MCPRE-051 §4).
//!
//! Given a [`ReplayPlan`](crate::startup_plan::ReplayPlan) — pure intent, decided in
//! `startup_plan` — this establishes the tier the per-core serving path awaits, plus the
//! dispatch posture that goes with it. The handover value and its durability guard are the
//! sealed owner in [`materialized`]; this module is the plane the two backends hang off.
//!
//! # This plane owns nothing
//!
//! Unlike `trust_plane`, which owns background workers and has a `Drop` that stops them,
//! this is a MATERIALIZER: it constructs, hands the result over by value, and has nothing
//! left. Both are "planes"; the word does not imply a uniform shape, and pretending it
//! does would put a `Drop` here with nothing to do in it.
//!
//! What it produces is moved into `HttpProfileProxy`, which becomes an
//! `Arc<HttpProfileProxy>` shared by every per-core handler. No handle is retained here,
//! so none can outlive this plane.
//!
//! # The control runtime must outlive every USE, not just the connect
//!
//! The Redis arm connects on the shared control runtime, and that is not merely where the
//! connect happens. `redis`'s `ConnectionManager` captures the runtime it is CREATED in
//! (`Runtime::locate()`) and schedules its disconnect-watch and its reconnect attempts
//! there for the rest of its life. A call site reading `rt.block_on(connect)` looks like
//! "connect here, done"; it is actually a permanent binding.
//!
//! So the substrate must outlive every use of the store. Two things discharge that, and
//! neither is field-declaration order:
//!
//! - **On a later startup failure**, nothing here needs cleaning up. Neither the store nor
//!   its `ConnectionManager` has a `Drop`; the detached reconnect work lives on the
//!   control runtime and dies with it, and the control runtime provably does not escape a
//!   later `?` (see `control_runtime`'s property-4 test). This plane's failure path is
//!   therefore INHERITED from the substrate's, not established locally — which is worth
//!   stating, because it is the reason there is no guard type here.
//! - **On normal shutdown**, `serve_fleet` drains the fleet before any drop runs. Once
//!   the drain returns, no request can be using the tier, so the order in which the proxy
//!   and the runtime are dropped is immaterial. DRAIN-BEFORE-RECLAIM is the property to
//!   preserve when a later owner holds both in one struct — not a field order.

/// Establishing one concrete backend, and refusing the ones this build does not carry.
mod backends;

/// The sealed handover value and the durability guard that is part of producing it.
///
/// A SIBLING of `backends`, not its parent and not its child: the owner's private fields
/// must be unnameable from the module that builds the halves, or the sole-producer claim
/// would hold only for as long as `backends` chose not to assemble one itself.
mod materialized;

pub use materialized::MaterializedReplay;
