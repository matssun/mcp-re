// SPDX-License-Identifier: Apache-2.0
//! Trust resolution for one signing slot.
//!
//! One authority: **the presented keyid was vouched for BY THE DEPLOYMENT, for the slot it
//! is being used in.** The seam is caller-supplied and is the primary authorization — a key
//! not trusted for the slot resolves to `None`. What this module adds is the typed
//! cross-check (MCPRE-100) that the returned actor is vouched for the slot that was ASKED
//! for, never a role-string comparison, so a misbehaving resolver is caught too.
//!
//! `ResolvedActor` is deliberately unsealed, and that is the reason this is a function
//! rather than a constructor: every in-process and test resolver is a legitimate producer,
//! so a seal would relocate ceremony without moving authority (ASM-0029, and
//! `docs/dev/sealed-owners.md`).

use crate::block::ResolvedActor;
use crate::block::ResolverOutcome;
use crate::block::SignerSlot;
use crate::error::HttpProfileError;

/// Resolve a keyid through the trust seam for a specific signing slot and apply
/// the typed defense-in-depth cross-check (MCPRE-100). The seam is the primary
/// slot-authorization authority: a key not trusted for `slot` resolves to `None`
/// and fails `actor_binding_failed`. The verifier additionally asserts the
/// returned actor is vouched for the slot it asked for — never a role-string
/// comparison — so a resolver that hands back a wrong-slot actor is also caught.
pub(crate) fn resolve_actor_for_slot<R: Into<ResolverOutcome>>(
    resolve_actor: &dyn Fn(&str, SignerSlot) -> R,
    key_id: &str,
    slot: SignerSlot,
) -> Result<ResolvedActor, HttpProfileError> {
    let actor = match resolve_actor(key_id, slot).into() {
        ResolverOutcome::Resolved(actor) => *actor,
        // A definitive negative from a healthy resolver.
        ResolverOutcome::NotTrusted => return Err(HttpProfileError::UnresolvedKeyId),
        // The resolver could not answer. Fail closed, but say WHICH failure it was
        // (C079): during a store outage the previous seam reported "untrusted key",
        // which sends an operator to look at the caller's credentials instead of at
        // their trust store.
        ResolverOutcome::Unavailable => return Err(HttpProfileError::TrustResolverUnavailable),
    };
    if actor.slot != slot {
        return Err(HttpProfileError::ActorSlotMismatch);
    }
    Ok(actor)
}
