// SPDX-License-Identifier: Apache-2.0
//! The selector vocabulary a deployment request is written in.
//!
//! Each enum names the alternatives for one deployment question — whether admission is
//! enforced, what the transport binds, where the security record goes. They are the request's
//! own vocabulary rather than the CLI's: an option spelling maps ONTO one of these, and
//! nothing here knows that a command line exists. That is what lets the configuration
//! state model read a request without depending on the parser that usually builds one.
//!
//! Not every variant is a deployment a `ValidatedDeployment` can be in. [`BindingKind`]
//! has three the boundary refuses outright; they are input forms the model must be able to
//! REPRESENT in order to refuse, which is a different thing from admitting them.

/// Replay-cache backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionKind {
    /// Admission is not enforced. A call's admission binding, if it carries one, is
    /// verified evidence that decides nothing — the pre-MCPRE-493 behaviour.
    Off,
    /// Enforced when present. For a rollout that has not reached every client yet.
    Optional,
    /// Enforced always: a call with no admission evidence is refused. The only
    /// setting under which "every served call acted under a current admission" is a
    /// true statement about this deployment.
    Required,
}

/// Where the ADR-MCPS-035 per-request security record goes.
///
/// The record is the deployment's only per-request attribution surface: which actor
/// was admitted, which calls were refused and under exactly which frozen `mcp-re.*`
/// wire code. It is therefore ON unless a deployment names the opposite — the absent
/// case must not be the one that leaves an incident unreconstructable — and the
/// startup line states which posture is in force either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditSinkKind {
    /// No per-request security record is emitted.
    None,
    /// One structured `key=value` line per decision on the proxy's stderr diagnostic
    /// channel — the same channel the startup lines and rotation warnings use.
    Stderr,
}

/// Whether the PEP writes its own verified context into the body forwarded to the
/// inner server (#415 rev 2 §10).
///
/// The caller-supplied reserved key is stripped either way; this selects only
/// whether the PEP's own context is then written in its place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedContextKind {
    /// Forward the stripped body with no verified context. The inner server makes no
    /// authorization decision on PEP-resolved identity.
    Disabled,
    /// Write the PEP's verified context into the forwarded body. Selecting this
    /// ASSERTS that nothing but this PEP can reach the inner server — the carrier is
    /// unsigned, so the channel is the only thing making it trustworthy, and no check
    /// here can confirm that property.
    Trusted,
}

/// Authorization-policy selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzKind {
    /// No authorization policy.
    Off,
    /// The reference signed-authorization profile.
    ///
    /// Retained and refused rather than deleted: it names the profile ADR-MCPRE-050's
    /// carrier change retired, and an operator who set it needs to be told that rather
    /// than told the flag is a typo.
    Reference,
    /// The carried PDP decision (ADR-MCPRE-065 §8) — the production authority.
    ///
    /// Selecting it is a claim that authorization is an ACTIVE control here, so a request
    /// carrying no applicable decision is refused (§7.1: `NoPolicyConfigured` is not
    /// available to a deployment that configured an authority). There is deliberately no
    /// permissive variant; a migration posture would be a separately named deployment
    /// posture with its own audit semantics, not a weaker reading of this one.
    PdpDecision,
}
