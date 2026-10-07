// SPDX-License-Identifier: Apache-2.0
//! One audited key-lifecycle event (ADR-MCPRE-052 §7), and the closed set of transitions it
//! can name.
//!
//! The event type is a [`KeyLifecycle`], not a string: the three `mcp-re.delegated_key.*`
//! tokens are the only ones a lifecycle event can carry, and that is a property of the
//! carrier rather than of whoever builds one. Only the custody state machine builds one, so
//! an event in hand was emitted by an issuance step.

use mcp_re_core::audit::event_type;

use super::ActiveDelegatedKey;

/// Which key-lifecycle transition an event records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLifecycle {
    /// A key was adopted with no live predecessor.
    Issued,
    /// A successor was adopted while its predecessor was still valid.
    Rotated,
    /// A key stopped being authoritative.
    Retired,
}

impl KeyLifecycle {
    /// The frozen `mcp-re.delegated_key.*` token for this transition.
    pub fn event_type(self) -> &'static str {
        match self {
            KeyLifecycle::Issued => event_type::DELEGATED_KEY_ISSUED,
            KeyLifecycle::Rotated => event_type::DELEGATED_KEY_ROTATED,
            KeyLifecycle::Retired => event_type::DELEGATED_KEY_RETIRED,
        }
    }
}

/// One audited key-lifecycle event. Carries no key material and no nonce/correlation data
/// (ADR-MCPS-020 startup-line discipline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLifecycleEvent {
    kind: KeyLifecycle,
    delegated_kid: String,
    issuer_kid: String,
    nbf: i64,
    exp: i64,
    jti: String,
    at: i64,
}

impl KeyLifecycleEvent {
    /// The event `kind` records for `key`, issued under `issuer_kid`, at `at`.
    pub(super) fn of(
        kind: KeyLifecycle,
        key: &ActiveDelegatedKey,
        issuer_kid: &str,
        at: i64,
    ) -> Self {
        Self {
            kind,
            delegated_kid: key.delegated_kid().to_owned(),
            issuer_kid: issuer_kid.to_owned(),
            nbf: key.nbf(),
            exp: key.exp(),
            jti: key.jti().to_owned(),
            at,
        }
    }

    /// Which transition this records.
    pub fn kind(&self) -> KeyLifecycle {
        self.kind
    }

    /// The frozen `mcp-re.delegated_key.*` token for [`Self::kind`].
    pub fn event_type(&self) -> &'static str {
        self.kind.event_type()
    }

    /// The delegated key's id.
    pub fn delegated_kid(&self) -> &str {
        &self.delegated_kid
    }

    /// The root `issuer_kid` the key's credential chains to.
    pub fn issuer_kid(&self) -> &str {
        &self.issuer_kid
    }

    /// The credential's `nbf`.
    pub fn nbf(&self) -> i64 {
        self.nbf
    }

    /// The credential's `exp`.
    pub fn exp(&self) -> i64 {
        self.exp
    }

    /// The credential's id, which a revocation names.
    pub fn jti(&self) -> &str {
        &self.jti
    }

    /// When the event happened (the injected `now`).
    pub fn at(&self) -> i64 {
        self.at
    }
}

#[cfg(test)]
mod tests {
    use super::KeyLifecycle;
    use mcp_re_core::audit::KEY_LIFECYCLE_EVENT_TYPES;

    /// The carrier's closed set is exactly the frozen allowlist: a transition with no token,
    /// or a token no transition names, would make one of the two a second vocabulary.
    #[test]
    fn the_transitions_name_exactly_the_frozen_lifecycle_tokens() {
        let named: Vec<&str> = [
            KeyLifecycle::Issued,
            KeyLifecycle::Rotated,
            KeyLifecycle::Retired,
        ]
        .into_iter()
        .map(KeyLifecycle::event_type)
        .collect();
        assert_eq!(named, KEY_LIFECYCLE_EVENT_TYPES.to_vec());
    }
}
