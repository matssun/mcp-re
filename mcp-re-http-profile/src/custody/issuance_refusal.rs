// SPDX-License-Identifier: Apache-2.0
//! Why an issuance adopted nothing.
//!
//! Every refusal has the same security outcome — no key is published, the predecessor
//! serves until its own `exp`, and then the deployment fails closed (ADR-MCPRE-052 §6) —
//! but not the same remedy. A root that did not answer is an outage to wait out; a root
//! that answered with a credential its advertised key did not sign is a misconfigured or
//! substituted root, which waiting never fixes. The cause is kept so an operator can tell
//! the two apart.

use std::fmt;

/// The cause of the most recent issuance attempt that adopted nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuanceRefusal {
    /// The issuer seam returned no credential.
    RootUnavailable,
    /// The issuer returned a credential the configured root public key, under the
    /// configured `issuer_kid`, did not sign — including one too malformed to carry such a
    /// signature. The root broke its contract; this is not an outage.
    RootKeyMismatch,
    /// The root signed a credential that does not attest this issuance: another key,
    /// another identity, another delegation context, or a window that is not this one's.
    NotAsRequested,
}

impl IssuanceRefusal {
    /// The stable token an operator matches on (`cause=<token>`).
    pub const fn token(self) -> &'static str {
        match self {
            IssuanceRefusal::RootUnavailable => "root-unavailable",
            IssuanceRefusal::RootKeyMismatch => "root-key-mismatch",
            IssuanceRefusal::NotAsRequested => "credential-not-as-requested",
        }
    }
}

impl fmt::Display for IssuanceRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self {
            IssuanceRefusal::RootUnavailable => "the root issuer returned no credential",
            IssuanceRefusal::RootKeyMismatch => {
                "root issuer CONTRACT VIOLATION: the credential it returned is not signed by \
                 the public key it advertises under the configured issuer kid"
            }
            IssuanceRefusal::NotAsRequested => {
                "root issuer CONTRACT VIOLATION: the credential it signed does not attest \
                 the issuance requested"
            }
        };
        write!(f, "cause={}: {what}", self.token())
    }
}

#[cfg(test)]
mod tests {
    use super::IssuanceRefusal;

    /// An operator tells an outage from a broken root by the token alone, so no two causes
    /// may share one, and the rendered line leads with it.
    #[test]
    fn each_cause_renders_its_own_token_first() {
        let all = [
            IssuanceRefusal::RootUnavailable,
            IssuanceRefusal::RootKeyMismatch,
            IssuanceRefusal::NotAsRequested,
        ];
        for (i, a) in all.iter().enumerate() {
            assert!(a.to_string().starts_with(&format!("cause={}: ", a.token())));
            for b in &all[i + 1..] {
                assert_ne!(a.token(), b.token());
            }
        }
        assert!(!IssuanceRefusal::RootUnavailable
            .to_string()
            .contains("CONTRACT VIOLATION"));
        assert!(IssuanceRefusal::RootKeyMismatch
            .to_string()
            .contains("CONTRACT VIOLATION"));
    }
}
