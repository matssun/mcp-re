//! The outcome of authorization evaluation (ADR-MCPS-013).

use crate::error::PolicyError;

/// The result of evaluating an authorization artifact against a verified request.
///
/// `Deny` carries the precise [`PolicyError`] so the caller (e.g. the sidecar)
/// can surface the matching `mcp-re.authorization_*` wire token and fail closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationDecision {
    /// The request is authorized by the artifact.
    Allow,
    /// The request is refused; the reason is the precise policy error.
    Deny(PolicyError),
}

impl AuthorizationDecision {
    /// `true` iff this is [`AuthorizationDecision::Allow`].
    pub fn is_allowed(&self) -> bool {
        matches!(self, AuthorizationDecision::Allow)
    }

    /// The denial reason, or `None` when allowed.
    pub fn denial(&self) -> Option<&PolicyError> {
        match self {
            AuthorizationDecision::Allow => None,
            AuthorizationDecision::Deny(err) => Some(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AuthorizationDecision;
    use crate::error::PolicyError;

    #[test]
    fn allow_is_allowed_and_has_no_denial() {
        let d = AuthorizationDecision::Allow;
        assert!(d.is_allowed());
        assert_eq!(d.denial(), None);
    }

    #[test]
    fn deny_carries_the_reason() {
        let d = AuthorizationDecision::Deny(PolicyError::AuthorizationScopeDenied);
        assert!(!d.is_allowed());
        assert_eq!(d.denial(), Some(&PolicyError::AuthorizationScopeDenied));
    }
}
