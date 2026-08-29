// SPDX-License-Identifier: Apache-2.0
//! The published-list revocation mechanism (X.509 CRLs today).

/// The revocation lists this deployment reads, and how often it re-reads them.
///
/// The cadence is a sibling of the set rather than a member of it because the boundary
/// still has something to say about the pair: a cadence for re-reading an empty set states
/// a control the deployment does not have (CF-04), and both halves are values an operator
/// supplies independently. What a type cannot make unrepresentable, a boundary must still
/// refuse.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RevocationListRequest {
    /// The list files. Empty is exactly what "no lists" means.
    pub paths: Vec<String>,
    /// Seconds between re-reads, where the operator asked for them.
    pub reload_secs: Option<u64>,
}

impl RevocationListRequest {
    /// Whether any list is consulted at all.
    pub fn is_configured(&self) -> bool {
        !self.paths.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An empty set is the unconfigured posture, and it is the default.
    #[test]
    fn an_empty_set_is_the_unconfigured_posture() {
        assert!(!RevocationListRequest::default().is_configured());
        assert!(RevocationListRequest {
            paths: vec!["/crl.pem".to_string()],
            reload_secs: None,
        }
        .is_configured());
    }
}
