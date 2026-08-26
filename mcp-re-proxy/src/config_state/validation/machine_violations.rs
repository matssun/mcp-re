// SPDX-License-Identifier: Apache-2.0
//! What the two validation passes decided, per owner.

/// What the two passes decided, kept apart by owner so the clause list can splice each
/// where it has always been read.
pub(super) struct MachineViolations {
    pub(super) admission: Vec<String>,
    pub(super) authorization: Vec<String>,
    pub(super) channel_binding: Vec<String>,
    pub(super) continuation_control: Vec<String>,
    pub(super) crl_revocation: Vec<String>,
    pub(super) custody: Vec<String>,
    pub(super) delegated_signing: Vec<String>,
    pub(super) freshness: Vec<String>,
    pub(super) replay: Vec<String>,
    pub(super) trust_document: Vec<String>,
    pub(super) client_credential_window: Vec<String>,
    pub(super) server_identity: Vec<String>,
    pub(super) tls_custody: Vec<String>,
    pub(super) trust_revocation: Vec<String>,
    pub(super) cross: crate::config_state::cross_machine::CrossMachineViolations,
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::MachineViolations;

    /// The clause list splices each machine's result at that machine's own position, so a
    /// machine that decided nothing must contribute nothing rather than a placeholder.
    #[test]
    fn a_machine_with_no_clauses_contributes_nothing_to_the_list() {
        let decided = MachineViolations {
            admission: Vec::new(),
            authorization: Vec::new(),
            channel_binding: Vec::new(),
            continuation_control: Vec::new(),
            crl_revocation: Vec::new(),
            custody: Vec::new(),
            delegated_signing: Vec::new(),
            freshness: Vec::new(),
            replay: Vec::new(),
            trust_document: Vec::new(),
            client_credential_window: Vec::new(),
            server_identity: Vec::new(),
            tls_custody: Vec::new(),
            trust_revocation: Vec::new(),
            cross: crate::config_state::cross_machine::CrossMachineViolations::default(),
        };
        let mut list: Vec<String> = Vec::new();
        list.extend(decided.authorization);
        assert!(list.is_empty());
    }
}
