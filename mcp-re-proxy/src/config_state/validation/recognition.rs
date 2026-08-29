// SPDX-License-Identifier: Apache-2.0
//! PASS 1: what each machine recognises about a request, and what it refuses.
//!
//! One machine per column, each asked only about its own. Nothing here relates two
//! machines to each other — that is the cross-machine pass, and it is asked of the
//! RECOGNISED states rather than of the fields again.
//!
//! **A `None` state is not an absence, it is a refusal already made.** Seven owners can
//! name nothing: `Replay` (`memory` and `file` are input forms, not deployments),
//! `ChannelBinding` (three undeployable binding kinds, one deprecated identity source),
//! `DelegatedSigning` (the §7 epoch has no default, so without it there is no posture to
//! resolve), `TrustRevocation` (three of its four states require a reload cadence),
//! `Admission` (its two enforcing states require an authority and a record locator),
//! `Custody` (every state requires the material it signs with) and `TlsCustody` (its
//! exported state requires the key it exports) — a state cannot be built without the
//! witnesses that make it inhabitable. Each has already pushed its refusal when that
//! happens, so [`MachineStates::into_recognised`]'s arms are unreachable in a build with no
//! bug. They are stated one machine at a time all the same, so an owner that forgets to
//! refuse fails loudly and NAMES itself instead of hiding inside a wildcard over a widening
//! tuple.

use crate::config_state::RecognisedStates;
use crate::deployment_request::DeploymentRequest;

use super::refusable_machines::classify_refusable;
use super::refusable_machines::RefusableStates;
use super::total_machines::classify_total;
use super::total_machines::TotalStates;

pub(super) use super::refusable_machines::Refusals;

/// The report for a machine that recognised no state AND raised no refusal.
///
/// It NAMES the machine. A wildcard over the widening tuple would say only that something
/// was missing, which is the diagnosis these arms exist to avoid.
fn unrecognised(machine: &str) -> Vec<String> {
    vec![format!(
        "internal error: the {machine} configuration machine recognised no state and raised \
         no refusal"
    )]
}

/// What pass 1 produced: the states, and the refusals raised reaching them.
pub(super) struct Recognised {
    pub(super) states: MachineStates,
    pub(super) refusals: Refusals,
}

/// Each machine's recognised state, before the legality boundary has been passed.
///
/// The fallible ones are `Option` because a machine that recognises nothing has refused;
/// the rest are values because their illegal combinations are not representable.
pub(super) struct MachineStates {
    refusable: RefusableStates,
    total: TotalStates,
}

impl MachineStates {
    /// The one state the cross-machine pass relates the others to.
    pub(super) fn trust_revocation(&self) -> Option<&crate::config_state::TrustRevocationState> {
        self.refusable.trust_revocation.as_ref()
    }

    /// Every machine named a state, or one of them did not and says which.
    ///
    /// Reachable only through a bug — each `None` here means an owner recognised no state
    /// AND raised no refusal, which the legality boundary would already have reported.
    pub(super) fn into_recognised(self) -> Result<RecognisedStates, Vec<String>> {
        let r = self.refusable;
        let t = self.total;
        Ok(RecognisedStates {
            admission: r.admission.ok_or_else(|| unrecognised("admission"))?,
            authorization: r
                .authorization
                .ok_or_else(|| unrecognised("authorization"))?,
            audit: t.audit,
            channel_binding: r
                .channel_binding
                .ok_or_else(|| unrecognised("channel-binding"))?,
            client_credential_window: r
                .client_credential_window
                .ok_or_else(|| unrecognised("client-credential-window"))?,
            continuation_control: r.continuation_control,
            crl_revocation: r.crl_revocation,
            custody: r.custody.ok_or_else(|| unrecognised("custody"))?,
            delegated_signing: r
                .delegated_signing
                .ok_or_else(|| unrecognised("delegated-signing"))?,
            freshness: r.freshness.ok_or_else(|| unrecognised("freshness"))?,
            in_flight_limit: t.in_flight_limit,
            key_file_access: t.key_file_access,
            mcp_transport_contract: t.mcp_transport_contract,
            replay: r.replay.ok_or_else(|| unrecognised("replay"))?,
            retention: t.retention,
            server_identity: r
                .server_identity
                .ok_or_else(|| unrecognised("server-identity"))?,
            shard_topology: t.shard_topology,
            channel_credential_custody: r
                .channel_credential_custody
                .ok_or_else(|| unrecognised("tls-custody"))?,
            topology: t.topology,
            trust_document: r
                .trust_document
                .ok_or_else(|| unrecognised("trust-document"))?,
            trust_revocation: r
                .trust_revocation
                .ok_or_else(|| unrecognised("trust-revocation"))?,
            verified_context: t.verified_context,
        })
    }
}

impl Recognised {
    /// Ask every machine about its own columns.
    ///
    /// The two halves are different in KIND, which is why they are two functions rather
    /// than one list: a machine in the first can refuse, and a machine in the second cannot
    /// — its illegal combinations are not representable, so there is nothing for it to say.
    pub(super) fn classify(config: &DeploymentRequest) -> Self {
        let (refusable, refusals) = classify_refusable(config);
        Recognised {
            states: MachineStates {
                refusable,
                total: classify_total(config),
            },
            refusals,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The report names the MACHINE. Every arm in `into_recognised` builds its message
    /// through this, so a machine that forgets to refuse says which one it is rather than
    /// leaving an operator with an unattributed internal error.
    #[test]
    fn the_internal_error_names_the_machine_that_recognised_nothing() {
        let reported = unrecognised("trust-revocation");
        assert_eq!(reported.len(), 1, "one machine is named, not a summary");
        assert!(
            reported[0].contains("trust-revocation"),
            "unexpected report: {reported:?}"
        );
        assert_ne!(
            reported,
            unrecognised("replay"),
            "the name is not a constant"
        );
    }
}
