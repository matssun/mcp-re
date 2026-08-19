// SPDX-License-Identifier: Apache-2.0
//! What this deployment IS, at two different altitudes.
//!
//! `--fleet`, `--cores` and `--workers-per-shard` were the last request fields the
//! composition root read raw, and they were left until last because they are not the same
//! kind of fact. Giving them one owner would have been the mistake:
//!
//! ```text
//!   --fleet ─────────────▶ DeploymentTopology        a SEMANTIC fact, knowable from
//!                          SingleNode | Fleet        the request alone
//!
//!   --cores ─────────┐
//!   --workers-per-   ├────▶ ShardTopologyRequest ──▶ host CPU discovery ──▶ shard count
//!     shard ─────────┘      Auto | Pinned(n)         (RUNTIME evidence, not layer A)
//! ```
//!
//! # Why the shard counts stop here
//!
//! `--cores 0` does not mean "no cores". It means *ask the host*, and the answer is
//! `ceil(cpus / workers_per_shard)` — a number this process cannot know until it runs.
//! Classifying the resolved count as a layer-A fact would state as knowable-from-the-request
//! something that depends on the machine, which is the distinction ADR-MCPRE-056 §5.1
//! exists to keep. So layer A owns the REQUEST — did the operator choose, or defer? — and
//! resolution stays where the host is: [`crate::async_fleet::resolve_core_count`].
//!
//! That is also why `0` is modelled as a variant rather than kept as a sentinel. A `usize`
//! where zero means something else entirely is a value every reader has to remember to
//! interpret, and the composition root was the reader remembering it.
//!
//! # Known: the resolved count is established twice
//!
//! `app.rs` resolves it to size the inner-plane ceiling, and `serve_fleet` resolves it
//! again from `FleetConfig`. Both call the same function with the same request, so they
//! agree today — but nothing makes them agree, and a resolved count is runtime evidence
//! that ought to be established once and carried. Recorded rather than fixed here: that is
//! a change to the serving runtime's shape, not to configuration ownership.

use std::num::NonZeroUsize;

use crate::deployment_request::DeploymentRequest;

/// Whether this deployment is one node or one replica of several.
///
/// A semantic fact about the deployment, not a resource setting: under `Fleet` a request
/// may reach a different verifier than the one that saw it first, which is what makes the
/// cross-replica revocation-lag bounds a statement the operator needs at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeploymentTopology {
    /// One node, the sole verifier.
    #[default]
    SingleNode,
    /// One replica among several, all in one trust domain.
    Fleet,
}

impl DeploymentTopology {
    /// Whether more than one replica may serve the same client.
    pub fn is_fleet(&self) -> bool {
        matches!(self, DeploymentTopology::Fleet)
    }
}

/// The serving-shard shape AS THE OPERATOR STATED IT.
///
/// Both axes are `Auto` unless pinned, and `Auto` is a choice — "let the host decide" — not
/// a missing value. Nothing here is a count of anything: it is what the request said, and
/// the host turns it into shards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShardTopologyRequest {
    shards: Option<NonZeroUsize>,
    workers_per_shard: Option<NonZeroUsize>,
}

impl ShardTopologyRequest {
    /// The pinned shard count, or `None` where the operator deferred to the host.
    pub fn shards(&self) -> Option<NonZeroUsize> {
        self.shards
    }

    /// The pinned per-shard worker depth, or `None` where the operator deferred.
    pub fn workers_per_shard(&self) -> Option<NonZeroUsize> {
        self.workers_per_shard
    }

    /// The shard count in the serving runtime's encoding, where `0` means auto.
    ///
    /// Named, so the sentinel is spelled once here instead of at each call site. The
    /// runtime keeps that encoding because it is what performs the host discovery; this is
    /// the projection into it, not a second representation of the choice.
    pub fn shards_or_auto(&self) -> usize {
        self.shards.map_or(0, NonZeroUsize::get)
    }

    /// The worker depth in the serving runtime's encoding, where `0` means auto.
    pub fn workers_per_shard_or_auto(&self) -> usize {
        self.workers_per_shard.map_or(0, NonZeroUsize::get)
    }
}

/// Resolve both facts. Infallible: every value of each field is a legal deployment, and
/// `0` is a choice rather than a defect.
pub fn classify(config: &DeploymentRequest) -> (DeploymentTopology, ShardTopologyRequest) {
    let topology = if config.fleet {
        DeploymentTopology::Fleet
    } else {
        DeploymentTopology::SingleNode
    };
    let shards = ShardTopologyRequest {
        shards: NonZeroUsize::new(config.cores),
        workers_per_shard: NonZeroUsize::new(config.workers_per_shard),
    };
    (topology, shards)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify_with(
        fleet: bool,
        cores: usize,
        workers: usize,
    ) -> (DeploymentTopology, ShardTopologyRequest) {
        let mut config = crate::config_state::test_support::legal_config();
        config.fleet = fleet;
        config.cores = cores;
        config.workers_per_shard = workers;
        classify(&config)
    }

    /// The default deployment is one node, and it says so as a state rather than as a
    /// `false`.
    #[test]
    fn the_default_deployment_is_a_single_node() {
        let (topology, _) = classify_with(false, 0, 0);
        assert_eq!(topology, DeploymentTopology::SingleNode);
        assert!(!topology.is_fleet());

        let (topology, _) = classify_with(true, 0, 0);
        assert_eq!(topology, DeploymentTopology::Fleet);
        assert!(topology.is_fleet());
    }

    /// `0` is "ask the host", and the request says which of the two the operator meant.
    ///
    /// This is the whole reason the field is not carried as a `usize`: a reader holding
    /// `cores == 0` has to know that zero is not a count, and the composition root was the
    /// reader that had to know it.
    #[test]
    fn zero_is_a_deferral_not_a_count() {
        let (_, request) = classify_with(false, 0, 0);
        assert_eq!(request.shards(), None, "0 shards is a deferral");
        assert_eq!(request.workers_per_shard(), None);

        let (_, request) = classify_with(false, 4, 8);
        assert_eq!(request.shards().map(NonZeroUsize::get), Some(4));
        assert_eq!(request.workers_per_shard().map(NonZeroUsize::get), Some(8));
    }

    /// The runtime projection round-trips the encoding it is named for.
    #[test]
    fn the_runtime_projection_spells_auto_as_zero() {
        let (_, auto) = classify_with(false, 0, 0);
        assert_eq!(auto.shards_or_auto(), 0);
        assert_eq!(auto.workers_per_shard_or_auto(), 0);

        let (_, pinned) = classify_with(false, 4, 8);
        assert_eq!(pinned.shards_or_auto(), 4);
        assert_eq!(pinned.workers_per_shard_or_auto(), 8);
    }

    /// The two facts are independent: a pinned shard count says nothing about whether this
    /// is a fleet, and a fleet says nothing about the shard count.
    ///
    /// They were one raw-read group only because one function read both.
    #[test]
    fn the_topology_and_the_shard_request_do_not_constrain_each_other() {
        for fleet in [false, true] {
            for cores in [0_usize, 1, 4] {
                let (topology, request) = classify_with(fleet, cores, 0);
                assert_eq!(topology.is_fleet(), fleet);
                assert_eq!(
                    request.shards().map(NonZeroUsize::get),
                    (cores != 0).then_some(cores)
                );
            }
        }
    }
}
