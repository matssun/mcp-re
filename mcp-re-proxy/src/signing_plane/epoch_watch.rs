// SPDX-License-Identifier: Apache-2.0
//! The shared trust-epoch counter, watched by the delegated-rotation owner so an
//! operator's `mcp-re-proxy trust-epoch advance` invalidates the outstanding epoch of
//! delegated response keys across the fleet (ADR-MCPRE-052 §7). The RESPONSE-side counterpart to
//! the trust plane's epoch channel, which flushes the REQUEST-trust cache on the same
//! advance. A read error leaves the epoch unchanged (never advance on a transient blip).
//!
//! What an advance does and does not do: it stops this fleet MINTING under the prior
//! epoch. It does not reach credentials already issued under it — no verifier reads the
//! counter, so `accepted_epochs` is static verifier configuration and a leaked
//! credential stays verifiable until the verifiers are pointed at the new epoch
//! (docs/spec/delegated-required-validation-matrix.md §C.1, "Operational consequence").
//! Advancing the counter is the operator's revocation action, so whoever may write the
//! key holds that authority: an advance makes every replica mint a label the currently
//! configured verifiers reject until they are re-pointed.
//!
//! The emitted label is ALWAYS `<base>#<counter>` — never the bare base label. The label
//! is derived purely from shared state, so every replica at counter `N` mints `<base>#N`
//! regardless of when it started, and an operator's advance survives a replica restart.
//!
//! `high_water` makes the emitted epoch monotone WITHIN a process: a read that goes
//! backwards (store reset, failover to a stale replica, a reconnect landing on the wrong
//! instance) or a counter that has vanished is refused rather than rebased, so reconnection
//! can never re-mint under an epoch a verifier has already stopped accepting. The refusal
//! also REPAIRS, as a forward rotation: the replica moves the shared counter to one past
//! its high-water mark ([`EpochRaiser::raise_past`]) and mints again once a read is at or
//! above the mark — which the repaired counter is, under a label it never minted before.
//! The write is atomic in the store and happens only while the counter is absent or below
//! the mark: a second replica repairing from the same mark finds the first one's write and
//! writes nothing, and an advance above the mark is never overwritten.
//!
//! A number alone cannot say whether an advance happened: after a rollback the counter can
//! return to a value this replica already minted under, by a peer's repair from a lower mark
//! or by an advance on the regressed store. So the watch also tracks the GENERATION each
//! operator advance writes beside the counter (`trust_epoch::advance`). A generation it has
//! not seen, on a counter at its mark, is a fresh advance landing on an acknowledged label:
//! the replica refuses and moves the counter past the mark exactly as for a regression, and
//! records the generation only once the counter is past it. An unchanged generation on an
//! unchanged counter is no advance. Every advance therefore ends strictly beyond the mark of
//! every replica that reads it.
//!
//! Across a restart the high-water mark is gone: the shared counter is the only authority.
//! A replica that starts while the store is regressed mints under the regressed label
//! until a live peer's repair raises the counter, at most one watch interval later, and
//! then advances like any other replica. Minting a FRESH key under an older label extends
//! no credential that was already issued, and the verifiers' accepted epochs decide
//! whether it is accepted, so the window costs availability, not authority. A fleet that
//! restarts entirely while the store is regressed has no mark left to repair toward.

mod refusal;

use crate::trust_epoch::raise::EpochRaiser;
use crate::trust_epoch::EpochState;
use mcp_re_http_profile::custody::TrustEpoch;
pub(in crate::signing_plane) use refusal::EpochRefusal;

/// What this replica has acknowledged: the highest counter it read, and the generation of
/// the advance it last accounted for.
struct Seen {
    high_water: i64,
    generation: Option<String>,
}

/// The delegated plane's view of the shared trust-epoch counter.
pub(super) struct DelegatedEpochWatch {
    reader: Box<dyn EpochRaiser>,
    base: TrustEpoch,
    seen: std::sync::Mutex<Option<Seen>>,
}

impl DelegatedEpochWatch {
    #[cfg(any(test, feature = "redis_replay"))]
    pub(super) fn new(reader: Box<dyn EpochRaiser>, base: TrustEpoch) -> Self {
        DelegatedEpochWatch {
            reader,
            base,
            seen: std::sync::Mutex::new(None),
        }
    }

    /// The label to mint under, or `None` when the shared epoch cannot be established.
    ///
    /// `None` is FAIL CLOSED FOR MINTING: the caller must not issue a credential,
    /// because it cannot produce an epoch verifiers can compare. It does not retire the
    /// current key — the fleet keeps signing off it until its `exp` and the hot path
    /// then fails closed on its own (ADR-MCPRE-052 §6). Crucially it is also not treated
    /// as "no change": a blip must never be read as an advance, nor as permission to
    /// mint under a stale label.
    #[cfg(test)]
    pub(super) fn current_label(&self) -> Option<String> {
        self.label().ok()
    }

    /// [`current_label`](Self::current_label), with the reason when there is none.
    #[cfg(test)]
    pub(super) fn label(&self) -> Result<String, EpochRefusal> {
        self.epoch().map(|epoch| epoch.label())
    }

    /// The epoch to mint under: the base at the shared counter, read once.
    pub(super) fn epoch(&self) -> Result<TrustEpoch, EpochRefusal> {
        self.counter().map(|counter| self.base.at(counter))
    }

    /// The shared counter the label extends the base with, read once.
    pub(super) fn counter(&self) -> Result<i64, EpochRefusal> {
        let read = self.reader.read_state();
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| EpochRefusal::Unestablished("high-water lock poisoned".into()))?;
        let Some(prior) = seen.as_mut() else {
            let state = read.map_err(|e| EpochRefusal::Unestablished(e.0))?;
            *seen = Some(Seen {
                high_water: state.counter,
                generation: state.generation,
            });
            return Ok(state.counter);
        };
        match read {
            Err(e) => Err(self.behind(Err(e.0), prior.high_water)),
            Ok(EpochState { counter, .. }) if counter < prior.high_water => {
                Err(self.behind(Ok(counter), prior.high_water))
            }
            Ok(EpochState {
                counter,
                generation,
            }) if counter == prior.high_water && generation != prior.generation => {
                Err(self.reused(prior, generation))
            }
            Ok(EpochState {
                counter,
                generation,
            }) => {
                *prior = Seen {
                    high_water: counter,
                    generation,
                };
                Ok(counter)
            }
        }
    }

    /// Refuse, and move the store past `high_water`. The mark itself is untouched: it moves
    /// only when a read at or above it succeeds.
    fn behind(&self, observed: Result<i64, String>, high_water: i64) -> EpochRefusal {
        EpochRefusal::Behind {
            observed,
            high_water,
            repair: self.raise_past(high_water, high_water),
        }
    }

    /// A fresh advance landed on the mark: refuse, move the store past the mark, and account
    /// for the generation only once the store is past it, so a failed repair is refused
    /// again on the next read rather than minting under the reused label.
    fn reused(&self, prior: &mut Seen, generation: Option<String>) -> EpochRefusal {
        let repair = self.raise_past(prior.high_water, prior.high_water.saturating_add(1));
        if repair.as_ref().is_ok_and(|now| *now > prior.high_water) {
            prior.generation = generation;
        }
        EpochRefusal::Reused {
            high_water: prior.high_water,
            repair,
        }
    }

    /// Move the counter to one past `high_water` while it is below `below`: below the mark
    /// for a regression, at or below it for a reused label. At the counter's maximum there
    /// is no label past the mark, and nothing is written.
    fn raise_past(&self, high_water: i64, below: i64) -> Result<i64, String> {
        match high_water.checked_add(1) {
            Some(past) => self.reader.raise_past(below, past).map_err(|e| e.0),
            None => Err(format!(
                "the counter is at its maximum {high_water}; no label lies past it"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DelegatedEpochWatch;
    use super::EpochRefusal;
    use crate::trust_epoch::raise::EpochRaiser;
    use crate::trust_epoch::EpochReadError;
    use crate::trust_epoch::EpochReader;
    use crate::trust_epoch::EpochState;
    use std::sync::Arc;
    use std::sync::Mutex;

    /// The shared key and its generation, modelled as the scripts treat them: `None` is an
    /// absent key, and a store that refuses writes answers a raise the way an ACL without
    /// `SET` does.
    struct Store {
        value: Mutex<Option<i64>>,
        generation: Mutex<Option<String>>,
        writable: bool,
    }

    impl Store {
        fn new(value: Option<i64>, writable: bool) -> Arc<Self> {
            Arc::new(Store {
                value: Mutex::new(value),
                generation: Mutex::new(None),
                writable,
            })
        }
        fn set(&self, value: Option<i64>) {
            *self.value.lock().expect("store") = value;
        }
        fn get(&self) -> Option<i64> {
            *self.value.lock().expect("store")
        }
        /// What a rollback restores: the counter AND the generation beside it.
        fn restore(&self, value: Option<i64>, generation: Option<&str>) {
            self.set(value);
            *self.generation.lock().expect("store") = generation.map(str::to_string);
        }
        /// The operator's advance: the counter plus one, under a generation never used before.
        fn advance(&self, generation: &str) {
            let next = self.get().map_or(1, |c| c + 1);
            self.restore(Some(next), Some(generation));
        }
    }

    struct Replica(Arc<Store>);

    impl EpochReader for Replica {
        fn read_epoch(&self) -> Result<i64, EpochReadError> {
            self.0
                .get()
                .ok_or_else(|| EpochReadError("key absent".into()))
        }

        fn read_state(&self) -> Result<EpochState, EpochReadError> {
            Ok(EpochState {
                counter: self.read_epoch()?,
                generation: self.0.generation.lock().expect("store").clone(),
            })
        }
    }

    impl EpochRaiser for Replica {
        fn raise_past(&self, mark: i64, to: i64) -> Result<i64, EpochReadError> {
            if !self.0.writable {
                return Err(EpochReadError(
                    "NOPERM this user has no permissions to run the 'eval' command".into(),
                ));
            }
            let mut value = self.0.value.lock().expect("store");
            let now = match *value {
                Some(c) if c >= mark => c,
                _ => to,
            };
            *value = Some(now);
            Ok(now)
        }
    }

    fn watch(store: &Arc<Store>) -> DelegatedEpochWatch {
        DelegatedEpochWatch::new(
            Box::new(Replica(Arc::clone(store))),
            "epoch-min".parse().expect("base"),
        )
    }

    /// The repair: a rolled-back counter is refused on the read that sees it, the store is
    /// moved one past the replica's mark, and the next read mints under that new label.
    #[test]
    fn a_regression_moves_the_store_past_the_high_water_mark_and_minting_resumes() {
        let store = Store::new(Some(9), true);
        let w = watch(&store);
        assert_eq!(w.current_label().as_deref(), Some("epoch-min#9"));

        store.set(Some(2));
        assert!(
            matches!(
                w.label(),
                Err(EpochRefusal::Behind {
                    observed: Ok(2),
                    high_water: 9,
                    repair: Ok(10)
                })
            ),
            "the read that sees the regression mints nothing and moves the store past the mark"
        );
        assert_eq!(store.get(), Some(10));
        assert_eq!(w.current_label().as_deref(), Some("epoch-min#10"));
    }

    /// The repair never writes the mark itself, so the pre-rollback label is not re-entered.
    #[test]
    fn a_repair_never_writes_the_mark() {
        for rolled_back_to in [None, Some(0), Some(5), Some(8)] {
            let store = Store::new(Some(9), true);
            let w = watch(&store);
            assert!(w.current_label().is_some());
            store.set(rolled_back_to);
            assert!(w.current_label().is_none());
            assert_eq!(store.get(), Some(10), "rolled back to {rolled_back_to:?}");
            assert_ne!(w.current_label().as_deref(), Some("epoch-min#9"));
        }
    }

    /// An operator's INCR on the rolled-back store, below the mark, does not pull the fleet
    /// back to the pre-rollback label: the repair still ends past the mark.
    #[test]
    fn a_rollback_followed_by_an_operator_incr_below_the_mark_still_ends_past_it() {
        let store = Store::new(Some(9), true);
        let w = watch(&store);
        assert!(w.current_label().is_some());
        store.set(Some(2));
        store.set(Some(3)); // the operator's INCR, against the regressed store
        assert!(w.current_label().is_none());
        assert_eq!(store.get(), Some(10));
        assert_eq!(w.current_label().as_deref(), Some("epoch-min#10"));
    }

    /// A counter lost from the store is repaired the same way once the replica holds a mark.
    #[test]
    fn a_lost_counter_is_recreated_past_the_high_water_mark() {
        let store = Store::new(Some(4), true);
        let w = watch(&store);
        assert!(w.current_label().is_some());
        store.set(None);
        assert!(w.current_label().is_none());
        assert_eq!(store.get(), Some(5));
        assert_eq!(w.current_label().as_deref(), Some("epoch-min#5"));
    }

    /// With no successful read there is no mark, and nothing is written: an absent or
    /// misnamed key at startup stays a refusal, never a counter this replica invents.
    #[test]
    fn a_replica_with_no_mark_writes_nothing() {
        let store = Store::new(None, true);
        let w = watch(&store);
        assert!(matches!(w.label(), Err(EpochRefusal::Unestablished(_))));
        assert_eq!(store.get(), None);
    }

    /// At the counter's maximum there is no label past the mark: the refusal stands and the
    /// store is not written.
    #[test]
    fn a_mark_at_the_counter_maximum_is_refused_without_a_write() {
        let store = Store::new(Some(i64::MAX), true);
        let w = watch(&store);
        assert!(w.current_label().is_some());
        store.set(Some(2));
        assert!(matches!(
            w.label(),
            Err(EpochRefusal::Behind { repair: Err(_), .. })
        ));
        assert_eq!(store.get(), Some(2));
    }

    /// A store the proxy may not write keeps the replica failing closed, read after read,
    /// and the mark does not move down to meet it.
    #[test]
    fn a_store_that_refuses_the_raise_keeps_minting_refused() {
        let store = Store::new(Some(9), false);
        let w = watch(&store);
        assert!(w.current_label().is_some());
        store.set(Some(2));
        for _ in 0..3 {
            assert!(matches!(
                w.label(),
                Err(EpochRefusal::Behind {
                    repair: Err(_),
                    high_water: 9,
                    ..
                })
            ));
        }
        store.set(Some(8));
        assert!(w.current_label().is_none(), "the mark is still 9");
        store.set(Some(9));
        assert_eq!(w.current_label().as_deref(), Some("epoch-min#9"));
    }

    /// Two replicas repairing from the same mark: the first moves the store past it, the
    /// second finds that write, writes nothing, and both mint under the new label.
    #[test]
    fn repairs_from_the_same_mark_write_once() {
        let store = Store::new(Some(9), true);
        let first = watch(&store);
        let second = watch(&store);
        assert!(first.current_label().is_some() && second.current_label().is_some());

        store.set(Some(3));
        assert!(first.current_label().is_none());
        assert_eq!(store.get(), Some(10));
        assert_eq!(second.current_label().as_deref(), Some("epoch-min#10"));
        assert_eq!(store.get(), Some(10));
        assert_eq!(first.current_label().as_deref(), Some("epoch-min#10"));
    }

    /// Marks that differ: an advance on the rolled-back store, repaired from the lower mark
    /// onto the higher replica's label, still ends past the higher mark, because the advance's
    /// generation tells that replica a fresh advance landed on a label it already minted under.
    #[test]
    fn an_advance_repaired_onto_a_higher_replicas_label_still_ends_past_it() {
        let store = Store::new(Some(9), true);
        store.restore(Some(9), Some("g1"));
        let lagging = watch(&store);
        assert!(lagging.current_label().is_some());
        store.advance("g2");
        let current = watch(&store);
        assert_eq!(current.current_label().as_deref(), Some("epoch-min#10"));

        store.restore(Some(3), Some("g0")); // the rollback
        store.advance("g3"); // the operator's advance, against the regressed store
        assert!(lagging.current_label().is_none());
        assert_eq!(
            store.get(),
            Some(10),
            "the lower mark repairs onto the higher label"
        );
        assert!(matches!(
            current.label(),
            Err(EpochRefusal::Reused {
                high_water: 10,
                repair: Ok(11)
            })
        ));
        assert_eq!(current.current_label().as_deref(), Some("epoch-min#11"));
        assert_eq!(lagging.current_label().as_deref(), Some("epoch-min#11"));
    }

    /// An advance that brings the rolled-back key back to exactly the mark is not mistaken for
    /// no change: its fresh generation moves every replica past the mark.
    #[test]
    fn an_advance_back_to_the_mark_ends_past_it() {
        let store = Store::new(Some(10), true);
        store.restore(Some(10), Some("g1"));
        let first = watch(&store);
        let second = watch(&store);
        assert!(first.current_label().is_some() && second.current_label().is_some());

        store.restore(Some(9), Some("g0"));
        store.advance("g2");
        assert_eq!(store.get(), Some(10));
        assert!(first.current_label().is_none());
        assert_eq!(store.get(), Some(11));
        assert_eq!(second.current_label().as_deref(), Some("epoch-min#11"));
        assert_eq!(first.current_label().as_deref(), Some("epoch-min#11"));
        assert_eq!(
            store.get(),
            Some(11),
            "the second replica found the repair and wrote nothing"
        );
    }

    /// The same counter under the same generation is no advance: the replica keeps minting
    /// its label and writes nothing.
    #[test]
    fn an_unchanged_counter_and_generation_is_not_an_advance() {
        let store = Store::new(Some(10), true);
        store.restore(Some(10), Some("g1"));
        let w = watch(&store);
        for _ in 0..3 {
            assert_eq!(w.current_label().as_deref(), Some("epoch-min#10"));
        }
        assert_eq!(store.get(), Some(10));
    }

    /// A fresh advance on the mark that the replica cannot repair stays refused read after
    /// read: the generation is not accounted for until the store is past the mark.
    #[test]
    fn an_unrepaired_advance_on_the_mark_stays_refused() {
        let store = Store::new(Some(10), false);
        store.restore(Some(10), Some("g1"));
        let w = watch(&store);
        assert!(w.current_label().is_some());
        store.restore(Some(10), Some("g2"));
        for _ in 0..3 {
            assert!(matches!(
                w.label(),
                Err(EpochRefusal::Reused { repair: Err(_), .. })
            ));
        }
        store.restore(Some(11), Some("g2"));
        assert_eq!(w.current_label().as_deref(), Some("epoch-min#11"));
    }

    /// An operator's advance above the mark is never undone by a repair.
    #[test]
    fn a_repair_never_lowers_an_advanced_counter() {
        let store = Store::new(Some(5), true);
        let w = watch(&store);
        assert!(w.current_label().is_some());
        store.set(Some(1));
        store.set(Some(6)); // the operator's INCR lands above the mark before the next read
        assert_eq!(w.current_label().as_deref(), Some("epoch-min#6"));
        assert_eq!(store.get(), Some(6));
    }

    /// The refusal names what the operator must do.
    #[test]
    fn the_refusal_line_names_the_mark_and_the_missing_write_access() {
        let store = Store::new(Some(9), false);
        let w = watch(&store);
        assert!(w.current_label().is_some());
        store.set(Some(2));
        let line = w.label().expect_err("refused").to_string();
        assert!(
            line.contains("REGRESSED to 2") && line.contains("high-water mark 9"),
            "{line}"
        );
        assert!(line.contains("needs write access"), "{line}");
    }
}

/// The repair against a live Redis, through the watch the rotation loop polls.
#[cfg(test)]
#[cfg(feature = "redis_replay")]
mod live {
    use super::DelegatedEpochWatch;
    use crate::trust_epoch::raise::live::admin;
    use crate::trust_epoch::raise::live::redis_url;
    use crate::trust_epoch::raise::live::set;
    use crate::trust_epoch::raise::live::unique_key;
    use crate::trust_epoch::RedisEpochReader;

    fn replica(url: &str, key: &str) -> DelegatedEpochWatch {
        let reader = RedisEpochReader::connect_lazy(url, key).expect("reader");
        DelegatedEpochWatch::new(Box::new(reader), "epoch-live".parse().expect("base"))
    }

    /// A rollback by `SET` is refused, repaired past the mark by the replica that holds it,
    /// and minting resumes under the new label for it and for a peer that never saw the mark.
    #[test]
    fn a_rollback_is_refused_repaired_past_the_mark_and_minting_resumes() {
        let Some(url) = redis_url() else {
            eprintln!("SKIP epoch watch live: MCP_RE_TEST_REDIS_URL unset");
            return;
        };
        let key = unique_key("watch");
        let mut operator = admin(&url);
        set(&mut operator, &key, "5");
        let long_lived = replica(&url, &key);
        assert_eq!(long_lived.current_label().as_deref(), Some("epoch-live#5"));

        set(&mut operator, &key, "1");
        let restarted = replica(&url, &key);
        assert!(
            long_lived.current_label().is_none(),
            "the regressed read mints nothing"
        );
        assert_eq!(long_lived.current_label().as_deref(), Some("epoch-live#6"));
        assert_eq!(restarted.current_label().as_deref(), Some("epoch-live#6"));
    }

    /// An operator advance that brings the rolled-back key back to exactly a replica's mark
    /// is told apart by its generation, and moves that replica past the mark.
    #[test]
    fn an_advance_back_to_the_mark_is_moved_past_it() {
        let Some(url) = redis_url() else {
            eprintln!("SKIP epoch watch live: MCP_RE_TEST_REDIS_URL unset");
            return;
        };
        let key = unique_key("advance-to-mark");
        let mut operator = admin(&url);
        set(&mut operator, &key, "9");
        assert_eq!(crate::trust_epoch::advance::advance(&url, &key), Ok(10));
        let long_lived = replica(&url, &key);
        assert_eq!(long_lived.current_label().as_deref(), Some("epoch-live#10"));

        // The rollback restores the counter and the generation beside it.
        set(&mut operator, &key, "9");
        redis::cmd("DEL")
            .arg(crate::trust_epoch::advance::generation_key(&key))
            .query::<()>(&mut operator)
            .expect("DEL");
        assert_eq!(crate::trust_epoch::advance::advance(&url, &key), Ok(10));
        assert!(
            long_lived.current_label().is_none(),
            "the reused label is refused"
        );
        assert_eq!(long_lived.current_label().as_deref(), Some("epoch-live#11"));
    }
}
