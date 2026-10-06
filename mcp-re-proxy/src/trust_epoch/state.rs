// SPDX-License-Identifier: Apache-2.0
//! What one trust-epoch read returns: the counter, and the generation of the advance that
//! last set it.
//!
//! The generation is what makes an advance visible after a store rollback returned the
//! counter to a value a node already saw: a fresh advance draws a new generation, so equal
//! counters under a different generation are still a change.

#[cfg(feature = "redis_replay")]
use super::EpochReadError;

/// The trust-epoch counter and the generation of the advance that last set it, read
/// together.
///
/// `pub` because it is the return type of [`EpochReader::read_state`](super::EpochReader);
/// its fields stay crate-private, so nothing outside the crate can construct one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochState {
    pub(crate) counter: i64,
    /// `None` while no [`advance`](super::advance) has ever written the key's generation.
    pub(crate) generation: Option<String>,
}

#[cfg(feature = "redis_replay")]
impl super::RedisEpochReader {
    /// [`EpochReader::read_state`](super::EpochReader::read_state) over Redis: the counter
    /// and its generation in one `MGET`.
    pub(super) fn mget_state(&self) -> Result<EpochState, EpochReadError> {
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| EpochReadError("trust-epoch connection lock poisoned".into()))?;
        if guard.is_none() {
            *guard = Some(Self::fresh_conn(&self.client)?);
        }
        let Some(conn) = guard.as_mut() else {
            return Err(EpochReadError("trust-epoch connection missing".into()));
        };
        let generation_key = super::advance::generation_key(&self.epoch_key);
        let state_command = || {
            let mut cmd = redis::cmd("MGET");
            cmd.arg(&self.epoch_key).arg(&generation_key);
            cmd
        };
        // One reconnect-and-retry: a broken socket is replaced and the read attempted once
        // more; a second failure fails closed, and the socket is dropped so the NEXT read
        // reconnects rather than reusing a known-broken connection.
        let (counter, generation) =
            match state_command().query::<(Option<i64>, Option<String>)>(conn) {
                Ok(state) => state,
                Err(e) if super::is_transient(&e) => {
                    *guard = None;
                    let mut fresh = Self::fresh_conn(&self.client)?;
                    let state = state_command()
                        .query::<(Option<i64>, Option<String>)>(&mut fresh)
                        .map_err(|e| EpochReadError(format!("MGET after reconnect: {e}")))?;
                    *guard = Some(fresh);
                    state
                }
                Err(e) => return Err(EpochReadError(format!("MGET {}: {e}", self.epoch_key))),
            };
        Ok(EpochState {
            counter: Self::require_present(counter, &self.epoch_key)?,
            generation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::EpochState;

    #[test]
    fn equal_counters_under_different_generations_are_different_states() {
        let before = EpochState {
            counter: 10,
            generation: Some("a".into()),
        };
        let after = EpochState {
            counter: 10,
            generation: Some("b".into()),
        };
        assert_ne!(before, after);
        assert_eq!(before, before.clone());
    }
}
