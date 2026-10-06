// SPDX-License-Identifier: Apache-2.0
//! The server-side scripts the shared continuation tier runs, and the live set they keep.
//!
//! Each script is one atomic step on the Redis server, which is what lets the capacity
//! test and the write, and the removal and the slot's return, be one operation across
//! replicas.
//!
//! The live set's count is DERIVED, never kept: it is the members whose expiry is still in
//! the future, by the server's own clock (`TIME`), which also set the entry's `PX`. An
//! expired or crashed-away entry therefore frees its slot at the next create, and there is
//! no counter to drift. `TIME` before a write requires effects replication, the default
//! from Redis 5.

/// The live set: every recorded key, scored by its expiry in server milliseconds. Inside
/// the continuation keyspace and never a continuation key, whose suffix is a 43-character
/// digest.
pub(super) const LIVE_SET_KEY: &str = "mcp-re:cont:live";

/// `KEYS[1]` the entry, `KEYS[2]` the live set; `ARGV` the value, the TTL in ms, the
/// capacity. `1` stored, `0` a live key is taken, `-1` the live set is full.
pub(super) const CREATE: &str = "local t = redis.call('TIME') \
local now = t[1] * 1000 + math.floor(t[2] / 1000) \
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now) \
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end \
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[3]) then return -1 end \
redis.call('SET', KEYS[1], ARGV[1], 'NX', 'PX', ARGV[2]) \
redis.call('ZADD', KEYS[2], now + tonumber(ARGV[2]), KEYS[1]) \
return 1";

/// `KEYS[1]` the entry, `KEYS[2]` the live set. The `DEL` count is the verdict.
pub(super) const CONSUME: &str = "local n = redis.call('DEL', KEYS[1]) \
redis.call('ZREM', KEYS[2], KEYS[1]) \
return n";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::continuation_store::ContinuationKey;
    use crate::continuation_store::CONTINUATION_KEY_PREFIX;

    /// The live set shares the continuation keyspace but can never be a continuation key:
    /// those carry a 43-character digest after the prefix.
    #[test]
    fn the_live_set_is_in_the_keyspace_and_is_no_entrys_key() {
        let suffix = LIVE_SET_KEY
            .strip_prefix(CONTINUATION_KEY_PREFIX)
            .expect("prefixed");
        let entry = ContinuationKey::of_parts("aud", "actor", b"s");
        let entry_suffix = entry
            .as_str()
            .strip_prefix(CONTINUATION_KEY_PREFIX)
            .expect("p");
        assert_eq!(entry_suffix.len(), 43);
        assert_ne!(suffix.len(), entry_suffix.len());
    }

    /// The create script prunes before it counts, counts before it writes, and writes the
    /// expiry in the same `SET` that guards the key.
    #[test]
    fn the_create_script_prunes_then_counts_then_writes_with_nx_and_px() {
        let at = |needle: &str| CREATE.find(needle).unwrap_or_else(|| panic!("{needle}"));
        assert!(at("ZREMRANGEBYSCORE") < at("ZCARD"));
        assert!(at("ZCARD") < at("'SET'"));
        assert!(CREATE.contains("'NX', 'PX'"));
        assert!(at("redis.call('TIME')") < at("ZREMRANGEBYSCORE"));
        assert!(CONSUME.contains("'DEL'") && CONSUME.contains("'ZREM'"));
    }
}
