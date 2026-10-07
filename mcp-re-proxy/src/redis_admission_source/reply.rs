// SPDX-License-Identifier: Apache-2.0
//! What one `GET` of an admission key came back as: the outage-versus-answer split for this
//! store, decided in one place.
//!
//! # Why the split is the security decision
//!
//! An outage reaches the §5.2 degraded fork; an answer never does. The degraded window is
//! replica-wide — any answered read for any workload restarts it — so a reply that this
//! adapter misfiled as an outage for ONE workload is not bounded by P while other workloads
//! keep reading. A party that can write the store but holds no signing key chooses what a
//! key holds: it can give a revoked workload's key another Redis type, which the server
//! answers with `WRONGTYPE`, or bytes that are not text. Both are the store ANSWERING about
//! that key, so both are definitive negatives here.
//!
//! An outage is therefore the store not answering at all — the connection failed, dropped
//! or timed out — or the server stating that it cannot answer anything right now (loading a
//! dump, a cluster down or retrying, a master down). Every other error reply, and every
//! value that is not a bulk string or nil, is an answer about the key and classifies as a
//! malformed record. The default for an error kind not named here is the answer side: an
//! unrecognised reply fails closed rather than into the degraded fork.

use redis::ErrorKind;
use redis::RedisError;
use redis::ServerErrorKind;
use redis::Value;

use crate::admission_source::AdmissionSourceError;

/// A reply the store gave about one admission key, before any of it is read as a record.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum StoreReply {
    /// The key holds nothing.
    Absent,
    /// The key holds these bytes.
    Bytes(Vec<u8>),
    /// The store answered with something that cannot hold a record.
    Unreadable,
}

/// Read one `GET` reply. `Err` is an outage — the store did not answer — and nothing else
/// is.
pub(super) fn read_reply(
    reply: redis::RedisResult<Value>,
) -> Result<StoreReply, AdmissionSourceError> {
    match reply {
        Ok(Value::Nil) => Ok(StoreReply::Absent),
        Ok(Value::BulkString(bytes)) => Ok(StoreReply::Bytes(bytes)),
        Ok(Value::ServerError(error)) => answered_error(&RedisError::from(error)),
        Ok(_) => Ok(StoreReply::Unreadable),
        Err(error) => answered_error(&error),
    }
}

/// An error reply is an outage only when the store did not answer, or said it can answer
/// nothing right now; otherwise it is the store's answer about the key.
fn answered_error(error: &RedisError) -> Result<StoreReply, AdmissionSourceError> {
    if is_outage(error) {
        return Err(AdmissionSourceError::Unavailable {
            details: format!("redis GET admission failed: {error}"),
        });
    }
    Ok(StoreReply::Unreadable)
}

/// The store did not answer, or stated it cannot answer any key at present.
fn is_outage(error: &RedisError) -> bool {
    error.is_io_error()
        || error.is_connection_dropped()
        || error.is_timeout()
        || error.is_connection_refusal()
        || matches!(
            error.kind(),
            ErrorKind::Server(
                ServerErrorKind::BusyLoading
                    | ServerErrorKind::TryAgain
                    | ServerErrorKind::ClusterDown
                    | ServerErrorKind::MasterDown
            ) | ErrorKind::ClusterConnectionNotFound
                | ErrorKind::AuthenticationFailed
        )
}

#[cfg(test)]
mod tests {
    use super::read_reply;
    use super::StoreReply;
    use crate::admission_source::AdmissionSourceError;

    /// The reply a RESP server sends, parsed as the client library parses it.
    fn frame(resp: &[u8]) -> redis::RedisResult<redis::Value> {
        redis::parse_redis_value(resp)
    }

    #[test]
    fn a_wrongtype_reply_is_an_answer_about_the_key_and_not_an_outage() {
        let reply =
            frame(b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n");
        assert_eq!(
            read_reply(reply).expect("an answer"),
            StoreReply::Unreadable
        );
        let as_error =
            frame(b"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n")
                .and_then(|value| value.extract_error());
        assert_eq!(
            read_reply(as_error).expect("an answer"),
            StoreReply::Unreadable
        );
    }

    #[test]
    fn a_value_of_another_type_is_unreadable_and_not_an_outage() {
        for resp in [&b":5\r\n"[..], b"*1\r\n$1\r\nx\r\n", b"+OK\r\n"] {
            assert_eq!(
                read_reply(frame(resp)).expect("an answer"),
                StoreReply::Unreadable
            );
        }
    }

    #[test]
    fn nil_is_absent_and_a_bulk_string_is_its_bytes_whatever_they_are() {
        assert_eq!(
            read_reply(frame(b"$-1\r\n")).expect("an answer"),
            StoreReply::Absent
        );
        assert_eq!(
            read_reply(Ok(redis::Value::BulkString(vec![0xff, 0x00]))).expect("an answer"),
            StoreReply::Bytes(vec![0xff, 0x00])
        );
    }

    #[test]
    fn a_dropped_connection_is_the_outage() {
        let dropped = redis::RedisError::from(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "peer reset",
        ));
        let Err(AdmissionSourceError::Unavailable { details }) = read_reply(Err(dropped)) else {
            panic!("a connection that did not answer is an outage");
        };
        assert!(details.contains("redis GET admission failed"), "{details}");
    }

    #[test]
    fn a_server_that_can_answer_nothing_right_now_is_the_outage() {
        let loading = frame(b"-LOADING Redis is loading the dataset in memory\r\n")
            .and_then(|value| value.extract_error());
        assert!(matches!(
            read_reply(loading),
            Err(AdmissionSourceError::Unavailable { .. })
        ));
    }
}
