// SPDX-License-Identifier: Apache-2.0
//! The AUDIT INSTANT.
//!
//! One fact: **the moment this audit is taken to have been performed at.**
//!
//! It is not bookkeeping. Every retained message's `created` is compared against it, and
//! every delegated credential's window is judged against it, so it is the value that
//! decides whether an archive reads as evidence or as messages from the future. That is
//! why it is refused rather than defaulted when it cannot be established: at instant zero
//! every hop is `HopAfterAuditInstant`, and the reconstruction would report the archive as
//! broken when the caller's clock is.

/// The audit instant: what `--at` said, or the system clock.
///
/// An instant at or before the Unix epoch is refused rather than used. Every hop's
/// `created` is compared against it, so at zero every message reads as being in the
/// future and the reconstruction reports `HopAfterAuditInstant` — the archive blamed for
/// the caller's clock.
pub(super) fn audit_instant(stated: Option<String>) -> Result<i64, String> {
    let Some(text) = stated else {
        return now_unix();
    };
    let seconds: i64 = text
        .parse()
        .map_err(|_| format!("--at {text:?}: not a Unix timestamp"))?;
    if seconds <= 0 {
        return Err(format!(
            "--at {seconds}: an audit instant at or before the Unix epoch cannot be an \
             instant this archive was observed at",
        ));
    }
    Ok(seconds)
}

/// The system clock as Unix seconds, or a refusal. A clock that will not read is not an
/// audit at instant zero.
fn now_unix() -> Result<i64, String> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "the system clock reads before the Unix epoch".to_owned())?;
    i64::try_from(elapsed.as_secs())
        .map_err(|_| "the system clock does not fit a Unix timestamp".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stated_instant_is_the_instant() {
        assert_eq!(
            audit_instant(Some("1700000100".to_owned())).expect("a legal instant"),
            1_700_000_100,
        );
    }

    #[test]
    fn an_instant_at_or_before_the_epoch_is_refused() {
        for stated in ["0", "-1"] {
            let refused = audit_instant(Some(stated.to_owned())).expect_err("an epoch instant");
            assert!(refused.contains("--at"), "{refused}");
        }
    }

    #[test]
    fn a_value_that_is_not_a_timestamp_is_refused() {
        assert!(audit_instant(Some("later".to_owned())).is_err());
    }

    /// With nothing stated the instant is the system clock, and it is positive — so the
    /// default can never silently be the value the check above refuses.
    #[test]
    fn the_default_is_the_system_clock() {
        assert!(audit_instant(None).expect("a clock reading") > 1_700_000_000);
    }
}
