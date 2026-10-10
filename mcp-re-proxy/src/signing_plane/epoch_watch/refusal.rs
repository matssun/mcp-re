// SPDX-License-Identifier: Apache-2.0
//! Why the delegated plane has no trust-epoch label to mint under, worded for the operator.

/// Why there is no label to mint under.
#[derive(Debug)]
pub(in crate::signing_plane) enum EpochRefusal {
    /// No read has succeeded in this process, so there is no mark to repair toward.
    Unestablished(String),
    /// The store is unreadable, below this replica's high-water mark, or has lost the
    /// counter. `repair` is the counter after the raise, or why the raise failed.
    Behind {
        observed: Result<i64, String>,
        high_water: i64,
        repair: Result<i64, String>,
    },
    /// A fresh advance — a generation this replica has not seen — set the counter to its
    /// high-water mark, a label it has already minted under. `repair` as for `Behind`.
    Reused {
        high_water: i64,
        repair: Result<i64, String>,
    },
}

impl std::fmt::Display for EpochRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (high_water, repair) = match self {
            EpochRefusal::Unestablished(e) => {
                return write!(f, "the shared trust epoch is unreadable ({e})");
            }
            EpochRefusal::Behind {
                observed: Ok(read),
                high_water,
                repair,
            } => {
                write!(f, "the shared trust epoch REGRESSED to {read}, below this replica's high-water mark {high_water}")?;
                (high_water, repair)
            }
            EpochRefusal::Behind {
                observed: Err(e),
                high_water,
                repair,
            } => {
                write!(
                    f,
                    "the shared trust epoch is unreadable ({e}) at high-water mark {high_water}"
                )?;
                (high_water, repair)
            }
            EpochRefusal::Reused { high_water, repair } => {
                write!(f, "a fresh trust-epoch advance landed on {high_water}, a label this replica already minted under")?;
                (high_water, repair)
            }
        };
        match repair {
            Ok(now) => write!(f, "; moved the store to {now}, past the mark {high_water}, so the advance acts as a forward rotation; minting resumes on the next read under the new label, which verifiers must accept"),
            Err(e) => write!(f, "; repair FAILED ({e}): the proxy's Redis user needs write access (GET, MGET, SET, EVAL) to the epoch key and its generation"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EpochRefusal;

    /// Each refusal names the mark and what became of the repair.
    #[test]
    fn the_refusal_names_the_mark_and_the_repair_outcome() {
        let reused = EpochRefusal::Reused {
            high_water: 9,
            repair: Ok(10),
        }
        .to_string();
        assert!(
            reused.contains("landed on 9") && reused.contains("moved the store to 10"),
            "{reused}"
        );
        let refused = EpochRefusal::Reused {
            high_water: 9,
            repair: Err("NOPERM".into()),
        }
        .to_string();
        assert!(refused.contains("needs write access"), "{refused}");
    }
}
