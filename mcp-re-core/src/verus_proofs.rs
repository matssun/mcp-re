//! Proof-mode lemmas supporting the ADR-MCPRE-059 Phase 2 specifications.
//!
//! Compiled only under `--features verify`; no production build contains this module.
//!
//! Unlike [`crate::verus_std_specs`], nothing here is assumed — every lemma is checked,
//! so this module adds nothing to the Trusted Computing Base.

use crate::time::DAYS_IN_MONTH;
use verus_builtin_macros::verus;
use vstd::prelude::*;

verus! {

/// No month is longer than 31 days.
///
/// Needed because the verifier sees the month-length table as a constant it must
/// evaluate: without this the caller cannot establish `day <= 31`, which is what
/// `days_from_civil` requires to stay inside `i64`.
pub(crate) proof fn lemma_days_in_month_bounded(i: int)
    requires
        0 <= i < 12,
    ensures
        DAYS_IN_MONTH@[i] <= 31,
{
    assert(DAYS_IN_MONTH@ =~= seq![31u8, 28u8, 31u8, 30u8, 31u8, 30u8, 31u8, 31u8, 30u8, 31u8, 30u8, 31u8]);
}

}
