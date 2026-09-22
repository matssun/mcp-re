// SPDX-License-Identifier: Apache-2.0
//! WHICH groups this process belongs to, as the key-file permission guard asks it.
//!
//! One fact: **the group set is what the kernel reported, and nothing else.**
//!
//! # Why this is its own role
//!
//! It is the PROCESS half of the environmental context this subtree observes, and it is
//! separate from the file half because the two fail differently: a file can be absent or
//! unstat'able, a group set cannot. The answer is an input to a FAIL-CLOSED decision —
//! `KeyFileAccessPolicy::violation`
//! admits a group-readable key file only when the file's group is one this process is
//! actually in, which is what makes the Kubernetes `fsGroup` relaxation safe rather than a
//! blanket permission. A group this process is NOT in, appearing in that set, turns the
//! relaxation into exactly the blanket permission it was written to avoid.
//!
//! # The defect this module exists to remove
//!
//! r12 R12-631. The two-call `getgroups` idiom asks for a count, allocates a buffer of
//! that size, fills it, and — this was the defect — extended the group set with the WHOLE
//! BUFFER, checking only that the second call had not failed. The second call returns the
//! number of entries it actually wrote, and that number can be SMALLER: the supplementary
//! list can shrink between the two calls. The tail of the buffer then still holds its
//! initialiser, `0`, and **gid 0 — root — enters the set of groups this process is in.**
//!
//! Under `--allow-group-readable-key-files` a `0640` key file owned by group root would
//! then be admitted as an fsGroup-shaped mount by a process that is not in group root. No
//! realistic attacker drives the race, which needs a concurrent privileged `setgroups`; it
//! is a fail-OPEN direction in a guard whose entire job is to fail closed, which is reason
//! enough.
//!
//! [`supplementary_prefix`] is the decision, split out as a pure function so it is
//! testable without a kernel: the unsafe call below supplies `filled` and the buffer, and
//! this module's controls supply the cases the kernel is not obliged to avoid.

/// The part of a `getgroups` buffer the kernel actually wrote.
///
/// `filled` is the second call's return value. A NEGATIVE one means the call failed and no
/// posture was established, and the empty prefix is the fail-closed reading: a smaller
/// group set can only make [`crate::config_state::KeyFileAccessPolicy::violation`] refuse
/// MORE files, never fewer.
///
/// A `filled` larger than the buffer cannot happen — the kernel writes at most the size it
/// was given — and is clamped rather than trusted, because the alternative is an
/// out-of-bounds read decided by a number this process did not compute.
//
// PRIVATE, and it stays private: its only non-test caller is `process_gids` below, in this
// same module. A `pub(crate)` here would be a production widening with a test-shaped
// justification, and the tests are a child module that needs none.
#[cfg(unix)]
fn supplementary_prefix(buf: &[u32], filled: i32) -> &[u32] {
    let filled = usize::try_from(filled).unwrap_or(0);
    buf.get(..filled.min(buf.len())).unwrap_or(&[])
}

/// The groups this process belongs to: the effective gid plus its supplementary groups.
///
/// Under Kubernetes `fsGroup` the mounted Secret is owned by a supplementary group, not
/// the effective one, so checking only `getegid()` would refuse the very mount model the
/// relaxation exists for.
#[cfg(unix)]
pub(super) fn process_gids() -> Vec<u32> {
    let mut gids = vec![unsafe { libc::getegid() } as u32];
    // SAFETY: the two-call idiom — ask for the count, then fill a buffer of that size.
    // The RETURN of the second call is authoritative over the buffer's length; see
    // `supplementary_prefix`.
    unsafe {
        let count = libc::getgroups(0, std::ptr::null_mut());
        if count > 0 {
            let mut buf = vec![0 as libc::gid_t; count as usize];
            let filled = libc::getgroups(count, buf.as_mut_ptr());
            gids.extend_from_slice(supplementary_prefix(&buf, filled));
        }
    }
    gids
}

#[cfg(all(test, unix))]
mod tests {
    use super::process_gids;
    use super::supplementary_prefix;

    /// LOAD-BEARING (R12-631): the tail of the buffer is the INITIALISER, not a group.
    ///
    /// This is the defect exactly: a buffer sized for four groups that the kernel filled
    /// with two still reads `[.., 0, 0]`, and taking the whole buffer put gid 0 — root —
    /// into the set of groups this process is in.
    #[test]
    fn the_unwritten_tail_is_not_a_group_this_process_is_in() {
        let buf = [1000_u32, 2000, 0, 0];
        assert_eq!(supplementary_prefix(&buf, 2), &[1000, 2000]);
        assert!(
            !supplementary_prefix(&buf, 2).contains(&0),
            "gid 0 must not enter the group set from an unwritten tail"
        );
    }

    /// A FAILED second call establishes no posture, and the empty prefix is the
    /// fail-closed reading: a smaller group set can only make the policy refuse more.
    #[test]
    fn a_failed_call_yields_no_supplementary_groups() {
        let buf = [1000_u32, 2000];
        assert!(supplementary_prefix(&buf, -1).is_empty());
    }

    /// POSITIVE CONTROL: a fully written buffer is taken whole. Without this the two above
    /// are satisfied by a function that always returns nothing, which would refuse every
    /// fsGroup mount the relaxation exists to admit.
    #[test]
    fn a_fully_written_buffer_is_taken_whole() {
        let buf = [1000_u32, 2000];
        assert_eq!(supplementary_prefix(&buf, 2), &buf[..]);
        assert_eq!(supplementary_prefix(&[], 0), &[] as &[u32]);
    }

    /// A count larger than the buffer is CLAMPED rather than trusted. The kernel cannot
    /// return one, and the alternative is an out-of-bounds read decided by a number this
    /// process did not compute.
    #[test]
    fn a_count_past_the_buffer_is_clamped_not_trusted() {
        let buf = [1000_u32, 2000];
        assert_eq!(supplementary_prefix(&buf, 99), &buf[..]);
    }

    /// The effective gid is always present: it is the group the non-relaxed path compares
    /// against, and a process is always in it.
    #[test]
    fn the_effective_gid_is_always_in_the_set() {
        let egid = unsafe { libc::getegid() } as u32;
        assert!(process_gids().contains(&egid));
    }
}
