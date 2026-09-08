// SPDX-License-Identifier: Apache-2.0
//! A flag given EXACTLY ONCE.
//!
//! One fact: **whether a single-valued argument was supplied, and supplied once.**
//!
//! [`Filled`] is the other half of the same job: which of the two shapes a flag has. It is
//! here rather than in the parser because the parser's loop should read as *resolve the
//! flag, then take its value*, and the shapes it resolves to are this module's.
//!
//! [`Slot`] is its own type rather than an `Option<String>` per flag because the rule it
//! enforces is
//! not "the last one wins". An operator who passed `--out` twice did not express a
//! preference between them, and resolving that silently is how a run writes its artifact
//! somewhere nobody meant. The refusal names the flag, so the message is about the command
//! line rather than about a missing value discovered much later.

/// One required, single-valued string flag while it is being collected.
pub(super) struct Slot {
    flag: &'static str,
    pub(super) value: Option<String>,
}

impl Slot {
    pub(super) fn new(flag: &'static str) -> Self {
        Slot { flag, value: None }
    }

    pub(super) fn set(&mut self, value: String) -> Result<(), String> {
        if self.value.is_some() {
            return Err(format!(
                "{}: given more than once; an auditor does not choose between two",
                self.flag,
            ));
        }
        self.value = Some(value);
        Ok(())
    }

    pub(super) fn required(self) -> Result<String, String> {
        self.value
            .ok_or_else(|| format!("{} is required", self.flag))
    }
}

/// WHAT the flag just read fills: the one repeatable list, or one single-valued slot.
///
/// Resolved BEFORE the flag's value is taken, so an unknown argument is reported as one
/// rather than as a value that is missing.
pub(super) enum Filled<'a> {
    /// `--hop`, the only flag an invocation may give more than once.
    Hop,
    /// A slot that refuses a second value.
    Once(&'a mut Slot),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_given_once_is_the_value() {
        let mut slot = Slot::new("--out");
        slot.set("/a".to_owned()).expect("first");
        assert_eq!(slot.required().expect("present"), "/a");
    }

    #[test]
    fn a_value_given_twice_is_refused_rather_than_resolved() {
        let mut slot = Slot::new("--out");
        slot.set("/a".to_owned()).expect("first");
        let refused = slot.set("/b".to_owned()).expect_err("second");
        assert!(refused.contains("--out"), "{refused}");
    }

    #[test]
    fn a_value_never_given_is_refused_by_name() {
        let refused = Slot::new("--out").required().expect_err("absent");
        assert!(refused.contains("--out"), "{refused}");
    }
}
