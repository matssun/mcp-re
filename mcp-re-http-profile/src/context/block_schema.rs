// SPDX-License-Identifier: Apache-2.0
//! WHICH verified-context representation a block is written in, as a fact a reader
//! decides rather than infers.
//!
//! One fact: **the block declares its own shape, and exactly one shape is current.**
//!
//! # Why the discriminator exists
//!
//! Without it, "this member is absent because the writer predates it" and "this member is
//! absent because someone removed it" are the same bytes. A reader that tolerates the
//! first tolerates the second, and the tolerance can never be withdrawn — there is nothing
//! it could be withdrawn ON. That was r12 RA1-003: `audience` and `request_expires` were
//! `Option` + `serde(default)` for a compatibility window with no way to close it, on a
//! block whose only integrity is the channel's isolation.
//!
//! # One representation, and no second reader
//!
//! Owner Ruling 8, and CLAUDE.md's general form: MCP-RE does not keep a compatibility
//! layer merely because an earlier internal representation existed. There is no
//! absence-as-v1, no legacy parser, no migration flag and no fallback. The writer always
//! emits the discriminator; a block without one is malformed and a block naming another
//! schema is refused. When the representation changes, the constant changes and the tree
//! migrates atomically — which is a thing a reader can decide, and is the whole point.
//!
//! [`BlockSchema`] is how that becomes structural instead of remembered: it is the only
//! inhabitant of its own type and it deserializes from exactly one string, so a claim
//! holding one has already had the discriminator checked. There is no branch to forget and
//! no second reader to keep in step.

use serde::de::Error as _;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

/// The one current verified-context block representation.
///
/// FROZEN WIRE VOCABULARY, not a type name ([[published-vocabulary-is-not-a-type-name]]):
/// it is namespaced like the block key it accompanies so that a reader seeing it in a
/// `_meta` dump knows whose it is without a registry lookup.
pub(crate) const VERIFIED_CONTEXT_BLOCK_SCHEMA: &str = "se.syncom/mcp-re.verified-context/1";

/// The declared shape of a verified-context block, and evidence that it is the current
/// one.
///
/// A zero-sized type with one inhabitant, deliberately. Holding one means the block
/// carried [`VERIFIED_CONTEXT_BLOCK_SCHEMA`] — not that it carried *a* discriminator, and
/// not that a reader looked at it somewhere. Both refusals live in `Deserialize`, which is
/// the only way one comes into existence from bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct BlockSchema;

impl Serialize for BlockSchema {
    /// The writer cannot emit anything else: there is no value to emit.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(VERIFIED_CONTEXT_BLOCK_SCHEMA)
    }
}

impl<'de> Deserialize<'de> for BlockSchema {
    /// Both refusals, in the one place a block becomes a value.
    ///
    /// A MISSING discriminator never reaches here — the field is required on the read
    /// type, so serde refuses the block before this runs. What this refuses is a
    /// discriminator that is present and names a schema this build does not write.
    ///
    /// The refusal does NOT echo the declared string. A verified-context block arrives on
    /// a channel whose isolation is an operator assertion, so its contents are attacker-
    /// controlled wherever that assertion is wrong, and a parse error is a diagnostic an
    /// operator reads.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let declared = String::deserialize(deserializer)?;
        if declared == VERIFIED_CONTEXT_BLOCK_SCHEMA {
            return Ok(BlockSchema);
        }
        Err(D::Error::custom(
            "verified-context block declares a schema this build does not read",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The writer emits the current schema and nothing else can be emitted, because there
    /// is no other value of the type to emit.
    #[test]
    fn the_only_inhabitant_serializes_as_the_current_schema() {
        assert_eq!(
            serde_json::to_value(BlockSchema).expect("serializes"),
            serde_json::json!(VERIFIED_CONTEXT_BLOCK_SCHEMA)
        );
    }

    /// LOAD-BEARING: an UNKNOWN discriminator is refused rather than read as something
    /// this build understands. It is the half a required field cannot enforce.
    #[test]
    fn a_schema_this_build_does_not_write_is_refused() {
        for declared in [
            "se.syncom/mcp-re.verified-context/2",
            "se.syncom/mcp-re.verified-context",
            "se.syncom/mcp-re.verified-context/1 ",
            "",
            "1",
        ] {
            let read: Result<BlockSchema, _> = serde_json::from_value(serde_json::json!(declared));
            assert!(
                read.is_err(),
                "{declared:?} must not read as the current schema"
            );
        }
    }

    /// A discriminator that is not a string is refused too — a reader that accepted a
    /// number or an object would be deciding the shape from something other than the name.
    #[test]
    fn a_discriminator_that_is_not_a_string_is_refused() {
        for declared in [
            serde_json::json!(1),
            serde_json::json!(null),
            serde_json::json!({"name": VERIFIED_CONTEXT_BLOCK_SCHEMA}),
            serde_json::json!([VERIFIED_CONTEXT_BLOCK_SCHEMA]),
        ] {
            let read: Result<BlockSchema, _> = serde_json::from_value(declared.clone());
            assert!(read.is_err(), "{declared} must not read as a schema name");
        }
    }

    /// The refusal names the failure without echoing the declared string, which arrives on
    /// a channel whose isolation is an assertion rather than a check.
    #[test]
    fn the_refusal_does_not_echo_what_the_block_declared() {
        let read: Result<BlockSchema, _> =
            serde_json::from_value(serde_json::json!("conspicuous-attacker-marker"));
        let why = read.expect_err("an unknown schema").to_string();
        assert!(!why.contains("conspicuous-attacker-marker"), "{why}");
        assert!(why.contains("schema"), "{why}");
    }

    /// POSITIVE CONTROL: the round trip closes, so the refusals above are not satisfied by
    /// a reader that refuses everything.
    #[test]
    fn what_the_writer_emits_the_reader_accepts() {
        let emitted = serde_json::to_value(BlockSchema).expect("serializes");
        let read: BlockSchema = serde_json::from_value(emitted).expect("the writer's own");
        assert_eq!(read, BlockSchema);
    }
}
