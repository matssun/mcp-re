// SPDX-License-Identifier: Apache-2.0
//! The serving path signs under the credential materialization produced (THM-0082).
//!
//! `serving_trust_seam_test` pins the same shape on the TRUST side: the resolver the PEP
//! consults was built from the deployment's materialized authority rather than from
//! something frozen beside it. This is its counterpart on the SIGNING side, and it exists
//! because the defect is symmetric — ADR-MCPS-021 recorded a chain that was constructed, its
//! guarantee printed, and then dropped, while the serving path resolved from somewhere else.
//!
//! What no behavioural control notices: a deployment that announces one signing custody at
//! startup and signs with another on the data plane. Every signature still verifies, every
//! startup line is still true, and the two facts are simply about different keys.
//!
//! > The composition root opens the key source ONCE, through the materializer; it opens the
//! > role-separation witness once; it constructs no key source of its own; and the signing
//! > plane it installs is materialized from that same source.
//!
//! # Why a source scan and not a type
//!
//! `MaterializedSigningRoles` seals the ROLE RELATION — its representation is private and
//! `establish` is its only producer, so a source that reached the serving path came through
//! the comparison. What it cannot seal is that the composition root uses it at all:
//! `FileKeySource` and the KMS adapters are public constructors, as external embedders need,
//! so a root that built one beside the materializer would compile. That is the root's own
//! bug to make and the root's own bug to be caught making — evidence, not
//! unconstructibility (`docs/dev/sealed-owners.md`).

/// The materializer, the witness's one exit, and the plane the signer is installed through.
const MATERIALIZER: &str = "build_key_source";
const WITNESS_EXIT: &str = ".into_key_source()";
const SIGNING_PLANE: &str = "SigningPlane::materialize";

/// The binding the root must carry from one to the other. Named, because the property is
/// not "a source exists" but "THIS source is the one that signs".
const SOURCE_BINDING: &str = "key_source";

/// Every public key-source constructor a composition root could reach for instead. A root
/// that opens one of these has materialized a second signing capability beside the one the
/// deployment validated — which is the defect, whether or not the two agree today.
const RIVAL_CONSTRUCTORS: &[&str] = &[
    "FileKeySource::",
    "EnvKeySource::",
    "KmsKeySource::",
    "Pkcs11KeySource::",
    "AwsKmsKeySource::",
    "GcpKmsKeySource::",
];

fn app_source() -> String {
    let path = mcp_re_test_paths::resolve_runfile("MCP_RE_APP_SRC");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    mcp_re_test_paths::rust_source::production_half(&text)
}

/// How many times `needle` appears outside a comment line.
fn occurrences(text: &str, needle: &str) -> usize {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .map(|line| line.matches(needle).count())
        .sum()
}

/// The composition root opens the key source once, through the materializer.
#[test]
fn the_composition_root_opens_one_key_source_through_the_materializer() {
    let source = app_source();
    assert_eq!(
        occurrences(&source, &format!("{MATERIALIZER}(")),
        1,
        "the composition root must call `{MATERIALIZER}` exactly once. None means the \
         signing credential came from somewhere this test cannot see; more than one means \
         two capabilities that happen to agree today."
    );
    assert_eq!(
        occurrences(&source, WITNESS_EXIT),
        1,
        "the role-separation witness must be opened exactly once. A second `{WITNESS_EXIT}` \
         is a second source, and the witness proves nothing about the one that was not \
         compared."
    );
}

/// It constructs no key source of its own.
#[test]
fn the_composition_root_constructs_no_rival_key_source() {
    let source = app_source();
    for rival in RIVAL_CONSTRUCTORS {
        assert_eq!(
            occurrences(&source, rival),
            0,
            "the composition root reaches `{rival}` directly. A source opened beside the \
             materializer skipped the custody state the deployment validated and skipped the \
             role-separation comparison — and a startup line describing the other one would \
             still be true."
        );
    }
}

/// The signing plane is materialized from that same source.
#[test]
fn the_signing_plane_is_materialized_from_the_materialized_source() {
    let source = app_source();
    let at = source.find(SIGNING_PLANE).unwrap_or_else(|| {
        panic!("the composition root no longer installs a signing plane through {SIGNING_PLANE}")
    });
    assert_eq!(
        occurrences(&source, SIGNING_PLANE),
        1,
        "the signing plane must be materialized exactly once — a second one is a second \
         response-signing authority, and nothing decides which signs."
    );
    let call = &source[at..];
    let end = call.find(");").unwrap_or(call.len());
    assert!(
        call[..end].contains(SOURCE_BINDING),
        "the signing plane is not materialized from `{SOURCE_BINDING}`. Whatever it signs \
         with is then a credential the deployment did not validate, on a data plane whose \
         startup transcript describes a different one."
    );
}

/// The rules detect what they claim to.
#[test]
fn the_rules_would_catch_each_regression() {
    assert_eq!(
        occurrences("let a = build_key_source(x);", "build_key_source("),
        1
    );
    assert_eq!(
        occurrences("// build_key_source(x);", "build_key_source("),
        0
    );
    assert_eq!(
        occurrences("a.into_key_source();\nb.into_key_source();", WITNESS_EXIT),
        2,
        "a second exit from the witness must be seen"
    );
    assert_eq!(
        occurrences("let k = FileKeySource::new(p);", "FileKeySource::"),
        1,
        "a rival constructor must be seen"
    );

    // A signing plane materialized from something else must be visible in the call text.
    let bad = "install_signing(SigningPlane::materialize(&plan, other_signer, now));";
    let at = bad
        .find(SIGNING_PLANE)
        .expect("the helper must find the call");
    let call = &bad[at..];
    let end = call.find(");").unwrap_or(call.len());
    assert!(
        !call[..end].contains(SOURCE_BINDING),
        "a plane built from another operand must not read as one built from the source"
    );

    // Test regions are out of scope, and production below one is still production.
    let half = mcp_re_test_paths::rust_source::production_half(
        "#[cfg(test)]\nmod tests {\n    FileKeySource::new(p);\n}\nfn late() { build_key_source(x); }\n",
    );
    assert_eq!(occurrences(&half, "FileKeySource::"), 0);
    assert_eq!(occurrences(&half, "build_key_source("), 1);
}
