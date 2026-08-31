// SPDX-License-Identifier: Apache-2.0
//! Every production listener denies unknown client revocation status (THM-0054).
//!
//! The behavioural half lives in `tls_test`: a revoked client is denied, a stale CRL denies
//! even a client it does not revoke, and a client whose status the configured CRLs cannot
//! determine is denied. Those drive real handshakes and say what the verifier the tests
//! build does.
//!
//! What they cannot say is that the verifier a PRODUCTION listener uses is that verifier.
//! `ClientCertVerifier` is a foreign trait, and it plainly admits permissive
//! implementations — rustls ships `UnknownStatusPolicy::Allow` and an
//! `allow_unknown_revocation_status()` builder method, either of which would leave every
//! behavioural test above passing while a serving listener admitted an undeterminable
//! credential. So the second half is a proposition about the CONSTRUCTION SITES:
//!
//! > `build_client_verifier` is the only production producer of a client-certificate
//! > verifier; it takes no argument that could relax the posture; it enforces CRL
//! > expiration; and the one other implementation in the crate is behind the declared
//! > fault-injection feature, which is not a production build.
//!
//! # Why a source scan and not a type
//!
//! The verifier is a `dyn` trait object from a foreign crate. Nothing this project owns can
//! make a permissive inhabitant unconstructible — rustls constructs them — so this is
//! EVIDENCE about which inhabitants this crate builds, never unconstructibility. Deleting
//! it leaves a permissive verifier compiling.

use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;

/// The one production producer, and where it lives.
const BUILDER_FN: &str = "build_client_verifier";
const BUILDER_FILE: &str = "tls_listener_state/client_verifier.rs";

/// The foreign builder that decides the posture. Exactly one production file may name it.
const FOREIGN_BUILDER: &str = "WebPkiClientVerifier::builder";

/// The relaxation, by name. It must appear nowhere at all.
const RELAXATION: &str = "allow_unknown_revocation_status";

/// The posture the builder must positively state.
const EXPIRATION: &str = ".enforce_revocation_expiration()";

/// The one other implementation in the crate, and the feature that gates it. It exists to
/// prove the control is live by breaking it, so it is named here rather than excluded by a
/// filter that would also hide a real second implementation.
const FAULT_IMPL_FILE: &str = "tls.rs";
const FAULT_FEATURE: &str = r#"#[cfg(feature = "fault_accept_any_client")]"#;

/// What an argument that could relax the posture would look like. A verifier builder whose
/// caller chooses the policy has moved the decision to whoever calls it correctly.
const POSTURE_ARGUMENT_HINTS: &[&str] = &["bool", "policy", "unknown", "allow", "relax"];

fn collect_rust_files(dir: &Path, into: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read dir {dir:?}: {e}"));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, into);
        } else if path.extension().is_some_and(|e| e == "rs") {
            into.push(path);
        }
    }
}

/// Every production file of the crate, as `(path suffix, text)`.
fn crate_production() -> Vec<(String, String)> {
    let anchor = mcp_re_test_paths::resolve_runfile("MCP_RE_APP_SRC");
    let root = anchor
        .parent()
        .unwrap_or_else(|| panic!("{anchor:?} has no parent directory"))
        .to_path_buf();
    let mut files = Vec::new();
    collect_rust_files(&root, &mut files);
    files.sort();
    assert!(
        files.len() > 10,
        "the crate source walk found {} file(s) under {root:?} — the scope has moved",
        files.len()
    );
    files
        .into_iter()
        .map(|path| {
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let text =
                std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
            (rel, mcp_re_test_paths::rust_source::production_half(&text))
        })
        .collect()
}

/// The code of `text` with whole-line comments removed.
///
/// Necessary rather than tidy: `client_verifier.rs` documents the relaxation BY NAME, in a
/// paragraph explaining that it is not called and that there is no parameter through which
/// it could be. A scan that cannot tell a call from the sentence saying there is no call
/// would force that explanation to be deleted — which would remove the thing a reader needs
/// most, to satisfy a matcher.
fn code_only(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The body of `fn <name>`, by brace depth from its opening brace.
fn body_of(text: &str, name: &str) -> Option<String> {
    let needle = format!("fn {name}");
    let at = text.find(&needle)?;
    let open = at + text[at..].find('{')?;
    let chars: Vec<char> = text[open..].chars().collect();
    let mut depth = 0i64;
    for (offset, c) in chars.iter().enumerate() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(chars[..=offset].iter().collect());
                }
            }
            _ => {}
        }
    }
    None
}

/// The parenthesised parameter list of `fn <name>`.
fn signature_of(text: &str, name: &str) -> Option<String> {
    let needle = format!("fn {name}");
    let at = text.find(&needle)?;
    let open = at + text[at..].find('(')?;
    let chars: Vec<char> = text[open..].chars().collect();
    let mut depth = 0i64;
    for (offset, c) in chars.iter().enumerate() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(chars[..=offset].iter().collect());
                }
            }
            _ => {}
        }
    }
    None
}

/// Exactly one production file builds a client-certificate verifier.
#[test]
fn one_production_file_builds_the_client_certificate_verifier() {
    let builders: BTreeSet<String> = crate_production()
        .into_iter()
        .filter(|(_, text)| text.contains(FOREIGN_BUILDER))
        .map(|(rel, _)| rel)
        .collect();
    let declared: BTreeSet<String> = [BUILDER_FILE.to_string()].into_iter().collect();
    assert_eq!(
        builders, declared,
        "client-certificate verifiers are built in {builders:?}, declared {declared:?}. A \
         second builder is a second posture, and nothing decides which listener gets which."
    );
}

/// The relaxation appears nowhere in the crate.
#[test]
fn no_production_code_relaxes_the_unknown_status_policy() {
    let offenders: Vec<String> = crate_production()
        .into_iter()
        .filter(|(_, text)| code_only(text).contains(RELAXATION))
        .map(|(rel, _)| rel)
        .collect();
    assert!(
        offenders.is_empty(),
        "{offenders:?} call `{RELAXATION}`. Deny-unknown is what makes a credential whose \
         status cannot be determined fail closed; relaxing it admits one that may have been \
         withdrawn, and no behavioural control above would notice."
    );
}

/// The builder states the posture positively, and takes no argument that could relax it.
#[test]
fn the_builder_enforces_expiration_and_admits_no_posture_argument() {
    let source = crate_production()
        .into_iter()
        .find(|(rel, _)| rel == BUILDER_FILE)
        .map(|(_, text)| text)
        .unwrap_or_else(|| panic!("{BUILDER_FILE} is not in the crate"));
    let body = body_of(&source, BUILDER_FN)
        .unwrap_or_else(|| panic!("`fn {BUILDER_FN}` is not in {BUILDER_FILE}"));
    assert!(
        body.contains(EXPIRATION),
        "`{BUILDER_FN}` no longer calls `{EXPIRATION}`. Without it a CRL past its \
         `nextUpdate` is still honoured, so revocation checking fails OPEN on staleness — \
         the exact regression ADR-MCPS-023 §A1 closed."
    );
    let signature = signature_of(&source, BUILDER_FN)
        .unwrap_or_else(|| panic!("`fn {BUILDER_FN}` has no parameter list"));
    let lowered = signature.to_lowercase();
    for hint in POSTURE_ARGUMENT_HINTS {
        assert!(
            !lowered.contains(hint),
            "`{BUILDER_FN}` takes a parameter mentioning {hint:?}. Deny-unknown must be a \
             property of the construction, not of an argument every caller passed correctly: \
             {signature}"
        );
    }
}

/// The one other verifier implementation is behind the declared fault-injection feature.
#[test]
fn the_only_other_verifier_is_the_declared_fault_injector() {
    let others: Vec<(String, String)> = crate_production()
        .into_iter()
        .filter(|(rel, text)| rel != BUILDER_FILE && text.contains("impl ClientCertVerifier"))
        .collect();
    for (rel, text) in &others {
        assert_eq!(
            rel, FAULT_IMPL_FILE,
            "{rel} implements `ClientCertVerifier`. Only the declared fault injector may, and \
             it may only because its feature is never in a production build."
        );
        assert!(
            text.contains(FAULT_FEATURE),
            "{rel} implements `ClientCertVerifier` outside `{FAULT_FEATURE}` — an \
             implementation a production build would compile."
        );
    }
}

/// The rules detect what they claim to.
#[test]
fn the_rules_would_catch_each_regression() {
    let relaxed = "fn build_client_verifier(a: u8) -> V {\n    b().allow_unknown_revocation_status().build()\n}";
    assert!(
        code_only(relaxed).contains(RELAXATION),
        "a real call must survive comment stripping"
    );
    assert!(
        !code_only("/// `allow_unknown_revocation_status()` is NOT called.").contains(RELAXATION),
        "a doc comment naming the relaxation must not read as a call"
    );
    let body = body_of(relaxed, BUILDER_FN).expect("the helper must find a body");
    assert!(body.contains(RELAXATION), "a relaxation must be seen");
    assert!(
        !body.contains(EXPIRATION),
        "a builder that dropped expiration enforcement must be seen"
    );

    let arg = "fn build_client_verifier(ca: Vec<C>, deny_unknown: bool) -> V {}";
    let signature = signature_of(arg, BUILDER_FN).expect("the helper must find a signature");
    assert!(
        signature.to_lowercase().contains("bool"),
        "a posture argument must be seen"
    );
    let real = "fn build_client_verifier(\n    client_ca: Vec<CertificateDer<'static>>,\n    crls: Vec<Crl>,\n    provider: Arc<CryptoProvider>,\n) -> R {}";
    let signature = signature_of(real, BUILDER_FN).expect("the helper must find a signature");
    for hint in POSTURE_ARGUMENT_HINTS {
        assert!(
            !signature.to_lowercase().contains(hint),
            "the real signature must not trip the hint {hint:?}"
        );
    }

    // Test regions are out of scope, and production below one is still production.
    let half = mcp_re_test_paths::rust_source::production_half(
        "#[cfg(test)]\nmod tests {\n    b().allow_unknown_revocation_status();\n}\nfn late() {}\n",
    );
    assert!(
        !half.contains(RELAXATION),
        "a relaxation inside a test region is not a production relaxation"
    );
}
