// SPDX-License-Identifier: Apache-2.0
//! Corpus content-pinning (#415 rev 2 §12.2, issue #427).
//!
//! §12.2: "a tag or branch name alone is insufficient to prove that two reviewers
//! used the same corpus." A filename list has the same weakness one level down —
//! it proves which files were MEANT to be there, not what was in them. Two
//! reviewers on the same tag, one with a locally-edited vector, would both report
//! "corpus green" and mean different things.
//!
//! These tests prove the pin actually bites: that a tampered fixture is caught
//! rather than run, and that the corpus digest commits to the whole set. Without
//! them the manifest would carry hashes nobody checks, which is worse than no
//! hashes — it reads as a guarantee.

use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ManifestEntry {
    file: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    corpus_digest: String,
    fixtures: Vec<ManifestEntry>,
}

fn hex_sha256(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn corpus_digest(entries: &[ManifestEntry]) -> String {
    let mut lines: Vec<String> = entries
        .iter()
        .map(|e| format!("{}:{}\n", e.file, e.sha256))
        .collect();
    lines.sort();
    hex_sha256(lines.concat().as_bytes())
}

/// Locate a committed corpus under BOTH build systems (the same dual-mode bridge
/// the vector runners use): Bazel passes `MCP_RE_*_VECTORS_MANIFEST` as a runfiles
/// path, and Cargo falls back to `CARGO_MANIFEST_DIR`.
fn corpus(dir: &str) -> PathBuf {
    let env_key = match dir {
        "http-profile" => "MCP_RE_HTTP_PROFILE_VECTORS_MANIFEST",
        "delegation-profile" => "MCP_RE_DELEGATION_VECTORS_MANIFEST",
        other => panic!("unknown corpus {other}"),
    };
    if let Ok(rel) = std::env::var(env_key) {
        for key in ["TEST_SRCDIR", "RUNFILES_DIR"] {
            if let Ok(root) = std::env::var(key) {
                let candidate = Path::new(&root).join(&rel);
                if candidate.exists() {
                    return candidate.parent().expect("manifest has a parent").to_path_buf();
                }
            }
        }
        let candidate = PathBuf::from(&rel);
        if candidate.exists() {
            return candidate.parent().expect("manifest has a parent").to_path_buf();
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join(dir)
}

fn load(dir: &str) -> (PathBuf, Manifest) {
    let root = corpus(dir);
    let manifest: Manifest =
        serde_json::from_slice(&std::fs::read(root.join("manifest.json")).expect("manifest"))
            .expect("manifest parses");
    (root, manifest)
}

const CORPORA: [&str; 2] = ["http-profile", "delegation-profile"];

/// Every committed fixture's bytes match the SHA-256 the manifest publishes, and
/// the manifest names every file present. A vector on disk that the manifest does
/// not name is as much a corpus discrepancy as a hash mismatch: it means the
/// published index does not describe the directory a reviewer is reading.
#[test]
fn every_committed_fixture_matches_its_published_hash() {
    for dir in CORPORA {
        let (root, manifest) = load(dir);
        assert!(!manifest.fixtures.is_empty(), "{dir}: corpus is empty");

        for entry in &manifest.fixtures {
            let bytes = std::fs::read(root.join(&entry.file))
                .unwrap_or_else(|_| panic!("{dir}/{}: manifest names a missing file", entry.file));
            assert_eq!(
                hex_sha256(&bytes),
                entry.sha256,
                "{dir}/{}: bytes do not match the published hash",
                entry.file
            );
        }

        // No unlisted vectors: walk the directory and check every .json but the
        // manifest itself is accounted for.
        let named: std::collections::HashSet<&str> =
            manifest.fixtures.iter().map(|e| e.file.as_str()).collect();
        for f in std::fs::read_dir(&root).expect("corpus dir") {
            let name = f.expect("entry").file_name().to_string_lossy().to_string();
            if name == "manifest.json" || !name.ends_with(".json") {
                continue;
            }
            assert!(
                named.contains(name.as_str()),
                "{dir}/{name}: present on disk but absent from the manifest"
            );
        }
    }
}

/// The published corpus digest commits to the full sorted set of (path, hash)
/// pairs — the single value two reviewers compare to know they read the same
/// bytes.
#[test]
fn corpus_digest_commits_to_the_manifest_entries() {
    for dir in CORPORA {
        let (_root, manifest) = load(dir);
        assert_eq!(
            corpus_digest(&manifest.fixtures),
            manifest.corpus_digest,
            "{dir}: published corpus_digest does not commit to the entries"
        );
    }
}

/// The pin BITES: flip one byte of one fixture and the hash check fails. This is
/// the property the whole mechanism exists for — a manifest carrying hashes that
/// nobody verifies is worse than no hashes, because it reads as a guarantee.
#[test]
fn a_tampered_fixture_fails_its_hash() {
    let (root, manifest) = load("http-profile");
    let entry = &manifest.fixtures[0];
    let mut bytes = std::fs::read(root.join(&entry.file)).expect("fixture");

    // A single-byte edit, of the kind a careless rebase or a local experiment
    // makes: append one space. The JSON still parses and the vector still "looks"
    // fine — only the hash notices.
    bytes.push(b' ');
    assert_ne!(
        hex_sha256(&bytes),
        entry.sha256,
        "a one-byte edit must break the published hash"
    );
}

/// Adding or removing a vector changes the corpus digest, so a corpus cannot gain
/// or lose a case while still claiming to be the pinned one.
#[test]
fn adding_or_removing_a_vector_changes_the_corpus_digest() {
    let (_root, manifest) = load("http-profile");
    let baseline = corpus_digest(&manifest.fixtures);

    let mut with_extra: Vec<ManifestEntry> = manifest
        .fixtures
        .iter()
        .map(|e| ManifestEntry {
            file: e.file.clone(),
            sha256: e.sha256.clone(),
        })
        .collect();
    with_extra.push(ManifestEntry {
        file: "h99_smuggled.json".into(),
        sha256: hex_sha256(b"{}"),
    });
    assert_ne!(baseline, corpus_digest(&with_extra), "an added vector must move the digest");

    let mut without = with_extra;
    without.truncate(manifest.fixtures.len() - 1);
    assert_ne!(baseline, corpus_digest(&without), "a removed vector must move the digest");
}

/// The digest is a property of corpus CONTENT, not of the order the writer emitted
/// fixtures in: reordering the same entries yields the same digest. Otherwise
/// reshuffling the builder would churn the published digest while every vector
/// stayed byte-identical, and reviewers would learn to ignore it.
#[test]
fn corpus_digest_is_order_independent() {
    let (_root, manifest) = load("http-profile");
    let forward = corpus_digest(&manifest.fixtures);
    let mut reversed: Vec<ManifestEntry> = manifest
        .fixtures
        .iter()
        .rev()
        .map(|e| ManifestEntry {
            file: e.file.clone(),
            sha256: e.sha256.clone(),
        })
        .collect();
    assert_eq!(forward, corpus_digest(&reversed), "sorted: order must not matter");
    reversed.reverse();
    assert_eq!(forward, corpus_digest(&reversed));
}
