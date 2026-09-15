// SPDX-License-Identifier: Apache-2.0
//! What a `--trust` document BECOMES.
//!
//! One fact, and it is a correspondence rather than a lifecycle: **two products come out of
//! one read, so they can never disagree.** The resolver that answers `resolve` and the
//! `kid -> signer` map the actor seam reads as an identity coordinate are built together
//! from the same bytes; built separately they could describe different trust pictures while
//! both looking current.
//!
//! Separate from [`reload`](super::reload), which owns *how often the read happens and when
//! to stop trusting a stale one*. This module is called by both the first read at
//! materialization and every re-read after it, and it must give the same answer to both.
//!
//! `response_kid` is excluded from the request-signer map here rather than at either caller:
//! the deployment's own issuer key must never be presentable as a client credential, and a
//! rule enforced at the read is one neither caller can forget.

use std::collections::HashMap;
use std::io::Read;

/// The most `--trust` bytes this process will read into memory.
///
/// The document is read WHOLE, and not only at startup: [`read_trust_file`] is the read
/// [`supervise_trust_reload`](super::reload::supervise_trust_reload) performs on its
/// configured cadence, inside a live serving process. Unbounded there, a path that has
/// grown, been swapped for a large file, or been pointed at a device is loaded in full on
/// every tick.
///
/// A megabyte is far more than any real enrolment — an entry is a signer, a key id and a
/// base64 Ed25519 public key, so on the order of 250 bytes, and this admits thousands of
/// them. It bounds the READ. It is not a policy about how many keys a deployment may
/// enrol, and a deployment that needs more should be told so by this refusal rather than
/// by a process that grew until it was killed.
const MAX_TRUST_DOCUMENT_BYTES: u64 = 1024 * 1024;

/// Read `--trust` and build the snapshot the revocation tiers resolve against.
///
/// Two things come out of one read so they can never disagree: the
/// [`InMemoryTrustResolver`](mcp_re_core::InMemoryTrustResolver) that answers
/// `resolve`, and the `kid -> signer` map the actor seam uses as the identity
/// coordinate. `response_kid` is excluded from the request-signer map: the
/// deployment's own issuer key must never be presentable as a client credential.
pub(in crate::trust_plane) fn load_trust_snapshot(
    trust_path: &str,
    response_kid: &str,
) -> Result<crate::reloading_trust::ReloadingTrustStore, String> {
    let (resolver, signers) = read_trust_file(trust_path, response_kid)?;
    Ok(crate::reloading_trust::ReloadingTrustStore::new(
        resolver, signers,
    ))
}
/// The file read shared by startup and every reload.
pub(super) fn read_trust_file(
    trust_path: &str,
    response_kid: &str,
) -> Result<(mcp_re_core::InMemoryTrustResolver, HashMap<String, String>), String> {
    let bytes = read_bounded(trust_path)?;
    let document = crate::trust_document::TrustDocument::parse(&bytes)?;
    // Slot-scoped: only entries this file enrols for the REQUEST slot become client
    // request signers. A key carried here for another purpose is not one.
    Ok((document.resolver(), document.request_signers(response_kid)))
}

/// Read at most [`MAX_TRUST_DOCUMENT_BYTES`], and REFUSE rather than truncate.
///
/// One byte past the cap is read deliberately, so an oversized document is answered as
/// "larger than the bound" and never as a parse failure over a document cut in half. Those
/// are different things for an operator to do about, and only the first names the cap.
fn read_bounded(trust_path: &str) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(trust_path).map_err(|e| format!("{trust_path}: {e}"))?;
    let mut bytes = Vec::new();
    file.take(MAX_TRUST_DOCUMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{trust_path}: {e}"))?;
    if bytes.len() as u64 > MAX_TRUST_DOCUMENT_BYTES {
        return Err(format!(
            "{trust_path}: trust document exceeds the {MAX_TRUST_DOCUMENT_BYTES}-byte read \
             bound and was refused rather than read into memory. This read also runs on the \
             --trust reload cadence, inside the serving process."
        ));
    }
    Ok(bytes)
}

// Everything below is test code. The `#[cfg(test)]` marker lives HERE because it is the
// region `scripts/module_size_gate.py` reads.
#[cfg(test)]
mod tests {
    use super::read_bounded;
    use super::MAX_TRUST_DOCUMENT_BYTES;

    /// A file of `len` bytes at a path unique to this test.
    fn file_of(tag: &str, len: usize) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "mcp_re_trust_bound_{tag}_{}.json",
            std::process::id()
        ));
        std::fs::write(&path, vec![b'x'; len]).expect("write");
        path
    }

    /// The bound is on the READ, so a document one byte past it is refused whole rather
    /// than handed to the parser truncated — and the refusal names the cap, because an
    /// operator whose enrolment outgrew it has something to do about that and nothing to
    /// do about "expected value at line 1".
    #[test]
    fn a_document_past_the_read_bound_is_refused_and_says_so() {
        let cap = usize::try_from(MAX_TRUST_DOCUMENT_BYTES).expect("cap fits a usize");
        let path = file_of("over", cap + 1);
        let err = read_bounded(path.to_str().expect("utf-8 path")).expect_err("refused");
        assert!(
            err.contains("exceeds") && err.contains(&MAX_TRUST_DOCUMENT_BYTES.to_string()),
            "the refusal must name the bound: {err}"
        );
        std::fs::remove_file(&path).ok();
    }

    /// And the bound is not a narrowing: a document AT the cap is read in full.
    #[test]
    fn a_document_at_the_read_bound_is_read_whole() {
        let cap = usize::try_from(MAX_TRUST_DOCUMENT_BYTES).expect("cap fits a usize");
        let path = file_of("at", cap);
        let bytes = read_bounded(path.to_str().expect("utf-8 path")).expect("read");
        assert_eq!(bytes.len(), cap);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_missing_trust_file_names_the_path_it_could_not_read() {
        let err = read_bounded("/nonexistent/mcp-re-trust.json").expect_err("refused");
        assert!(err.starts_with("/nonexistent/mcp-re-trust.json: "), "{err}");
    }
}
