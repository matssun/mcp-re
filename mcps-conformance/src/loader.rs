//! Vector loading (MCPS-010).
//!
//! Two sources, one model:
//!   - [`load_from_dir`]: read the committed manifest + fixtures from a
//!     filesystem directory (used by the CLI for local `cargo run`). This is
//!     the only place `mcps-conformance` touches `std::fs`; `mcps-core` never
//!     does (ADR-MCPS-011/012 purity is preserved — fs lives here, not there).
//!   - [`parse_manifest`] / [`parse_case`]: pure parsers reused by the embedded
//!     (compile-time) loader in tests, so the bazel test needs no runfiles.

use std::path::Path;

use crate::vector::ManifestEntry;
use crate::vector::VectorCase;

/// Parse a `manifest.json` payload into its ordered entries.
pub fn parse_manifest(text: &str) -> Result<Vec<ManifestEntry>, String> {
    serde_json::from_str(text).map_err(|e| format!("parse manifest failed: {e}"))
}

/// Parse a single fixture file's JSON into a [`VectorCase`].
pub fn parse_case(text: &str) -> Result<VectorCase, String> {
    serde_json::from_str(text).map_err(|e| format!("parse vector failed: {e}"))
}

/// Load all vectors from a directory containing `manifest.json` and the
/// per-vector fixture files it references. The manifest defines the set and the
/// run order; each entry's `file` is read and parsed.
pub fn load_from_dir(dir: &Path) -> Result<Vec<VectorCase>, String> {
    let manifest_path = dir.join("manifest.json");
    let manifest_text = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("read {}: {e}", manifest_path.display()))?;
    let entries = parse_manifest(&manifest_text)?;

    let mut cases = Vec::with_capacity(entries.len());
    for entry in entries {
        let path = dir.join(&entry.file);
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        cases.push(parse_case(&text)?);
    }
    Ok(cases)
}
