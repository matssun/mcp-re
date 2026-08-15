//! Vector-replay plumbing for the object conformance target.
//!
//! **Nothing in the repository consumes this library.** No crate, test, or binary
//! names `mcp_re_conformance::`, and the corpus these modules load —
//! `mcp-re-core/tests/vectors/` — is not in the tree. The executable conformance
//! evidence lives in this crate's `tests/`, which reach their corpora under
//! `tests/vectors/` directly; see `docs/conformance-guide.md` for the categories
//! and the harness that proves each one.
//!
//! Its disposition is an open ruling, not a settled design: either a harness
//! wires it to a real corpus, or it is deleted. Do not cite it as the loader for
//! any advertised conformance category — it is wired to none of them.
//!
//! Crate boundary (ADR-MCPS-011/012): `mcp-re-conformance` may use `std::fs`
//! (vector loading) — `mcp-re-core` must not, and stays pure.

pub mod http;
pub mod loader;
pub mod vector;

pub use loader::load_from_dir;
pub use loader::parse_case;
pub use loader::parse_manifest;
pub use mcp_re_core::unix_to_rfc3339_utc;
pub use vector::Expected;
pub use vector::ManifestEntry;
pub use vector::ResolverEntry;
pub use vector::VectorCase;
