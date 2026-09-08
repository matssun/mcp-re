// SPDX-License-Identifier: Apache-2.0
//! WHAT an operator may type, as they read it.
//!
//! One fact: **the command line this tool offers**, in the form it is offered in.
//!
//! Its own owner because it is a DOCUMENT, and one the build gates:
//! `scripts/proxy_flag_doc_gate.py` reads it as one of the flag documents in the tree and
//! fails if it names a flag no tool accepts. [`super::AuditInvocation`] is a value and a
//! parse; this is the contract a person reads before either exists, and folding them
//! together made the module answer *which record this run attests* AND *what may be typed*
//! — an "and" in its own first sentence.
//!
//! The reasoning behind a flag does NOT live here. `--help` output is a list; why the
//! protocol is named rather than guessed belongs in [`super`]'s documentation and in
//! `docs/auditor-guide.md`, where a reader has room for it.

/// The usage text, which is also the flag list the parser accepts.
pub(super) const USAGE: &str = "\
mcp-re-auditor — turn retained MCP-RE evidence into a portable SCITT attestation.

Runs OFF the request path, against an archive a serving proxy wrote with
--retained-evidence-dir. The attestation is always produced and written; registering it
with a transparency service is opt-in and happens afterwards.

  --retained-evidence-dir <dir>   the archive to read
  --hop <digest>                  one hop of the record, repeated IN ORDER (>= 1)
  --audit-profile <path>          what this auditor asserts about the deployment
  --trust-document <path>         the deployment's request-signer trust document
  --service-trust-pin <path>      the transparency service this attestation is for
  --issuer-kid <kid>              the kid this auditor signs its statement under
  --issuer-key-seed <path>        base64url Ed25519 seed for that key
  --out <path>                    where to write the attestation artifact
  --at <unix-seconds>             the audit instant (default: the system clock)

Registration (opt-in). Without --register-to nothing is submitted anywhere.

  --register-to <url>                    an HTTPS transparency-service base URL
  --registration-protocol <name>         scrapi-11 (default) | capsule-anchor
  --registration-timeout-secs <n>        the whole registration budget (default 300)
  --registration-poll-interval-secs <n>  wait between polls (default 2)
";
