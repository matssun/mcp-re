// SPDX-License-Identifier: Apache-2.0
//! The AUDIT INVOCATION — authority A.
//!
//! One fact: **which retained record this run attests, and where the inputs that describe
//! it live.**
//!
//! It is separate from the profile because the two change on different clocks. A profile
//! describes a deployment and is written once; an invocation names one chain and is
//! different every run. Folding the hops into the profile would make attesting a second
//! record require editing the document that says what the deployment's posture was.
//!
//! Everything here is REQUIRED except the audit instant. There is no default archive, no
//! default profile and no default output path: an auditor that guessed any of them would
//! be attesting a record the operator did not name.

use std::path::PathBuf;

use mcp_re_http_profile::scitt::EvidenceDigest;

/// A flag given exactly once.
mod flag;
/// The moment this audit is taken to have been performed at.
mod instant;

use flag::Slot;
use instant::audit_instant;

/// What one audit run was asked to do.
///
/// # What construction proved
///
/// Every required input was given exactly once, at least one hop was named, and every hop
/// token is a digest. A repeated single-valued flag is refused rather than last-write-wins
/// — an operator who passes `--out` twice has not expressed a preference between them.
#[derive(Debug, Clone)]
pub struct AuditInvocation {
    /// The retained-evidence directory the deployment wrote.
    pub(super) retained_evidence_dir: PathBuf,
    /// The record's hops, IN ORDER. Order is a fact the archive does not carry: the store
    /// is content-addressed and flat, so which hop came first is the operator's to state.
    pub(super) hops: Vec<EvidenceDigest>,
    /// The audit profile document.
    pub(super) audit_profile: PathBuf,
    /// The deployment's trust document.
    pub(super) trust_document: PathBuf,
    /// The operator's transparency-service trust pin.
    pub(super) service_trust_pin: PathBuf,
    /// The `kid` this auditor issues its Signed Statement under.
    pub(super) issuer_kid: String,
    /// The file holding this auditor's base64url Ed25519 statement-signing seed.
    pub(super) issuer_key_seed: PathBuf,
    /// The audit instant, Unix seconds.
    pub(super) at: i64,
    /// Where to write the attestation artifact.
    pub(super) out: PathBuf,
}

/// The usage text, which is also the flag list this parser accepts.
pub(super) const USAGE: &str = "\
mcp-re-auditor — turn retained MCP-RE evidence into a portable SCITT attestation.

Runs OFF the request path, against an archive a serving proxy wrote with
--retained-evidence-dir. It contacts no transparency service; what it writes is the
artifact a registration step submits.

  --retained-evidence-dir <dir>   the archive to read
  --hop <digest>                  one hop of the record, repeated IN ORDER (>= 1)
  --audit-profile <path>          what this auditor asserts about the deployment
  --trust-document <path>         the deployment's request-signer trust document
  --service-trust-pin <path>      the transparency service this attestation is for
  --issuer-kid <kid>              the kid this auditor signs its statement under
  --issuer-key-seed <path>        base64url Ed25519 seed for that key
  --out <path>                    where to write the attestation artifact
  --at <unix-seconds>             the audit instant (default: the system clock)
";

impl AuditInvocation {
    /// The usage text: what this auditor accepts, and nothing it does not.
    pub fn usage() -> &'static str {
        USAGE
    }

    /// Whether `args` is a request for the usage text rather than an audit.
    ///
    /// Asking what a tool does is not a failed invocation, so it is answered on stdout at
    /// exit 0. An empty argument list is the same request: a bare `mcp-re-auditor` cannot
    /// be an audit — every input naming which record to attest is required — so treating
    /// it as one would print eight refusals where an operator asked one question.
    pub fn is_help_request(args: &[String]) -> bool {
        args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h")
    }

    /// Where the artifact will be written.
    pub fn output_path(&self) -> &std::path::Path {
        &self.out
    }

    /// Parse an argument list, or name the first rule it breaks.
    ///
    /// `args` is the list WITHOUT the program name.
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut dir = Slot::new("--retained-evidence-dir");
        let mut profile = Slot::new("--audit-profile");
        let mut trust = Slot::new("--trust-document");
        let mut pin = Slot::new("--service-trust-pin");
        let mut kid = Slot::new("--issuer-kid");
        let mut seed = Slot::new("--issuer-key-seed");
        let mut out = Slot::new("--out");
        let mut at = Slot::new("--at");
        let mut hops: Vec<EvidenceDigest> = Vec::new();

        let mut args = args.into_iter();
        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--retained-evidence-dir" => dir.set(value_for(&flag, &mut args)?)?,
                "--audit-profile" => profile.set(value_for(&flag, &mut args)?)?,
                "--trust-document" => trust.set(value_for(&flag, &mut args)?)?,
                "--service-trust-pin" => pin.set(value_for(&flag, &mut args)?)?,
                "--issuer-kid" => kid.set(value_for(&flag, &mut args)?)?,
                "--issuer-key-seed" => seed.set(value_for(&flag, &mut args)?)?,
                "--out" => out.set(value_for(&flag, &mut args)?)?,
                "--at" => at.set(value_for(&flag, &mut args)?)?,
                "--hop" => hops.push(hop_digest(&value_for(&flag, &mut args)?)?),
                other => return Err(format!("unknown argument {other:?}\n\n{USAGE}")),
            }
        }

        if hops.is_empty() {
            return Err("--hop is required at least once: an audit attests a named \
                        record, and an empty chain names none"
                .to_owned());
        }

        Ok(AuditInvocation {
            retained_evidence_dir: dir.required()?.into(),
            hops,
            audit_profile: profile.required()?.into(),
            trust_document: trust.required()?.into(),
            service_trust_pin: pin.required()?.into(),
            issuer_kid: kid.required()?,
            issuer_key_seed: seed.required()?.into(),
            at: audit_instant(at.value)?,
            out: out.required()?.into(),
        })
    }
}

/// The retained-evidence digest a `--hop` token names, or a refusal naming the token.
///
/// The refusal says which argument was wrong rather than only that a digest was: an
/// operator pasting hop tokens from a directory listing needs to know which one.
fn hop_digest(token: &str) -> Result<EvidenceDigest, String> {
    EvidenceDigest::from_token(token)
        .map_err(|_| format!("--hop {token:?}: not a retained-evidence digest"))
}

/// The value following `flag`, or a refusal naming the flag that is short of one.
fn value_for(flag: &str, args: &mut impl Iterator<Item = String>) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{flag}: needs a value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(bytes: &[u8]) -> String {
        EvidenceDigest::of(bytes).as_str().to_owned()
    }

    fn args(extra: &[&str]) -> Vec<String> {
        let mut v: Vec<String> = [
            "--retained-evidence-dir",
            "/archive",
            "--audit-profile",
            "/profile.json",
            "--trust-document",
            "/trust.json",
            "--service-trust-pin",
            "/pin.json",
            "--issuer-kid",
            "auditor-1",
            "--issuer-key-seed",
            "/seed",
            "--out",
            "/out.json",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        v.extend(extra.iter().map(|s| (*s).to_owned()));
        v
    }

    #[test]
    fn a_complete_invocation_parses_and_keeps_the_hop_order() {
        let (a, b) = (token(b"hop-0"), token(b"hop-1"));
        let parsed =
            AuditInvocation::parse(args(&["--hop", &a, "--hop", &b, "--at", "1700000100"]))
                .expect("a complete invocation");

        assert_eq!(parsed.at, 1_700_000_100);
        assert_eq!(parsed.issuer_kid, "auditor-1");
        assert_eq!(
            parsed
                .hops
                .iter()
                .map(EvidenceDigest::as_str)
                .collect::<Vec<_>>(),
            [a.as_str(), b.as_str()],
            "the hops keep the order the operator gave, because the archive does not carry it",
        );
    }

    #[test]
    fn every_required_flag_is_required() {
        let hop = token(b"hop-0");
        let full = args(&["--hop", &hop]);
        for flag in [
            "--retained-evidence-dir",
            "--audit-profile",
            "--trust-document",
            "--service-trust-pin",
            "--issuer-kid",
            "--issuer-key-seed",
            "--out",
        ] {
            let mut without = Vec::new();
            let mut skip = false;
            for arg in &full {
                if skip {
                    skip = false;
                    continue;
                }
                if arg == flag {
                    skip = true;
                    continue;
                }
                without.push(arg.clone());
            }
            let refused = AuditInvocation::parse(without).expect_err("must be required");
            assert!(refused.contains(flag), "{flag}: {refused}");
        }
    }

    /// An empty chain is an invocation error, not a record. `attest_chain` would happily
    /// label it `Incomplete { EmptyChain }` and issue a statement about nothing.
    #[test]
    fn no_hop_at_all_is_refused() {
        let refused = AuditInvocation::parse(args(&[])).expect_err("no hops");
        assert!(refused.contains("--hop"), "{refused}");
    }

    #[test]
    fn a_hop_that_is_not_a_digest_is_refused() {
        let refused =
            AuditInvocation::parse(args(&["--hop", "not-a-digest"])).expect_err("bad token");
        assert!(refused.contains("--hop"), "{refused}");
    }

    /// A repeated single-valued flag is refused rather than resolved. The operator who
    /// passed two output paths did not express a preference between them.
    #[test]
    fn a_repeated_single_valued_flag_is_refused() {
        let hop = token(b"hop-0");
        let refused = AuditInvocation::parse(args(&["--hop", &hop, "--out", "/other.json"]))
            .expect_err("two --out");
        assert!(refused.contains("--out"), "{refused}");
    }

    #[test]
    fn an_unknown_flag_is_refused_with_the_usage() {
        let hop = token(b"hop-0");
        let refused =
            AuditInvocation::parse(args(&["--hop", &hop, "--register"])).expect_err("unknown");
        assert!(refused.contains("--register"), "{refused}");
        assert!(refused.contains("--retained-evidence-dir"), "{refused}");
    }

    #[test]
    fn a_flag_with_no_value_is_refused() {
        let refused = AuditInvocation::parse(["--hop".to_owned()]).expect_err("no value");
        assert!(refused.contains("needs a value"), "{refused}");
    }

    /// An audit instant at or before the epoch is refused rather than used. Every hop's
    /// `created` would compare as being in the future, so the reconstruction would report
    /// the archive as broken when the caller's clock is.
    #[test]
    fn a_non_positive_audit_instant_is_refused() {
        let hop = token(b"hop-0");
        for instant in ["0", "-1"] {
            let refused = AuditInvocation::parse(args(&["--hop", &hop, "--at", instant]))
                .expect_err("epoch instant");
            assert!(refused.contains("--at"), "{refused}");
        }
        assert!(AuditInvocation::parse(args(&["--hop", &hop, "--at", "later"])).is_err());
    }

    /// Asking what the tool does is answered, not refused — and a bare invocation is the
    /// same question, because every input naming which record to attest is required.
    #[test]
    fn help_and_a_bare_invocation_are_the_same_question() {
        for args in [vec![], vec!["--help".to_owned()], vec!["-h".to_owned()]] {
            assert!(AuditInvocation::is_help_request(&args), "{args:?}");
        }
        let hop = token(b"hop-0");
        assert!(
            !AuditInvocation::is_help_request(&args(&["--hop", &hop])),
            "a real invocation is not a help request",
        );
        assert!(AuditInvocation::usage().contains("--retained-evidence-dir"));
    }

    /// With no `--at`, the instant is the system clock — and it is positive, so the
    /// default cannot silently be the refused one.
    #[test]
    fn the_default_audit_instant_is_the_system_clock() {
        let hop = token(b"hop-0");
        let parsed = AuditInvocation::parse(args(&["--hop", &hop])).expect("parses");
        assert!(
            parsed.at > 1_700_000_000,
            "a real clock reading: {}",
            parsed.at
        );
    }
}
