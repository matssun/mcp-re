// SPDX-License-Identifier: Apache-2.0
//! Evidence retention on the serving path, and the auditor step that turns retained
//! evidence into a portable SCITT record (ADR-MCPRE-054).
//!
//! The SCITT surface — `issue_signed_statement`, `reconstruct_chain`,
//! `verify_retained_evidence`, `FsRetainedEvidenceStore` — was reachable only from
//! tests, conformance vectors and interop harnesses. Nothing on the serving path
//! produced a statement, reconstructed a chain, or retained anything, so
//! `retained_evidence.rs` was dead code inside the serving crate and any claim of
//! transparency coverage was unbacked.
//!
//! ## The split: the PEP retains, an auditor attests
//!
//! Retention is the only half that MUST happen while the call is being served — nobody
//! can reconstruct later what was not kept. So the PEP writes each exchange into the
//! content-addressed store and nothing more.
//!
//! Everything else is deliberately NOT on the request path:
//!
//! * `reconstruct_chain` needs the WHOLE chain, and a chain is not whole until its last
//!   hop. A PEP attesting per hop could only ever commit to a one-hop record, which for
//!   a continuation is a truncated one — precisely what the `ChainLabel` exists to make
//!   impossible to launder.
//! * It needs an audit posture — a resolver, delegation expectations, an audit instant —
//!   which is the auditor's to choose, not the serving deployment's.
//! * Registering against a transparency service is network I/O, and putting it in front
//!   of a response would make an audit dependency an availability dependency.
//!
//! ## Retention fails CLOSED
//!
//! When a deployment turns retention on it is asserting it can account for what it
//! served. Serving a call whose evidence could not be kept breaks that assertion
//! silently, and the deployment would find out only when an auditor asked for a record
//! that was never written. So a retention failure refuses the exchange with a signed
//! `mcp-re.evidence_retention_unavailable` rejection, the same posture the replay tier
//! takes for the same reason.
//!
//! This is the opposite of the audit SINK's posture, and deliberately: the sink must not
//! fail a request, because a lost log line does not change what the deployment can
//! prove about the call. Lost retained evidence does.
//!
//! **The cost of that choice, stated rather than discovered.** Failing closed on a store
//! failure means a FULL VOLUME is a total outage: every request is refused until space
//! is freed. The store grows without bound by construction — one object per accepted
//! call, each holding a request and response body up to `--max-body-bytes` (16 MiB by
//! default), with no expiry, no lifecycle and no quota. So an authenticated client can
//! drive disk exhaustion, and the fail-closed posture turns that into a refusal of
//! everything.
//!
//! A cap here would not fix it, it would only move it: at the cap the choice is refuse
//! (the same outage) or stop retaining (breaking the assertion retention exists to make).
//! The real control is an external retention policy — a dedicated volume, rotation or
//! archival off the node, and free-space alerting — which is a deployment concern this
//! module deliberately does not try to be. Turning retention on without one is choosing
//! an outage on a timer.
//!
//! ## What is retained: ACCEPTED exchanges only
//!
//! Retention runs at the one exit where a request was verified, dispatched and answered.
//! A REJECTED request is not retained: it produced no hop a chain can be reconstructed
//! from, and a signed rejection receipt is already an audit-sink record carrying the
//! frozen wire code. "We can account for what we served" is therefore the honest reading
//! of a full store — not "we can account for everything that was attempted."
//!
//! ## First exposure
//!
//! Nothing under here had met hostile input before this wiring. Every value that
//! arrives from the wire — a body, a header, a digest read back from disk — is treated
//! as such: the store re-addresses what it returns, the retained record carries a schema
//! token, and the loader refuses a record it cannot read rather than reconstructing a
//! chain from a partial one.

use std::sync::Mutex;

use mcp_re_core::b64url_decode;
use mcp_re_core::b64url_encode;
use mcp_re_http_profile::chain::RetainedHop;
use mcp_re_http_profile::scitt::EvidenceDigest;
use mcp_re_http_profile::scitt::RetainedEvidenceStore;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;
use serde::Deserialize;
use serde::Serialize;

use crate::retained_evidence::FsRetainedEvidenceStore;

/// The schema token every retained record carries.
///
/// A content-addressed blob has no type of its own — the store returns bytes that hash
/// to the name asked for and nothing more. Without a token in the record, a future
/// change to the encoding would be read by an old reader as a valid record of a
/// different shape, and the chain it reconstructed would be about something else.
pub const RETAINED_HOP_SCHEMA: &str = "mcp-re-retained-hop/v1";

/// A retention failure. Both variants refuse the exchange.
#[derive(Debug)]
pub enum RetentionError {
    /// The store could not write or read.
    Store(std::io::Error),
    /// A record came back that this reader cannot use.
    Malformed(&'static str),
}

impl std::fmt::Display for RetentionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RetentionError::Store(e) => write!(f, "retained-evidence store: {e}"),
            RetentionError::Malformed(what) => write!(f, "retained evidence: {what}"),
        }
    }
}

impl std::error::Error for RetentionError {}

/// One retained exchange, in the form an auditor reconstructs a chain from.
///
/// Bodies are base64url rather than byte arrays: a JSON array of 40 000 integers is the
/// same information at eight times the size, and this store holds one of these per
/// served call.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedHopRecord {
    schema: String,
    request: RetainedRequest,
    response: RetainedResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedRequest {
    method: String,
    target_uri: String,
    headers: Vec<(String, String)>,
    body_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body_b64: String,
}

impl RetainedHopRecord {
    fn of(request: &HttpRequest, response: &HttpResponse) -> Self {
        RetainedHopRecord {
            schema: RETAINED_HOP_SCHEMA.to_owned(),
            request: RetainedRequest {
                method: request.method.clone(),
                target_uri: request.target_uri.clone(),
                headers: request.headers.clone(),
                body_b64: b64url_encode(&request.body),
            },
            response: RetainedResponse {
                status: response.status,
                headers: response.headers.clone(),
                body_b64: b64url_encode(&response.body),
            },
        }
    }

    fn into_hop(self) -> Result<RetainedHop, RetentionError> {
        if self.schema != RETAINED_HOP_SCHEMA {
            return Err(RetentionError::Malformed("unknown retained-hop schema"));
        }
        Ok(RetainedHop {
            request: HttpRequest {
                method: self.request.method,
                target_uri: self.request.target_uri,
                headers: self.request.headers,
                body: b64url_decode(&self.request.body_b64)
                    .map_err(|_| RetentionError::Malformed("request body encoding"))?,
            },
            response: HttpResponse {
                status: self.response.status,
                headers: self.response.headers,
                body: b64url_decode(&self.response.body_b64)
                    .map_err(|_| RetentionError::Malformed("response body encoding"))?,
            },
        })
    }
}

/// Retains served exchanges so an auditor can attest to them later.
///
/// One recorder is shared by every core, behind a mutex. The lock is held only across a
/// `put` — a temp-file write, an fsync and a rename — which is real work on the request
/// path and is exactly the cost a deployment accepts when it turns retention on. It is
/// not hidden behind a queue: a queued write that fails after the response has gone out
/// cannot fail the exchange, which would put us back to serving calls we cannot account
/// for while reporting that we can.
pub struct EvidenceRetention {
    store: Mutex<FsRetainedEvidenceStore>,
}

impl EvidenceRetention {
    /// Open (creating if absent) a retention store rooted at `dir`.
    pub fn open(dir: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        Ok(EvidenceRetention {
            store: Mutex::new(FsRetainedEvidenceStore::open(dir)?),
        })
    }

    /// Retain one served exchange, returning the handle an audit record carries.
    pub fn retain(
        &self,
        request: &HttpRequest,
        response: &HttpResponse,
    ) -> Result<EvidenceDigest, RetentionError> {
        let record = RetainedHopRecord::of(request, response);
        let bytes = serde_json::to_vec(&record)
            .map_err(|_| RetentionError::Malformed("retained hop does not serialize"))?;
        // A poisoned lock is an operational failure, and this path fails closed on
        // those — so it takes the last value and proceeds rather than panicking every
        // request for the lifetime of the replica.
        let mut store = match self.store.lock() {
            Ok(store) => store,
            Err(poisoned) => poisoned.into_inner(),
        };
        store.put(&bytes).map_err(RetentionError::Store)
    }

    /// Read back one retained exchange.
    ///
    /// `Ok(None)` means the store does not hold it — an auditor, not the store, decides
    /// whether a missing hop is fatal for the reconstruction being attempted.
    pub fn load(&self, digest: &EvidenceDigest) -> Result<Option<RetainedHop>, RetentionError> {
        let store = match self.store.lock() {
            Ok(store) => store,
            Err(poisoned) => poisoned.into_inner(),
        };
        let Some(bytes) = store.get(digest).map_err(RetentionError::Store)? else {
            return Ok(None);
        };
        let record: RetainedHopRecord = serde_json::from_slice(&bytes)
            .map_err(|_| RetentionError::Malformed("retained hop does not parse"))?;
        record.into_hop().map(Some)
    }

    /// Read back an ordered chain, refusing rather than reconstructing from a gap.
    ///
    /// A missing hop is fatal HERE because the caller asked for a specific ordered
    /// chain: silently reconstructing from the hops that happen to be present would
    /// produce a `Complete` label for a record with a hole in it, which is the quiet
    /// truncation the chain seam exists to prevent.
    pub fn load_chain(
        &self,
        digests: &[EvidenceDigest],
    ) -> Result<Vec<RetainedHop>, RetentionError> {
        digests
            .iter()
            .map(|digest| {
                self.load(digest)?
                    .ok_or(RetentionError::Malformed("retained chain is missing a hop"))
            })
            .collect()
    }
}

/// What an attestation produced: the portable statement, and the chain verdict it
/// commits to.
///
/// Both, never just the statement. A `SignedStatement` alone does not say whether the
/// record it describes is whole — the `ChainLabel` inside it does, and handing back the
/// reconstruction means a caller can act on an INCOMPLETE verdict rather than discover
/// it by decoding the statement it just published.
pub struct Attestation {
    /// The RFC 9943 Signed Statement, ready to submit to a transparency service.
    pub statement: mcp_re_http_profile::scitt::SignedStatement,
    /// The reconstruction the statement commits to.
    pub reconstruction: mcp_re_http_profile::ChainReconstruction,
}

/// An attestation that could not be produced.
#[derive(Debug)]
pub enum AttestError {
    /// The retained evidence could not be read.
    Retention(RetentionError),
    /// The statement could not be issued, or did not describe the retained bytes.
    Statement(mcp_re_http_profile::HttpProfileError),
}

impl std::fmt::Display for AttestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttestError::Retention(e) => write!(f, "{e}"),
            AttestError::Statement(e) => write!(f, "scitt statement: {}", e.wire_code()),
        }
    }
}

impl std::error::Error for AttestError {}

/// Reconstruct a retained chain and issue a Signed Statement committing to it.
///
/// This is the auditor step, off the request path by design (see the module note). It
/// runs the FULL delegated verification over every retained hop — that is what
/// `reconstruct_chain` is for, and the label it produces is embedded in the statement,
/// so a receipt could otherwise commit to a COMPLETE call record established without
/// any delegation chain ever being checked.
///
/// An INCOMPLETE chain is attested, not refused. That is the point of the §9 seam: a
/// truncated or broken record is representable and distinguishable, and refusing to
/// issue a statement about one would leave the most interesting records — the ones with
/// a hop missing — with no portable evidence at all.
///
/// The statement is verified against the retained bytes before it is returned. Issuing
/// is a signature over a commitment this function just computed, so checking it is
/// checking our own arithmetic — but the check is the one an auditor will later run
/// with the same call, and a statement that fails it must never leave this process.
#[allow(clippy::too_many_arguments)]
pub fn attest_chain<R: Into<mcp_re_http_profile::ResolverOutcome>>(
    retention: &EvidenceRetention,
    hops: &[EvidenceDigest],
    resolve_actor: &dyn Fn(&str, mcp_re_http_profile::SignerSlot) -> R,
    expect: &mcp_re_http_profile::DelegationExpectations<'_>,
    is_revoked: &dyn Fn(&str) -> bool,
    now: i64,
    issuer_kid: &str,
    bindings_commitment: Option<String>,
    verified_context_commitment: Option<String>,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, mcp_re_http_profile::HttpProfileError>,
) -> Result<Attestation, AttestError> {
    let retained = retention.load_chain(hops).map_err(AttestError::Retention)?;
    let reconstruction =
        mcp_re_http_profile::reconstruct_chain(&retained, resolve_actor, expect, is_revoked, now);
    let commitment = mcp_re_http_profile::scitt::EvidenceCommitment::from_reconstruction(
        &reconstruction,
        bindings_commitment.clone(),
        verified_context_commitment.clone(),
    );
    let statement =
        mcp_re_http_profile::scitt::issue_signed_statement(issuer_kid, commitment, now, sign)
            .map_err(AttestError::Statement)?;
    mcp_re_http_profile::scitt::verify_retained_evidence(
        statement.commitment(),
        &reconstruction,
        bindings_commitment,
        verified_context_commitment,
    )
    .map_err(AttestError::Statement)?;
    Ok(Attestation {
        statement,
        reconstruction,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("mcp-re-transparency-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            TempDir(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn exchange() -> (HttpRequest, HttpResponse) {
        (
            HttpRequest {
                method: "POST".into(),
                target_uri: "https://mcp.example.com/mcp?route=a".into(),
                headers: vec![("signature".into(), "sig1=:AAAA:".into())],
                // Deliberately NOT valid UTF-8: a retained body is whatever went over
                // the wire, and an encoding that assumed text would corrupt it.
                body: vec![0x00, 0xff, 0x7b, 0x7d],
            },
            HttpResponse {
                status: 200,
                headers: vec![("content-digest".into(), "sha-256=:BBBB:".into())],
                body: b"{\"jsonrpc\":\"2.0\"}".to_vec(),
            },
        )
    }

    #[test]
    fn a_retained_exchange_comes_back_byte_identical() {
        let dir = TempDir::new("roundtrip");
        let retention = EvidenceRetention::open(&dir.0).expect("open");
        let (request, response) = exchange();

        let digest = retention.retain(&request, &response).expect("retain");
        let hop = retention.load(&digest).expect("load").expect("present");

        assert_eq!(hop.request.method, request.method);
        assert_eq!(hop.request.target_uri, request.target_uri);
        assert_eq!(hop.request.headers, request.headers);
        assert_eq!(
            hop.request.body, request.body,
            "a retained body is whatever went over the wire, bytes and all"
        );
        assert_eq!(hop.response.status, response.status);
        assert_eq!(hop.response.headers, response.headers);
        assert_eq!(hop.response.body, response.body);
    }

    /// Content addressing makes retention idempotent: the same exchange retained twice
    /// is one object under one handle.
    #[test]
    fn retaining_the_same_exchange_twice_yields_one_object() {
        let dir = TempDir::new("idempotent");
        let retention = EvidenceRetention::open(&dir.0).expect("open");
        let (request, response) = exchange();
        let first = retention.retain(&request, &response).expect("retain");
        let second = retention.retain(&request, &response).expect("retain again");
        assert_eq!(first, second);
    }

    /// A blob that is not a retained hop must not be reconstructed from. The store
    /// returns bytes that hash to the name asked for; whether they are a hop is this
    /// module's question, and the schema token is how it answers.
    #[test]
    fn a_record_without_the_schema_token_is_refused() {
        let dir = TempDir::new("schema");
        let retention = EvidenceRetention::open(&dir.0).expect("open");
        let alien = br#"{"schema":"something-else/v1","request":{"method":"POST","target_uri":"u","headers":[],"body_b64":""},"response":{"status":200,"headers":[],"body_b64":""}}"#;
        let digest = {
            let mut store = retention.store.lock().expect("lock");
            store.put(alien).expect("put")
        };
        assert!(
            matches!(
                retention.load(&digest),
                Err(RetentionError::Malformed("unknown retained-hop schema"))
            ),
            "an unrecognized schema is refused, not reinterpreted"
        );
    }

    /// A gap in a requested chain is fatal. Reconstructing from the hops that happen to
    /// be present would label a record with a hole in it COMPLETE.
    #[test]
    fn a_chain_with_a_missing_hop_is_refused_rather_than_reconstructed() {
        let dir = TempDir::new("gap");
        let retention = EvidenceRetention::open(&dir.0).expect("open");
        let (request, response) = exchange();
        let present = retention.retain(&request, &response).expect("retain");
        let absent = EvidenceDigest::of(b"a hop nobody retained");

        assert_eq!(
            retention
                .load_chain(std::slice::from_ref(&present))
                .expect("the present hop loads")
                .len(),
            1
        );
        assert!(
            matches!(
                retention.load_chain(&[present, absent]),
                Err(RetentionError::Malformed("retained chain is missing a hop"))
            ),
            "a missing hop refuses the whole chain"
        );
    }
}
