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
//! ## What a retained record contains: the covered headers, credentials included
//!
//! A record keeps each message's body and the headers that message's own signature
//! covers — no more, because reconstruction reads nothing else, and no less, because the
//! signature base cannot be recomputed from a subset. This profile REQUIRES
//! `authorization` and `dpop` to be covered when present, so a retained request holds the
//! call's live bearer token and DPoP proof verbatim.
//!
//! That is a real cost, stated rather than discovered. It cannot be avoided by digesting
//! them — the signature is over the raw header line, so a digest makes the hop
//! unverifiable, which is the one thing retention exists to enable. What it does buy is a
//! boundary that can be stated: the store holds what the evidence carrier covers, never
//! whatever else the client happened to send. Uncovered credentials — `cookie`,
//! `proxy-authorization`, bespoke API-key headers — are dropped, because no auditor can
//! use them.
//!
//! The consequence for a deployment: this directory is credential material for every
//! call since it was created, with no expiry. It is created `0700` and its objects
//! `0600`, and an existing directory that is looser is warned about at startup. Handing
//! it to an auditor hands over replayable tokens.
//!
//! ## First exposure
//!
//! Nothing under here had met hostile input before this wiring. Every value that
//! arrives from the wire — a body, a header, a digest read back from disk — is treated
//! as such: the store re-addresses what it returns, the retained record carries a schema
//! token, and the loader refuses a record it cannot read rather than reconstructing a
//! chain from a partial one.

use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::SyncSender;
use std::sync::Arc;

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

/// The headers a retained message keeps: the ones its own signature covers, plus the two
/// that carry the signature itself.
///
/// Everything else is dropped. Reconstruction re-verifies each message, and verification
/// reads exactly the covered components plus `signature`/`signature-input` — so an
/// uncovered header contributes nothing to a chain and is retained for no reason. That
/// distinction matters because of what these records hold: this profile REQUIRES
/// `authorization` and `dpop` to be covered when present, so a retained request contains
/// the live bearer token and DPoP proof of the call it describes. Those cannot be
/// stripped without making the signature base unreproducible — the signature is over
/// them. What CAN be kept out is every other credential the client happened to send
/// (`cookie`, `proxy-authorization`, bespoke API-key headers), none of which any auditor
/// will ever need.
///
/// The covered set is read from the ONE `Signature-Input` dictionary member the verifier
/// checked — `label`, which is [`mcp_re_http_profile::REQUEST_LABEL`] for a request and
/// [`mcp_re_http_profile::RESPONSE_LABEL`] for a response — and from inside that member's
/// component list `( … )` only. Both restrictions are load-bearing. Verification reads a
/// single member and ignores every other one, so a client may add `decoy=("cookie")` to a
/// value that verifies normally; and a component may carry its own parameters, so
/// `("@method";key="cookie")` names one component, not two. Neither may decide what is
/// written to a store that holds credential material.
fn covered_headers(headers: &[(String, String)], label: &str) -> Vec<(String, String)> {
    let mut covered: Vec<String> = Vec::new();
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("signature-input") {
            continue;
        }
        let Some(list) = component_list_for(value, label) else {
            continue;
        };
        for component in component_names(list) {
            // `@method`, `@target-uri`, … are derived, not headers.
            if !component.starts_with('@') {
                covered.push(component.to_ascii_lowercase());
            }
        }
    }
    headers
        .iter()
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            lower == "signature" || lower == "signature-input" || covered.contains(&lower)
        })
        .cloned()
        .collect()
}

/// The `( … )` component list of the dictionary member named `label`, if it has one.
fn component_list_for<'a>(value: &'a str, label: &str) -> Option<&'a str> {
    for member in dictionary_members(value) {
        let Some((name, rest)) = member.split_once('=') else {
            continue;
        };
        if name.trim() != label {
            continue;
        }
        let open = rest.find('(')?;
        let tail = &rest[open + 1..];
        let close = tail.find(')')?;
        return Some(&tail[..close]);
    }
    None
}

/// The top-level members of a structured-fields dictionary: commas inside a quoted string
/// do not separate members.
fn dictionary_members(value: &str) -> Vec<&str> {
    let mut members = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => {
                members.push(&value[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    members.push(&value[start..]);
    members
}

/// The component names in one component list: the leading quoted token of each
/// whitespace-separated item, so an item's own `;key="…"` parameters are not names.
fn component_names(list: &str) -> impl Iterator<Item = &str> {
    list.split_whitespace().filter_map(|item| {
        let rest = item.strip_prefix('"')?;
        let end = rest.find('"')?;
        Some(&rest[..end])
    })
}

impl RetainedHopRecord {
    fn of(request: &HttpRequest, response: &HttpResponse) -> Self {
        RetainedHopRecord {
            schema: RETAINED_HOP_SCHEMA.to_owned(),
            request: retained_request(request),
            response: RetainedResponse {
                status: response.status,
                headers: covered_headers(&response.headers, mcp_re_http_profile::RESPONSE_LABEL),
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

/// The retained-request half of a record, shared by the reservation marker and the hop.
fn retained_request(request: &HttpRequest) -> RetainedRequest {
    RetainedRequest {
        method: request.method.clone(),
        target_uri: request.target_uri.clone(),
        headers: covered_headers(&request.headers, mcp_re_http_profile::REQUEST_LABEL),
        body_b64: b64url_encode(&request.body),
    }
}

/// Process-global ceiling on calls that hold a retention reservation at once.
///
/// A backstop, not the primary admission control — the per-core in-flight ceiling is
/// that. Its job is to bound the write queue: a reservation contributes at most one
/// queued job at any instant, so `K` reservations bound the queue at `K` jobs. Exceeding
/// it is refused BEFORE dispatch, which is the one place refusing is still free and
/// genuinely retry-safe.
const MAX_RESERVATIONS: usize = 1024;

/// The write queue's capacity for a given reservation ceiling.
///
/// Twice the ceiling, and the factor of two is load-bearing rather than slack. A
/// reservation holds its permit until it is dropped, which can happen while its
/// completion job is still queued; the permit it releases can then admit a successor
/// whose reserve job is queued alongside it. One transient extra slot per reservation is
/// the most that window can produce, so at `2K` the send can never find the channel
/// full — and `complete` is therefore never refused for capacity, which is the whole
/// point of taking the admission decision before dispatch.
const fn write_queue_capacity(max_reservations: usize) -> usize {
    2 * max_reservations
}

/// How many queued jobs one directory barrier may cover.
///
/// A directory `fsync` has no per-entry granularity, so one call after B renames is
/// exactly as durable as B calls after one rename each. Bounding the batch bounds the
/// latency the last job in it waits, not its durability.
const MAX_WRITE_BATCH: usize = 64;

/// One durable write, and the acknowledgement the awaiting request is owed.
struct WriteJob {
    /// Where the bytes must land, and what must be there before this job is
    /// acknowledged. `None` for a job that only clears a marker — a reservation
    /// released by a call that was refused before it could be dispatched publishes
    /// nothing, so there is no object to make durable.
    write: Option<(PathBuf, Vec<u8>)>,
    /// A reservation marker to unlink once the write is durable. Its own removal is
    /// deliberately not made durable: a lost unlink leaves a stale marker, which
    /// over-reports indeterminacy — the safe direction.
    clear_marker: Option<PathBuf>,
    /// Sent ONLY after the durability boundary for this job has been crossed. Never on
    /// enqueue: a queued write that is acknowledged early is fire-and-forget with extra
    /// steps, and the serving path would emit a success for an exchange it cannot
    /// account for.
    ack: tokio::sync::oneshot::Sender<Result<(), std::io::Error>>,
}

/// Retains served exchanges so an auditor can attest to them later.
///
/// The filesystem work is owned by ONE dedicated thread, which is neither a runtime
/// worker nor a blocking-pool thread. The request future serializes the record, takes an
/// admission permit, hands the job over and AWAITS its acknowledgement — so the core's
/// runtime keeps running while the write is in progress, and there is no lock on the
/// request path at all: the writer owns the store outright.
///
/// It is not fire-and-forget. Nothing is acknowledged before it is durable, and the
/// serving path does not emit a success result until it has the acknowledgement — the
/// same guarantee the old inline write gave, minus the stalled core. Overload is refused
/// where refusing is free (before dispatch, HTTP 503, retry-safe), never dropped after
/// the backend has run.
pub struct EvidenceRetention {
    /// Read side. `get` needs no mutable state and never contends with the writer.
    reader: FsRetainedEvidenceStore,
    root: PathBuf,
    /// Hand-off to the writer thread.
    jobs: SyncSender<WriteJob>,
    /// Bounds concurrent reservations, and through them the queue.
    permits: Arc<tokio::sync::Semaphore>,
    /// Joined on drop, so a dropped store has no writes still in flight.
    writer: Option<std::thread::JoinHandle<()>>,
}

impl Drop for EvidenceRetention {
    fn drop(&mut self) {
        // Dropping the last sender ends the writer's receive loop; the join then waits
        // for the batch it may be in the middle of.
        let (dead, _) = std::sync::mpsc::sync_channel(1);
        let live = std::mem::replace(&mut self.jobs, dead);
        drop(live);
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

/// Drain, write, take ONE directory barrier for the batch, then acknowledge.
///
/// The order is the whole contract: no job is acknowledged until the `fsync` covering its
/// rename has returned, so a batch is a durability optimisation over jobs that were each
/// admitted individually — never a transaction over them, and never an early success.
fn write_loop(store: FsRetainedEvidenceStore, jobs: Receiver<WriteJob>) {
    loop {
        let Ok(first) = jobs.recv() else { return };
        let mut batch = vec![first];
        while batch.len() < MAX_WRITE_BATCH {
            match jobs.try_recv() {
                Ok(job) => batch.push(job),
                Err(_) => break,
            }
        }

        let staged: Vec<std::io::Result<()>> = batch
            .iter()
            .map(|job| match &job.write {
                Some((path, bytes)) => store.stage_at(path, bytes),
                None => Ok(()),
            })
            .collect();
        let published = batch
            .iter()
            .zip(&staged)
            .any(|(job, staged)| job.write.is_some() && staged.is_ok());
        let barrier = if published { store.sync_root() } else { Ok(()) };

        for (job, staged) in batch.into_iter().zip(staged) {
            let outcome = staged.and_then(|()| match &barrier {
                Ok(()) => Ok(()),
                // `io::Error` is not `Clone`; the batch shares one failure, so each
                // caller is given an equivalent one.
                Err(e) => Err(std::io::Error::new(e.kind(), e.to_string())),
            });
            if outcome.is_ok() {
                if let Some(marker) = &job.clear_marker {
                    if let Err(e) = std::fs::remove_file(marker) {
                        if e.kind() != std::io::ErrorKind::NotFound {
                            let stored = match &job.write {
                                Some((path, _)) => path.display().to_string(),
                                None => "nothing (the call was refused before dispatch)".to_owned(),
                            };
                            eprintln!(
                                "retained evidence: hop {stored} is stored but its \
                                 reservation marker {} could not be cleared ({e}); an \
                                 auditor will see it as indeterminate",
                                marker.display()
                            );
                        }
                    }
                }
            }
            let _ = job.ack.send(outcome);
        }
    }
}

/// Durable acceptance of responsibility for one exchange, taken BEFORE the backend runs.
///
/// Holding one means a `<request-digest>.pending` marker is on disk. It is consumed by
/// [`EvidenceRetention::complete`] once the exchange is retained, or by
/// [`EvidenceRetention::release_before_dispatch`] if the call is refused while the
/// backend is still untouched; a marker that outlives the process is the record
/// that this exact request crossed the execution threshold and its outcome was never
/// retained — the one fact an auditor otherwise cannot recover, because the completed
/// hop is precisely what failed to be written.
#[derive(Debug)]
pub struct RetentionReservation {
    digest: EvidenceDigest,
    /// Returned on drop, so a request that dies on any path gives its slot back. Held
    /// for the whole span from `reserve` to `complete`, which is what guarantees the
    /// completion job always has somewhere to go.
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl RetentionReservation {
    /// The request digest this reservation is keyed by.
    pub fn digest(&self) -> &EvidenceDigest {
        &self.digest
    }
}

impl EvidenceRetention {
    /// Open (creating if absent) a retention store rooted at `dir`, proving it writable
    /// and starting its writer thread.
    pub fn open(dir: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        Self::open_bounded(dir, MAX_RESERVATIONS)
    }

    /// [`EvidenceRetention::open`] with an explicit reservation ceiling, so the overload
    /// behaviour can be exercised without standing up [`MAX_RESERVATIONS`] of them.
    fn open_bounded(
        dir: impl AsRef<std::path::Path>,
        max_reservations: usize,
    ) -> std::io::Result<Self> {
        let root = dir.as_ref().to_path_buf();
        let reader = FsRetainedEvidenceStore::open(&root)?;
        let writer_store = FsRetainedEvidenceStore::open(&root)?;
        let (jobs, receiver) =
            std::sync::mpsc::sync_channel(write_queue_capacity(max_reservations));
        let writer = std::thread::Builder::new()
            .name("mcp-re-retention".to_owned())
            .spawn(move || write_loop(writer_store, receiver))?;
        Ok(EvidenceRetention {
            reader,
            root,
            jobs,
            permits: Arc::new(tokio::sync::Semaphore::new(max_reservations)),
            writer: Some(writer),
        })
    }

    /// Hand one job to the writer and await its acknowledgement.
    ///
    /// The `await` is the point of the whole arrangement: the runtime worker is free
    /// while the fsync runs. Every failure mode — a full queue, a dead writer, a dropped
    /// acknowledgement — is a store failure, never a silent success.
    async fn durable_write(
        &self,
        path: PathBuf,
        bytes: Vec<u8>,
        clear_marker: Option<PathBuf>,
    ) -> Result<(), RetentionError> {
        self.submit(Some((path, bytes)), clear_marker).await
    }

    /// Hand the writer a job and await its acknowledgement.
    async fn submit(
        &self,
        write: Option<(PathBuf, Vec<u8>)>,
        clear_marker: Option<PathBuf>,
    ) -> Result<(), RetentionError> {
        let (ack, acked) = tokio::sync::oneshot::channel();
        self.jobs
            .try_send(WriteJob {
                write,
                clear_marker,
                ack,
            })
            .map_err(|_| {
                RetentionError::Store(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "retention writer is not accepting work",
                ))
            })?;
        match acked.await {
            Ok(result) => result.map_err(RetentionError::Store),
            Err(_) => Err(RetentionError::Store(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "retention writer stopped before acknowledging the write",
            ))),
        }
    }

    /// The marker path for a reservation.
    ///
    /// The digest is base64url, so it is already a safe single path segment; the
    /// `.pending` extension keeps it out of the content-addressed namespace, which is
    /// read back by bare digest and can therefore never resolve to one of these.
    fn pending_path(&self, digest: &EvidenceDigest) -> std::path::PathBuf {
        self.root.join(format!("{}.pending", digest.as_str()))
    }

    /// Take durable responsibility for an exchange BEFORE its side effects run.
    ///
    /// A store that cannot accept this must stop the call reaching the backend, which
    /// is the only point at which refusing is still free. This is NOT a health probe
    /// and does not claim the later write will succeed — nothing here can, since the
    /// backend and the store share no transaction. What it establishes is that the
    /// crossing of the execution threshold is itself durable, so a failure afterwards
    /// is a recorded state rather than an inference.
    ///
    /// Keyed by the digest of the request bytes, which is a sound call identity exactly
    /// because retention sits behind the replay tier: two byte-identical admitted
    /// requests cannot exist, the second being refused as a replay.
    /// Taking a permit is also the queue's admission decision, and it is taken HERE for
    /// both of the call's writes. A full queue is therefore an
    /// `ABORTED_BEFORE_EXECUTION` refusal — 503, backend untouched, retry safe — and
    /// never a completion the writer had no room for.
    pub async fn reserve(
        &self,
        request: &HttpRequest,
    ) -> Result<RetentionReservation, RetentionError> {
        let permit = Arc::clone(&self.permits).try_acquire_owned().map_err(|_| {
            RetentionError::Store(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "retention queue is full",
            ))
        })?;
        let bytes = serde_json::to_vec(&retained_request(request))
            .map_err(|_| RetentionError::Malformed("retained request does not serialize"))?;
        let digest = EvidenceDigest::of(&bytes);
        // A marker that is not durable proves nothing about a call that is about to
        // have effects, so the acknowledgement is awaited before the caller may
        // dispatch.
        self.durable_write(self.pending_path(&digest), bytes, None)
            .await?;
        Ok(RetentionReservation {
            digest,
            _permit: permit,
        })
    }

    /// Complete a reservation with the exchange the backend actually produced.
    ///
    /// The hop is written first and the marker cleared only after it lands, so an
    /// interruption between them leaves the marker — over-reporting indeterminacy,
    /// which is the safe direction. A failure to clear the marker after a successful
    /// hop write is likewise not an error for the caller: it costs an auditor one
    /// reconciliation, whereas failing the exchange there would refuse a call whose
    /// evidence is on disk.
    pub async fn complete(
        &self,
        reservation: &RetentionReservation,
        request: &HttpRequest,
        response: &HttpResponse,
    ) -> Result<EvidenceDigest, RetentionError> {
        let bytes = serde_json::to_vec(&RetainedHopRecord::of(request, response))
            .map_err(|_| RetentionError::Malformed("retained hop does not serialize"))?;
        let digest = EvidenceDigest::of(&bytes);
        let path = self.object_path(&digest)?;
        let marker = self.pending_path(&reservation.digest);
        self.durable_write(path, bytes, Some(marker)).await?;
        Ok(digest)
    }

    /// Give a reservation back for a call that was refused BEFORE the backend ran.
    ///
    /// A marker says one thing: this request crossed the execution threshold and its
    /// outcome was never retained. A call refused between `reserve` and dispatch did not
    /// cross it, so leaving its marker asserts an execution that provably never happened
    /// — it collapses did-not-run into unknown-if-ran in the direction that invents
    /// indeterminacy, and it keeps the request's covered headers, this profile's live
    /// bearer token and DPoP proof among them, in the store for an exchange the boundary
    /// refused.
    ///
    /// The caller therefore owes this call on exactly one path: a refusal taken while
    /// the backend is still untouched. Calling it once dispatch has begun would erase
    /// the one fact an auditor cannot recover afterwards, which is why it consumes the
    /// reservation rather than being available to a handle that has been completed.
    ///
    /// Failing to clear the marker is not the caller's error to handle — the refusal
    /// stands either way, and a stale marker over-reports indeterminacy, which is the
    /// safe direction.
    pub async fn release_before_dispatch(&self, reservation: RetentionReservation) {
        let marker = self.pending_path(&reservation.digest);
        let _ = self.submit(None, Some(marker)).await;
    }

    /// The digest tokens of every reservation marker currently on disk.
    ///
    /// The reconciliation read. A marker records an exchange whose outcome was never
    /// retained, and a fact recorded where nothing can enumerate it is not a record an
    /// auditor can act on: this is how the audit lane asks which calls crossed the
    /// execution threshold without landing a hop.
    pub fn pending_reservations(&self) -> Result<Vec<String>, RetentionError> {
        let mut pending = Vec::new();
        for entry in std::fs::read_dir(&self.root).map_err(RetentionError::Store)? {
            let entry = entry.map_err(RetentionError::Store)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if let Some(digest) = name.strip_suffix(".pending") {
                pending.push(digest.to_owned());
            }
        }
        pending.sort();
        Ok(pending)
    }

    /// Retain one exchange with NO execution boundary, returning its handle.
    ///
    /// NOT the serving path's entry point — that is [`EvidenceRetention::reserve`] then
    /// [`EvidenceRetention::complete`], and the serving path refuses an accepted exit
    /// that reached completion without a reservation. This is for a caller with nothing
    /// to dispatch: importing a hop, or a test. Using it to retain a call that had side
    /// effects would leave no record that the execution threshold was crossed, which is
    /// the one fact an auditor cannot recover afterwards.
    pub async fn retain(
        &self,
        request: &HttpRequest,
        response: &HttpResponse,
    ) -> Result<EvidenceDigest, RetentionError> {
        // The same admission permit a reservation holds, so the queue-capacity argument
        // covers every job that can reach the writer rather than most of them.
        let _permit = Arc::clone(&self.permits).try_acquire_owned().map_err(|_| {
            RetentionError::Store(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "retention queue is full",
            ))
        })?;
        let bytes = serde_json::to_vec(&RetainedHopRecord::of(request, response))
            .map_err(|_| RetentionError::Malformed("retained hop does not serialize"))?;
        let digest = EvidenceDigest::of(&bytes);
        let path = self.object_path(&digest)?;
        self.durable_write(path, bytes, None).await?;
        Ok(digest)
    }

    /// The content-addressed path for `digest`, refusing a name that is not a base64url
    /// token — the store's own guard, applied on the write side too.
    fn object_path(&self, digest: &EvidenceDigest) -> Result<PathBuf, RetentionError> {
        let name = digest.as_str();
        let safe = !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !safe {
            return Err(RetentionError::Malformed("evidence digest is not a token"));
        }
        Ok(self.root.join(name))
    }

    /// Read back one retained exchange.
    ///
    /// `Ok(None)` means the store does not hold it — an auditor, not the store, decides
    /// whether a missing hop is fatal for the reconstruction being attempted.
    pub fn load(&self, digest: &EvidenceDigest) -> Result<Option<RetainedHop>, RetentionError> {
        let Some(bytes) = self.reader.get(digest).map_err(RetentionError::Store)? else {
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
/// `audit` carries the two full-profile inputs the retained bytes cannot supply — the
/// verifier's own audience tuple and the artifact credential surface — so a `Complete`
/// label asserts what an admission asserts rather than the minimal proof path.
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
    audit: &mcp_re_http_profile::ChainAudit<'_>,
    is_revoked: &dyn Fn(&str) -> bool,
    now: i64,
    issuer_kid: &str,
    bindings_commitment: Option<String>,
    verified_context_commitment: Option<String>,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, mcp_re_http_profile::HttpProfileError>,
) -> Result<Attestation, AttestError> {
    let retained = retention.load_chain(hops).map_err(AttestError::Retention)?;
    let reconstruction = mcp_re_http_profile::reconstruct_chain(
        &retained,
        resolve_actor,
        expect,
        audit,
        is_revoked,
        now,
    );
    let commitment = mcp_re_http_profile::scitt::EvidenceCommitment::from_reconstruction(
        &reconstruction,
        bindings_commitment.clone(),
        verified_context_commitment.clone(),
    );
    let statement =
        mcp_re_http_profile::scitt::issue_signed_statement(issuer_kid, commitment, now, sign)
            .map_err(AttestError::Statement)?;
    // The self-check compares a record against the bytes it names, and a reconstruction
    // with no verified prefix — a chain that broke at hop 0, and the empty chain — names
    // none: two empty handles and a fold over nothing. `verify_retained_evidence` refuses
    // such a record rather than reporting a match that would equally hold for every
    // unrelated submission that failed the same way, so running it here would refuse to
    // attest exactly the records this seam exists for. The statement is still issued: its
    // label says which hop broke, and `commits_to_verified_evidence` is how any reader
    // tells that it identifies no particular call.
    if statement.commitment().commits_to_verified_evidence() {
        mcp_re_http_profile::scitt::verify_retained_evidence(
            statement.commitment(),
            &reconstruction,
            bindings_commitment,
            verified_context_commitment,
        )
        .map_err(AttestError::Statement)?;
    }
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
                headers: vec![
                    (
                        "signature-input".into(),
                        "mcp-re=(\"@method\" \"content-digest\" \"authorization\");keyid=\"k\""
                            .into(),
                    ),
                    ("signature".into(), "mcp-re=:AAAA:".into()),
                    ("content-digest".into(), "sha-256=:AAAA:".into()),
                    ("authorization".into(), "Bearer live-access-token".into()),
                    ("cookie".into(), "session=not-covered".into()),
                ],
                // Deliberately NOT valid UTF-8: a retained body is whatever went over
                // the wire, and an encoding that assumed text would corrupt it.
                body: vec![0x00, 0xff, 0x7b, 0x7d],
            },
            HttpResponse {
                status: 200,
                headers: vec![
                    (
                        "signature-input".into(),
                        "mcp-re-response=(\"@status\" \"content-digest\");keyid=\"k\"".into(),
                    ),
                    ("signature".into(), "mcp-re-response=:BBBB:".into()),
                    ("content-digest".into(), "sha-256=:BBBB:".into()),
                ],
                body: b"{\"jsonrpc\":\"2.0\"}".to_vec(),
            },
        )
    }

    /// The retained headers are exactly the signed ones.
    fn covered(headers: &[(String, String)], label: &str) -> Vec<(String, String)> {
        covered_headers(headers, label)
    }

    #[tokio::test]
    async fn a_retained_exchange_comes_back_byte_identical() {
        let dir = TempDir::new("roundtrip");
        let retention = EvidenceRetention::open(&dir.0).expect("open");
        let (request, response) = exchange();

        let digest = retention.retain(&request, &response).await.expect("retain");
        let hop = retention.load(&digest).expect("load").expect("present");

        assert_eq!(hop.request.method, request.method);
        assert_eq!(hop.request.target_uri, request.target_uri);
        assert_eq!(
            hop.request.headers,
            covered(&request.headers, mcp_re_http_profile::REQUEST_LABEL)
        );
        assert_eq!(
            hop.request.body, request.body,
            "a retained body is whatever went over the wire, bytes and all"
        );
        assert_eq!(hop.response.status, response.status);
        assert_eq!(
            hop.response.headers,
            covered(&response.headers, mcp_re_http_profile::RESPONSE_LABEL)
        );
        assert_eq!(hop.response.body, response.body);
    }

    /// R7-C075/C076: a retained record keeps the SIGNED headers and nothing else.
    ///
    /// `authorization` stays because this profile requires it to be covered and the
    /// signature base cannot be recomputed without it — digesting it would make the hop
    /// unverifiable, which is the one thing retention exists to enable. What must not
    /// be there is every OTHER credential the client happened to send: no auditor can
    /// use them, so keeping them is exposure bought for nothing.
    #[tokio::test]
    async fn only_the_signed_headers_are_retained() {
        let dir = TempDir::new("covered");
        let retention = EvidenceRetention::open(&dir.0).expect("open");
        let (request, response) = exchange();

        let digest = retention.retain(&request, &response).await.expect("retain");
        let hop = retention.load(&digest).expect("load").expect("present");

        let names: Vec<&str> = hop
            .request
            .headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        assert!(
            !names.contains(&"cookie"),
            "an UNCOVERED credential header was written to the store: {names:?}"
        );
        assert!(
            names.contains(&"authorization"),
            "a covered header is part of the signature base and cannot be dropped"
        );
        assert!(names.contains(&"content-digest") && names.contains(&"signature"));
        // And what is written to disk contains no trace of it either.
        let raw = std::fs::read(dir.0.join(digest.as_str())).expect("read the object");
        assert!(
            !String::from_utf8_lossy(&raw).contains("session=not-covered"),
            "the uncovered credential reached the file"
        );
    }

    /// A `keyid` (or any other signature parameter) that happens to name a header must
    /// not widen what is kept: only the `( … )` component list is the covered set.
    #[test]
    fn a_signature_parameter_cannot_widen_the_covered_set() {
        let headers = vec![
            (
                "Signature-Input".to_owned(),
                "mcp-re=(\"@method\");keyid=\"cookie\"".to_owned(),
            ),
            ("cookie".to_owned(), "session=secret".to_owned()),
        ];
        let kept = covered_headers(&headers, mcp_re_http_profile::REQUEST_LABEL);
        assert!(
            !kept.iter().any(|(name, _)| name == "cookie"),
            "kept {kept:?}"
        );
    }

    /// R8-C042/C121: a second dictionary member is not the covered set.
    ///
    /// The verifier reads ONE member and ignores every other, so a value carrying a
    /// decoy label verifies exactly as it would without it. If retention unioned the
    /// members instead, an enrolled client could name any header it liked — its own
    /// `cookie`, or an internal header an ingress adds that the client cannot even read
    /// — and have it written verbatim into a store of credential material with no
    /// expiry.
    #[test]
    fn a_decoy_dictionary_member_cannot_widen_the_covered_set() {
        let headers = vec![
            (
                "Signature-Input".to_owned(),
                "mcp-re=(\"@method\" \"authorization\");keyid=\"k\", \
                 decoy=(\"cookie\" \"x-forwarded-client-cert\")"
                    .to_owned(),
            ),
            ("authorization".to_owned(), "Bearer live".to_owned()),
            ("cookie".to_owned(), "session=secret".to_owned()),
            (
                "x-forwarded-client-cert".to_owned(),
                "By=spiffe://mesh".to_owned(),
            ),
        ];
        let kept = covered_headers(&headers, mcp_re_http_profile::REQUEST_LABEL);
        let names: Vec<&str> = kept.iter().map(|(name, _)| name.as_str()).collect();
        assert!(
            !names.contains(&"cookie") && !names.contains(&"x-forwarded-client-cert"),
            "an unverified dictionary member decided what is retained: {names:?}"
        );
        assert!(
            names.contains(&"authorization"),
            "the verified member's own covered header must still be kept: {names:?}"
        );
    }

    /// R8-C042: a component's own parameters are not component names.
    ///
    /// `("@method";key="cookie")` names one component. Reading every quoted token in the
    /// list would read the parameter VALUE as a second one, so the widening the previous
    /// test closes at the dictionary level would simply move inside the parentheses.
    #[test]
    fn an_in_list_component_parameter_cannot_widen_the_covered_set() {
        let headers = vec![
            (
                "Signature-Input".to_owned(),
                "mcp-re=(\"@method\";key=\"cookie\" \"content-digest\")".to_owned(),
            ),
            ("cookie".to_owned(), "session=secret".to_owned()),
            ("content-digest".to_owned(), "sha-256=:AAAA:".to_owned()),
        ];
        let kept = covered_headers(&headers, mcp_re_http_profile::REQUEST_LABEL);
        let names: Vec<&str> = kept.iter().map(|(name, _)| name.as_str()).collect();
        assert!(
            !names.contains(&"cookie"),
            "a component parameter value was read as a covered header: {names:?}"
        );
        assert!(names.contains(&"content-digest"), "kept {names:?}");
    }

    /// R8-C093: a call refused before dispatch takes its marker with it.
    ///
    /// A marker asserts that this request crossed the execution threshold. A refusal
    /// taken while the backend is untouched did not, so leaving the marker would invent
    /// an indeterminacy that never existed — and would leave the request's covered
    /// headers, live bearer token included, on disk for an exchange the boundary
    /// refused.
    #[tokio::test]
    async fn a_reservation_released_before_dispatch_leaves_nothing_behind() {
        let dir = TempDir::new("released");
        let retention = EvidenceRetention::open(&dir.0).expect("open");
        let (request, _) = exchange();

        let reservation = retention.reserve(&request).await.expect("reserve");
        let marker = dir
            .0
            .join(format!("{}.pending", reservation.digest().as_str()));
        assert!(marker.exists(), "the marker is durable before dispatch");
        assert_eq!(
            retention.pending_reservations().expect("list"),
            vec![reservation.digest().as_str().to_owned()],
            "an unfinished reservation is enumerable, or nothing can reconcile it"
        );

        retention.release_before_dispatch(reservation).await;

        assert!(
            !marker.exists(),
            "a call that never reached the backend left a credential-bearing marker \
             that only a successful completion can ever remove"
        );
        assert!(retention.pending_reservations().expect("list").is_empty());
    }

    /// A reservation that is merely DROPPED keeps its marker. Dropping is what a request
    /// that died mid-flight does, and for that one the outcome genuinely is unknown.
    #[tokio::test]
    async fn a_dropped_reservation_keeps_its_marker() {
        let dir = TempDir::new("dropped");
        let retention = EvidenceRetention::open(&dir.0).expect("open");
        let (request, _) = exchange();

        let reservation = retention.reserve(&request).await.expect("reserve");
        let marker = dir
            .0
            .join(format!("{}.pending", reservation.digest().as_str()));
        drop(reservation);

        assert!(
            marker.exists(),
            "over-reporting indeterminacy is the safe direction; a dropped reservation \
             must not read as a call that never ran"
        );
    }

    /// Content addressing makes retention idempotent: the same exchange retained twice
    /// is one object under one handle.
    #[tokio::test]
    async fn retaining_the_same_exchange_twice_yields_one_object() {
        let dir = TempDir::new("idempotent");
        let retention = EvidenceRetention::open(&dir.0).expect("open");
        let (request, response) = exchange();
        let first = retention.retain(&request, &response).await.expect("retain");
        let second = retention
            .retain(&request, &response)
            .await
            .expect("retain again");
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
        // Written through a second handle on the same directory: the retention store is
        // owned outright by its writer thread, which is what removed the lock from the
        // request path.
        let digest = {
            let mut store = FsRetainedEvidenceStore::open(&dir.0).expect("open");
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
    #[tokio::test]
    async fn a_chain_with_a_missing_hop_is_refused_rather_than_reconstructed() {
        let dir = TempDir::new("gap");
        let retention = EvidenceRetention::open(&dir.0).expect("open");
        let (request, response) = exchange();
        let present = retention.retain(&request, &response).await.expect("retain");
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

    /// R7-C001/C002/C028/C046: the write must not run on the runtime worker.
    ///
    /// The per-core runtime is `new_current_thread`, so a spawned task is polled ONLY
    /// while the task doing the retaining is suspended at an `await`. An inline
    /// filesystem write has no await point at all — it returns to its caller without
    /// ever handing the runtime back — so the spawned task below could not run before
    /// the loop finished, and the flag would still be false. It runs here because the
    /// request future genuinely yields while the writer thread performs the fsync.
    #[test]
    fn the_fsync_does_not_run_on_the_runtime_worker() {
        let dir = TempDir::new("yields");
        let retention = EvidenceRetention::open(&dir.0).expect("open");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime, exactly like a serving core");

        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        runtime.block_on(async {
            let flag = Arc::clone(&ran);
            tokio::spawn(async move {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            });
            let (request, response) = exchange();
            for i in 0..200u32 {
                let mut request = request.clone();
                request.body.extend_from_slice(&i.to_be_bytes());
                retention.retain(&request, &response).await.expect("retain");
            }
        });

        assert!(
            ran.load(std::sync::atomic::Ordering::SeqCst),
            "nothing else on this core ran while evidence was being written: the fsync \
             is back on the runtime worker, which freezes the core's accept loop and \
             every other in-flight request on it"
        );
    }

    /// R7-C001/C002/C028: acknowledged means DURABLE, never merely enqueued.
    ///
    /// A queue whose completion is acknowledged on enqueue is fire-and-forget with extra
    /// steps: the serving path would emit a success for an exchange whose evidence is
    /// still only in memory. The bytes must be readable at their final name the instant
    /// the await returns.
    #[tokio::test]
    async fn an_acknowledged_write_is_already_at_its_final_name() {
        let dir = TempDir::new("acked");
        let retention = EvidenceRetention::open(&dir.0).expect("open");
        let (request, response) = exchange();

        let digest = retention.retain(&request, &response).await.expect("retain");

        assert!(
            dir.0.join(digest.as_str()).exists(),
            "the acknowledgement came back before the object was published"
        );
    }

    /// R7-C001/C002/C028: overload is refused BEFORE dispatch, and the slot comes back.
    ///
    /// The queue bound has to be applied at the one point where refusing is still free
    /// and genuinely retry-safe. `reserve` failing is that refusal — the serving path
    /// maps it to `evidence_retention_unavailable`/503 with the backend untouched.
    #[tokio::test]
    async fn a_full_reservation_queue_is_refused_at_reserve_and_the_slot_returns() {
        let dir = TempDir::new("full");
        let retention = EvidenceRetention::open_bounded(&dir.0, 2).expect("open");
        let (request, _) = exchange();
        let mut other = request.clone();
        other.body.push(0x01);
        let mut third = request.clone();
        third.body.push(0x02);

        let first = retention.reserve(&request).await.expect("first reserves");
        let second = retention.reserve(&other).await.expect("second reserves");
        assert!(
            retention.reserve(&third).await.is_err(),
            "a call beyond the ceiling must be refused before it can be dispatched"
        );

        drop(second);
        retention
            .reserve(&third)
            .await
            .expect("a returned slot admits the next call");
        drop(first);
    }

    /// R7-C001/C002/C028: a completion is NEVER refused for capacity.
    ///
    /// This is what the whole permit scheme buys. The backend has already run by the
    /// time `complete` is called, so a capacity refusal there would be a post-execution
    /// drop — the one outcome the design forbids. Every reservation that exists has a
    /// queue slot reserved for its completion.
    #[tokio::test]
    async fn completion_is_never_refused_for_capacity() {
        let dir = TempDir::new("capacity");
        let retention = EvidenceRetention::open_bounded(&dir.0, 3).expect("open");
        let (request, response) = exchange();

        let mut held = Vec::new();
        for i in 0..3u8 {
            let mut request = request.clone();
            request.body.push(i);
            held.push((
                request.clone(),
                retention.reserve(&request).await.expect("reserve"),
            ));
        }
        // Every permit is now taken, so no further call could be admitted.
        assert!(retention.reserve(&request).await.is_err());

        for (request, reservation) in &held {
            retention
                .complete(reservation, request, &response)
                .await
                .expect("a reserved call always has somewhere to put its evidence");
        }
    }

    /// The reservation marker is durable before the caller may dispatch, and is cleared
    /// once the hop it stands for is itself durable.
    #[tokio::test]
    async fn a_reservation_marker_is_durable_before_dispatch_and_cleared_after() {
        let dir = TempDir::new("marker");
        let retention = EvidenceRetention::open(&dir.0).expect("open");
        let (request, response) = exchange();

        let reservation = retention.reserve(&request).await.expect("reserve");
        let marker = dir
            .0
            .join(format!("{}.pending", reservation.digest().as_str()));
        assert!(
            marker.exists(),
            "the backend must not be reachable before the marker is on disk"
        );

        let digest = retention
            .complete(&reservation, &request, &response)
            .await
            .expect("complete");

        assert!(dir.0.join(digest.as_str()).exists(), "the hop is retained");
        assert!(!marker.exists(), "its marker is consumed");
    }
}
