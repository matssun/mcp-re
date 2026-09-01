// SPDX-License-Identifier: Apache-2.0
//! WHEN responsibility for retaining an exchange has been durably established.
//!
//! A different authority from [`super::retained_record`], and the distinction is the whole
//! design: that one says what an auditor will find, this one says at what INSTANT the
//! deployment became answerable for it — and therefore at what instant it may serve.
//!
//! The order is what makes the guarantee real. A reservation is admitted BEFORE the request
//! is dispatched, which is the last point at which refusing is still free and genuinely
//! retry-safe; the write is completed, and its durability barrier crossed, before the
//! response goes out. A deployment that acknowledged first and wrote later would be
//! asserting it could account for a call while the evidence was still in a queue.
//!
//! The queue is bounded by the reservations, not the other way round: a reservation
//! contributes at most one queued job at any instant, so `K` reservations bound the queue at
//! `K` jobs. Exceeding the ceiling is refused before dispatch.
//!
//! Nothing here decides what a record CONTAINS, and nothing in the record owner decides
//! when a write has landed. Two copies of either fact is how they would come to disagree.

use super::durability_bounds::write_queue_capacity;
use super::durability_bounds::MAX_RESERVATIONS;
use std::path::PathBuf;
use std::sync::mpsc::SyncSender;
use std::sync::Arc;

use mcp_re_http_profile::scitt::EvidenceDigest;
use mcp_re_http_profile::scitt::RetainedEvidenceStore;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;

use crate::retained_evidence::FsRetainedEvidenceStore;

use mcp_re_http_profile::chain::RetainedHop;

use super::dispatch_committed::PENDING_EXTENSION;
use super::durable_job::JobFault;
use super::durable_job::JobKind;
use super::durable_job::WriteJob;
use super::durable_writer::write_loop;
use super::reservation_marker::ReservationMarker;
use super::reserved_before_dispatch::RESERVED_EXTENSION;
use super::retained_record::retained_request;
use super::retained_record::RetainedHopRecord;
use super::DispatchCommitted;
use super::ReservedBeforeDispatch;
use super::RetentionError;

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

    /// Hand the writer a job and await its acknowledgement.
    ///
    /// The `await` is the point of the whole arrangement: the runtime worker is free
    /// while the fsync runs. Every failure mode — a full queue, a dead writer, a dropped
    /// acknowledgement — is a store failure, never a silent success.
    async fn submit(&self, kind: JobKind) -> Result<(), RetentionError> {
        let (ack, acked) = tokio::sync::oneshot::channel();
        self.jobs.try_send(WriteJob::new(kind, ack)).map_err(|_| {
            RetentionError::Store(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "retention writer is not accepting work",
            ))
        })?;
        match acked.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(JobFault::NotPublished(e))) => Err(RetentionError::Store(e)),
            Ok(Err(JobFault::Unwithdrawn(e))) => Err(RetentionError::Unresolved(e)),
            Err(_) => Err(RetentionError::Store(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "retention writer stopped before acknowledging the write",
            ))),
        }
    }

    /// The path for a marker at `stage`.
    ///
    /// The digest is base64url, so it is already a safe single path segment; the extension
    /// keeps it out of the content-addressed namespace, which is read back by bare digest
    /// and can therefore never resolve to one of these.
    fn marker_path(&self, digest: &EvidenceDigest, stage: &str) -> PathBuf {
        self.root.join(format!("{}.{stage}", digest.as_str()))
    }

    /// Accept durable responsibility for an exchange, WITHOUT asserting that anything ran.
    ///
    /// A store that cannot accept this must stop the call reaching the backend, which is
    /// the only point at which refusing is still free. This is NOT a health probe and does
    /// not claim the later writes will succeed — nothing here can, since the backend and
    /// the store share no transaction.
    ///
    /// What it establishes is narrower than what its predecessor claimed, and the
    /// narrowing is the point. The marker it publishes is at the RESERVED stage: it says
    /// an obligation was accepted, and it says nothing about execution. The crossing of
    /// the execution threshold is recorded separately, by
    /// [`commit_to_dispatch`](Self::commit_to_dispatch), because one artefact asked to
    /// mean both left a refused call indistinguishable from one whose backend may have
    /// acted (R9-C004, R9-C099).
    ///
    /// Keyed by the digest of the request bytes, which is a sound call identity exactly
    /// because retention sits behind the replay tier: two byte-identical admitted requests
    /// cannot exist, the second being refused as a replay. The digest is computed over the
    /// retained request and the retained request is NOT persisted here — the digest
    /// commits to it, and a marker for a call that has not dispatched has no business
    /// holding the live credentials its covered headers carry.
    ///
    /// Taking a permit is also the queue's admission decision, and it is taken HERE for
    /// every job the call will submit. A full queue is therefore an
    /// `ABORTED_BEFORE_EXECUTION` refusal — 503, backend untouched, retry safe — and never
    /// a completion the writer had no room for.
    pub async fn reserve(
        &self,
        request: &HttpRequest,
    ) -> Result<ReservedBeforeDispatch, RetentionError> {
        let permit = Arc::clone(&self.permits).try_acquire_owned().map_err(|_| {
            RetentionError::Store(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "retention queue is full",
            ))
        })?;
        let digest = EvidenceDigest::of(
            &serde_json::to_vec(&retained_request(request))
                .map_err(|_| RetentionError::Malformed("retained request does not serialize"))?,
        );
        let marker = self.marker_path(&digest, RESERVED_EXTENSION);
        // A marker that is not durable proves nothing about an obligation the exchange is
        // about to rely on, so the acknowledgement is awaited before the caller may go on.
        self.submit(JobKind::PublishOrWithdraw {
            path: marker.clone(),
            bytes: ReservationMarker::of(&digest).to_bytes()?,
        })
        .await?;
        Ok(ReservedBeforeDispatch::over(
            digest,
            marker,
            self.jobs.clone(),
            Arc::new(permit),
        ))
    }

    /// Record that this exchange is committing to a dispatch. **The execution threshold.**
    ///
    /// Advances the reservation's marker from the reserved stage to the committed one, as
    /// a RENAME — which is what makes the two facts one artefact that changes what it
    /// asserts, rather than two that can both be present or both be missing. Awaited, so
    /// nothing is transmitted before the crossing is durable.
    ///
    /// Consumes the reservation. A caller cannot hold a `ReservedBeforeDispatch` and the
    /// `DispatchCommitted` it became, so *this exchange has not committed* and *this
    /// exchange may have executed* are never the same value in two places. On the way out
    /// the reservation drops, and its rescind unlinks a name this commitment has already
    /// moved — a no-op, and the reason no flag is needed to remember that it committed.
    ///
    /// # What a failure here is
    ///
    /// [`RetentionError::Store`] means nothing was published: the exchange did not
    /// dispatch and an ordinary retry is correct.
    /// [`RetentionError::Unresolved`] means the rename could not be made durable and could
    /// not be taken back, so a committed-stage marker may survive for an exchange that
    /// never dispatched. That is not an ordinary outage and must not be answered as one.
    pub async fn commit_to_dispatch(
        &self,
        reserved: ReservedBeforeDispatch,
    ) -> Result<DispatchCommitted, RetentionError> {
        let digest = reserved.digest().clone();
        self.submit(JobKind::Commit {
            reserved: reserved.marker().to_path_buf(),
            committed: self.marker_path(&digest, PENDING_EXTENSION),
        })
        .await?;
        Ok(DispatchCommitted::over(digest, reserved.permit()))
    }

    /// Complete a commitment with the exchange the backend actually produced.
    ///
    /// The hop is written first and the marker cleared only after it lands, so an
    /// interruption between them leaves the marker — over-reporting indeterminacy, which
    /// is the safe direction once the threshold has been crossed. A failure to clear the
    /// marker after a successful hop write is likewise not an error for the caller: it
    /// costs an auditor one reconciliation, whereas failing the exchange there would
    /// refuse a call whose evidence is on disk.
    ///
    /// A commitment is worth exactly one completion, and a second attempt is refused with
    /// [`RetentionError::AlreadyCompleted`] before any job is queued —
    /// [`DispatchCommitted`] owns that fact.
    pub async fn complete(
        &self,
        committed: &DispatchCommitted,
        request: &HttpRequest,
        response: &HttpResponse,
    ) -> Result<EvidenceDigest, RetentionError> {
        if !committed.take_completion() {
            return Err(RetentionError::AlreadyCompleted);
        }
        let bytes = serde_json::to_vec(&RetainedHopRecord::of(request, response))
            .map_err(|_| RetentionError::Malformed("retained hop does not serialize"))?;
        let digest = EvidenceDigest::of(&bytes);
        self.submit(JobKind::Publish {
            path: self.object_path(&digest)?,
            bytes,
            clear_marker: Some(self.marker_path(committed.digest(), PENDING_EXTENSION)),
        })
        .await?;
        Ok(digest)
    }

    /// The digest tokens of every COMMITTED marker currently on disk.
    ///
    /// The reconciliation read, and it reads one stage only. A committed-stage marker
    /// records an exchange that crossed the execution threshold and whose outcome was
    /// never retained, and a fact recorded where nothing can enumerate it is not a record
    /// an auditor can act on: this is how the audit lane asks which calls crossed without
    /// landing a hop.
    ///
    /// Reserved-stage markers are deliberately NOT here. They record obligations accepted
    /// by exchanges that never committed, so counting them would be counting refused calls
    /// as calls that may have run — the collapse this stage split exists to remove. They
    /// have their own enumerator, [`stale_reservations`](Self::stale_reservations), and it
    /// answers a different question.
    pub fn pending_reservations(&self) -> Result<Vec<String>, RetentionError> {
        self.markers_at(PENDING_EXTENSION)
    }

    /// The digest tokens of every RESERVED marker currently on disk.
    ///
    /// Cleanup debt, and nothing else. Each one is an obligation that was accepted by an
    /// exchange which then did not commit, and whose rescind did not land — a queue that
    /// was full when the reservation dropped, or a process that died between the two.
    ///
    /// An auditor must not read this as indeterminacy. That is the whole reason the stage
    /// has its own name on disk: a residue that says *nothing ran* is answerable by
    /// deleting it, and one that says *something may have* is not.
    pub fn stale_reservations(&self) -> Result<Vec<String>, RetentionError> {
        self.markers_at(RESERVED_EXTENSION)
    }

    /// The digest tokens of every marker at one stage.
    fn markers_at(&self, stage: &str) -> Result<Vec<String>, RetentionError> {
        let suffix = format!(".{stage}");
        let mut found = Vec::new();
        for entry in std::fs::read_dir(&self.root).map_err(RetentionError::Store)? {
            let entry = entry.map_err(RetentionError::Store)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if let Some(digest) = name.strip_suffix(&suffix) {
                found.push(digest.to_owned());
            }
        }
        found.sort();
        Ok(found)
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
        self.submit(JobKind::Publish {
            path,
            bytes,
            clear_marker: None,
        })
        .await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transparency::covered_set::covered_headers;

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

    /// A response, for the tests that only need the writer to make one round trip.
    fn response_of() -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![],
            body: b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}".to_vec(),
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
            let reserved = retention.reserve(&request).await.expect("reserve");
            held.push((
                request.clone(),
                retention
                    .commit_to_dispatch(reserved)
                    .await
                    .expect("commit"),
            ));
        }
        // Every permit is now taken, so no further call could be admitted.
        assert!(retention.reserve(&request).await.is_err());

        for (request, committed) in &held {
            retention
                .complete(committed, request, &response)
                .await
                .expect("a committed call always has somewhere to put its evidence");
        }
    }

    /// The two stages are two artefacts, and the commitment is the move between them.
    ///
    /// The property this pins is the one #741 exists for: at no instant does a single
    /// name have to mean both *an obligation was accepted* and *this call crossed the
    /// execution threshold*. Reserving publishes the reserved stage and only that;
    /// committing moves it; completing consumes it.
    #[tokio::test]
    async fn the_reserved_and_committed_stages_are_distinct_artefacts() {
        let dir = TempDir::new("marker");
        let retention = EvidenceRetention::open(&dir.0).expect("open");
        let (request, response) = exchange();

        let reserved = retention.reserve(&request).await.expect("reserve");
        let digest = reserved.digest().as_str().to_owned();
        let reserved_marker = dir.0.join(format!("{digest}.reserved"));
        let committed_marker = dir.0.join(format!("{digest}.pending"));
        assert!(
            reserved_marker.exists(),
            "the obligation must be durable before anything relies on it"
        );
        assert!(
            !committed_marker.exists(),
            "accepting an obligation must not assert that anything crossed"
        );
        assert_eq!(
            retention.pending_reservations().expect("list"),
            Vec::<String>::new(),
            "a reservation is not a crossing, and reconciliation must not count it as one"
        );

        let committed = retention
            .commit_to_dispatch(reserved)
            .await
            .expect("commit");
        assert!(
            !reserved_marker.exists(),
            "the commitment MOVES the marker; two artefacts would let one be lost"
        );
        assert!(
            committed_marker.exists(),
            "the backend must not be reachable before the crossing is on disk"
        );
        assert_eq!(
            retention.pending_reservations().expect("list"),
            vec![digest.clone()],
            "a crossing that never lands a hop is what an auditor reconciles"
        );

        let hop = retention
            .complete(&committed, &request, &response)
            .await
            .expect("complete");

        assert!(dir.0.join(hop.as_str()).exists(), "the hop is retained");
        assert!(!committed_marker.exists(), "its marker is consumed");
        assert!(retention.pending_reservations().expect("list").is_empty());
    }

    /// The marker holds the exchange's digest and none of its credentials.
    ///
    /// R9-C099, asserted on the BYTES. The predecessor wrote `retained_request(request)`
    /// into the marker at `reserve` — covered headers included, which for this profile
    /// means the live bearer and the DPoP proof — before the call had dispatched, into a
    /// store with no expiry, for exchanges that were then sometimes refused.
    #[tokio::test]
    async fn a_marker_on_disk_carries_no_credential() {
        let dir = TempDir::new("no-credential");
        let retention = EvidenceRetention::open(&dir.0).expect("open");
        let (request, response) = exchange();

        let reserved = retention.reserve(&request).await.expect("reserve");
        let digest = reserved.digest().as_str().to_owned();
        let on_disk = std::fs::read_to_string(dir.0.join(format!("{digest}.reserved")))
            .expect("the reserved marker is readable");
        assert!(!on_disk.contains("Bearer"), "{on_disk}");
        assert!(!on_disk.contains("dpop"), "{on_disk}");
        assert!(on_disk.contains(&digest), "{on_disk}");

        // And the committed stage is the same bytes, because the commitment renames.
        let committed = retention
            .commit_to_dispatch(reserved)
            .await
            .expect("commit");
        let moved = std::fs::read_to_string(dir.0.join(format!("{digest}.pending")))
            .expect("the committed marker is readable");
        assert_eq!(moved, on_disk);

        // The completed hop is where the full retained message belongs, and it is there.
        let hop = retention
            .complete(&committed, &request, &response)
            .await
            .expect("complete");
        let retained = std::fs::read_to_string(dir.0.join(hop.as_str())).expect("hop");
        assert!(
            retained.contains("Bearer"),
            "the hop still carries what an auditor recomputes the handles from"
        );
    }

    /// One crossing of the execution threshold is worth one hop.
    ///
    /// A reservation holds one permit, and the queue bound is the reservation count times
    /// one job. A handle that could be completed again would put a second job behind that
    /// permit — so at the ceiling a completion could find the channel full, which is the
    /// post-execution drop the whole permit scheme exists to make impossible — and it
    /// would land a second hop object for a backend call that ran once, which an auditor
    /// counting hops reads as two calls.
    #[tokio::test]
    async fn a_reservation_is_worth_exactly_one_completion() {
        let dir = TempDir::new("one-completion");
        let retention = EvidenceRetention::open(&dir.0).expect("open");
        let (request, response) = exchange();

        let reserved = retention.reserve(&request).await.expect("reserve");
        let committed = retention
            .commit_to_dispatch(reserved)
            .await
            .expect("commit");
        let first = retention
            .complete(&committed, &request, &response)
            .await
            .expect("the reserved completion is always available");

        let mut second_response = response.clone();
        second_response.body = b"{\"jsonrpc\":\"2.0\",\"result\":\"again\"}".to_vec();
        let second = retention
            .complete(&committed, &request, &second_response)
            .await;

        assert!(
            matches!(second, Err(RetentionError::AlreadyCompleted)),
            "a completed commitment was completed again"
        );
        assert!(dir.0.join(first.as_str()).exists(), "the one hop is stored");
        let hops: Vec<String> = std::fs::read_dir(&dir.0)
            .expect("list")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|name| !name.ends_with(".pending") && !name.ends_with(".reserved"))
            .collect();
        assert_eq!(
            hops,
            vec![first.as_str().to_owned()],
            "one execution wrote more than one hop object"
        );
    }
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

    /// R8-C093 / R9-C004: a call that never committed takes its marker with it, and
    /// takes it on DROP.
    ///
    /// The predecessor had `release_before_dispatch`, and the operative question for
    /// whether a value owns an invariant is *can the check be deleted and still leave the
    /// forbidden state unconstructible?* For a call site the answer was no — and that call
    /// site was reachable only from tests, so the separation was not merely deletable but
    /// absent. This asserts the property with no call at all: the value goes out of scope,
    /// which is what a refusal, an early return and a cancelled request future all do.
    #[tokio::test]
    async fn a_reservation_that_never_commits_is_rescinded_by_being_dropped() {
        let dir = TempDir::new("rescinded");
        let retention = EvidenceRetention::open(&dir.0).expect("open");
        let (request, _) = exchange();

        let reserved = retention.reserve(&request).await.expect("reserve");
        let digest = reserved.digest().as_str().to_owned();
        let marker = dir.0.join(format!("{digest}.reserved"));
        assert!(
            marker.exists(),
            "the obligation is durable before it is relied on"
        );
        assert_eq!(
            retention.stale_reservations().expect("list"),
            vec![digest.clone()],
            "an accepted obligation is enumerable, or nothing can reconcile it"
        );

        drop(reserved);
        // The rescind is queued, not awaited — `Drop` cannot await. One round trip
        // through the writer is enough to observe it.
        retention
            .retain(&request, &response_of())
            .await
            .expect("a round trip through the writer");

        assert!(
            !marker.exists(),
            "a call that never committed left a marker only a completion could remove"
        );
        assert!(retention.stale_reservations().expect("list").is_empty());
        assert!(
            retention.pending_reservations().expect("list").is_empty(),
            "and it never produced a committed-stage marker at all"
        );
    }

    /// A COMMITMENT that is merely dropped keeps its marker.
    ///
    /// The other half of the asymmetry, and the reason the two states are two types.
    /// Dropping is what a request that died mid-flight does; past the commitment the
    /// outcome genuinely is unknown, so over-reporting indeterminacy is the safe
    /// direction — and only here. A `Drop` that rescinded this one too would erase the one
    /// fact an auditor cannot recover.
    #[tokio::test]
    async fn a_dropped_commitment_keeps_its_marker() {
        let dir = TempDir::new("dropped");
        let retention = EvidenceRetention::open(&dir.0).expect("open");
        let (request, _) = exchange();

        let reserved = retention.reserve(&request).await.expect("reserve");
        let digest = reserved.digest().as_str().to_owned();
        let marker = dir.0.join(format!("{digest}.pending"));
        let committed = retention
            .commit_to_dispatch(reserved)
            .await
            .expect("commit");
        drop(committed);
        retention
            .retain(&request, &response_of())
            .await
            .expect("a round trip through the writer");

        assert!(
            marker.exists(),
            "a dropped commitment must not read as a call that never ran"
        );
        assert_eq!(
            retention.pending_reservations().expect("list"),
            vec![digest]
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
}
