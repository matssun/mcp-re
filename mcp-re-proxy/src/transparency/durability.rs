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
use super::durability_bounds::MAX_WRITE_BATCH;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::SyncSender;
use std::sync::Arc;

use mcp_re_http_profile::scitt::EvidenceDigest;
use mcp_re_http_profile::scitt::RetainedEvidenceStore;
use mcp_re_http_profile::HttpRequest;
use mcp_re_http_profile::HttpResponse;

use crate::retained_evidence::FsRetainedEvidenceStore;

use mcp_re_http_profile::chain::RetainedHop;

use super::retained_record::retained_request;
use super::retained_record::RetainedHopRecord;
use super::RetentionError;

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
    /// The one completion this reservation is worth, taken by the first
    /// [`EvidenceRetention::complete`] that asks for it.
    completion: std::sync::atomic::AtomicBool,
}

impl RetentionReservation {
    /// The request digest this reservation is keyed by.
    pub fn digest(&self) -> &EvidenceDigest {
        &self.digest
    }

    /// Take this reservation's single completion, reporting whether it was still there.
    ///
    /// The permit is what makes the queue bound hold — `K` reservations bound the queue
    /// at `K` completion jobs — and a permit is held by a handle, not by a call. A
    /// completion that could be taken from the same handle twice would put two jobs
    /// behind one permit, so the count that bounds the queue would stop counting jobs.
    /// The swap is what makes the second taker lose even when both race.
    fn take_completion(&self) -> bool {
        self.completion
            .swap(false, std::sync::atomic::Ordering::AcqRel)
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
            completion: std::sync::atomic::AtomicBool::new(true),
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
    ///
    /// A reservation is worth exactly one completion, and a second attempt is refused
    /// with [`RetentionError::AlreadyCompleted`] before any job is queued. One crossing
    /// of the execution threshold produces one hop: a reservation that could be completed
    /// repeatedly would let one execution write N hop objects, so an auditor counting
    /// hops would count calls that never happened — and it would put N jobs behind the
    /// one permit that bounds the write queue, which is what makes a completion refusable
    /// for capacity after the backend has already run.
    pub async fn complete(
        &self,
        reservation: &RetentionReservation,
        request: &HttpRequest,
        response: &HttpResponse,
    ) -> Result<EvidenceDigest, RetentionError> {
        if !reservation.take_completion() {
            return Err(RetentionError::AlreadyCompleted);
        }
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

        let reservation = retention.reserve(&request).await.expect("reserve");
        let first = retention
            .complete(&reservation, &request, &response)
            .await
            .expect("the reserved completion is always available");

        let mut second_response = response.clone();
        second_response.body = b"{\"jsonrpc\":\"2.0\",\"result\":\"again\"}".to_vec();
        let second = retention
            .complete(&reservation, &request, &second_response)
            .await;

        assert!(
            matches!(second, Err(RetentionError::AlreadyCompleted)),
            "a completed reservation was completed again"
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
            .filter(|name| !name.ends_with(".pending"))
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
}
