// SPDX-License-Identifier: Apache-2.0
//! ADR-MCPRE-057 §4 — the per-exchange lifecycle, and the sibling machines it interacts
//! with, as values.
//!
//! # Why this exists
//!
//! The exchange machine is not new. `http_profile_serve::handle` has always moved through
//! these states; until now no value held which one it was in. Each state was a position of
//! the program counter, and its name existed only in a comment above the code that entered
//! it.
//!
//! That absence had a consequence, and it is the same shape as the one that produced this
//! module's sibling [`runtime_state`](crate::runtime_state). A refusal must state whether
//! the action it refused can simply be retried. Answering that requires knowing two facts
//! at once — whether the backend ran, and whether a human's approval was already spent —
//! and neither was represented, so each refusal site answered from source position instead.
//! One combination was reachable and unrepresented: a continuation consumed to enforce
//! one-shot, followed by a refusal before the dispatch. The approval is destroyed, the
//! action never ran, and the retry-safe reading is wrong in a way no local check could see.
//!
//! # One machine, two regions
//!
//! There is ONE exchange lifecycle, with a pre-dispatch region and a post-dispatch region
//! either side of a single irreversible effect:
//!
//! ```text
//! ... -> InnerPlaneAccepted -> RetentionReserved -> [DISPATCH] -> Dispatched -> ...
//! ```
//!
//! The response region is not a second machine standing beside the first. A response is an
//! EVENT presented to the current exchange state: raw backend bytes authorize nothing on
//! their own, and only a response legal for the state the exchange is actually in may
//! advance it.
//!
//! # The architecture: separate machines, invariants over the tuple
//!
//! Five machines are live during one exchange, and they are NOT combined into a product
//! enum (ADR-MCPRE-057 §4: the machines are not independent Cartesian products, and neither
//! are they enumerated as one).
//!
//! ```text
//! R in ExchangeState        where this exchange is in its own pipeline
//! C in ContinuationState   what has happened to the MRTR approval leg this exchange ANSWERED
//! B in BackendState        whether the inner server can have acted
//! O in ResponseOrigin      who authored the bytes about to be signed
//! L in OpenLeg             the fate of the leg this exchange's own reply OPENS
//! ```
//!
//! Correctness lives in invariants over projections of that tuple, not in an enumeration of
//! it. [`ExchangeProgress`] holds the tuple; [`ExchangeProgress::retry_semantics`] is the
//! first such invariant, and the one whose absence was a defect.
//! [`ExchangeProgress::invariant_violation`] is the rest.
//!
//! # What this is NOT
//!
//! **Not synchronization**, exactly as in [`runtime_state`](crate::runtime_state). Reading a
//! state is a read. One-shot continuation retirement is enforced where it is committed, by
//! the store's atomic `consume` — this type records that it happened, and must not replace
//! it.
//!
//! **Not a second source of truth.** The states below are entered by the operations that
//! establish them, and a state is not asserted alongside control flow that could disagree:
//! a transition IS the step. `transition` refuses anything else, and
//! [`ExchangeProgress::advance`] consults it — and the cross-machine invariants — on every
//! step of every build, release included. A refused step latches an anomaly that
//! [`ExchangeProgress::retry_semantics`] reports at full strength.
//!
//! **Not a framework.** Closed enums and exhaustive matches, per ADR-MCPRE-058 §12.
//! **Not public.** Exchange state is not a protocol surface (ADR-MCPRE-057 §18).

/// Where one exchange is in the serving pipeline.
///
/// The order is the pipeline order: a directed path with five terminals and exactly two
/// branches out of it — the notification arm's 202, leaving from the execution threshold,
/// and the open-leg/terminal split at the end.
///
/// That the path is otherwise total is what makes the interesting theorems statable.
/// `state >= Dispatched` is a meaningful predicate only because every exchange traverses
/// the same order; on a branching graph it would say nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ExchangeState {
    /// An HTTP message has been received. Nothing about it is trusted.
    Received,
    /// RFC 9421 + RFC 9530 verification succeeded, and an actor is resolved.
    Verified,
    /// The verified actor matches the mTLS peer identity (Mode-A binding).
    TransportBound,
    /// Admission currency holds (ADR-MCPRE-053 §7).
    AdmissionChecked,
    /// Any retained continuation bases have been recovered. `peek` only — see
    /// [`ContinuationState::Peeked`].
    ContinuationPrepared,
    /// Replay admission won and continuation binding checked; the nonce is burned.
    ReplayAdmitted,
    /// A delegated key is in hand, so a reply CAN be signed. Asked before anything
    /// irreversible, so that a missing key is not discovered after the backend has run.
    Answerable,
    /// The answer leg's continuation is retired. One-shot is committed here.
    ContinuationRetired,
    /// The proxy-owned `_meta` is stripped and the backend-bound body is prepared.
    Forwarded,
    /// The inner plane has capacity and a live backend, so the request CAN be transmitted.
    ///
    /// Asked before the dispatch for the same reason [`Answerable`](Self::Answerable) is:
    /// local saturation and an all-ejected backend set are facts about THIS proxy, knowable
    /// without transmitting anything, and discovering them from the far side of the
    /// threshold turns a definitely-not-executed outage into an exchange that must report
    /// `possibly_executed` forever after.
    ///
    /// Asked BEFORE [`RetentionReserved`](Self::RetentionReserved), because a saturated
    /// plane must leave nothing on disk: refusing after the reservation would write a
    /// durable marker asserting that a request crossed the execution threshold, for a
    /// request that provably never reached a backend.
    InnerPlaneAccepted,
    /// Durable retention responsibility is taken.
    ///
    /// **The last point at which refusing is free**, and the last state before the
    /// threshold. Nothing between this and the dispatch can refuse, and past the dispatch
    /// no refusal can say nothing happened.
    RetentionReserved,
    /// The inner server has been handed the request. **The execution threshold.** No state
    /// at or after this may claim nothing happened.
    Dispatched,
    /// Bytes attributable to the backend exist. Nothing about them is trusted yet — this
    /// state says only that a reply was OBSERVED, not that it is a legal MCP response.
    ///
    /// Distinct from [`ResponseValidated`](Self::ResponseValidated) on purpose: "I can hold
    /// these bytes" and "these bytes are a response the protocol permits here" are the two
    /// facts the old `ResponseBuilt` state conflated, and conflating them is what let an
    /// unparseable body reach the signer.
    ResponseObserved,
    /// The JSON-RPC control envelope is legal and correlates to the outstanding request:
    /// syntax, `jsonrpc`, `id`, and exactly one of `result` / `error`.
    ResponseValidated,
    /// The reply's MCP lifecycle class is decided — terminal result, terminal JSON-RPC
    /// error, or a non-terminal `input_required` carrying usable state.
    ResponseClassified,
    /// The reply carries the enforcement boundary's signature.
    ResponseSigned,
    /// The continuation obligation this reply creates is discharged: either it opens no leg,
    /// or the leg it opens is durably recorded.
    ContinuationSettled,
    /// The exchange is durably retained (ADR-MCPRE-054).
    Retained,
    /// Terminal. A signed bodyless 202 is being returned for a one-way notification.
    ///
    /// A distinct terminal from [`CompletedTerminal`](Self::CompletedTerminal), not a short
    /// path to it. The 202 states that the enforcement boundary authenticated and ACCEPTED
    /// the message — never that any action completed (#418). Collapsing the two would
    /// restate in the state machine exactly the confusion that issue exists to prevent.
    AcknowledgedNotification,
    /// Terminal. A signed reply that ENDS the exchange is being returned — an ordinary
    /// result, or a JSON-RPC error, which is a legal terminal protocol response and not a
    /// transport failure.
    CompletedTerminal,
    /// Terminal. A signed `input_required` reply is being returned, and the continuation
    /// that makes its answer leg bindable is already durable.
    ///
    /// Separate from [`CompletedTerminal`](Self::CompletedTerminal) because the exchange
    /// makes a different claim in each: one says the call is over, the other says the client
    /// may continue — and MCP-RE may only say the second when it can actually honour it.
    CompletedContinuationOpen,
    /// Terminal. Refused before the execution threshold — the backend never acted.
    ///
    /// Distinct from [`FailedAfterDispatch`](Self::FailedAfterDispatch) because the
    /// distinction is the whole point of the type: collapsing them is what let a refusal
    /// answer the retry question from source position.
    RefusedBeforeDispatch,
    /// Terminal. Failed at or after the execution threshold — the backend may have acted.
    FailedAfterDispatch,
}

/// What happened. Facts already established, never intentions (ADR-MCPRE-057 §18: planned
/// != established). A state is entered because the work justifying it succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExchangeEvent {
    SignatureVerified,
    TransportBindingChecked,
    AdmissionCurrencyChecked,
    ContinuationPrepared,
    ReplayAdmitted,
    DelegatedKeySnapshotted,
    ContinuationRetired,
    ForwardBodyPrepared,
    /// The inner plane took a permit and selected a live backend. Nothing is transmitted.
    InnerPlaneAccepted,
    RetentionReserved,
    /// The inner server has been handed the request. Emitted at the dispatch, not around
    /// it: an event asserting that the threshold was crossed must not be emitted by a path
    /// that did not cross it.
    BackendDispatched,
    /// Bytes attributable to the backend were observed.
    ResponseObserved,
    /// The JSON-RPC control envelope is legal and correlates to the request.
    EnvelopeValidated,
    /// The MCP lifecycle class is decided.
    ResponseClassified,
    ResponseSigned,
    /// This reply opens a continuation leg, and the bases are durably recorded.
    OpenLegRecorded,
    /// This reply opens no continuation leg, so there is nothing to record.
    ContinuationNotRequired,
    EvidenceRetained,
    /// The reply is a signed bodyless 202 for a message that carried no JSON-RPC `id`.
    NotificationAcknowledged,
    /// A reply that ends the exchange is being served.
    TerminalResponseServed,
    /// An `input_required` reply is being served, its continuation already durable.
    OpenLegResponseServed,
    /// A fail-closed refusal at the current state.
    Refused,
}

/// What happened to the approval leg this exchange ANSWERED (ADR-MCPS-047).
///
/// Its authority is the shared continuation store, not this value: `Consumed` records the
/// outcome of the store's atomic `consume`, and does not perform it.
///
/// **Scope, stated because getting it wrong produced a defect.** This describes one axis
/// only — the fate of the approval this exchange spent. It deliberately says nothing about
/// continuation TOPOLOGY, and in particular nothing about a new leg the exchange's own reply
/// may open. Those are independent facts: an answer leg routinely consumes one approval and
/// opens another, so they coexist rather than exclude each other. The second fact lives in
/// [`OpenLeg`], which is a different projection for exactly that reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContinuationState {
    /// This exchange carries no continuation, so no approval is at stake.
    NotInvolved,
    /// Retained bases were read WITHOUT side effect. A refusal from here destroys nothing,
    /// which is why the read is a `peek` and not a `consume`.
    Peeked,
    /// The live entry was removed by this exchange. **A human's approval is spent.** It
    /// cannot be answered again, whatever happens to this request afterwards.
    Consumed,
}

/// Whether the inner server can have acted.
///
/// Two states, because there is no third: the question a refusal must answer is not how far
/// the backend got, but whether "nothing happened" is a true statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendState {
    NotDispatched,
    Dispatched,
}

/// Who authored the bytes the exchange is about to act on.
///
/// The inner seam used to answer this with `Vec<u8>` and nothing else, so a per-request
/// timeout and a backend that genuinely replied `{"error":...}` arrived as identical bytes.
/// They are not the same fact, and no downstream reader could reconstruct the difference:
/// a timeout is the textbook may-have-executed case, and serving it as an ordinary signed
/// reply is the strongest available signal that the exchange completed normally.
///
/// Ordered weakest-first for the same reason [`RetrySemantics`] is: an exchange may learn
/// that its bytes are less trustworthy than it thought, never more.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ResponseOrigin {
    /// No bytes yet.
    Undetermined,
    /// The backend answered. Whether its answer is LEGAL is a separate question, decided at
    /// [`ExchangeState::ResponseValidated`].
    BackendReplied,
    /// The transport failed after the request was transmitted — a timeout, a reset, a
    /// truncated body. Any bytes here were synthesized by MCP-RE, and whether the action ran
    /// is unknown. Such bytes may never be served as a successful MCP response.
    DispatchIndeterminate,
}

/// The fate of the continuation leg THIS exchange's reply opens.
///
/// Deliberately not a variant of [`ContinuationState`]: that machine tracks the approval
/// this exchange SPENT, and an earlier design that carried both on one axis made
/// `Consumed -> Recorded` look like a legal state change, which moved the exchange's
/// consequence backward.
///
/// Ordered so that the obligation, once incurred, cannot be dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum OpenLeg {
    /// This reply opens nothing — an ordinary terminal result or a JSON-RPC error.
    NotApplicable,
    /// The reply is an `InputRequiredResult`: an answer leg must be able to bind to it.
    /// **An obligation, not an achievement.**
    Required,
    /// The bases are durably in the shared tier, so an answer leg on any replica can bind.
    Recorded,
}

/// What a client may safely do with a refusal.
///
/// Derived from the tuple, never asserted at a call site — the derivation is the invariant,
/// and a refusal site that could state this itself is a refusal site that could state it
/// wrongly.
///
/// **Ordered, and the order is the theorem.** An exchange only ever acquires consequence:
///
/// ```text
/// SafeNothingExecuted < RequiresNewElicitation < NotRetrySafe
/// ```
///
/// No legal transition and no store observation may move an exchange to a weaker claim
/// about what has happened to it. `Ord` follows declaration order, so the variants below are
/// written weakest-first deliberately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RetrySemantics {
    /// Nothing was executed and nothing was spent. An ordinary retry is correct.
    SafeNothingExecuted,
    /// Nothing was executed, but the approval that authorized it is gone. A retry will
    /// carry a fresh nonce, pass the replay tier, and then fail as already-answered. The
    /// action needs a NEW human elicitation, not a retry.
    RequiresNewElicitation,
    /// At or past the execution threshold. The backend may have acted, so a retry may
    /// execute the action a second time.
    NotRetrySafe,
}

impl ExchangeEvent {
    /// The state this event establishes, when it names one.
    ///
    /// `Refused` names none: which terminal a refusal reaches is not the event's to choose
    /// — it is decided by how far the exchange had already got.
    fn establishes(self) -> Option<ExchangeState> {
        use ExchangeState as S;
        Some(match self {
            Self::SignatureVerified => S::Verified,
            Self::TransportBindingChecked => S::TransportBound,
            Self::AdmissionCurrencyChecked => S::AdmissionChecked,
            Self::ContinuationPrepared => S::ContinuationPrepared,
            Self::ReplayAdmitted => S::ReplayAdmitted,
            Self::DelegatedKeySnapshotted => S::Answerable,
            Self::ContinuationRetired => S::ContinuationRetired,
            Self::ForwardBodyPrepared => S::Forwarded,
            Self::InnerPlaneAccepted => S::InnerPlaneAccepted,
            Self::RetentionReserved => S::RetentionReserved,
            Self::BackendDispatched => S::Dispatched,
            Self::ResponseObserved => S::ResponseObserved,
            Self::EnvelopeValidated => S::ResponseValidated,
            Self::ResponseClassified => S::ResponseClassified,
            Self::ResponseSigned => S::ResponseSigned,
            Self::OpenLegRecorded | Self::ContinuationNotRequired => S::ContinuationSettled,
            Self::EvidenceRetained => S::Retained,
            Self::NotificationAcknowledged => S::AcknowledgedNotification,
            Self::TerminalResponseServed => S::CompletedTerminal,
            Self::OpenLegResponseServed => S::CompletedContinuationOpen,
            Self::Refused => return None,
        })
    }
}

/// An event the current state has no transition for.
///
/// Carries both halves because the pair is the diagnosis. A caller must not recover by
/// picking a nearby legal transition (ADR-MCPRE-057 §12.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvalidExchangeTransition {
    pub(crate) state: ExchangeState,
    pub(crate) event: ExchangeEvent,
}

impl std::fmt::Display for InvalidExchangeTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "illegal request transition: {:?} has no transition for {:?}",
            self.state, self.event
        )
    }
}

impl ExchangeState {
    /// Whether the inner server can have acted by this state.
    ///
    /// The predicate the execution threshold exists to make statable. `Dispatched` is the
    /// boundary and is itself included: the event is emitted at the handoff, so by the time
    /// the state holds, the backend has the request.
    pub(crate) fn backend_may_have_executed(self) -> bool {
        match self {
            Self::Received
            | Self::Verified
            | Self::TransportBound
            | Self::AdmissionChecked
            | Self::ContinuationPrepared
            | Self::ReplayAdmitted
            | Self::Answerable
            | Self::ContinuationRetired
            | Self::Forwarded
            | Self::InnerPlaneAccepted
            | Self::RetentionReserved
            | Self::RefusedBeforeDispatch => false,
            Self::Dispatched
            | Self::ResponseObserved
            | Self::ResponseValidated
            | Self::ResponseClassified
            | Self::ResponseSigned
            | Self::ContinuationSettled
            | Self::Retained
            | Self::AcknowledgedNotification
            | Self::CompletedTerminal
            | Self::CompletedContinuationOpen
            | Self::FailedAfterDispatch => true,
        }
    }

    /// Whether this state admits no further transitions.
    pub(crate) fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::AcknowledgedNotification
                | Self::CompletedTerminal
                | Self::CompletedContinuationOpen
                | Self::RefusedBeforeDispatch
                | Self::FailedAfterDispatch
        )
    }

    /// Whether this state is one the exchange reaches by SUCCEEDING.
    ///
    /// The predicate the origin invariant is stated over: bytes MCP-RE synthesized because
    /// the transport failed may be reported, but never as one of these.
    pub(crate) fn is_success_terminal(self) -> bool {
        matches!(
            self,
            Self::AcknowledgedNotification
                | Self::CompletedTerminal
                | Self::CompletedContinuationOpen
        )
    }
}

/// The legal transition relation for one exchange.
///
/// `Refused` is legal from every non-terminal state and is the only branching in the
/// relation that any state admits: which terminal it reaches is decided by
/// [`backend_may_have_executed`](ExchangeState::backend_may_have_executed), so a refusal
/// cannot choose the flattering terminal.
pub(crate) fn transition(
    state: ExchangeState,
    event: ExchangeEvent,
) -> Result<ExchangeState, InvalidExchangeTransition> {
    use ExchangeEvent as E;
    use ExchangeState as S;

    let illegal = Err(InvalidExchangeTransition { state, event });

    if state.is_terminal() {
        return illegal;
    }
    if event == E::Refused {
        return Ok(if state.backend_may_have_executed() {
            S::FailedAfterDispatch
        } else {
            S::RefusedBeforeDispatch
        });
    }

    match (state, event) {
        // ---- the request region (ADR-MCPRE-057 §4, frozen) ----
        (S::Received, E::SignatureVerified) => Ok(S::Verified),
        (S::Verified, E::TransportBindingChecked) => Ok(S::TransportBound),
        (S::TransportBound, E::AdmissionCurrencyChecked) => Ok(S::AdmissionChecked),
        (S::AdmissionChecked, E::ContinuationPrepared) => Ok(S::ContinuationPrepared),
        (S::ContinuationPrepared, E::ReplayAdmitted) => Ok(S::ReplayAdmitted),
        (S::ReplayAdmitted, E::DelegatedKeySnapshotted) => Ok(S::Answerable),
        (S::Answerable, E::ContinuationRetired) => Ok(S::ContinuationRetired),
        (S::ContinuationRetired, E::ForwardBodyPrepared) => Ok(S::Forwarded),
        (S::Forwarded, E::InnerPlaneAccepted) => Ok(S::InnerPlaneAccepted),
        (S::InnerPlaneAccepted, E::RetentionReserved) => Ok(S::RetentionReserved),
        (S::RetentionReserved, E::BackendDispatched) => Ok(S::Dispatched),
        // ================== THE EXECUTION THRESHOLD ==================
        // The notification arm branches out of the pipeline HERE, at the only point where
        // the backend has acted and no bodied reply has been observed yet.
        (S::Dispatched, E::NotificationAcknowledged) => Ok(S::AcknowledgedNotification),
        // ---- the response region ----
        // A response is an EVENT presented to the state, and the order below is the whole
        // point: bytes are observed, then validated as a protocol envelope, then classified
        // as an MCP lifecycle transition, and only then signed. There is no edge from
        // `ResponseObserved` to `ResponseSigned`.
        (S::Dispatched, E::ResponseObserved) => Ok(S::ResponseObserved),
        (S::ResponseObserved, E::EnvelopeValidated) => Ok(S::ResponseValidated),
        (S::ResponseValidated, E::ResponseClassified) => Ok(S::ResponseClassified),
        (S::ResponseClassified, E::ResponseSigned) => Ok(S::ResponseSigned),
        (S::ResponseSigned, E::OpenLegRecorded) => Ok(S::ContinuationSettled),
        (S::ResponseSigned, E::ContinuationNotRequired) => Ok(S::ContinuationSettled),
        (S::ContinuationSettled, E::EvidenceRetained) => Ok(S::Retained),
        (S::Retained, E::TerminalResponseServed) => Ok(S::CompletedTerminal),
        (S::Retained, E::OpenLegResponseServed) => Ok(S::CompletedContinuationOpen),
        _ => illegal,
    }
}

/// A fact a stage established, carrying the event that records it.
///
/// # The invariant this owns
///
/// The exchange machine learns that a stage ran by CONSUMING the stage's result — not by
/// the assembly remembering to assert it afterwards. There is no `advance` call at the
/// call site to forget, to misplace, or to write for work that did not happen: the only
/// way to reach the `T` a stage produced is [`ExchangeProgress::establish`], and taking it
/// advances the machine by the event the stage itself named.
///
/// Apply the ownership test to what this replaces. `handle` used to run a stage and then
/// state its event on the next line, so the correspondence between *the work happened* and
/// *the event was emitted* was a deletable statement — twenty of them, in the one function
/// where every refusal's retry contract is decided. Deleting one left the machine silently
/// behind the code until some later advance happened to be illegal. The check could be
/// deleted; therefore it was remembered, not owned.
///
/// [`ExchangeProgress`] already owned transition LEGALITY — `(state, event)` is checked on
/// every advance of every build, and a refusal latches. What it did not own is this. The
/// two together are what make the pipeline order one statement instead of several.
///
/// # Why the event is named inside the stage
///
/// The event is written next to the work that justifies it, in the same function whose
/// contract documents what the stage ensures. A stage and its transition are one unit of
/// review, and neither the assembly nor a future caller can pair them differently. What
/// the pairing may NOT do is invent an order: the event is still presented to
/// [`transition`], so a stage moved to the wrong place in the pipeline is refused by the
/// relation exactly as before.
///
/// # What this deliberately does not cover
///
/// The sibling machines. `observe_origin`, `observe_continuation` and `observe_open_leg`
/// stay ordinary calls: they latch monotonically, so they are already safe by
/// construction, and several of them legitimately fire on a stage's REFUSING arm — which
/// is precisely the case a value returned only on success cannot express.
///
/// Nor the transitions that are the assembly's own rather than any stage's — the dispatch
/// itself, the retirement decided from a [`ContinuationState`], and the terminals. Those
/// are stated in `handle` because that is where the fact is established.
#[must_use = "a stage's established fact must be handed to ExchangeProgress::establish, or \
              the machine does not learn the stage ran"]
pub(crate) struct Established<T> {
    value: T,
    event: ExchangeEvent,
}

impl<T> Established<T> {
    /// Pair a stage's result with the event it establishes.
    ///
    /// Called by the stage, at the point the work succeeded — never by the assembly.
    pub(crate) fn new(value: T, event: ExchangeEvent) -> Self {
        Self { value, event }
    }
}

/// The tuple of live machine states for one exchange, and the invariants over it.
///
/// Held as five fields rather than one combined enum: the machines advance independently
/// and the combinations that matter are expressed as predicates over projections
/// (ADR-MCPRE-057 §4). Enumerating the product would be 23 x 3 x 2 x 3 x 3 cells, almost all
/// of them unreachable, and would push the interesting properties out of reach of an SMT
/// solver rather than into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExchangeProgress {
    request: ExchangeState,
    continuation: ContinuationState,
    backend: BackendState,
    origin: ResponseOrigin,
    open_leg: OpenLeg,
    /// The first illegal transition or invariant violation this exchange hit, latched.
    ///
    /// `None` is the ordinary case and the only one in which the tuple below may be read
    /// at face value. Once set, the model and the code driving it have disagreed, so the
    /// tuple describes an exchange that was never legally reached and nothing derived from
    /// it can be trusted to under-claim safely — see [`ExchangeProgress::retry_semantics`].
    anomaly: Option<&'static str>,
}

impl ExchangeProgress {
    pub(crate) fn new() -> Self {
        Self {
            request: ExchangeState::Received,
            continuation: ContinuationState::NotInvolved,
            backend: BackendState::NotDispatched,
            origin: ResponseOrigin::Undetermined,
            open_leg: OpenLeg::NotApplicable,
            anomaly: None,
        }
    }

    pub(crate) fn state(self) -> ExchangeState {
        self.request
    }

    #[cfg(test)]
    pub(crate) fn continuation(self) -> ContinuationState {
        self.continuation
    }

    #[cfg(test)]
    pub(crate) fn origin(self) -> ResponseOrigin {
        self.origin
    }

    #[cfg(test)]
    pub(crate) fn open_leg(self) -> OpenLeg {
        self.open_leg
    }

    /// Advance the exchange machine, keeping the sibling machines consistent with it.
    ///
    /// The backend projection is derived from the request state rather than set separately,
    /// so the two cannot disagree — the second-source-of-truth failure this module exists to
    /// avoid.
    #[cfg(test)]
    pub(crate) fn apply(
        &mut self,
        event: ExchangeEvent,
    ) -> Result<ExchangeState, InvalidExchangeTransition> {
        let next = transition(self.request, event)?;
        self.request = next;
        self.sync_backend();
        Ok(next)
    }

    fn sync_backend(&mut self) {
        self.backend = if self.request.backend_may_have_executed() {
            BackendState::Dispatched
        } else {
            BackendState::NotDispatched
        };
    }

    /// Advance along the pipeline, and never backward.
    ///
    /// The serving path is straight-line code, so [`apply`](Self::apply) can only refuse if
    /// this model and the function driving it disagree about the pipeline. That is a bug in
    /// one of them, but it must not become a security answer: a state that lags behind the
    /// code claims LESS happened than did, and "less happened" is the direction a refusal
    /// must never err in. So the state each event establishes is taken as a floor.
    ///
    /// Monotone by construction — `ExchangeState` is ordered along the pipeline, and this
    /// only ever moves toward the end of it.
    ///
    /// # Both checks run in every build
    ///
    /// The legality of `(state, event)` under [`transition`] and the coherence of the
    /// resulting tuple under [`invariant_violation`](Self::invariant_violation) are
    /// evaluated on every advance of the shipped binary, and a failure of either LATCHES
    /// into [`anomaly`](Self::anomaly). Neither is a `debug_assert!`: an enforcement layer
    /// compiled out of release builds leaves the ordering of `?` in the serving path as the
    /// only thing standing between a reordered stage and the defects this machine exists to
    /// make unrepresentable, while every test stays green.
    ///
    /// Nor is it a panic. Aborting the task would turn a model/code disagreement into a
    /// dropped connection, whose retry contract is *nothing at all* — strictly less than the
    /// machine already knows. The latch is the enforcement: it is consumed by
    /// [`retry_semantics`](Self::retry_semantics), which degrades to the strongest claim
    /// about consequence, so an exchange the model cannot vouch for is reported as one that
    /// may have executed rather than as one that provably did not.
    pub(crate) fn advance(&mut self, event: ExchangeEvent) {
        if transition(self.request, event).is_err() {
            self.latch("the serving path drove an illegal exchange transition");
        }
        if let Some(floor) = event.establishes() {
            if floor > self.request {
                self.request = floor;
            }
        }
        self.sync_backend();
        if let Some(violation) = self.invariant_violation() {
            self.latch(violation);
        }
    }

    /// Take a stage's established fact, advancing the machine by the event the stage named.
    ///
    /// The only way to open an [`Established`]. The machine cannot learn less than the
    /// pipeline did, because the value and the transition arrive together.
    pub(crate) fn establish<T>(&mut self, established: Established<T>) -> T {
        self.advance(established.event);
        established.value
    }

    /// Record the FIRST anomaly and keep it. A later one cannot describe how the exchange
    /// left the legal path, and the consequence it forces is already at its maximum.
    fn latch(&mut self, what: &'static str) {
        if self.anomaly.is_none() {
            self.anomaly = Some(what);
        }
    }

    /// The latched illegal transition or invariant violation, if the exchange hit one.
    ///
    /// `None` on every exchange that stayed on the legal path, which is every exchange the
    /// serving path is written to produce. `Some` means this process is running code that
    /// disagrees with the machine, and the exchange record is not evidence of anything.
    #[cfg(test)]
    pub(crate) fn anomaly(self) -> Option<&'static str> {
        self.anomaly
    }

    /// Record what the continuation store reported.
    ///
    /// Separate from [`apply`](Self::apply) because the continuation machine is not this
    /// exchange's to drive: it is shared across replicas and its authority is the store.
    /// `Consumed` LATCHES. Once a human's approval is spent it is spent for the rest of the
    /// exchange, and no later observation may report otherwise.
    ///
    /// The latch makes monotonicity a property of the TYPE rather than of the current call
    /// sites, so a future observation cannot reintroduce the defect silently.
    pub(crate) fn observe_continuation(&mut self, observed: ContinuationState) {
        if self.continuation == ContinuationState::Consumed {
            return;
        }
        self.continuation = observed;
    }

    /// Record who authored the bytes this exchange holds.
    ///
    /// Latches upward on the same principle as the continuation: an exchange may learn its
    /// bytes are less trustworthy than it believed, never more. A transport that failed
    /// after transmission cannot be talked back into having produced a backend reply.
    pub(crate) fn observe_origin(&mut self, observed: ResponseOrigin) {
        if observed > self.origin {
            self.origin = observed;
        }
    }

    /// Record the state of the continuation leg this reply OPENS.
    ///
    /// Latches upward: `Required` is an obligation the exchange has incurred, and only
    /// `Recorded` discharges it. Nothing may downgrade an incurred obligation to
    /// `NotApplicable`, which is precisely how an `input_required` reply used to be served
    /// by a deployment that had recorded nothing.
    pub(crate) fn observe_open_leg(&mut self, observed: OpenLeg) {
        if observed > self.open_leg {
            self.open_leg = observed;
        }
    }

    /// What a client may safely do if the exchange terminates here.
    ///
    /// ```text
    /// anomaly latched                          -> NotRetrySafe
    /// backend dispatched                       -> NotRetrySafe
    /// approval spent, backend never dispatched -> RequiresNewElicitation
    /// otherwise                                -> SafeNothingExecuted
    /// ```
    ///
    /// The third case is the one that had no representation. It is reachable whenever a
    /// refusal lands between the continuation retirement and the dispatch — a forwarding
    /// failure or a retention-store outage — and the ordinary retry it used to imply
    /// cannot succeed: the retry's fresh nonce passes the replay tier and the answer then
    /// fails as already-answered, with the human's approval already destroyed.
    ///
    /// Throughout, a "retry" is the client re-signing and re-sending the same call, so it
    /// carries a fresh nonce and a fresh signature. `SafeNothingExecuted` is a claim about
    /// EFFECTS — nothing ran, no approval was destroyed — and not a promise that replaying
    /// the identical signed bytes will be admitted; the replay tier refuses those by design,
    /// at every state past [`ReplayAdmitted`](ExchangeState::ReplayAdmitted).
    ///
    /// The first case is why the anomaly latch exists. A tuple that reached a state the
    /// relation does not admit is not evidence that the backend was never handed the
    /// request; it is evidence that the machine no longer tracks the code. Reporting that as
    /// `SafeNothingExecuted` would collapse "did not run" and "unknown whether it ran" into
    /// the one answer a client may act on destructively, so the unknown is reported at full
    /// strength instead.
    pub(crate) fn retry_semantics(self) -> RetrySemantics {
        if self.anomaly.is_some() {
            return RetrySemantics::NotRetrySafe;
        }
        if self.request.backend_may_have_executed() {
            return RetrySemantics::NotRetrySafe;
        }
        match self.continuation {
            ContinuationState::Consumed => RetrySemantics::RequiresNewElicitation,
            ContinuationState::NotInvolved | ContinuationState::Peeked => {
                RetrySemantics::SafeNothingExecuted
            }
        }
    }

    /// The cross-machine invariants, as one predicate over the tuple.
    ///
    /// `None` means the tuple is coherent. These are the combinations that the transition
    /// relation alone cannot rule out, because they are agreements BETWEEN projections and
    /// `transition` sees only one of them.
    pub(crate) fn invariant_violation(self) -> Option<&'static str> {
        // P2. An open leg may be claimed only once it can actually be answered. The
        // obligation is incurred at classification and discharged only by the durable
        // record; reaching a success terminal with it outstanding is MCP-RE telling a client
        // to continue an exchange it has kept nothing to continue from.
        if self.request == ExchangeState::CompletedContinuationOpen
            && self.open_leg != OpenLeg::Recorded
        {
            return Some("an open leg was served without a durable continuation record");
        }
        if self.request == ExchangeState::CompletedTerminal
            && self.open_leg != OpenLeg::NotApplicable
        {
            return Some("a reply that opens a leg was served as a terminal completion");
        }
        // Bytes MCP-RE synthesized because the transport failed are a report ABOUT the
        // exchange, never the exchange's own successful answer. Serving them as one is the
        // signed-200-carrying-a-timeout case.
        if self.request.is_success_terminal()
            && self.origin == ResponseOrigin::DispatchIndeterminate
        {
            return Some("synthesized transport-failure bytes were served as a success");
        }
        // The derived projection, asserted rather than assumed.
        let expected = if self.request.backend_may_have_executed() {
            BackendState::Dispatched
        } else {
            BackendState::NotDispatched
        };
        if self.backend != expected {
            return Some("the backend projection disagrees with the exchange state");
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATES: &[ExchangeState] = &[
        ExchangeState::Received,
        ExchangeState::Verified,
        ExchangeState::TransportBound,
        ExchangeState::AdmissionChecked,
        ExchangeState::ContinuationPrepared,
        ExchangeState::ReplayAdmitted,
        ExchangeState::Answerable,
        ExchangeState::ContinuationRetired,
        ExchangeState::Forwarded,
        ExchangeState::InnerPlaneAccepted,
        ExchangeState::RetentionReserved,
        ExchangeState::Dispatched,
        ExchangeState::ResponseObserved,
        ExchangeState::ResponseValidated,
        ExchangeState::ResponseClassified,
        ExchangeState::ResponseSigned,
        ExchangeState::ContinuationSettled,
        ExchangeState::Retained,
        ExchangeState::AcknowledgedNotification,
        ExchangeState::CompletedTerminal,
        ExchangeState::CompletedContinuationOpen,
        ExchangeState::RefusedBeforeDispatch,
        ExchangeState::FailedAfterDispatch,
    ];

    const EVENTS: &[ExchangeEvent] = &[
        ExchangeEvent::SignatureVerified,
        ExchangeEvent::TransportBindingChecked,
        ExchangeEvent::AdmissionCurrencyChecked,
        ExchangeEvent::ContinuationPrepared,
        ExchangeEvent::ReplayAdmitted,
        ExchangeEvent::DelegatedKeySnapshotted,
        ExchangeEvent::ContinuationRetired,
        ExchangeEvent::ForwardBodyPrepared,
        ExchangeEvent::InnerPlaneAccepted,
        ExchangeEvent::RetentionReserved,
        ExchangeEvent::BackendDispatched,
        ExchangeEvent::ResponseObserved,
        ExchangeEvent::EnvelopeValidated,
        ExchangeEvent::ResponseClassified,
        ExchangeEvent::ResponseSigned,
        ExchangeEvent::OpenLegRecorded,
        ExchangeEvent::ContinuationNotRequired,
        ExchangeEvent::EvidenceRetained,
        ExchangeEvent::NotificationAcknowledged,
        ExchangeEvent::TerminalResponseServed,
        ExchangeEvent::OpenLegResponseServed,
        ExchangeEvent::Refused,
    ];

    /// The transition relation, written out. Every non-refusal edge, once.
    ///
    /// Stated as data rather than derived from a walk of the happy path: with two branches
    /// in the relation, a derivation would have to encode the branches to check them, which
    /// is circular. `every_state_event_pair_has_a_decided_outcome` checks `transition`
    /// against this table over the FULL cross product, so an edge added to the function and
    /// not to the table fails, and an edge in the table that the function refuses fails too.
    const RELATION: &[(ExchangeState, ExchangeEvent, ExchangeState)] = &[
        (
            ExchangeState::Received,
            ExchangeEvent::SignatureVerified,
            ExchangeState::Verified,
        ),
        (
            ExchangeState::Verified,
            ExchangeEvent::TransportBindingChecked,
            ExchangeState::TransportBound,
        ),
        (
            ExchangeState::TransportBound,
            ExchangeEvent::AdmissionCurrencyChecked,
            ExchangeState::AdmissionChecked,
        ),
        (
            ExchangeState::AdmissionChecked,
            ExchangeEvent::ContinuationPrepared,
            ExchangeState::ContinuationPrepared,
        ),
        (
            ExchangeState::ContinuationPrepared,
            ExchangeEvent::ReplayAdmitted,
            ExchangeState::ReplayAdmitted,
        ),
        (
            ExchangeState::ReplayAdmitted,
            ExchangeEvent::DelegatedKeySnapshotted,
            ExchangeState::Answerable,
        ),
        (
            ExchangeState::Answerable,
            ExchangeEvent::ContinuationRetired,
            ExchangeState::ContinuationRetired,
        ),
        (
            ExchangeState::ContinuationRetired,
            ExchangeEvent::ForwardBodyPrepared,
            ExchangeState::Forwarded,
        ),
        (
            ExchangeState::Forwarded,
            ExchangeEvent::InnerPlaneAccepted,
            ExchangeState::InnerPlaneAccepted,
        ),
        (
            ExchangeState::InnerPlaneAccepted,
            ExchangeEvent::RetentionReserved,
            ExchangeState::RetentionReserved,
        ),
        (
            ExchangeState::RetentionReserved,
            ExchangeEvent::BackendDispatched,
            ExchangeState::Dispatched,
        ),
        (
            ExchangeState::Dispatched,
            ExchangeEvent::NotificationAcknowledged,
            ExchangeState::AcknowledgedNotification,
        ),
        (
            ExchangeState::Dispatched,
            ExchangeEvent::ResponseObserved,
            ExchangeState::ResponseObserved,
        ),
        (
            ExchangeState::ResponseObserved,
            ExchangeEvent::EnvelopeValidated,
            ExchangeState::ResponseValidated,
        ),
        (
            ExchangeState::ResponseValidated,
            ExchangeEvent::ResponseClassified,
            ExchangeState::ResponseClassified,
        ),
        (
            ExchangeState::ResponseClassified,
            ExchangeEvent::ResponseSigned,
            ExchangeState::ResponseSigned,
        ),
        (
            ExchangeState::ResponseSigned,
            ExchangeEvent::OpenLegRecorded,
            ExchangeState::ContinuationSettled,
        ),
        (
            ExchangeState::ResponseSigned,
            ExchangeEvent::ContinuationNotRequired,
            ExchangeState::ContinuationSettled,
        ),
        (
            ExchangeState::ContinuationSettled,
            ExchangeEvent::EvidenceRetained,
            ExchangeState::Retained,
        ),
        (
            ExchangeState::Retained,
            ExchangeEvent::TerminalResponseServed,
            ExchangeState::CompletedTerminal,
        ),
        (
            ExchangeState::Retained,
            ExchangeEvent::OpenLegResponseServed,
            ExchangeState::CompletedContinuationOpen,
        ),
    ];

    /// The ordinary terminal-result path, as the events the pipeline actually establishes.
    const PIPELINE: &[(ExchangeEvent, ExchangeState)] = &[
        (ExchangeEvent::SignatureVerified, ExchangeState::Verified),
        (
            ExchangeEvent::TransportBindingChecked,
            ExchangeState::TransportBound,
        ),
        (
            ExchangeEvent::AdmissionCurrencyChecked,
            ExchangeState::AdmissionChecked,
        ),
        (
            ExchangeEvent::ContinuationPrepared,
            ExchangeState::ContinuationPrepared,
        ),
        (ExchangeEvent::ReplayAdmitted, ExchangeState::ReplayAdmitted),
        (
            ExchangeEvent::DelegatedKeySnapshotted,
            ExchangeState::Answerable,
        ),
        (
            ExchangeEvent::ContinuationRetired,
            ExchangeState::ContinuationRetired,
        ),
        (ExchangeEvent::ForwardBodyPrepared, ExchangeState::Forwarded),
        (
            ExchangeEvent::InnerPlaneAccepted,
            ExchangeState::InnerPlaneAccepted,
        ),
        (
            ExchangeEvent::RetentionReserved,
            ExchangeState::RetentionReserved,
        ),
        (ExchangeEvent::BackendDispatched, ExchangeState::Dispatched),
        (
            ExchangeEvent::ResponseObserved,
            ExchangeState::ResponseObserved,
        ),
        (
            ExchangeEvent::EnvelopeValidated,
            ExchangeState::ResponseValidated,
        ),
        (
            ExchangeEvent::ResponseClassified,
            ExchangeState::ResponseClassified,
        ),
        (ExchangeEvent::ResponseSigned, ExchangeState::ResponseSigned),
        (
            ExchangeEvent::ContinuationNotRequired,
            ExchangeState::ContinuationSettled,
        ),
        (ExchangeEvent::EvidenceRetained, ExchangeState::Retained),
        (
            ExchangeEvent::TerminalResponseServed,
            ExchangeState::CompletedTerminal,
        ),
    ];

    /// Walk `PIPELINE` up to and including `stop`, returning the progress value.
    fn walk_to(stop: ExchangeEvent) -> ExchangeProgress {
        let mut progress = ExchangeProgress::new();
        for (event, _) in PIPELINE {
            progress.apply(*event).unwrap();
            if *event == stop {
                return progress;
            }
        }
        progress
    }

    #[test]
    fn the_pipeline_path_is_legal_end_to_end() {
        let mut progress = ExchangeProgress::new();
        for (event, expected) in PIPELINE {
            assert_eq!(progress.apply(*event).unwrap(), *expected, "{event:?}");
        }
        assert_eq!(progress.state(), ExchangeState::CompletedTerminal);
    }

    /// The open-leg path is legal end to end too, and ends at its OWN terminal.
    #[test]
    fn the_open_leg_path_is_legal_end_to_end_and_ends_somewhere_else() {
        let mut progress = walk_to(ExchangeEvent::ResponseSigned);
        progress.observe_open_leg(OpenLeg::Required);
        assert_eq!(
            progress.apply(ExchangeEvent::OpenLegRecorded).unwrap(),
            ExchangeState::ContinuationSettled
        );
        progress.observe_open_leg(OpenLeg::Recorded);
        progress.apply(ExchangeEvent::EvidenceRetained).unwrap();
        assert_eq!(
            progress
                .apply(ExchangeEvent::OpenLegResponseServed)
                .unwrap(),
            ExchangeState::CompletedContinuationOpen
        );
        assert!(progress.state().is_terminal());
        assert!(progress.invariant_violation().is_none());
    }

    /// Exhaustive over the whole relation: every (state, event) pair is either an edge in
    /// `RELATION`, a refusal, or illegal. Nothing is left to a reader's assumption about
    /// which pairs were considered.
    #[test]
    fn every_state_event_pair_has_a_decided_outcome() {
        let mut legal = 0;
        for state in STATES {
            for event in EVENTS {
                let outcome = transition(*state, *event);
                if state.is_terminal() {
                    assert!(
                        outcome.is_err(),
                        "{state:?} is terminal, {event:?} admitted"
                    );
                    continue;
                }
                if *event == ExchangeEvent::Refused {
                    assert!(outcome.is_ok(), "{state:?} cannot refuse");
                    legal += 1;
                    continue;
                }
                let expected = RELATION
                    .iter()
                    .find(|(from, e, _)| from == state && e == event)
                    .map(|(_, _, to)| *to);
                match (outcome, expected) {
                    (Ok(got), Some(want)) => {
                        assert_eq!(got, want, "{state:?} + {event:?}");
                        legal += 1;
                    }
                    (Err(_), None) => {}
                    (got, want) => panic!("{state:?} + {event:?}: {got:?} vs expected {want:?}"),
                }
            }
        }
        // Every edge in the table, plus a refusal from each non-terminal state.
        let non_terminal = STATES.iter().filter(|s| !s.is_terminal()).count();
        assert_eq!(legal, RELATION.len() + non_terminal);
    }

    #[test]
    fn a_terminal_state_admits_nothing_at_all() {
        for state in STATES.iter().filter(|s| s.is_terminal()) {
            for event in EVENTS {
                assert!(transition(*state, *event).is_err(), "{state:?} + {event:?}");
            }
        }
    }

    /// The execution threshold, stated as the theorem rather than as an ordering comment:
    /// a refusal cannot reach the retry-safe terminal from at or after the dispatch.
    #[test]
    fn a_refusal_at_or_after_the_dispatch_can_only_reach_the_post_dispatch_terminal() {
        for state in STATES.iter().filter(|s| !s.is_terminal()) {
            let terminal = transition(*state, ExchangeEvent::Refused).unwrap();
            if state.backend_may_have_executed() {
                assert_eq!(terminal, ExchangeState::FailedAfterDispatch, "{state:?}");
            } else {
                assert_eq!(terminal, ExchangeState::RefusedBeforeDispatch, "{state:?}");
            }
        }
    }

    /// Non-vacuity control for the test above: the threshold actually partitions the
    /// pipeline, rather than every state falling on one side of it.
    ///
    /// The two states either side of the last free refusal are named explicitly, because
    /// they are the whole reason the threshold sits where it does: local saturation is
    /// knowable without transmitting anything, and the retention marker is written before
    /// the dispatch and not after — so both must refuse from the retry-safe half.
    #[test]
    fn the_execution_threshold_partitions_the_pipeline_into_two_non_empty_halves() {
        let executed = STATES
            .iter()
            .filter(|s| s.backend_may_have_executed())
            .count();
        assert!(executed > 0 && executed < STATES.len(), "{executed}");
        assert!(!ExchangeState::RetentionReserved.backend_may_have_executed());
        assert!(!ExchangeState::InnerPlaneAccepted.backend_may_have_executed());
        assert!(ExchangeState::Dispatched.backend_may_have_executed());
    }

    /// **P5, as a property over every response-region state.** Once the threshold is
    /// crossed, no state the response region can reach reports a retry-safe posture.
    ///
    /// The broken implementation this catches: a response-side refusal deciding its own
    /// retry contract from the fact that "only signing failed, the reply is fine". Every
    /// state below the threshold answers the same way, and there is no site that can
    /// answer differently.
    #[test]
    fn no_state_in_the_response_region_can_report_a_retry_safe_posture() {
        let response_region = [
            ExchangeState::Dispatched,
            ExchangeState::ResponseObserved,
            ExchangeState::ResponseValidated,
            ExchangeState::ResponseClassified,
            ExchangeState::ResponseSigned,
            ExchangeState::ContinuationSettled,
            ExchangeState::Retained,
            ExchangeState::AcknowledgedNotification,
            ExchangeState::CompletedTerminal,
            ExchangeState::CompletedContinuationOpen,
            ExchangeState::FailedAfterDispatch,
        ];
        for state in response_region {
            for continuation in CONTINUATIONS {
                let mut p = ExchangeProgress::new();
                p.request = state;
                p.continuation = *continuation;
                p.sync_backend();
                assert_eq!(
                    p.retry_semantics(),
                    RetrySemantics::NotRetrySafe,
                    "{state:?}/{continuation:?}"
                );
            }
        }
    }

    /// The defect the request region closed, as a property. A refusal between the
    /// continuation retirement and the dispatch is NOT an ordinary retry.
    #[test]
    fn a_refusal_after_the_approval_is_spent_never_reads_as_an_ordinary_retry() {
        let mut progress = ExchangeProgress::new();
        for (event, _) in PIPELINE {
            if *event == ExchangeEvent::BackendDispatched {
                break;
            }
            progress.apply(*event).unwrap();
            if *event == ExchangeEvent::ContinuationRetired {
                progress.observe_continuation(ContinuationState::Consumed);
            }
            if progress.continuation() == ContinuationState::Consumed {
                assert_eq!(
                    progress.retry_semantics(),
                    RetrySemantics::RequiresNewElicitation,
                    "at {:?}",
                    progress.state()
                );
            }
        }
        // Every refusal site in the window: forwarding, retention reservation, and the
        // inner-plane admission that D4 added below them.
        assert_eq!(progress.state(), ExchangeState::RetentionReserved);
        let mut refused = progress;
        refused.apply(ExchangeEvent::Refused).unwrap();
        assert_eq!(refused.state(), ExchangeState::RefusedBeforeDispatch);
        assert_eq!(
            refused.retry_semantics(),
            RetrySemantics::RequiresNewElicitation
        );
    }

    /// Negative control for the test above: the same pre-dispatch refusal on an exchange
    /// that spent no approval IS an ordinary retry. Without this, the property above would
    /// hold trivially if `retry_semantics` returned `RequiresNewElicitation` always.
    #[test]
    fn the_same_refusal_without_a_spent_approval_is_an_ordinary_retry() {
        let mut progress = ExchangeProgress::new();
        for (event, _) in PIPELINE {
            if *event == ExchangeEvent::BackendDispatched {
                break;
            }
            progress.apply(*event).unwrap();
        }
        assert_eq!(progress.continuation(), ContinuationState::NotInvolved);
        progress.apply(ExchangeEvent::Refused).unwrap();
        assert_eq!(
            progress.retry_semantics(),
            RetrySemantics::SafeNothingExecuted
        );
    }

    /// A peek destroys nothing, so a refusal after one is still an ordinary retry. This is
    /// what makes the `peek`/`consume` split load-bearing rather than stylistic.
    #[test]
    fn a_peeked_continuation_leaves_the_refusal_retry_safe() {
        let mut progress = ExchangeProgress::new();
        progress.observe_continuation(ContinuationState::Peeked);
        progress.apply(ExchangeEvent::SignatureVerified).unwrap();
        assert_eq!(
            progress.retry_semantics(),
            RetrySemantics::SafeNothingExecuted
        );
    }

    /// Past the threshold the approval no longer changes the answer: nothing is retry-safe
    /// there, spent approval or not.
    #[test]
    fn past_the_threshold_no_continuation_state_makes_a_retry_safe() {
        for continuation in CONTINUATIONS.iter().copied() {
            let mut progress = walk_to(ExchangeEvent::BackendDispatched);
            progress.observe_continuation(continuation);
            assert_eq!(
                progress.retry_semantics(),
                RetrySemantics::NotRetrySafe,
                "{continuation:?}"
            );
        }
    }

    /// The backend projection is derived, never set, so it cannot drift from the request
    /// state — the two-sources-of-truth failure this module is built to avoid.
    #[test]
    fn the_backend_projection_never_disagrees_with_the_exchange_state() {
        let mut progress = ExchangeProgress::new();
        for (event, _) in PIPELINE {
            progress.apply(*event).unwrap();
            let expected = if progress.state().backend_may_have_executed() {
                BackendState::Dispatched
            } else {
                BackendState::NotDispatched
            };
            assert_eq!(progress.backend, expected, "after {event:?}");
            assert!(progress.invariant_violation().is_none(), "after {event:?}");
        }
    }

    /// The 202 arm is a terminal of its own, reached only from the execution threshold.
    ///
    /// It must read as possibly-executed: the backend has already acted by the time the
    /// reply's shape is known, so a 202 that reported "nothing happened" would be false in
    /// exactly the case the notification path is for.
    #[test]
    fn the_notification_terminal_is_reachable_only_from_the_dispatch_and_reads_as_executed() {
        let mut progress = walk_to(ExchangeEvent::BackendDispatched);
        assert_eq!(progress.state(), ExchangeState::Dispatched);
        progress
            .apply(ExchangeEvent::NotificationAcknowledged)
            .unwrap();
        assert_eq!(progress.state(), ExchangeState::AcknowledgedNotification);
        assert!(progress.state().is_terminal());
        assert!(progress.state().backend_may_have_executed());
        assert_eq!(progress.retry_semantics(), RetrySemantics::NotRetrySafe);

        // Reachable from NOWHERE else: a 202 cannot be acknowledged before the backend has
        // been handed the message.
        for state in STATES.iter().filter(|s| **s != ExchangeState::Dispatched) {
            assert!(
                transition(*state, ExchangeEvent::NotificationAcknowledged).is_err(),
                "{state:?} reached the notification terminal"
            );
        }
    }

    /// **P3, structurally.** There is no path from observed bytes to a signature that does
    /// not pass through envelope validation and lifecycle classification.
    ///
    /// The broken implementation this catches is the one in the tree today: a classifier
    /// that swallows a JSON parse error and lets the body through to the signer. Here the
    /// edge simply does not exist — `ResponseObserved + ResponseSigned` is illegal, and so
    /// is every other shortcut into `ResponseSigned`.
    #[test]
    fn nothing_reaches_the_signature_without_being_validated_and_classified() {
        for state in STATES
            .iter()
            .filter(|s| **s != ExchangeState::ResponseClassified)
        {
            assert!(
                transition(*state, ExchangeEvent::ResponseSigned).is_err(),
                "{state:?} reached the signature"
            );
        }
        assert!(transition(
            ExchangeState::ResponseObserved,
            ExchangeEvent::ResponseClassified
        )
        .is_err());
        assert!(transition(
            ExchangeState::ResponseObserved,
            ExchangeEvent::ResponseSigned
        )
        .is_err());
    }

    /// **P4 — verified is not actionable.** Validation and classification are two states,
    /// and a message can pass the first and be refused at the second.
    ///
    /// The refusal at `ResponseValidated` is the unrecognized-`resultType` case: a
    /// perfectly well-formed JSON-RPC response whose MCP lifecycle meaning this reader
    /// cannot determine. "I can parse this" is not "this response is legal for the request
    /// currently outstanding".
    #[test]
    fn a_validated_response_can_still_be_refused_at_classification() {
        let mut progress = walk_to(ExchangeEvent::EnvelopeValidated);
        assert_eq!(progress.state(), ExchangeState::ResponseValidated);
        progress.apply(ExchangeEvent::Refused).unwrap();
        assert_eq!(progress.state(), ExchangeState::FailedAfterDispatch);
        assert_eq!(progress.retry_semantics(), RetrySemantics::NotRetrySafe);
    }

    /// **P2, as the invariant.** An open leg cannot be served without a durable record.
    ///
    /// The broken implementation this catches is the one in the tree today: a deployment
    /// with no continuation store returns the `input_required` reply anyway, with a success
    /// status, and every later answer leg is refused at the binding. Here the tuple that
    /// would represent it is a violation.
    #[test]
    fn an_open_leg_cannot_be_served_without_a_durable_record() {
        let mut progress = walk_to(ExchangeEvent::EvidenceRetained);
        progress.observe_open_leg(OpenLeg::Required);
        progress.request = ExchangeState::CompletedContinuationOpen;
        progress.sync_backend();
        assert_eq!(
            progress.invariant_violation(),
            Some("an open leg was served without a durable continuation record")
        );

        // And with the record, it is coherent — the non-vacuity half.
        progress.observe_open_leg(OpenLeg::Recorded);
        assert!(progress.invariant_violation().is_none());
    }

    /// The other direction of P2: a reply that opens a leg must not be served as though the
    /// exchange had ended. Reaching `CompletedTerminal` with the obligation outstanding is
    /// the silent-completion failure, arrived at from the terminal side.
    #[test]
    fn a_reply_that_opens_a_leg_is_never_served_as_a_completed_exchange() {
        let mut progress = walk_to(ExchangeEvent::EvidenceRetained);
        progress.observe_open_leg(OpenLeg::Required);
        progress.request = ExchangeState::CompletedTerminal;
        progress.sync_backend();
        assert_eq!(
            progress.invariant_violation(),
            Some("a reply that opens a leg was served as a terminal completion")
        );
    }

    /// The open-leg obligation latches: nothing can talk it back down to "no leg here".
    ///
    /// Without the latch, P2 would be enforceable only if every call site remembered to
    /// observe in the right order — which is the class of guarantee this module exists to
    /// replace.
    #[test]
    fn an_incurred_open_leg_obligation_cannot_be_downgraded() {
        for observed in [OpenLeg::NotApplicable, OpenLeg::Required, OpenLeg::Recorded] {
            let mut p = ExchangeProgress::new();
            p.observe_open_leg(OpenLeg::Required);
            p.observe_open_leg(observed);
            assert!(p.open_leg() >= OpenLeg::Required, "{observed:?}");
        }
        let mut p = ExchangeProgress::new();
        p.observe_open_leg(OpenLeg::Recorded);
        p.observe_open_leg(OpenLeg::NotApplicable);
        assert_eq!(p.open_leg(), OpenLeg::Recorded);
    }

    /// **D4, as the invariant.** Bytes MCP-RE synthesized because the transport failed may
    /// never be served as a successful MCP response.
    ///
    /// The broken implementation this catches is the current seam: a per-request timeout
    /// becomes a synthesized JSON-RPC error, signed at HTTP 200, indistinguishable from the
    /// backend genuinely answering. That tuple is now a violation at every success terminal.
    #[test]
    fn synthesized_transport_failure_bytes_are_never_a_successful_response() {
        for terminal in [
            ExchangeState::CompletedTerminal,
            ExchangeState::CompletedContinuationOpen,
            ExchangeState::AcknowledgedNotification,
        ] {
            let mut p = ExchangeProgress::new();
            p.request = terminal;
            p.sync_backend();
            if terminal == ExchangeState::CompletedContinuationOpen {
                p.observe_open_leg(OpenLeg::Recorded);
            }
            assert!(p.invariant_violation().is_none(), "{terminal:?} baseline");
            p.observe_origin(ResponseOrigin::DispatchIndeterminate);
            assert_eq!(
                p.invariant_violation(),
                Some("synthesized transport-failure bytes were served as a success"),
                "{terminal:?}"
            );
        }
    }

    /// The origin latches upward, for the same reason the approval does: an exchange may
    /// learn its bytes are less trustworthy, never more. A backend reply arriving after a
    /// timeout has been observed does not undo the timeout.
    #[test]
    fn a_dispatch_that_became_indeterminate_cannot_be_downgraded_to_a_clean_reply() {
        let mut p = ExchangeProgress::new();
        p.observe_origin(ResponseOrigin::DispatchIndeterminate);
        p.observe_origin(ResponseOrigin::BackendReplied);
        p.observe_origin(ResponseOrigin::Undetermined);
        assert_eq!(p.origin(), ResponseOrigin::DispatchIndeterminate);
    }

    /// Non-vacuity control for the origin invariant: an ordinary backend reply reaches every
    /// success terminal cleanly, so the test above is not passing because the predicate is
    /// always true.
    #[test]
    fn an_ordinary_backend_reply_reaches_the_success_terminals_cleanly() {
        let mut p = walk_to(ExchangeEvent::TerminalResponseServed);
        p.observe_origin(ResponseOrigin::BackendReplied);
        assert_eq!(p.state(), ExchangeState::CompletedTerminal);
        assert!(p.invariant_violation().is_none());
    }

    const CONTINUATIONS: &[ContinuationState] = &[
        ContinuationState::NotInvolved,
        ContinuationState::Peeked,
        ContinuationState::Consumed,
    ];

    /// **The monotonicity theorem.** An exchange only ever acquires consequence.
    ///
    /// ```text
    /// forall p, e.  legal(p.state, e)  =>  effect(p.advance(e)) >= effect(p)
    /// forall p, c.  effect(p.observe(c)) >= effect(p)
    /// ```
    ///
    /// Exhaustive over every reachable (exchange state x continuation state) pair crossed
    /// with every event and every observation — not a walk of the happy path. What it rules
    /// out is the failure that has no local symptom: a later step making an earlier,
    /// truthful admission of consequence quietly weaker.
    #[test]
    fn the_consequence_of_an_exchange_never_moves_backward() {
        for state in STATES {
            for continuation in CONTINUATIONS {
                let mut base = ExchangeProgress::new();
                base.request = *state;
                base.continuation = *continuation;
                base.sync_backend();
                let before = base.retry_semantics();

                for event in EVENTS {
                    if transition(*state, *event).is_err() {
                        continue;
                    }
                    let mut after = base;
                    // `advance` debug-asserts the tuple invariants, which the open-leg and
                    // origin projections are not being exercised by here; the consequence
                    // question is about the request/continuation pair alone.
                    after.request = transition(*state, *event).unwrap();
                    after.sync_backend();
                    assert!(
                        after.retry_semantics() >= before,
                        "{state:?}/{continuation:?} + {event:?}: {:?} < {before:?}",
                        after.retry_semantics()
                    );
                }

                for observed in CONTINUATIONS {
                    let mut after = base;
                    after.observe_continuation(*observed);
                    assert!(
                        after.retry_semantics() >= before,
                        "{state:?}/{continuation:?} observed {observed:?}: {:?} < {before:?}",
                        after.retry_semantics()
                    );
                }
            }
        }
    }

    /// Non-vacuity control for the theorem: the effect ordering is not trivially constant,
    /// and each of the three classes is actually reachable.
    #[test]
    fn all_three_consequence_classes_are_reachable() {
        let mut p = ExchangeProgress::new();
        assert_eq!(p.retry_semantics(), RetrySemantics::SafeNothingExecuted);
        p.observe_continuation(ContinuationState::Consumed);
        assert_eq!(p.retry_semantics(), RetrySemantics::RequiresNewElicitation);
        for (event, _) in PIPELINE {
            p.advance(*event);
            if *event == ExchangeEvent::BackendDispatched {
                break;
            }
        }
        assert_eq!(p.retry_semantics(), RetrySemantics::NotRetrySafe);
        assert!(RetrySemantics::SafeNothingExecuted < RetrySemantics::RequiresNewElicitation);
        assert!(RetrySemantics::RequiresNewElicitation < RetrySemantics::NotRetrySafe);
    }

    /// The latch, over every observation that survives.
    ///
    /// Once the approval is spent, NO later observation weakens what this exchange must
    /// admit. Stated over the whole set rather than one example, so a variant added later is
    /// covered by construction.
    ///
    /// The other half of the coexistence question — that a leg opened by an answer leg
    /// remains ANSWERABLE — is deliberately not testable here. Answerability lives in the
    /// shared continuation store, which this type does not model; it is proved end to end by
    /// `mrt_continuation_serving_test::a_leg_opened_by_an_answer_leg_is_itself_answerable`.
    #[test]
    fn nothing_observed_after_an_approval_is_spent_makes_it_look_unspent() {
        for observed in CONTINUATIONS {
            let mut p = ExchangeProgress::new();
            p.observe_continuation(ContinuationState::Peeked);
            p.observe_continuation(ContinuationState::Consumed);
            p.observe_continuation(*observed);
            assert_eq!(
                p.continuation(),
                ContinuationState::Consumed,
                "{observed:?}"
            );
            assert_eq!(
                p.retry_semantics(),
                RetrySemantics::RequiresNewElicitation,
                "{observed:?}"
            );
        }
    }

    /// Drive the machine to `target` along the legal pipeline, as `handle` does.
    fn progressed_to(target: ExchangeState) -> ExchangeProgress {
        use ExchangeEvent as E;
        let ladder = [
            E::SignatureVerified,
            E::TransportBindingChecked,
            E::AdmissionCurrencyChecked,
            E::ContinuationPrepared,
            E::ReplayAdmitted,
            E::DelegatedKeySnapshotted,
            E::ContinuationRetired,
            E::ForwardBodyPrepared,
            E::InnerPlaneAccepted,
            E::RetentionReserved,
        ];
        let mut p = ExchangeProgress::new();
        for e in ladder {
            if p.state() == target {
                break;
            }
            p.advance(e);
        }
        assert_eq!(p.state(), target, "ladder reached the requested state");
        assert_eq!(p.anomaly(), None, "the legal ladder latches nothing");
        p
    }

    #[test]
    fn the_whole_legal_ladder_latches_no_anomaly() {
        let p = progressed_to(ExchangeState::RetentionReserved);
        assert_eq!(p.anomaly(), None);
        assert_eq!(p.retry_semantics(), RetrySemantics::SafeNothingExecuted);
    }

    #[test]
    fn an_illegal_advance_is_refused_and_latched_in_every_build() {
        // The stage reorder the relation exists to catch: the dispatch event arrives at a
        // state that never reserved retention.
        let mut p = progressed_to(ExchangeState::Answerable);
        assert!(transition(p.state(), ExchangeEvent::BackendDispatched).is_err());
        p.advance(ExchangeEvent::BackendDispatched);
        assert_eq!(
            p.anomaly(),
            Some("the serving path drove an illegal exchange transition"),
            "an inadmissible (state, event) pair must not pass unrecorded"
        );
    }

    #[test]
    fn an_illegal_advance_never_reports_the_exchange_as_retry_safe() {
        // Before the illegal step the exchange is genuinely pre-dispatch and retry-safe.
        let mut p = progressed_to(ExchangeState::Answerable);
        assert_eq!(p.retry_semantics(), RetrySemantics::SafeNothingExecuted);
        // A skipped stage means the model no longer tracks the code, so whether the backend
        // ran is UNKNOWN — and unknown must never be served as "nothing executed".
        p.advance(ExchangeEvent::ResponseSigned);
        assert!(p.anomaly().is_some());
        assert_eq!(
            p.retry_semantics(),
            RetrySemantics::NotRetrySafe,
            "unknown-if-ran must not collapse into did-not-run"
        );
    }

    #[test]
    fn a_violated_invariant_is_latched_on_the_advance_that_causes_it() {
        // P2: an open leg served with no durable continuation record. The reply opens a leg
        // (`Required`) that nothing ever `Recorded`.
        let mut p = ExchangeProgress::new();
        for e in [
            ExchangeEvent::SignatureVerified,
            ExchangeEvent::TransportBindingChecked,
            ExchangeEvent::AdmissionCurrencyChecked,
            ExchangeEvent::ContinuationPrepared,
            ExchangeEvent::ReplayAdmitted,
            ExchangeEvent::DelegatedKeySnapshotted,
            ExchangeEvent::ContinuationRetired,
            ExchangeEvent::ForwardBodyPrepared,
            ExchangeEvent::InnerPlaneAccepted,
            ExchangeEvent::RetentionReserved,
            ExchangeEvent::BackendDispatched,
            ExchangeEvent::ResponseObserved,
            ExchangeEvent::EnvelopeValidated,
            ExchangeEvent::ResponseClassified,
            ExchangeEvent::ResponseSigned,
            ExchangeEvent::OpenLegRecorded,
            ExchangeEvent::EvidenceRetained,
        ] {
            p.advance(e);
        }
        p.observe_open_leg(OpenLeg::Required);
        assert_eq!(p.anomaly(), None, "nothing is violated until it is SERVED");
        p.advance(ExchangeEvent::OpenLegResponseServed);
        assert_eq!(
            p.anomaly(),
            Some("an open leg was served without a durable continuation record"),
            "the P2 invariant must be evaluated outside cfg(debug_assertions)"
        );
    }

    #[test]
    fn the_latch_keeps_the_first_anomaly() {
        let mut p = progressed_to(ExchangeState::Verified);
        p.advance(ExchangeEvent::ResponseSigned); // illegal
        let first = p.anomaly();
        assert!(first.is_some());
        p.advance(ExchangeEvent::SignatureVerified); // illegal from ResponseSigned too
        assert_eq!(p.anomaly(), first, "the first anomaly is the diagnosis");
    }

    #[test]
    fn an_illegal_advance_still_never_moves_consequence_backward() {
        let mut p = progressed_to(ExchangeState::RetentionReserved);
        p.advance(ExchangeEvent::BackendDispatched);
        assert_eq!(p.retry_semantics(), RetrySemantics::NotRetrySafe);
        // An event establishing an EARLIER state cannot walk the exchange back below the
        // execution threshold, latch or no latch.
        p.advance(ExchangeEvent::SignatureVerified);
        assert!(p.state() >= ExchangeState::Dispatched);
        assert_eq!(p.retry_semantics(), RetrySemantics::NotRetrySafe);
    }

    #[test]
    fn an_illegal_transition_names_both_halves() {
        let err =
            transition(ExchangeState::Received, ExchangeEvent::BackendDispatched).unwrap_err();
        assert_eq!(err.state, ExchangeState::Received);
        assert_eq!(err.event, ExchangeEvent::BackendDispatched);
        let rendered = err.to_string();
        assert!(rendered.contains("Received"), "{rendered}");
        assert!(rendered.contains("BackendDispatched"), "{rendered}");
    }
}
