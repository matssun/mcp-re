<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-135 residue — R6 ratification packet: what a handle means after its trust plane is gone

**Disposition:** R2 in part, R6 for the residue. Six of NP-135's eight controls landed —
four as `unit://proxy.trust_posture_declaration` under THM-0100 (probe
`M327-proxy-the-tier-line-names-its-reload-floor`) and two as R1 rows into
`proxy.trust_resolution_window` under THM-0097. Two rows remain; NP-135's `[[proposition]]`
entry and record stay in place, with the title narrowed to the half that remains.

Measured from the tree at `adr069/px-trust-plane-premises`, 2026-09-19. All eight controls
appear in `cargo test -p mcp-re-proxy --lib -- --list`; the default lane is the lane.

## What landed, and the clauses that contain it

THM-0100, statement, verbatim:

> The interval the startup transcript prints as the delivered revocation window is exactly this
> arithmetic: `R + T` for the caching tiers, `R` for the live tier, and `UNBOUNDED` when no
> cadence is configured — in which case the snapshot is the startup read for the process's
> lifetime and nothing here bounds anything.

The four `store_cadence_tests` rows are that sentence at the line the replica prints: every
posture names the reload floor under its number, a configured cadence is named on the tier
line, and a tier with no cadence says on that same line that the store cannot change until a
restart.

THM-0097, statement, verbatim:

> The two terminal cases are irreversible; a successful reload landing afterwards does not
> reopen the resolver.

The two `freshness::tests` rows are that sentence measured on the `TrustStoreFreshness` type
rather than driven through the plane, which is what `proxy.trust_resolution_window` already
does with its four `freshness_transition_tests` rows over the same files. They are an R1
needing no `paths` widening: `freshness.rs` is already in that unit's declared paths.

## The residue

**2 controls**, `mcp-re-proxy`, rust unit test, default cargo lane, carrier
`mcp-re-proxy/src/trust_plane/mod.rs`:

- `handle_lifetime_tests::a_directory_that_outlives_the_plane_still_answers_from_the_last_snapshot`
- `handle_lifetime_tests::surviving_handles_do_not_keep_the_refresh_workers_alive`

## Why no existing theorem contains them

THM-0097 covers HALF of the second control and declines the rest. Its statement does say that
a plane that *"was dropped"* yields no binding and that the resolver answers `Unavailable` —
which is the first assertion `surviving_handles_do_not_keep_the_refresh_workers_alive` makes,
and which `proxy.trust_resolution_window` ALREADY registers as
`handle_lifetime_tests::a_resolver_that_outlives_the_plane_fails_closed`. What neither control
is contained by is the part each is NAMED for:

> Not a liveness claim: that an admitted key IS served is not stated.

Both controls assert that something KEEPS ANSWERING after the plane is gone — the signer
directory in the first, the directory again in the second. That is liveness by name, and a
theorem that disclaims liveness cannot contain it.

The second control carries an additional proposition THM-0097 does not reach at all: that a
surviving HANDLE does not keep the refresh WORKERS alive. That is a runtime-ownership fact of
the family NP-124 carries, and THM-0012 names the same family as an obligation rather than a
result — *"What actually confines requests to the serving interval is resource ownership"*.

Registering either under THM-0097 would make the theorem's own scope paragraph false, which is
the one cost ADR-MCPRE-069 §5 rules strictly worse than leaving a control unregistered.

## The proposition, as it would be stated

> When a trust plane retires, the two handles it published diverge, and the divergence is the
> security argument. The RESOLVER stops answering, because a resolver answer is authority and a
> frozen snapshot still holds the key the operator revoked. The SIGNER DIRECTORY keeps
> answering from the last snapshot, because a kid to signer coordinate is not verification
> material and admits nothing by itself, and a directory that emptied or panicked would turn a
> retirement into a request-path failure. Neither surviving handle keeps the refresh workers
> alive: the workers' lifetime is the plane's, not the handles'.

**Security consequence.** The directory clause is a statement about what a handle may keep
doing, and it is safe ONLY while the directory stays a coordinate. Widening `SignerDirectory`
to yield anything an admission could rest on would invalidate this proposition rather than
merely change a test's expectation, and that is exactly why it should be a claim rather than a
comment: the next person to widen it has to come here first. The worker clause is the
converse — a handle that kept the workers alive makes a plane's lifetime unbounded by its
owner, so a deployment that retired a plane goes on re-reading `--trust` under it.

**Scope.** ONE replica, the two handles a `TrustPlane` publishes, after the plane is dropped.
NOT what the resolver may answer while the plane lives (THM-0097's). NOT the reload cadence
(THM-0100's). NOT what the snapshot represents.

**`direct_consequence_severity`:** `critical`, matching the registry's `NP-135.consequence`.

**`depends_on`:** `THM-0097` — the resolver's fail-closed on drop is the premise the divergence
is stated against.

## Supporting unit, if ratified

One new unit over `mcp-re-proxy/src/trust_plane/mod.rs` — a file already in
`proxy.trust_resolution_window`'s, `proxy.trust_reload_cadence`'s and
`proxy.trust_posture_declaration`'s `paths`, so this is a fourth unit over an overlapping path
and not a widening of any of them. `tested`, V0, `critical`, two `tested_symbols` verbatim, and
a `mutation://` falsifier: make `SignerDirectory`'s read consult the plane's liveness flag the
way the resolver does, and `a_directory_that_outlives_the_plane_still_answers_from_the_last_snapshot`
must go red.

## The fingerprint it would carry

New: `theorem_id`, `theorem_claim`, `theorem_dependencies = {THM-0097}` (THM-0097's own closure
is empty, so the new closure is one entry), `theorem_review_requirement`. `supported_by` is not
a component, so **no existing theorem's fingerprint moves.** Making this a premise of THM-0097
would move THM-0097 and its dependents THM-0099, THM-0100 and the root THM-0074.

## What the owner is being asked

Ratify this statement / consequence / scope under ADR-MCPRE-059 §28, or decline it and say what
the two residue controls are instead. A third answer is available and is worth naming: the
worker-lifetime clause may belong with NP-124 (`control_runtime.rs`) as one runtime-ownership
proposition across carriers rather than as half of this one.
