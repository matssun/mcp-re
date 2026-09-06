# Trust-document interpretation — census record, 2026-09-06

The second v0.17 trust-plane finding. The census of 2026-09-05
(`trust-plane-ownership-2026-09-05.md`, §"An owner-less parser") recorded
`mcp-re-proxy/src/trust_document.rs` as belonging to no unit and declined to absorb it
into `proxy.trust_plane_runtime`; THM-0097 then took the materialized snapshot as an INPUT
authority and named this file as the place its correspondence to the operator's document
would have to attach. This record measures that gap and closes it.

Baseline: main `67ee9f30` (#816 merged: THM-0097 registered and reviewed, 96/96 theorems
established and 12/12 roots complete measured locally at its tip `761cd7dd`). Slice branch
`assurance/trust-document-interpretation`. Question ruled for this slice: *does the materialized trust snapshot faithfully
represent the trust document supplied to the runtime, and which authority owns that
correspondence?*

## 1. The canonical format and the parser authority

One format, one parser, one reader per consumer.

| fact | measured |
|---|---|
| format | a JSON array of objects `{ "signer", "key_id", "public_key" }` with optional `"slots"`; `public_key` Base64URL-no-pad Ed25519; documented in `docs/sidecar-deployment-guide.md` (correct) and `docs/dogfood-runbook.md` (was stale: it showed an authority entry with no `slots`, which the runtime reads as a request signer only, and named `--authz reference`, which is refused) |
| parser | `mcp-re-proxy/src/trust_document.rs` — the only code that interprets the bytes. `mcp-re-client` has its own manifest format (`org_keys` / `kid`); not this document, not a second parser |
| readers | `trust_plane/snapshot.rs::read_trust_file` (startup and every reload); `authorization/capability.rs::evaluator` (startup only, its own `std::fs::read` of the same locator) |
| locator | `config_state/trust_document.rs::TrustDocumentSource`, owned by `proxy.trust_configuration_state`; claims only that the locator names something |
| consumers of the products | `reloading_trust.rs` (the snapshot both tiers resolve against and the `SignerDirectory`); `app.rs::build_actor_resolver` (Request slot: `signer_for(kid)` THEN `resolve(signer, kid)`); `PdpDecisionPolicy::resolve_authority` (issuer map by `kid`) |

## 2. Stages, and whether they were one authority

Before this slice: three `pub fn`s each re-parsed the bytes with `serde_json::Value` and
each carried a partial copy of the validation.

| function | validated | did not validate |
|---|---|---|
| `load_trust` | members present, `(signer, key_id)` unique, key decodes | slots at all |
| `load_trust_request_signers` | members present, slot vocabulary, `response_kid` exclusion | key decodes; `key_id` unique across signers |
| `load_authorization_issuers` | issuer slot, `key_id` unique among issuers, key decodes | unknown slot names (ignored) |

The correspondence between the resolver and the `kid -> signer` map therefore held only
because `snapshot.rs` called the first two on the same bytes in sequence — a
call-ordering relationship (twelve-questions Q7), held by a three-line function in another
unit. Parsing and interpretation were one function each, three times over; validation was
remembered per function, not owned by a value.

After: two stages with one owner each. `TrustDocument::parse` is the structural stage
(typed `RawEntry` with `deny_unknown_fields`; serde's duplicate-member refusal; `Slot` as a
closed enum; every key decoded; every `key_id` unique across the whole document); the three
projections read the parsed entries and never the bytes. Both readers parse once and
project.

## 3. What invalid or ambiguous documents did, and do

| input | before | after |
|---|---|---|
| duplicated JSON member in an entry (`"signer":"a","signer":"b"`) | `serde_json::Value` read the LAST value silently; another parser would read the first | refused: `duplicate field \`signer\`` |
| unknown member (`"slot": [...]`, a misspelt `slots`) | ignored — the key stayed a request signer, i.e. enrolled for everything the default grants | refused: `unknown field \`slot\`` |
| unknown slot name (`"reqest"`) | refused (already) | refused |
| `"slots": null` | refused (`slots must be an array`) | refused — `null` is not a second spelling of absent |
| `"slots": []` | request-signer map: not a signer; issuer map: not an issuer | same (a key enrolled for nothing) |
| same `(signer, key_id)` twice | refused (already) | refused |
| same `key_id` under TWO signers, request slot | ACCEPTED; the `kid -> signer` map was last-write-wins, so file order chose which signer the coordinate named and the other signer's key verified nothing, silently | refused: `duplicate key_id k enrolled for a and b` |
| same `key_id` under two signers, issuer slot | refused (already) | refused (same rule) |
| entry that is not an object | refused (`missing signer`) | refused |
| bad key bytes | refused | refused |
| `response_kid` entry | resolver holds it; excluded from both maps | same |

The one that mattered: the serving path resolves a request signer by `key_id` ALONE
(`build_actor_resolver`: `signers.signer_for(kid)` and only then `resolve(signer, kid)`), so
a document binding one `key_id` to two signers was ambiguous under the coordinate the
runtime uses, and the ambiguity was resolved by file order. Not fail-open — the losing
signer's key could not verify — but a silent signer substitution under an existing
`key_id`, which is the exact shape `load_trust`'s duplicate rule refuses for keys. The
issuer map already refused it "on the same reasoning"; the request map did not.

## 4. Determinism and the object consumed

`TrustDocument::parse` is a pure function of the bytes; the projections are pure functions
of the parsed entries and `response_kid`. No ordering dependence survives (the one that
existed is now a refusal). The trust plane's snapshot IS `(document.resolver(),
document.request_signers(response_kid))` of one parsed value, published together by
`ReloadingTrustStore::store` — the object every tier and the `SignerDirectory` read.

Not the same object: the authorization-issuer set. `capability.rs` performs its own read of
the same locator at startup and never again (the startup transcript says so). Nothing
relates its bytes to the trust plane's first read beyond both having been read from the
same path at nearly the same instant; a write between the two reads gives the two
authorities different documents. Recorded as a non-claim, not a defect: the two sets are
different authorities by ADR-MCPRE-065 §8, and `--trust-reload-secs` is documented as
refreshing request signers only.

## 5. Foreign assumptions

None new. The bytes are the input authority. The filesystem read is the caller's;
provenance of the file (who wrote it, whether it is the operator's intent) is outside every
unit here and is not asserted. `serde_json` and `serde` are `boundary.rust_std`-class
dependencies already in the closure of every unit that parses JSON.

## 6. Existing evidence, and what was added

Before: 14 lib tests in `trust_document.rs`, registered nowhere; no mutation probe; the
integration suite exercised the parser only through startup (`the_trust_store_is_refused_before_the_client_crls_are_read`, `trust_with_authority`).

After: 17 lib controls registered under `unit://proxy.trust_document_interpretation`
(`test://proxy/trust_document/one_parse_slot_projections`), five probes M100–M104 each
red-verified, no integration test changed. Every trust-document writer in the tree
(`serving_fixtures`, `demo_fixtures`, `saturation_rig`, `tls_load_harness_bench`, the
authorization characterization test) writes the three or four documented members only, so
no fixture met the stricter parser: proxy lib 1256/1256, integration 140/140, demo 5/5.

## 7. The theorem

THM-0098, "A replica's trust snapshot is the slot-wise interpretation of one accepted trust
document". Owner `proxy.trust_document_interpretation`; supported by that unit and
`proxy.trust_plane_runtime` (the one-parse composition in `snapshot.rs`, structural, not
probed — a second parse of the same bytes is indistinguishable from the first). No
assumption in the closure. `depends_on = []`. Composed at THM-0074 beside THM-0097: the
snapshot THM-0097 serves from is one accepted document's request-slot enrolment, and the
root is where that conjunction is stated. THM-0097 is unchanged and does not depend on
THM-0098 — it takes the snapshot as an input authority and its proposition uses nothing
here.

Non-claims, verbatim in the scope: the path and the bytes' provenance; when a change
reaches the snapshot (R, THM-0097); the evaluator's separate read; key validity beyond
decodability; which slot the serving seam consults first (`proxy.serving_trust_seam`);
anything cross-replica.

## 8. Decisions taken under the standing mandate, for the owner to overturn

1. **A `key_id` is unique across the whole document.** Extends the already-ruled
   duplicate posture ("last-write-wins substitution refused") from keys to signers, on
   the coordinate the serving path resolves by. A document that enrolled one `key_id`
   for two signers loaded before and is refused at startup now.
2. **The member vocabulary is closed** (`deny_unknown_fields`, duplicated members
   refused). Extends the ruled closed slot vocabulary ("a typo is a startup failure rather
   than a silently narrower key") to the entry's members, where a typo was a silently
   WIDER key. A document carrying an undocumented extra member loaded before and is
   refused now. The documented format has only the four members and every writer in the
   tree emits only those.
3. `trust_document` became `pub(crate)`; nothing outside the crate used it.
4. The dogfood runbook's stale trust-file text was corrected to the measured rules.

Both 1 and 2 are compatibility tightenings of undocumented inputs, taken as extensions
of rulings already on record rather than as new rulings; each is one line to reverse.

## 9. The next gap this exposes

`mcp-re-proxy/src/authorization/capability.rs` — the evaluator installation, including
the startup-only read of the trust document — belongs to no unit. THM-0098 covers the
issuer PROJECTION and stops at the installation for that reason.
