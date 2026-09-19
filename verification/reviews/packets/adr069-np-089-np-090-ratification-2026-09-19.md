<!-- SPDX-License-Identifier: Apache-2.0 -->
# HP-1 — The RFC 9421 wire surface is closed, and refuses rather than normalises

R6 referral, `http_profile` cluster. `SOURCE_REVISION: cdb28a93`. Read-only.
**This packet carries a reclassification INTO R6 — read §2 first.**

**Filed as** `verification/reviews/packets/adr069-np-089-np-090-ratification-2026-09-19.md`
— the `http_profile` R6 cluster's packet **HP-1**. It covers three records, so NP-089, NP-090
and NP-091 all reference this one file; it is not duplicated per record. Sibling handles
`HP-4`…`HP-8` name packets for records this slice did not register, and are not filed here.

## 1. The question

Does the owner ratify a theorem stating that this profile's RFC 9421 surface — the covered
component set, the signature parameter set, and the signature base composed from them — is
CLOSED and ORDERED, and that anything outside it fails closed rather than being tolerated,
merged or silently normalised? Or decline it, leaving 25 controls at ADR-069 §5 step 1?

## 2. Records covered, control count, and the reclassification

| record | rows at `cdb28a93` | in this packet |
|---|---:|---:|
| **NP-090** *The structured-field surface is closed and canonical* | 16 | 16 (whole) |
| **NP-089** *The signature base is exactly the covered components* | 8 | **8 (whole)** |
| **NP-091** — one row only, moved here (§2.2) | 32 | 1 |
| | | **25** |

Counted from `git show cdb28a93:verification/policy/control-dispositions.toml` via `tomllib`,
not copied from `ANALYSIS-http-profile.md`. NP-090 = `CD-14039…CD-14054`; NP-089 =
`CD-14031…CD-14038`.

### 2.1 NP-089 is WHOLE R6 — the analysis's one R2 row does not survive re-testing

`ANALYSIS-http-profile.md` §3 classes NP-089 as **R2 (1) + R6 (7)**, putting
`lib#sigbase::tests::req_component_on_request_fails_closed` under **THM-0022**. That
assignment is **wrong**, and the residue is 8, not 7.

THM-0022, statement, quoted verbatim and match-verified against
`git show cdb28a93:verification/policy/theorems.toml`:

> If either `Verifier::verify_unbound_response_floor` or
> `Verifier::verify_delegated_unbound_response` returns Ok, then for the response supplied:
> … the signature verified over a base covering ONLY response components under the
> verification key of the accepted signer the operation returns — a `;req` component is
> refused as malformed, **because no request exists to resolve it against**.

The measured control is over a **request**. `git show
cdb28a93:mcp-re-http-profile/src/sigbase.rs:526-532`:

```rust
fn req_component_on_request_fails_closed() {
    let r = request();
    let src = SourceMessage::Request(&r);
    let err = signature_base(&[CoveredComponent::req("content-digest")], …
```

THM-0022's stated REASON — *no request exists to resolve it against* — is false here: the
request is the source message. The refusal has a different ground (`;req` marks a request
component bound into a *response* signature, RFC 9421 §2.4; on a request it is meaningless
by construction). **Clause 2 therefore fails: this is not a strict decomposition of
THM-0022's proposition, it is a different proposition wearing the same three letters.**
Registering it under THM-0022 would be the §5 quiet widening.

Its true home is this packet, and the cluster confirms it: NP-090's
`tests/structured_fields_strictness_test#req_component_on_a_request_fails_closed`
(`CD-14054`) is the same proposition measured end-to-end. The two records were split across
two theorems by an artefact of where the control file sits.

### 2.2 One NP-091 row belongs here, not in HP-4

`tests/mcp_transport_headers_test#the_component_allowlist_is_still_closed` (`CD-15145`)
is filed under NP-091 (*the MCP transport contract*), but it measures the allowlist with a
non-transport header. `git show cdb28a93:mcp-re-http-profile/tests/mcp_transport_headers_test.rs:287-301`:

```rust
fn the_component_allowlist_is_still_closed() {
    …h.1.replace("\"content-type\"", "\"content-type\" \"x-acme-custom\"");
    … HttpProfileError::MalformedEvidence("unknown covered component"),
```

`x-acme-custom` is nothing to do with the MCP transport contract. This is NP-090's
`closed_component_set_rejects_a_foreign_component` measured from the transport test file.
**Recommendation: register it here.** If the owner prefers record boundaries to proposition
boundaries, this packet is 24 and HP-4 is 32; the argument in §4 is unaffected either way.

`tests/mcp_transport_headers_test#mcp_session_id_is_not_a_coverable_component` (`CD-15140`)
was tested for the same move and **kept in HP-4**: which MCP headers are coverable at all is
the transport contract's own boundary, not the generic allowlist's.

## 3. Why existing authority does not answer it

**Keyword sweep over all 130 theorems at `cdb28a93`** (`statement` + `security_consequence`
+ `scope`, case-insensitive, over the tomllib-parsed registry) for
`structured field|RFC ?8941|canonicali[sz]` returns **two** hits, and neither is this:

- **THM-0055**, match-verified: *"…cannot be given the same keyid by anything this project
  wrote: not by a canonicalization that reorders or drops a member…"* — RFC 7638 JWK
  thumbprints, not RFC 8941.
- **THM-0089**, match-verified: *"…separators a parser resolves differently, alternate IP
  spellings a resolver canonicalizes, and non-numeric or non-canonical ports are refused…"*
  — endpoint text, not signature fields.

The nearest theorem that TOUCHES the base is **THM-0014**, and it reaches the base only as
the OBJECT of verification. Statement, match-verified:

> the RFC 9421 signature verified over the reconstructed signature base under an algorithm
> the verifier's policy accepts

"The reconstructed signature base" is a thing the theorem consumes. Nothing in THM-0014's
statement, `security_consequence` or `scope` says what the base may CONTAIN, what a
duplicated or CRLF-bearing component does, or that the parameter set is closed and ordered.

And **THM-0125** pushes the question here by name. Scope, match-verified:

> THE SHAPE, NOT THE SIGNATURE'S CORRECTNESS. That the RFC 9421 signature base is composed
> correctly and verifies is the carrier's, under the http-profile units.

A ratified theorem pointing at a claim that does not exist is the cleanest possible evidence
of an R6.

## 4. Which subsumption clause fails

**Clause 2 fails**, and it is the load-bearing failure. THM-0014's claim is a conditional on
a successful return; the proposition here is a family of REFUSALS by a composer that also
runs on the signing side (`a_nonce_the_profile_cannot_carry_is_never_emitted` is emission-side
and cannot be a decomposition of any verification-return conditional).

**Clause 3 fails** for the closure half. "This deployment's Signature-Input is parsed under a
closed, ordered set and normalises nothing" is an externally meaningful promise about how a
MCP-RE verifier differs from a permissive RFC 9421 library, and it is the promise that makes
parser-differential attacks a non-question. ADR-MCPRE-050 §Resolved-owner ruling 3 (MCPRE-98)
already decided it as product behaviour; no theorem states it.

**Not because the controls sit in an integration binary.** Measured: 16 of the 25 are in
`tests/structured_fields_strictness_test.rs`, which carries **no** crate-level `#![cfg]` and
no `#[ignore]` (§7). The exclusion is a claim-content exclusion, not a positional one.

**Not because the files sit in a shared `paths` tail.** `sigbase.rs` is in **ten** units'
`paths` and in **no** unit's `tested_symbols` — measured over all 204 units. That is the
`http_profile.verifier_results` split's 22-shared-path residue, and it is exactly the
argument this packet must NOT make: *"it is in the paths"* would license registering these
25 into any of the ten and would be a quiet widening ten times over. The R6 verdict rests
on §3's quoted exclusions, not on the path tail.

## 5. Proposed theorem text

- **statement** — This profile parses and composes the RFC 9421 surface under a CLOSED,
  ORDERED component set and a CLOSED, ORDERED parameter set. A covered component outside the
  set, a signature parameter outside the set, a duplicated component or parameter, a
  reordering of either, a non-canonical RFC 8941 form, a value carrying CRLF, a string
  parameter RFC 8941 cannot carry, and a `;req` component on a request signature each fail
  closed as malformed evidence. Quoting and escaping do not merge adjacent members: a
  semicolon inside a quoted value does not split parameters and an escaped quote in a
  neighbouring member does not absorb it. The signature base is exactly the covered
  components in exactly their declared order, with derived components resolved from the
  message and the method carried verbatim; a nonce the profile cannot carry is never emitted
  rather than being truncated. The closure is not vacuous: canonical order, ordinary string
  parameters, and the resolvable derived components still sign and verify.
- **security_consequence** — The excluded outcome is a parser differential: two readers of
  one `Signature-Input` disagreeing about what was covered. Every tolerated form is a way to
  make the verifier's view of the base differ from the signer's, or from an intermediary's —
  a merged member, a silently dropped duplicate, a normalised integer, a CRLF splitting a
  field value into a header the base never claimed. A permissive parser does not fail; it
  succeeds over a different message. The emission-side arm excludes the mirror failure: a
  value the profile cannot carry exactly is refused at the point of signing rather than being
  altered into something the signature then covers.
- **scope** — THE SURFACE AND THE BASE, NOT WHAT THEY PROVE. It establishes nothing about
  whether a signature verifies, which keys are trusted, or what a successful verification
  returns — those are THM-0014, THM-0021 and THM-0022. It is not a claim that RFC 8941 is
  implemented completely: what is claimed is that the forms this profile accepts are a closed
  subset and everything else is refused, which is strictly stronger than conformance for this
  purpose and strictly weaker as an interop claim (that is HP-8's question). It says nothing
  about the body, whose representability boundary is HP-3's, and nothing about the evidence
  block's contents, which is THM-0015's. It does not establish that the closed sets are the
  RIGHT sets — which components a deployment ought to cover is a policy question, and a
  closed set can be closed around the wrong members.
- **depends_on** — `[]`. This is a floor property of the carrier surface; it consumes no
  other ratified claim. In particular it does NOT depend on THM-0014: the implication runs
  the other way, and an edge would assert support the argument does not use.
- **review_requirement** — `Owner security-specification review`.

## 6. Units that would support it

Two, split by altitude because the evidence is genuinely at two altitudes and one unit would
hide that.

| unit | paths | test_features | symbols | exist today |
|---|---|---|---|---|
| `http_profile.signature_base_composition` | `mcp-re-http-profile/src/sigbase.rs` | none (default lib lane) | the 8 `lib#sigbase::tests::*` of NP-089 | yes, all 8 |
| `http_profile.wire_surface_closure` | `mcp-re-http-profile/src/verify/floor/covered_components.rs`, `…/signature_input.rs`, `…/signature_parameters.rs`, `…/sf_dictionary.rs` | none (default `--test` lane) | the 16 `tests/structured_fields_strictness_test#*` of NP-090, plus `tests/mcp_transport_headers_test#the_component_allowlist_is_still_closed` | yes, all 17 |

Both `evidence_class = "tested"`. `direct_consequence_severity`: the registry gives both
records **critical**, and the packet does not argue it down — a parser differential over the
signed base is a signature-bypass class.

**N1 (ADR-MCPRE-068 §3/§9), effective severity critical ⇒ a demonstrated falsifier each, and
this packet names three because two arms of the closure are independently deletable:**

| probe | anchor | weakening | expect_red |
|---|---|---|---|
| `mutation://http_profile/wire_surface/closed_component_set` | the allowlist membership test in `verify/floor/covered_components.rs` | accept an unknown identifier instead of returning `MalformedEvidence("unknown covered component")` | `closed_component_set_rejects_a_foreign_component`, `the_component_allowlist_is_still_closed` |
| `mutation://http_profile/wire_surface/parameter_canonical_form` | the RFC 8941 integer/string form check in `verify/floor/signature_parameters.rs` | normalise instead of refuse | `non_canonical_integer_parameter_forms_fail_closed`, `a_string_parameter_that_rfc_8941_cannot_carry_is_never_signed` |
| `mutation://http_profile/signature_base/duplicate_and_crlf` | the duplicate-component and CRLF guards in `sigbase.rs` | drop both guards | `duplicated_covered_field_fails_closed`, `crlf_in_a_field_value_fails_closed`, `crlf_in_a_derived_component_fails_closed` |

Existing probe format confirmed against `git show cdb28a93:verification/policy/mutation-probes.toml`
(316 probes; fields `id`, `unit`, `theorem`, `conjunct`, `path`, `anchor`, `weakening`,
`expect_red`).

## 7. Lane correspondence — measured, not assumed

Measured at `cdb28a93`. `mcp-re-http-profile/Cargo.toml` declares **one** feature, `verify`,
and it is the Verus lane (`dep:vstd`, `verus_builtin`, `mcp-re-core/verify`). There is no
`redis_replay`, no `async_serve`, no optional backend in this crate.

| file | crate-level `cfg`/`ignore` | tests | lane |
|---|---|---:|---|
| `src/sigbase.rs` | none (`lib.rs:76` is a bare `pub mod sigbase;`) | 8 | `cargo test -p mcp-re-http-profile --lib` |
| `tests/structured_fields_strictness_test.rs` | none | 16 | `cargo test -p mcp-re-http-profile --test structured_fields_strictness_test` |
| `tests/mcp_transport_headers_test.rs` | none | 17 | `--test mcp_transport_headers_test` |

`grep -cE '#\[cfg\(feature|#\[ignore'` returns **0** for all three. Every one of the 25
controls compiles and runs in the lane its proposed battery names, with `test_features`
unset and required to stay unset. **The NP-122 / NP-169 hazard — nine controls compiling to
zero under default features at `lib.rs:99` — does not reach this crate: `mcp-re-http-profile/src/lib.rs`
has no `#[cfg(feature …)]` on any of `block`, `body`, `sigbase`, `mcp_transport`,
`result_class`, `error` or `rejection`.**

## 8. Fingerprint consequence

Two new units, one new theorem with `depends_on = []`. Re-verified at `cdb28a93`:
`_dependency_closure` (`tools/verification/_fingerprint.py:683-704`) seeds its stack from
`by_id[theorem_id]["depends_on"]` and extends it with each dependency's own `depends_on` —
it walks **downward only**. `fingerprint_theorem` (`:707-727`) has exactly five components —
`encoding_version`, `theorem_id`, `theorem_claim`, `theorem_dependencies`,
`theorem_review_requirement` — and `supported_by` is **not** one of them.

With an empty `depends_on`, nothing enters this theorem's closure and nothing enters anyone
else's. **Granting this packet moves ZERO existing fingerprints.** No `paths`, `description`
or `tested_symbols` of any existing unit is touched, so no existing unit fingerprint moves
either.

Conditional cost, priced so the owner can decline it: if the owner instead wants
`THM-0014 depends_on <new>`, THM-0014's fingerprint moves, and so does every theorem whose
transitive closure contains THM-0014 — measured at `cdb28a93`, that is **THM-0015** and
everything above it. This packet does not propose that edge.

## 9. What the owner is NOT being asked

Not to rule on whether the closed sets contain the right members. Not to ratify RFC 8941
conformance — HP-8 is the interop question and is deliberately separate. Not to reopen the
`http_profile.verifier_results` 1→10 split, and not to accept that a control may be
registered into a successor because the successor's `paths` happen to contain its file. Not
to decide NP-091's other 31 rows (HP-4).

## 10. If declined

The 25 controls stay `new-proposition` at ADR-069 §5 step 1 as visible unresolved assurance
debt. NP-089 and NP-090 remain whole unresolved records, and `sigbase.rs` continues to sit
in ten units' `paths` with its entire eight-test battery evidencing nothing. The visible
terminal state: the parser-differential defence that ADR-MCPRE-050 ruled on is exercised on
every PR and promised by no theorem.
