<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-152 — R6 ratification packet: a facade that owns nothing, two KMS instances of a claim already quantified, and a warn band no theorem states

**Disposition:** three of NP-152's thirty-three rows landed; **fourteen are refused here** in
three residues. Its `[[proposition]]` entry and record stay in place, with the heading, the
title, the `**Controls:**` counts and the statement corrected by measurement.

Measured from the tree at `adr069/co-s3-5-certificate-identity`, branched from `origin/main`
at `0ad0008f`, 2026-09-20. Nineteen of NP-152's rows are outside this slice's scope
(CO-S3-P03, P05, P08, P10, P11, P12, and the fixture-toolchain row CO-S3-P02), were not
examined, and are left exactly as they were; nothing below should be read as a finding about
them.

## 1. The lanes, measured before anything was decided

| selection | selected | of which `tls_test::` |
|---|---:|---:|
| `cargo test -p mcp-re-proxy --test integration -- --list` | 145 | **28** |
| `cargo test -p mcp-re-proxy --features aws_kms_keysource --test integration -- --list` | 146 | **30** |
| `cargo test -p mcp-re-proxy --features gcp_kms_keysource --test integration -- --list` | 146 | **30** |
| `cargo test -p mcp-re-proxy --lib -- --list` | 1498 | — |
| `cargo test -p mcp-re-proxy --features aws_kms_keysource --lib -- --list` | 1569 | — |

The analysis's lane column was **correct** for all five propositions in this slice:
`aws_kms_delegated_build_rejects_mismatch_and_non_ed25519_leaf` and
`gcp_kms_delegated_build_rejects_mismatch_and_non_ed25519_leaf` are selected by **zero**
names in the default lane — neither appears among the 28 — and by exactly one each under
their own feature. Every row of CO-S3-P01, P04 and P09 is among the default 28.

**One measured fact the analysis does not carry, and it is a subtraction rather than an
addition.** Both KMS lanes select 146, not 147: enabling either feature adds the two
`tls_test::` names and **removes**
`app_startup_characterization_test::app_run_refuses_unbuildable_key_sources_and_replay_tiers`
(CO-S3-P17, slice 6). A slice that measures a feature lane by subtracting totals would
conclude one name appeared where two did. Recorded for slice 6, not acted on here.

## 2. Residue 1 — CO-S3-P01, eleven rows: the historical identity facade

`CD-19083`, `CD-19087`, `CD-19089`, `CD-19094`, `CD-19095`, `CD-19096`, `CD-19099`,
`CD-19100`, `CD-19101`, `CD-19103`, `CD-19104`.

The work package names this the slice's load-bearing judgement and assigns it to the worker:
*is `transport::extract_identity` a strict decomposition of THM-0024, or a second claim?* It
is **neither**, and that is what decides the eleven rows. The analysis's premise — *"this is
a SECOND production implementation of the same proposition"* — is **wrong on the text**, and
the correct reading refuses the rows for a different reason than the analysis anticipated.

### 2.1 The carrier implements nothing

`mcp-re-proxy/src/transport/identity.rs` is 144 lines. `extract_identity` is five
statements, and all five are delegation or vocabulary conversion:

```rust
let evidence = CertificateChainEvidence::from_leaf_der(leaf_der)
    .interpret_identity(policy.into())
    .ok()?;
```

Its own doc comment states the consequence in terms: *"**Compatibility facade.** The
semantics live in the certificate identity authority (ADR-MCPRE-063 Slice 1): this converts
the historical vocabulary in and out and owns nothing. It parses no certificate, selects no
field, validates no value, and decides no fallback."* Under this repository's operational
ownership test — *can the check be deleted and still leave an invalid value
unconstructible?* — the file's own answer is *"no check deleted here could let an invalid
identity through, because there is none here to delete."*

So a unit over `transport/identity.rs` would claim a file that decides nothing, and the
§8 falsifier the work package supplies — *reinstate the URI→DNS→CN fallback* — would have to
be reinstated in `communication_assurance/certificate_identity_interpreter.rs`, which is
`proxy.certificate_identity`'s carrier and not this one.

### 2.2 The clause-2 test, run against THM-0024

The proposition the eleven controls measure is *`extract_identity` returns the configured
field of a real DER leaf, and returns nothing rather than falling back*. Clause 2 asks
whether that is a strict decomposition of a proposition contained in THM-0024's claim, its
scope, or an existing subordinate authority. It is not, on three independent grounds.

**(a) The refusal half of the statement is unobservable through this entrance.** THM-0024's
`statement`, verbatim:

> The five refusals are distinguishable: no leaf was presented, the leaf could not be
> interpreted as a certificate, the representation carrying the configured field could not be
> interpreted, the configured field was absent, or the configured field's first value was not
> a well-formed identity — the last carrying which value rule it broke.
> Present-but-uninterpretable is never reported as absent, and the refusal names the first
> rule that failed under the precedence readability -> presence -> identity-value validity.

`extract_identity` returns `Option`, and its own doc says so: *"The `Option` return is the
historical shape, and it is lossy: the authority distinguishes an absent peer certificate, an
unreadable one, a missing configured field, and a malformed configured value, and all four
arrive here as `None`."* Six of the eleven rows assert exactly `is_none()`. A control that
cannot distinguish the outcomes the statement requires to be distinguishable is not evidence
for that statement.

The repository has already written this argument down, in the module doc of the suite that
exists BECAUSE of it —
`mcp-re-proxy/tests/integration/certificate_identity_no_fallback_test.rs`:

> Every assertion goes through `CertificateChainEvidence::interpret_identity` — the block's
> one public entrance — and names the EXACT refusal. Asserting `is_none()` on the legacy
> facade would pass equally for a certificate that was never parsed, and the whole point of
> the refusal algebra is that those are different answers.

That is the file whose eight controls ARE in `proxy.certificate_identity`'s battery under the
heading *"the same law through real DER"*. The distinction between the two suites is not
incidental: it is the reason the second one was written.

**(b) THM-0080's scope names this exact suite and declines to claim it.** Verbatim:

> the historical extractor is a published API with its own X.509 conformance suite over real
> DER, so it cannot be removed to make the wrong call unavailable, and deleting the controls
> leaves a second identity route compiling. What can be held is that the SERVING PATHS do not
> take it, which is a call-site fact.

*Its own X.509 conformance suite over real DER* is the eleven rows. The registry's position
on them is already recorded, and it is that what can be held is a call-site fact about the
serving paths — not what the extractor returns.

**(c) The proposition already exists, unclaimed, and `origin/main` already refused it.**
`[[proposition]] NP-078` — *"The historical identity facade refuses, and its product cannot
be manufactured"*, `carrier = "mcp-re-proxy/src/transport/identity.rs"`, severity `critical`
— holds `CD-12001`
(`lib#transport::identity::tests::a_certificate_that_does_not_carry_the_configured_field_yields_nothing`),
which is the same sentence as `CD-19101` in the `lib` lane. It was disposed **R6** at
`origin/main` in
`verification/reviews/packets/adr069-np-078-ratification-2026-09-20.md`, whose closing
paragraph is binding here:

> The ordinary ADR-069 §5 route applies: the proposition is IDENTIFIED here with its carrier
> and its evidence, and stays visible unresolved assurance debt until the theorem
> architecture ratifies it. What it must NOT become is an entry in the nearest `supported_by`
> list.

Adding the eleven to `proxy.certificate_identity`'s `tested_symbols` is that entry, arriving
through a battery instead of through a `supported_by` line. `verification/policy/verification.toml`
says the same thing in the peer-identity block's own comment: *"What is deliberately NOT here:
the historical `extract_identity` facade and the `TransportIdentity` seal (NP-078) … Each is
refused against quoted theorem text in its own packet."*

And THM-0024's scope refuses the other candidate shape independently — the possession claim a
unit over `transport/identity.rs` would carry:

> It characterizes values successfully returned by the interpretation operation. It says
> nothing about arbitrary possession of a CertificatePeerIdentityEvidence value, whose
> construction closure is the module boundary rather than a proved postcondition.

**Verdict: R6 on clause 2, eleven rows.** The consequence — that eleven controls over a
`critical` published API are carried by no theorem — is the owner's to resolve, and NP-078
already names the shape of the theorem that would resolve it: two conjuncts, *that the
historical facade propagates the authority's refusal rather than falling back*, and *that the
product cannot be manufactured outside its module*. The eleven rows here are the evidence for
the first conjunct at integration width; NP-078's `CD-12001` is the same conjunct in the `lib`
lane; `CD-12002` is the second conjunct.

### 2.3 Two corrections to the analysis, both measured

1. **Not a second implementation.** §2's deciding-evidence line reads *"THM-0024 is
   characterised over the communication-assurance operation; this is a SECOND production
   implementation of the same proposition."* There is no second implementation.
   `extract_identity` calls the first one. A claim that two implementations exist would have
   justified a second unit; a facade does not.
2. **`transport/identity.rs` is not unowned.** §2 proposes *"new unit over
   `mcp-re-proxy/src/transport/identity.rs`"*. That file is already inside
   `proxy.transport_binding_application`'s `paths`, admitted there by UC-1 as a source-closure
   member and explicitly NOT as part of that unit's proposition. A second unit over the same
   file would have put one file in two units' closures for two different reasons.

## 3. Residue 2 — CO-S3-P06 and CO-S3-P07, two rows: the KMS delegated builds

`CD-19081` (`aws_kms_keysource`), `CD-19090` (`gcp_kms_keysource`).

Read side by side with the two rows this slice DID land, the three bodies are the same test
with the signer swapped:

| row | signer construction | assertions |
|---|---|---|
| `CD-19105` (landed) | `MismatchedEd25519Tls(SigningKey::from_seed_bytes(&[0xAA; 32]))` | `build_delegated_config` → `Err(DelegatedKeyMismatch)` |
| `CD-19081` (refused) | `AwsKmsEd25519Backend::for_test_with_local_seed(&[0x22; 32], "alias/mcp-re-tls")` | the same, twice — mismatch and ECDSA leaf |
| `CD-19090` (refused) | `GcpKmsEd25519Backend::for_test_with_local_seed(&[0x22; 32])` | the same, twice |

THM-0027's `statement` quantifies over the type, not over a signer kind — *"Every
DelegatedCertResolver produced by MCP-RE was produced by DelegatedCertResolver::materialize"*
— and the gate it names compares two public keys, which is `security_consequence`'s *"a
certificate and a signer whose exported public key differs from the certificate's leaf public
key"*. A KMS-backed signer is an INHABITANT of that quantifier, not a sub-proposition of it.

Because the two rows are in non-default lanes and `proxy.delegated_resolver_materialization`
declares no `test_features`, they cannot join its battery: a unit holds ONE `test_features`
set, and adding a name that compiles to zero tests in the unit's lane is the
`MEASUREMENT FAILURE` shape, not evidence. The analysis's proposal is therefore two **new**
lane-scoped units under THM-0027 — and a new unit stating the same proposition as an existing
one, once per signer backend, is not a decomposition. It relocates one authority into three
copies, and clause 2 asks for a strict decomposition.

**This is the ruling CO-S3-4 already made on the identical shape, one slice earlier**, for
`pkcs11_tls_cert_signer_mismatch_fails_closed`
(`verification/reviews/packets/adr069-np-164-ratification-2026-09-20.md`), verbatim: *"THM-0027's
claim is already quantified over every `RawEd25519TlsSigner`, and
`unit://proxy.delegated_resolver_materialization` already carries
`a_mismatched_credential_and_signer_cannot_materialize_a_resolver` as a `lib#` control.
Re-running one universally quantified refusal with one more signer kind is an INSTANCE, not a
sub-proposition — registering it as a second unit would make the assurance graph look more
precise than the measurement is."* Landing the AWS and GCP rows would have the campaign
contradict itself on the PKCS#11 row it refused the day before.

**The analysis's justification is also wrong on the theorem.** §2 closes P06 with *"Same
shape THM-0116 scope already blesses."* THM-0116 is the **response** signer's theorem — its
statement opens *"Each non-exporting response signer — AWS KMS, GCP Cloud KMS, PKCS#11 —
establishes the key it advertises BEFORE it will sign anything"* — and CO-S3-4 measured that
it does not reach the TLS handshake signer, with THM-0073 as the registry's own authority
that the two roles are different propositions. THM-0116's scope refuses the shape twice over
in any case: *"NOT A CUSTODY CLAIM"* and *"NOT A PROTOCOL-CONFORMANCE CLAIM."*

**Verdict: R6 on clause 2, two rows.** What the two rows would genuinely add — that the KMS
backends' `Ed25519TlsSigner` implementations reach the correspondence gate at all, so a
backend that exported a stale or unrelated key would be caught rather than silently paired —
is the same unclaimed proposition CO-S3-4 identified for the token signer. It is recorded
here so a later slice does not land these against THM-0027 and believe the gap closed.

## 4. Residue 3 — CO-S3-P09's first row: a warn band no claim holds

`CD-19084` (`crl_freshness_classifies_fresh_near_and_stale`). Its sibling `CD-19085` landed;
see §5.

The analysis marks P09 a single proposition and flags the problem itself (§9 judgement 2:
*"That is more than the unit says today; adding it changes the unit's proposition, not just
its battery"*). Measured, P09 is **two** describable propositions, and C5 forbids filing a
record spanning two as one. They split cleanly:

* *an undecodable CRL is a hard error rather than a pass* — contained, landed;
* *the currency classifier has three states against a configurable warn window* — not
  contained.

`crl_freshness` returns four variants. Two of them, `Fresh` and `NearExpiry`, are both
**ADMITTED** by `require_in_force` in `tls_plane/crl_evidence.rs`; `NearExpiry` differs only
in that it `eprintln!`s a warning. So the third state changes nothing about installability,
which is the whole of what THM-0131 claims:

> A set of client CRLs is installable only when every one of them is inside its own
> `nextUpdate` window and states one at all.

`CD-19084` asserts the `NearExpiry` variant is returned at `nu - 1` under a 6-hour warn
window and `Fresh` at `nu - warn - 1`. Delete `NearExpiry` and fold it into `Fresh` and the
control goes red while THM-0131 stays true and every deployment installs exactly the same
CRLs — the sharpest available statement that the assertion is not evidence for the claim.
The warn band's width is moreover a choice between product behaviours (`CRL_NEAR_EXPIRY_WARN_SECS`),
which clause 3 excludes on its own terms.

The unit `proxy.client_crl_next_update_gate` describes what it holds as *"a CRL that states a
`nextUpdate` is classified fresh and admitted, and one that states none at all is REFUSED by
name and by index"* — two classes, not three — and this work package may not amend a unit's
`description`. Absorbing the row would widen a `critical` unit's proposition by battery
rather than by review, which is the defect ADR-MCPRE-069 exists to remove.

**Verdict: R6 on clauses 2 and 3, one row.** The inclusive-boundary half of the control
(*at exactly `nextUpdate` the CRL is Stale*) IS contained in THM-0131 and is protected
already: `M326-proxy-a-crl-with-no-expiry-is-not-fresh` and, newly,
`M357-proxy-an-undecodable-crl-is-not-a-fresh-one`. Nothing is lost by refusing the row
except the warn band, which nothing claims.

## 5. What landed, and the four clauses for each

### `unit://proxy.delegated_resolver_materialization` (THM-0027) — `CD-19105`, `CD-19106`

* **Clause 1** — `verification/policy/theorems.toml` is **byte-identical to `origin/main`**;
  `unit://proxy.delegated_resolver_materialization` is already THM-0027's `owner` and one of
  its two `supported_by` entries.
* **Clause 2** — both are strict decompositions of the scope sentence, verbatim: *"Within the
  API this crate publishes, delegated-resolver materialization has no route that bypasses the
  validated correspondence gate."* Every `lib#` name already in the battery calls
  `materialize` or the facade from inside the crate over operands built beside the call. These
  two enter at `TlsListenerSecurityState::build_delegated_config` — the published entrance —
  with a leaf minted by a real `rcgen` CA and a signer keyed independently of it. `CD-19106`
  is the same comparison taken at the algorithm boundary: an ECDSA P-256 leaf's SPKI can equal
  no Ed25519 signer's exported key, which is `security_consequence`'s *"a certificate and a
  signer whose exported public key differs from the certificate's leaf public key."*
* **Clause 3** — no new promise. THM-0027's scope already says *"It is a claim about
  CONSTRUCTION, and only about resolvers this crate produces"*, and neither row reaches a
  handshake.
* **Clause 4** — two `tested_symbols` entries and one widened `expect_red`. Nothing else.
* **Lane** — the unit declares no `test_features`; both rows are among the default lane's 28.

### `unit://proxy.client_crl_next_update_gate` (THM-0131) — `CD-19085`

* **Clause 1** — `theorems.toml` unchanged; the unit is already one of THM-0131's three
  `supported_by` entries.
* **Clause 2** — a strict decomposition of *"installable only when every one of them is
  inside its own `nextUpdate` window and states one at all."* A CRL whose DER does not decode
  is demonstrably inside no window; `crl_freshness` erroring is what keeps it out. Both `lib#`
  names in the battery hand the function a CRL that PARSED, so neither reaches this arm.
* **Clause 3** — no product choice: the alternative to an error is admitting a document
  nothing can age out.
* **Clause 4** — one `tested_symbols` entry, one new `[[probe]]`.
* **Lane** — no `test_features`; the row is among the default lane's 28.

All three controls were run and observed, not assumed: `--exact`, `--test-threads=1`,
**`3 passed; 0 failed; 0 ignored`**. None is behind a skip guard.

## 6. The falsifiers, demonstrated

| probe | lane | result |
|---|---|---|
| `M36-materialization-gate-consumes-a-real-relation` | default | **VERDICT: PASS** — red on the two `lib#` names **and on `tests/integration#tls_test::validated_delegated_build_rejects_cert_signer_key_mismatch`**, which is why that row was added to `expect_red` |
| `M326-proxy-a-crl-with-no-expiry-is-not-fresh` | default | **VERDICT: PASS** — unchanged |
| `M357-proxy-an-undecodable-crl-is-not-a-fresh-one` (**new**) | default | **VERDICT: PASS** — red on `tests/integration#tls_test::crl_freshness_rejects_malformed_der` |

`validated_delegated_build_rejects_non_ed25519_leaf` was run under M36's weakening and stayed
**GREEN** — a leaf whose SPKI is not Ed25519 is refused before the correspondence comparison
is reached — so it is deliberately NOT declared in `expect_red`. Declaring it would have been
a claim the lane contradicts, and the lane tolerates it (`verify-mutations` requires *at least
one* declared control to go red), which is exactly why it had to be measured rather than
assumed.

M357's first adjudication was **STALE — an anchor matches 2 site(s)**: the two-line
`CertificateList::from_der` parse appears verbatim in `crl_posture` directly below
`crl_freshness`. The anchor now carries the `next_update` line that distinguishes them. The
refusal is recorded because it is the tool doing its job — a weakening applied to the wrong
one of two identical sites would have measured a different function and reported PASS.

## 7. Quotation checks

Twenty-three quotations, whitespace-normalised (comment and blockquote markers stripped) and
asserted as substrings of the named field of the named theorem in
`verification/policy/theorems.toml`, or of the named source file: **23 OK, 0 MISS.** Nothing
was paraphrased and nothing was removed for failing to match.

Covering THM-0024 `statement` ×2 and `scope` ×2; THM-0027 `statement` ×1,
`security_consequence` ×1 and `scope` ×3; THM-0080 `scope` ×1; THM-0116 `statement` ×1 and
`scope` ×2; THM-0131 `statement` ×2; plus the module docs of `transport/identity.rs` ×3,
`certificate_identity_no_fallback_test.rs` ×1 and `tls_plane/crl_evidence.rs` ×1;
`verification.toml` ×2; and the NP-078 and NP-164 packets ×1 each.

One quotation was **corrected rather than kept**: the CO-S3-4 sentence in §3 was first written
from memory of its sense and did not match; it is now the packet's own words.

## 8. Residuals, recorded not fixed

1. **`mcp-re-proxy/src/transport/identity.rs` carries a `critical` published API under no
   theorem.** NP-078 names it; the eleven rows of residue 1 are further evidence for the same
   unclaimed conjunct. This slice may not add a `[[theorem]]`.
2. **The AWS and GCP delegated-TLS signer establishment is unclaimed**, the same gap CO-S3-4
   recorded for the PKCS#11 TLS signer. Refusing `CD-19081`/`CD-19090` against THM-0027 leaves
   it open rather than papering it over.
3. **The `NearExpiry` warn band is stated nowhere in the registry** — not in THM-0131, not in
   `proxy.client_crl_next_update_gate`, not in `proxy.client_revocation_currency`. It is an
   operator-facing behaviour with a compiled-in constant and one control, and no claim.
4. **`proxy.delegated_resolver_materialization`'s `paths` do not include
   `mcp-re-proxy/src/tls_listener_state/mod.rs`**, where `build_delegated_config` — the
   entrance the two landed rows use — lives. A change there does not move the unit's
   fingerprint. This work package may not widen `paths`; the direction is conservative,
   because the controls go RED rather than silently green if that entrance stops reaching the
   gate.
5. **Nineteen NP-152 rows were not examined** (§ preamble). Their propositions remain
   CO-S3-P02, P03, P05, P08, P10, P11 and P12, six of them R6 in the analysis and one a
   new-`not-evidence`-family judge trigger the campaign may not create.

**Severity:** `critical`.
