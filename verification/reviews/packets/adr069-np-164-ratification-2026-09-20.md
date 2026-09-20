<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-164 residue — R6 ratification packet: what a key source LOADS, and the token's second key

**Disposition:** R1 for one row, R6 for the residue in scope. One of NP-164's sixteen controls
landed as a `tested_symbol` of `unit://proxy.pkcs11_adapter` under THM-0116. Eight further rows
were examined by ADR-MCPRE-069 CO-S3-4 and are REFERRED, in **three** describable propositions.
Six rows (`CD-19017`–`CD-19020`, `CD-19311`, `CD-19312`, `CD-19316`) were outside this slice and
are untouched: this packet says nothing about them. NP-164's `[[proposition]]` entry and record
stay in place with fifteen rows.

Nothing here is a claim that the eight are unevidenced. Every one is a live, passing control that
measured something. The finding is that no RATIFIED theorem contains what it asserts, so
registering it would make a theorem's battery claim something the theorem did not write down.

## The lane, measured first — three selections, both directions

The slice's analysis named `default` and `pkcs11_keysource`. Both are correct here, and both were
re-measured rather than inherited — the analysis's lane column was wrong for a whole carrier in
CO-S3-3 and for all seven propositions in CO-S3-2.

| selection | controls selected |
|---|---|
| `cargo test -p mcp-re-proxy --test key_source_test -- --list` | **4** |
| `cargo test -p mcp-re-proxy --test pkcs11_keysource_e2e_test -- --list` | **0** |
| `cargo test -p mcp-re-proxy --features pkcs11_keysource --test pkcs11_keysource_e2e_test -- --list` | **6** |
| `cargo test -p mcp-re-proxy --lib -- --list` | **1498** |
| `cargo test -p mcp-re-proxy --features pkcs11_keysource --lib -- --list` | **1506** |

`pkcs11_keysource_e2e_test.rs` carries `#![cfg(feature = "pkcs11_keysource")]` on line 30, so a
plain `cargo test --workspace` compiles its six controls to **zero tests and exits 0** — the
measured-nothing shape this repository already names. `proxy.pkcs11_adapter` declares
`test_features = ["pkcs11_keysource"]`, which is the lane the landed row is taken in; a
`tests/key_source_test#` name could not join the same battery, because a unit has ONE
`test_features` set and those four controls select in the default lane.

**The control that landed was checked for a silent skip, not just for a green.**
`pkcs11_keysource_e2e_test.rs` self-skips when the in-tree mock provider cannot be built
(`require_mock_or_skip`, which only `eprintln!`s). Re-run under `MCP_RE_REQUIRE_LIVE_INFRA=1`,
where a skip is a hard panic: `1 passed`. The mock WAS built and the Cryptoki path WAS driven.

## Residue 1 — what a file-backed key source loads, and how it names its failures (3 rows)

`CD-19313` `file_source_bad_seed_is_malformed`, `CD-19314` `file_source_loads_all_material`,
`CD-19315` `file_source_missing_file_is_not_found`.

**The carrier is not the one the analysis recorded.** The analysis proposed a new unit over
`mcp-re-proxy/src/capability_materialization/key_source/**`. These three controls never enter that
module. They construct `mcp_re_proxy::key_source::FileKeySource` literally — a `pub struct` with
four `pub` `String` path fields — and call `signing_key()`, `tls_server_cert_chain()`,
`tls_server_key()` and `client_ca_roots()` on it. The production text they measure is
`mcp-re-proxy/src/key_source.rs`, which is in **no unit's `paths`** today. Neither
`capability_materialization/key_source/file.rs` nor `build_key_source` is reached.

**THM-0082 refuses them in its own scope**, and the quotation is unusually direct — it names this
exact construction as the thing the theorem exists to measure AGAINST:

> `FileKeySource` and the KMS adapters are public constructors, as external embedders need, so a
> root that opened one beside it would compile.

THM-0082's claim is a PROVENANCE claim about the composition root —

> the root opens one key source through the materializer, opens the role-separation witness once,
> constructs no key source of its own, and installs the signing plane from that same source.

— and it disclaims the rest: *"It says nothing about what the signing plane does with the source
once installed, which is `proxy.response_signing`'s."* A control that constructs a source beside
the root and asks what it loaded is not a decomposition of "the root used the materializer"; it is
a proposition about a component the theorem deliberately holds at arm's length. Clause 2 fails.

**THM-0064, the other candidate, excludes the custody class by name:**

> it establishes nothing about a deployment that selects file custody, which is `ProcessReadable`
> and honestly says so

That is the same sentence that already sent CO-S3-P45's dev-source rows away, and it applies to
the file source verbatim — file custody IS the state THM-0064 names as the one it makes no claim
about.

**THM-0062 is not it either**, though THM-0082's scope points at it (*"THM-0062 establishes what
the credential source yields and when it yields nothing"*). THM-0062 is about the DELEGATED
signing credential's rotation snapshot — *"The credential's existence, not its content"* — not
about a `KeySource` reading four files. Following the pointer does not land anywhere that holds
this proposition.

**Searched, not assumed.** Every `statement`, `security_consequence` and `scope` in
`verification/policy/theorems.toml` was scanned for `key source`, `key_source`, `FileKeySource`,
`seed`, `Malformed`, `NotFound`, `key material`, `client-CA` and `trust anchor`. The hits are the
four theorems discussed above plus THM-0089/THM-0090 (endpoint authority), and none of them claims
what a source loads or that its two failure modes are distinguishable.

**Referred as:** one proposition — *a file-backed key source loads exactly the material its four
paths name, and a missing file and a malformed seed are distinguishable answers.* Severity
`critical`, no ratified home, carrier `mcp-re-proxy/src/key_source.rs`, lane default.

## Residue 2 — the PKCS#11 delegated TLS signer's establishment and its refusals (3 rows)

`CD-19319` `pkcs11_tls_delegated_signer_none_then_some`, `CD-19321`
`pkcs11_tls_multiple_objects_fails_closed`, `CD-19322` `pkcs11_tls_non_ed25519_fails_closed`.

THM-0116 was the proposed home, and its statement is over a different role. Verbatim:

> Each non-exporting response signer — AWS KMS, GCP Cloud KMS, PKCS#11 — establishes the key it
> advertises BEFORE it will sign anything

The registry's own authority for the two roles being distinct propositions is THM-0073, whose
statement refuses the deployment where they coincide —

> the response-signing role and the channel-signing role resolve to the same cryptographic
> signing-key identity

— and whose scope has both roles *"asked for their public verification key after materialization
and compared as `Ed25519PublicKeyValue`"*. So "the response signer establishes its key" cannot be
read onto "the channel signer establishes its key" without asserting the very identification
THM-0073 exists to refuse.

What these three measure is `Pkcs11TlsSigner::open` (`pkcs11_keysource/tls_signer.rs`): a SECOND,
differently labelled token object, proved at construction to exist as both a private and a public
object, to be Ed25519, and to be UNAMBIGUOUS. The third conjunct has no counterpart anywhere in
the registry — no theorem says how many token objects may match one label, or that a signer
refuses rather than choosing one. That is §8's falsifier shape (*let `open` pick one of several
matching token objects*) arriving as a GAP rather than as a weakening: there is no ratified claim
for such a probe to falsify, so no probe was written. ADR-MCPRE-068 N4 forbids choosing a class to
make the row fit instead.

`CD-19319` additionally asserts the NEGATIVE arm — that without a TLS label the delegated signer
is `None` and the deployment stays on file-backed channel custody. THM-0116 has no absent-signer
arm at all; its nearest sentence, *"the public key is accepted only as a well-formed RFC 8410
Ed25519 encoding"*, is about the response key.

**Referred as:** one proposition — *the PKCS#11 delegated TLS signer is established at `open`
from a single unambiguous Ed25519 token object, or it does not exist.* Severity `critical`, no
ratified home, carrier `mcp-re-proxy/src/pkcs11_keysource/tls_signer.rs` and
`.../pkcs11_keysource/token.rs`, lane `pkcs11_keysource`.

## Residue 3 — a token signer at the correspondence gate, and a handshake it really signs (2 rows)

`CD-19318` `pkcs11_tls_cert_signer_mismatch_fails_closed`, `CD-19320`
`pkcs11_tls_full_mtls_handshake_token_resident_no_disk_read`.

`CD-19318` drives `TlsListenerSecurityState::build_delegated_config`, which reaches
`crate::tls::validated_delegated_resolver` and so `DelegatedCertResolver::materialize` — THM-0027's
gate — and asserts `TlsError::DelegatedKeyMismatch`. THM-0027's consequence describes that
outcome:

> An embedder cannot construct MCP-RE's correspondence-assured delegated resolver from a
> certificate and a signer whose exported public key differs from the certificate's leaf public
> key.

**It is nonetheless not a landable decomposition, for two separate reasons.** First, THM-0027's
claim is already quantified over every `RawEd25519TlsSigner`, and
`unit://proxy.delegated_resolver_materialization` already carries
`a_mismatched_credential_and_signer_cannot_materialize_a_resolver` as a `lib#` control. Re-running
one universally quantified refusal with one more signer kind is an INSTANCE, not a sub-proposition
— registering it as a second unit would make the assurance graph look more precise than the
measurement is. Second, that unit is default-lane; this control selects only under
`pkcs11_keysource`, and a unit holds ONE `test_features` set, so it could not join the existing
battery in any case.

**What `CD-19318` would genuinely establish belongs to residue 2, not to THM-0027.** If
`Pkcs11TlsSigner`'s exported public key were the RESPONSE key rather than the TLS key, the
existing `lib#` control stays green and the correspondence gate compares an honest pair of the
wrong key. That is a claim about the PKCS#11 TLS signer's honesty about which object it speaks
for, and it is exactly the unclaimed proposition residue 2 refers. It is recorded here so a later
slice does not land this row against THM-0027 and believe the gap closed.

`CD-19320` is refused twice by THM-0116's own scope:

> NOT A CUSTODY CLAIM. That the private key never leaves the KMS or the token is the provider's
> property and the trait's shape

> NOT A PROTOCOL-CONFORMANCE CLAIM. That each adapter speaks its provider's wire protocol
> correctly is established by its own controls against fixtures, not against a live provider

The control's whole content is that the key stayed on the token (`--tls-key` points at a
guaranteed-missing path) and that a fully validating rustls client completed a real mTLS
handshake against a `CertificateVerify` the token signed. Those are the custody claim and the
conformance claim the scope hands away, in one control.

**Referred as:** one proposition — *a deployment whose channel key is token-resident completes a
real validating mTLS handshake without reading a key from disk, and the correspondence gate sees
the token's own TLS key.* Severity `critical`, no ratified home, lane `pkcs11_keysource`.

## What landed, and the falsifier obligation it inherits

`tests/pkcs11_keysource_e2e_test#pkcs11_sign_verifies_against_token_public_key` joins
`unit://proxy.pkcs11_adapter`. THM-0116's statement contains it in terms:

> Every signature the adapter produces is verified against that advertised public key, with the
> deployment's own verifier, before it is returned.

and the scope authorises the per-lane shape the unit already has:

> THREE LANES, MEASURED SEPARATELY. Each adapter exists only under its own non-default feature

The unit is `evidence_class = "tested"`, severity `critical`, and it already owes and holds a
demonstrated-red `mutation://` falsifier **in this lane**:
`M248-proxy-a-pkcs11-signature-is-verified-before-emission`, weakening the `verify_ed25519` call
in `pkcs11_keysource/mod.rs`. No new probe was minted, because the obligation ADR-MCPRE-068 places
is on the UNIT and the unit discharges it; minting a second probe for the added symbol would be a
falsifier written to decorate a row rather than to attack a conjunct.

Every one of the nine controls in this slice's scope passes. The added row changes what the
battery claims, not whether it runs.

## Residuals recorded, not fixed

1. **`mcp-re-proxy/tests/mock-pkcs11/**` is the landed control's instrument and is not in the
   fingerprint.** `_fingerprint.test_source_patterns` derives exactly two patterns from a
   `tests/<name>#` selector — `<pkg>/tests/<name>.rs` and `<pkg>/tests/<name>/**/*.rs` — and the
   mock provider is a sibling CRATE at `tests/mock-pkcs11/`, matched by neither. Its bytes decide
   what `C_Sign` and `CKA_EC_POINT` return, so a change to it changes what the control means while
   the ReviewFingerprint stands still. Closing it needs machinery, not a `paths` entry, and this
   work package may not widen `paths`.

2. **`mcp-re-proxy/src/key_source.rs` is in no unit's `paths`.** 536 production lines carrying
   `FileKeySource`, `EnvKeySource`, `KeyError` and `signing_key_from_seed_b64url` — the seed
   decode that every file-custody deployment signs under. Residue 1's proposition is the claim
   that would own it.

3. **Two stale comments, reported and not fixed** (carried forward from the slice analysis and
   re-confirmed against the tree). `mcp-re-proxy/tests/dev_env_key_source_test.rs`'s module doc
   says the target is `manual`-tagged and skipped by `bazel test //...`; `BUILD.bazel` says the
   opposite in terms. The same BUILD comment says the env source removes the env var after read,
   while the test asserts it REMAINS set. No claim rests on either, and both are inside the six
   rows this slice did not examine.
