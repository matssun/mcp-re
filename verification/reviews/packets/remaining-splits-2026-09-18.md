<!-- SPDX-License-Identifier: Apache-2.0 -->
# Phase-1 splits — the last three multi-proposition units

**ADR-MCPRE-068 Phase 1**, positions three to five on the campaign ruling's scheduler:
*highest semantic fan-out, then highest effective consequence severity, then greatest number
of dependent/root paths.*

| # | unit | eff. severity | theorems | outcome |
|---|---|---|---|---|
| 3 | `proxy.exchange_lifecycle` | critical | **5** (two of them roots) | 3 owners |
| 4 | `proxy.tls_listener_state` | critical | 3 | 3 owners |
| 5 | `proxy.audit_record_coordinates` | high | 2 | 2 owners |

With the verifier (10) and the SCITT receipt (6), **all five instances of ADR-MCPRE-061
question 2 that the Phase-1 report named are now split.**

---

## 1. The exchange machine — three propositions, five theorems, and six unlabelled probes

Its description named three propositions and they map exactly onto THM-0043 (the relation),
THM-0044 (the retry consequence) and THM-0101 (the publication). The same shape the verifier
had.

**Its six probes named no theorem at all.** `[[probe]].theorem` is optional, and this unit is
one of the places `theorem-falsifier-coverage-2026-09-18.md` counts: six falsifiers, each
attacking a conjunct of one of three claims, and nothing in the registry saying which. The
split adjudicates all six — **P2-T1's work arriving one unit at a time**, and the reason that
obligation asks for the LINK rather than for more probes.

**The backend projection went with the consequence, not the relation**, because THM-0044's
statement is what asserts it: *the backend projection is derived from the exchange state
rather than asserted beside it, so the two cannot disagree.*

**M81 was trimmed, and the trim is the adjudication.** It expected
`an_illegal_advance_never_reports_the_exchange_as_retry_safe` — a claim about what may be
REPORTED, not about whether the relation latched. The lane refused it as a control outside the
battery, correctly.

---

## 2. The listener — and THM-0054, `critical`, attacked by nothing

Three propositions: the assembly (THM-0048), the client-certificate posture (THM-0054), the
epoch-bound store (THM-0103). Eight probes, and **every one attacked the assembly or the
store**. THM-0054 is one of the 22 in the coverage census, and the split made that
merge-fatal rather than invisible.

### 2.1 M76 found that the handshake control never reaches its own property

The obvious target for THM-0054's first falsifier was
`tls_test::a_client_whose_revocation_status_cannot_be_determined_is_denied`. It does **not**
detect `allow_unknown_revocation_status()`. Instrumented in both worlds, the server reports
the same thing either way:

```
PROBE-OBSERVED: Some((InvalidData, "invalid peer certificate: BadSignature"))
```

The fixture's client leaf is refused for a **bad signature** before any revocation decision is
reached. The control's own comment says the CRL is there *"to switch revocation checking ON,
so the second CA's leaf reaches the unknown-status decision"* — **and the leaf does not reach
it.** The control has never exercised the property it names, and it passes for a reason
unrelated to it.

**This is the third instance of one class in this campaign**, and all three were found by a
falsifier and none by reading:

| where | what the control actually did |
|---|---|
| `sdk/python/tests/test_transport_e2e.py` | never ran — `importorskip("httpx")` against a lock that provides `httpx2` |
| `scitt::receipt::parse::tests` | tested a **copy of production** living in the test module |
| `tls_test::a_client_whose_revocation_status…` | refused the fixture for a **different reason** before reaching the property |

Each was green, correctly named, and in the battery of a unit under a declared root.

**M76 is aimed at the control that IS load-bearing**:
`client_verifier_posture_test::no_production_code_relaxes_the_unknown_status_policy` — a
source-text inventory whose whole subject is a call to `allow_unknown_revocation_status()` in
production code, which is exactly what the weakening introduces. That is the honest target,
because THM-0054's claim — *no configuration or argument can relax any of the three* — is a
source-text claim.

**P2-C1** — repair the handshake fixture so the leaf reaches the unknown-status decision, or
retire the control and state what does establish the runtime half. That is a product question
about a test fixture, not an assurance one, and it is recorded rather than guessed at.

### 2.2 The anti-vacuity probe, named as one

M118 (`a-current-session-does-resume`) is kept and labelled: a store that refused every
resumption would satisfy M116 and M117 and break every honest handshake.

---

## 3. The audit record — coordinates and vocabulary are two authorities

`proxy.audit_record_coordinates` carried THM-0069's whole statement **and** THM-0071's half of
it. One decides **where** a verdict is written; the other decides **in whose words**.

`proxy.audit_vocabulary_import` is the second, and **three outcomes are not two**: *not
configured* and *authorized* are different facts about a deployment, and a record that renders
the first as the second reports a decision nobody made — which is the reading an auditor would
act on. **M77** is that weakening, and it turns
`the_unconfigured_line_cannot_be_read_as_an_authorization` red.

---

## 4. Two premises and two edges corrected

- **ASM-0049** (distinct anchor sets yield distinct epoch digests) was scoped to the whole
  listener. It is the epoch derivation's premise: scoped to the store and the assembly, and
  not to the certificate posture, which never touches it.
- A `COMPILE_DEPENDENCY` edge from the listener to `proxy.credential_currency` names the
  per-request REVOCATION verdict in its own rationale, so it is retargeted to
  `proxy.client_certificate_posture`.

## 5. Measured

```
[manifests] PASS — 169 unit(s), 130 theorem(s)
verify-mutations: PASS — M81, M82, M83, M90, M91, M93, T01, M116, M165, M76, M77
87 controls repartitioned across eight new units; none duplicated, none dropped
obligations: 75, unchanged — every new unit discharges N1
```
