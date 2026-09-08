<!-- SPDX-License-Identifier: Apache-2.0 -->

# The MCP-RE auditor

`mcp-re-auditor` turns the evidence a serving proxy retained into a portable SCITT
attestation. It runs **off the request path**, as a separate executable, against an
archive written by a proxy started with `--retained-evidence-dir`.

It produces a portable attestation and, if you ask it to, registers that attestation with a
transparency service and keeps the verified receipt beside it. Registration is opt-in and
strictly after the attestation is durable.

## Why it is a separate binary

Attestation is not on the request path, for three reasons the retention design already
states: a chain is not whole until its last hop, the audit posture is the auditor's to
choose rather than the serving deployment's, and registering with a transparency service
would make an audit dependency an availability dependency.

Those are reasons about *when* attestation runs. A `--attest` mode on the proxy would
honour all three and still put the auditor's trust inputs, signing key and audit posture
inside the process that answers requests. A separate executable means a deployment that
runs one need not run the other, and an auditor can run against an archive long after the
proxy that wrote it is gone.

## What you need

Four inputs, and each one is a thing somebody wrote down:

| input | what it is |
| --- | --- |
| the archive | the directory the proxy's `--retained-evidence-dir` names |
| the hop digests | which retained objects make up the record, **in order** |
| an audit profile | what you assert about the deployment you are auditing |
| the deployment's trust document | the same `--trust` file the proxy served under |
| a service trust pin | the transparency service this attestation is for |
| an issuer key | the Ed25519 seed this auditor signs its own statement with |

**The hop order is yours to state.** The store is content-addressed and flat: each object's
file name *is* its digest, so listing the directory gives you the tokens, but nothing in it
records which hop of a continuation came first. That is why `--hop` is repeatable and
ordered rather than derived.

## The audit profile

An archive of retained messages does not describe the posture they were served under.
Reconstruction needs that posture, none of it is in the bytes, and a verdict that rested on
values nobody wrote down would not be reproducible. So it is a document:

```json
{
  "schema": "mcp-re-audit-profile/v1",
  "trust_domain": "example.com",
  "expected_audience": {
    "audience_id": "verifier-1",
    "target_uri": "https://mcp.example.com/mcp?route=a",
    "route": "a"
  },
  "delegation": {
    "verifier_audiences": ["verifier-1"],
    "expected_audience_hash": "verifier-1",
    "accepted_epochs": ["epoch-1"],
    "max_clock_skew_secs": 60
  },
  "response_anchor": {
    "subject": "did:example:server",
    "key_id": "root-kid",
    "public_key": "<base64url Ed25519 public key>"
  }
}
```

`revoked_key_ids` is optional and defaults to none. The set it names is applied in **both**
places one audit consults revocation — the actor seam and the delegated-credential check —
so a key cannot be refused in one and honoured in the other.

Two lines carry different weight, and it is worth knowing which:

* `response_anchor.key_id` **decides a verdict**. A retained response whose evidence block
  names a different `key_id` does not verify.
* `subject` and `trust_domain` are the auditor's own **labels** for the identities it
  resolves. They travel into the reconstruction's identity fields; no comparison turns on
  them.

A document is refused outright — before anything is read from the archive — when its schema
is wrong, its expected audience is incomplete, its verifier-audience list or epoch set is
empty, its clock skew is outside `0..=3600`, or its anchor key does not decode. An empty
epoch set does not audit more strictly; it audits nothing.

## Running it

```sh
mcp-re-auditor \
  --retained-evidence-dir /var/lib/mcp-re/evidence \
  --hop 8xJ2h1t0d2n1r6QpVQ9r2mBz3nQ0y7hK1sVc5vJ4wXk \
  --audit-profile /etc/mcp-re/audit-profile.json \
  --trust-document /etc/mcp-re/trust.json \
  --service-trust-pin /etc/mcp-re/service-key-pin.json \
  --issuer-kid auditor-1 \
  --issuer-key-seed /etc/mcp-re/auditor.seed \
  --out ./attestation.json \
  --at 1757280000
```

`--at` defaults to the system clock. Every retained message's `created` is compared against
it, and every delegated credential's window is judged against it, so it is the value that
decides whether an archive reads as evidence or as messages from the future. Pass it
explicitly when re-running an audit you want to reproduce.

Run `mcp-re-auditor` with no arguments for the flag list.

## What it writes

```json
{
  "schema": "mcp-re-attestation/v1",
  "issuer_kid": "auditor-1",
  "issued_at": 1757280000,
  "signed_statement": "<base64url COSE_Sign1>",
  "hops": ["8xJ2h1t0d2n1r6QpVQ9r2mBz3nQ0y7hK1sVc5vJ4wXk"],
  "chain": { "label": "complete" },
  "correspondence": "bound-to-verified-call",
  "transparency_service": { "service_identifier": "example-ts", "kid": "ts-2026-09" },
  "receipt": "<base64url COSE_Sign1, present only after a VERIFIED registration>"
}
```

`signed_statement` is the **exact** Signed Statement, byte for byte. A registration step
submits those bytes and nothing else.

The two verdicts beside it are the point of the file, and neither is decoration:

* **`chain`** is `complete`, or `incomplete` naming the hop that broke the record and why —
  with the frozen `mcp-re.*` wire code where the break was a verification failure. The
  completeness half is read from the SIGNED commitment rather than recomputed, so what the
  file summarizes and what a receipt will commit to cannot disagree.
* **`correspondence`** is `bound-to-verified-call` or `bound-to-submission-only`. The
  second means the statement identifies no verified call: these are the bytes the issuer
  saw, and *that any hop verified* is not among the things it says.

## What is a refusal and what is a verdict

This distinction is the whole design, so it is worth stating plainly.

**Refusals** — nothing is written, and the exit status is non-zero:

* a hop the archive does not hold, or one whose bytes do not hash to the name they are
  stored under;
* an audit profile, trust document or service pin that will not parse or is incoherent;
* an unreadable or malformed issuer seed;
* an archive directory that cannot be opened.

**Verdicts** — an artifact *is* written, and it says so:

* an INCOMPLETE record, whatever broke it. Refusing here would leave the most interesting
  records — the truncated ones, the ones with a hop that did not verify — with no portable
  evidence at all, which is exactly what the chain label exists to prevent.

## Registering with a transparency service

Opt-in, and it happens **after** the attestation is on disk:

```sh
mcp-re-auditor \
  --retained-evidence-dir /var/lib/mcp-re/evidence \
  --hop 8xJ2h1t0d2n1r6QpVQ9r2mBz3nQ0y7hK1sVc5vJ4wXk \
  --audit-profile /etc/mcp-re/audit-profile.json \
  --trust-document /etc/mcp-re/trust.json \
  --service-trust-pin /etc/mcp-re/service-key-pin.json \
  --issuer-kid auditor-1 \
  --issuer-key-seed /etc/mcp-re/auditor.seed \
  --out ./attestation.json \
  --register-to https://ts.example.com/scitt \
  --registration-timeout-secs 300 \
  --registration-poll-interval-secs 2
```

### The protocol

SCRAPI — **`draft-ietf-scitt-scrapi-11`, an Internet-Draft and not a published RFC.** That
matters operationally: drafts are renumbered, restructured and withdrawn, and this one names
its own media types and status semantics. Every refusal message states the revision it was
performed under, because "SCITT" alone does not identify a protocol anyone can reproduce.

The exchange: `POST <base>/entries` with the exact Signed Statement as `application/cose`;
`201 Created` returns the receipt; `202 Accepted` names a receipt resource in `Location`,
which is polled — `204` means *still working*, and a `200` yields the receipt. `--register-to`
is HTTPS; plaintext is admitted only to the loopback interface, where there is no network to
observe it.

### The receipt is not accepted because the HTTP succeeded

Before reporting success the receipt is verified with the **offline** verifier against two
things: the exact statement that was submitted, and the `ScittServiceTrustPin` you passed at
the start of the run. No key is fetched or refreshed during that check — the pin was loaded
before the audit began, and a verifier that reached out for a key while checking a receipt
would be verifying against whatever the network offered at that moment.

So an artifact that carries a `receipt` field is one whose receipt verified. There is no
other way for that field to appear.

### What a failed registration means, exactly

The attestation is written **before** anything is submitted, so a registration that does not
succeed costs you nothing but the receipt: the artifact is on disk, offline-verifiable, and
re-running the audit with the same `--at` reproduces the same statement byte for byte.

The exit status is non-zero, and the message distinguishes three states that must not be
confused:

| the message says | what it means |
| --- | --- |
| *the transparency service refused the statement* | Definitively **not** registered. The service read the submission and declined it. |
| *the transparency service is not accepting registrations* | Definitively not registered — rate limiting or over capacity. Retry later. |
| *the outcome is UNKNOWN — it may be registered* | The statement went out and what happened next is not knowable from here: a transport failure, an unreadable answer, a `202` whose polling budget ran out. **Do not treat this as a negative.** Re-submitting may put a second copy of the record in the log. |
| *a receipt came back and does not verify* | The service answered and its answer is unusable — either it is not the service your pin names, or the receipt is not about the statement you sent. This is a trust problem, not an availability one. |

## What this tool does not do

* **It supplies no out-of-band credential material.** A DPoP binding resolves from the
  covered `authorization` header the archive keeps verbatim. Anything else is not derivable
  from the archive, and a hop that needs it is reported unverifiable rather than verified
  against material somebody typed in.
* **It needs WRITE access to the archive directory.** The retention store's only
  constructor proves the directory writable — it writes and removes a probe object — so the
  auditor cannot currently run against a read-only mount or a snapshot. Copy the archive to
  a writable path.
* **It does not discover a service key.** The pin is cut out of band by
  `tools/scitt_fetch_service_key.py`, reviewed, and passed in. That split is what makes the
  offline property reproducible after the service is gone.

## Handling the archive

The retained records hold each message's **covered headers**, and this profile requires
`authorization` and `dpop` to be covered when present. A retained request therefore holds
the call's live bearer token and DPoP proof verbatim. **Handing an archive to an auditor
hands over replayable credentials.** Treat the copy the way you treat the original: `0700`
directory, `0600` objects, and a lifetime you chose.
