<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-170 — R6 ratification packet: Ed25519 signing is a deterministic function of seed and message

**Disposition:** referred. One control, one `[[disposition]]` row, one record. Nothing
registered.

## Provenance

Split out of NP-106 by RR-002 C5 during the RM-S1 repair. It was one of thirteen controls filed
whole into `unit://core.ed25519_primitive` under THM-0014, and an adversarial review of PR #1018
named it as one of the five it could see were outside that theorem.

## The control and what it states

`lib#crypto::tests::signature_is_deterministic_for_fixed_seed`, whose whole body is:

```rust
let sk = SigningKey::from_seed_bytes(&SEED);
let preimage = b"hello";
// Ed25519 is deterministic; same seed + message -> same signature.
assert_eq!(sk.sign(preimage), sk.sign(preimage));
```

The proposition: **`sign` is a function of `(seed, message)` and of nothing else.** No clock, no
randomness, no interior state.

## Why THM-0014 does not contain it, and why no other theorem does either

THM-0014 constrains a VERIFIER: what it means that `verify_request_floor` returned Ok. It
mentions no signer, and it has to mention none — the requests it verifies are signed by peers,
not by this process.

The operational test is decisive and does not need a reading of the words. Replace
`ed25519_dalek`'s deterministic nonce with a random one. Every signature this signer emits still
verifies under the matching key, so every clause of THM-0014 is still true of every request the
floor admits, and so is every clause of THM-0021 on the response side. This control is false and
nothing in the theorem registry notices. A proposition whose falsehood is invisible to a theorem
is not a decomposition of it.

Every other theorem over `mcp-re-core/src/crypto.rs` was checked and has the same shape: an
`Ok ⟹ …` statement about a verification, indifferent to how the signature was produced.

## What the control is actually protecting, which is why it should be ratified somewhere

`SigningKey`'s own documentation states the dependency:

> Pure and I/O-free: signing belongs in the library (it has no side effects) and is needed to
> generate reproducible conformance vectors (MCPS-002).

The conformance vectors and the SDK-parity fixtures pin EMITTED BYTES. Under a randomised
signer those lanes do not fail — they become vacuous in the worst way, because a byte mismatch
would no longer distinguish a wrong implementation from a fresh signature, and the lane's only
honest response would be to stop comparing bytes. So the proposition this control holds is a
premise of an evidence lane rather than of a runtime refusal, which is a real distinction this
register already makes elsewhere and the reason the severity here is `high` and not `critical`.

## Proposed shape for ratification

A theorem owned by a new unit over the SIGNER half of `mcp-re-core/src/crypto.rs`:

> For a fixed 32-byte seed and a fixed message, `SigningKey::sign` returns one Base64URL
> signature, always. The conformance vectors and the SDK-parity fixtures are comparisons of
> emitted bytes and are evidence only under this.

Its natural dependents are the parity and conformance lanes, not the verification theorems,
which is the correct direction and the reason it could not be folded into either.

## N1

Nothing registered. No unit changed. No obligation moves.
