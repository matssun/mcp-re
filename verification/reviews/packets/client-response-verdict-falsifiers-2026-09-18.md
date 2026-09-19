# ADR-MCPRE-068 Phase 2, slice 13 — what a verified reply entitles a client to conclude

Four probes, `M224`–`M227`, over the three client-side units that split one question into
three: **who signed it**, **does it answer this request**, and **what does it say**. The
split is ADR-MCPRE-061's question 2 applied to a verdict, and each probe shows why the
neighbouring unit is not a second carrier.

## 1. The signature cannot carry the binding

A preflight receipt is signed over RESPONSE components only — no `@method`, no `;req` binding
— because the request never earned a trustworthy hash. So a verifying delegated signature
proves the issuer said it and says **nothing about which request it answers**. One such
receipt would otherwise answer every request from every client of that issuer for the
credential's whole validity window.

`M224` weakens the digest comparison. Its sibling — the digest-ALGORITHM check one line above
— is a separate conjunct, not a second carrier: it refuses a receipt whose commitment this
client cannot compare, and admits every correctly-shaped commitment to somebody else's bytes.

## 2. The fork, not the verifier

`M225` weakens `if (200..300).contains(&response.status)`, which sends a 2xx down the
rejection-receipt path — where an unbound verification is a legitimate outcome. Both verifiers
are correct; the defect is **reaching the wrong one**, which is why the fork is the anchor.

That is the shape the unit forbids in its own words: *there is no path on which a failed bound
verification is retried as an unbound one.*

## 3. The trust picture is not the pin

A credential chaining to another root the current manifest resolves is fully trusted — the
signature verifies, the chain resolves, revocation says nothing. Every gate around the pin
passes. The pin is the only statement that says **this route answers to that issuer and no
other**, and it is compared against the ROOT issuer rather than the rotating delegated kid,
which is what makes it survive a delegation rotation.

`M227` takes three controls red, one per shape the pin holds over: a success, a bound
rejection receipt, and a bodyless 202.

## 4. The `?` is the carrier

`M226` does not delete a check. `continuation_state_of` answers three ways — terminal,
non-terminal with a usable state, or MALFORMED — and the weakening discards the third,
folding *not classifiable* into *terminal*. A reply that announces itself non-terminal and
carries no usable `requestState` then resolves as a success an answer leg could never be
honoured for, and an unrecognized `resultType` — a set MCP 2026-07-28 closed — becomes
terminal too.

One anchor, both controls red: the *one carrier, several conjuncts* shape slice 4 named.

## 5. What this slice discharged

| unit | probes | severity |
|---|---|---|
| `client.response_binding_disposition` | `M224`, `M225` | critical |
| `client.response_signer_authorization` | `M227` | critical |
| `client.verified_outcome` | `M226` | critical |

N1 moves 56 -> 53; the probe registry 245 -> 249.
