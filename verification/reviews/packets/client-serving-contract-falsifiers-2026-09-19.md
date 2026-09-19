# ADR-MCPRE-068 Phase 2, slice 22 — the default is the decision

Three probes, `M250`–`M252`. One of them found a defect in the lane rather than in the tree.

## 1. A one-token edit that no reader would flag

`ExecutionContract::execution` maps an absence to `Unstated`. `M250` maps it to `NotExecuted`
instead — nothing validates, nothing refuses, and the whole proposition is **which of two
answers an absence means**.

| answer | what a caller does |
|---|---|
| `Unstated` | the question is open; reconcile before retrying |
| `NotExecuted` | the question is closed; retry |

And if the work did run, the retry runs it twice, under a fresh nonce that passes replay
admission.

The `Unrecognized` arm is not a second carrier: it covers a value the server DID send that this
client does not know — a third fact again. Three answers, one match, and collapsing any two is
a silent change of meaning rather than a broken mechanism.

## 2. The third adapter, the third falsifier, one rule

`M251` is the same conjunct as `M219` (AWS KMS) and `M248` (PKCS#11): a signature is verified
locally against the advertised key before it is returned. Three adapters implement it
independently, so each needs its own probe — a fourth provider could implement it in none of
them and no existing probe would notice.

**Recorded as a Phase-2 observation, not acted on:** three independent implementations of one
proposition is a candidate for a shared owner. That is an ADR-MCPRE-061 question 2 question,
not a falsifier question.

## 3. `let _ =` rather than a deletion

`M252` attacks *held for as long as it serves* and leaves *started* alone: the refresher is
still started, and is dropped at the end of the statement. Nothing on the request path
withdraws anchors, so a client without a running refresher keeps verifying against the anchors
it loaded at startup for as long as it runs — including after the manifest in force has passed
its own `expires_at` — and every unit test of the refresher would still pass while it did.

## 4. The probe that was blamed for the lane

`M252` first reported MEASUREMENT FAILURE. Applying its weakening by hand takes the control red
in 31 seconds; through the lane it "measured nothing" in **0.77** — the shape of a run that
never happened, which is the fact this lane exists to refuse, one level down.

`_ecosystems` declares four Cargo target shapes; the lane built its own argv from two of them,
so `bin/mcp-re-client` became `--test -re-client`. Cargo refuses that with a message which is
not a build failure, so the lane read an empty result set.

`bin/<name>` is not exotic. It exists because **a deployable's own crate is not its library**:
what a client binary does at startup lives in the binary, and there is no other target to test
it through. Fixed in the lane — it calls the seam now, and the lane-local `target_argv` is
gone.

## 5. What this slice discharged

| unit | probe | severity |
|---|---|---|
| `client.execution_contract` | `M250` | critical |
| `proxy.gcp_kms_adapter` | `M251` | critical |
| `client.serving_lifetime` | `M252` | critical |

N1 moves 33 -> 30; the probe registry 271 -> 274.
