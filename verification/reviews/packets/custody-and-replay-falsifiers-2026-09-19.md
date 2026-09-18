# ADR-MCPRE-068 Phase 2, slice 21 — a posture that misreports is worse than none

Three probes, `M247`–`M249`. One of them settles a question the campaign has been counting.

## 1. The module says defence in depth; the measurement says sole carrier

`assert_durable` refuses a replay tier that self-declares the volatile single-process posture,
and its own comment calls that defence in depth — `--replay-cache memory` never reaches here,
because validation refuses it outright.

For *that selection* the comment is right. It is not right about the proposition, and the
measurement shows it: `M247` takes **both** declared controls red. The statement is the **sole**
carrier for two other populations:

- a store reached by some other selection path, and
- an **undeclared** backend, because `mcp_re_core::durability_class()` defaults to the
  single-process reference.

A redundant carrier would have left the controls green. So **this is not a second instance of
the compound-falsifier shape**, and the post-close-emission count stays at **one**: there, each
of two sites independently enforces the whole proposition; here the sibling refusal covers a
strictly smaller set of selections.

What the weakening costs is durability the operator believes they have — admitted nonces lost
on restart and invisible to peer verifiers, under a posture that advertises replay protection.

## 2. The length is not the check, again

`M248` is the same conjunct and the same weakening shape as `M219` on the AWS KMS adapter. A
token configured with a prehash or over-hashing CKM mechanism returns a perfectly well-formed
**64 bytes** that verifies under nothing, and so does a mis-bound key: the shape is right and
the signature is wrong.

Two adapters, two units, one rule — and each needs its own falsifier, because a third provider
could implement the rule in neither.

## 3. A weakening that breaks nothing

`M249` is the odd one out: under it, **nothing stops working**. A file-seed deployment keeps
signing exactly as before. The only thing that changes is what it *says about itself*.

`PrivateKeyExposure` is the semantic answer ADR-MCPRE-067 consumers read — it names no
mechanism, deliberately — so a consumer asking whether the private key can be read out of this
process is told **no** while the seed sits in the process's own memory.

That is why the classifier and the projection are one unit. A posture nobody can act on is
worth nothing; a posture that misreports is worse than none.

## 4. What this slice discharged

| unit | probe | severity |
|---|---|---|
| `proxy.replay_materialization` | `M247` | critical |
| `proxy.pkcs11_adapter` | `M248` | critical |
| `proxy.custody_exposure` | `M249` | critical |

N1 moves 36 -> 33; the probe registry 268 -> 271.
