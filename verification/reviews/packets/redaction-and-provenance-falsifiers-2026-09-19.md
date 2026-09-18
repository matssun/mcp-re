# ADR-MCPRE-068 Phase 2, slice 25 — what reaches an operator's eyes

Three probes, `M259`–`M261`. Each proposition is about what a deployment SAYS, and in two of
them the weakening leaves every mechanism working.

## 1. A `Debug` impl is a security carrier

A deployment request is derived-`Debug` all the way down and printed by ordinary diagnostics.
Nothing at a call site decides whether the PKCS#11 User PIN is safe to render, and no reviewer
sees the moment it happens — **the type is the only thing stopping it**.

The PIN unlocks a token holding the response-signing key, so it sits in the same custody class
as the key itself. The redaction carries **no length** either, because a PIN's length is worth
guessing with.

The sibling control — *the value is still readable where it is needed* — stays green under
`M259`, correctly: the seal is about the rendering, not about access.

## 2. Startup is where a stale CRL is still a configuration fact

The verifier enforces CRL expiration, so a replica that installs a CRL past its `nextUpdate`
fails every new client handshake closed — correctly, and with no way for the operator to tell
that the cause is their own revocation list rather than the clients. Refusing to produce
evidence from it turns a silent outage into a **named startup refusal**.

The NEAR-EXPIRY arm is not a second carrier: it warns and returns `Ok`, deliberately, so a
refreshed CRL can be installed before the window closes. Two arms, one measurement, a graded
response — and only the stale one refuses.

## 3. Whose vocabulary it is

An authorization refusal has two arms: a **policy denied this**, and the deployment **could not
establish the action** to ask about. Both are non-grants and both are served as an
`mcp-re.authorization_*` token, so a reader that sees only the served code cannot tell them
apart — and `M261` serves one token for both.

The subordinate `PolicyError -> mcp-re.authorization_*` mapping belongs to
`mcp_re_policy::PolicyError` alone. This boundary asks each authority what it says and adds
nothing, so a constant here is this file **minting vocabulary it does not own** — the defect
whether or not the constant happens to be a legal token today.

`M261`'s first `expect_red` named the core-producer control and it stayed green, correctly: the
weakening touches only the Authorization arm. A probe is adjudicated against the control that
measures the arm it weakens.

## 4. Two weakenings that did not build

Both `M259` and `M260` were re-adjudicated once. `SecretString` wraps a
`zeroize::Zeroizing<String>`, so `write!("{}", self.0)` does not compile; `Ok(drop(format!(`
leaves a type the match arm cannot produce. The lane refused both as measurement failures
rather than reporting anything about the conjuncts — the right answer to a tree that does not
build, and the third time this campaign has relied on it.

## 5. What this slice discharged

| unit | probe | severity |
|---|---|---|
| `proxy.operator_facing_redaction` | `M259` | high |
| `proxy.client_revocation_currency` | `M260` | high |
| `proxy.refusal_provenance` | `M261` | high |

N1 moves 24 -> 21; the probe registry 280 -> 283.
