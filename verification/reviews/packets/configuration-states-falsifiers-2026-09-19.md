# ADR-MCPRE-068 Phase 2, slice 27 — a deployment that believes it has a control

Three probes, `M265`–`M267`, and a shape that has now appeared three times.

## 1. The default on an unreadable field is a lifetime

`UNIX_EPOCH` means **already expired**, so the next use refreshes: an unreadable STS expiry
costs a bounded window rather than an indefinite one. `M265` substitutes the ceiling, which
reads as a plausible value and means the opposite — a credential whose expiry could not be
established is held for the maximum.

The truncation travels in the same `Option` chain and is the same proposition from the other
end. `AssumeRoleWithWebIdentity` cannot issue a session longer than the role's
`MaxSessionDuration`, whose own ceiling is 12 hours, so a longer claim is not a lifetime the
peer can honestly promise. Nothing downstream re-reads the expiry — the cache refreshes on this
number alone.

## 2. The plausible defaults are the dangerous ones

`M266` defaults the authorization scope to `Principal` and the staleness bound to ten minutes —
exactly what somebody would reach for. The result is a deployment that runs, decides, and
reports an enforcing posture, under an actor scope and a staleness window the operator never
chose.

ADR-MCPRE-065 §8.3 is why neither may be defaulted: those two are what the **deployment**
decides, and a decision cannot supply either about itself. A default here would let the
document being judged set the terms it is judged under, one remove away.

## 3. Three instances of one shape

`M267` makes a gate that names no authority return `Ok(None)` — which **is** `--admission off`.
An operator who asked for admission enforcement and named no authority gets a deployment that
starts, reports the OFF posture, and admits every request; the OFF line is a legitimate line,
so nothing in the transcript reads as wrong.

| slice | the selected capability | what the weakening degrades it to |
|---|---|---|
| 12 | a grant deny-list no profile reads | accepted, enforcing nothing |
| 18 | a continuation store that cannot be established | the OFF posture |
| 27 | an admission gate naming no authority | the OFF posture |

**A selected security capability that cannot be established must never degrade into the posture
of a deployment that selected nothing.** Recorded as a pattern, not built into a mechanism: the
three refusals live in three owners and each is separately falsifiable, which is the correct
arrangement.

## 4. A control that measured one clause further on

`M267` failed first. `a_refused_configuration_recognises_no_state` supplies `"not-a-key"` —
non-empty and undecodable — so it measures the **decode** refusal, and the empty-authority
clause had nothing holding it. The written control names both spellings of nothing, an empty
string and whitespace, and the empty kid beside them.

## 5. What this slice discharged

| unit | probe | severity |
|---|---|---|
| `proxy.aws_sts_credentials` | `M265` | high |
| `proxy.authorization_configuration_state` | `M266` | high |
| `proxy.admission_configuration_state` | `M267` | high |

N1 moves 18 -> 15; the probe registry 286 -> 289. One control written.
