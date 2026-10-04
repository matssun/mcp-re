# Ruling 12 premise restatements — THM-0074 and THM-0075 dependency digests move

Written under the owner's standing instruction to finish the Ruling 12 run, pending the
owner's later fingerprint review. A correction record is not an approval.

## What moved, measured

Between `cfdcd1ce` (where the previous correction chain ends) and HEAD, the only edits to
`verification/policy/theorems.toml` are the Ruling 12 remediation commits (6e86fb53,
d6afcd01, e18b571e, afe1cacb, ab761689 and neighbours). For both roots, `theorem_claim`,
`depends_on` and `review_requirement` are byte-identical across that range; only
`theorem_dependencies` moved.

| root | from | to | premises whose claim digest moved |
|---|---|---|---|
| THM-0074 | `74c38cc0fce8b28d` | `06584e94261de88b` | THM-0004, 0006, 0010, 0073, 0087, 0106, 0107 |
| THM-0075 | `35ccabd23e0f7459` | `3b4f10cb7ea14d66` | THM-0063, 0073, 0082 |

Neither root's statement, security consequence or scope is edited, so what a reader may rely
on for either root is the text they already reviewed.

## Per-premise classification (from the diff)

| premise | edit | direction |
|---|---|---|
| THM-0004 | conjuncts re-routed through `authenticate_admission` | restated, same conjuncts |
| THM-0006 | adds "verdict carries the same actor" | strengthened |
| THM-0010 | handles compared with retained evidence handles; store retains no signature base | restated + strengthened; one clause relocated (below) |
| THM-0073 | scope names the pinning control; supported_by gains a unit | evidence added |
| THM-0087 | "bases" -> "handles"; scope names ASM-0060 | restated; reliance disclosed |
| THM-0106 | PX TTL padded by divergence bound; policy scope names ASM-0059 | strengthened; assumptions named |
| THM-0107 | lease TTL padded by divergence bound | strengthened |
| THM-0063 | delegated key crate-private, emitters take a window | strengthened |
| THM-0082 | witness by type, eager fallible reads pinned | strengthened |

## For the owner, not asserted away

1. THM-0010: that each retained handle was minted under its own role label is no longer a
   clause of THM-0010's proof; its scope assigns it to `RetainedHandles::over`, measured in
   `proxy.continuation_correlation_store`.
2. THM-0106/0107: THM-0074's transitive closure now rests on named assumptions ASM-0059
   (`noeviction` on every reachable server) and ASM-0061 (replica clock divergence bound),
   and THM-0087 on ASM-0060. The old texts left these to "operator control" or an implicit
   digest property; the TTL change only lengthens retention.

Neither is a change to what THM-0074 or THM-0075 states. Both are the owner's to confirm at
the next specification review.

## Every theorem the gate now enforces over the same range

The gate's "not moved" half also enforces theorems whose own claim, or a premise beneath
them, moved over the same range. One record per theorem, each from the reviewed fingerprint
(which equals the registry's at `cfdcd1ce` in every case) to the current one:

| theorem | moved | cause |
|---|---|---|
| THM-0004, 0006, 0010, 0063, 0073, 0087, 0106, 0107 | own claim | rows above |
| THM-0082 | own claim and premise THM-0073 | rows above |
| THM-0104 | own claim | connection-granular drain, item 13 (dd8cf80a): reply delivery added, admission-stop and bounded wait kept |
| THM-0125 | own claim | structurally invalid binding is unconstructible rather than refused at signing, item 12 (afe1cacb) |
| THM-0009 | premise THM-0010 | cascade |
| THM-0077 | premise THM-0073 | cascade |
| THM-0078 | premise THM-0063 | cascade |
| THM-0092 | premises THM-0106, 0107 | cascade |
| THM-0093 | premise THM-0087 | cascade |
| THM-0129 | premise THM-0004 | cascade |
| THM-0074, 0075 | premises listed above | cascade; root text unchanged |

Where a non-root theorem's own claim gained a conjunct (THM-0006, 0010, 0063, 0082, 0104),
that is a strengthening the Phase-1 ruling's "not materially expanded" wording would not
cover by itself. The owner ordered each restatement in Ruling 12 and the records say so; the
owner's confirmation of those fingerprints is still owed.
