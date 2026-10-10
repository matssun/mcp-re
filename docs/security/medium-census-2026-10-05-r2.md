# Medium-finding census, refreshed — 2026-10-05 (r2)

Read-only classification of every actionable medium (`open`, `provisional`, `confirmed`) in
`docs/security/finding-ledger.jsonl`, **pinned at `db3b551f`**: **51 rows, 47 distinct
defects**. Machine-readable table: [`medium-census-2026-10-05-r2.jsonl`](medium-census-2026-10-05-r2.jsonl).

This supersedes nothing silently. The first census
([`medium-census-2026-10-05.md`](medium-census-2026-10-05.md)) is pinned at `aa9ed8fd` and
described **104** rows; the live ledger stood at **103** when it was read back (`2ca90cad`
closed by F2). Between the two pins:

| movement | rows |
|---|---:|
| pinned census rows | 104 |
| closed by F2 before this refresh (`2ca90cad`) | −1 |
| r10 mediums closed by reconciliation R1/R5/R7/R8/R9 (no-longer-present or duplicate, every closure second-reviewed) | −43 |
| pinned rows still present, re-identified under current ids (the old row becomes a duplicate of its successor) | −31 |
| current medium findings minted for them (several old rows fold into one) | +21 |
| adjacent defect found by the second review (`343ce9e4`) | +1 |
| **actionable mediums at `db3b551f`** | **51** |

Of the 52 M6 closure candidates the first census named, 43 closed on their own evidence; the
other 9 were still present. Across all five batches the adversarial review refuted 6 first-pass
closures and amended 3 (108 closures reviewed, at every severity). The 70% candidate rate did not hold as a closure rate, and was not used as one.

## The four questions

| question | rows | distinct defects |
|---|---:|---:|
| 1. production behaviour must change | 14 | 14 |
| 2. type / API hardening, no behavioural bug | 17 | 17 |
| 3. test / evidence, theorem / registry, or claim text only | 14 | 13 |
| 4. genuinely blocked | 6 | 3 |
| **total** | **51** | **47** |

Question 3 splits as: test / evidence 5, theorem / registry 4, claim text 5 (a posture line,
module comment or operator guide that states something the code does not — production text,
no behaviour change).

Question 4 is two blockers, neither folded into the production-code number:

- **M7 infrastructure** — the `sdk/python` pinned-root trio (`31419f23`, `83208e90`,
  `9cf9662b`; one defect), behind the Bazel `py_test` lane.
- **F1 owner surface** — `0f0dc26c`, `b86c0b8d`, `e49adade` (two defects). Both ratified
  seals need Verus premise surfaces the ratification did not cover: a type with private fields
  cannot have a transparent `external_type_specification` (measured: `private fields not
  supported for transparent datatypes`), so each sealed type joins ASM-0046's opaque list, and
  the block's seal also needs a getter premise under the continuation-unbypassability
  postcondition, which reads `request_block.continuation` as a field. Escalated 2026-10-05.

Four rows are **owner-question candidates**, not blocked yet: `2942e46a` (continuation quota
policy), `f3e6d4f0` (delegated deployment without a trust-epoch source), `7419544c`
(placeholder trust domain), `fb29f893` (epoch-store write premise). Each is tested against the
two-admissible-remedies rule when its batch runs.

## Rows versus distinct defects

Distinct defects fold only rows that state one defect side by side: the SDK trio (1), the two
Verus reproducer `ensures` rows `90cdf796`/`ddbee9c2` (1), and the F1 role-typing pair
`b86c0b8d`/`e49adade` (1). Shared fixes below do NOT fold rows: one change can close several
distinct defects, and each still closes only on its own post-change evidence.

## Proposed batches, re-derived at `db3b551f`

| batch | question | rows | shared fix and the ids it is expected to close |
|---|---|---|---|
| B4 seal public values | Q2 | `04683c6a`, `11bd6924`, `51bb21a2`, `d08f262d`, `d4966e39` | none — five owners, one pattern |
| B5 MCP transport contract | Q1 ×3, Q2 ×2 | `1cce4612`, `46bf0c30`, `aee88e1f`, `b4648cd2`, `cd5dd994` | narrow `McpTransportPolicy` API: `b4648cd2`, `cd5dd994` |
| B6 config coordinate canonical form | Q1 | `0746d8e0`, `094e44dd` | refuse a coordinate that differs from its trim: both |
| B7 custody issuance and lifecycle | Q1 ×2, Q2 ×2, Q3 ×1 | `0d3f59f5`, `630acbf3`, `4519b138`, `d46ed638`, `86743e76` | bound the issued window: `0d3f59f5`, `630acbf3` |
| B8 serving capabilities | Q2 ×2, Q3 ×6 | `13e5191c`, `7c9949b4`, `b8fa7c66`, `38769270`, `445eb5f9`, `4f63fcdf`, `7793ddd9`, `c87a43d4` | audit seam returns an `Established` capability: `13e5191c`, `7c9949b4`, `b8fa7c66`; posture lines derived from the installed capability: `38769270`, `445eb5f9`, `4f63fcdf`, `7793ddd9`, `c87a43d4` |
| B9 liveness and budgets | Q1 | `195be657`, `22df94d6`, `7dc00d40`, `2942e46a` | `--trust` reloader liveness and budget: `22df94d6`, `7dc00d40` |
| B10 TLS plane retirement contract | Q3 | `b6c5fda5` | — |
| B11 verification registry | Q3 | `218bdb7d`, `90cdf796`, `ddbee9c2`, `fb29f893` | register the Verus ICE ceiling: `218bdb7d`, `90cdf796`, `ddbee9c2` |
| B12 test evidence | Q3 | `2c13658e`, `f0015b94` | — |
| B13 owner-question candidates | Q1 | `7419544c`, `f3e6d4f0` | — |
| B14 singletons | Q1 ×1, Q2 ×3 | `1eec3590`, `9a4744a7`, `a1379559`, `a3a9c140` | — |
| B16 key-custody export (new) | Q2 | `343ce9e4`, `3757220b` | — |
| B3 F4 residue | Q2 | `9c5a6680` | F4 retired the sync Redis/etcd stores but `HttpReplayKey::check_and_insert` (http-profile `replay.rs:87`) is still public: not absorbed |
| B1 F1 | Q4 | `0f0dc26c`, `b86c0b8d`, `e49adade` | escalated |
| B15 SDK | Q4 | `31419f23`, `83208e90`, `9cf9662b` | one resolver, behind the SDK lane |

B10 (`b6c5fda5`) is the successor of the first census's TLS-plane pair `6297cdd7`/`b70e342b`;
`6297cdd7`'s duplicate closure was refuted by the second review and both now carry forward
as this one row.

## Also open, outside the medium set

`557e664c` (low, test evidence): the Rust conformance replay never compares the oracle's
`signature_base_b64url`. `cd5dbac0` is now recorded as a duplicate of `51bb21a2` rather than
`fixed`.
