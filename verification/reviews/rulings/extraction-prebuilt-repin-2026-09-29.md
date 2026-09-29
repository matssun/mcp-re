# The extraction instrument is the pinned Aeneas/Charon prebuilt pair

Owner ruling, 2026-09-29. ACCEPTED.

## The instrument

The extraction image (`[extraction_container]`, tag `tc-ac2daa3af3dcc7c4`, artifact
`sha256:ce0df16f21fb96766708409e80f6c788bd3d42c32a0912576924512a4b7b3c02`) installs upstream
release binaries and builds neither tool:

| tool | release | commit | archive SHA-256 |
|---|---|---|---|
| Aeneas | `nightly-2026.09.07-8d58d14` | `8d58d14ad655b3d871af1038c203c3f524ab4df9` | `d170dde7f25cb32604b376f6f74ae442c2e407d20353ce331a2fc269522f7967` |
| Charon | `nightly-2026.09.04` | `b82d2748c1e5bfd9519cd9401f9186d33b44a7f1` | `ef0fc8a0c40e0b57e36ccca035f22a78ce2ad97acabc1bde8134b2314a3b0516` |

The pair is the one Aeneas declares, checked three ways at build time: the Aeneas commit's
`charon-pin` names the Charon commit; the Charon binary states that commit; and the Charon
binaries the Aeneas release ships are byte-identical to the pinned Charon release's. Every
executed binary is digest-pinned in `verification/policy/toolchains.lock.toml` and re-digested
by `tools/verification/extraction-image smoke`. `scripts/extraction_image_gate.py` holds the
definition to installing the two tools only as pinned, digest-checked downloads.

## The model difference, accepted

The previous instrument (Aeneas `daa85d7`, Charon `340b1af`, built from source) and this one
extract `verification/lean/generated/McpReCore.lean` from identical Rust. The regenerated file
differs by exactly these three lines, in the generated preamble:

```text
+set_option linter.style.whitespace false
+set_option linter.style.setOption false
+set_option linter.style.longLine false
```

Accepted as an instrument preamble/linter change, not a semantic model change: every
generated definition is byte-identical, `verify-lean` passes on the regenerated model, and the
axiom closure is unchanged — the declared kernel baseline.
