# THM-0091: stale specification review, tracked

Not part of #1074's five, not caused by it, and not changed by it.

| | fingerprint | claim digest |
|---|---|---|
| reviewed (owner ruling 2026-09-02, first and only review, `THM-0091.json`) | `sha256:21502a0d158da5aaca9a2eff9c07d4c612a5e16b297f1b241135df9ea7e6b7f8` | `sha256:12966c7af1075408f004c454f73cb905cb280ced31b4c00606fea714cc0aad21` |
| current | `sha256:20f89a291e53e454086014366d76597919e7bfb98eb509246e9a8c54a77ee6e6` | `sha256:892ff5f8e344b85c990ffa314ed2ca4f8d3e4121f50f3c1e5db6dda2f99e12f3` |

State: `STALE_CLAIM: changed since review: theorem_claim`. It has no premises
(`depends_on = []`), so only its own statement and scope moved.

What moved, and its authority: `verification/claim-corrections/THM-0091-2026-09-18.json`
(`adr-068-phase1`, item 1) records the statement and scope correction. The security
consequence is byte-identical, severity stays critical, and the record says explicitly that
the owner did not individually review this fingerprint. The claim-surface gate accepts the
chain; the specification review axis does not refresh.

Evidence recorded for the correction: the packet
`verification/reviews/packets/thm-0091-consequence-decomposition-2026-09-18.md`; structural
probes S22 and S23 reported refused by E0451; seven supporting units
(`client.accepted_authority`, `…_sole_producer`, `client.bind_scope`, `…_sole_producer`,
`client.caller_shape_admission`, `client.local_leg_declaration`,
`client.local_request_surface`). Local unit evidence prints UNKNOWN for want of
attestations, which is not a measurement.

Next action (owner): a specification review of the corrected statement and scope against that
packet, recorded at the current fingerprint. It is independent of THM-0076: THM-0091 is a
declared root of its own. Not scheduled by this PR, and it does not gate #1074.
