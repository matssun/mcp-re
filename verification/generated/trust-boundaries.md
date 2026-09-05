<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- GENERATED FILE — DO NOT EDIT.
     Regenerate with: tools/verification/generate-views
     Gated by:        tools/verification/check-generated
     Derived from:
       verification/policy/theorems.toml
       verification/policy/verification.toml
       verification/policy/assumptions.toml
       verification/policy/trust-boundaries.toml
-->

# Trust boundaries

Where MCP-RE stops being able to prove and starts having to trust, and what
each boundary carries. Derived by following assumption scope → boundary, and
scope → unit → theorem: the forward edges live in `assumptions.toml` and this
direction is computed, never stored.

A boundary with no premise is not thereby safe. It means no claim above V0 has
yet had to trust it — which is a fact about what has been proved so far, not
about the boundary.

| boundary | kind | class cap | premises crossing it | reaches theorems |
|---|---|---|---|---|
| boundary.clock | environment | V0 | _no premise_ | _no theorem_ |
| boundary.crypto_primitives | cryptographic | V0 | ASM-0027, ASM-0028, ASM-0037 | THM-0014, THM-0015, THM-0016, THM-0017, THM-0018, THM-0019, THM-0020, THM-0021, THM-0022, THM-0050, THM-0065 |
| boundary.external_kms | external-service | V0 | _no premise_ | _no theorem_ |
| boundary.libc | ffi | V0 | _no premise_ | _no theorem_ |
| boundary.monotonic_clock | environment | V0 | _no premise_ | _no theorem_ |
| boundary.pkcs11 | ffi | V0 | _no premise_ | _no theorem_ |
| boundary.rust_std | language-runtime | _no cap_ | ASM-0002, ASM-0003, ASM-0005, ASM-0006, ASM-0010, ASM-0014, ASM-0020 | THM-0001, THM-0002, THM-0003, THM-0004, THM-0005, THM-0006, THM-0007, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022 |
| boundary.shared_state_store | external-service | V0 | ASM-0040, ASM-0041 | THM-0092 |
| boundary.tls_mechanism | foreign-dependency | V0 | ASM-0033, ASM-0034, ASM-0035, ASM-0036, ASM-0039 | THM-0027, THM-0028, THM-0029, THM-0030, THM-0031 |
| boundary.unmodelled_own_behaviour | proof-lane | V0 | ASM-0001, ASM-0004, ASM-0007, ASM-0008, ASM-0009, ASM-0011, ASM-0012, ASM-0013, ASM-0018, ASM-0019, ASM-0021, ASM-0023, ASM-0024, ASM-0025, ASM-0026, ASM-0029 | THM-0001, THM-0002, THM-0003, THM-0004, THM-0005, THM-0006, THM-0007, THM-0009, THM-0010, THM-0014, THM-0015, THM-0016, THM-0017, THM-0018, THM-0019, THM-0020, THM-0021, THM-0022, THM-0065 |
| boundary.x509 | foreign-dependency | V0 | ASM-0030, ASM-0031, ASM-0032, ASM-0038 | THM-0024, THM-0025, THM-0026, THM-0032 |

6 of 11 declared boundary(ies) carry at least one registered premise.
