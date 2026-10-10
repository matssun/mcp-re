<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- GENERATED FILE — DO NOT EDIT.
     Regenerate with: tools/verification/generate-views
     Gated by:        tools/verification/check-views
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
| boundary.base64_encoding | foreign-dependency | V0 | ASM-0073, ASM-0075 | THM-0007 |
| boundary.clock | environment | V0 | ASM-0057, ASM-0061, ASM-0069, ASM-0076, ASM-0077 | THM-0001, THM-0003, THM-0004, THM-0005, THM-0006, THM-0014, THM-0016, THM-0017, THM-0019, THM-0020, THM-0021, THM-0022, THM-0039, THM-0053, THM-0057, THM-0058, THM-0063, THM-0075, THM-0106, THM-0107, THM-0116, THM-0117, THM-0120, THM-0127, THM-0129 |
| boundary.cose_cbor | foreign-dependency | V0 | ASM-0085 | THM-0041 |
| boundary.crypto_primitives | cryptographic | V0 | ASM-0018, ASM-0027, ASM-0028, ASM-0037, ASM-0049, ASM-0060, ASM-0065, ASM-0072, ASM-0074 | THM-0007, THM-0014, THM-0015, THM-0016, THM-0017, THM-0018, THM-0019, THM-0020, THM-0021, THM-0022, THM-0039, THM-0041, THM-0042, THM-0048, THM-0050, THM-0053, THM-0057, THM-0058, THM-0059, THM-0065, THM-0075, THM-0076, THM-0087, THM-0103, THM-0108, THM-0113, THM-0116, THM-0117, THM-0129 |
| boundary.external_kms | external-service | V0 | _no premise_ | _no theorem_ |
| boundary.filesystem | environment | V0 | ASM-0078 | THM-0045, THM-0088 |
| boundary.http_client | foreign-dependency | V0 | ASM-0082 | THM-0089, THM-0090 |
| boundary.inner_server_channel | deployment-topology | V0 | ASM-0050, ASM-0051 | _no theorem_ |
| boundary.json_parser | foreign-dependency | V0 | ASM-0083 | THM-0050, THM-0083, THM-0098 |
| boundary.libc | ffi | V0 | _no premise_ | _no theorem_ |
| boundary.manifest_floor_filesystem | environment | V0 | ASM-0084 | THM-0121 |
| boundary.monotonic_clock | environment | V0 | ASM-0079 | THM-0069, THM-0097, THM-0098, THM-0100, THM-0132 |
| boundary.napi_marshalling | foreign-dependency | V0 | ASM-0087 | THM-0095 |
| boundary.os_entropy | environment | V0 | ASM-0068 | THM-0062, THM-0063, THM-0114, THM-0133 |
| boundary.pkcs11 | ffi | V0 | ASM-0052, ASM-0053, ASM-0054 | THM-0116 |
| boundary.pyo3_marshalling | foreign-dependency | V0 | ASM-0088 | THM-0094 |
| boundary.rust_std | language-runtime | _no cap_ | ASM-0002, ASM-0003, ASM-0005, ASM-0006, ASM-0010, ASM-0014, ASM-0020, ASM-0056 | THM-0001, THM-0002, THM-0003, THM-0004, THM-0005, THM-0006, THM-0007, THM-0014, THM-0016, THM-0017, THM-0021, THM-0022, THM-0069, THM-0132 |
| boundary.shared_state_store | external-service | V0 | ASM-0040, ASM-0041, ASM-0044, ASM-0047, ASM-0048, ASM-0058, ASM-0059, ASM-0071, ASM-0081 | THM-0087, THM-0092, THM-0093, THM-0106, THM-0107, THM-0133 |
| boundary.tls_mechanism | foreign-dependency | V0 | ASM-0033, ASM-0034, ASM-0035, ASM-0036, ASM-0039, ASM-0070 | THM-0027, THM-0028, THM-0029, THM-0030, THM-0031, THM-0109 |
| boundary.unmodelled_own_behaviour | proof-lane | V0 | ASM-0001, ASM-0004, ASM-0009, ASM-0011, ASM-0012, ASM-0013, ASM-0021, ASM-0023, ASM-0024, ASM-0029, ASM-0045, ASM-0046, ASM-0066, ASM-0067 | THM-0001, THM-0002, THM-0003, THM-0004, THM-0005, THM-0006, THM-0007, THM-0009, THM-0010, THM-0014, THM-0016, THM-0017, THM-0019, THM-0020, THM-0021, THM-0022, THM-0057, THM-0058 |
| boundary.x509 | foreign-dependency | V0 | ASM-0030, ASM-0031, ASM-0032, ASM-0038, ASM-0080, ASM-0086 | THM-0024, THM-0025, THM-0026, THM-0032, THM-0131 |

19 of 21 declared boundary(ies) carry at least one registered premise.
