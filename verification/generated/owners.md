<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- GENERATED FILE — DO NOT EDIT.
     Regenerate with: tools/verification/generate-views
     Gated by:        tools/verification/check-generated
     Derived from:
       verification/policy/theorems.toml
       verification/policy/verification.toml
       verification/policy/assumptions.toml
-->

# Owner view

Each review unit and the claims it is the semantic authority for. A unit with no
theorem is shown too: an unclaimed unit is a question for the specification work,
not an omission to hide.

| unit | class | owns theorems | assumptions |
|---|---|---|---|
| core.time_rfc3339 | V1 | THM-0002 | 4 |
| http_profile.admission_currency | V1 | THM-0003, THM-0004, THM-0005, THM-0006 | 4 |
| http_profile.artifact_typing | V1 | THM-0007, THM-0008 | 3 |
| http_profile.continuation_binding | V1 | THM-0010 | 1 |
| http_profile.continuation_unbypassability | V1 | THM-0009 | 1 |
| http_profile.freshness_window | V1 | THM-0001 | 6 |
| http_profile.keyid | V0 | _none_ | 0 |
| proxy.online_ocsp_reachability | V0 | THM-0013 | 0 |
| proxy.runtime_lifecycle | V0 | THM-0012 | 0 |
