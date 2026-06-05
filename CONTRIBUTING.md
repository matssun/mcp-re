<!-- SPDX-License-Identifier: Apache-2.0 -->

# Contributing to MCP-S

Thank you for considering a contribution to MCP-S.

MCP-S is an experimental third-party security extension proposal for the Model Context Protocol. Contributions should preserve the project's security boundaries and must avoid implying official MCP status unless the extension is accepted through the official MCP process.

## Licensing of contributions

Unless otherwise stated, all contributions intentionally submitted to this repository are licensed under the Apache License, Version 2.0.

By submitting a contribution, you represent that you have the right to submit it under the Apache License, Version 2.0.

## Contribution expectations

Contributions should:

- preserve the distinction between MCP-S Core, policy profiles, transport hardening, and deployment-specific integrations;
- include tests for security-relevant behavior;
- fail closed on malformed, unknown, or unsupported security inputs;
- avoid broadening the project's public claims without updating the Security Boundary Document;
- update documentation and conformance manifests when behavior changes.

## Security-sensitive changes

Changes touching any of the following areas require special review:

- signature verification;
- canonicalization;
- nonce/replay handling;
- trust resolution;
- authorization profile evaluation;
- transport binding or mTLS;
- key loading or signing;
- verified-context injection;
- inner-server isolation;
- conformance vectors;
- public security claims.

Security-sensitive changes should include positive tests, negative/fail-closed tests, traceability to requirements, and notes about what is not covered.

## Experimental status

MCP-S is incubating under a third-party extension identifier. Do not describe it as an official MCP extension unless accepted through the official MCP governance process.

## Developer workflow

Suggested baseline check before opening a PR:

```text
bazel test //...
```

Use the repository-specific MCP-S conformance guide when available.
