# CodeQL triage — the two recurring Rust false positives

CodeQL runs from [`.github/workflows/codeql.yml`](../../.github/workflows/codeql.yml)
against [`.github/codeql/codeql-config.yml`](../../.github/codeql/codeql-config.yml):
`push: main`, `merge_group`, and a weekly sweep. Two Rust rules produce essentially all
of this repo's alerts, and neither has ever produced a true positive here. This page is
the standing verdict so each new batch is triaged in one pass instead of re-derived.

## 1. `rust/hard-coded-cryptographic-value` — excluded by query id

Fires on the deterministic nonces and seeds that reproducible golden-vector conformance
*requires*. Excluded at the query level in `codeql-config.yml`, because these live in
`#[cfg(test)]` modules inside `src/` files that no `paths-ignore` filter can reach.

## 2. `rust/cleartext-logging` — triaged per alert, rule still enabled

Two distinct false-positive shapes. Both are dismissals, not code changes; the rule stays
on because it is the detector that would catch a genuine secret-logging regression in a
security proxy.

### Shape A — boot-posture logs (`false positive`)

The taint source is `Config::tls_cert` (`mcp-re-proxy/src/cli.rs:184`): the **path** to
the **public** PEM TLS server certificate chain. It is not key material, but CodeQL's
sensitive-data heuristic matches it by name and then taints all of `Config`
field-insensitively — so every startup log that reads any `config` field is reported,
whatever it actually prints.

The reported value is never the source. The `mcp-re-proxy/src/app.rs` sinks print the
resolved trust-epoch label, `config.mcp_protocol_versions`, and `config.max_clock_skew`.

What makes this safe is not the absence of these logs but where the one real secret
lives. The PKCS#11 User PIN is not a `Config` field at all:

- `--pkcs11-pin` is **refused** on argv (`cli.rs:685`) — a process command line is
  world-readable. Only `--pkcs11-pin-file <path>`, at the same permission floor as the
  other key files.
- In transit it is a `SecretString` (`cli.rs:38`), whose `Debug` renders
  `SecretString(redacted)` — so it cannot ride along into a structured log, panic
  message, or debug print of an enclosing struct.

### Shape B — `#[cfg(test)]` assert messages (`used in tests`)

`assert!` panic messages inside the test module (`cli.rs:2599` onward) that interpolate a
`SecretString` or a cert-derived `Result`. These are the **negative controls** that prove
the redaction: `a_secret_string_does_not_print_its_value_or_length` asserts the rendered
`Debug` contains neither the fixture value nor its length. The fixture is test-only and
unreachable at runtime.

### Why a batch can arrive with no code change

On 2026-08-27 the rust job on `main` went from **zero** new alerts at 08:07Z to **22** at
12:06Z with no source change: every flagged sink was 2--6 weeks old. What changed was the
analyzer. The 08:07Z run used CodeQL **2.26.3** from the runner toolcache; the 12:06Z run
downloaded **2.26.4**.

The extractor logs measure it directly:

| CodeQL | `macro expansion failed` warnings | rust job |
|---|---|---|
| 2.26.3 | **3916** (1599 `assert_eq`, 1239 `assert`, 359 `format`, 295 `vec`, ...) | 2m38s |
| 2.26.4 | **0** | 6m10s |

`rust/cleartext-logging` fires on format-macro arguments. Until 2.26.4 the extractor could
not expand ~3900 of this repo's `assert!` / `eprintln!` / `format!` sites, so those sinks
were invisible to the query; expanding them made the whole population visible at once and
tripled the job's runtime. A batch that appears overnight is therefore not evidence of new
logging -- check the CodeQL version in the run log and `git log -L` the sink before
treating it as a regression.

That batch also introduced a **third taint source** alongside `Config::tls_cert`:
`cert_der` in `ocsp.rs`, the DER of a **public** certificate. It is Shape B wherever it
appears (test assert messages), and the same reasoning applies -- a public certificate is
not key material.

### The one alert that was not just dismissed

`app.rs`'s inner-backend startup line was a Shape A false positive like the rest -- the
taint came from `tls_cert`, not from the URLs. But it was the only production sink echoing
an operator-supplied string verbatim, and a URL's authority is a place credentials ride
along. It now prints
[`RedactedBackendUrls`](../../mcp-re-proxy/src/deployment_request/inner_backend_display.rs),
a projection owned next to `SecretString` under `deployment_request`, whose sole
constructor drops any `userinfo` and reports only that it was present.

Dismissing an alert is a statement about the *taint path*. It is not a reason to leave a
sink that would be worth narrowing on its own merits.

### Triaging a new batch

Confirm each alert fits Shape A or Shape B — read the sink and check the logged
expression is not the tainted source — then dismiss:

```sh
gh api repos/:owner/:repo/code-scanning/alerts --paginate \
  -q '.[] | select(.state=="open") | [.number,.rule.id,.most_recent_instance.location.path,.most_recent_instance.location.start_line] | @tsv'

gh api -X PATCH repos/:owner/:repo/code-scanning/alerts/<N> \
  -f state=dismissed \
  -f dismissed_reason='false positive' \
  -f dismissed_comment='<why — 280 char limit>'
```

`dismissed_reason` is `false positive` for Shape A and `used in tests` for Shape B.
`dismissed_comment` is capped at **280 characters**; cite this page rather than restating
the argument.

An alert that fits **neither** shape is not covered by this verdict — a logged value that
is itself secret-derived is a real finding, and the fix is to stop logging it.

## The exclusion this repo deliberately has not taken

Excluding `rust/cleartext-logging` by query id, the way shape 1 is excluded, would end
the recurrence outright. It is left enabled on purpose: the FP rate is a naming heuristic
on a public cert path, whereas the rule's value is catching the one regression class that
matters most here — a secret reaching stderr. The redaction invariant is enforced by the
`SecretString` unit tests, and this rule is the independent second check on it.
