//! Conformance runner + machine-readable report (MCPS-010).
//!
//! Executes a slice of [`VectorCase`]s against a [`ConformanceTarget`] and
//! produces a deterministic, serializable [`RunReport`]. A case passes iff the
//! target's actual wire token equals the vector's expected token.

use serde::Serialize;

use crate::target::canonical_request_hash;
use crate::target::ConformanceTarget;
use crate::target::RunContext;
use crate::vector::VectorCase;

/// The name of the canonical valid request whose `request_hash` seeds response
/// verification (responses in the committed suite bind to this request).
const CANONICAL_REQUEST_NAME: &str = "v1_valid_request";

/// Outcome of running a single vector.
#[derive(Debug, Clone, Serialize)]
pub struct CaseResult {
    pub name: String,
    pub kind: String,
    /// Expected wire token (`verify_ok` or `mcps.*`).
    pub expected: String,
    /// Actual wire token produced by the target, or a harness error string.
    pub actual: String,
    pub pass: bool,
    pub requires_pipeline: bool,
}

/// Aggregate, serializable result of an object-suite run.
#[derive(Debug, Clone, Serialize)]
pub struct RunReport {
    pub results: Vec<CaseResult>,
    pub passed: usize,
    pub failed: usize,
    pub total: usize,
}

impl RunReport {
    /// Whether every case passed.
    pub fn all_passed(&self) -> bool {
        self.failed == 0 && self.passed == self.total
    }

    /// Serialize to pretty JSON (deterministic field order via `serde`).
    pub fn to_json_string(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("serialize report failed: {e}"))
    }

    /// Human-readable summary, one line per case plus a totals line.
    pub fn to_human_string(&self) -> String {
        let mut out = String::new();
        for r in &self.results {
            let mark = if r.pass { "PASS" } else { "FAIL" };
            out.push_str(&format!(
                "{mark}  {:<34}  expected={:<28} actual={}\n",
                r.name, r.expected, r.actual
            ));
        }
        out.push_str(&format!(
            "\n{} passed, {} failed, {} total\n",
            self.passed, self.failed, self.total
        ));
        out
    }
}

/// Build the [`RunContext`] for a suite: locate the canonical request and
/// compute its `request_hash` so response vectors can verify against it.
fn build_context(cases: &[VectorCase]) -> RunContext {
    let canonical = cases
        .iter()
        .find(|c| c.name == CANONICAL_REQUEST_NAME)
        .or_else(|| {
            cases
                .iter()
                .find(|c| c.kind == "request" && c.expected == "verify_ok")
        });
    let canonical_request_hash = canonical.and_then(|c| canonical_request_hash(c).ok());
    RunContext {
        canonical_request_hash,
    }
}

/// Run every vector through `target` and assemble a [`RunReport`].
pub fn run_suite(target: &dyn ConformanceTarget, cases: &[VectorCase]) -> RunReport {
    let ctx = build_context(cases);
    let mut results = Vec::with_capacity(cases.len());
    let mut passed = 0usize;
    let mut failed = 0usize;

    for case in cases {
        let expected = case.expected();
        let (actual, pass) = match target.run_case(case, &ctx) {
            Ok(outcome) => {
                let pass = outcome.matches(&expected);
                (outcome.as_token().to_string(), pass)
            }
            // A harness error (malformed vector) is a failure of that case.
            Err(harness_err) => (format!("harness_error: {harness_err}"), false),
        };

        if pass {
            passed += 1;
        } else {
            failed += 1;
        }

        results.push(CaseResult {
            name: case.name.clone(),
            kind: case.kind.clone(),
            expected: expected.as_token().to_string(),
            actual,
            pass,
            requires_pipeline: case.requires_pipeline,
        });
    }

    let total = results.len();
    RunReport {
        results,
        passed,
        failed,
        total,
    }
}
