// SPDX-License-Identifier: Apache-2.0
//! The composition root reads only ORDINARY validated parameters from the request.
//!
//! ADR-MCPRE-056's completion criterion has a fourth clause, and this is it: after layer A
//! has classified a deployment, the original request stops being a semantic authority. A
//! plane must not reach back for a posture (that is `plane_config_reachback_test`), and the
//! ROOT must not reach back for a decision — which is a different failure, because the root
//! is entitled to read the request. It builds things out of it.
//!
//! So the rule cannot be "no reads". It is:
//!
//! > No post-validation consumer may read `ValidatedDeployment::config()` to make a
//! > security-sensitive decision.
//!
//! # Why an inventory, and not a cleverer rule
//!
//! "Security-sensitive" is not mechanically decidable, and a gate that pretends otherwise
//! either passes vacuously or blocks honest work. What IS decidable is *which fields* the
//! root reads, so this pins the set. Adding a read fails the test; the fix is to add the
//! field here with the sentence saying why it is ordinary — or, far more often, to find the
//! owner it belongs to.
//!
//! That is the same shape as the validation residue's `INVENTORY`: a list checked against
//! the file it describes rather than trusted, so a number in prose cannot drift from the
//! code.
//!
//! # What "ordinary" means here
//!
//! An ordinary validated parameter is one where *this value changing, while every owner
//! state stays unchanged, cannot change a security-sensitive decision or effect.* A
//! certificate path is ordinary: which file is loaded is a deployment's own business, and
//! the custody state decides how its contents are used. A skew bound is NOT ordinary, which
//! is why it left this list and became `FreshnessWindow`.

use std::collections::BTreeSet;

/// Every `DeploymentRequest` field the composition root still reads directly, and the
/// reason each is an ordinary validated parameter rather than an unowned decision.
///
/// Read the reasons before adding to this list. Six fields that looked ordinary on a first
/// pass were not: the skew bound, the trust locator, the certificate lifetime, the
/// connection age, the key-file posture flag and the topology pair all became owners, and
/// two of them were holding live defects.
const ORDINARY: &[(&str, &str)] = &[
    (
        "audience",
        "the deployment's own audience coordinate; ServerIdentity owns the identity built \
         from it, and the string itself names no posture",
    ),
    (
        "bind",
        "the listen address, resolved to a SocketAddr here because resolution is an \
         environment act",
    ),
    (
        "client_ca",
        "a locator: which roots are loaded. How a loaded root is used is the TLS plane's, \
         and whether the file may be group-readable is KeyFileAccessPolicy's",
    ),
    (
        "inner_http_urls",
        "the backends the pool forwards to; the pool is built here and nothing about \
         forwarding is a classified posture",
    ),
    (
        "limits",
        "the resource ceilings, already normalized by layer A. The one member that WAS a \
         decision — max_connection_age — is owned by ClientCredentialWindow and read from \
         there",
    ),
    ("route", "the request path this deployment answers on"),
    (
        "target_uri",
        "the RFC 9421 @target-uri the signature base is reconstructed against; layer A \
         checked its shape, and the value is a coordinate rather than a posture",
    ),
    ("tls_cert", "a locator, for the same reason as client_ca"),
    (
        "trust_domain",
        "the deployment's own trust-domain coordinate; ServerIdentity owns what is built \
         from it",
    ),
];

/// Every `values.<field>` the production half of `app.rs` reads.
///
/// `values` is the root's binding for `config.config()`, so this is exactly the set of raw
/// request reads. Matched on the binding rather than on `config()` because a read written
/// as `config.config().foo` would still bind through the same name to be used twice — and
/// the one-shot form is caught too, since it also spells `.config()`.
fn raw_reads(source: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let production = mcp_re_test_paths::rust_source::production_half(source);
    for (index, _) in production.match_indices("values.") {
        let rest = production
            .get(index + "values.".len()..)
            .unwrap_or_default();
        let field: String = rest
            .chars()
            .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
            .collect();
        if !field.is_empty() {
            found.insert(field);
        }
    }
    found
}

fn app_source() -> String {
    let path = mcp_re_test_paths::resolve_runfile("MCP_RE_APP_SRC");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"))
}

/// The root reads exactly the inventory, and nothing else.
#[test]
fn the_composition_root_reads_only_ordinary_validated_parameters() {
    let declared: BTreeSet<String> = ORDINARY.iter().map(|(f, _)| f.to_string()).collect();
    let actual = raw_reads(&app_source());

    let undeclared: Vec<&String> = actual.difference(&declared).collect();
    assert!(
        undeclared.is_empty(),
        "app.rs reads {undeclared:?} raw. Before adding to ORDINARY, ask whether this value \
         changing — with every owner state unchanged — could change a security-sensitive \
         decision. If it could, it needs an owner, not an entry."
    );

    let stale: Vec<&String> = declared.difference(&actual).collect();
    assert!(
        stale.is_empty(),
        "ORDINARY names {stale:?}, which app.rs no longer reads. A field that acquired an \
         owner should leave this list, so the list stays a measurement rather than a memory."
    );
}

/// The rule detects what it claims to.
///
/// Without this, a matcher that never matches leaves the assertion above vacuously true and
/// a green run would mean nothing at all.
#[test]
fn the_rule_would_catch_a_new_raw_read() {
    let reaching = "fn run() { let _ = values.max_clock_skew; }\n#[cfg(test)]\nmod tests {}\n";
    assert!(
        raw_reads(reaching).contains("max_clock_skew"),
        "the matcher must see a raw read"
    );
    assert!(
        !raw_reads("fn run() { let _ = state.max_clock_skew; }").contains("max_clock_skew"),
        "an owner projection is not a raw read"
    );
    assert!(
        raw_reads("#[cfg(test)]\nmod tests { let _ = values.audience; }").is_empty(),
        "test code is out of scope, so a fixture cannot make the gate fail or pass"
    );
    // The control the truncating form could not pass: production below a test module is
    // still production. `app.rs` may grow one at any time, and a scan that stopped at the
    // first `#[cfg(test)]` would have reported a clean inventory over unread code.
    assert!(
        raw_reads("#[cfg(test)]\nmod tests {\n    let _ = values.audience;\n}\nfn late() { let _ = values.max_clock_skew; }\n")
            .contains("max_clock_skew"),
        "a raw read below the test module must still be seen"
    );
}

/// The inventory is not a bare list: every entry states why the field is ordinary.
///
/// A reason nobody wrote is a field nobody classified, and this list only means anything
/// while adding to it costs a sentence.
#[test]
fn every_ordinary_field_states_why_it_is_ordinary() {
    for (field, reason) in ORDINARY {
        assert!(
            reason.len() > 30,
            "{field} has no real justification: {reason:?}"
        );
    }
}
