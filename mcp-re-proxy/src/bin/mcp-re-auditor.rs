// SPDX-License-Identifier: Apache-2.0
//! `mcp-re-auditor` — the runnable auditor.
//!
//! Deliberately thin. Everything it does is `mcp_re_proxy::transparency::auditor`'s; this
//! file exists to turn an argument list into a process exit status, and a composition root
//! that also owned a process boundary would be two authorities in one place.

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(args) {
        Ok(summary) => {
            println!("{summary}");
            std::process::ExitCode::SUCCESS
        }
        Err(refusal) => {
            eprintln!("mcp-re-auditor: {refusal}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Parse, audit, and describe what was written.
///
/// The summary names BOTH verdicts. An operator who ran an audit and saw only "written"
/// would have to decode COSE to learn that the record it attests is truncated, which is
/// the discovery-by-decoding the attestation authority exists to prevent.
fn run(args: Vec<String>) -> Result<String, String> {
    use mcp_re_proxy::transparency::auditor::AuditInvocation;

    if AuditInvocation::is_help_request(&args) {
        return Ok(AuditInvocation::usage().to_owned());
    }
    let invocation = AuditInvocation::parse(args)?;
    let out = invocation.output_path().display().to_string();
    // Named before the run, so a refusal's context is the invocation's rather than the
    // artifact's — an audit that failed to register wrote no line naming where it tried.
    let registered_with = invocation.registration_endpoint().map_or_else(
        || "not registered (no --register-to)".to_owned(),
        str::to_owned,
    );
    let artifact = mcp_re_proxy::transparency::auditor::attest(&invocation)
        .map_err(|e: mcp_re_proxy::transparency::auditor::AuditError| e.to_string())?;

    Ok(format!(
        "wrote {out}\n  chain          {:?}\n  correspondence {:?}\n           service        {}\n  registration   {registered_with}",
        artifact.chain(),
        artifact.correspondence(),
        artifact.transparency_service().service_identifier,
    ))
}
