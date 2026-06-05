//! Error type for the long-lived demo server (MCPS-062).
//!
//! Every fallible path returns a [`DemoServerError`] rather than panicking. The
//! server maps these to either a JSON-RPC error object (protocol-level faults)
//! or an `isError: true` tool result (tool-level failures), so bad input is
//! always handled in-band. `unwrap`/`panic!` are reserved for unreachable
//! invariants only.

use thiserror::Error;

/// All ways the long-lived demo server can fail to produce a normal result.
#[derive(Debug, Error)]
pub enum DemoServerError {
    /// The request bytes were not valid JSON-RPC (parse error, -32700).
    #[error("parse error: {0}")]
    ParseError(String),

    /// The request was valid JSON but not a well-formed JSON-RPC request
    /// (missing/!string `method`, etc.) — invalid request, -32600.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// A request other than `initialize` arrived before the handshake. The MCP
    /// lifecycle requires `initialize` first — server not initialized, -32002.
    #[error("server not initialized: '{0}' arrived before 'initialize'")]
    NotInitialized(String),

    /// The `method` is not one this server implements — method not found, -32601.
    #[error("method not found: {0}")]
    MethodNotFound(String),

    /// `tools/call` named a tool this server does not expose — invalid params.
    #[error("unknown tool: {0}")]
    UnknownTool(String),

    /// A tool's parameters were missing or the wrong shape — invalid params.
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
}

impl DemoServerError {
    /// The JSON-RPC error code for protocol-level faults. Tool-level failures
    /// become `isError: true` tool results rather than JSON-RPC errors, but a
    /// code is still defined for completeness and reuse.
    pub fn json_rpc_code(&self) -> i64 {
        match self {
            DemoServerError::ParseError(_) => -32700,
            DemoServerError::InvalidRequest(_) => -32600,
            // -32002 is the MCP-convention "server not initialized" code.
            DemoServerError::NotInitialized(_) => -32002,
            DemoServerError::MethodNotFound(_) => -32601,
            DemoServerError::UnknownTool(_) => -32602,
            DemoServerError::InvalidParams(_) => -32602,
        }
    }
}
