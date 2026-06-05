//! The demo fileserver (MCPS-045): a minimal, MCP-S-UNAWARE stdio MCP server.
//!
//! [`FileServer`] speaks plain MCP JSON-RPC: `initialize`, `tools/list`, and
//! `tools/call`. It exposes exactly one tool, `list_files`, which lists the
//! entries of a directory **confined to a configured demo-root**. It knows
//! nothing about MCP-S signing, envelopes, or verified context — that is the
//! sidecar's job (the proxy wraps this server unchanged).
//!
//! Confinement (independent of, and in addition to, any MCP-S authorization):
//! the requested `path` is joined onto the demo root and the result must stay
//! inside the root. Lexical `..` segments and absolute paths are rejected before
//! touching the filesystem; the joined path is then canonicalized so a symlink
//! that would escape the root is also refused. Nothing here ever panics on bad
//! input — every failure is a [`FileServerError`].

use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use serde_json::json;
use serde_json::Value;

use crate::error::FileServerError;

/// The MCP protocol version this demo server advertises.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// The single tool name this server exposes.
const TOOL_NAME: &str = "list_files";

/// A plain MCP server that lists files under a fixed demo root.
pub struct FileServer {
    demo_root: PathBuf,
}

impl FileServer {
    /// Construct a server confined to `demo_root`. The root itself is not
    /// required to exist at construction time; per-call resolution reports a
    /// tool error if it cannot be read.
    pub fn new(demo_root: impl Into<PathBuf>) -> Self {
        FileServer {
            demo_root: demo_root.into(),
        }
    }

    /// Handle one raw JSON-RPC request and return the raw response bytes. Never
    /// panics: parse/protocol faults become JSON-RPC error objects; `list_files`
    /// failures become `isError: true` tool results.
    pub fn handle(&self, request_bytes: &[u8]) -> Vec<u8> {
        // Best-effort id recovery so error responses echo the request id.
        let parsed: Option<Value> = serde_json::from_slice(request_bytes).ok();
        let id = parsed
            .as_ref()
            .and_then(|v| v.get("id").cloned())
            .unwrap_or(Value::Null);

        let response = match self.dispatch(parsed.as_ref(), request_bytes) {
            Ok(result) => json_rpc_result(&id, result),
            Err(err) => json_rpc_error(&id, &err),
        };

        // Serialization of a Value we built ourselves cannot fail; fall back to a
        // static error object rather than unwrap to keep the no-panic guarantee.
        serde_json::to_vec(&response).unwrap_or_else(|_| {
            b"{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"serialization failed\"}}"
                .to_vec()
        })
    }

    /// Route a parsed request to its handler, returning the JSON-RPC `result`
    /// value on success. `tools/call` tool failures are folded into a successful
    /// `result` carrying `isError: true` (per MCP), so they do not appear here as
    /// `Err`; only protocol-level faults propagate as [`FileServerError`].
    fn dispatch(
        &self,
        parsed: Option<&Value>,
        request_bytes: &[u8],
    ) -> Result<Value, FileServerError> {
        let request = parsed.ok_or_else(|| {
            FileServerError::ParseError(format!(
                "not valid JSON ({} bytes)",
                request_bytes.len()
            ))
        })?;

        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| FileServerError::InvalidRequest("missing string 'method'".into()))?;

        match method {
            "initialize" => Ok(self.initialize_result()),
            "tools/list" => Ok(self.tools_list_result()),
            "tools/call" => self.tools_call_result(request),
            other => Err(FileServerError::MethodNotFound(other.to_string())),
        }
    }

    /// The `initialize` result: protocol version, tool capability, server info.
    fn initialize_result(&self) -> Value {
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": {
                "name": "mcps-demo-fileserver",
                "version": env!("CARGO_PKG_VERSION"),
            }
        })
    }

    /// The `tools/list` result: exactly one `list_files` tool with a `path` schema.
    fn tools_list_result(&self) -> Value {
        json!({
            "tools": [
                {
                    "name": TOOL_NAME,
                    "description": "List the entries of a directory inside the demo root.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Directory path, resolved against (and confined to) the demo root.",
                            }
                        },
                        "required": ["path"],
                        "additionalProperties": false,
                    }
                }
            ]
        })
    }

    /// The `tools/call` result. Dispatches on the tool name; an unknown tool is a
    /// JSON-RPC error (`Err`), but a `list_files` failure (escape, missing dir) is
    /// an in-band tool error result (`isError: true`).
    fn tools_call_result(&self, request: &Value) -> Result<Value, FileServerError> {
        let params = request.get("params").unwrap_or(&Value::Null);
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| FileServerError::InvalidParams("missing tool 'name'".into()))?;

        if name != TOOL_NAME {
            return Err(FileServerError::UnknownTool(name.to_string()));
        }

        let path_arg = params
            .get("arguments")
            .and_then(|a| a.get("path"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                FileServerError::InvalidParams("list_files requires a string 'path' argument".into())
            })?;

        match self.list_files(path_arg) {
            Ok(entries) => Ok(tool_success(path_arg, entries)),
            Err(err) => Ok(tool_error(&err)),
        }
    }

    /// Resolve `requested` against the demo root, refuse any escape, and return
    /// the directory's entries sorted by name. Never reads outside the root.
    fn list_files(&self, requested: &str) -> Result<Vec<Value>, FileServerError> {
        let resolved = self.resolve_within_root(requested)?;

        let read_dir = std::fs::read_dir(&resolved)
            .map_err(|e| FileServerError::ReadDir(requested.to_string(), e.to_string()))?;

        let mut entries: Vec<Value> = Vec::new();
        for entry in read_dir {
            let entry =
                entry.map_err(|e| FileServerError::ReadDir(requested.to_string(), e.to_string()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            // file_type() avoids following symlinks for classification; size is
            // best-effort (0 when metadata is unavailable, e.g. a broken symlink).
            let (kind, size) = match entry.metadata() {
                Ok(meta) if meta.is_dir() => ("directory", 0u64),
                Ok(meta) => ("file", meta.len()),
                Err(_) => ("unknown", 0u64),
            };
            entries.push(json!({ "name": name, "type": kind, "size": size }));
        }

        // Deterministic ordering so the committed fixture yields stable results.
        entries.sort_by(|a, b| {
            a["name"]
                .as_str()
                .unwrap_or_default()
                .cmp(b["name"].as_str().unwrap_or_default())
        });
        Ok(entries)
    }

    /// Join `requested` onto the demo root and confine the result to the root.
    ///
    /// Two layers of defense:
    ///   1. Lexical: reject absolute inputs and any `..` segment outright (no
    ///      filesystem access), so an obvious escape never even hits the disk.
    ///   2. Canonical: canonicalize the joined path and the root and require the
    ///      former to start with the latter, catching symlink escapes.
    fn resolve_within_root(&self, requested: &str) -> Result<PathBuf, FileServerError> {
        let requested_path = Path::new(requested);

        // Layer 1 — lexical rejection.
        for component in requested_path.components() {
            match component {
                Component::ParentDir => {
                    return Err(FileServerError::PathEscapesRoot(requested.to_string()))
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(FileServerError::PathEscapesRoot(requested.to_string()))
                }
                Component::CurDir | Component::Normal(_) => {}
            }
        }

        let joined = self.demo_root.join(requested_path);

        // Layer 2 — canonical containment. Canonicalize the root once; if the
        // joined target exists, canonicalize it too and require containment. If it
        // does not exist, the lexical check above already guaranteed no `..`/abs
        // escape, so read_dir will simply report a not-found tool error.
        let canonical_root = self
            .demo_root
            .canonicalize()
            .map_err(|e| FileServerError::ReadDir(".".to_string(), e.to_string()))?;
        if let Ok(canonical_target) = joined.canonicalize() {
            if !canonical_target.starts_with(&canonical_root) {
                return Err(FileServerError::PathEscapesRoot(requested.to_string()));
            }
            return Ok(canonical_target);
        }

        Ok(joined)
    }
}

/// Wrap a JSON-RPC `result` value in the full response envelope.
fn json_rpc_result(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id.clone(), "result": result })
}

/// Wrap a [`FileServerError`] in a JSON-RPC error object.
fn json_rpc_error(id: &Value, err: &FileServerError) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.clone(),
        "error": { "code": err.json_rpc_code(), "message": err.to_string() }
    })
}

/// A successful `list_files` tool result (MCP `tools/call` result shape).
fn tool_success(path: &str, entries: Vec<Value>) -> Value {
    let summary = format!("{} entr{} under '{}'", entries.len(),
        if entries.len() == 1 { "y" } else { "ies" }, path);
    json!({
        "content": [ { "type": "text", "text": summary } ],
        "structuredContent": { "path": path, "entries": entries },
        "isError": false,
    })
}

/// An in-band tool error result (MCP `isError: true`); carries no listing.
fn tool_error(err: &FileServerError) -> Value {
    json!({
        "content": [ { "type": "text", "text": err.to_string() } ],
        "isError": true,
    })
}
