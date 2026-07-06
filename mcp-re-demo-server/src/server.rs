//! The long-lived demo server (MCPS-062): an MCP-RE-UNAWARE stdio MCP server
//! that models the full MCP lifecycle.
//!
//! [`DemoServer`] speaks plain MCP JSON-RPC: `initialize`, `tools/list`,
//! `tools/call`, and a modelled `shutdown`. It is the persistent counterpart of
//! `mcp-re-demo-fileserver`: a single process serves an `initialize` handshake
//! followed by ANY number of tool calls, staying alive until stdin EOF (or
//! `shutdown`). It knows nothing about MCP-RE signing, envelopes, or verified
//! context — that is the sidecar's job (the proxy fronts this server unchanged).
//!
//! ## Scoped demo tools (for the Phase-5 policy demo, #3959)
//! The server is MCP-RE-UNAWARE: it does NOT enforce scopes. The "scope" is
//! pure metadata — surfaced in each tool's `annotations` (the
//! `net.mcp-re.intendedScope` key) and its description — so the policy layer can
//! bind a grant to a tool name. The three tools, by intended scope:
//!   * `echo`        — **public**    (no grant needed): returns its argument.
//!   * `list_items`  — **protected** (needs a Phase-5 grant): lists the in-memory items.
//!   * `reset_items` — **admin**     (higher scope): restores the seed item set.
//!
//! ## Determinism
//! All mutable state is an in-memory item set seeded at construction from an
//! injected list; nothing reads the clock, filesystem, or network. `reset_items`
//! restores exactly the injected seed, so any call sequence is reproducible.

use std::cell::RefCell;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use serde_json::json;
use serde_json::Value;

use crate::error::DemoServerError;

/// The MCP protocol version this demo server advertises.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// The annotation key under which each tool publishes its intended Phase-5
/// scope. The server does NOT enforce it; #3959's policy layer reads it.
const INTENDED_SCOPE_KEY: &str = "net.mcp-re.intendedScope";

/// Public tool — no authorization intended. Echoes its `message` argument.
pub const TOOL_ECHO: &str = "echo";
/// Protected tool — intended to require a Phase-5 grant. Lists in-memory items.
pub const TOOL_LIST_ITEMS: &str = "list_items";
/// Admin tool — intended to require a higher scope. Restores the seed items.
pub const TOOL_RESET_ITEMS: &str = "reset_items";

/// Intended-scope tag values, surfaced as tool annotations for the policy demo.
const SCOPE_PUBLIC: &str = "public";
const SCOPE_PROTECTED: &str = "protected";
const SCOPE_ADMIN: &str = "admin";

/// A long-lived, MCP-RE-UNAWARE MCP server over a small in-memory item set.
///
/// Lifecycle is modelled explicitly: `initialized` flips on the first
/// `initialize` and gates every other request. Mutable state lives behind a
/// [`RefCell`] so the persistent serve loop can keep a shared `&DemoServer`
/// handle (matching the sibling stdio servers) while `reset_items` still
/// mutates. Single-threaded by construction (one stdin reader); never shared
/// across threads.
pub struct DemoServer {
    /// The exact item set injected at construction; `reset_items` restores it.
    seed_items: Vec<String>,
    /// The live item set served by `list_items`.
    items: RefCell<Vec<String>>,
    /// Whether `initialize` has been seen. Gates all non-`initialize` requests.
    initialized: RefCell<bool>,
    /// Optional append-only sink recording every `tools/call` the server ACTUALLY
    /// executes (MCPS-068, #3965). `None` by default — a normal run writes no
    /// file. When `Some`, each served call appends one JSON line
    /// `{"id":<json-rpc id>,"tool":"<name>"}` so a black-box test can assert,
    /// from the INNER's own record (not the proxy's claim), exactly which request
    /// ids reached and ran here. A request denied pre-dispatch never reaches this
    /// server, so its id can never appear.
    received_log: RefCell<Option<File>>,
}

impl DemoServer {
    /// Construct a server seeded with `seed_items` (injected for determinism).
    /// The server starts UNINITIALIZED; the first `initialize` request flips it.
    /// The received-request log is OFF; attach one with [`Self::with_received_log`].
    pub fn new(seed_items: Vec<String>) -> Self {
        DemoServer {
            items: RefCell::new(seed_items.clone()),
            seed_items,
            initialized: RefCell::new(false),
            received_log: RefCell::new(None),
        }
    }

    /// Enable the append-only received-request log at `path` (MCPS-068). Each
    /// `tools/call` the server actually executes appends one JSON line. The file
    /// is opened for create-append, truncated on attach so the record reflects
    /// only THIS session. Returns the server for chaining; an open failure is an
    /// I/O error rather than a panic (the caller decides whether to abort).
    pub fn with_received_log(self, path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        *self.received_log.borrow_mut() = Some(file);
        Ok(self)
    }

    /// Append one received-`tools/call` record line, if the log is enabled. The
    /// id is echoed verbatim from the request so the test can correlate exactly.
    /// Write failures are swallowed (best-effort instrumentation must never break
    /// the serve loop or panic); flush keeps the record readable mid-session.
    fn record_received_call(&self, id: &Value, tool: &str) {
        if let Some(file) = self.received_log.borrow_mut().as_mut() {
            let line = json!({ "id": id.clone(), "tool": tool });
            if let Ok(mut bytes) = serde_json::to_vec(&line) {
                bytes.push(b'\n');
                let _ = file.write_all(&bytes);
                let _ = file.flush();
            }
        }
    }

    /// Whether a modelled `shutdown` has been requested. The serve loop checks
    /// this after each request to end the session cleanly (in addition to EOF).
    pub fn handle_should_stop(&self, request_bytes: &[u8]) -> bool {
        serde_json::from_slice::<Value>(request_bytes)
            .ok()
            .and_then(|v| v.get("method").and_then(Value::as_str).map(str::to_owned))
            .map(|m| m == "shutdown")
            .unwrap_or(false)
    }

    /// Handle one raw JSON-RPC request and return the raw response bytes. Never
    /// panics: parse/protocol faults become JSON-RPC error objects; tool
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
    /// `result` carrying `isError: true` (per MCP); only protocol-level faults
    /// propagate as [`DemoServerError`].
    fn dispatch(
        &self,
        parsed: Option<&Value>,
        request_bytes: &[u8],
    ) -> Result<Value, DemoServerError> {
        let request = parsed.ok_or_else(|| {
            DemoServerError::ParseError(format!("not valid JSON ({} bytes)", request_bytes.len()))
        })?;

        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| DemoServerError::InvalidRequest("missing string 'method'".into()))?;

        // `initialize` is always allowed; it flips the lifecycle flag. Every
        // other method requires a prior `initialize` (MCP lifecycle). `shutdown`
        // is allowed regardless so a client can always tear down cleanly.
        if method == "initialize" {
            *self.initialized.borrow_mut() = true;
            return Ok(self.initialize_result());
        }
        if method != "shutdown" && !*self.initialized.borrow() {
            return Err(DemoServerError::NotInitialized(method.to_string()));
        }

        match method {
            "tools/list" => Ok(self.tools_list_result()),
            "tools/call" => self.tools_call_result(request),
            "shutdown" => Ok(json!({ "ok": true })),
            other => Err(DemoServerError::MethodNotFound(other.to_string())),
        }
    }

    /// The `initialize` result: protocol version, tool capability, server info.
    fn initialize_result(&self) -> Value {
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": {
                "name": "mcp-re-demo-server",
                "version": env!("CARGO_PKG_VERSION"),
            }
        })
    }

    /// The `tools/list` result: the three scoped demo tools, each tagging its
    /// intended Phase-5 scope under `annotations.net.mcp-re.intendedScope` (the
    /// server itself does not enforce it).
    fn tools_list_result(&self) -> Value {
        json!({
            "tools": [
                tool_descriptor(
                    TOOL_ECHO,
                    "Echo back the supplied 'message' string. PUBLIC: intended to need no Phase-5 grant.",
                    SCOPE_PUBLIC,
                    json!({
                        "type": "object",
                        "properties": {
                            "message": { "type": "string", "description": "The text to echo back." }
                        },
                        "required": ["message"],
                        "additionalProperties": false,
                    }),
                ),
                tool_descriptor(
                    TOOL_LIST_ITEMS,
                    "List the in-memory demo items. PROTECTED: intended to require a Phase-5 grant.",
                    SCOPE_PROTECTED,
                    json!({
                        "type": "object",
                        "properties": {},
                        "additionalProperties": false,
                    }),
                ),
                tool_descriptor(
                    TOOL_RESET_ITEMS,
                    "Restore the in-memory demo items to their seed set. ADMIN: intended to require a higher scope.",
                    SCOPE_ADMIN,
                    json!({
                        "type": "object",
                        "properties": {},
                        "additionalProperties": false,
                    }),
                ),
            ]
        })
    }

    /// The `tools/call` result. Dispatches on the tool name; an unknown tool is a
    /// JSON-RPC error (`Err`), but a per-tool argument fault is an in-band tool
    /// error result (`isError: true`).
    fn tools_call_result(&self, request: &Value) -> Result<Value, DemoServerError> {
        let params = request.get("params").unwrap_or(&Value::Null);
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| DemoServerError::InvalidParams("missing tool 'name'".into()))?;
        let arguments = params.get("arguments").unwrap_or(&Value::Null);

        // Record receipt ONLY for tools we actually execute, AFTER the name is
        // recognized. An unknown tool falls through to the `Err` arm below and is
        // NOT recorded — it was never dispatched. This is the anti-gaming signal
        // (MCPS-068): the inner's own record reflects exactly what ran here.
        match name {
            TOOL_ECHO | TOOL_LIST_ITEMS | TOOL_RESET_ITEMS => {
                let id = request.get("id").cloned().unwrap_or(Value::Null);
                self.record_received_call(&id, name);
            }
            _ => {}
        }

        match name {
            TOOL_ECHO => Ok(self.call_echo(arguments)),
            TOOL_LIST_ITEMS => Ok(self.call_list_items()),
            TOOL_RESET_ITEMS => Ok(self.call_reset_items()),
            other => Err(DemoServerError::UnknownTool(other.to_string())),
        }
    }

    /// `echo` (public): return the `message` argument verbatim. A missing/non-
    /// string argument is an in-band tool error (`isError: true`), not a panic.
    fn call_echo(&self, arguments: &Value) -> Value {
        match arguments.get("message").and_then(Value::as_str) {
            Some(message) => tool_text_success(
                message.to_string(),
                json!({ "message": message }),
            ),
            None => tool_error("echo requires a string 'message' argument"),
        }
    }

    /// `list_items` (protected): the current in-memory item set, in order.
    fn call_list_items(&self) -> Value {
        let items = self.items.borrow();
        let summary = format!(
            "{} item{}",
            items.len(),
            if items.len() == 1 { "" } else { "s" }
        );
        tool_text_success(summary, json!({ "items": items.clone() }))
    }

    /// `reset_items` (admin): restore the live set to the injected seed and
    /// report how many items the set now holds.
    fn call_reset_items(&self) -> Value {
        let mut items = self.items.borrow_mut();
        *items = self.seed_items.clone();
        let summary = format!("reset to {} seed item(s)", items.len());
        tool_text_success(summary, json!({ "items": items.clone() }))
    }
}

/// Build one `tools/list` tool descriptor, attaching the intended-scope
/// annotation the Phase-5 policy layer binds to.
fn tool_descriptor(name: &str, description: &str, intended_scope: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "annotations": { INTENDED_SCOPE_KEY: intended_scope },
    })
}

/// Wrap a JSON-RPC `result` value in the full response envelope.
fn json_rpc_result(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id.clone(), "result": result })
}

/// Wrap a [`DemoServerError`] in a JSON-RPC error object.
fn json_rpc_error(id: &Value, err: &DemoServerError) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.clone(),
        "error": { "code": err.json_rpc_code(), "message": err.to_string() }
    })
}

/// A successful tool result (MCP `tools/call` result shape) with a text summary
/// and machine-readable `structuredContent`.
fn tool_text_success(summary: String, structured: Value) -> Value {
    json!({
        "content": [ { "type": "text", "text": summary } ],
        "structuredContent": structured,
        "isError": false,
    })
}

/// An in-band tool error result (MCP `isError: true`); carries no payload.
fn tool_error(message: &str) -> Value {
    json!({
        "content": [ { "type": "text", "text": message } ],
        "isError": true,
    })
}
