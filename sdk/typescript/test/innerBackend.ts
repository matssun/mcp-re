/**
 * A minimal, MCP-RE-unaware HTTP MCP backend for the live mTLS e2e test.
 *
 * MCP-RE is HTTP-profile only: the real `mcp-re-proxy` verifies each signed request and
 * forwards the stripped, verified-context-injected plain JSON-RPC over HTTP to a
 * stateless inner backend (`--inner-http-url`), then signs the backend's response. This
 * is the HTTP analogue of the (removed) stdio `mcp-re-demo-fileserver` fixture: a tiny
 * `node:http` server that speaks plain MCP JSON-RPC over one POST per request and
 * implements exactly the surface the e2e test drives —
 *
 *   - `tools/call` `read_file`    → the file's text as an MCP tool result;
 *   - `tools/call` `delete_files` → an ADR-MCPS-047 elicit/answer continuation:
 *       - no `inputResponses`                 → an `InputRequiredResult` (non-terminal),
 *         pending paths encoded into the opaque `requestState`;
 *       - `inputResponses` + `requestState`   → the terminal result (dry-run).
 *
 * (`initialize` / `tools/list` are also served so the same backend suffices for a full
 * MCP `Client` driver.) The backend is MCP-RE-unaware — it never inspects the injected
 * `params._meta`; the proxy owns all signing/verification. `requestState` is opaque to
 * the proxy and client (echoed verbatim), meaningful only to this backend.
 */
import { createServer, type Server } from "node:http";

export const PROTOCOL_VERSION = "2025-06-18";
export const INNER_SERVER_NAME = "mcp-re-http-inner-demo";
export const FILE_TEXT = "hello from the inner http backend\n";

function encodeRequestState(paths: unknown[]): string {
  return Buffer.from(JSON.stringify(paths), "utf-8").toString("hex");
}

function decodeRequestState(state: string): unknown[] | null {
  try {
    const value = JSON.parse(Buffer.from(state, "hex").toString("utf-8"));
    return Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}

function readFileResult(): Record<string, unknown> {
  return {
    content: [{ type: "text", text: FILE_TEXT }],
    structuredContent: { content: FILE_TEXT, size: FILE_TEXT.length },
    isError: false,
  };
}

function deleteFilesElicit(paths: unknown[]): Record<string, unknown> {
  return {
    resultType: "inputRequired",
    inputRequests: {
      confirm: { type: "elicitation", message: `Delete ${paths.length} file(s)?`, schema: { type: "boolean" } },
    },
    requestState: encodeRequestState(paths),
  };
}

function deleteFilesTerminal(paths: unknown[], responses: unknown, requestState: string): Record<string, unknown> {
  const statePaths = decodeRequestState(requestState);
  if (JSON.stringify(statePaths) !== JSON.stringify(paths)) {
    return { content: [{ type: "text", text: "delete_files requestState invalid" }], isError: true };
  }
  const confirmed =
    typeof responses === "object" && responses !== null && (responses as Record<string, unknown>).confirm === true;
  return {
    content: [{ type: "text", text: confirmed ? "deleted (dry-run)" : "deletion declined" }],
    structuredContent: { deleted: confirmed ? paths : [], confirmed },
    isError: false,
  };
}

function dispatch(request: Record<string, unknown>): unknown {
  const method = request.method;
  const params = (request.params as Record<string, unknown>) ?? {};
  if (method === "initialize") {
    return {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: { tools: {} },
      serverInfo: { name: INNER_SERVER_NAME, version: "0" },
    };
  }
  if (method === "tools/list") {
    // No `outputSchema` on purpose (see the Python `_inner_backend`): the MCP client
    // validates structuredContent against a tool's outputSchema; omitting it keeps this
    // MCP-RE-unaware fixture from also owning schemas.
    return {
      tools: [
        { name: "read_file", description: "Read a UTF-8 text file.", inputSchema: { type: "object" } },
        { name: "delete_files", description: "Delete files (elicits first; dry-run).", inputSchema: { type: "object" } },
      ],
    };
  }
  if (method === "tools/call") {
    const name = params.name;
    const args = (params.arguments as Record<string, unknown>) ?? {};
    if (name === "read_file") return readFileResult();
    if (name === "delete_files") {
      const paths = (args.paths as unknown[]) ?? [];
      if (!("inputResponses" in params)) return deleteFilesElicit(paths);
      return deleteFilesTerminal(paths, params.inputResponses, (params.requestState as string) ?? "");
    }
  }
  return { content: [{ type: "text", text: `unknown method ${String(method)}` }], isError: true };
}

/** Start the inner backend on an ephemeral 127.0.0.1 port. Resolves `{ url, server }`. */
export function startInnerBackend(): Promise<{ url: string; server: Server }> {
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      let request: Record<string, unknown> = {};
      try {
        request = JSON.parse(Buffer.concat(chunks).toString("utf-8"));
      } catch {
        request = {};
      }
      const body = JSON.stringify({ jsonrpc: "2.0", id: request.id ?? null, result: dispatch(request) });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) });
      res.end(body);
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      resolve({ url: `http://127.0.0.1:${port}/mcp`, server });
    });
  });
}
