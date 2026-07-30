// SPDX-License-Identifier: Apache-2.0
//
// Live e2e: a real MCP `Client` through `McpReHttpTransport` against the real Rust
// `http_profile_proxy` and a real MCP SDK Streamable-HTTP backend.
//
// This is the claim the adapter exists to make: **application code calls
// `client.callTool(...)` and nothing else** — no signRequest, no verifyResponse, no
// correlation. If that only worked against a stub, it would prove nothing, so the
// counterparty here is the project's own proof harness: it signs DELEGATED responses
// (ADR-MCPRE-052) and emits delegated rejection receipts, exactly as the production
// serving path does. This is the TypeScript mirror of
// `sdk/python/tests/test_transport_e2e.py` — same harness, same five proofs.
//
// Skips cleanly when the harness is unavailable (no MCP SDK server, or the examples are not
// built), so the Bazel-free downloader lane stays green without it.
//
// Prerequisites, from the repo root:
//
//     cargo build -p mcp-re-proxy --example http_profile_proxy
//     pip install "mcp>=2.0,<3" uvicorn
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createPrivateKey, createPublicKey, randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { connect } from "node:net";
import { join, resolve } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/client";

import { McpReError, Signer, SignerPolicy } from "../src/index.js";
import {
  McpReHttpTransport,
  type HttpReply,
  type McpReConfig,
  type Poster,
} from "../src/transport.js";

// The hpp_common demo material — deterministic proof seeds, TEST-ONLY.
const CLIENT_SEED = Buffer.alloc(32, 11);
const ROOT_SEED = Buffer.alloc(32, 22);
const REPO_ROOT = resolve(__dirname, "..", "..", "..");
const PROXY_BIN = join(REPO_ROOT, "target", "debug", "examples", "http_profile_proxy");
const BACKEND = join(REPO_ROOT, "tools", "fastmcp_inner_backend.py");

/** The root public key, derived from the seed rather than pasted in: a copied constant
 * would still "pass" if the harness rotated its anchor. */
function rootPubB64Url(): string {
  // RFC 8410 PKCS#8 prefix for an Ed25519 private key, so node will import a raw seed.
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    ROOT_SEED,
  ]);
  const spki = createPublicKey(createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" }))
    .export({ format: "der", type: "spki" });
  // The last 32 bytes of the SPKI DER are the raw Ed25519 public key.
  return spki.subarray(spki.length - 32).toString("base64url");
}

const ROOT_PUB = rootPubB64Url();

/** No hardcoded ports: config/ports.toml is the single source of truth. */
function port(service: string): number {
  const toml = readFileSync(join(REPO_ROOT, "config", "ports.toml"), "utf8");
  const section = toml.split(`[services.${service}]`)[1];
  const match = section?.match(/^port\s*=\s*(\d+)/m);
  if (!match) throw new Error(`no port for '${service}' in config/ports.toml`);
  return Number(match[1]);
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function probe(p: number): Promise<boolean> {
  return new Promise((res) => {
    const sock = connect({ port: p, host: "127.0.0.1" });
    const done = (ok: boolean) => {
      sock.destroy();
      res(ok);
    };
    sock.setTimeout(200);
    sock.on("connect", () => done(true));
    sock.on("error", () => done(false));
    sock.on("timeout", () => done(false));
  });
}

async function waitPort(p: number, timeoutMs = 15_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await probe(p)) return true;
    await sleep(200);
  }
  return false;
}

/** The interpreter that runs the inner backend. It needs `mcp>=2.0` + uvicorn importable,
 * which a bare system python3 usually does not have — set MCP_RE_PYTHON to a venv's
 * interpreter to run the live lane instead of skipping it. */
const PYTHON = process.env.MCP_RE_PYTHON ?? "python3";

/** The inner backend is an MCP SDK server run by an interpreter, so what has to be
 * present is one that can import it — not a CLI on PATH. */
function haveInnerBackend(): boolean {
  const r = spawnSync(PYTHON, ["-c", "import mcp.server.mcpserver, uvicorn"], { stdio: "ignore" });
  return r.status === 0;
}

let procs: ChildProcess[] = [];
let target = "";
let available = false;

beforeAll(async () => {
  if (!existsSync(PROXY_BIN) || !haveInnerBackend()) return;

  const front = port("mcp_re_http_profile_proxy");
  const inner = port("mcp_re_inner_backend");
  target = `http://127.0.0.1:${front}/mcp`;

  if (!(await probe(inner))) {
    procs.push(
      spawn(PYTHON, [BACKEND], {
        env: {
          ...process.env,
          MCP_RE_INNER_BACKEND_PORT: String(inner),
          MCP_RE_INNER_BACKEND_HOST: "127.0.0.1",
        },
        stdio: "ignore",
      }),
    );
    if (!(await waitPort(inner))) return;
  }

  procs.push(
    spawn(PROXY_BIN, [], {
      env: {
        ...process.env,
        HPP_BIND: `127.0.0.1:${front}`,
        HPP_INNER_URL: `http://127.0.0.1:${inner}/mcp/`,
        HPP_TARGET: target,
      },
      stdio: "ignore",
    }),
  );
  available = await waitPort(front);
}, 40_000);

afterAll(() => {
  for (const p of procs) p.kill();
  procs = [];
});

function config(over: Partial<McpReConfig> = {}): McpReConfig {
  return {
    signer: Signer.software(CLIENT_SEED, "did:example:host-a", "client-key-1"),
    policy: new SignerPolicy("did:example:host-a", "development"),
    audienceId: "verifier-1",
    targetUri: target,
    route: "a",
    dpopToken: "access-token-xyz",
    // The trusted ROOT anchor only: the delegated key is learned from the credential the
    // response carries, never enrolled here.
    issuerKeyId: "server-key-1",
    issuerPubkeyB64Url: ROOT_PUB,
    issuerRole: "server",
    issuerTrustDomain: "example.com",
    issuerSubject: "did:example:server-1",
    verifierAudiences: ["verifier-1"],
    expectedAudienceHash: "aud-scope-1",
    acceptedEpochs: ["epoch-1"],
    maxClockSkew: 60,
    ...over,
  };
}

const poster: Poster = async (method, targetUri, headers, body) => {
  const res = await fetch(targetUri, {
    method,
    headers: headers.map((h) => [h.key, h.value] as [string, string]),
    body: new Uint8Array(body),
  });
  return {
    status: res.status,
    headers: [...res.headers.entries()].map(([key, value]) => ({ key, value })),
    body: Buffer.from(await res.arrayBuffer()),
  };
};

const newClient = () => new Client({ name: "mcp-re-adapter-e2e", version: "0.1.0" });

describe.runIf(existsSync(PROXY_BIN) && haveInnerBackend())("McpReHttpTransport (live)", () => {
  it("lets a real MCP Client call a tool with no sign/verify in app code", async () => {
    expect(available).toBe(true);
    const acknowledged: [string, string][] = [];
    const client = newClient();
    await client.connect(
      new McpReHttpTransport(
        config({ onNotificationAcknowledged: (m, k) => acknowledged.push([m, k]) }),
        poster,
      ),
    );

    expect(client.getServerVersion()?.name).toBe("mcp-re-inner-backend");

    const result = await client.callTool({ name: "add", arguments: { a: 2, b: 40 } });

    // The real FastMCP tool ran behind the real proxy.
    expect((result.content as { text: string }[])[0].text).toBe("42");
    expect(result.structuredContent).toEqual({ result: 42 });
    // The app never saw MCP-RE's own evidence block.
    expect(result.structuredContent).not.toHaveProperty("_meta");

    // C055: the lifecycle notification went over the wire as a signed POST and the
    // proxy's signed bodyless 202 verified against the real credential chain — the
    // acknowledgement half of the contract, which nothing on the client side used to
    // check. The signer is a DELEGATED key; the root stays off the request path.
    expect(acknowledged.map(([m]) => m)).toContain("notifications/initialized");
    expect(acknowledged.map(([, k]) => k)).not.toContain("server-key-1");
    await client.close();
  }, 30_000);

  it("rejects rather than hangs when the proxy signs a rejection", async () => {
    // A replay is refused by the proxy with a DELEGATED rejection receipt. The adapter
    // must verify that receipt, read its frozen wire code, and deliver it as a JSON-RPC
    // error correlated to the request id — so the awaiting call REJECTS. A dropped
    // failure would hang the client forever, which is worse than an error.
    const client = newClient();
    // A session now emits three signed messages — `initialize`, the lifecycle
    // notification, and the tool call — so a single frozen nonce would make the
    // NOTIFICATION the replay and fail the connection before the call under test ran.
    // Draw 0 (`initialize`) and draw 2 (the tool call) share a nonce; draw 1 (the
    // notification) gets its own.
    // The prefix is unique per run so the test does not depend on a freshly-started
    // proxy: the replay it proves is the one it creates, not a leftover from an earlier
    // run whose nonces this proxy still remembers.
    const run = randomBytes(8).toString("base64url");
    let draw = 0;
    const replayingNonce = (): string => {
      const n = draw++;
      return `nonce-ts-adapter-replay-${run}-${n === 2 ? 0 : n}`;
    };
    await client.connect(new McpReHttpTransport(config({ nonceFactory: replayingNonce }), poster));

    // The replay: `initialize` already consumed this nonce.
    await expect(client.callTool({ name: "add", arguments: { a: 1, b: 1 } })).rejects.toThrow(
      /mcp-re\.replay_detected/,
    );
    await client.close();
  }, 30_000);

  it("fails closed on a tampered response, which never reaches the app", async () => {
    const tampering: Poster = async (m, u, h, b) => {
      const reply = await poster(m, u, h, b);
      // RFC 9530 content-digest covers the raw body, so ANY edit must break
      // verification. A trailing space keeps the JSON valid on purpose: the response
      // must be refused on its evidence, not because it failed to parse.
      return { ...reply, body: Buffer.concat([reply.body, Buffer.from(" ")]) } as HttpReply;
    };
    await expect(newClient().connect(new McpReHttpTransport(config(), tampering))).rejects.toThrow(
      /mcp-re\./,
    );
  }, 30_000);

  it("fails closed on an unsigned response", async () => {
    // A response with the evidence stripped is not evidence — it must be refused.
    const unsigned: Poster = async () => ({
      status: 200,
      headers: [{ key: "content-type", value: "application/json" }],
      body: Buffer.from('{"jsonrpc":"2.0","id":0,"result":{"ok":true}}'),
    });
    await expect(newClient().connect(new McpReHttpTransport(config(), unsigned))).rejects.toThrow(
      /mcp-re\./,
    );
  }, 30_000);

  it("refuses a software key under the hardening profile before connecting", async () => {
    // Custody is checked in start(), so a violation fails the connection, not a request.
    const transport = new McpReHttpTransport(
      config({ policy: SignerPolicy.hardened("did:example:host-a") }),
      poster,
    );
    await expect(transport.start()).rejects.toThrow(McpReError);
    await expect(transport.start()).rejects.toThrow(/mcp-re\.actor_binding_failed/);
  });
});
