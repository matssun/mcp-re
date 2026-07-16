// SPDX-License-Identifier: Apache-2.0
//
// Live e2e: a real MCP `Client` through `McpReHttpTransport` against the real Rust
// `http_profile_proxy` and a real FastMCP Streamable-HTTP backend.
//
// This is the claim the adapter exists to make: **application code calls
// `client.callTool(...)` and nothing else** — no signRequest, no verifyResponse, no
// correlation. If that only worked against a stub, it would prove nothing, so the
// counterparty here is the project's own proof harness: it signs DELEGATED responses
// (ADR-MCPRE-052) and emits delegated rejection receipts, exactly as the production
// serving path does. This is the TypeScript mirror of
// `sdk/python/tests/test_transport_e2e.py` — same harness, same five proofs.
//
// Skips cleanly when the harness is unavailable (no `fastmcp`, or the examples are not
// built), so the Bazel-free downloader lane stays green without it.
//
// Prerequisites, from the repo root:
//
//     cargo build -p mcp-re-proxy --example http_profile_proxy
//     brew install fastmcp
import { spawn, type ChildProcess } from "node:child_process";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { connect } from "node:net";
import { join, resolve } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";

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

function haveFastmcp(): boolean {
  const paths = (process.env.PATH ?? "").split(":");
  return paths.some((d) => d && existsSync(join(d, "fastmcp")));
}

let procs: ChildProcess[] = [];
let target = "";
let available = false;

beforeAll(async () => {
  if (!existsSync(PROXY_BIN) || !haveFastmcp()) return;

  const front = port("mcp_re_http_profile_proxy");
  const inner = port("mcp_re_inner_backend");
  target = `http://127.0.0.1:${front}/mcp`;

  if (!(await probe(inner))) {
    procs.push(
      spawn(
        "fastmcp",
        ["run", `${BACKEND}:mcp`, "--transport", "http", "--host", "127.0.0.1",
         "--port", String(inner), "--stateless", "--path", "/mcp/", "--no-banner"],
        {
          env: { ...process.env, FASTMCP_JSON_RESPONSE: "true", FASTMCP_STATELESS_HTTP: "true" },
          stdio: "ignore",
        },
      ),
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
    // A standard Client cannot complete its lifecycle without
    // `notifications/initialized`, and MCP-RE has no ratified one-way notification
    // profile yet (#418) — so every live session today needs this unsafe opt-in. That it
    // is required here is the point: the hole is visible, not papered over.
    unsafeDropNotifications: true,
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

describe.runIf(existsSync(PROXY_BIN) && haveFastmcp())("McpReHttpTransport (live)", () => {
  it("lets a real MCP Client call a tool with no sign/verify in app code", async () => {
    expect(available).toBe(true);
    const dropped: string[] = [];
    const client = newClient();
    await client.connect(
      new McpReHttpTransport(config({ onDroppedNotification: (m) => dropped.push(m) }), poster),
    );

    expect(client.getServerVersion()?.name).toBe("mcp-re-inner-backend");

    const result = await client.callTool({ name: "add", arguments: { a: 2, b: 40 } });

    // The real FastMCP tool ran behind the real proxy.
    expect((result.content as { text: string }[])[0].text).toBe("42");
    expect(result.structuredContent).toEqual({ result: 42 });
    // The app never saw MCP-RE's own evidence block.
    expect(result.structuredContent).not.toHaveProperty("_meta");

    // A client->server notification has no reply, so it carries no evidence and cannot be
    // verified. Dropping it is the honest behaviour — but it must be observable.
    expect(dropped).toContain("notifications/initialized");
    await client.close();
  }, 30_000);

  it("rejects rather than hangs when the proxy signs a rejection", async () => {
    // A replay is refused by the proxy with a DELEGATED rejection receipt. The adapter
    // must verify that receipt, read its frozen wire code, and deliver it as a JSON-RPC
    // error correlated to the request id — so the awaiting call REJECTS. A dropped
    // failure would hang the client forever, which is worse than an error.
    const client = newClient();
    // Freeze the nonce so the second call is a byte-identical replay.
    await client.connect(
      new McpReHttpTransport(config({ nonceFactory: () => "nonce-ts-adapter-replay-fixed" }), poster),
    );

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
