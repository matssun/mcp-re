// SPDX-License-Identifier: Apache-2.0
//
// Offline unit tests for `McpReHttpTransport`: the obligations that hold regardless of
// what a counterparty says. The live proof — a real MCP `Client` against the real proxy
// and a real FastMCP backend — is in `transport_e2e.test.ts`; these cover the paths a
// happy round-trip never reaches, with an injected `poster` and no network.
//
// The theme throughout: **a failure must be DELIVERED, not dropped.** A transport that
// swallowed a failed exchange would leave `Client` awaiting a reply that never comes, and
// a hang is a worse failure mode than a raise.
import { describe, expect, it, vi } from "vitest";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";

import {
  McpReError,
  McpReSdkError,
  OpaqueBytesProvider,
  Signer,
  SignerPolicy,
  SignerUnavailable,
} from "../src/index.js";
import { McpReHttpTransport, type McpReConfig, type Poster } from "../src/transport.js";

const CLIENT_SEED = Buffer.alloc(32, 11);
const TARGET = "https://proxy.internal:8600/mcp";

/** The minimum a config can carry: every optional knob left to its default, so the
 * default side of each branch is what runs. */
function minimalConfig(over: Partial<McpReConfig> = {}): McpReConfig {
  return {
    signer: Signer.software(CLIENT_SEED, "did:example:host-a", "client-key-1"),
    audienceId: "verifier-1",
    targetUri: TARGET,
    dpopToken: "access-token-xyz",
    issuerKeyId: "server-key-1",
    issuerPubkeyB64Url: "",
    issuerTrustDomain: "example.com",
    issuerSubject: "did:example:server-1",
    verifierAudiences: ["verifier-1"],
    expectedAudienceHash: "aud-scope-1",
    acceptedEpochs: ["epoch-1"],
    ...over,
  };
}

const REQUEST: JSONRPCMessage = { jsonrpc: "2.0", id: 7, method: "tools/list", params: {} };

/** Drive one message through a transport and capture what it hands the client. */
async function sendAndCapture(
  config: McpReConfig,
  poster: Poster,
  message: JSONRPCMessage = REQUEST,
): Promise<JSONRPCMessage | undefined> {
  const transport = new McpReHttpTransport(config, poster);
  let seen: JSONRPCMessage | undefined;
  transport.onmessage = (m) => {
    seen = m;
  };
  await transport.start();
  await transport.send(message);
  return seen;
}

const throwingPoster = (e: unknown): Poster => async () => {
  throw e;
};

describe("McpReHttpTransport lifecycle", () => {
  it("checks the signer against the route policy in start(), before anything is signed", async () => {
    const poster = vi.fn<Poster>();
    const transport = new McpReHttpTransport(
      minimalConfig({ policy: SignerPolicy.hardened("did:example:host-a") }),
      poster,
    );

    await expect(transport.start()).rejects.toThrow(McpReError);
    // A custody violation must fail the CONNECTION; nothing may reach the wire.
    expect(poster).not.toHaveBeenCalled();
  });

  it("checks the authorization policy in start() too", async () => {
    const transport = new McpReHttpTransport(
      minimalConfig({
        authorizationPolicy: { check: () => { throw new McpReError("mcp-re.authorization_binding_missing"); } } as never,
      }),
      vi.fn<Poster>(),
    );
    await expect(transport.start()).rejects.toThrow(/authorization_binding_missing/);
  });

  it("accepts a signer that satisfies the policy", async () => {
    const transport = new McpReHttpTransport(
      minimalConfig({ policy: new SignerPolicy("did:example:host-a", "development") }),
      vi.fn<Poster>(),
    );
    await expect(transport.start()).resolves.toBeUndefined();
  });

  it("refuses a second start()", async () => {
    // A second start would sign under a policy that was already accepted, hiding the
    // first one.
    const transport = new McpReHttpTransport(minimalConfig(), vi.fn<Poster>());
    await transport.start();
    await expect(transport.start()).rejects.toThrow(McpReSdkError);
  });

  it("fires onclose when closed, and can be started again afterwards", async () => {
    const transport = new McpReHttpTransport(minimalConfig(), vi.fn<Poster>());
    const onclose = vi.fn();
    transport.onclose = onclose;
    await transport.start();
    await transport.close();
    expect(onclose).toHaveBeenCalledOnce();
    await expect(transport.start()).resolves.toBeUndefined();
  });

  it("closes cleanly with no onclose installed", async () => {
    await expect(new McpReHttpTransport(minimalConfig(), vi.fn<Poster>()).close()).resolves.toBeUndefined();
  });
});

describe("McpReHttpTransport notification handling", () => {
  const NOTIFICATION: JSONRPCMessage = { jsonrpc: "2.0", method: "notifications/initialized" };

  it("drops a notification and reports it, because it carries no evidence", async () => {
    // MCP-RE's wire is one signed POST per request. A notification has no reply, so it
    // carries no evidence and cannot be verified — dropping is honest, silence is not.
    const dropped: string[] = [];
    const poster = vi.fn<Poster>();
    const seen = await sendAndCapture(
      minimalConfig({ onDroppedNotification: (m) => dropped.push(m) }),
      poster,
      NOTIFICATION,
    );

    expect(dropped).toEqual(["notifications/initialized"]);
    expect(poster).not.toHaveBeenCalled();
    expect(seen).toBeUndefined();
  });

  it("drops a notification silently when no observer is installed", async () => {
    const poster = vi.fn<Poster>();
    await expect(sendAndCapture(minimalConfig(), poster, NOTIFICATION)).resolves.toBeUndefined();
    expect(poster).not.toHaveBeenCalled();
  });

  it("drops a client-side response, which is not a client-initiated request", async () => {
    const dropped: string[] = [];
    const response: JSONRPCMessage = { jsonrpc: "2.0", id: 1, result: {} };
    await sendAndCapture(minimalConfig({ onDroppedNotification: (m) => dropped.push(m) }), vi.fn<Poster>(), response);
    expect(dropped).toEqual(["<unknown>"]);
  });
});

describe("McpReHttpTransport failure delivery", () => {
  it("delivers a wire failure as a JSON-RPC error carrying the frozen code", async () => {
    const seen = await sendAndCapture(
      minimalConfig(),
      throwingPoster(new McpReError("mcp-re.replay_detected", "seen before")),
    );
    expect(seen).toMatchObject({ id: 7, error: { code: -32001, message: "mcp-re.replay_detected" } });
  });

  it("delivers a local signer failure WITHOUT claiming a wire code", async () => {
    // The device broke on this side of the boundary; nothing was transmitted, so no peer
    // rejected anything. Reporting `mcp-re.invalid_signature` here would be a lie.
    const seen = await sendAndCapture(
      minimalConfig(),
      throwingPoster(new SignerUnavailable("kms timeout")),
    );
    const message = (seen as { error: { message: string } }).error.message;
    expect(message).toContain("mcp-re-sdk:");
    expect(message).not.toMatch(/^mcp-re\./);
  });

  it("delivers the core's own fail-closed Error rather than letting the caller hang", async () => {
    const seen = await sendAndCapture(
      minimalConfig(),
      throwingPoster(new Error("mcp-re.response_sig_invalid")),
    );
    expect(seen).toMatchObject({ error: { message: "mcp-re.response_sig_invalid" } });
  });

  it("re-throws a non-Error, which is a defect rather than a protocol outcome", async () => {
    const transport = new McpReHttpTransport(minimalConfig(), throwingPoster("not an error"));
    await transport.start();
    await expect(transport.send(REQUEST)).rejects.toBe("not an error");
  });

  it("still completes when no onmessage is installed", async () => {
    const transport = new McpReHttpTransport(
      minimalConfig(),
      throwingPoster(new McpReError("mcp-re.replay_detected")),
    );
    await transport.start();
    await expect(transport.send(REQUEST)).resolves.toBeUndefined();
  });
});

describe("McpReHttpTransport signing inputs", () => {
  /** Capture what the transport actually put on the wire. */
  function capturingPoster(): { poster: Poster; calls: { headers: { key: string; value: string }[]; body: Buffer }[] } {
    const calls: { headers: { key: string; value: string }[]; body: Buffer }[] = [];
    const poster: Poster = async (_m, _u, headers, body) => {
      calls.push({ headers, body });
      throw new McpReError("mcp-re.replay_detected"); // stop before native verification
    };
    return { poster, calls };
  }

  it("generates its own freshness, so a caller cannot repeat a nonce", async () => {
    // A nonce that repeats inside the window is a defect, not a policy knob.
    const { poster, calls } = capturingPoster();
    await sendAndCapture(minimalConfig(), poster);
    await sendAndCapture(minimalConfig(), poster);

    const sigs = calls.map((c) => c.headers.find((h) => h.key.toLowerCase() === "signature")?.value);
    expect(sigs[0]).toBeDefined();
    expect(sigs[0]).not.toEqual(sigs[1]);
  });

  it("signs the request body the caller's message described", async () => {
    const { poster, calls } = capturingPoster();
    await sendAndCapture(minimalConfig(), poster);
    const body = JSON.parse(calls[0].body.toString("utf8"));
    expect(body).toMatchObject({ method: "tools/list", id: 7 });
  });

  it("signs a request with no params", async () => {
    const { poster, calls } = capturingPoster();
    await sendAndCapture(minimalConfig(), poster, { jsonrpc: "2.0", id: 1, method: "ping" });
    expect(calls).toHaveLength(1);
  });

  it("honours an injected clock and ttl", async () => {
    const { poster, calls } = capturingPoster();
    await sendAndCapture(minimalConfig({ clock: () => 1_000, requestTtl: 30, route: "a" }), poster);
    const input = calls[0].headers.find((h) => h.key.toLowerCase() === "signature-input")?.value;
    expect(input).toContain("created=1000");
    expect(input).toContain("expires=1030");
  });

  it("passes authorization bindings to the core, which digests the real bytes", async () => {
    // bind-not-interpret: the provider supplies the artifact; the core digests it. The
    // bytes themselves must never appear in the evidence.
    const material = Buffer.from("pdp-decision-document");
    const { poster, calls } = capturingPoster();
    await sendAndCapture(
      minimalConfig({ authorization: [new OpaqueBytesProvider("pdp-decision", material)] }),
      poster,
    );

    const evidence = calls[0].body.toString("utf8");
    expect(evidence).toContain("pdp-decision");
    expect(evidence).not.toContain("pdp-decision-document");
    expect(evidence).not.toContain(material.toString("base64url"));
  });
});
