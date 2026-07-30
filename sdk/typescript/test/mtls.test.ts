// SPDX-License-Identifier: Apache-2.0
//
// The mTLS connect helper against a real TLS server (#413 slice 2).
//
// The transport adapter's HTTP leg used to be entirely the caller's, which meant the one
// part of the deployment that decides whether the channel is authenticated at all had no
// shipped implementation and no test. This covers it end-to-end: a genuine TLS handshake
// against a server holding a real certificate, with client-auth required.
//
// The interesting cases are the refusals. A response signature verifies identically
// whether or not the channel proved who produced it, so nothing above this layer can
// notice a connection that was never authenticated — which is exactly why *these*
// assertions carry the weight:
//
//   - a certificate from a CA the client does not trust is refused;
//   - a certificate the trusted CA *did* sign, for a DIFFERENT name, is refused.
//
// The second is the one a chain-of-trust-only client passes and should not. The identity
// proven is the configured `serverName`, not wherever the socket happened to land, so
// every test here dials loopback while requiring `mcp-re-proxy.test`.
//
// The X.509 material is minted at test time by `tools/gen_mtls_test_material.py` — never
// committed, because `scripts/tracked_secrets_gate.py` forbids a PEM private key in a
// tracked file and is right to. The generator needs Python with `cryptography`; where
// that is unavailable the TLS cases self-skip, exactly as the live-proxy e2e tests do,
// and the cases that need no server still run.
//
// Mirrors `sdk/python/tests/test_mtls.py` — same generated material, same assertions.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:https";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { Signer } from "../src/index.js";
import { connectMtlsHttp, MtlsTransportError, mtlsPoster, type MtlsOptions } from "../src/mtls.js";
import type { McpReConfig } from "../src/transport.js";

const REPO_ROOT = resolve(__dirname, "..", "..", "..");
/** RFC 6761 reserved: never resolvable, so a test cannot accidentally reach the network. */
const SERVER_NAME = "mcp-re-proxy.test";
const CLIENT_SEED = Buffer.alloc(32, 11);

let material: string | null = null;

beforeAll(() => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-re-mtls-"));
  for (const python of ["python3", "python"]) {
    try {
      execFileSync(python, [join(REPO_ROOT, "tools", "gen_mtls_test_material.py"), dir], {
        stdio: "pipe",
      });
      material = dir;
      return;
    } catch {
      // Try the next interpreter; a missing one is not a failure of this SDK.
    }
  }
  rmSync(dir, { recursive: true, force: true });
});

afterAll(() => {
  if (material) rmSync(material, { recursive: true, force: true });
});

const pem = (stem: string): Buffer => readFileSync(join(material!, stem));

/** A TLS server on loopback presenting `certStem`, requiring a client certificate. */
function serve(
  certStem: string,
  opts: { replyBytes?: number; extraHeaders?: [string, string][] } = {},
): Promise<{ server: Server; port: number }> {
  const server = createServer(
    {
      cert: pem(`${certStem}.crt`),
      key: pem(`${certStem}.key`),
      // Client-auth required, so a successful round trip proves the client certificate
      // was presented and accepted — not merely that the server was reachable.
      ca: pem("ca.crt"),
      requestCert: true,
      rejectUnauthorized: true,
    },
    (req, res) => {
      req.resume();
      req.on("end", () => {
        const body = Buffer.alloc(opts.replyBytes ?? 16, "x");
        res.setHeader("content-type", "application/json");
        for (const [name, value] of opts.extraHeaders ?? []) res.appendHeader(name, value);
        res.setHeader("content-length", String(body.length));
        res.writeHead(200);
        res.end(body);
      });
    },
  );
  return new Promise((done) =>
    server.listen(0, "127.0.0.1", () =>
      done({ server, port: (server.address() as { port: number }).port }),
    ),
  );
}

const config = (port: number, over: Partial<McpReConfig> = {}): McpReConfig => ({
  signer: Signer.software(CLIENT_SEED, "did:example:host-a", "client-key-1"),
  audienceId: "verifier-1",
  targetUri: `https://${SERVER_NAME}:${port}/mcp`,
  dpopToken: "access-token-xyz",
  issuerKeyId: "server-key-1",
  issuerPubkeyB64Url: "x".repeat(43),
  issuerTrustDomain: "example.com",
  issuerSubject: "did:example:server-1",
  verifierAudiences: ["verifier-1"],
  expectedAudienceHash: "aud-scope-1",
  acceptedEpochs: ["epoch-1"],
  ...over,
});

const options = (over: Partial<MtlsOptions> = {}): MtlsOptions => ({
  serverCa: pem("ca.crt"),
  clientCert: pem("client.crt"),
  clientKey: pem("client.key"),
  connectHost: "127.0.0.1",
  timeoutMs: 10_000,
  ...over,
});

async function post(
  port: number,
  over: Partial<MtlsOptions> = {},
  headers: { key: string; value: string }[] = [],
) {
  const cfg = config(port);
  const poster = mtlsPoster(cfg, options({ connectPort: port, ...over }));
  return poster("POST", cfg.targetUri, headers, Buffer.from("{}"));
}

/** Run `body` against a server presenting `certStem`, tearing it down either way. */
async function withServer(
  certStem: string,
  opts: Parameters<typeof serve>[1],
  body: (port: number) => Promise<void>,
) {
  const { server, port } = await serve(certStem, opts);
  try {
    await body(port);
  } finally {
    await new Promise((done) => server.close(done));
  }
}

describe("the mTLS connect helper", () => {
  /** A case that needs the generated X.509 and a live TLS server. */
  const tls = (name: string, fn: () => Promise<void>) =>
    it(name, async () => {
      if (!material) {
        // Reported, not silently passed: a lane where this never ran must say so.
        console.warn(`skipping "${name}": tools/gen_mtls_test_material.py could not run`);
        return;
      }
      await fn();
    });

  tls("round-trips a signed request over a verified channel", async () => {
    // The happy path — and the only one that says the helper is usable at all.
    await withServer("server", {}, async (port) => {
      const reply = await post(port, {}, [{ key: "content-type", value: "application/json" }]);
      expect(reply.status).toBe(200);
      expect(reply.body.toString()).toBe("x".repeat(16));
      // Lowercased, as the profile matches header names: the signature base is built
      // from what arrived, so the reply's headers are handed back verbatim in wire order.
      expect(reply.headers).toContainEqual({ key: "content-type", value: "application/json" });
    });
  });

  tls("refuses a certificate from an untrusted root", async () => {
    // Chain-of-trust: the certificate is perfectly valid — for the wrong root.
    await withServer("foreign_server", {}, async (port) => {
      await expect(post(port)).rejects.toThrow(MtlsTransportError);
    });
  });

  tls("refuses a certificate for a different name", async () => {
    // Identity: the TRUSTED CA signed this one — for somewhere else. A client that
    // verified only the chain would accept it. That is the failure this assertion exists
    // for: any certificate the CA ever issued is not automatically this server's.
    await withServer("wrongname", {}, async (port) => {
      await expect(post(port)).rejects.toThrow(MtlsTransportError);
    });
  });

  tls("refuses an oversized response", async () => {
    // A ceiling that fails closed, rather than buffering whatever the peer sends.
    await withServer("server", { replyBytes: 4096 }, async (port) => {
      await expect(post(port, { maxResponseBytes: 1024 })).rejects.toThrow(/maxResponseBytes/);
    });
  });

  tls("does not fold a repeated response header", async () => {
    // Wire order, duplicates intact: the RFC 9421 signature base is built from these. A
    // reader that folded repeats into one value would reconstruct a different base than
    // the server signed, and the response would fail verification for a reason that has
    // nothing to do with the evidence.
    await withServer("server", { extraHeaders: [["x-repeat", "one"], ["x-repeat", "two"]] }, async (port) => {
      const reply = await post(port);
      expect(reply.headers.filter((h) => h.key === "x-repeat").map((h) => h.value)).toEqual([
        "one",
        "two",
      ]);
    });
  });

  tls("refuses a transport-owned header", async () => {
    // Framing belongs to the transport. A caller-set `content-length` desynchronises the
    // message boundary from what the peer parses — the request-smuggling shape.
    await withServer("server", {}, async (port) => {
      await expect(post(port, {}, [{ key: "Content-Length", value: "9999" }])).rejects.toThrow(
        /content-length/,
      );
    });
  });

  tls("refuses a header value that would split the request", async () => {
    // A CR/LF in a value terminates the header block early and lets the rest be read as
    // a second request. Refused whole; never sanitised and sent.
    await withServer("server", {}, async (port) => {
      await expect(post(port, {}, [{ key: "x-evil", value: "a\r\nX-Injected: b" }])).rejects.toThrow(
        MtlsTransportError,
      );
    });
  });

  tls("opens a session transport over the channel", async () => {
    // The one-call form: the adapter, with its HTTP leg already built and verified. The
    // reply here is not signed evidence, so the exchange fails closed — which is the
    // point. It proves the composition reached the network and came back through the
    // adapter's verification, rather than that a stub returned something agreeable.
    await withServer("server", {}, async (port) => {
      const cfg = config(port);
      const transport = connectMtlsHttp(cfg, options({ connectPort: port }));
      let reply: any;
      transport.onmessage = (m) => {
        reply = m;
      };
      await transport.start();
      await transport.send({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
      await transport.close();
      expect(reply?.error, "an unsigned reply must never read as a result").toBeDefined();
    });
  });

  // These need no server: the helper refuses the configuration outright.

  it("refuses a plaintext target", () => {
    // An http:// target would be signed and sent in the clear, and the evidence would
    // still verify — so this cannot be left to the deployment to notice.
    expect(() =>
      mtlsPoster(config(443, { targetUri: "http://mcp-re-proxy.test/mcp" }), {
        serverCa: "ca",
        clientCert: "cert",
        clientKey: "key",
      }),
    ).toThrow(/https:\/\//);
  });

  it("refuses a non-positive response ceiling", () => {
    // Zero would refuse every reply, silently, as if every server were hostile.
    expect(() =>
      mtlsPoster(config(443), {
        serverCa: "ca",
        clientCert: "cert",
        clientKey: "key",
        maxResponseBytes: 0,
      }),
    ).toThrow(/maxResponseBytes/);
  });
});
