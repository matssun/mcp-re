import { describe, expect, it } from "vitest";
import { connectMtlsHttp } from "../dist/index.js";

// `connectMtlsHttp` interpolates serverName into the raw HTTP Host header, so it must
// reject control characters up front (CR/LF header injection). No network is opened —
// the guard runs at construction, before any POST.
describe("connectMtlsHttp serverName validation", () => {
  const tls = { serverCa: Buffer.alloc(0), clientCert: Buffer.alloc(0), clientKey: Buffer.alloc(0) };
  const cfg = {} as never;

  it("rejects a serverName containing CR/LF", () => {
    expect(() =>
      connectMtlsHttp("127.0.0.1", 443, cfg, { ...tls, serverName: "evil\r\nX-Injected: 1" }),
    ).toThrow(/control characters/);
  });

  it("accepts a normal serverName", () => {
    expect(() => connectMtlsHttp("127.0.0.1", 443, cfg, { ...tls, serverName: "proxy.internal" })).not.toThrow();
  });
});
