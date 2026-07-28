// SPDX-License-Identifier: Apache-2.0
// C080/C088 — the TypeScript half of the sign-time nonce floor. It must refuse exactly
// what the Python half refuses: the two SDKs diverging on a security check while both
// still emit byte-identical signatures is the failure mode #420 was about.
import { describe, expect, it } from "vitest";

import { __testing } from "../src/transport.js";

const { checkedNonce, defaultNonce, MIN_NONCE_CHARS } = __testing;

describe("sign-time nonce floor", () => {
  it("the default generator clears the floor", () => {
    expect(defaultNonce().length).toBeGreaterThanOrEqual(MIN_NONCE_CHARS);
  });

  it("the default generator is accepted", () => {
    expect(checkedNonce(defaultNonce)).toBeTruthy();
  });

  it.each(["", "1", "counter-1", "nonce-parity-0001"])(
    "a sub-floor override is refused at sign time: %s",
    (bad) => {
      expect(() => checkedNonce(() => bad)).toThrow(/at least 22/);
    },
  );

  it("a non-string override is refused without a TypeError", () => {
    expect(() => checkedNonce(() => 12345 as unknown as string)).toThrow(/nonceFactory/);
  });

  it("a factory at exactly the floor is accepted", () => {
    expect(checkedNonce(() => "a".repeat(MIN_NONCE_CHARS))).toHaveLength(MIN_NONCE_CHARS);
  });
});
