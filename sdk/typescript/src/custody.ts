// SPDX-License-Identifier: Apache-2.0
/**
 * Key custody for the MCP-RE TypeScript SDK (ADR-MCPS-044 §Compliance).
 *
 * Two explicit custody classes, and a policy that can refuse the weaker one:
 *
 * - `CustodyClass.Software` — the SDK holds the raw 32-byte Ed25519 seed and signs
 *   in-process.
 * - `CustodyClass.NonExporting` — the SDK holds only a `(preimage: Buffer) => Buffer`
 *   callback. The private key never enters the SDK; in production the callback is a
 *   KMS/HSM client call.
 *
 * Both produce byte-identical evidence for the same inputs — non-exporting custody
 * moves the key behind a device, it does not change the signed preimage.
 *
 * `SigningDevice` is the HSM/KMS stand-in used by tests and local development: it
 * encapsulates a seed and exposes ONLY `.sign(preimage)`, with no getter for the key.
 */
import {
  signPreimage,
  signRequest,
  signRequestWithSigner,
  type SignedRequestJs,
} from "../native/binding.js";

/** The Ed25519 seed length. */
const SEED_LEN = 32;
/** The Ed25519 detached-signature length the RFC 9421 profile emits. */
const SIGNATURE_LEN = 64;

/** How the signing key is held. */
export enum CustodyClass {
  Software = "software",
  NonExporting = "non-exporting",
}

/** Base for every error this SDK raises. Catch this to catch them all. */
export class McpReSdkError extends Error {}

/**
 * A protocol failure carrying a frozen `mcp-re.*` wire code.
 *
 * The taxonomy is the one the proxy and the Rust core emit, so a caller can branch on
 * `.wireCode` without parsing prose (ADR-MCPS-044 §error taxonomy). The taxonomy is
 * **wire-only and reuse-only** — no code here is invented.
 */
export class McpReError extends McpReSdkError {
  readonly wireCode: string;
  readonly detail: string;

  constructor(wireCode: string, detail = "") {
    super(detail ? `${wireCode}: ${detail}` : wireCode);
    this.name = "McpReError";
    this.wireCode = wireCode;
    this.detail = detail;
  }
}

/**
 * The local signing device could not produce a usable signature.
 *
 * Deliberately **not** an {@link McpReError}: this is a local condition — the device
 * threw, or handed back something that is not a 64-byte signature — and nothing was ever
 * transmitted, so no wire code describes it. Reporting it as `mcp-re.invalid_signature`
 * would claim a peer rejected a signature that was never sent, and the frozen taxonomy is
 * wire-only and reuse-only, so there is no client-side token to borrow either.
 *
 * Fail-closed either way: no evidence is emitted. `.cause` carries whatever the device
 * actually did.
 */
export class SignerUnavailable extends McpReSdkError {
  readonly detail: string;

  constructor(detail: string, cause?: unknown) {
    super(`signing device unavailable: ${detail}`, { cause });
    this.name = "SignerUnavailable";
    this.detail = detail;
  }
}

/**
 * An HSM/KMS stand-in: it holds the key and exposes only `.sign`.
 *
 * There is deliberately no accessor for the seed — the only way material leaves is as
 * a signature over a caller-supplied preimage.
 */
export class SigningDevice {
  readonly #seed: Buffer;

  constructor(seed: Buffer) {
    if (seed.length !== SEED_LEN) {
      throw new Error(`signing seed must be exactly ${SEED_LEN} bytes`);
    }
    this.#seed = Buffer.from(seed);
  }

  static fromSeed(seed: Buffer): SigningDevice {
    return new SigningDevice(seed);
  }

  /** Sign the exact preimage bytes, returning a 64-byte detached signature. */
  sign = (preimage: Buffer): Buffer => signPreimage(this.#seed, preimage);

  /** Never render key material. */
  toString(): string {
    return "SigningDevice(<sealed>)";
  }
}

/** The signing inputs a {@link Signer} does not itself supply. */
export interface SignRequestArgs {
  idJson: string;
  method: string;
  paramsJson: string;
  targetUri: string;
  audienceId: string;
  route?: string | null;
  dpopToken: string;
  nonce: string;
  created: number;
  expires: number;
  contPrevAlg?: string | null;
  contPrevValue?: string | null;
  contIrrAlg?: string | null;
  contIrrValue?: string | null;
  contRequestState?: string | null;
}

/**
 * A client signer plus the custody class its key is held under.
 *
 * Build with {@link Signer.software} or {@link Signer.nonExporting} — the constructor
 * cannot enforce that exactly one of seed/callback is present.
 */
export class Signer {
  readonly signerId: string;
  readonly keyId: string;
  readonly custody: CustodyClass;
  readonly #seed?: Buffer;
  readonly #signCallback?: (preimage: Buffer) => Buffer;

  private constructor(
    signerId: string,
    keyId: string,
    custody: CustodyClass,
    seed?: Buffer,
    signCallback?: (preimage: Buffer) => Buffer,
  ) {
    this.signerId = signerId;
    this.keyId = keyId;
    this.custody = custody;
    this.#seed = seed;
    this.#signCallback = signCallback;
  }

  /** A signer whose raw seed the SDK holds and signs with in-process. */
  static software(seed: Buffer, signerId: string, keyId: string): Signer {
    if (seed.length !== SEED_LEN) {
      throw new Error(`signing seed must be exactly ${SEED_LEN} bytes`);
    }
    return new Signer(signerId, keyId, CustodyClass.Software, Buffer.from(seed));
  }

  /**
   * A signer whose private key never enters the SDK.
   *
   * `signCallback` receives the exact RFC 9421 signature base and returns the 64-byte
   * detached Ed25519 signature over it — a KMS/HSM call in production, invoked
   * synchronously on the Node main thread.
   */
  static nonExporting(
    signerId: string,
    keyId: string,
    signCallback: (preimage: Buffer) => Buffer,
  ): Signer {
    if (typeof signCallback !== "function") {
      throw new TypeError("signCallback must be a function");
    }
    return new Signer(signerId, keyId, CustodyClass.NonExporting, undefined, signCallback);
  }

  /** A non-exporting signer backed by a {@link SigningDevice}. */
  static fromDevice(signerId: string, keyId: string, device: SigningDevice): Signer {
    return Signer.nonExporting(signerId, keyId, device.sign);
  }

  /**
   * Sign an MCP request, dispatching on custody class.
   *
   * Throws {@link SignerUnavailable} if a non-exporting device cannot sign, and an Error
   * carrying a frozen wire code for a genuine protocol failure.
   */
  signRequest(a: SignRequestArgs): SignedRequestJs {
    const tail = [
      a.idJson,
      a.method,
      a.paramsJson,
      a.targetUri,
      a.audienceId,
      a.route ?? null,
      a.dpopToken,
      a.nonce,
      a.created,
      a.expires,
      a.contPrevAlg ?? null,
      a.contPrevValue ?? null,
      a.contIrrAlg ?? null,
      a.contIrrValue ?? null,
      a.contRequestState ?? null,
    ] as const;
    if (this.custody === CustodyClass.Software) {
      return signRequest(this.#seed!, this.keyId, ...tail);
    }

    // The core cannot tell "the device is broken" from "the signature is bad" — it only
    // sees a callback that failed, and maps that to a wire code. Capture what the device
    // actually did on this side of the boundary so the local condition is reported as a
    // local condition.
    let cause: unknown;
    const guarded = (preimage: Buffer): Buffer => {
      let sig: unknown;
      try {
        sig = this.#signCallback!(preimage);
      } catch (e) {
        cause = e;
        throw e;
      }
      if (!Buffer.isBuffer(sig)) {
        cause = new TypeError(`device returned ${typeof sig}, expected a Buffer`);
        throw cause;
      }
      if (sig.length !== SIGNATURE_LEN) {
        cause = new RangeError(
          `device returned a ${sig.length}-byte signature, expected ${SIGNATURE_LEN}`,
        );
        throw cause;
      }
      return sig;
    };

    try {
      return signRequestWithSigner(guarded, this.keyId, ...tail);
    } catch (e) {
      if (cause === undefined) throw e; // a real protocol failure in the core
      throw new SignerUnavailable(
        cause instanceof Error ? cause.message : String(cause),
        cause,
      );
    }
  }

  /** Never render key material. */
  toString(): string {
    return `Signer(signerId=${this.signerId}, keyId=${this.keyId}, custody=${this.custody})`;
  }
}

/**
 * The custody + identity a route demands of its signer.
 *
 * `requireNonExporting` is the hardening profile: `NonExporting` is the only custody
 * class it accepts, so a software/dev-file key is refused before any signing happens.
 */
export class SignerPolicy {
  readonly expectedSignerId: string;
  readonly profile: string;
  readonly requireNonExporting: boolean;

  constructor(expectedSignerId: string, profile = "production", requireNonExporting = false) {
    this.expectedSignerId = expectedSignerId;
    this.profile = profile;
    this.requireNonExporting = requireNonExporting;
  }

  /** The hardening profile: non-exporting custody required. */
  static hardened(expectedSignerId: string, profile = "production"): SignerPolicy {
    return new SignerPolicy(expectedSignerId, profile, true);
  }

  /**
   * Fail closed unless `signer` satisfies this policy.
   *
   * Throws {@link McpReError} with `mcp-re.actor_binding_failed` — the same wire code
   * the proxy emits when a request's actor binding is unacceptable.
   */
  check(signer: Signer): void {
    if (signer.signerId !== this.expectedSignerId) {
      throw new McpReError(
        "mcp-re.actor_binding_failed",
        `signer '${signer.signerId}' is not the route's expected '${this.expectedSignerId}'`,
      );
    }
    if (this.requireNonExporting && signer.custody !== CustodyClass.NonExporting) {
      throw new McpReError(
        "mcp-re.actor_binding_failed",
        `profile '${this.profile}' requires non-exporting custody; signer holds ${signer.custody} custody`,
      );
    }
  }
}
