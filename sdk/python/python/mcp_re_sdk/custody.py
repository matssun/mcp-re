# SPDX-License-Identifier: Apache-2.0
"""Key custody for the MCP-RE Python SDK (ADR-MCPS-044 §Compliance).

Two explicit custody classes, and a policy that can refuse the weaker one:

``CustodyClass.SOFTWARE``
    The SDK holds the raw 32-byte Ed25519 seed and signs in-process.

``CustodyClass.NON_EXPORTING``
    The SDK holds only a ``(preimage: bytes) -> bytes`` callback. The private key
    never enters the SDK; in production the callback is a KMS/HSM client call.

Both produce byte-identical evidence for the same inputs — non-exporting custody
moves the key behind a device, it does not change the signed preimage.

``SigningDevice`` is the HSM/KMS stand-in used by tests and local development: it
encapsulates a seed and exposes ONLY ``.sign(preimage)``, with no getter for the key.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Callable, Optional

from . import _core

__all__ = [
    "CustodyClass",
    "McpReError",
    "Signer",
    "SignerPolicy",
    "SigningDevice",
]

#: The Ed25519 detached-signature length the RFC 9421 profile emits.
_SIGNATURE_LEN = 64
#: The Ed25519 seed length.
_SEED_LEN = 32


class McpReError(Exception):
    """An MCP-RE failure carrying a frozen ``mcp-re.*`` wire code.

    The taxonomy is the one the proxy and the Rust core emit, so a caller can branch
    on ``.wire_code`` without parsing prose (ADR-MCPS-044 §error taxonomy).
    """

    def __init__(self, wire_code: str, detail: str = "") -> None:
        super().__init__(f"{wire_code}: {detail}" if detail else wire_code)
        self.wire_code = wire_code
        self.detail = detail


class CustodyClass(enum.Enum):
    """How the signing key is held."""

    SOFTWARE = "software"
    NON_EXPORTING = "non-exporting"


class SigningDevice:
    """An HSM/KMS stand-in: it holds the key and exposes only ``.sign``.

    There is deliberately no accessor for the seed — the only way material leaves is
    as a signature over a caller-supplied preimage.
    """

    __slots__ = ("_seed",)

    def __init__(self, seed: bytes) -> None:
        if len(seed) != _SEED_LEN:
            raise ValueError(f"signing seed must be exactly {_SEED_LEN} bytes")
        self._seed = bytes(seed)

    @classmethod
    def from_seed(cls, seed: bytes) -> "SigningDevice":
        return cls(seed)

    def sign(self, preimage: bytes) -> bytes:
        """Sign the exact preimage bytes, returning a 64-byte detached signature."""
        return _core.sign_preimage(self._seed, preimage)

    def __repr__(self) -> str:  # never render key material
        return "SigningDevice(<sealed>)"


@dataclass(frozen=True)
class Signer:
    """A client signer plus the custody class its key is held under.

    Build with :meth:`software` or :meth:`non_exporting` rather than directly — the
    constructor cannot enforce that exactly one of seed/callback is present.
    """

    signer_id: str
    key_id: str
    custody: CustodyClass
    _seed: Optional[bytes] = None
    _sign_callback: Optional[Callable[[bytes], bytes]] = None

    @classmethod
    def software(cls, seed: bytes, signer_id: str, key_id: str) -> "Signer":
        """A signer whose raw seed the SDK holds and signs with in-process."""
        if len(seed) != _SEED_LEN:
            raise ValueError(f"signing seed must be exactly {_SEED_LEN} bytes")
        return cls(
            signer_id=signer_id,
            key_id=key_id,
            custody=CustodyClass.SOFTWARE,
            _seed=bytes(seed),
        )

    @classmethod
    def non_exporting(
        cls,
        signer_id: str,
        key_id: str,
        sign_callback: Callable[[bytes], bytes],
    ) -> "Signer":
        """A signer whose private key never enters the SDK.

        ``sign_callback`` receives the exact RFC 9421 signature base and returns the
        64-byte detached Ed25519 signature over it — a KMS/HSM call in production.
        """
        if not callable(sign_callback):
            raise TypeError("sign_callback must be callable")
        return cls(
            signer_id=signer_id,
            key_id=key_id,
            custody=CustodyClass.NON_EXPORTING,
            _sign_callback=sign_callback,
        )

    @classmethod
    def from_device(cls, signer_id: str, key_id: str, device: SigningDevice) -> "Signer":
        """A non-exporting signer backed by a :class:`SigningDevice`."""
        return cls.non_exporting(signer_id, key_id, device.sign)

    def sign_request(self, **kwargs) -> "_core.PySignedRequest":
        """Sign an MCP request, dispatching on custody class.

        Keyword arguments are those of :func:`mcp_re_sdk.sign_request` minus the
        credential (``seed``/``sign_callback``) and ``key_id``, which this signer
        supplies.
        """
        if self.custody is CustodyClass.SOFTWARE:
            return _core.sign_request(self._seed, self.key_id, **kwargs)
        return _core.sign_request_with_signer(self._sign_callback, self.key_id, **kwargs)

    def __repr__(self) -> str:  # never render key material
        return (
            f"Signer(signer_id={self.signer_id!r}, key_id={self.key_id!r}, "
            f"custody={self.custody.value!r})"
        )


@dataclass(frozen=True)
class SignerPolicy:
    """The custody + identity a route demands of its signer.

    ``require_non_exporting=True`` is the hardening profile: ``NON_EXPORTING`` is the
    only custody class it accepts, so a software/dev-file key is refused before any
    signing happens.
    """

    expected_signer_id: str
    profile: str = "production"
    require_non_exporting: bool = False

    @classmethod
    def hardened(cls, expected_signer_id: str, profile: str = "production") -> "SignerPolicy":
        """The hardening profile: non-exporting custody required."""
        return cls(
            expected_signer_id=expected_signer_id,
            profile=profile,
            require_non_exporting=True,
        )

    def check(self, signer: Signer) -> None:
        """Fail closed unless ``signer`` satisfies this policy.

        Raises :class:`McpReError` with ``mcp-re.actor_binding_failed`` — the same
        wire code the proxy emits when a request's actor binding is unacceptable.
        """
        if signer.signer_id != self.expected_signer_id:
            raise McpReError(
                "mcp-re.actor_binding_failed",
                f"signer {signer.signer_id!r} is not the route's expected "
                f"{self.expected_signer_id!r}",
            )
        if self.require_non_exporting and signer.custody is not CustodyClass.NON_EXPORTING:
            raise McpReError(
                "mcp-re.actor_binding_failed",
                f"profile {self.profile!r} requires non-exporting custody; signer holds "
                f"{signer.custody.value} custody",
            )
