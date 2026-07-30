#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Mint the throwaway X.509 material the SDK mTLS tests run against.

    python3 tools/gen_mtls_test_material.py <output-dir>

Written at test time, never committed: `scripts/tracked_secrets_gate.py` forbids a PEM
private key in a tracked file, and it is right to — a test key in git is still a key in
git, and the gate cannot tell one from the other. Both SDKs generate into a temporary
directory and both read the same files, so the Python and TypeScript mTLS tests are
making claims about identical material.

What it mints, and why each piece exists:

===================  =========================================================
`ca.crt` / `ca.key`  the ONLY root the client trusts
`server.*`           valid for `mcp-re-proxy.test` — the happy path
`wrongname.*`        signed by the SAME CA, valid for a DIFFERENT name: proves
                     the client checks identity, not merely chain-of-trust
`foreign_ca.crt`     a second, untrusted root
`foreign_server.*`   a perfectly valid certificate from the wrong root
`client.*`           the client certificate presented for mTLS client-auth
===================  =========================================================

The identity is a `.test` name (RFC 6761 — reserved, never resolvable) while the
connection is dialled to a loopback address, so the tests exercise the split the helper
exists to keep: what is PROVEN is the configured server name, not where the socket landed.
"""
from __future__ import annotations

import datetime
import pathlib
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

#: The identity the client requires the server to prove.
SERVER_NAME = "mcp-re-proxy.test"
#: A name the client never asks for, on a certificate the trusted CA did sign.
WRONG_NAME = "somewhere-else.test"

#: Not the point of these tests, and an expiry would turn a security test into a calendar
#: bomb that fails one morning for a reason unrelated to the code.
_VALID_YEARS = 20


def _key():
    # P-256: TLS-usable in both runtimes without a size/latency discussion. The evidence
    # layer's Ed25519 is a separate concern — this is the channel, not the signature.
    return ec.generate_private_key(ec.SECP256R1())


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _sign(subject_name, subject_key, issuer_name, issuer_key, *, ca: bool, san: str | None):
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365 * _VALID_YEARS))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if san is not None:
        # The name is checked against the SAN, not the subject CN: a CN-only certificate
        # is refused outright by both runtimes, which would make every test fail for the
        # wrong reason.
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _write(out: pathlib.Path, stem: str, cert, key=None) -> None:
    (out / f"{stem}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    if key is not None:
        (out / f"{stem}.key").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )


def generate(out_dir: str | pathlib.Path) -> pathlib.Path:
    """Mint the whole set into `out_dir`, which is created if needed."""
    out = pathlib.Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    ca_key = _key()
    ca = _sign(_name("mcp-re test CA"), ca_key, _name("mcp-re test CA"), ca_key, ca=True, san=None)
    _write(out, "ca", ca, ca_key)

    for stem, common_name, san in (
        ("server", SERVER_NAME, SERVER_NAME),
        ("wrongname", WRONG_NAME, WRONG_NAME),
        ("client", "mcp-re test client", None),
    ):
        key = _key()
        _write(out, stem, _sign(_name(common_name), key, ca.subject, ca_key, ca=False, san=san), key)

    foreign_key = _key()
    foreign_ca = _sign(
        _name("unrelated CA"), foreign_key, _name("unrelated CA"), foreign_key, ca=True, san=None
    )
    _write(out, "foreign_ca", foreign_ca, foreign_key)
    server_key = _key()
    _write(
        out,
        "foreign_server",
        _sign(_name(SERVER_NAME), server_key, foreign_ca.subject, foreign_key, ca=False, san=SERVER_NAME),
        server_key,
    )
    return out


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.splitlines()[2].strip(), file=sys.stderr)
        return 2
    print(generate(sys.argv[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
