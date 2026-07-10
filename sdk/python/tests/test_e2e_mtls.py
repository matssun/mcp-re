"""Live mTLS/HTTP MCP-RE interop: Python SDK <-> the REAL production mcp-re-proxy.

This is step (i) — the real mTLS/HTTP interop proof, deliberately NOT the full
ClientSession proof. The production `mcp-re-proxy` speaks one HTTP/1.1 POST per mTLS
connection (`Connection: close`; mcp-re-proxy/src/tls.rs::serve_once), so this drives
ONE signed MCP-RE request per connection at the wire level:

    Python signs a draft-02 tools/call
      -> one mTLS connection (client cert; server cert verified as proxy.internal)
      -> POST / HTTP/1.1  (MCP-RE request body)
      -> REAL mcp-re-proxy   verifies signature + freshness + audience, strips envelope
      -> HTTP inner backend  (MCP-RE-unaware; --inner-http-url) executes read_file
      -> mcp-re-proxy signs the draft-02 response
      -> Python verifies the signature + request_hash binding, strips to plain MCP

MCP-RE is HTTP-profile only: the inner MCP server is reached over HTTP (a stdio-only
server would be fronted by an external adapter such as FastMCP). Here the inner is a
tiny in-process threaded HTTP backend (`_inner_backend.start_inner_backend`).

Full `ClientSession.initialize()` over this request/response HTTP transport is the
SEPARATE, larger adapter slice (step ii) — it is NOT exercised here.

Materials come from `DemoFixtures` via the `emit_mtls_fixtures` example (TLS certs
vary per run; identities/seeds/audience are the deterministic defaults). Needs the
built binary + cargo:
    cargo build -p mcp-re-proxy
"""

import json
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import mcp_re_sdk

from _inner_backend import FILE_TEXT, start_inner_backend

ROOT = Path(__file__).resolve().parents[3]
PROXY = ROOT / "target" / "debug" / "mcp-re-proxy"

if not (PROXY.exists() and shutil.which("cargo")):
    pytest.skip(
        "needs cargo + built mcp-re-proxy (cargo build -p mcp-re-proxy)",
        allow_module_level=True,
    )

# Deterministic DemoFixtures defaults (only the TLS certs vary per run).
SIGNER_SEED = bytes([1] * 32)
SERVER_SEED = bytes([2] * 32)
SIGNER, SIGNER_KEY = "did:example:agent-1", "key-1"
SERVER, SERVER_KEY = "did:example:server-1", "server-key-1"
AUDIENCE, SERVER_NAME = "did:example:server-1", "proxy.internal"
ON_BEHALF_OF = "did:example:user-1"
AUTHZ_DIGEST = "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"


@pytest.fixture(scope="module")
def proxy():
    out = tempfile.mkdtemp(prefix="mcp_re_mtls_fx_")
    inner_http_url, inner = start_inner_backend()
    subprocess.run(
        ["cargo", "run", "-q", "-p", "mcp-re-demo", "--example", "emit_mtls_fixtures", "--", out],
        cwd=ROOT, check=True, capture_output=True,
    )
    p = subprocess.Popen(
        [str(PROXY),
         "--bind", "127.0.0.1:0", "--audience", AUDIENCE,
         "--server-signer", SERVER, "--server-key-id", SERVER_KEY,
         "--max-clock-skew", "300", "--expected-version-policy", "draft-02-only",
         "--key-source", "file", "--signing-key-seed", f"{out}/signing_seed",
         "--tls-cert", f"{out}/server_cert.pem", "--tls-key", f"{out}/server_key.pem",
         "--client-ca", f"{out}/client_ca.pem", "--trust", f"{out}/trust.json",
         "--max-client-cert-lifetime", "175200h", "--transport-binding", "none",
         "--inner-http-url", inner_http_url],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    port = None
    deadline = time.time() + 30
    while time.time() < deadline:
        line = p.stderr.readline()
        if not line:
            break
        if "async fleet serving on 127.0.0.1:" in line:
            port = int(line.split("async fleet serving on 127.0.0.1:")[1].split()[0])
            break
    # Drain remaining stderr so the proxy's per-request logging never blocks on a full pipe.
    threading.Thread(target=lambda: [None for _ in p.stderr], daemon=True).start()
    if port is None:
        p.terminate()
        inner.shutdown()
        pytest.fail("mcp-re-proxy did not report a serving address")
    try:
        yield {"port": port, "out": out}
    finally:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
        inner.shutdown()
        shutil.rmtree(out, ignore_errors=True)


def _sign(tool, arguments):
    now = datetime.now(timezone.utc)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    signer = mcp_re_sdk.Signer.software(SIGNER_SEED, signer_id=SIGNER, key_id=SIGNER_KEY)
    policy = mcp_re_sdk.SignerPolicy(SIGNER, environment="dev-test", require_mcp_re=True)
    return mcp_re_sdk.sign_request_with_signer(
        '"req-1"', "tools/call", json.dumps({"name": tool, "arguments": arguments}),
        on_behalf_of=ON_BEHALF_OF, audience=AUDIENCE,
        binding_digest_alg="sha256", binding_digest_value=AUTHZ_DIGEST,
        nonce=secrets.token_urlsafe(16),
        issued_at=now.strftime(fmt), expires_at=(now + timedelta(seconds=300)).strftime(fmt),
        signer=signer, policy=policy,
    )


def _sign_non_exporting(tool, arguments):
    """Sign via a NON-EXPORTING signer under the PRODUCTION hardening profile: the
    key lives in a SigningDevice, the signer holds only its sign callback, custody is
    NonExporting, and the policy requires it. The proxy must accept the resulting
    evidence exactly as for a software signer (same key, same signature)."""
    now = datetime.now(timezone.utc)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    device = mcp_re_sdk.SigningDevice.from_seed(SIGNER_SEED, signer_id=SIGNER, key_id=SIGNER_KEY)
    signer = mcp_re_sdk.Signer.non_exporting(signer_id=SIGNER, key_id=SIGNER_KEY, sign_callback=device.sign)
    policy = mcp_re_sdk.SignerPolicy(
        SIGNER, environment="production", require_mcp_re=True
    ).require_non_exporting()
    return mcp_re_sdk.sign_request_with_signer(
        '"req-1"', "tools/call", json.dumps({"name": tool, "arguments": arguments}),
        on_behalf_of=ON_BEHALF_OF, audience=AUDIENCE,
        binding_digest_alg="sha256", binding_digest_value=AUTHZ_DIGEST,
        nonce=secrets.token_urlsafe(16),
        issued_at=now.strftime(fmt), expires_at=(now + timedelta(seconds=300)).strftime(fmt),
        signer=signer, policy=policy,
    )


def _post(out, port, body):
    """One mTLS HTTP/1.1 POST; returns the response body bytes."""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=f"{out}/server_ca.pem")
    ctx.load_cert_chain(f"{out}/client_cert.pem", f"{out}/client_key.pem")
    raw = socket.create_connection(("127.0.0.1", port), timeout=15)
    tls = ctx.wrap_socket(raw, server_hostname=SERVER_NAME)
    try:
        head = (
            f"POST / HTTP/1.1\r\nHost: {SERVER_NAME}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        ).encode()
        tls.sendall(head + body)
        resp = b""
        while True:
            chunk = tls.recv(65536)
            if not chunk:
                break
            resp += chunk
    finally:
        tls.close()
    return resp.split(b"\r\n\r\n", 1)[1]


def _trusting_resolver():
    r = mcp_re_sdk.TrustResolver()
    r.insert_dev_seed(SERVER, SERVER_KEY, SERVER_SEED)
    return r


def test_mtls_roundtrip_real_proxy_and_fileserver(proxy):
    """A signed read_file is accepted by the real mcp-re-proxy over real mTLS, the
    real fileserver executes it, and the production-signed response is verified +
    correlated back to a plain MCP result with the file's content."""
    signed = _sign("read_file", {"path": "greeting.txt"})
    body = _post(proxy["out"], proxy["port"], signed.wire_bytes)

    res = mcp_re_sdk.verify_response(
        body, resolver=_trusting_resolver(),
        expected_request_hash=signed.request_hash, expected_server_signer=SERVER,
        enforcement_mode="require_mcp_re",
    )
    assert res.accepted and res.decision == "accept"
    assert res.server_signer == SERVER
    assert res.request_hash == signed.request_hash

    obj = json.loads(body)
    obj.get("result", {}).get("_meta", {}).pop(mcp_re_sdk.response_meta_key(), None)
    assert obj["result"]["content"][0]["text"] == FILE_TEXT
    assert "_meta" not in obj["result"] or obj["result"]["_meta"] == {}


def test_mtls_roundtrip_non_exporting_signer(proxy):
    """A request signed via a non-exporting (device-delegated) signer under the
    production hardening profile is accepted by the real mcp-re-proxy over real mTLS,
    the fileserver executes it, and the production-signed response verifies — proving
    the non-exporting custody path produces genuine, proxy-accepted evidence."""
    signed = _sign_non_exporting("read_file", {"path": "greeting.txt"})
    body = _post(proxy["out"], proxy["port"], signed.wire_bytes)

    res = mcp_re_sdk.verify_response(
        body, resolver=_trusting_resolver(),
        expected_request_hash=signed.request_hash, expected_server_signer=SERVER,
        enforcement_mode="require_mcp_re",
    )
    assert res.accepted and res.decision == "accept"

    obj = json.loads(body)
    obj.get("result", {}).get("_meta", {}).pop(mcp_re_sdk.response_meta_key(), None)
    assert obj["result"]["content"][0]["text"] == FILE_TEXT


def test_mtls_response_fails_closed_when_server_untrusted(proxy):
    """The proxy returns a genuinely-signed response, but with no trust anchor for
    its signer the SDK fails closed — proving verification is real, over real mTLS."""
    signed = _sign("read_file", {"path": "greeting.txt"})
    body = _post(proxy["out"], proxy["port"], signed.wire_bytes)
    res = mcp_re_sdk.verify_response(
        body, resolver=mcp_re_sdk.TrustResolver(),  # empty: server signer cannot resolve
        expected_request_hash=signed.request_hash, enforcement_mode="require_mcp_re",
    )
    assert res.decision == "fail-closed"
    assert res.reason == "mcp-re.actor_binding_failed"
