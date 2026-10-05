# SPDX-License-Identifier: Apache-2.0
"""The Bazel-native lane over the SDK's native module.

Runs under `bazel test //sdk/python:core_lane_test` with the standard library alone: the
package is the Bazel-assembled `mcp_re_sdk` (the Python sources copied beside the
Bazel-built `_core`), never an installed wheel and never the source tree. A test here
measures the extension this build produced, and the first test fails if any other one
was loaded.
"""
import base64
import json
import os
import unittest

import mcp_re_sdk
from mcp_re_sdk import _core

#: The ignored build output a local maturin build leaves in the source package.
_SOURCE_PACKAGE = os.path.join("sdk", "python", "python", "mcp_re_sdk")

#: Exchanges recorded from the real proxy (`tools/gen_sdk_transport_fixture.py`), named by
#: the target's `env`. Re-signing a recorded request reproduces its bytes, so the recorded
#: reply answers it.
with open(os.environ["MCP_RE_SDK_REPLAY_FIXTURE"], encoding="utf-8") as _fh:
    _REPLAY = json.load(_fh)


class TestCoreLane(unittest.TestCase):
    def test_the_extension_is_the_bazel_built_one(self):
        # The module Python loaded is the one the pyo3 rule declared, and the file behind
        # it is a Bazel output: a source-tree build is `_core.abi3.so` in the source package.
        self.assertEqual(os.path.basename(_core.__file__), "_core.so")
        core = os.path.realpath(_core.__file__)
        package = os.path.realpath(os.path.dirname(mcp_re_sdk.__file__))
        self.assertIn(os.sep + "bazel-out" + os.sep, core)
        self.assertNotIn(_SOURCE_PACKAGE, core)
        # One package: the Python sources import `_core` from beside themselves.
        self.assertEqual(
            os.path.dirname(os.path.abspath(_core.__file__)),
            os.path.abspath(os.path.dirname(mcp_re_sdk.__file__)),
        )
        self.assertIn(os.sep + "bazel-out" + os.sep, package)

    def test_the_core_reports_its_profile_and_version(self):
        self.assertTrue(mcp_re_sdk.profile_tag())
        version = mcp_re_sdk.core_version()
        major, minor = (int(x) for x in version.split(".")[:2])
        self.assertTrue(major > 0 or minor >= 17, version)

    def test_a_signed_request_carries_its_signature_and_evidence(self):
        signed = mcp_re_sdk.sign_request(
            bytes(range(32)),
            "key-1",
            "1",
            "tools/list",
            "{}",
            "https://proxy.internal:8600/mcp",
            "did:example:server-1",
            None,
            "dpop-token",
            "nonce-core-lane-0001-128bit",
            1000,
            2000,
        )
        headers = {k.lower() for k, _ in signed.headers}
        self.assertLessEqual({"signature", "signature-input", "content-digest"}, headers)
        self.assertEqual(signed.evidence_digest_alg, "sha256")
        self.assertIn(b"tools/list", signed.body())


class TestPinnedRoot(unittest.TestCase):
    """The root anchor is judged at the caller's `now`, and its identity is never empty."""

    def _signed(self, index, method, params):
        f = _REPLAY
        sign = mcp_re_sdk.sign_request if index == 0 else mcp_re_sdk.sign_notification
        lead = ("0", method) if index == 0 else (method,)
        signed = sign(
            base64.b64decode(f["client_seed_b64"]),
            f["key_id"],
            *lead,
            json.dumps(params, separators=(",", ":")),
            f["target_uri"],
            f["audience_id"],
            f["route"],
            f["dpop_token"],
            f"{f['nonce_prefix']}{index:04d}",
            f["created"],
            f["created"] + f["request_ttl"],
        )
        exchange = f["exchanges"][index]
        self.assertEqual(signed.body(), base64.b64decode(exchange["request_body_b64"]))
        return signed, exchange

    def _verify(self, verify, signed, exchange, now, **over):
        f = _REPLAY
        issuer = dict(f["issuer"])
        retired = {k: over.pop(k) for k in ["issuer_retired_until"] if k in over}
        issuer.update(over)
        return verify(
            exchange["status"],
            [tuple(h) for h in exchange["headers"]],
            base64.b64decode(exchange["body_b64"]),
            signed.method,
            signed.target_uri,
            list(signed.headers),
            signed.body(),
            issuer["key_id"],
            issuer["pubkey_b64url"],
            issuer["role"],
            issuer["trust_domain"],
            issuer["subject"],
            f["verifier_audiences"],
            f["expected_audience_hash"],
            f["accepted_epochs"],
            f["max_clock_skew"],
            [],
            now,
            **retired,
        )

    def _initialize(self):
        expect = _REPLAY["expect"]
        return self._signed(
            0,
            "initialize",
            {
                "capabilities": {},
                "clientInfo": expect["client_info"],
                "protocolVersion": expect["protocol_version"],
            },
        )

    def test_a_current_root_verifies_the_recorded_reply(self):
        signed, exchange = self._initialize()
        now = _REPLAY["created"]
        result = self._verify(mcp_re_sdk.verify_response, signed, exchange, now)
        self.assertEqual(result.outcome, "success")

    def test_a_retired_root_verifies_through_its_deadline_and_not_after(self):
        signed, exchange = self._initialize()
        now = _REPLAY["created"]
        verify = mcp_re_sdk.verify_response
        at = self._verify(verify, signed, exchange, now, issuer_retired_until=now)
        self.assertEqual(at.outcome, "success")
        with self.assertRaisesRegex(ValueError, "mcp-re.delegation_issuer_untrusted"):
            self._verify(verify, signed, exchange, now, issuer_retired_until=now - 1)

    def test_a_retired_root_acknowledges_a_notification_only_inside_its_window(self):
        signed, exchange = self._signed(1, "notifications/initialized", {})
        now = _REPLAY["created"]
        verify = mcp_re_sdk.verify_accepted_202
        self._verify(verify, signed, exchange, now, issuer_retired_until=now)
        with self.assertRaisesRegex(ValueError, "mcp-re.delegation_issuer_untrusted"):
            self._verify(verify, signed, exchange, now, issuer_retired_until=now - 1)

    def test_an_empty_identity_field_is_refused_by_name(self):
        signed, exchange = self._initialize()
        now = _REPLAY["created"]
        for field in ["key_id", "role", "trust_domain", "subject"]:
            for blank in ["", "  "]:
                with self.subTest(field=field, blank=blank):
                    with self.assertRaisesRegex(
                        ValueError, f"invalid issuer identity: issuer_{field} is empty"
                    ):
                        self._verify(
                            mcp_re_sdk.verify_response, signed, exchange, now, **{field: blank}
                        )
                    with self.assertRaisesRegex(
                        ValueError, f"invalid issuer identity: issuer_{field} is empty"
                    ):
                        self._verify(
                            mcp_re_sdk.verify_accepted_202, signed, exchange, now, **{field: blank}
                        )


if __name__ == "__main__":
    unittest.main()
