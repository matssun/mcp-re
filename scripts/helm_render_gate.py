#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Helm chart render gate — the fail-closed guards must actually refuse (CI gate).

`deploy/helm/mcp-re-proxy/templates/_helpers.tpl` carries the chart's security
guards: refuse a fleet on a node-local replay cache, refuse a plaintext Redis hop
carrying admitted nonces, refuse the shipped `did:example:` / `example.com` /
`epoch-1` placeholders, refuse a transport binding that cannot start, refuse an
admission ceiling of zero. Each is a `{{- fail ... }}` that runs at render time.

None of them had a test. A guard whose only proof is that someone read it is one
`{{- if }}` edit away from silently admitting, and the failure mode is quiet: the
chart renders, the pods start, and the property is gone. Worse, several of these
guards key on values Helm treats as FALSY (`0`, `""`), so an inverted condition
does not error — it omits a flag, and an omitted flag is the permissive default.

This gate renders the chart under a matrix of value sets and asserts, for each,
whether rendering must SUCCEED or must FAIL — and when it must fail, that the
refusal message names the value at fault. It also pins the rendered argv for the
cases where "renders successfully" is not the whole property: a flag that must be
present, and a flag that must be ABSENT; the pod-spec FIELDS that argv cannot
express (the apiserver token, the read-only root filesystem, the retention
volume); and three couplings the chart cannot check against itself, because a
chart can be flawless in isolation and still describe something the rest of the
system does not do — a `keySource` the image was never compiled for, a non-root
uid that lives only in the chart and not in the image, and a documented default
that is not the constant the proxy actually applies.

Requires the `helm` binary. Absence is a hard error, not a skip: a gate that
skips itself on the machine where it matters is the same defect it exists to
catch.

Run:  python3 scripts/helm_render_gate.py
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CHART = REPO / "deploy" / "helm" / "mcp-re-proxy"
DOCKERFILE = REPO / "deploy" / "docker" / "Dockerfile"

#: `keySource` value -> the cargo feature the binary needs to serve it. A mode the
#: chart accepts but the default image was not built with does not degrade: the CLI
#: arm behind `#[cfg(not(feature = ...))]` returns a KeyError at startup, so the pod
#: CrashLoopBackOffs after the operator has already provisioned a KMS key, an IAM
#: role and an OIDC provider. The chart validating a mode in detail is not the same
#: as the artifact being able to run it, and only this check couples the two.
KEY_SOURCE_FEATURES: dict[str, str] = {
    "gcpKms": "gcp_kms_keysource",
    "awsKms": "aws_kms_keysource",
}


def default_image_features() -> set[str]:
    """The feature set `ARG FEATURES=` bakes into the image the chart points at."""
    for line in DOCKERFILE.read_text(encoding="utf-8").splitlines():
        if line.startswith("ARG FEATURES="):
            return {f.strip() for f in line.split("=", 1)[1].split(",") if f.strip()}
    return set()


def check_image_declares_non_root() -> list[str]:
    """The proxy IMAGE must declare the same non-root uid the chart pins.

    Carried by the chart alone, the non-root posture is a property of one deployment
    description rather than of the artifact: `docker run`, a plain manifest, a kind
    side-load or a chart fork start the process that mounts the response-signing seed
    and the TLS private key as uid 0. `runAsNonRoot: true` also cannot act as an
    admission-time backstop unless the image declares a numeric uid for the kubelet
    to read. Equality with `runAsUser` is asserted too, because the material Secret is
    delivered 0440 owned by `fsGroup` and the proxy reads it through group membership
    — a drift between the two numbers is a pod that cannot read its own key.
    """
    text = DOCKERFILE.read_text(encoding="utf-8")
    stage, declared = None, {}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("FROM ") and " AS " in stripped:
            stage = stripped.rsplit(" AS ", 1)[1].strip()
        elif stripped.startswith("USER ") and stage:
            declared[stage] = stripped.split(None, 1)[1].strip()
    if "proxy" not in declared:
        return [f"{DOCKERFILE.name}: the `proxy` stage declares no USER, so the image "
                "that mounts the signing seed and the TLS key runs as uid 0"]
    uid = declared["proxy"].split(":")[0]
    if not uid.isdigit() or uid == "0":
        return [f"{DOCKERFILE.name}: the `proxy` stage runs as {declared['proxy']!r}; "
                "it must be a NUMERIC non-root uid for runAsNonRoot to admit against"]
    values = (CHART / "values.yaml").read_text(encoding="utf-8")
    for field in ("runAsUser", "runAsGroup", "fsGroup"):
        expected = [ln.split(":", 1)[1].strip() for ln in values.splitlines()
                    if ln.strip().startswith(f"{field}:")]
        if expected and expected[0] != uid:
            return [f"the image runs as uid {uid} but the chart pins {field}: "
                    f"{expected[0]} — the mounted key Secret would be unreadable"]
    return []


def check_documented_in_flight_default() -> list[str]:
    """The absent-flag in-flight ceiling the chart DOCUMENTS must be the code's.

    This number is what an operator sizes the boundary against, and the chart is
    where they read it. It had been stated three ways at once — `64` in values.yaml,
    "unbounded" in deployment.yaml, `256` in `ServerLimits::default()` — so two of
    the three files an operator consults were wrong about the control they configure,
    and the "unbounded" wording invited setting a ceiling to escape a fail-open
    default that does not exist. Nothing coupled the prose to the constant, so all
    three could be individually plausible.
    """
    limits = (REPO / "mcp-re-proxy" / "src" / "tls.rs").read_text(encoding="utf-8")
    actual = ""
    for line in limits.splitlines():
        stripped = line.strip()
        if stripped.startswith("max_in_flight_requests: Some("):
            actual = stripped.split("Some(", 1)[1].split(")", 1)[0]
            break
    if not actual:
        return ["mcp-re-proxy/src/tls.rs declares no `max_in_flight_requests: Some(N)`; "
                "the documented default can no longer be checked against the code"]
    problems = []
    # `_helpers.tpl` is the third place the number reaches an operator, and the only
    # one they hit while the render is refusing them.
    for name in ("values.yaml", "templates/deployment.yaml", "templates/_helpers.tpl"):
        raw = (CHART / name).read_text(encoding="utf-8")
        # Comment markers and line wrapping carry no meaning here, and the phrase
        # being asserted is long enough to straddle a wrap. Normalise both away so
        # the check reads the sentence rather than the layout.
        text = " ".join(raw.replace("#", " ").split())
        if "per-core ceiling" not in text:
            problems.append(f"{name} no longer explains the absent-flag ceiling at all")
        elif f"ceiling of {actual}" not in text:
            problems.append(f"{name} does not state the code's per-core ceiling of {actual}")
        if "UNBOUNDED" in text or "unbounded ceiling" in text:
            problems.append(f"{name} still calls the absent-flag default unbounded; "
                            f"the proxy applies {actual}")
    return problems


def check_image_serves_every_key_source() -> list[str]:
    """Every custody mode the chart's `keySource` comment offers must be compiled in."""
    problems: list[str] = []
    features = default_image_features()
    if not features:
        return [f"{DOCKERFILE.name}: no `ARG FEATURES=` line; cannot tell what the image serves"]
    values = (CHART / "values.yaml").read_text(encoding="utf-8")
    offered = [mode for mode in KEY_SOURCE_FEATURES if mode in values]
    if not offered:
        return ["values.yaml offers no KMS keySource; this check has stopped measuring anything"]
    for mode in offered:
        feature = KEY_SOURCE_FEATURES[mode]
        if feature not in features:
            problems.append(
                f"values.yaml offers keySource: {mode} but the default image is built "
                f"without `{feature}` — that install fails closed at startup"
            )
    return problems


# A values set that overrides every guard-tripping default, so the BASE render is
# expected to succeed. Each case below perturbs exactly one thing from here, which
# is what makes a failure attributable.
BASE = {
    "inner": {"httpUrls": ["http://inner-mcp.default.svc.cluster.local:8080/mcp"]},
    "identity": {
        "audience": "did:web:proxy.internal",
        "serverSigner": "did:web:proxy.internal",
        "serverKeyId": "server-key-1",
        "targetUri": "https://proxy.internal:8600/mcp",
        "trustDomain": "proxy.internal",
        "route": "",
        "delegatedTrustEpoch": "epoch-2026-07",
    },
}


def merged(*overlays: dict) -> dict:
    """BASE with `overlays` applied, one nesting level deep (all this chart needs)."""
    out = {key: (dict(value) if isinstance(value, dict) else value) for key, value in BASE.items()}
    for overlay in overlays:
        for key, value in overlay.items():
            if isinstance(value, dict) and isinstance(out.get(key), dict):
                out[key].update(value)
            else:
                out[key] = value
    return out


def render(values: dict) -> tuple[bool, str]:
    """Render the chart with `values`. Returns (succeeded, combined output)."""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
        json.dump(values, handle)  # JSON is valid YAML; avoids a yaml dependency
        path = handle.name
    try:
        proc = subprocess.run(
            ["helm", "template", "gate", str(CHART), "-f", path],
            capture_output=True,
            text=True,
        )
        return proc.returncode == 0, proc.stdout + proc.stderr
    finally:
        Path(path).unlink(missing_ok=True)


def container_args(output: str) -> list[str]:
    """The rendered container argv, read back off the manifest text.

    Deliberately textual rather than a YAML parse: the assertion is about the
    exact strings the chart emitted, and a parse would let a quoting change
    through unnoticed.
    """
    args: list[str] = []
    inside = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped == "args:":
            inside = True
            continue
        if inside:
            if stripped.startswith("- "):
                args.append(stripped[2:].strip().strip('"'))
            elif stripped and not stripped.startswith("#"):
                break
    return args


# (name, values, must_render, message_fragment_required_on_failure)
#
# `must_render=False` means the chart MUST refuse. The fragment is asserted so a
# guard cannot pass this gate by failing for an unrelated reason (a YAML typo
# elsewhere also makes `helm template` non-zero).
CASES: list[tuple[str, dict, bool, str]] = [
    ("base values render", merged(), True, ""),
    # --- inner plane ---
    (
        "no inner backend is refused",
        merged({"inner": {"httpUrls": []}}),
        False,
        "inner plane required",
    ),
    # --- fleet vs node-local replay ---
    (
        "fleet with no shared replay store is refused",
        merged({"replay": {"redisUrl": "", "durabilityTier": "redis-wait-quorum:2:2000"}}),
        False,
        "requires replay.redisUrl",
    ),
    (
        "fleet with a node-local durability tier is refused",
        merged({"replay": {"redisUrl": "rediss://r:6379", "durabilityTier": "redis-async"}}),
        False,
        "requires replay.durabilityTier",
    ),
    # --- plaintext Redis on the nonce / epoch hops ---
    (
        "plaintext replay redis is refused under fleet",
        merged({"replay": {"redisUrl": "redis://r:6379", "durabilityTier": "linearizable"}}),
        False,
        "replay.redisUrl is plaintext",
    ),
    (
        "plaintext trust-epoch redis is refused under fleet",
        merged({"revocation": {"tier": "push:60", "trustEpochRedisUrl": "redis://r:6379",
                               "trustEpochKey": "mcp-re:trust:epoch"}}),
        False,
        "trustEpochRedisUrl is plaintext",
    ),
    (
        "plaintext replay redis renders with the named opt-out",
        merged({"replay": {"redisUrl": "redis://r:6379", "durabilityTier": "linearizable",
                           "allowPlaintextRedis": True}},
               {"revocation": {"tier": "push:60", "trustEpochRedisUrl": "",
                               "trustEpochKey": "mcp-re:trust:epoch"}}),
        True,
        "",
    ),
    # --- shipped placeholders (one dispatch boundary per install) ---
    (
        "did:example: audience placeholder is refused",
        merged({"identity": {"audience": "did:example:server-1"}}),
        False,
        "did:example:",
    ),
    (
        "example.com trust-domain placeholder is refused",
        merged({"identity": {"trustDomain": "example.com"}}),
        False,
        "example.com placeholder",
    ),
    (
        "epoch-1 delegated-epoch placeholder is refused",
        merged({"identity": {"delegatedTrustEpoch": "epoch-1"}}),
        False,
        "epoch-1 placeholder",
    ),
    (
        "the shipped defaults render ONLY under allowExampleFixtures",
        merged({"identity": {"audience": "did:example:server-1",
                             "serverSigner": "did:example:server-1",
                             "trustDomain": "example.com",
                             "delegatedTrustEpoch": "epoch-1",
                             "allowExampleFixtures": True}}),
        True,
        "",
    ),
    (
        "empty targetUri is refused",
        merged({"identity": {"targetUri": ""}}),
        False,
        "identity.targetUri is required",
    ),
    # --- transport binding: only "" and exact can start ---
    ("transportBinding=none is refused", merged({"transportBinding": "none"}), False, "cannot start"),
    (
        "transportBinding=lb-assertion is refused",
        merged({"transportBinding": "lb-assertion"}),
        False,
        "cannot start",
    ),
    ("transportBinding=exact renders", merged({"transportBinding": "exact"}), True, ""),
    # --- key custody ---
    (
        "keySource=gcpKms with no keyVersion is refused",
        merged({"keySource": "gcpKms"}),
        False,
        "requires gcpKms.keyVersion",
    ),
    (
        "an unknown keySource is refused",
        merged({"keySource": "vault"}),
        False,
        "keySource must be",
    ),
    (
        "keySource=awsKms with no region is refused",
        merged({"keySource": "awsKms", "awsKms": {"keyId": "alias/k"}}),
        False,
        "requires awsKms.region",
    ),
    (
        "keySource=awsKms with no keyId is refused",
        merged({"keySource": "awsKms", "awsKms": {"region": "eu-north-1"}}),
        False,
        "requires awsKms.keyId",
    ),
    # The custody claim the chart exists to make is "no key material in the pod".
    # Under awsKms that holds only on the IRSA path, so the weaker one cannot be
    # reached by leaving a boolean at a convenient value.
    (
        "awsKms static credentials are refused unless deliberately accepted",
        merged({"keySource": "awsKms",
                "awsKms": {"region": "eu-north-1", "keyId": "alias/k",
                           "useWebIdentity": False,
                           "credentialsSecretName": "aws-creds"}}),
        False,
        "LONG-LIVED IAM key pair",
    ),
    (
        "accepted awsKms static credentials still need the Secret naming them",
        merged({"keySource": "awsKms",
                "awsKms": {"region": "eu-north-1", "keyId": "alias/k",
                           "useWebIdentity": False,
                           "allowStaticCredentials": True,
                           "credentialsSecretName": ""}}),
        False,
        "requires awsKms.credentialsSecretName",
    ),
    # Without the annotation EKS injects no AWS_ROLE_ARN and the proxy fails closed
    # at startup: a CrashLoop that says nothing about the missing annotation.
    (
        "awsKms IRSA without the role-arn annotation is refused",
        merged({"keySource": "awsKms",
                "awsKms": {"region": "eu-north-1", "keyId": "alias/k",
                           "useWebIdentity": True}}),
        False,
        "eks.amazonaws.com/role-arn",
    ),
    # --- admission ceilings (MCPRE-114) ---
    (
        "admission ceiling of 0 is refused, not read as unset",
        merged({"admission": {"maxInFlight": 0, "maxInFlightTotal": ""}}),
        False,
        "must be a positive integer",
    ),
    (
        "admission total of 0 is refused",
        merged({"admission": {"maxInFlight": "", "maxInFlightTotal": 0}}),
        False,
        "must be a positive integer",
    ),
    (
        "a non-numeric admission ceiling is refused",
        merged({"admission": {"maxInFlight": "many", "maxInFlightTotal": ""}}),
        False,
        "must be a positive integer",
    ),
    (
        "both admission ceilings set is refused (one would be discarded)",
        merged({"admission": {"maxInFlight": 32, "maxInFlightTotal": 256}}),
        False,
        "not both",
    ),
    # The drain invariant. The kubelet's clock starts at pod DELETION, so the preStop
    # delay is spent inside terminationGracePeriodSeconds; get it wrong and in-flight
    # requests are SIGKILLed with no signed response and no rejection evidence.
    (
        "preStop + proxy drain >= kubelet grace is refused",
        merged({"drainPreStopSeconds": 6, "proxyDrainGraceSeconds": 30,
                "drainGracePeriodSeconds": 30}),
        False,
        "SIGKILLs",
    ),
    (
        "a proxy drain below the 30s request deadline is refused",
        merged({"proxyDrainGraceSeconds": 10}),
        False,
        "request deadline",
    ),
    (
        "a drain budget that fits renders",
        merged({"drainPreStopSeconds": 6, "proxyDrainGraceSeconds": 30,
                "drainGracePeriodSeconds": 45}),
        True,
        "",
    ),
    # The connection-age bound is the only re-check of an established peer's
    # certificate against an expiry or a reloaded CRL.
    (
        "a disabled connection-age bound is refused",
        merged({"maxConnectionAgeSeconds": 0}),
        False,
        "keeps one connection open",
    ),
    (
        "a connection outliving the cert lifetime is refused",
        merged({"maxConnectionAgeSeconds": 7200, "maxClientCertLifetimeSeconds": 3600}),
        False,
        "outlive the certificate",
    ),
    (
        "a live revocation tier without a trust reload cadence is refused",
        merged({"revocation": {"tier": "live", "trustEpochRedisUrl": "", "trustEpochKey": "",
                               "trustReloadSeconds": ""}}),
        False,
        "trustReloadSeconds",
    ),
    (
        "an unknown auditSink is refused",
        merged({"auditSink": "syslog"}),
        False,
        "auditSink",
    ),
    (
        "an unknown verifiedContextCarrier is refused",
        merged({"verifiedContextCarrier": "yes"}),
        False,
        "verifiedContextCarrier",
    ),
    # --- ADR-MCPRE-053 §7 admission currency ---
    #
    # Distinct from the `admission:` in-flight ceiling above in every respect. The
    # naming collision is the reason these cases are explicit about which control
    # they exercise: an operator who set `admission.maxInFlightTotal` and believed
    # admission control was configured had configured a concurrency bound.
    (
        "an unknown admissionCurrency.mode is refused",
        merged({"admissionCurrency": {"mode": "on"}}),
        False,
        "admissionCurrency.mode",
    ),
    # A gate that looks enabled and verifies nothing is the worst of the three
    # states, so the trust anchor cannot be left out of a mode that checks.
    (
        "admission currency without an authority is refused",
        merged({"admissionCurrency": {"mode": "required"}}),
        False,
        "authorityKid",
    ),
    (
        "admission currency without the shared record is refused",
        merged({"admissionCurrency": {"mode": "required", "authorityKid": "adm-1",
                                      "authorityPubkey": "cHVia2V5"}}),
        False,
        "requires admissionCurrency.redisUrl",
    ),
    # This hop decides whether a caller is still admitted, so it gets the same
    # plaintext-Redis rule as the nonce and trust-epoch hops.
    (
        "plaintext admission-currency redis is refused under fleet",
        merged({"admissionCurrency": {"mode": "required", "authorityKid": "adm-1",
                                      "authorityPubkey": "cHVia2V5",
                                      "redisUrl": "redis://r:6379"}}),
        False,
        "admissionCurrency.redisUrl is plaintext",
    ),
    (
        "an unbounded degraded window is refused",
        merged({"admissionCurrency": {"mode": "optional", "authorityKid": "adm-1",
                                      "authorityPubkey": "cHVia2V5",
                                      "redisUrl": "rediss://r:6379",
                                      "allowDegraded": True, "degradedBoundSecs": 0}}),
        False,
        "degradedBoundSecs",
    ),
    # The half-configured state that reads as "admission control is on" to anyone
    # auditing the rendered args while nothing is enforced.
    (
        "admission-currency settings with mode off are refused, not silently ignored",
        merged({"admissionCurrency": {"mode": "", "authorityKid": "adm-1"}}),
        False,
        "mode is off",
    ),
    (
        "a fully configured admission currency renders",
        merged({"admissionCurrency": {"mode": "required", "authorityKid": "adm-1",
                                      "authorityPubkey": "cHVia2V5",
                                      "redisUrl": "rediss://r:6379"}}),
        True,
        "",
    ),
]

# (name, values, args that MUST appear as an adjacent pair, args that must NOT appear)
ARGV_CASES: list[tuple[str, dict, list[tuple[str, str]], list[str]]] = [
    (
        "unset admission ceilings omit both flags",
        merged(),
        [],
        ["--max-in-flight", "--max-in-flight-total"],
    ),
    (
        "maxInFlight renders the per-core flag only",
        merged({"admission": {"maxInFlight": 32, "maxInFlightTotal": ""}}),
        [("--max-in-flight", "32")],
        ["--max-in-flight-total"],
    ),
    (
        "maxInFlightTotal renders the fleet-wide flag only",
        merged({"admission": {"maxInFlight": "", "maxInFlightTotal": 256}}),
        [("--max-in-flight-total", "256")],
        ["--max-in-flight"],
    ),
    # ADR-MCPS-035: a chart-rendered pod must carry the per-request security record,
    # and the revocation flags the posture claims must actually be emitted.
    (
        "the audit sink and revocation bounds are rendered by default",
        merged(),
        [("--audit-sink", "stderr"), ("--max-connection-age-secs", "300"),
         ("--drain-grace-secs", "30")],
        ["--verified-context-carrier"],
    ),
    (
        "the trust reload cadence is rendered by default",
        merged(),
        [("--trust-reload-secs", "60")],
        [],
    ),
    (
        "clientCrl paths render the CRL flags",
        merged({"clientCrl": {"paths": ["/etc/mcp-re/client-crl.pem"], "reloadSeconds": 300}}),
        [("--client-crl", "/etc/mcp-re/client-crl.pem"),
         ("--client-crl-reload-secs", "300")],
        [],
    ),
    (
        "no CRL paths means no CRL flags at all",
        merged({"clientCrl": {"paths": [], "reloadSeconds": 300}}),
        [],
        ["--client-crl", "--client-crl-reload-secs"],
    ),
    (
        "the trusted verified-context carrier is opt-in and rendered when asked",
        merged({"verifiedContextCarrier": "trusted"}),
        [("--verified-context-carrier", "trusted")],
        [],
    ),
    (
        "gcpKms custody never passes a signing-key seed",
        merged({"keySource": "gcpKms",
                "gcpKms": {"keyVersion": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
                           "useMetadata": True, "endpoint": "", "tlsKeyVersion": "",
                           "accessTokenSecretName": ""}}),
        [("--key-source", "gcp-kms")],
        ["--signing-key-seed"],
    ),
    (
        "file custody does pass the signing-key seed",
        merged(),
        [("--key-source", "file")],
        [],
    ),
    (
        "delegated TLS custody omits the exported TLS key",
        merged({"keySource": "gcpKms",
                "gcpKms": {"keyVersion": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
                           "tlsKeyVersion": "projects/p/locations/l/keyRings/r/cryptoKeys/t/cryptoKeyVersions/1",
                           "useMetadata": True, "endpoint": "", "accessTokenSecretName": ""}}),
        [("--gcp-kms-tls-key-version",
          "projects/p/locations/l/keyRings/r/cryptoKeys/t/cryptoKeyVersions/1")],
        ["--tls-key"],
    ),
    # The awsKms twins of the three gcpKms cases above. The seed one is the reason
    # the "is this KMS custody" question moved into a helper: asked per-cloud, the
    # awsKms path would have kept mounting a seed the proxy never reads.
    (
        "awsKms IRSA custody renders the web-identity flag and no signing-key seed",
        merged({"keySource": "awsKms",
                "awsKms": {"region": "eu-north-1", "keyId": "alias/mcp-re",
                           "useWebIdentity": True},
                "serviceAccount": {"create": True, "name": "",
                                   "annotations": {"eks.amazonaws.com/role-arn":
                                                   "arn:aws:iam::455880745808:role/mcp-re"}}}),
        [("--key-source", "aws-kms"),
         ("--aws-kms-region", "eu-north-1"),
         ("--aws-kms-key-id", "alias/mcp-re"),
         "--aws-kms-use-web-identity"],
        ["--signing-key-seed"],
    ),
    (
        "awsKms delegated TLS omits the exported TLS key",
        merged({"keySource": "awsKms",
                "awsKms": {"region": "eu-north-1", "keyId": "alias/mcp-re",
                           "tlsKeyId": "alias/mcp-re-tls", "useWebIdentity": True},
                "serviceAccount": {"create": True, "name": "",
                                   "annotations": {"eks.amazonaws.com/role-arn":
                                                   "arn:aws:iam::455880745808:role/mcp-re"}}}),
        [("--aws-kms-tls-key-id", "alias/mcp-re-tls")],
        ["--tls-key"],
    ),
    (
        "accepted awsKms static credentials do NOT render the web-identity flag",
        merged({"keySource": "awsKms",
                "awsKms": {"region": "eu-north-1", "keyId": "alias/mcp-re",
                           "useWebIdentity": False,
                           "allowStaticCredentials": True,
                           "credentialsSecretName": "aws-creds"}}),
        [("--key-source", "aws-kms")],
        ["--aws-kms-use-web-identity", "--signing-key-seed"],
    ),
    # ADR-MCPRE-053 §7. "The guards refuse a bad config" is only half the property:
    # the chart previously rendered NO admission flag under any values at all, so
    # every chart-deployed fleet ran AdmissionKind::Off. The flag has to appear.
    (
        "no admissionCurrency means no admission flag at all",
        merged(),
        [],
        ["--admission", "--admission-authority-kid", "--admission-authority-pubkey",
         "--admission-redis-url", "--admission-allow-degraded",
         "--admission-degraded-bound-secs"],
    ),
    (
        "admission currency renders the mode and all three anchors",
        merged({"admissionCurrency": {"mode": "required", "authorityKid": "adm-1",
                                      "authorityPubkey": "cHVia2V5",
                                      "redisUrl": "rediss://r:6379"}}),
        [("--admission", "required"),
         ("--admission-authority-kid", "adm-1"),
         ("--admission-authority-pubkey", "cHVia2V5"),
         ("--admission-redis-url", "rediss://r:6379")],
        # Degraded serving is opt-in; leaving it unset must not render a bound that
        # would read as an authorised window.
        ["--admission-allow-degraded", "--admission-degraded-bound-secs"],
    ),
    (
        "a bounded degraded window renders both flags together",
        merged({"admissionCurrency": {"mode": "optional", "authorityKid": "adm-1",
                                      "authorityPubkey": "cHVia2V5",
                                      "redisUrl": "rediss://r:6379",
                                      "allowDegraded": True, "degradedBoundSecs": 30}}),
        [("--admission", "optional"),
         ("--admission-allow-degraded", "true"),
         ("--admission-degraded-bound-secs", "30")],
        [],
    ),
    # SCT-2 / SCT-3 retention. The flag is only half of it — with
    # readOnlyRootFilesystem set, a rendered path with no writable volume under it
    # is a proxy that fails on its first write.
    (
        "no retainedEvidence.dir means no retention flag",
        merged(),
        [],
        ["--retained-evidence-dir"],
    ),
    (
        "retainedEvidence.dir renders the retention flag",
        merged({"retainedEvidence": {"dir": "/var/lib/mcp-re/retained", "sizeLimit": "2Gi"}}),
        [("--retained-evidence-dir", "/var/lib/mcp-re/retained")],
        [],
    ),
]

# (name, values, YAML lines that MUST appear, YAML lines that must NOT appear)
#
# Pod-spec posture rather than argv: these are fields, not flags, so `container_args`
# cannot see them. Compared as whole stripped lines so indentation changes do not
# make a nested field pass for a top-level one.
MANIFEST_CASES: list[tuple[str, dict, list[str], list[str]]] = [
    # The pod holds the response-signing seed and the TLS private key and calls no
    # Kubernetes API. Asserted on BOTH objects: the ServiceAccount field is what a
    # reviewer reads, the pod-spec field is what still governs when an existing
    # account is reused with serviceAccount.create=false.
    (
        "the apiserver token is not automounted, on either object",
        merged(),
        ["automountServiceAccountToken: false"],
        [],
    ),
    (
        "the pod spec refuses the token even when the ServiceAccount is not created",
        merged({"serviceAccount": {"create": False, "name": "existing-sa"}}),
        ["automountServiceAccountToken: false"],
        ["kind: ServiceAccount"],
    ),
    # An attacker with code execution in the key-holding container is confined to
    # memory rather than able to stage tooling on the writable layer.
    (
        "the proxy container filesystem is read-only",
        merged(),
        ["readOnlyRootFilesystem: true"],
        [],
    ),
    (
        "retention gets the pod's only writable path, and it is bounded",
        merged({"retainedEvidence": {"dir": "/var/lib/mcp-re/retained", "sizeLimit": "2Gi"}}),
        ["readOnlyRootFilesystem: true", "- name: retained-evidence",
         "mountPath: \"/var/lib/mcp-re/retained\"", "emptyDir:", "sizeLimit: \"2Gi\""],
        [],
    ),
    (
        "no retention means no volume to write to",
        merged(),
        [],
        ["- name: retained-evidence", "emptyDir:"],
    ),
]


def main() -> int:
    if shutil.which("helm") is None:
        print("FAIL: helm not found on PATH; this gate cannot verify the chart guards")
        return 2
    if not CHART.is_dir():
        print(f"FAIL: chart not found at {CHART}")
        return 2

    failures: list[str] = []

    # Image-vs-chart couplings. Neither is visible in a render: the chart can be
    # perfect and the artifact still unable to run what it describes.
    for label, check in (
        ("the default image serves every offered keySource", check_image_serves_every_key_source),
        ("the proxy image declares the chart's non-root uid", check_image_declares_non_root),
        ("the documented in-flight default is the code's", check_documented_in_flight_default),
    ):
        problems = check()
        failures.extend(f"{label}: {p}" for p in problems)
        print(f"  {'FAIL' if problems else 'ok  '} {label}")

    for name, values, must_render, fragment in CASES:
        ok, output = render(values)
        problem = ""
        if must_render and not ok:
            problem = f"expected a successful render, got:\n{output.strip()[-600:]}"
        elif not must_render and ok:
            problem = "the chart RENDERED but the guard must refuse it"
        elif not must_render and fragment not in output:
            problem = (
                f"refused, but the message does not name the fault ({fragment!r} absent) — "
                f"it may be failing for an unrelated reason:\n{output.strip()[-400:]}"
            )
        if problem:
            failures.append(f"{name}: {problem}")
        print(f"  {'FAIL' if problem else 'ok  '} {name}")

    for name, values, required_pairs, forbidden in ARGV_CASES:
        ok, output = render(values)
        if not ok:
            failures.append(f"{name}: render failed:\n{output.strip()[-400:]}")
            print(f"  FAIL {name}")
            continue
        args = container_args(output)
        problems = []
        for required in required_pairs:
            # A bare string is a VALUELESS flag (`--gcp-kms-use-metadata`,
            # `--aws-kms-use-web-identity`): presence is the whole assertion, and
            # indexing +1 would read the next unrelated argument as its value.
            if isinstance(required, str):
                if required not in args:
                    problems.append(f"{required} missing")
                continue
            flag, value = required
            if flag not in args:
                problems.append(f"{flag} missing")
            elif args[args.index(flag) + 1] != value:
                problems.append(f"{flag} carries {args[args.index(flag) + 1]!r}, expected {value!r}")
        for flag in forbidden:
            if flag in args:
                problems.append(f"{flag} present but must be omitted")
        if problems:
            failures.append(f"{name}: " + "; ".join(problems))
        print(f"  {'FAIL' if problems else 'ok  '} {name}")

    for name, values, required_lines, forbidden_lines in MANIFEST_CASES:
        ok, output = render(values)
        if not ok:
            failures.append(f"{name}: render failed:\n{output.strip()[-400:]}")
            print(f"  FAIL {name}")
            continue
        # Comments are dropped: the assertion is about what the manifest DECLARES,
        # and every one of these fields is argued for in a comment right above it.
        lines = {
            line.strip() for line in output.splitlines()
            if line.strip() and not line.strip().startswith("#")
        }
        problems = [f"{line!r} missing" for line in required_lines if line not in lines]
        problems += [f"{line!r} present but must be absent" for line in forbidden_lines
                     if line in lines]
        if problems:
            failures.append(f"{name}: " + "; ".join(problems))
        print(f"  {'FAIL' if problems else 'ok  '} {name}")

    if failures:
        print("\nhelm render gate FAILED:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"\nhelm render gate: {3 + len(CASES) + len(ARGV_CASES) + len(MANIFEST_CASES)} cases pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
