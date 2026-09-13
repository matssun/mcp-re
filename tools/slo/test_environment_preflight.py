"""Controls for the SLO environment identity and the exact idle-plane baseline.

Two propositions, and both are negative-first because both mechanisms fail OPEN if wrong:

  * a run in an environment that differs from the declared class must be REFUSED, so that
    no altered VM can silently inherit a previous PASS;
  * the lifecycle must inspect the DECLARED daemon, and no ambient Docker setting may
    redirect it.

The endpoint tests talk to the real `colima-slo` daemon because that is the proposition --
a fake endpoint would prove only that the code passes a string around. The identity tests
need nothing but the declaration.

Run:  /opt/homebrew/bin/python3 tools/slo/test_environment_preflight.py
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "scripts"))

import environment_preflight  # noqa: E402

REPO = Path(__file__).resolve().parent.parent.parent

PASSED: list[str] = []
FAILED: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    (PASSED if condition else FAILED).append(name)
    print(f"  {'ok  ' if condition else 'FAIL'} {name}" +
          (f"  [{detail}]" if detail and not condition else ""))


# ==========================================================================================
# the environment identity must refuse a materially different plane
# ==========================================================================================


def test_altered_environment_is_refused() -> None:
    print("\nan altered VM cannot pass as the declared class (§5)")
    entry = environment_preflight.declared_class()
    check("the declared runner class is dev1-slo-v1", entry["name"] == "dev1-slo-v1",
          entry["name"])

    live = environment_preflight.verify_environment(entry)
    check("the real plane verifies against its own declaration", live["verified"],
          str(live["mismatches"]))

    # Each field is varied ALONE, so a refusal cannot be attributed to the wrong cause and
    # a field that is silently unchecked cannot hide behind a sibling that is.
    for field, wrong in (("vm_cpus", 8), ("vm_memory_gib", 16),
                         ("docker_server_version", "28.0.0"),
                         ("redis_image_digest", "sha256:" + "0" * 64)):
        altered = copy.deepcopy(entry)
        altered["environment"][field] = wrong
        got = environment_preflight.verify_environment(altered)
        named = any(field in m for m in got["mismatches"])
        check(f"a differing {field} is refused, and NAMED in the refusal",
              (not got["verified"]) and named, str(got["mismatches"]))

    # An unreachable endpoint is INFRASTRUCTURE_UNAVAILABLE, not "verified" and not a
    # silent pass -- "I could not look" must never read as "it matched".
    absent = copy.deepcopy(entry)
    absent["environment"]["docker_endpoint"] = "unix:///nonexistent/docker.sock"
    got = environment_preflight.verify_environment(absent)
    check("an unreachable endpoint is not reachable and not verified",
          (not got["reachable"]) and (not got["verified"]))


def test_a_class_without_an_environment_is_refused() -> None:
    print("\na class that declares no environment cannot be measured under")
    legacy = environment_preflight.declared_class("dev1-macos-arm64")
    check("the retired predecessor is no longer the runner class",
          not legacy["github_actions_runner"])
    try:
        environment_preflight.declared_environment(legacy)
        check("a class with no [context.class.environment] is refused", False, "accepted")
    except SystemExit:
        check("a class with no [context.class.environment] is refused", True)


# ==========================================================================================
# ambient Docker state must not be able to redirect the lifecycle
# ==========================================================================================


def test_ambient_docker_cannot_redirect() -> None:
    print("\nno ambient Docker setting can redirect the lifecycle (§6)")
    entry = environment_preflight.declared_class()
    declared = environment_preflight.endpoint(entry)

    host_default = subprocess.run(["docker", "context", "show"],
                                  capture_output=True, text=True).stdout.strip()
    check("the user's default context is NOT the SLO endpoint",
          host_default != "colima-slo",
          f"default={host_default} — this test is vacuous if they coincide")

    # Point every ambient mechanism at the WRONG daemon, then confirm the preflight still
    # inspects the declared one. If the lifecycle read ambient state, this would silently
    # reconcile one daemon and measure on another.
    poisoned = dict(os.environ)
    poisoned["DOCKER_CONTEXT"] = "colima-db"
    poisoned["DOCKER_HOST"] = "unix:///Users/mats/.colima/db/docker.sock"
    got = subprocess.run(
        ["/opt/homebrew/bin/python3", str(Path(__file__).resolve().parent / "environment_preflight.py")],
        capture_output=True, text=True, env=poisoned, timeout=300)
    payload = json.loads(got.stdout) if got.stdout.strip().startswith("{") else {}
    used = (payload.get("environment") or {}).get("endpoint")
    check("with DOCKER_CONTEXT and DOCKER_HOST pointed elsewhere, the declared endpoint is used",
          used == declared, f"used={used} declared={declared}")
    check("and the plane it inspected is still the SLO plane's baseline",
          payload.get("at_baseline") is True, str(payload.get("plane"))[:160])

    # The positive half: the poisoned endpoint really is a DIFFERENT daemon with different
    # contents, so the control above is not passing because the two happen to look alike.
    other = environment_preflight.docker("unix:///Users/mats/.colima/db/docker.sock",
                                         "ps", "-a", "--format", "{{.Names}}")
    check("the daemon we were redirected toward genuinely differs",
          bool((other.stdout or "").strip()),
          "colima-db appears empty — the redirect control cannot distinguish the two")


# ==========================================================================================
# the exact baseline
# ==========================================================================================


def test_exact_baseline() -> None:
    print("\nthe idle plane is an EXACT baseline, not 'roughly empty' (§2)")
    entry = environment_preflight.declared_class()
    plane = environment_preflight.inspect_plane(entry)
    check("the plane is currently at its declared baseline", plane["at_baseline"],
          json.dumps({k: plane[k] for k in ("containers", "networks", "volumes",
                                            "unapproved_images")}, default=str)[:200])

    # The baseline ADMITS the pinned infrastructure image. A definition of "clean" as zero
    # images would condemn the warm image the class pins, and a run would re-pull it every
    # time -- turning a declared invariant into per-run network variance.
    check("the pinned infrastructure image is present and admitted",
          environment_preflight.declared_environment(entry)["redis_image"] in plane["images"]
          and not plane["unapproved_images"],
          f"images={plane['images']}")

    # ...and builtin networks are admitted, because the daemon creates them itself.
    host = environment_preflight.endpoint(entry)
    allnets = (environment_preflight.docker(host, "network", "ls", "--format", "{{.Name}}").stdout or "").split()
    check("docker's own networks exist and are not counted as contamination",
          set(allnets) & environment_preflight.BUILTIN_NETWORKS and not plane["networks"],
          f"all={allnets} counted={plane['networks']}")


def test_owned_versus_unknown_disposition() -> None:
    print("\nowned leftovers and unknown occupants are dispositioned differently (§2)")
    owned = {"id": "a", "name": "mcp-re-loadgen-redis-primary-x",
             "image": "redis:7-alpine", "labels": "com.mcp-re.slo=true,com.mcp-re.slo.run=R1"}
    unknown = {"id": "b", "name": "somebody-elses-thing", "image": "nginx", "labels": ""}
    got = environment_preflight.classify({"containers": [owned, unknown],
                                          "networks": [], "volumes": [],
                                          "unapproved_images": []})
    check("a labelled container is classified OWNED", got["owned_containers"] == [owned])
    check("an unlabelled container is classified UNKNOWN", got["unknown_containers"] == [unknown])
    check("they are never merged into one bucket",
          got["owned_containers"] != got["unknown_containers"])


# ==========================================================================================
# the environment must be part of the IDENTITY, not merely enforced
# ==========================================================================================


def write_surface(tmp: Path, environment: dict) -> Path:
    """A minimal declaration carrying one class, for digest experiments."""
    import tomllib
    real = tomllib.loads((REPO / "config" / "performance-surface.toml").read_text())
    lines = ['[[context.class]]', 'name = "probe-class"', 'kind = "probe"',
             'slo_declarable = false', 'regression_anchor = ""',
             'github_actions_runner = false', 'reason = "probe"', '',
             '[context.class.environment]']
    for k, v in environment.items():
        lines.append(f'{k} = {v!r}' if not isinstance(v, int) else f'{k} = {v}')
    path = tmp / "surface.toml"
    path.write_text("\n".join(lines) + "\n")
    return path


def digest_under(surface: Path, klass: str = "probe-class") -> str:
    import slo_evidence_identity
    original = slo_evidence_identity.SURFACE_TOML
    try:
        slo_evidence_identity.SURFACE_TOML = surface
        return slo_evidence_identity.class_environment_digest(klass)
    finally:
        slo_evidence_identity.SURFACE_TOML = original


def test_environment_is_part_of_the_identity() -> None:
    print("\nediting the environment under a stable class name MOVES the identity (§1)")
    import tempfile
    tmp = Path(tempfile.mkdtemp())

    base = {"docker_endpoint": "unix:///a.sock", "colima_profile": "slo",
            "vm_cpus": 4, "vm_memory_gib": 4, "vm_arch": "aarch64",
            "vm_storage": "internal", "docker_server_version": "29.2.1",
            "redis_image": "redis:7-alpine", "redis_image_digest": "sha256:" + "a" * 64}
    (tmp / "a").mkdir(exist_ok=True)
    d_base = digest_under(write_surface(tmp / "a", base))

    # THE control the correction asks for: same class name, exactly one invariant varied.
    for field, changed in (("vm_cpus", 8), ("vm_memory_gib", 8),
                           ("vm_storage", "external"),
                           ("redis_image_digest", "sha256:" + "b" * 64),
                           ("docker_server_version", "30.0.0")):
        (tmp / field).mkdir(exist_ok=True)
        altered = dict(base, **{field: changed})
        check(f"changing {field} alone moves the environment digest",
              digest_under(write_surface(tmp / field, altered)) != d_base)

    # ...and key ORDER must not. Reordering a TOML table is not an environment change, and
    # a digest sensitive to it would force spurious re-measurements forever.
    (tmp / "reordered").mkdir(exist_ok=True)
    reordered = {k: base[k] for k in reversed(list(base))}
    check("reordering the declaration does NOT move the digest",
          digest_under(write_surface(tmp / "reordered", reordered)) == d_base)

    # The individual fields must NOT have been copied into measurement_context -- the class
    # declaration stays the one authority and this is a witness derived from it.
    import slo_evidence_identity
    ctx = slo_evidence_identity.measurement_context()
    check("the context carries the derived witness",
          "hardware_class_environment_digest" in ctx)
    leaked = sorted(set(base) & set(ctx))
    check("and does NOT restate the individual environment fields", not leaked, str(leaked))


def test_previous_pass_is_not_reusable_after_an_environment_edit() -> None:
    print("\na PASS from environment A cannot be reused in environment B (§1)")
    import slo_evidence_identity
    live = slo_evidence_identity.measurement_context()
    before = slo_evidence_identity.context_digest(live)
    mutated = dict(live, hardware_class_environment_digest="sha256:" + "c" * 64)
    after = slo_evidence_identity.context_digest(mutated)
    check("the context digest depends on the environment witness", before != after)
    check("so the record PATH changes with it",
          slo_evidence_identity.record_path("sha256:" + "f" * 64, before)
          != slo_evidence_identity.record_path("sha256:" + "f" * 64, after))


def test_no_unaccounted_declared_fields() -> None:
    print("\nevery declared field is enforced, derived, or absent — no fourth category (§2)")
    entry = environment_preflight.declared_class()
    live = environment_preflight.verify_environment(entry)
    check("no declared field is unaccounted for", live["unaccounted"] == [],
          str(live["unaccounted"]))
    check("vm_storage is now mechanically established",
          live["observed"].get("vm_storage") in ("internal", "external"),
          str(live["observed"].get("vm_storage")))
    check("a differing vm_storage is refused",
          not environment_preflight.verify_environment(
              {**entry, "environment": {**entry["environment"], "vm_storage": "external"}})["verified"])
    check("redis_server_version is gone as an independent authority",
          "redis_server_version" not in entry["environment"])

    # The meta-control: an unenforced field must FAIL the preflight, not pass quietly.
    smuggled = copy.deepcopy(entry)
    smuggled["environment"]["some_new_claim"] = "unverified"
    got = environment_preflight.verify_environment(smuggled)
    check("adding an unenforced declared field FAILS the preflight",
          (not got["verified"]) and got["unaccounted"] == ["some_new_claim"],
          str(got["unaccounted"]))


def main() -> int:
    print("environment-preflight controls — talks to the real colima-slo daemon")
    for fn in (test_altered_environment_is_refused,
               test_a_class_without_an_environment_is_refused,
               test_ambient_docker_cannot_redirect,
               test_exact_baseline,
               test_owned_versus_unknown_disposition,
               test_environment_is_part_of_the_identity,
               test_previous_pass_is_not_reusable_after_an_environment_edit,
               test_no_unaccounted_declared_fields):
        fn()
    total = len(PASSED) + len(FAILED)
    print(f"\n{'=' * 74}\nexecuted {total} checks: {len(PASSED)} passed, {len(FAILED)} failed")
    for name in FAILED:
        print(f"  FAILED: {name}")
    return 0 if not FAILED else 1


if __name__ == "__main__":
    raise SystemExit(main())
