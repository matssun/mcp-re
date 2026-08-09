#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Move every surface that carries the product version, in one step.
#
#   scripts/bump_version.sh 0.15.0
#   scripts/bump_version.sh 0.15.0 --dry-run
#
# See docs/dev/version-bump.md for what moves, what deliberately does NOT (the SDKs, the
# Helm chart's own version), and the order around this step.
#
# WHY A SCRIPT: a bump touches ~16 files, and `VERSION` is the IMAGE TAG. An uneven bump
# is syntactically fine everywhere and only surfaces as ImagePullBackOff on a cluster that
# is already billing. scripts/deploy_image_tag_gate.py catches the drift; this avoids
# creating it.
set -euo pipefail
cd "$(dirname "$0")/.."

DRY=0
NEW=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY=1; shift ;;
    -h|--help) sed -n '3,12p' "$0"; exit 0 ;;
    *) NEW="$1"; shift ;;
  esac
done

[[ -n "$NEW" ]] || { echo "usage: scripts/bump_version.sh <new-version> [--dry-run]" >&2; exit 2; }
[[ "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || { echo "not a semver: '$NEW' (expected MAJOR.MINOR.PATCH)" >&2; exit 2; }

OLD="$(tr -d '[:space:]' < VERSION)"
[[ "$OLD" != "$NEW" ]] || { echo "VERSION is already $NEW" >&2; exit 2; }

# Refuse to go backwards. A bump that lowers the tag makes the registry's newest image
# unreachable by name while every manifest still validates.
if [[ "$(printf '%s\n%s\n' "$OLD" "$NEW" | sort -V | tail -1)" != "$NEW" ]]; then
  echo "refusing to move $OLD -> $NEW: not an increase" >&2; exit 2
fi

# A dirty tree makes the bump commit unreviewable — the version churn hides whatever else
# was in flight, and `git diff` after the fact cannot separate them.
if [[ $DRY -eq 0 && -n "$(git status --porcelain)" ]]; then
  echo "refusing to bump on a dirty tree; commit or stash first" >&2; exit 2
fi

echo "bump $OLD -> $NEW"

# The deploy surface is matched on `mcp-re-*:<old>` specifically rather than on a bare
# version string: these files also carry unrelated semvers (chart version, image digests,
# tool pins) that must not move.
mapfile -t TARGETED < <(grep -rlE "mcp-re-[a-z-]+:${OLD//./\\.}" \
  deploy docs/security tools 2>/dev/null | sort -u || true)

changed=()
stage() {  # stage <file> <sed-expression>
  local f="$1" expr="$2"
  [[ -f "$f" ]] || return 0
  grep -qE "${3:-.}" "$f" 2>/dev/null || true
  if [[ $DRY -eq 1 ]]; then
    if sed -E "$expr" "$f" | diff -q - "$f" >/dev/null; then return 0; fi
    changed+=("$f"); return 0
  fi
  local tmp; tmp="$(mktemp)"
  sed -E "$expr" "$f" > "$tmp"
  if ! diff -q "$tmp" "$f" >/dev/null; then mv "$tmp" "$f"; changed+=("$f"); else rm -f "$tmp"; fi
}

# 1. The canonical source.
[[ $DRY -eq 1 ]] || printf '%s\n' "$NEW" > VERSION
[[ $DRY -eq 1 ]] && changed+=("VERSION")

# 2. Rust workspace + every crate carrying a LITERAL version. Anchored to a line that
#    starts `version = "<old>"` so dependency pins on other crates are untouched.
for f in Cargo.toml */Cargo.toml; do
  stage "$f" "s/^version = \"${OLD//./\\.}\"\$/version = \"$NEW\"/"
done

# 3. The deploy/runbook surface: image tags only.
for f in "${TARGETED[@]}"; do
  stage "$f" "s/(mcp-re-[a-z-]+):${OLD//./\\.}/\\1:$NEW/g"
done

# 4. Helm appVersion — it NAMES THE IMAGE, so it tracks VERSION. The chart's own
#    `version:` is deliberately untouched: it is the chart's semver and moves only when
#    the templates change (docs/dev/version-bump.md).
stage deploy/helm/mcp-re-proxy/Chart.yaml "s/^appVersion: \"${OLD//./\\.}\"\$/appVersion: \"$NEW\"/"

# 5. The chart's image tag, which is written as a BARE `tag:` value rather than
#    `name:tag`, so the image-reference pattern above does not see it. It is nonetheless
#    the tag the fleet pulls: missing it deploys the previous image under a release that
#    claims to be the new one, and every file still validates.
stage deploy/helm/mcp-re-proxy/values.yaml "s/^([[:space:]]*tag:[[:space:]]*)\"${OLD//./\\.}\"\$/\\1\"$NEW\"/"

printf '\n%s file(s) %s:\n' "${#changed[@]}" "$([[ $DRY -eq 1 ]] && echo 'would change' || echo 'changed')"
printf '  %s\n' "${changed[@]}"

cat <<EOF

NOT changed, deliberately (docs/dev/version-bump.md):
  sdk/python/pyproject.toml, sdk/typescript/package.json — independent cadence
  deploy/helm/mcp-re-proxy/Chart.yaml \`version:\` — chart semver; bump only if templates changed

Next:
  1. write the CHANGELOG.md entry by hand
  2. scripts/local_gate.sh --with-kind
  2b. commit the MODULE.bazel.lock that stage 3 regenerates — it hashes every Cargo.toml,
      so a bump invalidates all of them, and Bazel rewrites it silently rather than failing
  3. gcloud builds submit --config deploy/cloudbuild/mcp-re-images.yaml .   (the tag does
     not exist in the registry until this runs)
EOF
