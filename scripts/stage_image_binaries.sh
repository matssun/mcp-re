#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Build the binaries the deploy images carry, with Bazel, for one Linux architecture, and
# stage them where the Dockerfiles copy them from:
#
#   scripts/stage_image_binaries.sh --arch amd64     # registry images (Cloud Build)
#   scripts/stage_image_binaries.sh --arch arm64     # the local kind fleet on Apple Silicon
#
# Output: deploy/docker/dist/<arch>/ (gitignored), holding
#   mcp-re-proxy            //mcp-re-proxy:mcp_re_proxy_deploy_bin — the shipped proxy
#   tls_load_harness_bench  //mcp-re-proxy:tls_load_harness_bench — the §7 SLO bench, which
#                           spawns the proxy above (MCP_RE_PROXY_CLI in Dockerfile.bench)
#
# The images compile nothing. A Dockerfile that built its own binary did so with whatever
# toolchain its base image carried, which is not the one MODULE.bazel pins and the one every
# test lane ran; this is what makes the image's binary the one that was built and tested.
# `-c opt`: an image is a release artifact, and the SLO bench measures a release build.
set -euo pipefail
cd "$(dirname "$0")/.."

ARCH=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --arch) ARCH="${2:?--arch needs amd64 or arm64}"; shift 2 ;;
    -h|--help) sed -n '3,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
case "$ARCH" in
  amd64) PLATFORM=//platforms:linux_x86_64 ;;
  arm64) PLATFORM=//platforms:linux_arm64 ;;
  *) echo "stage-image-binaries: --arch amd64|arm64 is required" >&2; exit 2 ;;
esac

OUT="deploy/docker/dist/$ARCH"
FLAGS=(-c opt "--platforms=$PLATFORM")
# <published name> <label>
ARTIFACTS=(
  "mcp-re-proxy //mcp-re-proxy:mcp_re_proxy_deploy_bin"
  "tls_load_harness_bench //mcp-re-proxy:tls_load_harness_bench"
)

labels=()
for a in "${ARTIFACTS[@]}"; do labels+=("${a#* }"); done
echo "stage-image-binaries: building ${labels[*]} for $PLATFORM"
bazel build "${FLAGS[@]}" "${labels[@]}"

rm -rf "$OUT"
mkdir -p "$OUT"
for a in "${ARTIFACTS[@]}"; do
  name="${a%% *}" label="${a#* }"
  # The configured output path, not bazel-bin: bazel-bin names whichever configuration
  # built last, which is not necessarily this one.
  file="$(bazel cquery "${FLAGS[@]}" --output=files "$label" 2>/dev/null | head -1)"
  [[ -f "$file" ]] || { echo "stage-image-binaries: $label produced no file" >&2; exit 1; }
  install -m 0755 "$file" "$OUT/$name"
done
echo "stage-image-binaries: staged $(ls "$OUT" | tr '\n' ' ')in $OUT"
