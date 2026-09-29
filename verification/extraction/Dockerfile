# SPDX-License-Identifier: Apache-2.0
#
# ADR-MCPRE-059 §19 — the extraction container.
#
# The Charon -> LLBC -> Aeneas -> Lean pipeline runs here and nowhere else. Charon's driver
# links the private compiler crates of one exact nightly, which is why the pipeline has a
# host of its own rather than running on a developer machine.
#
# THIS IMAGE BUILDS NEITHER TOOL. Aeneas and Charon enter it as upstream release binaries,
# each downloaded from the URL `verification/policy/toolchains.lock.toml` pins and refused
# unless its SHA-256 is the pinned one. The pair is the one Aeneas itself declares: the
# Aeneas commit's own `charon-pin` names the Charon commit, and the build checks that three
# ways below. `scripts/extraction_image_gate.py` holds this definition to that — every
# Aeneas/Charon artifact it installs is a pinned, digest-checked download, and it clones and
# builds neither.
#
# Built and identified by `tools/verification/extraction-image`, which records the image's
# own content digest in `verification/policy/toolchains.lock.toml [extraction_container]`.
# Until an identity is recorded the Lean lane refuses to run, which is the mechanism, not
# an unfinished step. There is no registry in that path: see
# verification/reviews/rulings/extraction-artifact-storage-2026-09-09.md.
#
# WHAT THIS DEFINITION STILL RESOLVES AT BUILD TIME, and therefore what the recorded
# ARTIFACT identity — not the declared inputs — is what pins:
#
#   * `apt-get install` package versions, from whatever the archive holds that day;
#   * the rustup installer at https://sh.rustup.rs, which moves;
#   * the mathlib cache `lake exe cache get` fetches for the pinned mathlib revision.
#
# That is why `[extraction_container].artifact_digest` records the image that was actually
# built rather than deriving one from the pins.

# Pinned by DIGEST, not by tag: `bookworm-slim` is a moving pointer and Debian rebuilds it,
# so a tag would let the base change under an unchanged definition digest.
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

# The pinned release artifacts. Build arguments so the image records which pins it was built
# for; `scripts/extraction_image_gate.py` requires each default to equal the lock.
ARG CHARON_COMMIT=b82d2748c1e5bfd9519cd9401f9186d33b44a7f1
ARG CHARON_URL=https://github.com/AeneasVerif/charon/releases/download/nightly-2026.09.04/charon-linux-aarch64.tar.gz
ARG CHARON_SHA256=ef0fc8a0c40e0b57e36ccca035f22a78ce2ad97acabc1bde8134b2314a3b0516
ARG CHARON_BIN_SHA256=3b718a8c223aaa5a09a610acf1b7b7d218c5775c5d4a8118b78a49ba13104cc0
ARG CHARON_DRIVER_SHA256=e1471969ab794c8b6676a8dc1dd836e55ff060cf40561b3ced13fe0c019ce1f9
ARG AENEAS_COMMIT=8d58d14ad655b3d871af1038c203c3f524ab4df9
ARG AENEAS_URL=https://github.com/AeneasVerif/aeneas/releases/download/nightly-2026.09.07-8d58d14/aeneas-linux-aarch64.tar.gz
ARG AENEAS_SHA256=d170dde7f25cb32604b376f6f74ae442c2e407d20353ce331a2fc269522f7967
ARG AENEAS_BIN_SHA256=493fbc8bba182a9d5386e220aef35577a3c3919526919c02a9629ca97e15f16e
ARG RUST_NIGHTLY=nightly-2026-08-18

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/rust-home \
    PATH=/opt/rust-home/bin:$PATH

# `python3` is here because the lane's own entry points are Python and they run INSIDE this
# image: `regenerate-lean` drives the Bazel extraction and Aeneas, `verify-lean` drives lake
# and reads `#print axioms`. It parses the toolchain lock with the standard library, so the
# requirement is `tomllib`, which is 3.11+; bookworm ships 3.11. `git` is lake's: it clones
# the Lean packages the Aeneas backend's manifest pins. `build-essential` is the C toolchain
# Bazel's Rust rules configure at analysis and link the dependencies' build scripts with.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl git python3 \
    && rm -rf /var/lib/apt/lists/*

# The rustc Charon's driver was built against. Nothing is compiled with it here: the driver
# loads `librustc_driver` from this exact nightly at run time, and the crates Charon reads are
# built on the same nightly by Bazel. Minimal profile, with the components Charon's own
# `rust-toolchain` names.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --no-modify-path --profile minimal --default-toolchain "${RUST_NIGHTLY}" \
          --component rustc-dev,llvm-tools,rust-src,miri \
    && rustc --version

# Charon: the pinned release, checked by archive digest and by the digest of each binary.
RUN curl -fsSL -o /tmp/charon.tar.gz "${CHARON_URL}" \
    && echo "${CHARON_SHA256}  /tmp/charon.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/charon/bin \
    && tar -xzf /tmp/charon.tar.gz -C /opt/charon/bin charon charon-driver rust-toolchain \
    && rm /tmp/charon.tar.gz \
    && echo "${CHARON_BIN_SHA256}  /opt/charon/bin/charon" | sha256sum -c - \
    && echo "${CHARON_DRIVER_SHA256}  /opt/charon/bin/charon-driver" | sha256sum -c - \
    && grep -q "channel = \"${RUST_NIGHTLY}\"" /opt/charon/bin/rust-toolchain

# Aeneas: the pinned release — the static `aeneas` binary and its Lean backend.
RUN curl -fsSL -o /tmp/aeneas.tar.gz "${AENEAS_URL}" \
    && echo "${AENEAS_SHA256}  /tmp/aeneas.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/aeneas/bin \
    && tar -xzf /tmp/aeneas.tar.gz -C /opt/aeneas \
    && rm /tmp/aeneas.tar.gz \
    && mv /opt/aeneas/aeneas /opt/aeneas/bin/aeneas \
    && echo "${AENEAS_BIN_SHA256}  /opt/aeneas/bin/aeneas" | sha256sum -c -

# THE PAIR IS AENEAS'S OWN, checked three ways, each able to fail the build:
#   1. the Aeneas commit's `charon-pin` names the pinned Charon commit;
#   2. the Charon binary states that commit itself;
#   3. the Charon binaries Aeneas ships in its own release are byte-identical to the pinned
#      Charon release's.
RUN test "$(curl -fsSL "https://raw.githubusercontent.com/AeneasVerif/aeneas/${AENEAS_COMMIT}/charon-pin" | tail -1)" = "${CHARON_COMMIT}" \
    && grep -qaF "${CHARON_COMMIT}" /opt/charon/bin/charon \
    && cmp /opt/aeneas/charon /opt/charon/bin/charon \
    && cmp /opt/aeneas/charon-driver /opt/charon/bin/charon-driver \
    && rm /opt/aeneas/charon /opt/aeneas/charon-driver

# Lean, via elan. The Lean build and proofs run in this image too, so the toolchain must
# live here rather than on the host. `--default-toolchain none`, and the toolchain installed
# is the one the pinned Aeneas backend DECLARES, cross-checked against the build argument.
ARG LEAN_TOOLCHAIN=leanprover/lean4:v4.31.0
# Pinned by COMMIT. `master` is a moving ref, so the installer could change between two
# builds of the same declared toolchain.
RUN curl -fsSL https://raw.githubusercontent.com/leanprover/elan/0e36a07b9bbcc5381fa6250df109f9a4f94d7bac/elan-init.sh \
        | sh -s -- -y --no-modify-path --default-toolchain none \
    && test "$(cat /opt/aeneas/backends/lean/lean-toolchain)" = "${LEAN_TOOLCHAIN}" \
    && /root/.elan/bin/elan toolchain install "${LEAN_TOOLCHAIN}" \
    && /root/.elan/bin/elan default "${LEAN_TOOLCHAIN}" \
    && /root/.elan/bin/lean --version

# The Aeneas Lean backend, BUILT. The release ships the backend's own `.lake/build`; its
# packages — mathlib and the rest the manifest pins — are fetched here, mathlib from its
# cache. A backend with no `.lake/build` is one nothing elaborates against, so the build
# stops here without it.
ENV PATH=/root/.elan/bin:$PATH
RUN cd /opt/aeneas/backends/lean \
    && (lake exe cache get || echo "no mathlib cache for this package; building from source") \
    && lake build \
    && test -d /opt/aeneas/backends/lean/.lake/build

ENV \
    CHARON_EXE=/opt/charon/bin/charon \
    AENEAS_EXE=/opt/aeneas/bin/aeneas

WORKDIR /workspace
