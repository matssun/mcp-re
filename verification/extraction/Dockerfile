# SPDX-License-Identifier: Apache-2.0
#
# ADR-MCPRE-059 §19 — the extraction container.
#
# The Charon -> LLBC -> Aeneas -> Lean pipeline runs here and nowhere else. Charon is a
# rustc driver linking the private compiler crates; on aarch64-apple-darwin the `rustc-dev`
# component ships those crates as .rmeta only, with no .rlib for the crates Charon names,
# so it cannot link on the macOS host. On aarch64-unknown-linux-gnu the same component
# ships the .rlib files and Charon builds unmodified. We change the host, not the tool.
#
# Built and identified by `tools/verification/extraction-image`, which records the image's
# own content digest in `verification/policy/toolchains.lock.toml [extraction_container]`.
# Until an identity is recorded the Lean lane refuses to run, which is the mechanism, not
# an unfinished step. There is no registry in that path: see
# verification/reviews/rulings/extraction-artifact-storage-2026-09-09.md.

# Pinned by DIGEST, not by tag: `bookworm-slim` is a moving pointer and Debian rebuilds it,
# so a tag would let the base change under an unchanged definition digest.
# WHAT THIS DEFINITION STILL RESOLVES AT BUILD TIME, and therefore what the recorded
# ARTIFACT identity — not the declared inputs — is what pins:
#
#   * `apt-get install` package versions, from whatever the archive holds that day;
#   * the rustup installer at https://sh.rustup.rs, which moves;
#   * `opam install` library versions — and these BUILD THE AENEAS BINARY, so a different
#     `visitors` or `zarith` can produce a different extracted model from identical Rust.
#
# That is why `[extraction_container].artifact_digest` records the image that was actually
# built rather than deriving one from the pins: this definition is not reproducible, and
# saying so is the honest form. See
# verification/reviews/rulings/extraction-artifact-storage-2026-09-09.md.

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

# Charon's rust-toolchain and the Aeneas charon-pin. These are build arguments so the
# image records which pins it was built for; they must agree with the lock file.
ARG CHARON_COMMIT=340b1af4df92608d0911fc2ba26eef3fd3a30ab4
ARG AENEAS_COMMIT=daa85d7e89400fa978be83fedbc7e475a83f0889
ARG RUST_NIGHTLY=nightly-2026-06-01
ARG OCAML_VERSION=5.3.0

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    OPAMROOT=/opt/opam \
    PATH=/opt/cargo/bin:/opt/opam/default/bin:$PATH

# `python3` is here because the lane's own entry points are Python and they run INSIDE this
# image: `regenerate-lean` drives Charon and Aeneas, `verify-lean` drives lake and reads
# `#print axioms`. Without it the container answers `/usr/bin/env: 'python3': No such file
# or directory` — measured, on the first real run of the pipeline. It parses the toolchain
# lock with the standard library, so the requirement is `tomllib`, which is 3.11+; bookworm
# ships 3.11. It is an interpreter for the harness and never a prover: nothing it does
# decides a proof obligation.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl git make m4 unzip \
        libgmp-dev pkg-config bubblewrap rsync opam python3 \
    && rm -rf /var/lib/apt/lists/*

# Rust: the nightly Charon pins, with the compiler-internal components it links against.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --no-modify-path --default-toolchain "${RUST_NIGHTLY}" \
          --component rustc-dev,llvm-tools-preview,rust-src \
    && rustc --version && cargo --version

# OCaml for Aeneas. opam comes from apt; the pinned identity is the COMPILER version,
# which opam builds from source into the switch, not the opam client itself.
RUN opam init --bare --disable-sandboxing -y \
    && opam switch create default "${OCAML_VERSION}" \
    && eval "$(opam env)" \
    && opam install -y \
        calendar core_unix domainslib easy_logging menhir ocamlformat.0.27.0 \
        ocamlgraph odoc ppx_deriving ppx_deriving_yojson progress unionFind \
        visitors yojson zarith

# Aeneas, and Charon at the commit Aeneas' charon-pin names. The pair moves together: a
# Charon whose LLBC the pinned Aeneas does not claim to accept is not a valid combination.
# Charon must live at ./charon inside the Aeneas tree — that is where Aeneas' own
# check-charon-install.sh looks, and it verifies the commit matches charon-pin.
RUN git clone https://github.com/AeneasVerif/aeneas /opt/aeneas \
    && git -C /opt/aeneas checkout "${AENEAS_COMMIT}" \
    && test "$(tail -1 /opt/aeneas/charon-pin)" = "${CHARON_COMMIT}" \
    && git clone https://github.com/AeneasVerif/charon /opt/aeneas/charon \
    && git -C /opt/aeneas/charon checkout "${CHARON_COMMIT}"

# Charon's OCaml half (charon-ml) is what Aeneas links against, so its opam dependencies
# belong in the switch alongside the Aeneas ones. Both local package definitions must be
# named together: charon.opam depends on name_matcher_parser, which is a sibling package
# in this same repository rather than something opam can resolve from the registry.
RUN cd /opt/aeneas/charon && eval "$(opam env)" \
    && opam install -y --deps-only ./charon.opam ./name_matcher_parser.opam

# `make build` builds BOTH halves — the Rust driver (release) and charon-ml — and installs
# them into charon/bin, which is where Aeneas expects them. A bare `cargo build` produces
# only the Rust half and leaves the Aeneas build failing its charon check.
#
# Status is checked directly rather than through a pipeline: a pipeline reports its last
# stage, so a failed build can exit 0 and be baked into the image as a successful one.
#
# The cargo target directory for a rustc driver is many gigabytes and is dead weight once
# the binaries are in bin/. It is removed in the SAME layer as the build: deleting it in a
# later layer would leave the bytes in this one, and every layer is extracted on pull.
RUN cd /opt/aeneas/charon && eval "$(opam env)" && make build \
    && test -x /opt/aeneas/charon/bin/charon \
    && test -x /opt/aeneas/charon/bin/charon-driver \
    && rm -rf /opt/aeneas/charon/charon/target \
    && rm -rf "${CARGO_HOME}/registry" "${CARGO_HOME}/git"

RUN cd /opt/aeneas && eval "$(opam env)" && make \
    && test -x /opt/aeneas/bin/aeneas \
    && rm -rf /opt/aeneas/src/_build /opt/aeneas/tests/test_runner/_build \
    && opam clean -a -c -r --logs

# Lean, via elan. Step 6 of the authoritative loop (the Lean build/proofs) runs in this
# image too, so the toolchain must live here rather than on the host.
#
# `--default-toolchain none` is deliberate. elan's own default is whatever stable Lean it
# resolves at build time, and the 2026-08-30 measurement found exactly that: the image held
# v4.33.0 while [lean] pins v4.31.0, so the Lean half of the pipeline could not run at all
# and the lane was pinned to an image that could not honour the pin. The toolchain this
# image installs is the one the pinned Aeneas backend DECLARES, read out of the backend's
# own lean-toolchain and cross-checked against the build argument — if the two disagree the
# build fails here rather than producing an image whose Lean is not the pinned Lean.
ARG LEAN_TOOLCHAIN=leanprover/lean4:v4.31.0
# Pinned by COMMIT. `master` is a moving ref, so the installer could change between two
# builds of the same declared toolchain.
RUN curl -fsSL https://raw.githubusercontent.com/leanprover/elan/0e36a07b9bbcc5381fa6250df109f9a4f94d7bac/elan-init.sh \
        | sh -s -- -y --no-modify-path --default-toolchain none \
    && test "$(cat /opt/aeneas/backends/lean/lean-toolchain)" = "${LEAN_TOOLCHAIN}" \
    && /root/.elan/bin/elan toolchain install "${LEAN_TOOLCHAIN}" \
    && /root/.elan/bin/elan default "${LEAN_TOOLCHAIN}" \
    && /root/.elan/bin/lean --version

# The Aeneas Lean backend, BUILT. A generated model is proved against this library, so an
# image carrying its sources and no `.lake` build is an image in which nothing elaborates —
# the second half of what the 2026-08-30 measurement found. Its mathlib dependency is
# fetched from the cache where one exists for this toolchain; building it from source is
# the fallback rather than the plan, and either way the `.lake/build` directory must exist
# afterwards or the image is not usable and the build stops here.
ENV PATH=/root/.elan/bin:$PATH
RUN cd /opt/aeneas/backends/lean \
    && (lake exe cache get || echo "no mathlib cache for this package; building from source") \
    && lake build \
    && test -d /opt/aeneas/backends/lean/.lake/build

ENV \
    CHARON_EXE=/opt/aeneas/charon/bin/charon \
    AENEAS_EXE=/opt/aeneas/bin/aeneas

WORKDIR /workspace
