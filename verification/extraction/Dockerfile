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
# Build and pin by digest — never by tag:
#
#   docker build --platform linux/arm64 -t mcp-re/extraction verification/extraction
#   docker inspect --format '{{index .RepoDigests 0}}' mcp-re/extraction
#
# Record image + digest in verification/policy/toolchains.lock.toml [extraction_container].
# Until that digest is recorded the Lean lane refuses to run, which is the mechanism, not
# an unfinished step.

FROM debian:bookworm-slim

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

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl git make m4 unzip \
        libgmp-dev pkg-config bubblewrap rsync opam \
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
# image too, so the toolchain must live here rather than on the host. elan resolves the
# exact toolchain from verification/lean/lean-toolchain at run time; that file does not
# exist yet, which is why [lean] is still unresolved in the lock file.
RUN curl -fsSL https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh \
        | sh -s -- -y --no-modify-path \
    && /root/.elan/bin/lean --version

ENV PATH=/root/.elan/bin:$PATH \
    CHARON_EXE=/opt/aeneas/charon/bin/charon \
    AENEAS_EXE=/opt/aeneas/bin/aeneas

WORKDIR /workspace
