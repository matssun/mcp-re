#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Put the toolchain pinned in //rust-toolchain.toml on PATH, and refuse to run if
# it cannot be. SOURCE this, do not execute it — it edits PATH for the caller:
#
#   . "$(dirname "$0")/use_pinned_toolchain.sh"
#
# Why this exists: a `cargo` that is not a rustup shim silently ignores
# rust-toolchain.toml. On a box with Homebrew's `rust` formula installed
# alongside `rustup`, /opt/homebrew/bin/{cargo,rustc} are Homebrew's OWN
# binaries and shadow rustup on PATH, so `cargo build` locally used a different
# compiler than CI and Bazel (both pinned via rust-toolchain.toml / MODULE.bazel)
# without a word of warning. Codegen differs between compilers, so that silently
# invalidates any local build, benchmark, or "it passes for me" claim.
#
# The fix is deliberately repo-scoped: it prepends the rustup-resolved toolchain
# bin directory to PATH for THIS process tree only. It does not uninstall
# anything, does not edit the user's shell profile, and does not change the
# behaviour of any other project on the machine.

_mcpre_toolchain_die() {
  echo "toolchain gate: $*" >&2
  return 1
}

_mcpre_use_pinned_toolchain() {
  local root channel actual bindir
  # Walk UP from $PWD to find rust-toolchain.toml. Deliberately not derived from
  # the script's own path: `${BASH_SOURCE[0]}` does not exist in zsh, so sourcing
  # this from an interactive zsh (or any non-bash shell) silently resolved the
  # wrong directory. Callers cd to the repo root first, so $PWD is inside the tree.
  root="$PWD"
  while [ "$root" != "/" ] && [ ! -f "$root/rust-toolchain.toml" ]; do
    root="$(dirname "$root")"
  done
  [ -f "$root/rust-toolchain.toml" ] || {
    _mcpre_toolchain_die "no rust-toolchain.toml found at or above $PWD"; return 1; }

  # The pin is READ FROM rust-toolchain.toml, never restated here — one source of
  # truth, so bumping the pin needs no edit to this script.
  channel="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
    "$root/rust-toolchain.toml" | head -1)"
  [ -n "$channel" ] || { _mcpre_toolchain_die "no channel found in rust-toolchain.toml"; return 1; }

  if command -v rustup >/dev/null 2>&1; then
    # `rustup which` honours rust-toolchain.toml when run inside the repo, so this
    # resolves the pinned toolchain rather than whatever the default happens to be.
    bindir="$(cd "$root" && rustup which cargo 2>/dev/null)" && bindir="$(dirname "$bindir")"
    if [ -n "$bindir" ] && [ -x "$bindir/cargo" ]; then
      PATH="$bindir:$PATH"
      export PATH
    fi
  fi

  # Verify rather than assume: if the pin still is not what a bare `rustc` resolves
  # to, fail loudly. A gate that silently measured the wrong compiler is the exact
  # failure this script exists to prevent.
  actual="$(rustc --version 2>/dev/null)"
  case "$actual" in
    *"$channel"*) ;;
    *)
      _mcpre_toolchain_die "rust-toolchain.toml pins ${channel}, but \`rustc\` on PATH is:
    ${actual:-<none>}
  This build would NOT match CI or Bazel. Most likely cause: Homebrew's \`rust\`
  formula is installed alongside \`rustup\` and shadows it on PATH.
  Fix with either:
    rustup toolchain install ${channel}     # if the pinned toolchain is missing
    brew uninstall rust                      # drop the shadowing formula
  or put rustup's shims ahead of /opt/homebrew/bin in your PATH."
      return 1 ;;
  esac
  return 0
}

_mcpre_use_pinned_toolchain
