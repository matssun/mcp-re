# SPDX-License-Identifier: Apache-2.0
"""mcp-re-sdk is built by Bazel, and only by Bazel.

The package's native module is the PyO3 binding to mcp-re-client-core, and Bazel is the
Rust build authority, so a wheel comes from `bazel build //sdk/python:wheel`. A source
build through pip would need a second Rust build path; this backend refuses it, naming
the one that exists, rather than producing a package with no native core.
"""

_REFUSAL = (
    "mcp-re-sdk is built by Bazel: run `bazel build //sdk/python:wheel` and install the "
    "wheel it writes (scripts/prepare_python_matrix.sh does this for every pinned "
    "interpreter)."
)


def _refuse(*_args, **_kwargs):
    raise RuntimeError(_REFUSAL)


build_wheel = _refuse
build_sdist = _refuse
build_editable = _refuse


def get_requires_for_build_wheel(config_settings=None):
    return []


get_requires_for_build_sdist = get_requires_for_build_wheel
get_requires_for_build_editable = get_requires_for_build_wheel
