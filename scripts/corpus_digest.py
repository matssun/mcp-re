#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Recompute the v0.8.0 draft-02 conformance-corpus pins from checked-in bytes.

A conformance pin must be reproducible from checked-in code and checked-in
corpus bytes alone. This script IS the definition of the corpus-list digest:
the normative value is whatever this script computes from the committed corpus,
not a value copied from a comment or an external tool.

Two pins are emitted:

  manifest_sha256
      SHA-256 over the exact bytes of
      ``mcp-re-core/tests/vectors/draft-02/manifest.json``. A convenience
      single-file pin for the corpus index.

  draft02_file_hash_list_digest
      SHA-256 over a deterministic file-hash list covering EVERY regular file
      in ``mcp-re-core/tests/vectors/draft-02`` (the manifest included). The list
      is built as follows:

        * walk the corpus directory recursively;
        * take every regular file;
        * sort by repository-relative path in byte/lexicographic order;
        * for each file compute SHA-256 over its exact bytes;
        * emit one LF-terminated line per file of the form
              ``<repo-relative-path>  sha256:<hex>\n``
          (two spaces between path and digest; the final line is LF-terminated
          too);
        * the digest is SHA-256 over the UTF-8 bytes of that full list.

Run from anywhere:

    python3 scripts/corpus_digest.py            # print the two pins
    python3 scripts/corpus_digest.py --list      # also print the per-file list
    python3 scripts/corpus_digest.py --check A B  # exit non-zero on mismatch

The script has no third-party dependencies; the Python standard library is
enough, so a reviewer can reproduce the pins from a fresh clone with nothing
but ``python3``.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

# Repository root is the parent of the scripts/ directory this file lives in.
REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = REPO_ROOT / "mcp-re-core" / "tests" / "vectors" / "draft-02"
MANIFEST = CORPUS_DIR / "manifest.json"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _corpus_files() -> list[Path]:
    """Every regular file under the corpus dir, sorted by repo-relative path."""
    files = [p for p in CORPUS_DIR.rglob("*") if p.is_file()]
    return sorted(files, key=lambda p: p.relative_to(REPO_ROOT).as_posix())


def file_hash_list() -> str:
    """The exact LF-terminated preimage the corpus-list digest is taken over."""
    lines = []
    for path in _corpus_files():
        rel = path.relative_to(REPO_ROOT).as_posix()
        digest = _sha256_hex(path.read_bytes())
        lines.append(f"{rel}  sha256:{digest}\n")
    return "".join(lines)


def compute() -> tuple[str, str]:
    manifest_sha256 = _sha256_hex(MANIFEST.read_bytes())
    list_digest = _sha256_hex(file_hash_list().encode("utf-8"))
    return manifest_sha256, list_digest


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--list",
        action="store_true",
        help="also print the per-file hash list the digest is computed over",
    )
    parser.add_argument(
        "--check",
        nargs=2,
        metavar=("MANIFEST_SHA256", "LIST_DIGEST"),
        help="compare the recomputed pins against these expected values; "
        "exit non-zero on any mismatch",
    )
    args = parser.parse_args(argv)

    if not MANIFEST.is_file():
        print(f"error: corpus not found at {CORPUS_DIR}", file=sys.stderr)
        return 2

    manifest_sha256, list_digest = compute()

    if args.list:
        sys.stdout.write(file_hash_list())
        print()

    print(f"manifest_sha256 = {manifest_sha256}")
    print(f"draft02_file_hash_list_digest = {list_digest}")

    if args.check:
        exp_manifest, exp_list = args.check
        ok = True
        if exp_manifest != manifest_sha256:
            print(
                f"MISMATCH manifest_sha256: expected {exp_manifest}",
                file=sys.stderr,
            )
            ok = False
        if exp_list != list_digest:
            print(
                f"MISMATCH draft02_file_hash_list_digest: expected {exp_list}",
                file=sys.stderr,
            )
            ok = False
        if not ok:
            return 1
        print("check: OK", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
