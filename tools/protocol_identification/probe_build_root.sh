#!/usr/bin/env bash

# Shared build-root canonicalization and containment helper for S61 protocol
# identification probes. Source this file from probe scripts; it intentionally
# defines functions only and performs no standalone probe work.

protocol_identification_probe_canonical_build_root() {
    local repo_root="${1:?repo_root is required}"
    local build_root_input="${2:?build_root_input is required}"

    python3 - "$repo_root" "$build_root_input" <<'PY'
import pathlib
import sys

repo_root = pathlib.Path(sys.argv[1]).resolve(strict=False)
repo_build_output_root = (repo_root / "build-output").resolve(strict=False)
build_root_input = sys.argv[2]
build_root = pathlib.Path(build_root_input).resolve(strict=False)

if build_root != repo_build_output_root and repo_build_output_root not in build_root.parents:
    print(
        f"unsafe probe build root outside repo build-output: "
        f"{build_root_input} (resolved to {build_root})",
        file=sys.stderr,
    )
    raise SystemExit(1)

print(build_root)
PY
}
