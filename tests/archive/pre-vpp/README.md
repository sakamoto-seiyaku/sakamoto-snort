# Pre-VPP test and tool archive

Archived during SAKAMOTO-249 on 2026-09-13. The nested `tests/` and `dev/` paths
mirror the original repository-relative layout for historical interpretation.
File contents, including third-party licenses, are preserved; scripts are not
current entrypoints, are not executable by default and must not be run or wired
into current CMake/device workflows. Relative paths inside retain their old meaning.

Contents: former DX/vNext integration, device IP/diagnostics/telemetry tooling,
standalone traffic-generator dependencies, and their dedicated builders/resolver
helper. Standalone utility C/C++ here is not the removed Product daemon/model
and is not a product implementation reference.

The Android lifecycle migration harnesses still referenced by older checks remain
outside this archive, as explained in [integration routing](../../integration/README.md).
Current source-bound collectors and verifiers stay under `tests/device/` and
`tests/evidence/`; their dated IDs alone are not an archive criterion.
