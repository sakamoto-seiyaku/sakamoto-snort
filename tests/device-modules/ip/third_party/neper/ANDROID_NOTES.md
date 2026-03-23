# neper on Android

This directory vendors `google/neper` (Apache-2.0) for the device-side IP test module.

## Local patches

- `logging.c`: provide a fallback `program_invocation_short_name` on non-glibc (Android/Bionic does not define it).
- `thread.c`: disable `--pin-cpu` on Android (Bionic does not provide `pthread_setaffinity_np`).

## Build

Use `dev/dev-build-iptest-neper.sh`, which cross-compiles `tcp_crr` and `udp_stream` for `aarch64-linux-android31` using the Lineage kernel NDK toolchain.
