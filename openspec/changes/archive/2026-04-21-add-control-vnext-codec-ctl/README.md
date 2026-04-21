# add-control-vnext-codec-ctl

Host-side vNext control codec + `sucre-snort-ctl` (Roadmap 3.2.1 Slice 1).

## Build (host)

From repo root:

```bash
cmake -S . -B build_host -DSNORT_ENABLE_DEVICE_TESTS=OFF
cmake --build build_host --target sucre-snort-ctl control_vnext_codec_tests control_vnext_ctl_roundtrip_tests
```

## Run P0 tests (host)

```bash
./build_host/tests/host/control_vnext_codec_tests
./build_host/tests/host/control_vnext_ctl_roundtrip_tests
```

## Use `sucre-snort-ctl`

```bash
./build_host/tests/host/sucre-snort-ctl --help
```

Notes:
- This slice does **not** introduce the vNext daemon listener yet. The next slice (`add-control-vnext-daemon-base`) wires vNext endpoints and implements the first command set on-device.
- The tool supports tcp/unix targets; once the daemon slice lands, the expected targets are:
  - unix: `/dev/socket/sucre-snort-control-vnext`
  - abstract: `@sucre-snort-control-vnext`
  - tcp: `127.0.0.1:60607` (when `inetControl()` is enabled)

