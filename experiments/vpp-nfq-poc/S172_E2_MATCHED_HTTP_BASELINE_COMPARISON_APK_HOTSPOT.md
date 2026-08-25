# S172 E2 matched HTTP baseline comparison APK hotspot (2026-08-25)

## Status

`CLOSED_AS_PREFLIGHT_RUNNER_AND_MATCHED_HTTP_BASELINE_FIX`.

This record now covers two S172 construction hotspots:

1. `VPN-F048`: comparison APK provenance. The HEV baseline arm needs
   `tun_poc_plugin.so`, while the canonical OI3 APK intentionally does not
   carry it.
2. `VPN-F049`: matched HTTP baseline shape. A duration-only stream probe was
   not a matched request-count baseline and exposed a multi-owner TCP
   admission-before-tombstone race.

Both are closed for the bounded S172 HTTP construction slice. The remaining
full E2 matrix is still open. The later 4-request foreground HTTP staircase
hotspot is tracked separately as S173 / `VPN-F050`; it has its own bounded
closure and must not be conflated with the S172 one-GET matched-baseline slice.

## Symptom

After S171 closed the Direct-vs-OI3 bounded TCP hotspot, the next E2 step needed
a matched Direct / existing HEV / OI3 baseline on the same device, endpoint and
traffic shape.  The available legacy HEV runner could not be treated as that
matched E2 arm because it targeted older public/fixture assumptions and older
`tun-poc` plugin packaging.

The current canonical OI3 APK was inspected and contains:

- `lib/arm64-v8a/libhev_external_driver_poc_plugin.so`
- `lib/arm64-v8a/hev_external_driver_poc_plugin.so`
- `lib/arm64-v8a/libhev-socks5-tunnel.so`

It does not contain either:

- `lib/arm64-v8a/libtun_poc_plugin.so`
- `lib/arm64-v8a/tun_poc_plugin.so`

Running the new S172 default preflight against that APK stops before ADB/device
work:

```text
preflight=apk
preflight=FAIL missing_any_apk_member=lib/arm64-v8a/libtun_poc_plugin.so lib/arm64-v8a/tun_poc_plugin.so reason=hev-baseline-tun-poc
```

Evidence:

- `evidence/s172-e2-http-baseline-sample-20260825/run-20260825-125021-144734.log`

## Root cause

`vpp-hev` is a legacy HEV/tun-poc baseline mode.  In
`android/vpn-lite/native/vpn_fd_probe.c`, `write_vpp_files()` defaults to
`tun_poc_plugin.so` for forward/tun-poc modes, including `vppMode=2`
(`vpp-hev`).  OI3 modes select `libhev_external_driver_poc_plugin.so` instead.
VPP startup uses `plugins { path <native-dir>; name-filter <plugin-name> }`, so
an APK can safely carry both plugins; each arm loads only its selected plugin.

The canonical OI3 artifact intentionally omitted `tun_poc` after earlier paired
regressions.  That is correct for canonical OI3 evidence, but insufficient for
a matched Direct/HEV/OI3 E2 comparison artifact.

Before S172, Java start-outcome provenance only marked owner-resolver
`vppMode=5` as requiring `tun_poc`; `vpp-hev` missing-plugin failures were
therefore easy to misread as generic startup failures.

## Correction

1. `SnortVpnService` now marks all tun-poc VPP modes `1..12`, including
   `vpp-hev`, as requiring
   `libtun_poc_plugin.so|tun_poc_plugin.so` in start-outcome provenance.
2. Added `scripts/android-run-s172-e2-http-baseline-sample.sh`.
   - It is explicitly scoped as a bounded matched HTTP baseline sample, not a
     full E2 verdict.
   - It uses the same app-side HTTP stream probe for all arms and records
     `latencyMsP50`, `latencyMsP95` and `latencyMsP99`.
   - It supports default arms `direct hev oi3`.
   - It preflights APK members before ADB/device work.
   - It requires OI3 plugin + owner-context HEV always, and requires
     `tun_poc` when the HEV arm is selected.
   - It drives explicit OI3 `multi-stop` cleanup and records cleanup pass/fail,
     process/resource snapshots, fixture count and artifact hashes.
3. Added `scripts/tests/test_verify_s172_e2_http_baseline_sample.py` to lock the
   runner scope, comparison APK preflight, shared HTTP probe shape, OI3 cleanup
   and `vpp-hev` tun-poc provenance requirement.

Static validation:

```text
bash -n scripts/android-run-s172-e2-http-baseline-sample.sh
python3 -m unittest discover -s scripts/tests -p 'test_verify_s172_e2_http_baseline_sample.py'
python3 -m unittest discover -s scripts/tests -p 'test_verify_vpn_lite_plugin_staging.py'
```

All passed.

## Follow-up hotspot: OI3 TCP tail/admission and duration-only baseline

The first comparison APK run proved Direct and HEV but left OI3 invalid:

- `evidence/s172-e2-http-baseline-sample-20260825/cells-20260825-130051-110628.csv`
- Direct: `1199/1199`, valid.
- HEV: `8/8`, valid after adding the Android SOCKS smoke server.
- OI3: app received HTTP bytes (`2/2`, `errors=0`) but cleanup included one
  `oi3_cleanup result=FAIL`.

The failure was not an endpoint, UID, permission, ADB or HEV issue. Logs showed
the successful OI3 HTTP response on TUN output, followed by a FIN-only
generation admitted before the completed TCP tuple tombstone was visible. The
fix closes owner-local multi admission at the start of `oi3_finish_for()` and
reopens it only after `oi3_rearm_tun_flow()` has published the
tombstone/wait-SYN state.

The next run showed the cleanup fix worked (`cleanup=4/0`) but the original
duration-only stream probe still produced an invalid OI3 sample:

- `evidence/s172-e2-http-baseline-sample-20260825/cells-20260825-131000-916301.csv`
- OI3: `requests=2 successes=1 errors=1`, `cleanup=4/0`.

The fixture had only one OI3 GET. The second request hashed to an owner that was
still occupied by the previous TCP flow, so the dispatcher correctly rejected it
as `owner-busy`. That made the S172 runner a throughput/capacity probe, not a
matched HTTP baseline. S172 now:

- parses `Content-Length` in the app HTTP stream probe and closes the socket as
  soon as the response body is complete;
- records `contentLengthCompletions`;
- supports `count`/`MAX_REQUESTS`;
- defaults `MAX_REQUESTS=1`;
- requires `contentLengthCompletions == successes`.

## Accepted S172 execution

The accepted bounded matched HTTP baseline run is:

- Run id: `20260825-131542-644207`
- CSV: `evidence/s172-e2-http-baseline-sample-20260825/cells-20260825-131542-644207.csv`
- Manifest:
  `evidence/s172-e2-http-baseline-sample-20260825/run-20260825-131542-644207-manifest.json`
- Validity:
  `evidence/s172-e2-http-baseline-sample-20260825/run-validity-20260825-131542-644207.txt`

Artifact hashes:

- APK:
  `67f16c3a045c0a786e49ecb1f99a7a6496080ea0761404447c04434617880a94`
- OI3 plugin:
  `96e0e9f4cbf61fa2216c2ecff2e0ed568a98f966f0ef3b9f647cc74c92381806`
- `tun_poc_plugin.so`:
  `4f5608a631215a622b60bb72026edb6a8743011ed2c7d5ede9e1243a3844b0cd`
- HEV owner-context library:
  `37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d`

Final S172 cells:

| arm | requests | successes | errors | contentLengthCompletions | p50 ms | cleanup | valid |
| --- | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| direct | 1 | 1 | 0 | 1 | 67 | 0/0 | 1 |
| hev | 1 | 1 | 0 | 1 | 15 | 0/0 | 1 |
| oi3 | 1 | 1 | 0 | 1 | 1333 | 5/0 | 1 |

`failureCount=0`.

## Correct next execution for full E2

Do not run the historical S125/S124 or public-endpoint HEV loops as the E2
matched baseline.

Build an explicit comparison APK that carries both:

- the current OI3 plugin selected by `VPP_POC_PLUGIN`
- a compatible Android arm64 `tun_poc_plugin.so` selected by
  `VPP_TUN_POC_PLUGIN`

Then run S172 against the WSL2 LAN fixture:

```bash
ARMS="direct hev oi3" \
HOST=192.168.4.5 \
DURATION_SECONDS=10 \
MAX_REQUESTS=1 \
REPEATS=1 \
./scripts/android-run-s172-e2-http-baseline-sample.sh
```

The S172 result is accepted only as the matched HTTP baseline construction
slice. Full E2 still requires the broader IPv4/IPv6 TCP/UDP/DNS, multi-owner,
screen-off/Doze, thermal, CPU/work/context-switch/wake, RSS/fd/thread and
packet-loss matrix from the campaign spec.

The later S173 staircase runs selected that separate OI3 capacity design and
closed the bounded 4-request Direct/HEV/OI3 HTTP staircase slice. Full E2 still
requires the broader campaign matrix above.
