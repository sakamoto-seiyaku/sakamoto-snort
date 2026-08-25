# S139 A2-1 traffic adapter

This is a POC-only Android application. One Java implementation is packaged
as two APKs with distinct application IDs (`com.sakamoto.snort.poc.appa` and
`com.sakamoto.snort.poc.appb`), so Android assigns independent process UIDs.
It has no dependency on `app/android-runtime`, VpnLite, Gradle, or local
resources.

Build both APKs with the pinned local Lineage SDK prebuilts:

```sh
experiments/vpp-nfq-poc/android/a2-traffic-adapter/scripts/build-debug-apk.sh
```

Outputs:

```text
experiments/vpp-nfq-poc/android/a2-traffic-adapter/build/outputs/
  com-sakamoto-snort-poc-appa-debug.apk
  com-sakamoto-snort-poc-appb-debug.apk
```

The stable debug keystore is kept at
`build-output/a2-1-traffic-adapter-signing/debug.keystore`. Set
`PACKAGE_A`, `PACKAGE_B`, or `APPLICATION_ID` to choose other validated
application IDs; leaving `APPLICATION_ID` unset builds both defaults.

## Deterministic command

Start one package with the `EMIT` action (or pass `--ez a2Matrix true`) and
provide `ip4`/`ip6`, `tcp`/`udp`, and fixed ports.  A2-1 device evidence must
use the bounded WSL2/LAN fixture launched by
`android-run-s139-a2-1-two-app-matrix.sh`; public resolver addresses are not
valid UID-resolver oracles:

```sh
adb shell am start -a com.sakamoto.snort.a2traffic.EMIT \
  -n com.sakamoto.snort.poc.appa/com.sakamoto.snort.a2traffic.TrafficAdapterActivity \
  --es a2MatrixStageId A2-1-ip4-udp \
  --es a2MatrixFamily ip4 --es a2MatrixProtocol udp \
  --ei a2MatrixSourcePort 45624 \
  --es a2MatrixDestinationHost "$FIXTURE_HOST4" \
  --ei a2MatrixDestinationPort "$FIXTURE_UDP_PORT" \
  --ei a2MatrixRepeat 2
```

If omitted, the adapter retains its historical defaults; those defaults are
not accepted as controlled A2-1 evidence.  The S152 runner supplies fixture
hosts and ports explicitly.  For the historical A2-1/A2-2 matrix each repeat
closes and recreates the same source-port tuple; no ephemeral source-port
substitution is used. A2-5 stages (`A2-5-*`) are intentionally different: all repeats share
one bound UDP socket and its descriptor remains alive through the final
bounded observation delay. This gives the asynchronous Android owner resolver
a live, stable tuple to attribute before the admission ledger is evaluated.

For every operation the app discovers an active `TRANSPORT_VPN` network,
calls `Network.bindSocket` on the real TCP or UDP socket, attempts the fixed
tuple, and durably appends exactly one JSON object line to:

```text
/data/user/0/<package>/files/debug/a2-1-runtime.jsonl
```

The record includes the schema, cell/stage, package and process UID, family,
protocol, source/destination tuple, explicit bind result, VPN network handle,
local address, send/connect outcome, repeat index, socket-reuse mode, and a
monotonic timestamp.
A failed TCP connect is retained as a tuple attempt and is not an external
connect or reply claim.
