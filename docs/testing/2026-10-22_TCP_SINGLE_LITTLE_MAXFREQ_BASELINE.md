# Single TCP download: N1 little cores at maximum allowed frequency

Date: 2026-10-22. Status: complete; independent GPT-6.1 Spec and Standards reviews found zero findings.

## Scope and fixed configuration

This is the requested current-configuration baseline: three 20-second unprofiled
repeats on Pixel 6a, one real server-to-device TCP download, no echo/latency probe.
There is one packet owner. VPP main is pinned to CPU0, owner0 to CPU1, dedicated
VPN I/O to CPU2, and both download-helper main and receiver to CPU3. These CPUs
share the little cluster. IRQs, system services and background tasks retain their
normal placement; this is not a claim that all phone work ran on little cores.

Only policy0 minimum frequency was raised from 300000 to its existing maximum
1803000 kHz for each run. Maximum frequency and `sched_pixel` governor were
preserved. Policies4/6, thermal controls, IRQs and cpusets were unchanged. Each
run used an independent 120-second device watchdog, ready before the frequency
write; normal restoration completed after collector stop and before restoring
the original APK. No watchdog expired.

The frozen protocol is
`build-output/tcp-single-little-maxfreq-20261022-plan/protocol.json`, SHA256
`cb413732d763e8e0d0d47b2b45c36ff24fcf11908842276efe5d48eb36b2af31`.

Current Product settings: send ring65528 bytes, receive window32768, MTU10000,
MSS9940, 2048 native buffers of10240 bytes; default48 primary packet credits,
capture64, handoff/completion/reclaim64 and native owner return frame capacity256.
TCP batch/progress experiments are OFF. Source port31000 to
192.168.4.5:41723 was reused only after confirming its absence from TCP/TCP6,
including TIME_WAIT. A separate two-second live warmup proved helper UID2000 and
peer routing and was joined before each timed transfer. Each repeat used a fresh
ordinary VPN lifetime, with no credit or capture override.

The executed `collector_wrapper.py` calls the unchanged collector's `q.main`.
It asserts65528/48/64 from an existing CLI response before timing, with no
additional ADB query. Execution identities were frozen before the first window in
`build-output/tcp-single-little-maxfreq-20261022-plan/frozen-tool-identities.json`:

| Executed file in that directory | SHA256 |
| --- | --- |
| `driver.py` | `554d14e7e147bb6d9113c57190fa4b8c5e28a119918576948f032357e5306ade` |
| `frequency_guard.py` | `6932ac23b04fbd352d91edbd930607c24343ed3f2df2d2d718d414a39dcb2f86` |
| `collector_wrapper.py` | `5245f9fdfc327a7ca9ce0681fcc81cf11313942246da3dcc6d473089356da895` |

## Results

100% CPU means one fully occupied core. VPP CPU is the sum of its three threads;
the receiver is reported separately. Mbps uses client bytes and monotonic elapsed
time. VPP CPU percentages use the actual retained CPU monitor interval.

| Run | Download Mbit/s | Owner CPU1 % | I/O CPU2 % | Main CPU0 % | VPP total % | Receiver process % | Monitor coverage % |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 307.328 | 30.977 | 23.500 | 0.051 | 54.528 | 12.370 | 98.290 |
| 2 | 316.511 | 31.471 | 24.270 | 0.050 | 55.791 | 12.761 | 99.296 |
| 3 | 306.935 | 30.566 | 23.242 | 0.051 | 53.859 | 12.312 | 98.307 |

| Run | Client bytes | Transfer seconds | Observed VPP CPU seconds | Monitor seconds | Peak VPP RSS bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 768376636 | 20.001489268 | 10.72 | 19.659563446 | 106291200 |
| 2 | 791294304 | 20.000447805 | 11.08 | 19.859733611 | 106262528 |
| 3 | 767381884 | 20.001185557 | 10.59 | 19.662477102 | 106119168 |

VPP CPU intervals do not cover every byte of the transfer. The retained JSON's
CPU seconds/GiB values15.241/15.141/15.073 are stationary extrapolation estimates,
not exact matching-interval measurements. Receiver CPU comes from the helper's
own process accounting over the full transfer. Profiling was disabled for all
three runs; this baseline supplies no new flamegraphs or off-CPU attribution.

## Frequency, affinity and packet qualification

Each run retained nine lifecycle condition snapshots; all sampled policy0 current,
minimum and maximum frequencies were1803000 kHz, governor `sched_pixel`. Four
snapshots per run were wholly within the measured transfer. Their LITTLE sensor
ranges were43–45,45–46 and47–48°C respectively. Lifecycle sensor ranges were
42–46,45–52 and47–52°C. Sampler calls took2.256–3.336 seconds wall time; this is
collection latency, not measured sampler CPU or an overhead correction.

The bracketed cpu0 `time_in_state` counter deltas were2087/2083/2082 native counter
units at1803000 and zero at every other frequency. These brackets surround the
measurement and are not exact transfer boundaries. Residency and sampled settings
together qualify the requested frequency condition; no cycle or energy estimate
is inferred.

Actual VPP PID/TID observations match singleton masks and processor IDs0/1/2;
each VPP thread has eight condition observations per run. The helper PID from
`client.json` and its actual receiver TID each have five observations matching
singleton CPU3. The collector's legacy `client-affinity.txt` contains a spawned
`cat` status and is not used as proof of either actual helper thread's affinity.
The independent CPU sampler also reports each VPP role on its assigned CPU.

Before timing, existing CLI diagnostics verified native65528/48/64. Before/after
snapshots showed zero increments in credit/enqueue rejection, primary rejection,
completion deferral/retry, TUN policy/runtime drop/error/rejection, failed TUN
write and flow output rejection. Successful TUN writes were84027/86508/83702,
matching return packets and write attempts. Captured/submitted packets matched
76525/79035/76440. Native counters span the diagnostic brackets, not precisely the
client byte interval. Generation2559/2560/2561 stop records each show
pending/buffers/frames/obligations0 and tun_fd=-1; the runtime ended stopped.

## Interpretation

The observed baseline is306.9–316.5 Mbit/s and53.9–55.8% of one core for VPP,
with12.3–12.8% separately in the receiver. This establishes the requested current
configuration and placement at the verified maximum little-cluster frequency.
It does not isolate frequency's effect: historical dynamic-frequency N1 runs used
a different32KiB send ring. It also does not establish a bottleneck, a500Mbit/s
ceiling, a CPU improvement at equal throughput, energy savings, or whole-phone
CPU consumption. No additional layout, old-artifact arm or measurement was run.

## Artifact identity, evidence and restoration

- Product source closure SHA256:
  `98b2c06c0666044d151d61a3954b0eeab93fb27b8bddbec4954e417b377bb0a4`.
- APK: `build-output/tcp-send64-default-20261022/android/apk/sakamoto-runtime-debug.apk`,
  SHA256 `7105cbd896052e7d3ea1c8edfe5e00ad1d75a208425e9e7d5fed7aed5f3eff57`.
- Plugin SHA256 `c3b3406d637af2cb7dddf7fa8bdebce84605688826316967fd3cfd9a792406b7`.
- Frozen collector SHA256 `63881bc630f594da0d4c2252d1b7fcff4f9ae0d725f9569b4d24327402f1c531`;
  helper Android SHA256 `075e780dd4c5aa1de34d654ef8ec7cd698399c2112638662e5f4913b2ba53015`.
- Recompute numeric/frequency/TID audit with
  `python3 build-output/tcp-single-little-maxfreq-20261022/audit.py`;
  output `numeric-affinity-audit.json` alongside raw `campaign.json`, per-run
  collector results, CLI snapshots, CPU JSONL, condition JSONL and guard receipts.
- Final restoration:
  `build-output/tcp-single-little-maxfreq-20261022/restoration/result.json` PASS.
  Original APKcc329…9a1110, rules2b24…a450f, exact original worker preferences,
  CU_7WFb_5G WiFi and all original policy0/4/6 min/max/governors were verified.
  No VPP, runtime service, NFQUEUE hooks/rows, benchmark helper or profiler remains;
  the owned Host endpoint597074 exited and was verified gone.

No Product/native/collector/helper source change or build was made for this
baseline. Raw evidence remains local and gitignored; preserve it for replay.
S293 remains open and S308 remains Done. Publication receipts are retained in
`build-output/tcp-single-little-maxfreq-20261022/closeout.json`.
