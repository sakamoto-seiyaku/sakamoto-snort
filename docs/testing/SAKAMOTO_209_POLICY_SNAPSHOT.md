# SAKAMOTO-209 — one acquired policy snapshot and owner-private FlowEntry state

Acceptance: **PASS — 2026-09-08** for S209. Final same-source artifacts pass
**3,579 actual NFQUEUE packets**, 49 flow identities and 221 native publications:
Linux 1,861 packets / four processes and Pixel 1,718 packets / four generations.
Both workers use protected snapshots under continuous publication; all reader,
flow and completion checks pass, with no packet writer-lock acquisition and
no final resource residue.

## Implemented boundary

One native owner-side packet evaluation acquires one reader claim on the
immutable double bank. Network Gate, typed L4 and FlowEntry observation consume
that exact generation/revision/snapshot-hash identity. The claim is released
only after owner-local mutation finishes, including early-DROP/error returns.
Publication never restarts an already bound packet against a newer view.

The writer lock is restricted to control operations. The publisher validates
against the published bank, waits for the inactive bank's readers to finish,
copies its compiled successor, and atomically publishes its identity. Active
readers continue while the writer waits. The SC reader claim/validation and
reuse checks prevent a delayed claim from reading a bank being overwritten;
release orders all content reads before reuse. This retains the existing two
banks, sequence and reader counts; it introduces no RCU/QSBR mechanism.

The policy API handlers and bounded policy-publication CLI run without a worker
barrier. Control queries and stop retain their barrier/quiescence boundaries.
No publication scans, flushes, modifies or advances a worker's pool epoch.
FlowEntry no longer exposes a pool revision-publication API. Each packet brings
its acquired identity, and only its current worker invalidates a mismatched
decision. Same revision with a different hash is a mismatch, as is a changed
generation. Flow identity, first ORIG attribution and cumulative counters stay
intact. A previously acquired old snapshot may still complete its decision;
the next packet bound to a newer identity must invalidate that cache.

FlowEntry counters also remain in the current worker's pool; only bounded
control snapshots aggregate them. The flow mutation seam uses no atomic
counter update, mutex, spinlock or writer lock. Existing VPP synchronization,
reader-count atomics and coarse policy-diagnostic atomics are separate from
FlowEntry mutable state. No arbitrary-thread pool accessor is exported.
Legacy scalar policy inputs already compile typed banks; packet evaluation now
uses that same immutable compiled content throughout, while legacy status
activation flags remain diagnostic compatibility fields.

The 64-entry owner-local storage remains the S208 bounded seam. S221 table/pool
unification, timer/FlowEnd dynamic proof (S225/S227), protocol trackers, VPN
transport, and performance release gates are not claimed here.

## Final-source Linux evidence

`linux-g`: four fresh runtime processes, generations 20910–20913, **1,861 actual
NFQUEUE packets**, 16 observed flow identities and 109 publications. IPv4/IPv6
UDP and TCP each sustain both owners while 24 successor revisions are published.
Both workers observe 24 steady epochs in every case, with approximately 4.69
seconds of observed steady traffic. Largest consecutive steady acquisition gap
is 0.118118184 seconds; the registered functional stall bound is 8 seconds, not a
latency SLO.

Each case also holds one real owner-0 packet after Gate for 250 ms. During its
reader lifetime, the publisher commits a new bank and owner 1 acquires that new
bank. A second publication uses the same revision with a different hash and
waits before reusing the old bank. Independent timestamps prove that reuse
begins only after the old reader releases. Gate and L4 rule IDs, cache identity,
actual worker, original packet/buffer/obligation and final bank contents all
agree. The hold is an explicitly armed diagnostic, excluded from steady-flow
stall measurements.

The IPv4 UDP case additionally publishes a Gate DROP through the actual Rust
Product Core and generated VAPI client. Its real packet terminates before L4
and before FlowEntry allocation. All returned payload nonces are recovered
from forward and reverse raw captures and compared with the endpoint records.
All final pool/reader/completion ledgers close; socket inodes disappear, queues
rebind, hooks are removed and processes exit.

## Final-source Pixel evidence

`pixel-e`: generations **863–866**, Pixel 6a (`bluejay`), serial
`28201JEGR0XPAJ`, app UID 12632, Root profile, kernel
`6.1.134-android14-11-g66e758f7d0c0-ab13748739` (aarch64).
Linux uses `6.6.114.1-microsoft-standard-WSL2` (x86_64) in disposable user/network
namespaces. Both execute the default Product graph with W2 and four family lanes.

| Pixel case | Generation | Actual packets | Flow entries | Owner 0 / 1 steady epochs |
| --- | --- | --- | --- | --- |
| IPv4 UDP | 863 | 267 | 5 | 14 / 17 |
| IPv4 TCP | 864 | 602 | 8 | 13 / 13 |
| IPv6 UDP | 865 | 288 | 12 | 22 / 20 |
| IPv6 TCP | 866 | 561 | 8 | 18 / 18 |

The 33 entries include every real warm probe needed to select both workers;
none is omitted from counters or cleanup. Each case makes 27 fixture
publications (initial, two-bank overlap/same-revision hash change, and 24
continuous successors). The four startup publications bring native Pixel total
to 112. Linux has 108 fixture publications plus the Rust→VAPI Gate DROP (109).

Pixel steady acquisition spans approximately 7.76 seconds per worker; maximum
consecutive steady gap is 0.250522176 seconds. This modest test workload and
armed trace budget establish functional progress, not a throughput, power or
packet-latency release claim. The 500 ms held-packet diagnostic is reported
separately. Every held old packet completes with its original Gate/L4 identity,
while another worker uses the newly published bank. Final cache generation,
revision/hash, rule IDs, counters and raw forward/reverse nonce bytes agree.

One concrete Pixel generation-863 witness (native `CLOCK_MONOTONIC`, relative
to old token 40's acquisition) is:

| Event | Relative time | Snapshot / worker |
| --- | --- | --- |
| Old packet acquires bank 0 | 0 ms | generation 863 / revision 193 / hash 101; worker 0 |
| New publication completes | 155.296 ms | revision 194 / hash 202; bank 1 |
| Token 77 acquires new bank | 157.681 ms | revision 194 / hash 202; worker 1 |
| Old token 40 releases unchanged content | 501.753 ms | revision 193 / hash 101; worker 0 |
| Writer begins reusing bank 0 | 501.762 ms | revision 194 / hash 203 |

Exact events are in `pixel-e/g0-before-stop-vpp-stdout.log`. The verifier checks
all bank-reuse intervals, not only this example. `policy.worker.retired` counts
packets whose publication sequence changed before release; content and lifetime
are independently checked. All final readers, pending returns, frames, buffers
and obligations are zero. Both pools flush, recorded NFQUEUE socket inodes
disappear, kernel queues and product hooks are absent, and each runtime process
exits. Wi-Fi returns to its original value 1 after the final run.

## Supporting checks and failed witnesses

- Five CTest checks pass: L4 classifier, FlowEntry properties, FlowEntry source
  boundary, S209 snapshot boundary and S192 policy source contract. The S192
  historical Host-evidence graph runtime is explicitly skipped; it is not
  substituted for the real default-product runs.
- Clang ASan/UBSan passes the final FlowEntry properties with normal sanitizer
  options. GCC sanitizer direct runs were unstable (signal-handler recursion
  or SIGSEGV), while a debugger run exited normally. GCC results remain
  inconclusive and are not counted as passing evidence. Exact supporting
  records are under `host-checks/`.
- Seven independent cloned corruptions are rejected: released bank contents,
  cached generation, omitted Gate match, wrong L4 view, premature bank reuse,
  stale acquisition and a nonzero packet writer-lock count.
- The first implementation omitted the Gate matching loop during extraction.
  The independent oracle rejected real Linux/Pixel evidence because Gate
  always returned no match. The loop was restored; source contracts and the
  real Rust→VAPI Gate DROP now guard that regression. Sources A/B are not
  final acceptance artifacts.
- Initial collectors closed the CLI session with `quit` after every publish.
  Pinned VPP's `quit` command takes the default worker barrier, preventing the
  intended overlapping-reader proof. Collectors now keep the publication
  connection open; normal query/stop barriers remain in place. Earlier runs
  retain HOLD for that proof, even where packet conservation passed.
- Adjacent source ports at one Linux endpoint did not supply both local
  lane/owner relationships. Fixtures now select from real address/port tuples,
  retaining all warm probes. No assignment or pool is rewritten.
- The Windows adb bridge converts stdout LF to CRLF. Pixel collectors preserve
  raw warm stdout and normalize that transport newline only; raw kernel
  payloads remain independently checked.

## Source and artifacts

- Commit: `9c67175713baceb46cef015f3464893fa3d69950` with recorded dirty source snapshot.
- Source SHA-256: `d7bd2a525ccac318e25d5698d4ae55de0d68c45df886e08ec49ad06b0d4963a8`.
- Dirty diff SHA-256: `c1bf6620c348b488a143b8b54e229c5a97dbdfe2389008e7de6020e88f8af4da`.
- APK SHA-256: `6d08d65d0bcbe6d234407c922e5341fe0e98e5ace318d3cbd1e4022e6c155728`.
- VPP revision: `9258530f3804a152578ce11cc7c8a1e9eab88ed0`; API identity `product_core.api/1.0.0@76115fdc`.
- Android stage: `/tmp/sakamoto-s208-vpp-stage`, including the previously accepted 18-patch Android profile.

| Android native entry | SHA-256 |
| --- | --- |
| `libproduct_core_plugin.so` | `5708ad54780e092410c1643b6f1a89493f9d98fc74c611cb1b0b93d225798425` |
| `libsakamoto_product_core.so` | `3daa281f6952eb5438fa89f5caaf57b4120d077177b0b91852a4ad7c7a7d4336` |
| `libsakamoto_runtime_control.so` | `00ac497525f4949c2393bd13107ac5d0953dd51fbe16aee903a40b08363b16cc` |
| `libsvm.so` | `b091cff3dbb233d4b0973e899d7e8077dbcc530b1aecddea6186a7ad7aa7aa53` |
| `libvapiclient.so` | `d9ee9f04c97110c0f5d2470062e65c9360ad6e6575e7055db99351b0f5403ac9` |
| `libvlib.so` | `1224a8c38e8f396b753c162a39282cca0b963d0b29c095d9e5fcf3c130eeaf5e` |
| `libvlibapi.so` | `b650b403ce3c4d4c8616c117611e8410eb9b1361e627772634a24b0f4845e615` |
| `libvlibmemory.so` | `8170514a36baa3d78f0ac3037fbe935b742a61f3483c02d3e87f0bd602672e82` |
| `libvlibmemoryclient.so` | `f3464e9f97c03e2bb97bcff19eeea30b87f94f15a6ba787e98f43181003e9c97` |
| `libvnet.so` | `098428abd79a3ee88d2f2c122488546f0b7f4de4731b2c74ea6da3f289f58af0` |
| `libvpp_runtime.so` | `52f690bb5fda680ebafcd84061e2d93eb3b4c63ce41917483c642609872e97b7` |
| `libvppinfra.so` | `691d7a5273c7316ecc7456e3c04748facfcc8e1bd06add451d5206dfe6efe063` |

| Linux executable/control entry | SHA-256 |
| --- | --- |
| `bin/vpp` | `3f68cfab85ae1b49f1f016b6ab13ddb69dc8208dd9fb2d8a4098731bbe264485` |
| `lib/vpp_plugins/product_core_plugin.so` | `7d320bcbb5fee899bc8598fb2f3eb514b1ce6b757a864ff2fe8d935bf948ebb6` |
| `bin/sakamoto-product-core-host` | `aa8274431cbf601e987e2144089a5d894b264f2599a459c46dfedb67a2345fbe` |
| `control/libsakamoto_product_core.so` | `22de04ccd8acdf3ce5f19cb0c9ec990502638677453307c2ce65b4c7d39456a5` |
| `control/s230-policy` | `7f1b1a2b8e7e5bcd2b1eb339bbf03a46412de0a3381d77ce47a7c59638705d86` |

Build manifests: `build-output/s209-policy/linux-build-d/build.json` and `pixel-build-d/build.json`.

## Reproduction and evidence seal

From the repository root:

```sh
unshare --user --map-root-user --net python3 tests/device/s209-linux-policy.py --output build-output/s209-policy/linux-rerun --artifact build-output/product-vpp-host-s209-d --vppctl /tmp/sakamoto-s193-host-stage-current/source/build-root/install-vpp-native/vpp/bin/vppctl --policy-client build-output/s209-policy/linux-build-d/control/s230-policy
python3 tests/device/s209-pixel-policy.py --apk build-output/s209-policy/pixel-build-d/apk/sakamoto-runtime-debug.apk --output build-output/s209-policy/pixel-rerun
python3 tests/device/verify-s209-policy.py build-output/s209-policy/linux-g --build build-output/s209-policy/linux-build-d/build.json --platform linux
python3 tests/device/verify-s209-policy.py build-output/s209-policy/pixel-e --build build-output/s209-policy/pixel-build-d/build.json --platform pixel
python3 tests/evidence/test_s209_policy_negatives.py build-output/s209-policy/linux-g --build build-output/s209-policy/linux-build-d/build.json --output /tmp/s209-negative-fresh
python3 tests/host/s209-policy-snapshot-contract.py
```

The negative output path must be new. Collection commands and fixture source are
preserved in `evidence-tools-d/`. Linux collection needs its disposable
user/network namespace; Pixel collection uses only repo-local `./dev/adb` and
the installed artifact. The trace limit is bounded at 4096, configured before
ingress; its default remains 256. No injected packets count toward acceptance.
Current-source verification intentionally rejects these records after future
product changes; use the sealed source/tool copies for historical reproduction.

Evidence-tool manifest SHA-256: `a555b3f1ad4fd5f5626b2c60e6124d80fad35a80260bb93ec79a8dfa32b96a3c`.

| Record | SHA-256 |
| --- | --- |
| `linux-verification-g.json` | `266c081f92649b3d6f9ec50c81212c8dc1eac318ac5741a48679af6cb7ac2e0d` |
| `pixel-verification-e.json` | `307740c3e57d9d0c1a05360188adcd7059f83415a6593252a4b8cfc4366bb813` |
| `negative-c/results.json` | `6c2a11b0ad0bf0cc98128487b0ed3f3c13396cdc88d7ea04615cb092c45d48a6` |
| `host-checks/result.json` | `f7e886f83f278f9f8a208fffc087a1d6fc72d7fbffc80ab9b20f844406ff7981` |
| `linux-build-d/build.json` | `915142f6321653ab7eb003c291c7fb3ad1094ecb64f474591ba91fa0a939fdd3` |
| `pixel-build-d/build.json` | `939874a9df82ddd47eb238e5175558abbec792c661a537e105f8e99beb177544` |

| Core acceptance tool | SHA-256 |
| --- | --- |
| `tests/device/verify-s209-policy.py` | `6f7aadc2ece785aa204d8d90a10bcc0db69cb63c9d3ba17737bc9c3ad3e866df` |
| `tests/device/s209-policy-verify.py` | `d4e82e5961662ea5e96febd2cc827fec65b7915b7c78a67d85a50b187ae3fc17` |
| `tests/device/s208-flow-verify.py` | `9322ba395d3a3675641aa4be2ded1c7e6dfdb74bc3b15d5dfa31b8d2cc442e09` |
| `tests/host/s209-policy-snapshot-contract.py` | `d5aff8855949b71cc0ad752c4bf7f07d1c7c02fe97dbab9177ec54c54619e298` |
