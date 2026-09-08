# S245 / S246 Pixel evidence — 2026-09-07

## S245 result

**PASS for the registered single-owner UDP4 input boundary.** Five fresh-run
Pixel cells passed exact payload, event-order and resource-conservation checks.
This is interface evidence for S237, not product readiness.

| Cell | Evidence directory under `../evidence/` | App datagrams 1 / 2 / 3 |
| --- | --- | --- |
| Normal | `s245-s246-20260907-195540-mode0` | EXACT / EXACT / EXACT |
| 250 ms endpoint delay | `s245-s246-20260907-195657-mode1` | EXACT / EXACT / EXACT |
| Input packet-credit rejection | `s245-s246-20260907-195742-mode2` | EXACT / TIMEOUT / EXACT |
| Input pbuf allocation failure | `s245-s246-20260907-195829-mode3` | EXACT / TIMEOUT / EXACT |
| Rejection after pbuf allocation | `s245-s246-20260907-195954-mode4` | EXACT / TIMEOUT / EXACT |

All three app datagrams in each cell used one UDP socket, one HEV session and
owner generation 1 on VPP worker 1. Rejection was injected on datagram 2. Only
accepted datagrams reached the real endpoint. Policy remained ALLOW; a negative
input return meant rejected handoff, not a policy DROP or delivery result.

### Actual input timeline

| Point | Owner and storage responsibility |
| --- | --- |
| Input call enters | VPP owns the original boundary buffer. The experiment's shared UDP4 parser verifies its header/length. |
| Packet and pbuf admission | HEV reserves its packet/pbuf credits; failures unwind only acquired resources. |
| Input copy completes | The owner-local lwIP pool owns a distinct pbuf/payload. Its UDP frame may retain this storage across task steps. |
| Input call returns | The VPP pointer is no longer used by HEV. Successful submission does not mean endpoint delivery. |
| Adapter completion, then native free | VPP settles the handoff result and frees its own buffer. |
| Controlled native reuse | `vlib_buffer_alloc` returns the same index; the newly owned allocation is overwritten with `0xa5`, then freed. No freed allocation is written directly. |
| Actual socket send / reply | HEV's real task sends the copied payload. The endpoint echoes exact bytes, with 250 ms delay in the delayed cell. |
| Input pbuf release | HEV's UDP-frame cleanup releases its own pbuf and credit; it never frees the VPP input allocation. |

Each accepted packet crossed the input interface with one 42-byte copy (28-byte
IPv4/UDP header and 14-byte payload). Normal and delayed cells copied 126 input
bytes; each input-fault cell copied 84. Native input allocation/free totals were
6/6 including the three explicit reuse allocations. Input pbuf pool peak was
1; all pool objects, UDP frames and four credit categories balanced at stop.
The post-allocation rejection allocated and freed the additional pbuf before
copy/transport submission. Actual pool events, rather than the historical
optional performance counter's release-hook coverage, are the resource oracle.

### Artifact and provenance

- Device: Pixel 6a `28201JEGR0XPAJ`, Android 16
  `google/bluejay/bluejay:16/BP3A.250905.014/13873947:user/release-keys`, kernel
  `6.1.134-android14-11-g66e758f7d0c0-ab13748739`.
- S245 APK SHA-256:
  `075170678768f5ea521361328bd56e9459ce47160b0ebbb6654ae3cc22fdb3fd`.
- Source/artifact archive:
  `../work/s245-s246/artifacts/075170678768f5ea521361328bd56e9459ce47160b0ebbb6654ae3cc22fdb3fd/`.
  It includes the APK, full experimental HEV/plugin/app source, baseline file
  hashes, current artifact hashes, repository/VPP revisions and dirty diffs.
- VPP base: `9258530f3804a152578ce11cc7c8a1e9eab88ed0` with the recorded Android
  modifications. Compile headers/configuration match `vpp-android-configure-probe`.
  HEV/lwIP, the plugin, JNI and VPP executable were built this session. Pinned
  VPP shared-library dependencies were reused and independently hashed.
- HEV upstream lineage: `3911f79434d9a27c3ae4e6e07df5cefe2c3d5c70` plus the
  existing owner-context experimental modifications. `/tmp/hev-3911f79` is an
  unversioned patched fixture, not a clean Git revision; the archived exact
  source and per-file manifest are authoritative for this run.
- Modes 1–4 additionally read back the installed native hashes and matched
  the APK build. Mode 0 used the same APK installed by its recorded `install -r`.

### Scope and invalid startup attempts

The real app uses a narrow `10.200.0.0/24` VPN route. The existing C OI3 test
harness projects the destination to a real loopback UDP endpoint and uses the
Android socket broker. This proves the controlled bind/protect path, not physical
underlay switching or an unmodified public Internet destination. The harness
has staging copies before the instrumented VPP→lwIP boundary; the two interface
copies are not a total-copy count. The same small UDP4 parser is used on the
input and return seam; it is an experimental graph, not the full S237 product
parser/policy implementation. No POC source was imported into product code.

Two startup attempts reached no input seam and are retained as invalid runtime
setup evidence: `s245-s246-20260907-194818-mode0` lacked `api-segment` in a wrongly
selected lite executable; `s245-s246-20260907-195109-mode0` crashed during startup
with a mixed build/header/dependency selection. Rebuilding the complete entry
and plugin against the matching configured source resolved startup. Neither
attempt supplies packet-domain evidence. The passing runs all stopped through
the owner-local cleanup path and left no VPP process after service stop.

TCP, IPv6, W2, production capacity, performance, suspend timing and the complete
product Adapter lifecycle are outside these claims.

## S246 result

**PASS after correcting the experimental UDP receive error path.** Seven
registered output cases passed. S245's five cells plus these seven give twelve
accepted device runs. `evidence-summary.json` records the final verifier output
and retains the failed allocation-error run as HOLD.

| Cell | Evidence directory under `../evidence/` | App datagrams 1 / 2 / 3 |
| --- | --- | --- |
| Normal, final artifact regression | `s245-s246-20260907-201221-mode0` | EXACT / EXACT / EXACT |
| Return policy DROP | `s245-s246-20260907-200322-mode5` | EXACT / TIMEOUT / EXACT |
| Output VPP allocation failure, corrected | `s245-s246-20260907-200731-mode6` | EXACT / TIMEOUT / EXACT |
| Allocated output rejected before frame acceptance | `s245-s246-20260907-200816-mode7` | EXACT / TIMEOUT / EXACT |
| TUN completion failure | `s245-s246-20260907-200925-mode8` | EXACT / TIMEOUT / EXACT |
| Controlled noncontiguous pbuf chain | `s245-s246-20260907-201011-mode9` | EXACT / EXACT / EXACT |
| Controlled synchronous lwIP output during input | `s245-s246-20260907-201054-mode10` | EXACT / EXACT / EXACT |

### Actual output timeline and results

The real HEV UDP receive task copies the socket payload into an owner-pool pbuf
without header headroom. Pinned `udp_sendto_ctx` uses a second owner-pool pbuf
for the complete output packet in these cells. The netif callback borrows that
pbuf, enumerates its spans, and invokes the experimental borrowed-vector output
callback. VPP copies those spans into its own native buffer, fills the small
generation/owner/provenance/direction facts, and calls `vlib_put_frame_to_node`.
The callback then returns. Both lwIP pool allocations are freed and poisoned
before the independent VPP graph reads its buffer. The graph validates stored
bytes and metadata, applies its test policy, completes to the original TUN once
if allowed, and frees its native buffer.

| Case | Experimental callback result → actual lwIP result | Native-buffer final holder | Later action |
| --- | --- | --- | --- |
| Normal submission | `0` → `ERR_OK` (`0`) | Graph | TUN write once, then free |
| Return policy DROP | `0` → `ERR_OK` (`0`) | Graph | DROP; no TUN write or lwIP reentry |
| Output allocation failure | `-1` → `ERR_MEM` (`-1`) | No output allocation | Current datagram discarded; receive stays alive after correction |
| Pre-accept submission rejection | `-2` → `ERR_IF` (`-12`) | Callback | Free allocated native buffer exactly once; current datagram discarded |
| TUN write failure | `0` → `ERR_OK` (`0`) | Graph | Actual `write(-1, ...)` returns `-1` / `EBADF` (`9`); free once |

The rejection is an explicit experimental guard **before** native frame
acceptance, not a claim that `vlib_put_frame_to_node` exposes a reject return.
Neither downstream policy DROP nor TUN failure changes the already-returned
lwIP success. These concrete callback values are experiment evidence for S237;
they do not freeze a product C signature or error mapping.

The naturally occurring packets were single pbufs (`len=tot_len=42`). The chain
cell split the second real lwIP output into 23-byte and 19-byte segments backed
by distinct owner-pool objects. The former contiguous tail was overwritten
with `0xa5` during the callback, so a mistaken contiguous read could not pass
the exact-payload check. The borrowed chain was restored and its test-owned
tail freed by the lwIP-side test code. This is controlled chain evidence, not
a claim that this traffic naturally produced a chain. Output-pool peak rose
from 2 to 3; the additional object was reclaimed.

The synchronous cell invoked real `udp_sendto_ctx` within input call 2 with a
separately labelled `s245-sync` payload. It did not directly call or fabricate
the netif output callback. The controlled output was submitted, its pbuf freed,
the input returned, and only then did the native graph run. The test output
was consumed separately without TUN delivery; all three actual Direct replies
still reached the app. In this run the freed pbuf address was naturally reused
for the actual Direct reply before the first queued graph frame ran. Both
independent VPP buffers retained correct bytes; output-native peak was 2.

### F246-01 — output resource error disabled UDP receive

The retained run `s245-s246-20260907-200500-mode6` has app results
EXACT/TIMEOUT/TIMEOUT. The endpoint received and echoed all three datagrams,
but lwIP produced only two outputs. The second netif return propagated
`ERR_MEM` into `hev_socks5_session_udp_fwd_b`, which returned `-1`; the splice
loop retained `res_b=-1` and never called its receive half again. The third
reply stayed unread, generating repeated readable-socket wakes: 399 owner
steps, with a long sequence of zero task quanta. Resource cleanup still
balanced; that alone did **not** make this run pass.

The isolated HEV correction frees the consumed datagram's pbuf and returns
progress for `ERR_MEM`/`ERR_IF` from output submission, preserving the live UDP
receive path. Other error behavior is unchanged. Allocation-failure and
submission-rejection reruns each produced EXACT/TIMEOUT/EXACT in the same
session, zero consecutive zero-quanta steps, and balanced final resources.
This corrects the experimental implementation to the already-accepted
packet-only failure contract; it does not reopen the ownership/topology choice.

### S246 artifact and verification

Final APK SHA-256:
`8509cb58ed7ddcc89ce131586d5ce125fb33ebaa250050458d8d10b423b3b2de`.
Its full source/artifact archive is under `../work/s245-s246/artifacts/` with
that hash as the directory name. All final-artifact cells matched read-back
installed native hashes. The earlier DROP cell and retained failing cell used
APK `70cea7e602f6798a28cb44d13a580b01964c656ec97c56edc6506427303f5e0e`, also
archived. The final normal run verifies the normal path after the correction.

The verifier correlates pool **allocation intervals**, not raw addresses.
Its first synchronous-cell check incorrectly treated legitimate free/reallocate/
free at one address as two releases of one lifetime; that initial checker
result is preserved as `verification-address-only-checker.json`. The corrected
correlation verifies each allocation's unique free and its relation to callback
and graph execution. No device behavior or acceptance requirement was relaxed.
Deliberately duplicated frees, removed frees, and graph-before-callback-return
log mutations all fail the final checker. The original receive-path fault
also remains HOLD under that checker.

Every accepted cell completed owner-local stop with no pool, frame, credit or
native-buffer residue; post-service process snapshots contain no VPP process.
The final broker log records the SCM_RIGHTS duplicate close and broker stop.
The registered scope and S245's controlled-endpoint/product limitations apply
equally to S246.
