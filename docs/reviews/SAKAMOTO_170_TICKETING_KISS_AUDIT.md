# SAKAMOTO-170 Ticketing KISS Audit

Date: 2026-08-27
Scope: audit the proposed 30-ticket decomposition of SAKAMOTO-170. This note does not modify the parent spec, Plane, product code, or the accepted seven-slice architecture.

## Verdict

Do **not** publish the 30-ticket draft unchanged. Publish a **25-ticket** draft after user review.

The seven `Mainline Recovery Slice` groups and their architectural order remain correct:

```text
Product Spine
  -> Shared VPP Packet Kernel
       -> Root Foundation -----\
       -> VPN Foundation -------+-> VPP Foundation Closure
                                      -> Shared Policy/Control Foundation
                                           -> Mainline Recovery Closure
```

The defect is ticket shape, not architecture. The original #1--#4 split C plugin, APK packaging, Java lifecycle, and Rust control into horizontal language/build layers. Original Shared-Kernel #6--#8 similarly split one packet journey into parser, owner, and ledger layers. Original VPN #14 stopped at a graph-only UDP4 seam before #15 supplied the real Android path. Those tickets conflict with the `to-tickets` rule that a ticket must be a narrow but complete, independently verifiable tracer bullet that fits a fresh context.

KISS correction:

- Product Spine: **5 -> 3** tickets.
- Shared VPP Packet Kernel: **4 -> 2** tickets.
- VPN Foundation: **7 -> 6** tickets by merging graph-only UDP4 with the first real Android UDP4 path.
- Root, VPP Foundation Closure, Policy/Control, and final closure retain their small steps.
- Total: **30 -> 25** tickets. No new FGS, JNI, Cargo/NDK, packaging, telemetry, fragment-research, or test-only infrastructure ticket.

Claim boundary: the 25-ticket count is an audit recommendation derived from the repository's `to-tickets` workflow and SAKAMOTO-170 architecture. It is not an Android, Rust, VPP, or Netfilter platform requirement.

## Recommended 25-ticket graph

Every ticket below names an observable or executable capability. Detailed implementation checkpoints belong inside the ticket rather than becoming horizontal child tickets.

### A. Product Spine

| # | Ticket | Blocked by | Independently verifiable result |
|---|---|---|---|
| 1 | Run the Host Rust -> VAPI -> product C/VPP spine | None | The pinned product plugin loads without C++, Rust owns one serialized persistent VAPI session through a coarse non-unwinding ABI, and a typed query returns matching artifact/API/generation identity. |
| 2 | Start, query, and stop the same product VPP spine from the installed debug APK | 1 | Minimal Java debug controls start the packaged runtime from a legal foreground context, show status through Rust Product Core, survive Activity detach, and stop the generation cleanly on the real device. |
| 3 | Close Product Spine identity, failure, reconnect, and residue behavior | 2 | ABI/artifact/API mismatch, failed handshake, stale VAPI handle, Activity recreation, callback-free app stop, and fresh restart produce stable status and no old-generation process/socket/file/runtime residue. |

Why this is vertical: #1 proves the complete Host control seam instead of a C-only plugin; #2 proves the complete installed Android lifecycle instead of an APK-only or Java-only layer; #3 is a bounded failure journey with a visible recovery result. This preserves fresh-context size better than putting Host and Android packaging/lifecycle in one oversized ticket.

### B. Shared VPP Packet Kernel

| # | Ticket | Blocked by | Independently verifiable result |
|---|---|---|---|
| 4 | Complete one valid packet and its reverse through parser, canonical owner, and terminal ledger | 3 | Product VPP graph vectors cover IPv4/IPv6 TCP/UDP facts, direction-independent owner selection, local/remote Primary Distribution, origin return, and exactly one terminal settlement without copying packet bytes. |
| 5 | Close invalid, congestion, fragment, generation, and teardown paths without ownership debt | 4 | Invalid/unsupported packets, first/second owner mismatch, queue pressure, fragment success/failure, stale generation, and bounded teardown end with the specified disposition and zero buffer/credit/obligation debt. |

Why this is vertical: parser, owner, and ledger cannot be considered complete separately; the first useful result is an admitted packet reaching one terminal outcome. Fragment integration remains the already-selected VPP-native solution and is not a new POC.

### C. Root Foundation

| # | Ticket | Blocked by | Independently verifiable result |
|---|---|---|---|
| 6 | Run real IPv4 OUTPUT through one Root NFQUEUE lane | 5 | Installed product control starts Root, sends controlled-LAN IPv4 traffic through the shared graph, completes one origin-lane `ACCEPT`, observes the response, and stops cleanly. |
| 7 | Return verdicts across multiple exclusive Root lanes | 6 | Local and remote owner cases preserve original queue generation/packet ID, use no shared verdict socket, and settle each packet once under bounded credits. |
| 8 | Close the Root dual-stack TCP/UDP INPUT/OUTPUT matrix | 7 | Controlled-LAN IPv4/IPv6 TCP/UDP verifies nonce, tuple, bytes, response, status, counters, real app UID on OUTPUT, and explicit Unknown Application on INPUT when UID is unavailable. |
| 9 | Close Root fault, recovery, fail-open, and residue behavior | 8 | Missing listener/identity, queue pressure, verdict failure or ambiguity, stale/duplicate completion, crash, and supervised recovery preserve the defined attribution and leave no hook/queue/process/buffer/credit residue. |

### D. VPN Foundation

| # | Ticket | Blocked by | Independently verifiable result |
|---|---|---|---|
| 10 | Run real Android VPN UDP4 through TUN, VPP, and owner-local Flow Stack | 5 | Debug control performs authorization, foreground `VpnService`, TUN ownership transfer, protected/bound Direct socket setup, owner-local HEV/lwIP, controlled-LAN request/response, return through VPP/TUN, and clean stop. Host graph checkpoints are internal evidence, not a separate ticket. |
| 11 | Run VPN TCP4 Direct Egress | 10 | A real installed traffic source completes TCP4 request/response through the same owner, protected socket, and return path. |
| 12 | Run VPN UDP6 Direct Egress | 10 | A real installed traffic source completes IPv6 UDP request/response through the same provenance and settlement model. |
| 13 | Run VPN TCP6 Direct Egress | 11, 12 | The already-proven TCP and IPv6 capabilities meet in one real IPv6 TCP request/response. |
| 14 | Keep VPN flows generation-safe across a Wi-Fi network epoch | 13 | Wi-Fi off/on creates a new network epoch; new flows use the latest underlay while an old TCP flow is not silently migrated or reconnected. |
| 15 | Close VPN fault, revocation, recovery, and residue behavior | 14 | Authorization/TUN/protect/bind/capacity/Flow-Stack/stale/crash/revoke faults keep policy, completion, transport, and infrastructure facts distinct and leave no VPN slot/TUN/socket/flow/pbuf/callback/timer/buffer residue. |

Claim boundary: TCP4, UDP6, and TCP6 remain separate because they introduce two material capabilities--TCP transport and IPv6--and the final ticket composes both. They must deliver real product paths, not merely add a test matrix row. The graph-only UDP4 step is merged because it is not independently product-demoable.

### E. VPP Foundation Closure

| # | Ticket | Blocked by | Independently verifiable result |
|---|---|---|---|
| 16 | Close the Root -> VPN -> Root generation barrier | 9, 15 | Profile switches are serialized: quiesce, bounded drain, settle, close old resources, then start the replacement; at no point are two product runtimes accepted as active. |
| 17 | Fix worker/core placement and pass recovery engineering guardrails | 16 | Repeated short lifecycle runs prove fixed worker mapping/affinity plus pre-registered idle and representative-load CPU/latency trends, without inventing release SLOs. |

### F. Shared Policy/Control Foundation

| # | Ticket | Blocked by | Independently verifiable result |
|---|---|---|---|
| 18 | Publish and read back one empty immutable policy snapshot | 17 | Rust Product Core is the single writer; one complete revision is published transactionally through the persistent serialized VAPI session and queried as the active revision. |
| 19 | Control real Root traffic with one Network Gate rule | 18 | Minimal debug control persists, publishes, reads back, and applies one Gate rule; real controlled-LAN Root traffic proves block/open plus revision, winner, verdict, and reason. |
| 20 | Reuse the same Gate revision on VPN | 19 | The identical authoring revision and attribution control real VPN traffic without a second policy database or matcher. |
| 21 | Run one Root IPv4 TCP stateless L4 rule end to end | 20 | The first classifier rule crosses authoring, compile, publication, VPP evaluation, device traffic, and default `PASS_NEXT` restoration. |
| 22 | Close dual-stack TCP/UDP L4 parity and deterministic winner behavior | 21 | IPv4/IPv6 TCP/UDP cases prove Root/VPN parity and precedence `priority -> explicit order -> stable ID`. |
| 23 | Re-evaluate bounded `PASS_NEXT` FlowEntry state on revision change | 22 | Early drops allocate no FlowEntry; accepted flows use bounded owner-local state; a new revision invalidates cached decision state and the next packet observes the successor rule. |
| 24 | Fence outcome-unknown control mutations and reconcile by readback | 18 | Disconnect before/after submission and stale handle cases never auto-replay; dependent mutations remain fenced until a fresh handle reads active generation/revision and reconciles. |

Ticket #24 can run in parallel with #19--#23 after #18. Here `outcome-unknown mutation` is a control-operation result, not the per-packet Adapter Completion enum; ticket text must keep those namespaces explicit.

### G. Mainline Recovery Closure

| # | Ticket | Blocked by | Independently verifiable result |
|---|---|---|---|
| 25 | Audit and close the VPP-native Mainline Recovery Baseline | 23, 24 | Current-head evidence closes all seven Recovery Acceptance Cards, final controlled-LAN and Root -> VPN -> Root runs, provenance, and residue checks; unresolved gaps are classified explicitly and no retired C++ or POC PASS is credited as product completion. |

The initial executable frontier remains #1. Root #6 and VPN #10 become architecturally available after #5. The one-device laboratory schedules them serially without adding a false blocking relation.

## Mandatory acceptance constraints discovered by the audit

### 1. Native packaging and plugin startup (#1--#3)

- **Direct Android fact:** APK native libraries are ABI-specific and packaged under `lib/<abi>`; installation alone does not prove runtime load. The extraction choice also affects whether a library exists as an ordinary filesystem path. Sources: [Android ABIs](https://developer.android.com/ndk/guides/abis), [`extractNativeLibs`](https://developer.android.com/guide/topics/manifest/application-element#extractNativeLibs), and [Gradle external native builds](https://developer.android.com/studio/projects/gradle-external-native-builds).
- **Audit requirement:** use one packaging route for each artifact, verify device ABI plus direct and transitive native dependency closure, and prove the actual library/executable and product plugin load from the installed APK rather than from a build-tree path. A successful APK install, archive listing, or Host load is not this evidence. Do not package the same output through both a CMake target and a duplicate `jniLibs` entry.
- **Direct VPP fact:** plugin registration is discovered by the VPP loader; VPP plugin guidance recommends avoiding eager dynamic structures and process work merely because the plugin was loaded. Sources: [VPP plugins](https://docs.fd.io/vpp/26.02/developer/plugins/index.html) and [Adding a plugin](https://docs.fd.io/vpp/22.06.1/developer/plugindoc/add_plugin.html).
- **Audit requirement:** #1 identity/query must not accidentally start packet lanes or allocate the full dataplane. Packet resources are created only when the selected runtime profile is configured.

### 2. Android foreground lifecycle (#2, #3, #10, #15)

- **Direct Android fact:** Android 12+ restricts background foreground-service starts; target SDK 34+ requires a declared service type and its permission, and runtime promotion must use a type declared in the manifest. `systemExempted` VPN eligibility is conditional, not a generic pre-VPN exemption. Sources: [launching a foreground service](https://developer.android.com/develop/background-work/services/fgs/launch) and [foreground-service types](https://developer.android.com/develop/background-work/services/fgs/service-types).
- **Audit requirement:** start the recovery runtime from an explicit visible debug-Activity action, select a target-SDK-valid type/permission, promote within the platform deadline, prove Activity detach does not stop protection, and treat notification/runtime readiness truthfully. Exact Play-facing notification policy remains outside recovery.
- **Direct Android fact:** Android 13+ Task Manager stop removes the whole app and sends no callback; the official test uses `adb shell cmd activity stop-app PACKAGE_NAME`. Source: [user-initiated FGS stop](https://developer.android.com/develop/background-work/services/fgs/handle-user-stopping).
- **Audit requirement:** #3 must prove fresh restart and core residue cleanup without relying on `onDestroy()`. #9 and #15 repeat the same condition for Root hook/queue and VPN/TUN/Flow-Stack resources. Repository execution must use `./dev/adb`.

### 3. Rust/C ABI and VAPI ownership (#1, #3, #18, #24)

- **Direct Rust fact:** the Android ARM64 target is supported for cross-compilation but host build success is not device execution evidence. Default Rust layout is not a stable C ABI; FFI structures require an explicit representation, and unwinding behavior depends on the ABI. Sources: [Rust Android targets](https://doc.rust-lang.org/rustc/platform-support/android.html), [Rust type layout](https://doc.rust-lang.org/reference/type-layout.html), [function ABI and unwind](https://doc.rust-lang.org/reference/items/functions.html#unwinding), and [panic behavior](https://doc.rust-lang.org/reference/panic.html).
- **Audit requirement:** keep the boundary coarse and non-unwinding. ABI structs use `#[repr(C)]` and fixed-width fields; opaque handles, pointer-plus-length buffers, explicit release, and stable integer status/tag fields cross the seam. An integer tag is decoded with an explicit unknown case (or rejected as an unsupported ABI payload) before it becomes a Rust domain enum; a raw C value must never be materialized as a Rust fieldless enum that assumes only known discriminants. Do not expose Rust `String`, references, default-layout structs/enums, Android objects, packet bytes, or VPP buffers. Expected errors return values rather than panic. The selected panic containment/abort behavior must be explicit and tested.
- **Direct VPP fact:** generated VAPI provides request/reply matching and blocking/non-blocking modes; blocking mode can bound the outstanding request queue to one. Source: [VPP API module](https://docs.fd.io/vpp/21.10.0/gettingstarted/developers/vpp_api_module.html).
- **Project inference:** VAPI request context is not a durable idempotency record. A disconnect after submission can therefore be outcome-unknown at the product level. #24 must reconnect with a fresh handle, read active generation/revision, and reconcile before retry; it must never transparently replay.

### 4. Pinned VPP handoff ownership (#4, #5, #7, #15)

- **Direct pinned-source fact:** VPP revision `9258530f3804a152578ce11cc7c8a1e9eab88ed0` collects non-enqueued indexes into `drop_list`; with `drop_on_congestion=1` it calls `vlib_buffer_free()` internally and returns only the number enqueued. With `drop_on_congestion=0`, the helper waits for a frame-queue slot. Source: pinned `src/vlib/buffer_funcs.c` in the reproducible S73 source tree and the same [FD.io commit](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vlib/buffer_funcs.c).
- **POC evidence:** `VPN-F016` observed a caller freeing a rejected buffer a second time after `drop_on_congestion=1`, causing a crash; removing the second free corrected only that POC call site. Source: [`POC_FINDING_LEDGER.md`](../../experiments/vpp-nfq-poc/POC_FINDING_LEDGER.md#vpn-f016----handoff-rejection-double-freed-a-vpp-buffer).
- **Hard product requirement:** an admitted Root or VPN `PacketLease` must never enter generic auto-free handoff. `drop_on_congestion=1` can lose the only obligation identity; `drop_on_congestion=0` violates the bounded nonblocking hot-path rule. Before graph admission/handoff, the implementation reserves the ledger slot and credits needed to retain and settle that packet's origin obligation. #4/#5 must provide a completion-aware bounded handoff whose result identifies ownership of every buffer index: enqueued ownership transfers once; rejected ownership remains available for the explicit terminal path; every admitted obligation reaches exactly one settlement; no call site guesses whether VPP already freed it. A dedicated reservation/credit scheme or a narrow identity-preserving queue/helper is an implementation choice, but full-queue fault injection and an exact one-owner/one-settlement ledger are mandatory.
- **Claim boundary:** the sources prove the helper semantics and prior double-free. They do not select the final queue data structure, capacity, or wake policy.

### 5. NFQUEUE lifecycle and verdict truth (#6--#9)

- **Direct Netfilter fact:** every queued packet requires a userspace verdict; `nfq_set_verdict()` returns `-1` on error and nonnegative on successful submission. Queue overflow drops by default, while `NFQA_CFG_F_FAIL_OPEN` accepts on queue-full; hook-level `bypass` covers the no-listener case. Sources: [libnetfilter_queue](https://netfilter.org/projects/libnetfilter_queue/doxygen/html/), [queue API](https://netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Queue.html), [Linux NFQUEUE UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nfnetlink_queue.h), [kernel queue path](https://github.com/torvalds/linux/blob/master/net/netfilter/nf_queue.c), and [nftables queue statement](https://netfilter.org/projects/nftables/manpage.html).
- **Direct Netfilter fact:** `nfq_set_verdict_batch()` and its mark variant apply one verdict to every queued packet whose ID is less than or equal to the supplied ID. That is not a generic optimization for independently decided Sakamoto obligations. Source: [libnetfilter_queue verdict API](https://netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Queue.html).
- **Audit requirement:** bind/configure the queue before publishing hooks/readiness; distinguish no-listener bypass from queue-full fail-open; do not claim overall Root readiness until required IPv4/IPv6 INPUT/OUTPUT listeners and hooks are present. A nonnegative verdict return proves the terminal operation, not downstream delivery. Each admitted obligation gets at most one individual physical verdict attempt: no generic batch verdict, no retry after definite or ambiguous submission, and no replacement payload.
- **Project/device fact:** controlled Pixel evidence found Root INPUT `NFQA_UID` unavailable before delivery. #8 must record `uidKnown=false`/Unknown Application for INPUT and prove the real installed app UID on OUTPUT. Source: [`ANDROID_FUNCTIONAL_CLOSURE_CONTRACT.md`](../decisions/ANDROID_FUNCTIONAL_CLOSURE_CONTRACT.md#71-sakamoto-68-live-root-evidence-decisions).

### 6. Android VPN lifecycle (#10--#16)

- **Direct Android fact:** always call `VpnService.prepare()`; only one app is prepared, `protect()` can fail, `Builder.establish()` can return `null` after permission loss, and `onRevoke()` may run off the main thread. The TUN descriptor must be closed. Sources: [Android VPN guide](https://developer.android.com/develop/connectivity/vpn), [`VpnService`](https://developer.android.com/reference/android/net/VpnService), and [`VpnService.Builder`](https://developer.android.com/reference/android/net/VpnService.Builder).
- **Audit requirement:** #10 orders authorization, legal FGS startup, TUN establishment/ownership transfer, underlay bind plus successful protection before connect/first send, UDP4 traffic, then close. Bind/protect failure closes the socket with no unprotected fallback. Use an explicit nonblocking TUN mode compatible with the event-driven lane.
- **Direct Android fact:** establishing a new VPN deactivates the prior interface, but the old descriptor remains valid until closed. **Project requirement:** #16 does not rely on Android seamless handover; Sakamoto must quiesce, drain, settle, explicitly close the old TUN descriptor and remaining old-generation resources, and only then establish the replacement.
- **Direct Android fact:** `VpnService.setUnderlyingNetworks()` is a declaration of the networks the VPN actually uses; it does not replace `Network.bindSocket()` or `protect()` for a Direct Egress socket. Source: [`VpnService.setUnderlyingNetworks`](https://developer.android.com/reference/android/net/VpnService#setUnderlyingNetworks(android.net.Network%5B%5D)).
- **Conditional project inference:** call `setUnderlyingNetworks()` only when Sakamoto explicitly tracks and can truthfully publish the current underlay set. If that condition holds, #14 updates the declaration for the new epoch and still binds/protects every new Direct socket before connect/first send. Otherwise leave the declaration to platform inference; do not add a generic migration framework or silently move live TCP.

### 7. Policy publication (#18--#24)

- **Project architecture:** one Rust Product Store writer publishes one complete immutable successor policy revision; Root and VPN read the same VPP runtime semantics. Sources: [`ADR-0001`](../adr/0001-policy-bundle-staged-enforcement.md), [`ADR-0002`](../adr/0002-tauri-android-runtime-service-boundary.md), and [`CONTEXT.md`](../../CONTEXT.md).
- **Audit requirement:** #18 is not a schema-only ticket: it must persist, publish, and read back the empty revision through the actual Rust/VAPI/VPP path. Publication must be all-or-nothing across workers; exact barrier versus immutable-pointer primitive remains an implementation choice. #19 is the first real behavior-changing rule.
- **KISS boundary:** no broad authoring CRUD, final database choice, Tauri catalog, full UI, telemetry pipeline, or release migration framework. Bounded revision/status/winner/reason/fault evidence is enough.

## Explicitly defer or reject

- No restoration, translation, or reference use of the removed C++ product daemon, host model, tests, archive, NDK artifact, or Flow-Stack facade. ADR-0008 is absolute.
- No direct POC source import. C/VPP POCs supply evidence and failure invariants only.
- No conditional-wake implementation, per-packet Rust/Java bridge, shared NFQUEUE verdict socket, automatic outcome-unknown retry, second policy database, or parallel Root/VPN runtime.
- No release SLO, long soak, OEM matrix, release signing/upgrade, public IPv6 requirement, GSO/jumbo redesign, chain-aware parser, dynamic worker reshaping, complete UI, or high-cardinality telemetry in this recovery campaign.
- No ticket for each test cell, build file, schema, ABI function, language layer, or telemetry counter. Put those as ordered acceptance checkpoints inside the owning tracer bullet.

## Final publication recommendation

Revise the proposed list to the 25 tickets above, then present that list and its blocking edges to the user once more before creating Plane work items. Apply native `blocked_by` relations and `ready-for-agent` only after approval. Do not modify or close SAKAMOTO-170.
