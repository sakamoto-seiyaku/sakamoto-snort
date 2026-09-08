# SAKAMOTO-218 — TUN platform facts from Android network events

PASS, 2026-09-09.

Real TUN-origin packets now consume S232's Android event snapshot. Root and
TUN share one native generation-owned store and its existing validation and
worker-barrier publication. No new Android subscription system, per-packet
platform RPC, metadata overlay or second owner calculation was introduced.

## Platform semantics

The native TUN attachment obtains the interface name from the actual fd and
resolves its interface index once outside the packet path. That attachment
identity selects the existing Android event entry. It is not exposed as the
packet's Linux ifindex: VPN v1 keeps that fact explicitly unknown.

Android NetworkCapabilities and LinkProperties callbacks establish the actual
VPN classification for that interface. Neither the VPN Runtime Profile nor
the interface being a TUN supplies a guessed category. Missing entries remain
unknown. Underlay Wi-Fi loss/reconnect changes the event map; while the actual
VPN network survives, its confirmed category remains VPN. This task does not
claim that the TUN packet's category becomes Wi-Fi or that a future transport
session has acquired an underlay binding.

Every captured packet has OUTPUT device direction and TUN_ORIGIN provenance.
The existing controlled test-application UID provider remains labelled
CONTROLLED_TEST_PROVIDER; this is not acceptance of general Android UID
collection. Interface/category/provenance never enter the canonical key,
owner hash or ORIG/REPLY derivation.

## Accepted source and artifacts

Both final builds use source SHA-256 `1b300a2330f622a84c9cf400c8722dcc4b90e0c81a70570f8ad5c9b9ee39c8c5`.
Build base: `83eba3eefe7e87ed06b8a1148b48ea42ec9c078d`. Dirty-diff SHA-256:
`355269cdc3c6f4d69784999e9756c5a16f7ea995fe2fdd2e75712f0358d19471`.
Full per-file source snapshots are retained in the manifests; the later task
commit does not rewrite the historical build identities.

- Android: `build-output/s218-network/pixel-build-b/build.json`.
- Linux: `build-output/s218-network/linux-build-b/build.json`, artifact
  `build-output/product-vpp-host-s218-b`.
- Product identity: `sakamoto-product-vpp-s218-v1`.
- Generated API remains `product_core.api/1.0.0@2e53fed5`.
- APK SHA-256: `69cd9e2774b06a0e7a29a254e757aa4039eba587201c48e5a896c199f8c455cc`.

| Android native file | SHA-256 |
| --- | --- |
| `libvpp_runtime.so` | `d201d23fdfe48068562b8d514c661870fe747913d0af130fa6d7e3f4226edc08` |
| `libproduct_core_plugin.so` | `ad85ca218f784f98a42546f3ccf66eaffe411dff07d292f5ceab2f976880d91a` |
| `libsakamoto_product_core.so` | `51eae3f6ba2716b022d5b1833eec425ece2f062d285d7471c4d23e9878365bbd` |
| `libsakamoto_runtime_control.so` | `3c93ee6c3e6b3322f636b388a0ee93747b289cf1d91ac7fe05864512dca28d49` |

Installed APK and native bytes match the actual package. The Product plugin
and application were rebuilt; the pinned VPP five-patch profile and C API
layout remain unchanged. No removed C++ source or POC packet implementation
was imported.

## Pixel TUN acceptance

Pixel `28201JEGR0XPAJ`, application UID `12632`, kernel
`6.1.134-android14-11-g66e758f7d0c0-ab13748739` executes the native VPP process
under the app UID. Accepted run `pixel-d` uses generations **932 and 933**.
Each generation has 12 real app UDP target packets and seven real kernel IPv6
control packets: **38 TUN originals, including 24 targets** in total.

| Target cases per generation | Count | Actual matcher/completion |
| --- | ---: | --- |
| Initial confirmed VPN category: Gate and L4 | 2 | DROP |
| Interface-specific rule with packet ifindex unknown | 1 | No match; transport UNAVAILABLE |
| Missing snapshot: VPN-category Gate and L4 | 2 | No match; transport UNAVAILABLE |
| Missing snapshot: category-independent Gate | 1 | DROP |
| Restored snapshot: Gate and L4 | 2 | DROP |
| Actual Wi-Fi loss, VPN entry still confirmed: Gate and L4 | 2 | DROP |
| Actual Wi-Fi reconnect: Gate and L4 | 2 | DROP |

Across both generations, 18 targets have actual Policy DROP and six allow
results end transport UNAVAILABLE. A socket timeout alone is never counted
as policy proof. Original packet nonces and source ports bind the test
receipt to raw TUN bytes, actual rule IDs, verdict and Completion Frame.

The verifier independently matches Android event timestamps/revisions and
interface maps to each native packet snapshot, then checks shared admit and
policy facts. It verifies actual Wi-Fi removal and return in the event map,
not merely a request to toggle Wi-Fi. All target tuples independently select
owner 0, parse/select exactly once, and complete/free once on origin thread 1.
The full set of 38 originals also has exactly one completion and physical
return; incidental control packets are accounted separately from target
owner-local acceptance.

## Stop and regressions

Normal Service Stop unregisters the network subscription, publishes empty
facts and joins its callback thread before native TUN drain. Each accepted
log records subscription_stopped with thread_alive=false and a successful
stop_unknown publication. Native drain then settles all 19 originals and
records zero pending/buffer/frame/obligation debt with tun_fd=-1. The VPP
process and TUN interface are absent afterward.

The collector holds the native log inode across supervisor cleanup so these
terminal records survive file unlink. It exits when the actual VPP process
exits; it leaves no tail process. Native snapshot storage is cleared during
adapter stop. Ordinary VPN START and Resume remain unavailable.

Same-source regressions pass:

| Run | Platform | Real originals | Endpoint cases |
| --- | --- | ---: | ---: |
| `root-network` / generation 934 | Pixel dual-stack Root network events | 40 | 40 |
| `root-pixel` / generation 935 | Pixel ordinary Root TCP/UDP | 67 | 50 |
| `s218-l3` / generation 21710 | Linux ordinary Root TCP/UDP | 64 | 48 |

The Root network run revalidates per-actual-interface Wi-Fi classification,
INPUT/OUTPUT, callback loss/reconnect, controlled unknown/restoration, real
matcher and original-lane verdict/free on the shared store. Its independent
LAN echo endpoint was closed after the run. Linux uses an isolated user/net
namespace; its test resources are released. Pixel Wi-Fi is restored.

Android runtime/seam contracts and S175 exceptional packet semantics pass.
Twelve semantic evidence mutations are rejected, including a missing Android
event, fabricated Wi-Fi loss, wrong snapshot category, fabricated packet
ifindex, duplicate parser, wrong owner/rule, missing native free, live TUN
at stop and callback-thread residue. `git diff --check` passes.

## Retained checkpoints

The first collector externally stopped the native TUN through CLI while the
Android subscription remained active. A later real network publication was
rejected and the supervisor reported platform_network_publish_failed, then
removed the runtime. This is retained as `pixel-a` / generation 928 and is
excluded from acceptance. The final collector exercises the normal Service
Stop ordering instead of claiming that direct CLI teardown closes Android
subscriptions.

The next log monitor used kill -0 under run-as; Android denied that signal
probe, so it retired too early. `pixel-b` / generation 929 is excluded and its
runtime was cleaned up. The monitor now observes the actual process directory
and retains the log fd through cleanup. `pixel-c` / 930–931 passed the semantic
matrix but predates final comment cleanup and is not the final-source witness.
Final run `pixel-d` uses the rebuilt final source.

The first isolated Linux invocation was sandbox-denied before network setup;
it was rerun with the authorized namespace access. Its record is not a
packet-path failure or accepted run.

## Evidence and boundaries

`build-output/s218-network/records.json` binds the accepted raw runs, manifests,
helper binaries, exact evidence tools and retained checkpoints. SHA-256:
`3d4363a03ec142636ea9cfb1436682e0b36ab428b046a39cd4d4a4b1a330b9c9`.

There is no real Flow Stack return, INPUT return-policy or anti-loop claim;
those remain S237. There is no HEV/lwIP admission, protected Direct socket,
TUN write or forwarding readiness in this slice. Zero endpoint-routing fields
are structural counters backed by the accepted source and actual graph trace,
not a syscall trace. TCP/UDP forwarding, startup robustness, performance and
release acceptance remain outside this report.
