# SAKAMOTO-213 — Native TUN owner-local UDP DROP

PASS, 2026-09-08.

A newly implemented VPP-native TUN Adapter reads real Android TUN packets into
VPP buffers and submits them to the existing shared parser, canonical selector,
policy and Completion Frame path. The accepted target is owner-local IPv4 UDP
DROP. Ordinary VPN launch remains unavailable; this task does not enable Direct
Egress or restore the isolated handcrafted bridge.

## Final source and artifacts

The final Android and Linux builds share source SHA-256
`b558b5c79b319a87a8462e430d9e0cf216735a1e9ff0cd3af637dbde50c0adc0`.
Build base: `05920348ccfa1b01052e01275536c76e0907aa58`.
Tracked dirty-diff SHA-256:
`27e18c5bffe39936a7f35c3878fe6d38bea0e5e0545f2b9a46048a9b1bad4170`.
The complete per-file manifests and copied source include the newly added
Adapter and Java files. The later task commit preserves these original build
identities rather than rewriting their history.

- Android: `build-output/s213-tun/pixel-build-d/build.json`.
- Linux: `build-output/s213-tun/linux-build-a/build.json`;
  artifact `build-output/product-vpp-host-s213-a`.
- Product identity: `sakamoto-product-vpp-s213-v1`.
- Generated API identity: `product_core.api/1.0.0@2e53fed5`.
- APK SHA-256:
  `2d067ebd0321900e41836b323cb1b1f32b08e7d1a089f12c44efef7a134fb531`.

| Android native file | SHA-256 |
| --- | --- |
| `libvpp_runtime.so` | `d201d23fdfe48068562b8d514c661870fe747913d0af130fa6d7e3f4226edc08` |
| `libproduct_core_plugin.so` | `b29002cc1881d3762b0e742d940b0e1423e4d6673ce31160b663c208998ab05e` |
| `libsakamoto_product_core.so` | `51eae3f6ba2716b022d5b1833eec425ece2f062d285d7471c4d23e9878365bbd` |
| `libsakamoto_runtime_control.so` | `3c93ee6c3e6b3322f636b388a0ee93747b289cf1d91ac7fe05864512dca28d49` |

The pinned VPP revision, five core patches and Android profile remain the
accepted S228 baseline. Product builds compile the new C Adapter and Java
control path. Installation checks compare every packaged native library and
the APK with the actual installed bytes. Full dependency and Linux hashes are
in the build manifests.

## Real TUN acceptance

Pixel `28201JEGR0XPAJ`, app UID `12632`, Android kernel
`6.1.134-android14-11-g66e758f7d0c0-ab13748739` ran the Product VPP child under the
app UID. The raw before/after process and fd snapshots bind that process to its
TUN fd. The existing Android VPN grant was used. The validation VPN includes
only the current test application.

`pixel-d` records generations **918 and 919**. In each generation, the actual
Android application opens a Java `DatagramSocket`, binds `10.111.0.2` and one of
eight chosen source ports, and sends a nonce to `198.18.213.1:40633`. The test
chooses ports using the independent canonical oracle so these target packets
select owner 0; the Product Adapter never parses ports or pre-steers packets.

| Generation | Real TUN packets | Target app UDP | Target Gate DROP | Target L4 DROP |
| --- | ---: | ---: | ---: | ---: |
| 918 | 15 | 8 | 4 | 4 |
| 919 | 15 | 8 | 4 | 4 |

All **16 target packets** follow native admit → policy → terminal → origin
completion on thread 1 / worker 0. The independent verifier reconstructs the
original IPv4/UDP lengths, addresses and ports, recomputes the full canonical
key/hash/owner, and checks exactly one parse and selector event. The actual
matcher selects rule `21701` for Gate or `21704` for L4 from the typed control
helper. Each target ends in Policy DROP, with no Primary Handoff or completion
return handoff. Application socket timeouts agree with the native DROP records;
timeout alone is not used as proof of policy execution.

The remaining **14 packets** are real kernel-generated IPv6 control traffic
observed during TUN setup. They are preserved and included in conservation,
not counted as the S198 protocol matrix. Seven background packets in generation
918 used the existing remote-owner path; all target UDP packets remained local.
Generation 918 records nine total policy DROPs and six transport-unavailable
settlements; generation 919 records eight and seven respectively. This
separation prevents incidental background handoff or policy activity from
being misreported as the target local-only result.

## Facts, ownership and completion

The native read callback materializes into a VPP buffer, establishes the bounded
Adapter obligation and supplies platform-envelope fields. It does not inspect
TCP/UDP ports, flags, sequence numbers or protocol offsets, and has no protocol
allowlist before the shared graph. Valid non-TCP/UDP control packets therefore
reach the same graph with honest unavailable/OTHER transport facts.

UID is explicitly `CONTROLLED_TEST_PROVIDER` in this validation mode. Its value
matches the test application's UID, but this is not Android per-packet UID
collection evidence. Linux ifindex and NetworkContext remain unknown; direction
is OUTPUT and provenance is TUN-origin. Network/UID platform collection is not
inferred from the VPN profile or the single-application capture scope.

The appended TUN obligation kind uses the existing 24-byte AdapterObligation and
32-byte Completion Frame. `packet_id=0` is retained; no NFQUEUE identity is
invented. A bounded 128-slot origin-lane ledger carries token, buffer index and
active state. It is neither a Flow table nor a payload queue. The graph moves
and completes the original VPP buffer, and the origin consumer invokes the TUN
completion callback before its physical free. All **30 originals** have one
publication, one consumption, one Adapter settlement and one physical return.

The new Adapter has no TUN-write, NFQUEUE-verdict, Flow Stack admission or
protected-socket path. Actual target traces end at DROP and native buffer
return; the isolated POC is not called. The printed zero routing fields are
structural invariants of this Adapter, not claimed syscall-tracer measurements.
Allowed background packets record transport unavailable without rewriting their
Policy Verdict. No forwarding success is claimed.

## Control and lifecycle

Only an explicit debuggable validation request may bypass ordinary VPN launch
rejection. Runtime projection remains `adapterReadiness=unavailable` and
`protectionRunning=false`, even with a healthy graph and attached TUN.
Ordinary START before validation and ordinary Resume after the first stopped
generation both return `vpn_flow_stack_not_ready` without a VPP child. Resume
does not inherit the validation flag.

A generation-scoped Unix `SOCK_SEQPACKET` control socket transfers only the TUN
fd with `SCM_RIGHTS`; packet bytes do not traverse Java or Rust. Its bounded
20-byte envelope includes magic, operation, generation and the declared test
UID. The native receiver checks peer UID, generation, message/fd shape and the
TUN interface flags, and closes rejected descriptors. Four bounded control
slots avoid unbounded client allocation.

Stop quiesces TUN reads and reassembly, leaves completion processing alive while
debt drains, then closes the TUN fd and graph. The control client retries a
reported draining state within an eight-second bound. The same native stop
routine is used by the diagnostic CLI and RuntimeService cleanup. Both accepted
generations record native `pending=frames=buffers=obligations=0`, `fd=-1`, no
rejected completion or native I/O error, then a stopped service, absent TUN
interface and absent VPP process. Descriptor snapshots show the TUN fd gone
before process termination. Restart creates a new generation.

## Regression and verification

- Same-source Pixel Root: `root-pixel`, generation 920, **70 actual NFQUEUE
  packets / 50 endpoint cases**, including natural UID zero.
- Same-source Linux Root: `s213-l1`, generation 21710, **64 actual NFQUEUE
  packets / 48 cases** on x86-64
  `6.6.114.1-microsoft-standard-WSL2`, using a disposable user/network namespace.
- Both ordinary matrices cover dual-stack TCP/UDP INPUT/OUTPUT, actual
  attributes, controlled missing attributes, matcher results, original-lane
  verdict/free and cleanup.
- Android runtime contract suite, S192 bundle contract, S173 failure/owner
  contracts, S196 teardown contract and S175 exceptional packet semantics pass.
- Seven independent evidence mutations are rejected: spoofed ingress source,
  fabricated NFQUEUE identity, duplicate parser event, lost physical return,
  wrong canonical owner, wrong policy rule and a supposedly live post-stop TUN.
- `git diff --check` passes.

Accepted raw runs, exact evidence-tool copies and build manifest hashes are
indexed by `build-output/s213-tun/records.json`, SHA-256
`4530e9f383edc31c9fa63d4b75add00ed3e3b149bec404c9bc66f472500cf8f1`.
The negative record is `negative-verification.json`. Earlier exploratory and
incomplete runs are excluded from the counts above.

The first harness incorrectly expected an inactive ordinary VPN error to be
cleared by empty-runtime Stop; the corrected sequence preserves that rejection
and waits for the old control service to retire. A subsequent residue query
needed privileged Android `ip link` access. Separate process snapshots corrected
an overwritten before/after evidence filename. Linux exploratory runs encountered
a retained CLI socket and then an overlong Unix-socket path; the accepted run
uses a short unique path. These are retained checkpoints, not substituted PASS
results or TUN product failures.

## Limits

S213 proves the owner-local IPv4 UDP DROP slice and its lifecycle. It does not
qualify remote UDP policy, the complete protocol matrix, real platform UID,
VPN network snapshots, transport forwarding or return traffic. S198, S218 and
the S201 transport work retain their separate acceptance scopes. Pixel is
stopped after generation 920, Wi-Fi restored, and the Linux test resources are
closed.
