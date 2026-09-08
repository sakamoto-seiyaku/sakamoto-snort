# SAKAMOTO-198 — Shared TUN protocol facts and transport outcomes

PASS, 2026-09-08. Scope: the protocol and ownership acceptance below.
Startup robustness is not qualified; the separate observed startup failure is
recorded explicitly below and in SAKAMOTO-243.

The real TUN graph now demonstrates IPv4/IPv6 TCP and UDP DROP and legal ICMP
DROP/allow outcomes. The terminal node derives the unsupported-transport bit
from the already available shared PacketFacts before their lifetime ends. The
existing 32-byte Completion Frame carries that result to TUN completion, which
does not parse packet bytes again. Policy allow with Transport Outcome
`UNSUPPORTED` remains distinct from malformed input and Policy DROP.

## Accepted source and artifacts

Both final builds use source SHA-256
`33b970df033d7e80f5ae6cd0fa3b8b863c86f521aafbd9bc8d71e13abdc01307`.
Build base: `d481a1b125ad42231d8223993469aac6c8c08bfe`.
Dirty-diff SHA-256:
`d00fd2cf72d485fb16a64863d56831821cdc223e798e5db48b8b383cb6dc2829`.
Complete per-file source snapshots accompany the build manifests; the later
task commit does not rewrite these historical build identities.

- Android: `build-output/s198-protocol/pixel-build-a/build.json`.
- Linux: `build-output/s198-protocol/linux-build-a/build.json`, artifact
  `build-output/product-vpp-host-s198-a`.
- Product identity: `sakamoto-product-vpp-s198-v1`;
  generated API identity: `product_core.api/1.0.0@2e53fed5`.
- APK SHA-256:
  `3efd904928de2d4a72a28b0550047a9eb2d0af2d88f80b6b77813c44e44b11df`.

| Android native file | SHA-256 |
| --- | --- |
| `libvpp_runtime.so` | `d201d23fdfe48068562b8d514c661870fe747913d0af130fa6d7e3f4226edc08` |
| `libproduct_core_plugin.so` | `61a010fa276d438829464c477f9551b1de376faf9df8ea03a02831a4a2cb770d` |
| `libsakamoto_product_core.so` | `51eae3f6ba2716b022d5b1833eec425ece2f062d285d7471c4d23e9878365bbd` |
| `libsakamoto_runtime_control.so` | `3c93ee6c3e6b3322f636b388a0ee93747b289cf1d91ac7fe05864512dca28d49` |

Installed APK/native bytes match the actual package. The manifests retain all
dependency hashes, Linux artifact hashes and the unchanged pinned VPP/core
patch profile. The Product plugin and Android application were rebuilt from
this task's source.

## Real TUN matrix

Pixel `28201JEGR0XPAJ`, app UID `12632`, kernel
`6.1.134-android14-11-g66e758f7d0c0-ab13748739`, runs the VPP process under the app
UID. The S213 controlled validation VPN includes the test application only.
Its UID metadata remains explicitly `CONTROLLED_TEST_PROVIDER`; this task does
not claim Android UID collection or inferred network classification.

Accepted run `pixel-d` contains generations **925 and 926**:

| Per generation | Cases | Required result |
| --- | ---: | --- |
| Actual app IPv4 UDP, IPv6 UDP, IPv4 TCP and IPv6 TCP | 8 | Each family/protocol has Network Gate DROP and protocol/port-specific L4 DROP |
| Kernel-routed ICMPv4 Echo and ICMPv6 Echo | 4 | Each family has actual Policy DROP and policy allow followed by `UNSUPPORTED` |

There are **24 target packets** across the two generations, plus **14 real
kernel IPv6 control packets**, for **38 real TUN originals**. All target tuples
select canonical owner 0 and complete locally. Incidental control packets are
accounted separately and may use the existing remote-owner path.

The application uses real Java UDP sockets and TCP connect attempts bound to
the TUN address. UDP carries its nonce in the actual payload. TCP SYN has no
application payload: it is bound by the application receipt's unique source
port, family and protocol, the original captured tuple/ISN, generation and the
actual matching policy revision. A TCP receipt nonce is not falsely claimed
as SYN payload. Socket timeouts alone are never policy proof.

The ICMP test endpoint creates a kernel raw socket under the test app UID,
using test-only raw-socket capability, and routes through the actual TUN. It
does not write a TUN fd or inject into the graph. The independent verifier
checks Echo type/code/identifier/sequence, the real payload nonce and the
ICMP checksum, including the IPv6 pseudo-header. DROP and allow cases retain
the same canonical ICMP key despite changed Echo sequence numbers.

The verifier independently decodes original packet bytes, recomputes the
canonical key/hash/owner and checks one parser/selector operation. It compares
admit, policy and terminal facts, including TCP sequence, acknowledgment,
flags, window, header length and window-scale options. It then checks the
actual rule/verdict and the completion outcome:

- 20 target Policy DROPs have `NOT_ATTEMPTED` transport outcome.
- Four allowed target ICMP packets have `UNSUPPORTED`, zero runtime-drop reason
  and no Policy DROP.
- All 38 originals publish and consume one Completion Frame and return their
  original VPP buffer exactly once at the origin lane.

Including background traffic, each generation records 11 policy DROPs, four
unsupported outcomes and four unavailable outcomes. These three categories
are not merged.

## Unavailable and malformed facts

The bounded parser does not walk the recognized IPv6 extension headers listed
in its predicate. Their deeper transport now remains L4 unavailable, instead
of being presented as an already identified other terminal. Next Header
assignments are checked against the
[IANA protocol registry](https://www.iana.org/assignments/protocol-numbers/).
The implementation preserves the observed header value and L3 facts, exposes
no invented ports and makes no complete extension-chain support claim.

Real kernel Hop-by-Hop control packets exercise this unavailable branch. A new
Host vector also checks a complete IPv6 envelope containing an unwalked
Hop-by-Hop header followed by UDP. ICMP retains honest OTHER_TERMINAL status
and its supported identity fields; it is not relabelled TCP/UDP COMPLETE.

The same Product artifact additionally executes **eight clearly labelled
GRAPH_INJECTED carriers**, four per generation:

1. Invalid IPv4 IHL: runtime DROP before policy, no valid L3/owner facts.
2. Complete IPv4 envelope with a short UDP header: L3 valid, L4 unavailable,
   no invented ports, normal policy pass.
3. Unwalked IPv6 extension followed by UDP: L3 valid, deeper L4 unavailable.
4. Truncated IPv6 envelope: runtime DROP before policy, no valid L3 facts.

These supplement the real TUN matrix because an ordinary kernel app socket
does not emit those malformed L3 envelopes. Their source, obligation kind and
counter scope remain separate. Each diagnostic carrier also has one native
completion/free; none is counted as a TUN or NFQUEUE original.

## Ownership, stop and regressions

Unsupported classification happens after policy while the original shared
PacketFacts remain valid. Only the derived operation bit enters the existing
Completion Frame. Adapter ingress and completion contain no repeated
port/flags/sequence/offset parser, no second packet table and no forwarding
fallback. The TUN fd still has one native origin lane. There is no Flow Stack
or protected Direct socket admission in this slice.

Both accepted TUN generations drain to zero pending buffers, frames,
obligations and reassembly references, close the native TUN fd, then stop with
no VPP process or TUN interface. Before/after fd and process records bind the
app-UID process and cleanup. Ordinary VPN START and Resume still reject
forwarding readiness.

Same-source ordinary Root regressions pass:

| Run | Platform / generation | Real NFQUEUE packets | Endpoint cases |
| --- | --- | ---: | ---: |
| `root-pixel` | Pixel / 927 | 69 | 50 |
| `s198-l1` | Linux / 21710 | 64 | 48 |

Linux uses x86-64 `6.6.114.1-microsoft-standard-WSL2` in a disposable
user/network namespace. Both regressions independently check raw attributes,
dual-stack TCP/UDP policy, original-lane verdict/free and cleanup. The combined
accepted traffic is **171 real originals**, plus eight diagnostic carriers.

S175 exceptional packet semantics pass with the new unavailable-extension
vector. Eight evidence mutations are rejected: spoofed ingress, duplicate
parser, missing physical return, wrong canonical owner, changed TCP sequence,
unsupported relabelled as DROP, unavailable extension promoted to terminal,
and graph injection relabelled as real TUN. `git diff --check` passes.

## Retained checkpoints and startup observation

The first policy helper incorrectly populated L4-specific fields in a Network
Gate entry; the Rust control boundary correctly rejected it before the matrix
began. The corrected helper keeps Gate fields in their supported scope.

A later TCP bind failed because port 44104 was already present in the kernel
socket table. That unrelated socket was preserved. The collector now avoids
occupied ports when choosing controlled input tuples.

Generation **924** subsequently returned `product_core_not_ready` before the
protocol workload began. The lifecycle projection reported `mayBeActive=false`;
an empty-runtime Stop retained the error, causing the harness's stopped-state
expectation to fail. That collector version did not retain the pre-cleanup
native log, so the initiating cause remains **unconfirmed and not claimed
fixed**. The collector now saves native logs during STARTING. The next two
generations, 925 and 926, passed on the same APK. The intermittent readiness
and inactive-error Stop observation is recorded in **SAKAMOTO-243**, with task
metadata/dependencies preserved. This checkpoint is excluded from acceptance
counts and does not establish startup robustness.

## Evidence and limits

`build-output/s198-protocol/records.json` indexes accepted runs, build
manifests, exact evidence tools and retained checkpoint hashes. Its SHA-256 is
`83c4864c2a58249c98dd3c40e678ff6a55872f63ab6eefac6c59fbace4656b84`.
The source and verifier snapshots reside under `evidence-tools/`; semantic
negative results are in `negative-verification.json`.

This is protocol/facts/completion acceptance. It does not prove TCP/UDP VPN
forwarding, real return traffic, full IPv6 extension parsing, platform UID,
VPN network facts, latency/power or release readiness. Pixel is stopped after
generation 927 with Wi-Fi restored; the Linux test resources are closed.
