# Rust/VPP in-process dataplane FFI integration research

Date: 2026-08-01

Status: out of scope; based on a rejected architecture premise.

> Scope correction (2026-08-01): this investigation assumed Rust packet code would run inside VPP graph
> nodes. The product instead uses Rust to replace the surrounding C++ program; VPP packet processing remains
> in C. Consequently the Rust-native node, C-node-to-Rust batch call, broad/allowlisted bindgen, and
> per-packet accessor alternatives studied here are not candidates for the selected architecture. Retain
> this note only as evidence for why those alternatives are unnecessary.

## Executive conclusion

There is no universal production pattern for a Rust packet core inside VPP. The evidence supports a
**hybrid boundary**, followed by measurement, rather than either “bindgen all of VPP” or “every operation
goes through a stable C shim” as an article of faith.

Recommended first POC:

1. Keep a small C VPP plugin shell responsible for `VLIB_PLUGIN_REGISTER`, `VLIB_REGISTER_NODE`/
   `VLIB_NODE_FN`, frame acquisition, VPP enqueue macros/inlines, trace/error integration, and plugin build
   registration.
2. Call Rust **once per VPP frame/batch**, not once per packet.
3. Define a Sakamoto-owned, versioned C ABI using fixed-width scalars, pointers, spans and explicit status
   codes. Generate its C header from Rust with cbindgen or keep one reviewed C header as source of truth;
   do not expose Rust enums, `Option`, references, unwinding, or VPP structs as the public ABI.
4. Compare two internal data-access variants:
   - C materializes a preallocated per-frame array of compact packet views (`bi`, current pointer/length,
     selected metadata pointer/values), then Rust performs no per-packet FFI calls.
   - Rust receives the frame's index span and uses a **small allowlisted generated binding set** for the exact
     pinned fork's buffer layout, while C still owns macro/inline-heavy enqueue and registration.
5. Select between those variants only after Android measurements. The second may be faster; the first has a
   smaller unsafe/layout blast radius.

This is primarily option **C** (C node wrapper calling Rust once per frame), using part of **B** (a narrow
owned ABI), and optionally a carefully limited part of **A** (bindgen for a pinned, audited buffer-layout
subset). Option **D** is useful only inside the hybrid: Rust may call a few C accessors for rare operations,
but a per-packet accessor cascade should not be assumed cheap.

## Facts from VPP and this fork

### VPP's native integration surface is C, macro- and inline-heavy

The fork's sample plugin defines packet nodes with `VLIB_NODE_FN`, obtains frame vectors, uses
`vlib_get_next_frame`, `vlib_get_buffer`, speculative enqueue and prefetch operations, then registers with
`VLIB_REGISTER_NODE` (`/home/js/backup/backup/Git/vpp/src/examples/sample-plugin/sample/node.c`). The
official VPP architecture describes graph nodes processing vectors of packets per invocation, not one
foreign call per packet ([FD.io VPP software architecture](https://wiki.fd.io/view/VPP/Software_Architecture)).

The local build macro creates a shared plugin, compiles it with VPP's architecture flags, hidden visibility,
function/data sections and garbage collection, and separately supports `MULTIARCH_SOURCES`
(`/home/js/backup/backup/Git/vpp/src/cmake/plugin.cmake`, lines 14-128). The sample node is listed as a
`MULTIARCH_SOURCES` file (`src/examples/sample-plugin/sample/CMakeLists.txt`). This is evidence that keeping
the native C node shell participates naturally in VPP's build and multiarch model. A Rust-only node path
must reproduce or deliberately forgo those mechanics.

Many buffer and enqueue operations are `static_always_inline` wrappers in
`src/vlib/buffer_funcs.h` and `src/vlib/buffer_node.h`. Bindgen's own FAQ says inline functions normally have
no linkable symbol; generated wrappers turn them into out-of-line calls, and explicitly warns that hot inline
functions may then have unacceptable performance
([rust-bindgen FAQ](https://rust-lang.github.io/rust-bindgen/faq.html#why-isnt-bindgen-generating-bindings-to-inline-functions)).
Therefore “bindgen headers” does not mean Rust receives equivalent inlining for VPP's hot helpers.

### VPP plugin compatibility is coupled to the VPP build

The local loader verifies the plugin registration record's size and can reject a plugin whose
`version_required` does not match the application version prefix
(`/home/js/backup/backup/Git/vpp/src/vlib/unix/plugin.c`, lines 234-289;
`src/vlib/unix/plugin.h`, lines 55-70 and 154-156). This is useful admission checking, not a promise that all
internal structs/macros form a stable ABI. The plugin is built against the fork and should remain pinned to
that exact source/toolchain baseline.

### Enqueue return semantics must remain explicit

The fork's thread enqueue copies `u32` indices into frame-queue elements and returns the count enqueued. With
`drop_on_congestion`, it frees indices that could not be enqueued
(`/home/js/backup/backup/Git/vpp/src/vlib/buffer_funcs.c`, lines 290-378). An FFI API that merely says
“handoff these indices” is insufficient for obligated PacketLeases: it must specify success count, ownership
of every non-enqueued index, and whether any path freed buffers. The C node shell is a good place to preserve
these native semantics and convert them into one reviewed Rust-facing result.

## Pattern comparison

### A. Bindgen over broad VPP headers; Rust-native node entrypoint

**Evidence:** rust-bindgen generates C/C++ declarations and layouts, supports allowlisting, and emulates C
bitfields because Rust has no native C bitfield representation
([bindgen README](https://github.com/rust-lang/rust-bindgen),
[allowlisting](https://rust-lang.github.io/rust-bindgen/allowlisting.html),
[bitfields](https://rust-lang.github.io/rust-bindgen/using-bitfields.html)). Its inline-function limitation is
material for VPP. Cross-builds also require the correct target sysroot/include arguments and libclang setup;
bindgen documents target-specific `BINDGEN_EXTRA_CLANG_ARGS_<TARGET>` for this purpose.

An independent `vpp-plugin-rs` project demonstrates that Rust node registration is technically viable and
offers macros such as `vlib_node` and `vlib_plugin_register`
([crate documentation](https://docs.rs/vpp-plugin/latest/vpp_plugin/)). Its source also demonstrates the
maintenance burden: bindings are described as incomplete, unsafe, unstable, target/VPP-version dependent;
it contains manual fixes for duplicate definitions, alignment and unions, and its published pregenerated
bindings shown by docs.rs are for `x86_64-unknown-linux-gnu`
([bindings source](https://docs.rs/crate/vpp-plugin/latest/source/src/bindings.rs)). It states a goal of
performance parity, but the inspected public material does not provide Android/arm64 production evidence.

**Advantages:** Rust can potentially inline its own direct field access and keep its node loop in one
optimizer domain; smallest C source after bindings work.

**Risks:** large unsafe surface; generated churn on fork upgrades; C macros and static inlines are not direct
bindings; bitfields/unions/vector types/alignment and compiler extensions need auditing; recreating VPP
registration/link sections and multiarch behavior; libclang/sysroot complexity in Android builds. Whole-header
generation also exposes far more API than ownership correctness requires.

**Assessment:** viable as an experiment or for a deliberately maintained Rust VPP framework, but too broad
as Sakamoto's first production boundary. A small allowlisted layout subset remains a valid hybrid candidate.

### B. Thin C shim with a stable Sakamoto-owned ABI

**Evidence:** cbindgen generates C/C++ headers from a Rust library
([official cbindgen repository](https://github.com/mozilla/cbindgen)). CXX jointly generates Rust/C++ bridges,
adds static checks, and claims zero or negligible overhead for supported signatures
([official CXX repository](https://github.com/dtolnay/cxx)). But VPP's native surface is C, not an idiomatic
C++ object API; CXX would add generated C++ machinery without solving VPP macros, link sections or inline
helpers.

**Advantages:** explicit ownership contract; narrow unsafe surface; stable internal API across Rust module
refactors; simple layout assertions; easy panic/status boundary; generated header works with CMake/NDK.

**Risks:** “thin” can become hundreds of per-packet getter/setter calls. Separate C and Rust compilation
normally prevents ordinary cross-language inlining; LTO across Clang LLVM bitcode and rustc is not a baseline
guarantee and must be demonstrated for the exact Android toolchain. A copied descriptor array also costs
stores/cache bandwidth even though packet bytes are not copied.

**Assessment:** good contract technique, not by itself a dataplane topology. It should be combined with a
batch boundary and measured.

### C. C VPP node wrapper calls Rust once per frame/batch

**Evidence:** this matches VPP's vector node invocation model and preserves existing plugin registration,
multiarch compilation and enqueue idioms. Mature Suricata uses C/Rust FFI callbacks for application-layer
parsers and now develops app-layer protocol code in Rust for security reasons
([Suricata developer guide](https://docs.suricata.io/en/suricata-8.0.1/devguide/extending/app-layer/overview.html),
[official source](https://github.com/OISF/suricata)). This is evidence that a production packet-security
project can keep a C engine shell while moving bounded parsing logic into Rust; it is not evidence that its
per-call cost or ownership model equals VPP's.

**Advantages:** one ABI transition per vector; C retains VPP-native frame/enqueue operations; Rust owns
policy/parser/session logic; easy `extern "C"` no-unwind boundary; exact packet ownership can be expressed in
the batch contract.

**Risks:** representation of packet access is the key design choice. Building `PacketView[N]` may cost more
than direct buffer lookup; passing only indices may require per-packet callbacks or limited direct bindings.
Returning a large disposition array also adds traffic, though VPP nodes already maintain next-index arrays in
many paths.

**Assessment:** best first production-oriented POC and likely default shell.

### D. Rust controls C callbacks/accessors

**Advantages:** Rust owns the algorithm; C encapsulates every unstable VPP operation; convenient for rare
operations and mutation authorities.

**Risks:** opaque function pointers inhibit inlining and branch prediction; one or more calls per packet can
erase the benefit of a single batch entry; callbacks complicate lifetimes, panic behavior and ownership on
partial failure.

**Assessment:** use a small fixed function table/context only for cold or uncommon operations. Do not model
ordinary buffer reads, metadata reads and enqueue as a long callback chain without measurements.

### E. Rust as an out-of-process VPP API client

The repo's existing Rust probes call the VPP control API/socket; they validate control-plane connectivity and
reconnect behavior (`experiments/vpp-nfq-poc/android/vpn-lite/rust/vpp_rust_control_probe.rs`). They do not run
as packet graph nodes and provide no evidence for in-process dataplane FFI. VPP API client crates belong to
control-plane design and must not be cited as dataplane integration proof.

## Recommended ABI shape for the POC

Keep the boundary batch-oriented and ownership-explicit:

```c
struct sakamoto_packet_view_v1 {
  uint32_t buffer_index;
  const uint8_t *current_data;
  uint32_t current_length;
  void *lease_metadata;       /* exact private layout remains versioned */
};

struct sakamoto_packet_result_v1 {
  uint16_t next;
  uint16_t target_worker;
  uint8_t terminal_intent;
  uint8_t flags;
};

int32_t sakamoto_process_frame_v1(
  void *worker_context,
  const struct sakamoto_packet_view_v1 *packets,
  struct sakamoto_packet_result_v1 *results,
  uint32_t count);
```

This is illustrative, not accepted ABI. Production rules:

- arrays are caller-owned and preallocated for `VLIB_FRAME_SIZE`; no hot-path allocation;
- packet bytes remain VPP-owned and read-only for ordinary nodes;
- Rust cannot retain pointers/views after the call;
- raw buffer indices are not exposed to general safe Rust; the Rust boundary constructs its local linear
  owners for the duration of the frame;
- C consumes every result exactly once into local enqueue, worker handoff, completion return or explicit
  disposition;
- partial processing returns an exact processed prefix or per-item state; no ambiguous ownership;
- ABI returns integer status codes only; no Rust panic or C++ exception may cross it;
- release Rust uses `panic=abort` or catches at a deliberately tested outer boundary, but the C ABI remains
  non-unwinding. See Rust's official FFI unwinding rules
  ([Rustonomicon](https://doc.rust-lang.org/nomicon/ffi.html#ffi-and-unwinding)).

For the direct-layout variant, replace `PacketView[]` with an index span and allowlist only the exact
`vlib_buffer_t`/Sakamoto metadata facts needed. Keep C registration/enqueue unchanged. Generated bindings are
committed or reproducibly generated with the same pinned NDK Clang/sysroot and checked by C/Rust
size/alignment/offset assertions.

## Hot-path and LTO judgment

**Evidence:** a single non-inlined ABI call per frame amortizes call/return overhead across the vector. VPP's
sample comments report node cost in clocks per packet at a stated vector size, reinforcing that vector size
must be part of measurement (`sample/node.c`). Bindgen warns out-of-line wrappers for hot inline functions may
be unacceptable.

**Inference:** the once-per-frame call itself is unlikely to dominate. Descriptor materialization, result
array writes, lost direct inlining/prefetch scheduling, and any per-packet callback are more plausible costs.
This must be measured; no inspected source establishes their cost on the target Android CPUs.

Do not make cross-language LTO a correctness or launch dependency. If later enabled, verify the actual final
ELF disassembly and symbol/call graph. VPP's C plugin is a shared object with hidden visibility and its own
multiarch objects, which makes “rustc will inline through all C helpers” especially unsafe to assume.

## Android build and maintenance

The C shell naturally remains under VPP CMake and its NDK/architecture flags. Build Rust as one pinned
`aarch64-linux-android` static library and link it into the plugin, or prove that a companion shared library is
loaded and packaged correctly. The POC must verify:

- NDK API level, target triple, linker and C runtime agreement;
- no unexpected Rust shared-library dependency;
- symbol visibility/export list and plugin load on device;
- unwind/runtime libraries under the chosen panic strategy;
- reproducible generated headers/bindings without requiring target-side libclang;
- plugin registration/version check against the exact modified VPP build;
- release APK/VPP artifact size and relocation/startup cost.

Generating bindings on the host with explicit Android sysroot/target arguments is preferable to running
bindgen implicitly during every Cargo build. Whole-header bindgen would make the NDK/VPP include graph and
libclang version part of every developer build; a small checked-in generated subset limits that risk.

## Required POC matrix

Implement the same no-op/read-only/metadata-write node four ways where feasible:

1. native C baseline;
2. C node + one Rust batch call + materialized `PacketView[]`;
3. C node + one Rust batch call + limited direct buffer-layout bindings;
4. C node + Rust batch call + per-packet C accessor callbacks (control comparison).

Measure on representative Android arm64 devices:

- cycles or nanoseconds per packet by vector size (1, 2, 4, 16, 32, full frames);
- throughput, p50/p95/p99 latency and packet loss;
- instructions, branches/misses and L1/L2 cache misses where device tooling permits;
- descriptor/result bytes written per packet;
- handoff/local-completion/remote-completion mixes and enqueue congestion;
- idle/active CPU, power and thermal behavior;
- binary size, relocations, startup/load time;
- disassembly: ABI calls per frame/per packet and whether any promised LTO occurred.

Correctness fault injection must cover partial batch error, panic/abort, invalid length, stale generation,
wrong origin lane, return-ring pressure and every enqueue return count. A test must prove that C and Rust never
both believe they own the same index and that no obligated buffer reaches VPP's congestion-free path.

## Recommendation

Adopt **C node shell + one Rust call per frame** as the POC baseline, with a Sakamoto-owned versioned ABI.
Do not decide yet whether packet access uses compact C-built views or a tiny allowlisted direct binding; make
that the measured fork in the POC. Keep VPP registration, macros/static inlines, frame enqueue/handoff and
trace/error mechanics in C initially. Use C accessors only for rare/cold operations.

Reject whole-VPP bindgen as the default and do not use control-plane VPP API crates as dataplane evidence.
Reconsider a broader Rust-native VPP layer only if the limited-binding POC wins materially and the team is
willing to own target-specific generated bindings, VPP upgrade churn, registration sections and multiarch
equivalence as a first-class subsystem.
