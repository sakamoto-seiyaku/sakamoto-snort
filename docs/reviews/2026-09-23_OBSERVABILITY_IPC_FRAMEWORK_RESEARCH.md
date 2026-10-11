# Observability IPC frameworks: iceoryx2 and NNG

Date: 2026-09-23. Supporting research, not a transport selection or implementation plan.

Scope: a VPP-native C producer and Rust consumer on Android ARM64 phones
(`minSdk 31`) and Linux. Normal and debug exports have separate bounded capacity;
VPP must not wait for Rust consumption or an application ACK. Loss is permitted.
Shared memory is one candidate, not an already accepted requirement. The packet
domain remains C under [ADR-0006](../adr/0006-vpp-native-packet-io-adapters.md)
and [ADR-0008](../adr/0008-remove-snort-cpp-mainline.md).

## Conclusion

**Neither framework is an obvious replacement for a small local transport in
this product.** iceoryx2 is currently blocked as an off-the-shelf Android IPC
choice. NNG is a plausible Android socket middleware candidate, but its stock
send path and runtime are considerably more than a bounded queue operation.
This does not prove a bespoke ring is preferable: direct OS transports and
small queue libraries need their own comparison.

| Question | iceoryx2 v0.10.0 | NNG v1.12.4 |
| --- | --- | --- |
| Android support actually documented | Only local, intra-process service variants; C bindings unavailable on Android | Android listed as supported; Android build guide explicitly says testing was cursory |
| Linux / C integration | Linux ARM64 supported at tier 2; C ABI to Rust library | C99 library; C ABI directly usable from C and Rust |
| Transport | Shared data segments and per-peer zero-copy connections | Framed messages over Unix stream sockets on POSIX |
| Worker send is necessarily allocation-free / mutex-free | No: C wrapper allocation is optional, C service uses local mutex protection, connection changes do extra work | No: convenience send allocates/copies; internal mutexes and AIO completion machinery remain with NONBLOCK |
| Loss / bounded queues | Configurable limits, discard or overwrite behavior | Message-count limits; behavior depends on protocol; PUB can silently replace queued records |
| Background runtime | Core documents no background threads; explicit event integration needed | Eager internal task, expiration, poller, resolver and reaper threads in inspected POSIX implementation |
| Idle claim justified here | Blocking/coalesced notification exists; no phone power result | Blocking epoll/CV waits exist; no phone power result |
| Disposition | Do not shortlist as ready Android IPC; reconsider after upstream platform closure | Keep only if framing/lifecycle convenience justifies its runtime, and target measurements pass |

The following sections provide the sources and qualifications behind this table.
No third general messaging framework was added: neither candidate's mobile costs
justify expanding this into a broad middleware survey without a concrete missing
capability.

## Pinned evidence and limits

Public upstream source was downloaded into temporary directories for static
inspection only. No code was vendored, no build or benchmark was run, and no
device was used.

| Project | Inspected release / immutable revision | Commit date |
| --- | --- | --- |
| Eclipse iceoryx2 | [v0.10.0](https://github.com/eclipse-iceoryx/iceoryx2/releases/tag/v0.10.0), [`135d09dd8b29f321f1725920d434864c4e512378`](https://github.com/eclipse-iceoryx/iceoryx2/commit/135d09dd8b29f321f1725920d434864c4e512378) | 2026-09-18 |
| NNG | [v1.12.4](https://github.com/nanomsg/nng/releases/tag/v1.12.4), [`d504cf08ae8c87885d3dc07214b47a6b9a95c4bc`](https://github.com/nanomsg/nng/commit/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc) | 2026-08-30 |

“Documented” below means an upstream support/API statement. “Source” means a
static observation of this revision, not execution evidence. Listed CI jobs
establish intended coverage, not that this review independently verified their
latest results. Neither upstream support labels nor Linux ARM64 coverage prove
the Android app/daemon identity, SELinux, lifecycle, or power behavior required
here.

## iceoryx2

### Android is a present blocker, not merely an unmeasured optimization

The release README labels Android a proof of concept limited to inter-thread
communication. Linux x86-64, ARM64 and 32-bit are tier 2; that tier means a
restricted safety/security feature set, not full tier-1 coverage. The Android
development guide supports only `local` and `local_threadsafe`, says the C/C++
bindings are not available yet, and demonstrates a Rust local example using an
x86-64 Android/Waydroid setup. It is not an ARM64 API-31 inter-process acceptance
record. [Platform table](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/README.md#supported-platforms),
[Android guide](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/doc/development-setup/android.md).

There is a concrete source-level reason not to treat Android as ordinary Linux:
the Android PAL implementations of `shm_open` and `shm_unlink` set `ENOSYS` and
return `-1`. The recommended IPC shared-memory and dynamic-storage types select
POSIX shared memory, and the underlying shared-memory builder calls that PAL
interface. Consequently, changing a filesystem path or increasing Android's API
level does not make this pinned implementation into working IPC. An Android
memory backend and its discovery/lifetime integration would be porting work.
[Android PAL](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/iceoryx2-pal/posix/src/android/mman.rs),
[shared-memory selection](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/iceoryx2-cal/src/shared_memory/recommended.rs),
[dynamic-storage selection](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/iceoryx2-cal/src/dynamic_storage/recommended.rs),
[POSIX memory builder](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/iceoryx2-bb/posix/src/shared_memory.rs).

The inspected build/test and nightly workflows contain Linux ARM64 jobs, but no
Android test job. This corroborates the documented gap without asserting that
upstream has never performed a private Android test.
[Build/test workflow](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/.github/workflows/build-test.yml),
[nightly workflow](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/.github/workflows/nightly.yml).

Do not overgeneralize the blocker into “every POSIX primitive is missing.” The
recommended IPC event implementation uses a Unix datagram trigger with
shared-memory counting state. A semaphore alternative exists, but named
semaphores are not the selected event backend. The demonstrated shared-memory
stub and unsupported bindings are sufficient evidence; no claim that every
Android semaphore or robust-mutex limitation is reached on this path is needed.
[Event selection](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/iceoryx2-cal/src/event/recommended.rs),
[event implementations](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/iceoryx2-cal/src/event/implementations.rs).

### C ABI is real, but its send path needs careful qualification

On supported targets the official C package builds against `iceoryx2-ffi-c`;
C++ can be disabled. The Rust FFI crate exports static and dynamic C libraries.
Using that C interface would not require moving packet parsing or policy into
Rust, although it adds a Rust-built library to the producer process. This is a
language-integration possibility, not Android support.
[C build instructions](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/iceoryx2-c/README.md),
[FFI crate](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/iceoryx2-ffi/c/Cargo.toml).

The stock C binding aliases its IPC service to `ipc_threadsafe::Service`.
That service uses `MutexProtected`, implemented with a process-local recursive
POSIX mutex. Publisher loans take that policy's lock. Thus the framework's
lock-free inter-process data structures do **not** imply that the stock C
publisher API is mutex-free. A publisher confined to one VPP owner can reduce
contention, but does not erase those calls.
[C service alias](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/iceoryx2-ffi/c/src/api/service.rs#L51),
[thread-safe IPC service](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/iceoryx2/src/service/ipc_threadsafe.rs),
[mutex policy](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/iceoryx2-cal/src/arc_sync_policy/mutex_protected.rs).

The C loan function accepts caller-owned `iox2_sample_mut_t` storage. Passing
`NULL`, as the simple C example does, allocates the sample wrapper on the heap.
Supplying storage avoids that particular allocation; it is not proof that every
subsequent operation is allocation-free.
[C loan implementation](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/iceoryx2-ffi/c/src/api/publisher.rs#L585),
[basic C publisher](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/examples/c/publish_subscribe/src/publisher.c).

Variable-sized slices are supported. A configured maximum slice length with
`AllocationStrategy::Static` rejects larger loans; growth strategies should not
be confused with a fixed memory ceiling. Sending also checks connection changes
and may establish new connections, rather than always executing only the
steady-state queue path. The connection constructor builds names and opens or
creates connection resources with a configured creation timeout. Subscriber
restart is therefore an explicit producer-path case to investigate.
[Publisher implementation](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/iceoryx2/src/port/publisher.rs),
[connection construction](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/iceoryx2/src/port/details/sender.rs#L90).

### Queue semantics and mobile wake behavior

The configuration independently limits publishers, subscribers, queue depth,
loaned/borrowed samples and history. Safe overflow replaces the oldest queued
sample; disabling it exposes the backpressure strategy. At this revision the
defaults enable overflow but set the alternate strategy to
`RetryUntilDelivered`. For this task, explicitly choosing `DiscardData` matters
if overflow is disabled: retrying until Rust makes space violates the required
producer contract. Loan exhaustion and oversized records must also drop or be
rejected locally. Sequence/generation fields would still be needed to make
loss and restart visible to the Rust consumer.
[Configuration](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/iceoryx2/src/config.rs#L315),
[backpressure strategies](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/iceoryx2/src/port/backpressure_strategy.rs).

The core documents no background threads. It performs connection work through
ports and explicit updates. Plain publish/subscribe does not itself prescribe
the application's sleeping schedule: the event-based example combines a
publisher/subscriber with separate notifier/listener objects and a waitset.
Its receipt events are example policy, not a requirement to add ACKs here.
[Lifecycle FAQ](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/FAQ.md#losing-data),
[event-based publisher example](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/examples/rust/event_based_communication/publisher.rs).

In v0.10.0 the event layer coalesces triggers through shared notification state;
already-notified state avoids another socket trigger. The Unix datagram trigger
uses a nonblocking send and provides blocking/timed receiver waits. Therefore
neither mandatory busy-polling nor one wake syscall per record is a fair
description of this version. Conversely, source-level coalescing does not
establish Android battery savings, and these IPC event types still depend on
the unsupported Android shared-memory backend.
[Coalescing state machine](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/iceoryx2-cal/src/event/common.rs#L310),
[Unix datagram trigger](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/iceoryx2-cal/src/event/trigger/unix_datagram_socket.rs).

## NNG

### Android has an upstream path, with limited evidence

The stable README lists Android and Linux and describes a C99 implementation.
Its Android guide gives an NDK/CMake route but explicitly qualifies Android
testing as cursory. The pinned workflows include Linux, Darwin and Windows;
there is no Android workflow in that directory. This is stronger platform
evidence than iceoryx2's local-only Android prototype, but it is not an API-31
ARM64 phone acceptance result.
[Stable README](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/README.adoc),
[Android build guide](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/docs/BUILD_ANDROID.adoc),
[workflow directory](https://github.com/nanomsg/nng/tree/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/.github/workflows).

Android CMake explicitly selects the POSIX/Linux implementation and eventfd.
Feature checks select epoll when available. The IPC transport uses Unix-domain
`SOCK_STREAM` sockets with NNG framing; its selected path does not require
POSIX named shared memory or named semaphores. However, the Android CMake branch
does **not** define `NNG_HAVE_ABSTRACT_SOCKETS`, whereas the Linux branch does.
The abstract transport is compiled conditionally on that macro. Do not promise
`abstract://` on stock Android builds merely because Android's kernel supports
abstract Unix sockets.
[Platform configuration](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/CMakeLists.txt#L209),
[POSIX checks](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/src/platform/posix/CMakeLists.txt),
[IPC listener](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/src/platform/posix/posix_ipclisten.c),
[transport registration](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/src/sp/transport/ipc/ipc.c#L1148).

For `ipc://`, a filesystem socket needs a path both processes can access.
NNG provides IPC permission and peer-credential options, but it cannot establish
that the product's Android identities and SELinux policy permit the connection.
Path ownership, cleanup and restart must be tested in the real deployment.
[IPC manual](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/docs/man/nng_ipc.7.adoc).

### NONBLOCK is not an allocation-free or mutex-free worker contract

`nng_send` allocates an NNG message and copies the caller's bytes before sending.
`nng_sendmsg` can take an already constructed message, but successful submission
transfers ownership to NNG, so the producer cannot immediately reuse that same
storage. On failure the caller retains ownership. `NNG_FLAG_NONBLOCK` reports
`NNG_EAGAIN` when the chosen protocol cannot accept the message; a successful
return is not proof of Rust delivery.
[Send implementation](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/src/nng.c#L162),
[sendmsg contract](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/docs/man/nng_sendmsg.3.adoc).

The synchronous `nng_sendmsg` wrapper initializes an AIO object, sets a zero
timeout for NONBLOCK, submits it and calls `nni_aio_wait` for completion. Socket
lookup/release takes a global mutex, and protocols take their own mutexes.
Therefore NONBLOCK removes the wait for peer capacity, not all internal
scheduling or lock costs. Reusing a preallocated asynchronous AIO avoids the
synchronous wrapper pattern but does not remove protocol locking or message
ownership management. These are source observations, not measured worst-case
execution times.
[Synchronous wrapper](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/src/nng.c#L183),
[socket lookup](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/src/core/socket.c#L371),
[AIO send API](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/docs/man/nng_send_aio.3.adoc).

This suggests evaluating NNG first at a control/export boundary that can tolerate
its local scheduling costs. If protecting the worker requires a separate bounded
queue and export thread, NNG has not removed that part of the design; its benefit
would be framing, connection lifecycle and a simple Rust-facing message API.
Using its C ABI from Rust is sufficient; a packet-domain rewrite or C++ wrapper
is unnecessary. This is an integration inference from the API, not a tested
binding recommendation.

### Bounded messages, loss visibility and two-channel isolation

NNG accepts variable-sized messages. `NNG_OPT_SENDBUF` and `NNG_OPT_RECVBUF`
configure counts, not byte budgets; `NNG_OPT_RECVMAXSZ` caps accepted message
size. Configure both a record-size maximum and finite queue counts, then account
for in-flight and kernel socket buffers as well. The IPC receiver allocates a
message after parsing its length; oversized messages fail the pipe in this
implementation, so sender-side size enforcement avoids turning expected debug
truncation into reconnect work.
[Buffer and size options](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/docs/man/nng_options.5.adoc),
[IPC receive allocation and size check](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/src/sp/transport/ipc/ipc.c#L377).

Protocol choice materially changes loss reporting:

- **PUB/SUB:** the publisher sends to its connected subscribers, takes a socket
  mutex, and if a busy peer's queue is full removes the oldest queued message
  before admitting the new one. With no peers it still completes successfully.
  Send success consequently cannot serve as an export-delivery or drop counter.
  PUB's send-buffer setting is 1–8192 in this implementation, despite the generic
  option's 0–8192 range. A topic prefix also does not create independently sized
  normal/debug queues.
  [PUB implementation](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/src/sp/protocol/pubsub0/pub.c#L226).
- **PAIR0:** describes a one-to-one connection and normally applies backpressure.
  Combining it with NONBLOCK makes refusal visible as a local send failure,
  while preserving the rule that acceptance is not an ACK from Rust. It is a
  simpler candidate for one producer endpoint and one consumer than inventing
  a request/reply protocol. Multiple VPP workers and contention still require
  an explicit ownership/topology choice.
  [PAIR manual](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/docs/man/nng_pair.7.adoc).

For this product, separate sockets/endpoints would be the candidate mechanism
for normal/debug queue budgets, with application generation/sequence numbers
and local admission/drop accounting. They would still share NNG's process-wide
runtime and some locks: separate message buffers do not prove complete CPU or
scheduling isolation.

### Mobile idle cost is a runtime question, not a latency slogan

The inspected POSIX initialization eagerly starts its poller and DNS resolver
subsystems; the core then initializes task, reaper and AIO-expiration subsystems.
This occurs even if the application only intends to use local IPC. The default
resolver implementation starts four threads.
[POSIX initialization](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/src/platform/posix/posix_thread.c#L396),
[core initialization](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/src/core/init.c#L36),
[resolver implementation](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/src/platform/posix/posix_resolv_gai.c#L480).

Task threads default to twice the reported CPU count, capped at 16, with at least
two. Expiration threads default to the CPU count, capped at eight, with at least
one. The epoll implementation creates one global poller. These are source
defaults, **not** a measured phone thread count or RSS figure. Compile-time
settings can reduce pools; the runtime tuning function in the header explicitly
sits outside the API stability promise, so it should not become a hidden
correctness dependency.
[Task pool](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/src/core/taskq.c#L246),
[expiration pool](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/src/core/aio.c#L851),
[tuning caveat](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/include/nng/nng.h#L1471).

The poller blocks in `epoll_wait(..., -1)`. Task workers wait on a condition
variable, and expiration workers wait for their next deadline. This is evidence
against describing NNG as inherently busy-polling; it is not evidence of zero
idle energy. Disconnected dialers can create recurring reconnect work, whereas
listeners do not use reconnect timers. A mobile evaluation should cover a
connected idle consumer and an absent/restarting consumer separately.
[Epoll wait](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/src/platform/posix/posix_pollq_epoll.c#L244),
[task wait](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/src/core/taskq.c#L30),
[expiration wait](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/src/core/aio.c#L580),
[reconnect options](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/docs/man/nng_options.5.adoc#NNG_OPT_RECONNMINT).

## Maintenance, integration cost and remaining evidence

iceoryx2 is dual Apache-2.0 OR MIT and NNG is MIT. Both have recent inspected
releases. iceoryx2 v0.10.0 also lists API changes, including its event API; NNG's
current development README directs production users toward the stable branch
and describes an upcoming major API migration. Pin the chosen release and its
bindings instead of relying on moving documentation. Release activity is
maintenance evidence, not an assurance about future support.
[iceoryx2 manifest](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/Cargo.toml),
[iceoryx2 release notes](https://github.com/eclipse-iceoryx/iceoryx2/releases/tag/v0.10.0),
[NNG license](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/LICENSE.txt),
[NNG development README](https://github.com/nanomsg/nng/blob/96cc729b3009015bc3b1e899cab2ccd3f2bb1b36/README.md).

The research recommendation is to keep the comparison small:

1. Do not spend a product POC proving iceoryx2's Linux benchmark numbers while
   its documented Android IPC and C-binding gaps remain. Reopen it when a pinned
   upstream version supplies those capabilities, or when maintaining a platform
   port is explicitly justified.
2. Consider NNG only if its message API and connection management remove enough
   application work to justify its pools, locks and allocations. Compare a
   deliberately reduced configuration with the direct OS transport candidate;
   neither is presumed faster or cheaper here.
3. Any later experiment should include normal-only idle, debug disabled, burst
   export, full queues, Rust stalled/absent, crash/restart and load-to-idle return.
   Record worker publish cost, total CPU, wakeups, context switches, thread/fd
   counts and steady/peak memory on ARM64 phones. Use bounded records and
   explicitly count loss. No application ACK or retry loop may hold packet work.

These are evaluation questions, not newly accepted performance gates. This
report establishes no Android build success, delivery correctness, p99 result,
CPU reduction, power saving or final transport choice.
