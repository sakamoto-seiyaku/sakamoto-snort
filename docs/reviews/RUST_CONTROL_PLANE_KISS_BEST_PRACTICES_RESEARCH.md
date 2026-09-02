# Rust Control Plane KISS recovery-scope research

Date: 2026-08-26

Status: decision input for Wayfinder map `SAKAMOTO-163`; this report does not make the scope decision.

## Question

What is the smallest product-shaped Rust Control Plane worth restoring now, given the accepted Android/Tauri/VPP boundaries and the scoped Rust/VAPI POCs?

## Short answer

The evidence supports a firm separation between a reusable **Rust product core** and a thin **Tauri shell**.

```text
Tauri UI / commands
        |
versioned product-control interface
        |
Android RuntimeService-side host
        |
Rust product core + one Product Store writer
        |
one serialized persistent VPP control client
        |
versioned non-unwinding C ABI -> generated VAPI -> VPP binary API
```

On Android, the Activity-loaded Tauri library is not the lifetime owner of protection or durable product state. The RuntimeService side hosts the Local Product Backend/product core and remains authoritative while the Activity/WebView is absent. On Linux later, the same core may be hosted in the normal Tauri product process. This is an architectural layer boundary; the exact crate count, JNI/Binder shape, and process placement remain later Module/seam decisions.

This follows accepted [ADR-0002](../adr/0002-tauri-android-runtime-service-boundary.md), [ADR-0006](../adr/0006-vpp-native-packet-io-adapters.md), and the [Product UI/backend boundary](../product/ANDROID_L4_PRODUCT_PLAN.md). Tauri itself documents that mobile builds compile the Rust entry point as a library loaded by platform frameworks, while Android native integration uses a generated Kotlin plugin/library bridge; neither mechanism supplies Android Service lifecycle ownership ([Tauri project structure](https://v2.tauri.app/start/project-structure/), [Tauri mobile plugins](https://v2.tauri.app/develop/plugins/develop-mobile/)). Android documents that a started Service has a lifecycle independent of the Activity, can also expose a bound IPC interface, and still requires blocking work off its process main thread ([Android Services overview](https://developer.android.com/develop/background-work/services)).

## Evidence baseline and limits

- Current HEAD has no product `Cargo.toml`, workspace, Rust product-core crate, or Tauri backend. Product authoring/persistence/projection semantics currently survive mainly in the Java `LocalProductBackend`, `ProductStore`, and policy transaction classes. The completed Wayfinder capability/asset inventories record this as a current-head gap, not as evidence that a product Rust control plane already exists.
- Scoped POCs prove `Rust -> thin C ABI -> generated VAPI -> VPP binary API`, typed status/mutation, one opaque persistent handle, failure of a stale handle after VPP stop, fresh-handle recovery after restart, serialized access through a mutex, and a minimal stage/rollback/commit operation. See [POC_STATUS](../../experiments/vpp-nfq-poc/POC_STATUS.md) and the [persistent](../../experiments/vpp-nfq-poc/clients/tun_poc_rust_persistent.rs), [reconnect](../../experiments/vpp-nfq-poc/clients/tun_poc_rust_reconnect.rs), and [serialized](../../experiments/vpp-nfq-poc/clients/tun_poc_rust_serialized.rs) probes.
- Those POCs do **not** prove a stable product ABI, final compiled policy schema, automatic reconnect/backoff, concurrent VAPI calls, cancellation, in-flight mutation recovery, command replay, Tauri integration, packaging, or durable product transactions.
- VPP documents generated high-level C bindings, context-based request/reply matching, and blocking/non-blocking client modes. In blocking mode, a request waits for its response and the outstanding queue contains at most one request; non-blocking mode requires explicit dispatch or a dedicated dispatch thread ([VPP API module](https://docs.fd.io/vpp/21.10.0/gettingstarted/developers/vpp_api_module.html)). This supports generated VAPI and a serialized owner, but does not itself prove thread-safe concurrent calls or application-level idempotency.
- A VPP request `context` matches a reply to a request; it is not documented as a durable operation ID or proof that an acknowledged-lost mutation did or did not execute. Treating a disconnect after send as an outcome-unknown mutation is therefore a project inference, not a VPP guarantee ([VPP API language](https://docs.fd.io/vpp/25.02/interfacing/binapi/vpp_api_language.html), [VPP Python API assumptions](https://github.com/FDio/vpp/wiki/VPP-Python_API)).

## KISS candidate scope

### Must restore

1. **A minimal Cargo workspace and product-core build/test lane.** Start with one reusable core library and add boundary crates only where a distinct artifact or unsafe ABI boundary requires it; do not pre-split into a crate per domain concept. Cargo workspaces provide one lockfile, shared output, common commands, dependency/lint/profile inheritance, and explicit member selection ([Cargo workspaces](https://doc.rust-lang.org/cargo/reference/workspaces.html)).

2. **A Tauri-independent Rust product core.** It owns product/domain state transitions, validation, policy authoring/compile orchestration, persistence interfaces, runtime intent, product projections, and stable error mapping. Core code must not depend on `tauri::State`, WebView lifetime, Activity callbacks, Binder classes, or generated VAPI types. Tauri commands and Android native bridges delegate to the same product-facing interface.

3. **RuntimeService-side Android hosting.** Android keeps one lifecycle authority. The service-side host owns the Local Product Backend, telemetry consumer, and single Product Store writer; the Tauri Activity is a reconnectable client. Kotlin/Java retains platform-only duties such as Service/VpnService lifecycle, permission/TUN/protect operations, notification, and platform IPC. Rust does not become a second runtime supervisor.

4. **One typed, persistent, serialized VPP client owner.** Rust owns one control session per active runtime generation. A narrow C shim owns generated VAPI details and exposes an ABI version, opaque handle, fixed-width request/result structures, and explicit transport/protocol/VPP-return status. Calls remain serialized until stronger evidence justifies concurrency. A stale handle is retired; reconnect creates a fresh handle only after RuntimeService readiness identifies a fresh runtime generation.

5. **A coarse, non-unwinding Rust/C boundary.** Expected failures return explicit values; packet bytes and live VPP buffers never cross. Rust `#[repr(C)]` is the relevant layout tool for C-compatible structures, while opaque C objects should remain opaque Rust types ([Rust type layout](https://doc.rust-lang.org/reference/type-layout.html), [Rustonomicon opaque FFI types](https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs)). Rust panic or foreign exceptions must not unwind across a non-unwind ABI; ordinary failures use `Result`/status values, not panic ([Rustonomicon FFI and unwinding](https://doc.rust-lang.org/nomicon/ffi.html#ffi-and-unwinding), [`catch_unwind`](https://doc.rust-lang.org/std/panic/fn.catch_unwind.html)). Exact `panic=abort` versus a tested outer catch-and-poison policy is an implementation decision, but continuing with possibly broken mutable control state is not.

6. **Transactional full-snapshot publication.** Rust retains one authoritative Authoring Policy Bundle and implements the accepted `Draft -> Commit -> Apply -> Checkpoint + Runtime Snapshot` semantics. Apply validates and compiles a complete immutable successor, publishes one revision/generation transactionally, and confirms the active revision by typed status. No partial stage table becomes visible and no rule-by-rule hot mutation is a product path. The durable rules are fixed by [ADR-0001](../adr/0001-policy-bundle-staged-enforcement.md) and [NFQUEUE datapath boundaries §5.3](../decisions/NFQUEUE_DATAPATH_MODULE_BOUNDARIES.md).

7. **Outcome-unknown mutation fencing.** Every mutation carries a stable requested revision or operation identity and an expected predecessor where applicable. If transport fails after submission but before a trustworthy reply, Rust returns `OUTCOME_UNKNOWN`, stops issuing dependent mutations on that generation, reconnects with a fresh handle, reads active status/revision, and reconciles before any retry. It never automatically replays an unknown mutation. This is required project behavior inferred from the POC's stale-handle boundary and VPP's request/reply mechanics; the current POC did not implement it.

8. **One service-side Product Store writer.** Rust/product core is the durable authority for policy/configuration and bounded Activity persistence. The first version uses one embedded store and one writer, with distinct repository/table semantics for authoritative policy/config and lossy bounded Activity. VPP owns only the active in-memory Runtime Snapshot and exports facts/status; it does not write the product database. This is a project requirement from [Product Store terminology](../../CONTEXT.md) and [ADR-0002](../adr/0002-tauri-android-runtime-service-boundary.md), not a generic Tauri or VPP rule.

9. **Stable status and error projection.** The core exposes bounded product-facing state that preserves at least: runtime generation/artifact/ABI identity; connection state; active versus requested policy revision; mutation outcome (`SUCCEEDED`, `FAILED_DEFINITE`, `OUTCOME_UNKNOWN`); stable error code/category; recoverability; and a short diagnostic detail. Transport/shim failure, VPP `retval`, validation/compile failure, runtime health, and policy verdict remain distinct. UI receives projections, not raw VAPI structures or CLI text.

### Defer unless a recovery slice proves need

- Full Product UI, broad Tauri command catalog, and presentation polish beyond the smallest adapter needed to exercise product-core state.
- Async/non-blocking VAPI, concurrent calls on one context, connection pools, multiple control agents, speculative cancellation, and command batching.
- General retry/backoff frameworks. Start with explicit generation-bound reconnect and reconciliation for the few required operations.
- Multiple physical databases, database services, event sourcing, cloud/account sync, multi-writer replication, or an analytics pipeline.
- Dynamic plugin/provider frameworks, runtime-loaded Rust control modules, and broad generated VPP bindings in Rust.
- Release migration/backup matrix, high-cardinality analytics, long soak, and multi-device/OEM certification; preserve version fields and deterministic fixtures now so these can be added later.

### Reject for this architecture

- Tauri Activity/WebView, frontend state, or a mobile plugin as Android protection lifecycle owner or authoritative policy/history store.
- Two policy writers (for example Java and Rust stores), direct UI-to-VAPI calls, or VPP as the durable product database.
- CLI output parsing as product control, per-command reconnect, or generated VAPI structures exposed directly to product/core APIs.
- Concurrent use of one VAPI context without evidence, transparent reconnect that preserves a stale handle, or automatic replay of an outcome-unknown mutation.
- Per-packet Rust/C calls, Rust-owned live VPP buffers, packet payload over Binder/Tauri IPC, or restoration of superseded Rust-in-VPP packet paths.
- Panic/exception unwinding across the C ABI or treating panic as ordinary recoverable control error.
- Persisting compiled Runtime Snapshot tables as source authority, partial publication of stage views, or separate independently applied policy databases per enforcement stage/Profile.

## Narrow decision prompts

The scope ticket can now decide, without designing exact Modules:

1. Accept or reject the `product-core` / Tauri-shell separation and RuntimeService-side Android hosting.
2. Select which must-restore items above belong to recovery parity versus a later product slice.
3. Confirm that serialized persistent VAPI, fresh-generation reconnect, outcome-unknown fencing, one Product Store writer, and atomic full-snapshot publication are recovery requirements rather than optional refinements.

Exact crate names/count, command schema, JNI/Binder shape, store engine, ABI structs, and snapshot wire format belong to the later Module/seam decision.
