# VPP / Tauri Control Plane Discussion TMP

Date: 2026-06-29
Status: temporary discussion note, not ADR, not interface spec

## Question

If Sakamoto Snort moves the packet runtime to VPP, how should a Tauri-based app
interact with VPP without adding unnecessary extra control-plane layers?

The discussion intentionally does not assume the current vNext socket surface is
the final shape. It focuses on the simpler architecture after a VPP pivot.

## Short Conclusion

Tauri should not control VPP through a custom JSON daemon layer or by scripting
VPP CLI as the product API.

Recommended shape:

```text
Tauri UI
  -> Tauri Rust backend
  -> thin C ABI shim
  -> VPP binary API / VAPI generated client
  -> Sakamoto VPP plugin
  -> TUN / HEV / NFQUEUE datapath
```

VPP is the dataplane runtime. The Tauri Rust backend is the product control
plane. Any extra daemon/control socket between them needs a concrete reason.

## API Choice

Use VPP binary API / VAPI for production control.

Use VPP CLI only for:

- local development;
- debug commands;
- emergency diagnostics;
- manual inspection.

Do not make product features depend on parsing CLI output or building CLI
strings. CLI is a human interface. VPP binary API is the intended control-plane
message API.

## Rust Boundary

The lowest-maintenance Rust boundary is a small C shim over generated VPP API
headers, not direct bindgen over all VPP internals.

Example shape:

```c
int sk_vpp_connect(const char *api_socket);
int sk_vpp_policy_replace(const uint8_t *blob, size_t len, uint64_t epoch);
int sk_vpp_policy_commit(uint64_t epoch);
int sk_vpp_policy_rollback(uint64_t epoch);
int sk_vpp_stats_get(struct sk_vpp_stats *out);
```

Rust owns product state, validation, persistence, rule authoring, and UI-facing
commands. C only adapts Rust to VPP's generated API/client ABI.

## VPP Plugin Boundary

Do not expose VPP graph internals to the UI.

The Sakamoto VPP plugin should expose a small product-level API:

```text
sakamoto_runtime_start(...)
sakamoto_runtime_stop(...)
sakamoto_policy_replace(epoch, compiled_policy_blob)
sakamoto_policy_commit(epoch)
sakamoto_policy_rollback(epoch)
sakamoto_stats_get(...)
sakamoto_diag_start(filter)
sakamoto_diag_stop(session_id)
```

The compiled policy blob is the main simplifier. UI rules should not be mapped
one-by-one to VPP CLI commands or many low-level VPP API calls. Tauri/Rust
compiles product policy into a runtime snapshot; VPP atomically swaps that
snapshot into the datapath.

## Android VPN Boundary

Android still needs a small platform owner layer. This is not optional because
these capabilities live in Android framework APIs:

- `VpnService` creates and owns the TUN fd;
- `protect()` prevents upstream sockets from looping back into the VPN;
- `ConnectivityManager.getConnectionOwnerUid()` provides best-effort tuple to
  UID attribution for TCP/UDP traffic.

Recommended Android VPN shape:

```text
Tauri UI
  -> Rust controller
  -> Android VpnService owns tun-fd / protect / owner lookup bridge
  -> VPP runtime receives fd(s) and resolver bridge
  -> Rust applies policy through VPP API
```

The Android layer should not own allow/drop policy. It should provide platform
facts and fds. VPP should own packet verdicts.

## Root / NFQUEUE Boundary

Root mode can be simpler:

```text
Tauri UI
  -> Rust controller
  -> root-launched VPP process
  -> Rust controls VPP through binary API socket
  -> VPP plugin owns NFQUEUE packet verdicts
```

Here the VPP process is not an extra business backend. It is the packet runtime.

## Telemetry And Status

Start simple:

- low-frequency status: Rust calls VPP API;
- counters: use VPP stats segment or a small custom stats API;
- UI updates: Rust aggregates state and emits Tauri events;
- high-frequency flow history: add mmap/ring only when product requirements
  prove that polling stats is insufficient.

Do not introduce a general event bus before there is a concrete consumer and
backpressure model.

## What To Avoid

Avoid this shape unless a future constraint proves it necessary:

```text
Tauri UI
  -> Tauri Rust
  -> custom JSON control daemon
  -> daemon translates to VPP CLI
  -> VPP
```

That adds protocol translation, lifecycle ownership, error mapping, and test
surface without improving the core datapath design.

Also avoid putting Android framework calls directly in VPP graph nodes. Use a
bounded resolver bridge/cache. UID attribution can fail and must preserve
`uidKnown=false` instead of guessing.

## Current Recommendation

Design the VPP pivot around three components:

1. Tauri Rust backend as the product control plane.
2. Sakamoto VPP plugin as the packet runtime API and datapath implementation.
3. Minimal Android platform bridge for `VpnService`, fd handoff, `protect()`,
   and tuple-to-UID lookup.

This keeps the architecture small while still respecting the hard boundary
between product UI, platform ownership, and packet verdict execution.

## Open Questions

- Should VPP run as a child process owned by the app, or as a root/service-owned
  runtime depending on mode?
- Should Android fd handoff use fixed inherited fd numbers for the first cut, or
  a Unix domain bootstrap socket with `SCM_RIGHTS` from day one?
- What is the minimal compiled policy blob format for the first VPP plugin API?
- Are diagnostics initially API-polled counters, or does the first product slice
  require a bounded diagnostic event stream?
