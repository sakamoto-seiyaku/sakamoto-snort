# VPP NFQUEUE POC Notes

Status: living notes for this throwaway experiment.

For raw chronological execution notes, see `EXPERIMENT_LOG.md`.

For the Android ARM multiarch conclusion, see `ANDROID_ARM_MULTIARCH_MEMO.md`.

## 2026-06-21 Baseline

The plain C NFQUEUE smoke layer is viable inside Docker after adding:

```text
--cap-add NET_ADMIN
--cap-add NET_RAW
--cap-add SYS_ADMIN
--security-opt apparmor=unconfined
--security-opt seccomp=unconfined
```

`SYS_ADMIN` is needed for `ip netns add` in Docker. Without it, setup failed with:

```text
mount --make-shared /run/netns failed: Operation not permitted
```

Smoke results:

```text
accept-all:     ping 20/20, seen=20 accept=20 drop=0
drop-all:       ping 0/20,  seen=20 accept=0  drop=20
drop-ratio=50:  ping 10/20, seen=20 accept=10 drop=10
idle-cpu:       nfq-smoke sampled at 0.0% CPU before and after traffic
```

Observed NFQUEUE metadata:

```text
packet_id: present
hook: present, value 3 for OUTPUT
hwproto: 0x0800
payload_len: present, 84 bytes for ICMP echo request
outdev: present; concrete value depends on container network setup
uid/gid: present, both 0 because ping runs as root in the container
timestamp: not present with current queue configuration
```

This validates the Linux/Docker NFQUEUE harness. It does not validate VPP yet.

## VPP Adapter Direction

The next POC should patch upstream VPP `v26.02` with a minimal Linux-only plugin:

```text
src/plugins/nfqueue_poc/
  CMakeLists.txt
  nfqueue_poc.h
  main.c
  input.c
  verdict.c
```

Use `add_vpp_plugin()` and keep it CLI-only. No `.api` file is needed for the first slice.

The first VPP slice may verdict directly in the NFQUEUE callback:

```text
NFQUEUE fd ready
  -> VPP input node drains recv(..., MSG_DONTWAIT)
  -> nfq_handle_packet()
  -> callback reads packet id and metadata
  -> callback sends NF_ACCEPT / NF_DROP
```

This proves VPP can host the fd/input lifecycle and verdict path before building a full graph packet processor.

The second VPP slice can allocate `vlib_buffer_t` and pass a buffer through a minimal verdict node.

## Do Not Copy

From local `/home/js/backup/backup/Git/vpp/src/plugins/stellar_netfilter_queue_deprecated/`, reuse only the libnetfilter_queue open/config/recv/verdict mechanics.

Do not copy:

- hardcoded worker index;
- permanent `VLIB_NODE_STATE_POLLING`;
- disabling other workers;
- fake Ethernet header as the default path;
- L2 xconnect-to-self trick;
- edits to VPP core buffer headers;
- global buffer free callback for DROP fallback;
- assumptions that NFQUEUE packet id is never zero.

## Idle CPU Requirement

The VPP plugin must keep the input node in interrupt/fd-ready mode.

Target shape:

```text
nfq_fd O_NONBLOCK
  -> clib_file_add()
  -> read callback marks rx queue interrupt pending
  -> input node drains fd to EAGAIN
  -> returns to epoll sleep when idle
```

The plugin must not set the node to permanent polling just to make NFQUEUE work.

## Next Checkpoint

VPP `v26.02` now builds successfully in the Docker lane, and the first Linux-only NFQUEUE plugin POC can return verdicts.

Next steps:

1. Decide whether the next slice should stay as direct callback verdict or move packet ownership into `vlib_buffer_t`.
2. Add packet metadata extraction to the VPP-side POC: packet id, hook, ifindex, mark, UID/GID, payload length.
3. Design the handoff from NFQUEUE fd-ready input into graph processing without turning the node into permanent polling.
4. Re-check idle CPU and verdict behavior after the graph/buffer slice.

## VPP Source / Build Policy

VPP source and build output stay inside the experiment directory but outside git tracking by default:

```text
experiments/vpp-nfq-poc/work/vpp
```

Fetch command:

```sh
DOCKER_NETWORK=bridge ./scripts/run-container.sh make fetch-vpp
```

Build command:

```sh
DOCKER_NETWORK=bridge DOCKER_CAP_PROFILE=default ./scripts/run-container.sh env VPP_INSTALL_DEPS=1 JOBS=4 make build-vpp
```

Do not commit the VPP source tree or build output. `work/` is ignored. If later we need a plugin patch, keep it as a small patch or source overlay under this experiment directory.

Installed binary after a successful build:

```text
experiments/vpp-nfq-poc/work/vpp/build-root/install-vpp-native/vpp/bin/vpp
```

Installed plugin example:

```text
experiments/vpp-nfq-poc/work/vpp/build-root/install-vpp-native/vpp/lib/x86_64-linux-gnu/vpp_plugins/snort_plugin.so
```

Host version check:

```sh
/usr/bin/timeout 5s experiments/vpp-nfq-poc/work/vpp/build-root/install-vpp-native/vpp/bin/vpp -v
```

## Minimal Startup / Idle CPU

Minimal startup config:

```text
experiments/vpp-nfq-poc/configs/minimal-startup.conf
```

The config disables runtime plugins by default and sets:

```text
buffers { page-size default }
unix { poll-sleep-usec 1000 }
```

`buffers { page-size default }` avoids hugepage prealloc/fallback noise in this host experiment. `poll-sleep-usec 1000` reduces no-traffic idle CPU from roughly 3% to roughly 1% instantaneous CPU for the main VPP thread on this host.

Run:

```sh
make vpp-idle-cpu
```

Current observed result:

```text
vpp_main idle instantaneous CPU: about 1% on this host
```

This is not yet the final answer for the NFQUEUE adapter. Re-check after the fd-ready NFQUEUE input node is enabled.

## NFQUEUE Plugin Verdict POC

Local overlay:

```text
experiments/vpp-nfq-poc/overlay/src/plugins/nfqueue_poc/
```

Current shape:

```text
nfqueue-poc enable queue 42 mode accept-all|drop-all|drop-ratio <n>
  -> nfq_open / nfq_bind_pf / nfq_create_queue
  -> nfq_fd registered with clib_file_add
  -> read callback drains recv(..., MSG_DONTWAIT)
  -> nfq_handle_packet invokes callback
  -> callback calls nfq_set_verdict(packet_id, NF_ACCEPT|NF_DROP)
```

Observed result:

```text
accept-all:     ping 20/20, seen=20 accept=20 drop=0
drop-all:       ping 0/20,  seen=20 accept=0  drop=20
drop-ratio=50:  ping 10/20, seen=20 accept=10 drop=10
idle enabled:   vpp_main sampled around 0-2% CPU with queue enabled and no traffic
```

This answers the first Linux question positively: upstream VPP can be adapted to own an NFQUEUE fd and return verdicts without busy polling in this minimal form.

Open limitations:

```text
No VPP interface yet.
No vlib_buffer_t allocation yet.
No VPP graph processing yet.
No UID/GID/ifindex metadata extraction in the VPP plugin yet.
No worker handoff or multi-worker behavior yet.
No Android/VPN/TUN path yet.
```

## TUN POC Binary API Status

Local overlay:

```text
experiments/vpp-nfq-poc/overlay/src/plugins/tun_poc/
  tun_poc.api
  tun_poc_api.c
```

Raw VPP API references used for this slice:

```text
work/vpp/src/plugins/arping/arping.api
work/vpp/src/plugins/arping/arping_api.c
work/vpp/src/plugins/af_packet/af_packet.api
work/vpp/src/plugins/af_packet/af_packet_api.c
work/vpp/src/vpp-api/python/vpp_papi/vpp_papi.py
work/vpp/src/vpp-api/python/vpp_papi/vpp_transport_socket.py
```

Observed VPP plugin API pattern:

```text
add_vpp_plugin(... API_FILES <plugin>.api ...)
include <plugin>/<plugin>.api_enum.h
include <plugin>/<plugin>.api_types.h
include <plugin>/<plugin>.api.c
setup_message_id_table()
VLIB_API_INIT_FUNCTION(...)
```

Current status API:

```text
tun_poc_status -> tun_poc_status_reply

Fields:
  enabled, mode
  rx_packets, tx_packets, shim_tx_packets, blocked_packets
  tuple_parsed_packets
  resolver_queries, resolver_hits, resolver_errors
  owner_cache_hits, owner_cache_misses, owner_cache_stores
  uid_blocked_packets
  last_owner_uid
```

Current mutation API:

```text
tun_poc_owner_policy_set -> tun_poc_owner_policy_set_reply

Fields:
  owner_cache_enabled
  block_owner_uid_set
  block_owner_uid
```

Run:

```sh
CCACHE_DIR=/tmp/ccache make vpp-tun-poc-build
make vpp-tun-poc-api-status-smoke
make vpp-tun-poc-api-policy-smoke
make vpp-tun-poc-api-policy-transaction-smoke
make vpp-tun-poc-vapi-c-status-smoke
make vpp-tun-poc-rust-shim-status-smoke
make vpp-tun-poc-rust-shim-policy-smoke
make vpp-tun-poc-rust-shim-sdk-smoke
make vpp-tun-poc-rust-shim-persistent-smoke
make vpp-tun-poc-rust-shim-reconnect-smoke
make vpp-tun-poc-rust-shim-serialized-smoke
```

Observed result:

```text
tun_poc_status reply:
  retval=0
  enabled=0 mode=0
  counters rx=0 tx=0 shim_tx=0 blocked=0
  owner queries=0 hits=0 cache_enabled=0 cache_hits=0 block_uid_set=0 block_uid=-1 uid_blocks=0 last_uid=-1

tun_poc_owner_policy_set reply:
  retval=0
tun_poc_status after mutation:
  owner_cache_enabled=1 block_owner_uid_set=1 block_owner_uid=4242

tun_poc_owner_policy transaction via binary API:
  stage retval=0
  after_stage active owner_cache_enabled=0 block_owner_uid_set=0 block_owner_uid=-1
  rollback retval=0
  after_rollback active owner_cache_enabled=0 block_owner_uid_set=0 block_owner_uid=-1
  commit retval=0
  after_commit active owner_cache_enabled=1 block_owner_uid_set=1 block_owner_uid=4242

tun_poc_status via VAPI C:
  enabled=0 mode=0 retval=0
  counters rx=0 tx=0 shim_tx=0 blocked=0
  owner cache_enabled=0 block_uid_set=0 block_uid=-1 last_uid=-1

tun_poc_status via Rust FFI shim:
  enabled=0 mode=0 retval=0
  counters rx=0 tx=0 shim_tx=0 blocked=0
  owner cache_enabled=0 block_uid_set=0 block_uid=-1 last_uid=-1

Rust FFI policy smoke:
  tun_poc_owner_policy_set via Rust FFI shim:
    retval=0
  tun_poc_status after Rust FFI mutation:
    owner_cache_enabled=1 block_owner_uid_set=1 block_owner_uid=4242

Staged SDK smoke:
  tun_poc_owner_policy_set via Rust FFI shim:
    retval=0
  tun_poc_status after Rust FFI mutation:
  owner_cache_enabled=1 block_owner_uid_set=1 block_owner_uid=4242
  staged sdk: /tmp/sakamoto-vpp-tun-poc-rust-shim-sdk/sdk
  loader env: LD_LIBRARY_PATH=/tmp/sakamoto-vpp-tun-poc-rust-shim-sdk/sdk/lib

tun_poc persistent Rust FFI shim:
  before owner_cache_enabled=0 block_owner_uid_set=0 block_owner_uid=-1
  after_set owner_cache_enabled=1 block_owner_uid_set=1 block_owner_uid=4242
  after_clear owner_cache_enabled=0 block_owner_uid_set=0 block_owner_uid=-1

Rust FFI reconnect smoke:
  initial_status_ok
  stale_status_failed rc=-5
  stale_client_close rc=-7
  reopen_status_ok

tun_poc serialized Rust FFI shim threads:
  threads=4 calls_per_thread=5 total_calls=20
```

This proves the minimal non-CLI status surface:

```text
VPP API generator produces tun_poc.api.json and VAPI C/C++ headers.
tun_poc registers a binary API message table at startup.
Python PAPI can call tun_poc_status over socksvr and receive typed counters.
Python PAPI can call tun_poc_owner_policy_set over socksvr and mutate POC policy knobs.
Python PAPI can stage, rollback, and commit owner-policy knobs through typed binary API.
Generated VAPI C headers can be consumed by a small external C client for status calls.
Rust can call a thin C ABI shim, which hides generated VAPI types and reaches tun_poc_status.
Rust can also call the same C ABI shim to mutate owner policy and verify it through status.
The Rust shim client can link and run from a staged local Linux SDK when the launcher sets the loader path to the staged lib dir.
Rust can keep one opaque C-shim client handle open and reuse the same VAPI connection for multiple read/write calls.
A stale persistent handle fails after VPP stops, and a fresh handle can open/status after VPP restarts on the same socksvr path.
Rust threads can share one persistent C-shim client behind a Mutex and serialize status calls.
```

Boundary:

```text
This is read-only status plus direct mutation of POC owner policy knobs.
It does not implement fd handoff through VPP API.
It does not implement compiled policy blobs or snapshot epochs.
It does not prove Rust-native VAPI bindings.
It does not define final Android/Tauri installation packaging.
It does not define async/reconnect/thread ownership for a long-lived client.
It does not implement automatic reconnect, backoff, or command replay.
It does not prove concurrent VAPI calls on one context; threaded access is serialized.
```

VAPI C client notes:

```text
clients/tun_poc_vapi_status.c
scripts/run-vpp-tun-poc-vapi-c-status-smoke.py
scripts/run-vpp-tun-poc-api-policy-transaction-smoke.py

The smoke links against:
  install-vpp-native/vpp/lib/x86_64-linux-gnu/libvapiclient.so

The smoke includes:
  install-vpp-native/vpp/include
  build-vpp-native/vpp/CMakeFiles/vpp-api/vapi

The runtime root is under /tmp to avoid Unix socket path length limits for
socksvr/statseg sockets.
```

Rust FFI shim notes:

```text
clients/tun_poc_control_shim.h
clients/tun_poc_control_shim.c
clients/tun_poc_rust_status.rs
clients/tun_poc_rust_policy.rs
clients/tun_poc_rust_persistent.rs
clients/tun_poc_rust_reconnect.rs
clients/tun_poc_rust_serialized.rs
scripts/run-vpp-tun-poc-rust-shim-status-smoke.py
scripts/run-vpp-tun-poc-rust-shim-policy-smoke.py
scripts/run-vpp-tun-poc-rust-shim-persistent-smoke.py
scripts/run-vpp-tun-poc-rust-shim-reconnect-smoke.py
scripts/run-vpp-tun-poc-rust-shim-serialized-smoke.py

Public Rust-facing surface:
  tun_poc_control_shim_abi_version()
  tun_poc_client_open(const char *api_sock, tun_poc_client_t **client_out)
  tun_poc_client_close(tun_poc_client_t *client)
  tun_poc_client_status_get(tun_poc_client_t *client, tun_poc_status_out_t *out)
  tun_poc_client_owner_policy_set(tun_poc_client_t *client, const tun_poc_owner_policy_t *policy, int32_t *vpp_retval)
  tun_poc_status_get(const char *api_sock, tun_poc_status_out_t *out)
  tun_poc_owner_policy_set(const char *api_sock, const tun_poc_owner_policy_t *policy, int32_t *vpp_retval)

The shim keeps VAPI generated headers and message types on the C side.
Rust sees only fixed-width repr(C) fields.

The smoke links:
  libtun_poc_control_shim.a
  libvapiclient.so
```

The policy smoke sets:

```text
owner_cache_enabled=1
block_owner_uid_set=1
block_owner_uid=4242
```

Staged SDK notes:

```text
scripts/run-vpp-tun-poc-rust-shim-sdk-smoke.py

Staged files:
  sdk/include/tun_poc_control_shim.h
  sdk/lib/libtun_poc_control_shim.a
  sdk/lib/libvapiclient.so*
  sdk/lib/libvlibmemoryclient.so*
  sdk/lib/libvlibapi.so*
  sdk/lib/libsvm.so*
  sdk/lib/libvppinfra.so*

Loader note:
  copied VPP native libs keep RUNPATH pointing at the original install tree.
  patchelf is not available in this environment.
  the smoke therefore sets LD_LIBRARY_PATH=<sdk>/lib and verifies with ldd
  before running the Rust client.
```
