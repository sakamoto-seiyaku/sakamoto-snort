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
