# VPP NFQUEUE POC Notes

Status: living notes for this throwaway experiment.

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

Before cloning/building VPP:

1. Commit the current smoke harness.
2. Add VPP fetch/build scripts that place source and build output outside git-tracked files.
3. Confirm upstream `v26.02` build dependencies in the same Docker image or a derived one.
4. Add the smallest `nfqueue_poc` plugin patch.
5. Re-run accept/drop/ratio/idle cases through VPP.
