# VPP NFQUEUE POC

Status: throwaway experiment.

Question: before touching VPP, can this Linux/Docker environment reliably route packets through NFQUEUE and receive deterministic userspace verdicts (`ACCEPT`, `DROP`, partial drop)?

This directory is intentionally isolated from the production daemon. The first milestone is a plain C `nfq-smoke` program. VPP build/plugin work comes after this smoke layer proves that Docker, netns, iptables, and libnetfilter_queue are usable.

## One-command entry points

From this directory:

```sh
make docker-shell
```

Inside the container:

```sh
make build-smoke
make smoke-accept
make smoke-drop
make smoke-ratio
make idle-cpu
```

The smoke scripts create a temporary veth pair:

```text
root netns: nfq-host 10.200.42.1/24
peer netns: nfq-peer0 10.200.42.2/24
```

Only ICMP packets from root netns to `10.200.42.2` through `nfq-host` are queued:

```text
OUTPUT -o nfq-host -p icmp -d 10.200.42.2 -j NFQUEUE --queue-num 42
```

Cleanup:

```sh
make cleanup-netns
```

The container run path uses:

```text
--network none
--cap-drop ALL
--cap-add NET_ADMIN
--cap-add NET_RAW
--cap-add SYS_ADMIN
--security-opt apparmor=unconfined
--security-opt seccomp=unconfined
--tmpfs /run
```

`SYS_ADMIN` is needed by `ip netns add` in Docker because it performs mount namespace setup under `/run/netns`.

If a later step needs network access inside the container to fetch VPP, run:

```sh
DOCKER_NETWORK=bridge make docker-shell
```

## Current Milestone

Required before VPP:

- `accept-all`: ping succeeds.
- `drop-all`: ping fails.
- `drop-ratio=50`: ping shows partial loss.
- `nfq-smoke` logs exactly one verdict per queued packet.
- Metadata presence is visible in logs: packet id, hook, payload length, mark, ifindex, UID/GID, timestamp.
- `idle-cpu`: `nfq-smoke` stays near 0% CPU when no packet is queued.

## Baseline Result

Last run: 2026-06-21, Docker image `sakamoto-vpp-nfq-poc:dev`.

Observed:

- `make build-smoke`: passed inside Docker.
- `make smoke-accept`: 20 transmitted, 20 received, `seen=20 accept=20 drop=0`.
- `make smoke-drop`: 20 transmitted, 0 received, `seen=20 accept=0 drop=20`.
- `make smoke-ratio`: 20 transmitted, 10 received, `seen=20 accept=10 drop=10`.
- `make idle-cpu`: `nfq-smoke` sampled at `0.0%` CPU before and after traffic.

Observed metadata in this container:

- packet id: present.
- hook: present, value `3` for root namespace `OUTPUT`.
- payload: present, 84-byte ICMP packet.
- output ifindex: present; concrete value depends on container network setup.
- UID/GID: present, both `0` because ping ran as root inside the container.
- timestamp: not present through the current libnetfilter_queue configuration.

This proves the Linux/Docker NFQUEUE harness is viable enough to proceed to a VPP adapter POC. It does not yet prove anything about VPP plugin correctness.

## Notes

- Run this in Docker first. Running NFQUEUE experiments directly on a host can affect local networking if the rule is changed incorrectly.
- The smoke program does not call `nfq_unbind_pf()` unless explicitly passed `--unbind-existing`.
- The VPP source tree, build output, core files, and packet captures must not be committed here.
