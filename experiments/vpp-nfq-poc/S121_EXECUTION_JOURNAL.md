# SAKAMOTO-121 Execution Journal

> Raw execution record. Interpretive conclusions are in `S121_PACKET_PATH_MEMO.md`.

## Run

- Date: 2026-08-21 (Asia/Taipei)
- Host: x86_64 Linux; same two-worker VPP build used for S120.
- VPP binary: `/tmp/s119-vpp-build/bin/vpp`
- VPP CLI socket: `/tmp/sakamoto-vpp-nfq-poc/s120-hev-external-driver-cli.sock`
- HEV library: `/tmp/hev-3911f79/bin/libhev-socks5-tunnel.so`
- Plugin: `/tmp/s119-vpp-build/lib/x86_64-linux-gnu/vpp_plugins/hev_external_driver_poc_plugin.so`
- Config: `experiments/vpp-nfq-poc/configs/hev-external-driver-poc-startup.conf`
- `flow_stack_owner_udp_echo()` was a temporary POC-only helper added to the
  pinned `/tmp/hev-3911f79` source; it is not a production API decision.

## Packet fixture

One 33-byte IPv4/UDP packet was generated in the VPP buffer:

```text
10.0.0.2:40000 -> 10.0.0.1:49153, payload "hello"
```

The HEV owner-context UDP session echoed the payload back. The output packet
was checked for IPv4/UDP, reversed UDP ports (`49153 -> 40000`), and the
`hello` payload.

## First attempt (raw failure)

The first run used the default owner configuration (`inflight_pbuf_credit_limit=1`).
The ingress `flow_stack_owner_submit()` pbuf was still held while the receive
callback synchronously requested an egress pbuf, so the bounded credit check
returned `FLOW_STACK_OWNER_PBUF_LIMIT` (`-5`). Raw console:

```text
s121_packet_path stage=finished result=FAIL submits=1 recv=1 echo=1 outputs=0 ingress=1/1 egress=0/0 copies=33/0 setup=136137574303424 submit=136137574303424 recv-thread=136137574303424 output=0
```

Preserved at `/tmp/s121-evidence-20260821/vpp-console-credit1-fail.log`.

## Final run

The POC then used `flow_stack_owner_create_with_config()` with the default
owner config except `inflight_pbuf_credit_limit=2`, keeping the limit bounded
and explicit.

Command:

```text
s121-packet-path run target-thread 1 lib /tmp/hev-3911f79/bin/libhev-socks5-tunnel.so
s121-packet-path queued target-thread 1
```

Final CLI output:

```text
s121-packet-path loaded 1 target-thread 1 pending 0 active 0 finished 1 invocations 1 submit 1 recv 1 echo 1 output 1 output-valid 1 queue-error 0 submit-result 0 echo-result 0
s121-packet-path buffers ingress=1/1 egress=1/1 copies=33/33 bytes recv=5 output=33 threads setup=137740149409472 submit=137740149409472 recv=137740149409472 output=137740149409472 owner=0x0 lwip=0x0
```

Raw final console is preserved at
`/tmp/s121-evidence-20260821/vpp-console-validated.log`:

```text
s119_trace stage=netif-output thread=137740149409472 task=0xd3 owner=0x7d4625d812c0 lwip=0x7d4625d4f900 len=33
s121_packet_path stage=netif-output thread=137740149409472 len=33 vpp_buffer=1045720
s121_packet_path stage=finished result=PASS submits=1 recv=1 echo=1 outputs=1 ingress=1/1 egress=1/1 copies=33/33 setup=137740149409472 submit=137740149409472 recv-thread=137740149409472 output=137740149409472
```

VPP was stopped with SIGINT after the run; the `script` wrapper recorded exit
code 130. No VPP process or S121 CLI socket remained.

## Evidence hashes

```text
7c3798fe8d43eecc42f09478c74cf0118304cf8efdc22671ce61cefeb162a037  /tmp/s121-evidence-20260821/vpp-console-credit1-fail.log
1ace00fdc49b315c6f05e016244e4e9196ca1b4deeea2c1ddb4934e17f03f68e  /tmp/s121-evidence-20260821/vpp-console-validated.log
240c79fb887ca74f986833c4a4305fddd3f5868e496af924e7a0a6bd87bf37bf  /tmp/s119-vpp-build/lib/x86_64-linux-gnu/vpp_plugins/hev_external_driver_poc_plugin.so
ab910018f6714cdbfbd02372436cfe8a4de110060e963868ecb6bacdea5f8ed7  /tmp/hev-3911f79/bin/libhev-socks5-tunnel.so
7df0bda37f3055ed54aeb623fa400d2bebbb69c13a6573e6f104d838d0d444e4  /tmp/hev-3911f79/third-part/hev-task-system/bin/libhev-task-system.so
```
