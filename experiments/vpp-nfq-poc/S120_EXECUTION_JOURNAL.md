# SAKAMOTO-120 Execution Journal

> Raw execution record. Interpretive conclusions are in `S120_EXTERNAL_DRIVER_MEMO.md`.

## Run

- Date: 2026-08-21 (Asia/Taipei)
- Host: x86_64 Linux; VPP built from the S119 work tree.
- VPP binary: `/tmp/s119-vpp-build/bin/vpp`
- VPP CLI: `/tmp/s119-vpp-build/bin/vppctl`
- HEV library: `/tmp/hev-3911f79/bin/libhev-socks5-tunnel.so`
- Task-system library: `/tmp/hev-3911f79/third-part/hev-task-system/bin/libhev-task-system.so`
- Plugin: `/tmp/s119-vpp-build/lib/x86_64-linux-gnu/vpp_plugins/hev_external_driver_poc_plugin.so`
- Config: `experiments/vpp-nfq-poc/configs/hev-external-driver-poc-startup.conf`
- The external-driver symbols were temporary POC additions to the pinned
  `/tmp/hev-3911f79` HEV/task-system sources; no production API was frozen.

## Commands and observations

1. Built the consistent VPP executable and CLI:

   ```text
   cmake --build /tmp/s119-vpp-build --target vpp vppctl -j$(nproc)
   [729/729] Linking C executable bin/vpp
   ```

2. Started VPP with two workers and the external-driver plugin. `show threads`:

   ```text
   0 vpp_main
   1 vpp_wk_0 workers
   2 vpp_wk_1 workers
   ```

3. Triggered the worker-bound driver:

   ```text
   s120-external-driver run target-thread 1 budget 1 \
     lib /tmp/hev-3911f79/bin/libhev-socks5-tunnel.so
   s120-external-driver queued target-thread 1 budget 1
   ```

4. Final CLI state:

   ```text
   s120-external-driver loaded 1 target-thread 1 budget 1 pending 0 active 0 finished 1 turns 27 invocations 27 step-calls 27 queue-error 0 status 2 total 0 running 0 next-timeout-ms -1
   s120-external-driver threads worker=137885483947712 bound=137885483947712 owners=0x7d67fc75e920/0x7d67fc75ee60 lwip=0x7d67fc6b88d0/0x7d67fc6c2970 packets=1/1/2 timers=2/6 outputs=0/0 joined=1/1 residue=0/0
   ```

5. Raw console log is preserved at `/tmp/s120-evidence-20260821/vpp-console.log`.
   Counts from that file:

   ```text
   s120_worker_turn stage=enter: 27
   s120_driver_step: 27
   s119_trace task entries: 6
   s120_external_driver stage=finished result=PASS turns=27 step_calls=27 bound_pthread=137885483947712 a_joined=1 b_joined=1 task_residue=0 fd_residue=0
   ```

6. Stopped VPP with SIGINT after the run. The `script` wrapper recorded exit code
   130; no VPP process or S120 CLI socket remained.

## Evidence hashes

```text
6756d39a976f460e798a9b7b1245fac58c3bc71a3fa6839b6a779f07612294be  /tmp/s120-evidence-20260821/vpp-console.log
5c4d1f707d2e7072a2da5974b76e3f7c43b13ecd823f2d76fbb91d5aa644908d  /tmp/s119-vpp-build/bin/vpp
1f1c7a944b9178d9d4a24f2cbc01ba892b28cbd17a8de35fc687ba8ebcbd058f  /tmp/s119-vpp-build/bin/vppctl
54c6ebc845c736be4d50b2aecfe33d204a18cf2f751791983d58987a7c294d1c  /tmp/s119-vpp-build/lib/x86_64-linux-gnu/vpp_plugins/hev_external_driver_poc_plugin.so
bfff14bdbf5ea7e5e7fe3eab86c725a90ee7fee6c5ee007817483180943edf17  /tmp/hev-3911f79/bin/libhev-socks5-tunnel.so
7df0bda37f3055ed54aeb623fa400d2bebbb69c13a6573e6f104d838d0d444e4  /tmp/hev-3911f79/third-part/hev-task-system/bin/libhev-task-system.so
```
