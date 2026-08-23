# S119 HEV/lwIP 单 worker POC 执行流水账

本文件只记录本轮执行顺序、命令、原始现象和证据位置。可回顾的设计结论见
`S119_HEV_LWIP_WORKER_MEMO.md`；Plane 工单为 `SAKAMOTO-119`。

## 固定输入

```text
date: 2026-08-20
HEV: 3911f79434d9a27c3ae4e6e07df5cefe2c3d5c70
core: ee0f24505d344f14b14624fa2249e6ccfaed138b
hev-task-system: b1afa0e21fb4ed5a69560e78e54baf0efdebe171
lwIP: 8c69dfbe537835d5f2a5fd8c08c859f667b108ea
yaml: efa36117a8646d26d12b58e05bac472d7854a70d
device: Pixel 6a / Android 16 / API 36 / aarch64
evidence: /tmp/s119-evidence-20260820/
```

## 执行记录

### 22:xx — Host 单 worker task-model

命令：

```sh
make -C /tmp/hev-3911f79 tp-shared shared V=1 ENABLE_DEBUG=1
```

现象：构建退出码 0；抽取 tar 没有 `.git`，构建过程打印 `fatal: not a git repository`，
同时生成 `COMMIT_ID="unknown"`。

runner 输出：

```text
s119_worker_exit ... result=0 a_joined=1 b_joined=1 a_heartbeat=4 b_before=4 b_after=8 task_residue=0
s119_single_worker_task_model=PASS
```

原始文件：`task-model.log`，SHA256=
`293a32aebf5b9a9523a3f88163d077e50f903faa32319be74f60314112b6e22d`。

### 22:xx — Host TCP/UDP 单 worker

两个 owner 在同一个 pthread 内运行；完整输出最初保存在：

```text
/tmp/s119-evidence-20260820/tcp-worker.log
/tmp/s119-evidence-20260820/udp-worker.log
```

TCP 尾部：

```text
s118_hev_protected_tcp=PASS_ACTUAL_SESSION_TASK_PROTECTED_FULL_DUPLEX
s118_hev_protected_tcp_return=PASS_CTX_OUTPUT_REMOTE_ACK_SENT_RELEASE
s119_single_worker_real_lwip=PASS
```

UDP 尾部：

```text
s118_pbuf_credit_lifetime=PASS_RETAINED_REJECT_RELEASE_RECOVERY
s118_udp_zero_headroom_fallback=PASS_OWNER_ALLOC_COPY_CHECKSUM_RELEASE
s118_hev_protected_udp=PASS_ACTUAL_SESSION_TASK_PROTECTED_FULL_DUPLEX_IPV4
s119_single_worker_real_lwip_udp=PASS
```

### 22:xx — Android 初始 runner

NDK 构建第一次缺少 S118 `src/include/lwip/owner_context.h` include；只在 `/tmp` 的
`Android.mk` 和 lwIP `Android.mk` 补 include 后重建成功。未改仓库生产文件。

Pixel 6a runner：task-model、TCP、UDP 均退出码 0。设备原始输出：

```text
android-task-model.log
android-tcp-worker.log
android-udp-worker.log
```

### 22:57 — Plane 第一轮记录

向 `SAKAMOTO-119` 写入 Host/source 结果：单 worker 模型、TCP/UDP、owner/lwIP 分离，
并明确“模拟 VPP worker、尚未实际 VPP plugin/graph”。

### 23:03 — Plane 第二轮记录

向 `SAKAMOTO-119` 写入 Pixel 6a 结果：Android 16/API 36/aarch64，task-model、TCP、
UDP 均通过；明确尚未证明 VPP graph/plugin。

### 23:08 — scheduler takeover

Host 和 Pixel 6a 都运行 scheduler takeover runner。任务执行 5 次 25ms sleep；worker
在 `hev_task_system_run()` 返回前不增加下一次模拟 VPP node turn。

原始输出：

```text
Host:    s119_scheduler_elapsed_ms=125 task_steps=5 vpp_ticks_before=1 vpp_ticks_after=2 violation=0
Android: s119_scheduler_elapsed_ms=127 task_steps=5 vpp_ticks_before=1 vpp_ticks_after=2 violation=0
s119_scheduler_takeover=PASS_WORKER_BLOCKED_UNTIL_SCHEDULER_RETURN
```

证据：

```text
host-scheduler-takeover.log       52752dbce7ec10eabcea5bb2bff6f711b375dd9101688aaff99ebd17b62f4b38
android-scheduler-takeover.log    59b63c07ee5361204235a8817cbb566bbac4b9d2c7e43641a72fe4a048f56b16
```

### 23:09 — 临时 bounded step seam

只在 `/tmp/hev-3911f79` 添加临时 `hev_task_system_step()`：一次推进一个 task quantum，
reactor 使用非阻塞 poll；另加临时 `s119_hev_task_system_step()` wrapper。没有写入仓库。

task-only runner：

```text
Host:    s119_scheduler_step_ticks=121 task_steps=5 max_ticks_observed=121 violation=0
Android: s119_scheduler_step_ticks=116 task_steps=5 max_ticks_observed=116 violation=0
s119_scheduler_step=PASS_BOUNDED_EXTERNAL_DRIVER
```

证据：

```text
host-scheduler-step.log       abecdb8c7ad53033455bf520bac5d94804bb6d58a2753afae3c9bdf3aac4c2b6
android-scheduler-step.log    ab0925ad81a85fd224cc0ba7036f262a38c170c00dee17bca539b400c0b7647b
```

### 23:xx — 实际 owner/lwIP bounded step

临时修改 S118 TCP/UDP smoke，使其从 owner runtime identity 取得 event/io/timer task，
通过 wrapper 调 `hev_task_system_step()`，每次返回后再回到 worker runner。两个 owner
仍在同一个 worker pthread；日志额外输出 `s119_owner_step_driver result=done steps=8`。

Host/Android 四个 runner 均通过：

```text
s119_owner_step_driver result=done steps=8
s118_hev_protected_tcp=PASS_ACTUAL_SESSION_TASK_PROTECTED_FULL_DUPLEX
s119_single_worker_real_lwip=PASS

s119_owner_step_driver result=done steps=8
s118_hev_protected_udp=PASS_ACTUAL_SESSION_TASK_PROTECTED_FULL_DUPLEX_IPV4
s119_single_worker_real_lwip_udp=PASS
```

最终完整日志与哈希：

```text
host-tcp-owner-step.log       08c8dc2ef49704ca82d4cf69a4e1b4a43998d9dcf2badd8f4e9a96f2f052b1df
host-udp-owner-step.log       2eb18886ce3fedaabff931711260ec5e14185e2ce921633e7ea6d5f5745c0998
android-tcp-owner-step.log    926aeec020617c9ee384cc1b466f6a697829076ca5183e00b33a29954bab2376
android-udp-owner-step.log    abc90837ed576898e755bc0d6506a0b8b0cc87efa03a8ce39ab2f608ac62e4e0
```

最终临时库：

```text
Host libhev-socks5-tunnel.so       7e5fd053e1dd3411ad37feeae485765578e37d1e4200e52dc0245a12fea065d7
Android arm64 libhev-socks5-tunnel.so
                                    b98926d440b540a6b5d806326086ea3961aa68877b3f0b5e471f0fd639ab5d37
```

### 23:18 — 清理

```text
pidof s119-protected-tcp-worker s119-protected-udp-worker s119-single-worker
  -> empty
```

已删除设备明确临时目录 `/data/local/tmp/s119`。Host `/tmp` 证据目录保留供复核。

### 23:xx — 真实 VPP worker/plugin seam

新增仅用于本 POC 的插件源：

```text
overlay/src/plugins/hev_worker_step_poc/plugin.c
overlay/src/plugins/hev_worker_step_poc/CMakeLists.txt
overlay/src/plugins/hev_worker_step_poc/hev_worker_step_poc.c
configs/hev-worker-step-poc-startup.conf
```

插件路径：CLI 在 main thread 只分配 1 个 VPP buffer、唤醒 trigger node；trigger node
把 buffer 放进 `vlib_frame_queue_main_init()` 建立的 frame queue；真正的
`s119-hev-worker-step-worker` 在 target worker 上调用 HEV 的 local-I/O bounded proof。
HEV 通过 `dlopen` 装载，避免把临时 HEV ABI 链进 VPP 主程序。

构建记录：

```text
VPP: 26.02-release / 9258530f
target: hev_worker_step_poc_plugin
build: /tmp/s119-vpp-build (旧 build tree 的 root-owned object 不覆盖)
HEV: /tmp/hev-3911f79/bin/libhev-socks5-tunnel.so
plugin SHA256: 742ef36ad7f23577e95cde23d6ad9f099d22272db6bcb2af7e2481d95bd25a51
source SHA256: c70043b6cf75a4ae677dfb00f90dee2af24c7c3cec9fe21f44fd73d28bb658fb
CMakeLists SHA256: e25faa9af9b4bbff93ab03c54c622ff1620b91e25b359fe8ce9ed67a6de4bcea
startup config SHA256: 303f742c02f16b5c10f15fea559fd401b8b0a0869f580e896036a9a580c6d5e0
```

第一次 VPP worker 调用使用 20-byte 非完整 IPv4 探针；HEV 的 local-I/O proof 返回
`-1`，但 task/lwIP 生命周期本身完成。该输入没有产生 wire-output 计数，不能把它记成
完整 packet I/O PASS。随后改成 28-byte IPv4 ICMP echo 探针，并把判定拆成
`local_io_result` 与 `lifecycle_ok`；仍明确不宣称 VPP packet egress。

最终可复核命令：

```text
vppctl ... show threads
vppctl ... s119-hev-worker-step run count 1 target-thread 1
vppctl ... show s119-hev-worker-step
```

最终 CLI 原始输出：

```text
s119-hev-worker-step queued count 1 target-thread 1
s119-hev-worker-step loaded 1 target-thread 1 requested 1 pending 0 enqueued 1 processed 1 probe-calls 1 finished 1 result 0
s119-hev-worker-step vpp-thread 1 vpp-pthread 128431178114752 hev-pthread 128431178114752 owner-a 0x74cebdfa5600 owner-b 0x74cebdfa41e0 lwip-a 0x74cebdf2a180 lwip-b 0x74cebdedb180 packets 1/2 timers 2/6
```

最终真实 worker/HEV 原始 stdout/stderr（`vpp-worker-plugin-final.console.log`）关键行：

```text
s119_vpp_worker_probe stage=enter vpp_thread=1 pthread=128431178114752
s119_trace stage=event-enter thread=128431178114752 task=0x74cebdfa7ab0 owner=0x74cebdfa5600 lwip=0x74cebdf2a180
s119_trace stage=lwip-io-enter thread=128431178114752 task=0x74cebdfc8760 owner=0x74cebdfa5600 lwip=0x74cebdf2a180
s119_trace stage=lwip-timer-enter thread=128431178114752 task=0x74cebdfa5b50 owner=0x74cebdfa5600 lwip=0x74cebdf2a180
s119_trace stage=event-enter thread=128431178114752 task=0x74cebc679f50 owner=0x74cebdfa41e0 lwip=0x74cebdedb180
s119_trace stage=lwip-io-enter thread=128431178114752 task=0x74cebc67a150 owner=0x74cebdfa41e0 lwip=0x74cebdedb180
s119_trace stage=lwip-timer-enter thread=128431178114752 task=0x74cebb55f3f0 owner=0x74cebdfa41e0 lwip=0x74cebdedb180
s119_step_driver result=done steps=27 tasks=7
s119_vpp_worker_probe stage=hev-return result=0 local_io_result=-1 lifecycle_ok=1 vpp_thread=1 pthread=128431178114752 owner_a=0x74cebdfa5600 owner_b=0x74cebdfa41e0 lwip_a=0x74cebdf2a180 lwip_b=0x74cebdedb180 a_packets=1 b_packets=2 a_timer_steps=2 b_timer_steps=6 a_joined=1 b_joined=1 task_residue=0 fd_residue=0
s119_vpp_worker_probe stage=leave vpp_thread=1 pthread=128431178114752 result=0
```

这组行直接显示：VPP thread 1、HEV 入口 pthread、所有 HEV event/io/timer task 的
`pthread` 相同；两个 owner 与两个 lwIP context 地址各自不同；bounded driver 27 steps
后无 task/fd residue。真实证据文件与 SHA256：

```text
/tmp/s119-evidence-20260820/vpp-worker-plugin-final.cli.log
  65c1c0d98ea46cc682bea5bb062d7316c46949c576620d59ae6d7e18b6f6b592
/tmp/s119-evidence-20260820/vpp-worker-plugin-final.console.log
  8c35f5684f5004b9c4a424e8277fae76c02f718d3f445bad22e953581196eb8a
/tmp/s119-evidence-20260820/vpp-worker-plugin-final.threads.log
  6d5f8e016a3c7793dc3d64e5f97a077159e50bcfd1efdb9188de8e80f4893863
```

VPP teardown 的前两次交互式 SIGINT 曾打印 host shutdown SIGSEGV 栈；最终证据重跑
完成后进程退出，未把 teardown 当作 seam PASS 条件。该现象保留在终端流水中，需另行
判断是否是混用旧安装库/构建树造成的独立问题。
