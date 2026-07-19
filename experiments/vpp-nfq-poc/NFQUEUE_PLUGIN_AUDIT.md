# NFQUEUE Plugin Audit

状态：Android baseline Conditional-Go；正式 NFQUEUE Adapter No-Go/HOLD。

## 证据

- 设备：Pixel 6a / Android 16 / arm64-v8a，USB 供电通过 `dumpsys battery unplug` 模拟断开。
- VPP：`9258530f3804a152578ce11cc7c8a1e9eab88ed0`，`v26.02`。
- 正式 run：`20260719-141956`。
- 原始结果：`experiments/vpp-nfq-poc/results/sakamoto-32-nfqueue-plugin-audit-20260719-141956/`。
- 构件：Android `vpp`、`vppctl`、`nfqueue_poc_plugin` 均交叉编译并在真机加载；plugin SHA-256 为
  `eebc350f9eb95562a8cbbd6df981edf7eb6cd0c88b6730d23d64ff0395766ce0`。

## 已通过

- IPv4/IPv6 INPUT/OUTPUT ACCEPT、DROP。
- IPv4/IPv6 OUTPUT 20 包 50% mixed verdict：`accepted=10 dropped=10`。
- active NFQUEUE rule 下 plugin disable：`nfnetlink_queue=0`。
- 最终清理：VPP PID、NFQUEUE queue、iptables/ip6tables NFQUEUE hook 均为 0。
- 10 秒 idle 原始 `/proc` 采样：plugin disabled/enabled RSS 均 `102984 kB`；主进程 jiffy 增量分别为
  `utime/stime=1/0` 和 `0/0`。仅为短时基线。

## 已修复

1. `nfq_set_mode(..., 0xffff)` 改为 bounded copy `512`，CLI `show nfqueue-poc` 明确报告 `copy-range 512`。
2. `recv()` 遇到 `ENOBUFS` 时不再在 read-ready 回调内紧循环。
3. Android/WSL adb wrapper 的目录 push 改为逐文件 push，修复嵌套目录导致的假启动失败。

## 阻塞项

- packet callback 中同步 `fprintf`/`fflush` event log，不能作为生产 telemetry 热路径。
- 缺失 `packet_id` 无法安全发 verdict，当前仅计数返回；需要明确 fault policy。
- 单实例仅绑定一个 family/queue；本轮双栈通过重启实例分别验证，不是单实例双栈或多 queue 证明。
- IPv6 extension header、truncated/malformed packet、original packet length 与 copied prefix 尚无完整契约，
  当前部分 parse error 为 default-allow。
- 尚无 queue overflow/backlog、fault injection、crash/reboot、p50/p95/p99 latency 和长期 CPU/功耗预算证据。

Linux/Docker 只承担源码审计、交叉编译和打包辅助，不作为上述结论的功能证据。
