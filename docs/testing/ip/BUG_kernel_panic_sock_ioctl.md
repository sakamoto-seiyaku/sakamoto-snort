# Bug Record: Pixel 6a kernel panic in `sock_ioctl` during IP perf duration test

## Summary

在 Pixel 6a（`bluejay`）上运行 IP 真机测试模组的 perf case（Tier‑1 `netns+veth`）时，存在一个由 **Toybox `nc -L sh -c ...` server 模式** 触发的内核 panic。当前最小化结论是：

- `sucre-snort` / NFQUEUE / 规则下发都不是前提；
- 只启动 server，或只做一次不读 payload 的 direct connect，不会触发；
- 当 server 使用 `nc -L sh -c "cat /dev/zero"`，并且 client 端对该连接执行**真实读流**时，可在第 1 次迭代直接触发 panic；最新验证表明，哪怕只读 `1 byte` 也足够。

现象为设备发生 **kernel panic** 并重启：

- `getprop sys.boot.reason` / `sys.boot.reason.last`：`kernel_panic,stack`
- `console-ramoops-0`：`stack-protector: Kernel stack is corrupted in: sock_ioctl+0x4f8/0x55c`

该问题会使 perf 对比/长时压测无法稳定完成，属于 **P0 级别的测试阻塞问题**（会把设备打重启）。

## Environment

- Device: Pixel 6a (`bluejay`), rooted (Magisk)
- Build fingerprint: `google/bluejay/bluejay:16/BP3A.250905.014/13873947:user/release-keys`
- Kernel: `6.1.134-android14-11-g66e758f7d0c0-ab13748739` (see record file)
- Host ADB: 建议使用 Linux 原生 ADB（本仓库常用：`$HOME/.local/android/platform-tools/adb`）

## Repro (confirmed)

前置条件：
- 设备具备：root + `ip netns`/`veth` + `nc` + `ping` + `timeout`
- `tests/device/ip/` 真机模组可正常运行

复现命令（host 上执行，**已确认可触发重启**）：

```bash
export ADB="$HOME/.local/android/platform-tools/adb"
export ADB_SERIAL=28201JEGR0XPAJ

IPTEST_PERF_SECONDS=180 \
IPTEST_PERF_COMPARE=1 \
IPTEST_PERF_BG_TOTAL=2000 \
IPTEST_PERF_BG_UIDS=200 \
  bash tests/device/ip/run.sh --serial "$ADB_SERIAL" --profile perf
```

现象（关键观察点）：
- 日志进入 `CASE: 60_perf`，完成规则下发与 `preflight summary` 后，打印：
  - `tier1 tcp load duration=180s chunk=2000000 (iprules_on)`
- 随后 **ADB 连接断开**（`adb: device '...' not found`）并且设备重启

复现后确认（host 上执行）：

```bash
$ADB -s "$ADB_SERIAL" shell getprop sys.boot.reason
$ADB -s "$ADB_SERIAL" shell getprop sys.boot.reason.last
$ADB -s "$ADB_SERIAL" shell "su 0 sh -c 'cat /sys/fs/pstore/console-ramoops-0'" | rg -n "Kernel panic|sock_ioctl|stack-protector" -n
```

## On-device repro script (step marker)

为精确定位“在脚本执行到哪一步发生重启”，提供了一个**真机侧**的 1:1 reproducer 脚本，会把每一步的标记与关键进度写入持久化目录
`/data/local/tmp/iptest_panic_repro/`（重启后仍在）。

脚本路径（repo）：
- `tests/archive/device/ip/repro/kernel_panic_sock_ioctl_device_repro.sh`

也可以使用 host-side wrapper 一键执行 + 归档（推荐，跑完自动写入 `tests/device/ip/records/`）：

```bash
export ADB="$HOME/.local/android/platform-tools/adb"
export ADB_SERIAL=28201JEGR0XPAJ

# 例如：验证 workaround（server 不派生 sh）
SERVER_MODE=cat_zero REPRO_MODE=net_only STOP_SNORT=1 \
  IPTEST_PERF_SECONDS=60 LOAD_MAX_ITERS=1 LOAD_MODE=connect_q0 \
  bash tests/device/ip/repro/run_kernel_panic_sock_ioctl_host.sh
```

这个 host-side wrapper 会把下列 host 环境变量原样透传到设备侧 repro 脚本：

- `REPRO_MODE` / `STOP_SNORT` / `SERVER_MODE`
- `LOAD_MODE` / `LOAD_WRAPPER` / `LOAD_MAX_ITERS`
- `IPTEST_PERF_SECONDS` 以及其他 `IPTEST_*` / `LOAD_*` 调参项

如果要批量跑最小矩阵，也可以直接执行：

```bash
export ADB="$HOME/.local/android/platform-tools/adb"
export ADB_SERIAL=28201JEGR0XPAJ

RUN_ID_PREFIX=panic-matrix \
  bash tests/device/ip/repro/run_kernel_panic_sock_ioctl_matrix.sh
```

矩阵默认会顺序执行 4 组最小 case：

- `sh_cat_zero + connect_q0`
- `sh_cat_zero + head1_only`
- `cat_zero + connect_q0`
- `cat_zero + head1_only`

运行方式（host 上执行一次 adb，把脚本推到设备并运行）：

```bash
export ADB="$HOME/.local/android/platform-tools/adb"
export ADB_SERIAL=28201JEGR0XPAJ

$ADB -s "$ADB_SERIAL" push tests/archive/device/ip/repro/kernel_panic_sock_ioctl_device_repro.sh \
  /data/local/tmp/iptest_kernel_panic_sock_ioctl_repro.sh

$ADB -s "$ADB_SERIAL" shell "su 0 sh -c 'chmod 755 /data/local/tmp/iptest_kernel_panic_sock_ioctl_repro.sh && /data/local/tmp/iptest_kernel_panic_sock_ioctl_repro.sh'"
```

重启后查看“最后执行到哪一步”（host 上执行）：

```bash
$ADB -s "$ADB_SERIAL" shell "su 0 sh -c 'cat /data/local/tmp/iptest_panic_repro/last_step.txt || true'"
$ADB -s "$ADB_SERIAL" shell "su 0 sh -c 'tail -n 80 /data/local/tmp/iptest_panic_repro/latest.log || true'"
```

### Current localization result (2026-03-19)

使用上面的 device-side repro 脚本，并加入新的控制变量 `LOAD_WRAPPER=direct` 与 `LOAD_MODE=sleep_only` 后，当前最小化矩阵如下。

#### Negative controls (all finished without reboot)

- 仅启动 server，不发起任何连接：
  - `RUN_ID=20260319T_control_sleep_only`
  - `REPRO_MODE=net_only STOP_SNORT=1 SERVER_MODE=sh_cat_zero LOAD_MODE=sleep_only LOAD_WRAPPER=direct`
  - 结果：`STEP 21: done`
- `sh_cat_zero` server + 一次 direct connect，但**不读 payload**：
  - `RUN_ID=20260319T_direct_connect_panic`
  - `REPRO_MODE=net_only STOP_SNORT=1 SERVER_MODE=sh_cat_zero LOAD_MODE=connect_q0 LOAD_WRAPPER=direct`
  - 结果：`STEP 21: done`
- 将 server 改成不派生 `sh` 的 `cat_zero` 后，client 侧真实读流也不会触发：
  - `RUN_ID=20260319T_cat_head_only_sh`
  - `SERVER_MODE=cat_zero LOAD_MODE=head_only LOAD_WRAPPER=sh`
  - 结果：`STEP 21: done`
  - `RUN_ID=20260319T_cat_head_wc_sh`
  - `SERVER_MODE=cat_zero LOAD_MODE=head_wc LOAD_WRAPPER=sh`
  - 结果：`STEP 21: done`
  - `RUN_ID=20260319T_cat_head_wc_su_sh`
  - `SERVER_MODE=cat_zero LOAD_MODE=head_wc LOAD_WRAPPER=su_sh`
  - 结果：`STEP 21: done`

#### Positive cases (reproduced with `kernel_panic,stack`)

- 原始最小 net-only 组合：
  - `RUN_ID=20260319T_recheck_original`
  - `REPRO_MODE=net_only STOP_SNORT=1 SERVER_MODE=sh_cat_zero LOAD_MODE=head_wc LOAD_WRAPPER=su_sh`
  - 结果：`STEP 16: phase iprules_on: duration load start ...`
  - `last_iter.txt`：`iter=1 ... bytes=- rc=-`
- 去掉 `su` 之后仍可复现：
  - `RUN_ID=20260319T_sh_head_wc_sh`
  - `REPRO_MODE=net_only STOP_SNORT=1 SERVER_MODE=sh_cat_zero LOAD_MODE=head_wc LOAD_WRAPPER=sh`
  - 结果：同样停在 `STEP 16`，`iter=1 ... bytes=- rc=-`
- 刚刚重新验证，`wc -c` 也不是前提：
  - `RUN_ID=20260319T_sh_head_only_sh`
  - `REPRO_MODE=net_only STOP_SNORT=1 SERVER_MODE=sh_cat_zero LOAD_MODE=head_only LOAD_WRAPPER=sh`
  - 结果：同样停在 `STEP 16`，`iter=1 ... bytes=- rc=-`
- 读取大量 payload 也不是前提，`1 byte` 即可触发：
  - `RUN_ID=20260319T_sh_head1_sh`
  - `REPRO_MODE=net_only STOP_SNORT=1 SERVER_MODE=sh_cat_zero LOAD_MODE=head1_only LOAD_WRAPPER=sh`
  - 结果：同样停在 `STEP 16`，`iter=1 ... bytes=- rc=-`
- 额外的 client shell / pipeline 也不是前提：
  - `RUN_ID=20260319T_sh_timeout_direct_rerun`
  - `REPRO_MODE=net_only STOP_SNORT=1 SERVER_MODE=sh_cat_zero LOAD_MODE=timeout_raw_read LOAD_WRAPPER=direct`
  - 结果：同样停在 `STEP 16`，`iter=1 ... bytes=- rc=-`
  - `last_cmd.txt`：
    - `wrapper=direct`
    - `mode=timeout_raw_read`
    - `cmd=timeout "1" nc -n -w 5 "10.200.1.2" "18080" </dev/null >/dev/null 2>&1 || true`

#### What this narrows down

- **snort / NFQUEUE / 规则处理都不是前提**：`REPRO_MODE=net_only STOP_SNORT=1` 仍然复现。
- **仅 server 启动不是前提**：`sleep_only` 控制组稳定通过。
- **单次 connect 但不读 payload 不是前提**：`connect_q0 + direct` 控制组稳定通过。
- **`su` 不是前提**：`LOAD_WRAPPER=sh` 仍然复现。
- **`wc -c` 不是前提**：`head_only` 刚刚重新验证仍可复现。
- **读取大量 payload 不是前提**：`head1_only`（只读 1 byte）仍可复现。
- **额外 client `sh -c` / pipeline 不是前提**：`LOAD_WRAPPER=direct + LOAD_MODE=timeout_raw_read` 仍可复现。
- **当前最强相关项**：Tier‑1 server 使用 `nc -L sh -c "cat /dev/zero"`，并且 client 侧对该连接执行真实读取；“只 connect 不读”不会触发。

因此，之前“只要 accept 一次连接就会 panic”以及“必须经过 client shell pipeline 才会 panic”的推断都过强。当前更合理的假设是：
Toybox `nc -L sh -c ...` server 侧派生出的 `sh`，在对端开始真实读取 payload 后，会在某个 socket fd 上触发 `ioctl(...)` 路径，从而把内核打进
`sock_ioctl+0x4f8/0x55c`。

#### Mitigation candidate: avoid server-side `sh` by exec-ing `cat` directly

为了验证/绕开该问题，device-side repro 脚本已加入 `SERVER_MODE` 开关：

- `SERVER_MODE=sh_cat_zero`（默认）：`nc -L sh -c "cat /dev/zero"`（疑似触发点）
- `SERVER_MODE=cat_zero`：`nc -L cat /dev/zero`（不派生 `sh`，作为 workaround 候选）

建议用最小迭代验证（只打 1 次连接/读取）：

```bash
export ADB="$HOME/.local/android/platform-tools/adb"
export ADB_SERIAL=28201JEGR0XPAJ

$ADB -s "$ADB_SERIAL" shell "su 0 sh -c '
  SERVER_MODE=cat_zero REPRO_MODE=net_only STOP_SNORT=1 \
  IPTEST_PERF_SECONDS=60 LOAD_MAX_ITERS=1 LOAD_MODE=connect_q0 \
    /data/local/tmp/iptest_kernel_panic_sock_ioctl_repro.sh
'"
```

截至 2026-03-19 的最小矩阵，`SERVER_MODE=cat_zero` 在所有已验证的控制组中都可稳定跑完（无 `kernel_panic,stack`），因此可以把
这个 workaround 用到 IP 测试模组的 Tier‑1 server 实现里，先解除 perf/longrun 的测试阻塞；kernel 根因可另行上报/升级。

主线 harness 也已验证该 workaround：

- `IPTEST_PERF_SECONDS=30 IPTEST_PERF_COMPARE=1 IPTEST_PERF_BG_TOTAL=2000 IPTEST_PERF_BG_UIDS=200 bash tests/device/ip/run.sh --skip-deploy --profile perf`
- 结果：`passed=2 failed=0 skipped=0`
- 观察：双阶段 duration load 完整跑完，无 ADB 断连/设备重启，`METRICS.GET(name=perf)` 两阶段都返回有效 JSON 与正样本数

## Evidence (this repo)

本次复现证据：

- Host-side repro（抓取时间：`20260318T145949Z`）
  - `tests/device/ip/records/20260318T145949Z_28201JEGR0XPAJ_boot.txt`
  - `tests/device/ip/records/20260318T145949Z_28201JEGR0XPAJ_console-ramoops-0.txt`
  - `tests/device/ip/records/20260318T145949Z_28201JEGR0XPAJ_pmsg-ramoops-0.bin`

- Device-side repro + step marker（抓取时间：`20260318T153320Z`）
  - `tests/device/ip/records/20260318T153320Z_28201JEGR0XPAJ_boot.txt`
  - `tests/device/ip/records/20260318T153320Z_28201JEGR0XPAJ_console-ramoops-0.txt`
  - `tests/device/ip/records/20260318T153320Z_28201JEGR0XPAJ_pmsg-ramoops-0.bin`
  - `tests/device/ip/records/20260318T153320Z_28201JEGR0XPAJ_device-repro.log`

关键 excerpt（来自 `console-ramoops-0`）：

```text
Kernel panic - not syncing: stack-protector: Kernel stack is corrupted in: sock_ioctl+0x4f8/0x55c
CPU: 2 PID: 11608 Comm: sh
__stack_chk_fail+0x2c/0x30
sock_ioctl+0x4f8/0x55c
```

## Notes

- panic 已确认与 `sucre-snort`/NFQUEUE 无关（`REPRO_MODE=net_only` 仍可触发）。
- 进一步定位显示：问题不是“server child `sh` 一 accept 就炸”；目前最小必要集合更接近于 `sh_cat_zero` server + client 侧真实读流，client 是否再额外起 shell/pipeline 不重要。
- 该文档固定“必现复现条件 + 证据路径 + 当前定位结论”；kernel 根因与长期修复（替换负载生成方式、替换 netcat 实现/版本、或上报 AOSP/kernel bug）另开 change 讨论。
