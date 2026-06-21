# VPP NFQUEUE POC 实验任务

日期：2026-06-21
分支：`research/vpp-nfq-poc`
状态：实验任务定义 / 暂停点。本文只定义下一步实验，不表示已经开始 clone、build、patch 或运行。

## 1. 实验目标

这轮实验只回答两个问题：

1. VPP 能否通过 Linux NFQUEUE 收包，并把 `ACCEPT` / `DROP` verdict 正确回写给 NFQUEUE。
2. 在 NFQUEUE fd 没有流量时，VPP 能否进入 fd/epoll/interrupt 型等待，而不是像 DPDK polling 一样让单个 CPU core 长期 100%。

如果这两个问题有任何一个不成立，VPP 作为 Snort core datapath 的优先级应下降，至少不能直接进入 Android / VPN / HEV / UID attribution 讨论。

## 2. 当前边界

本 POC 先只做 Linux + Docker。

暂不做：

- Android 真机编译。
- Android root NFQUEUE 验证。
- Android VPN `tun-fd` 接入。
- HEV / tun2socks 接入。
- UID attribution。
- Snort CT A++ 移植。
- Snort policy / telemetry 移植。
- 性能优化。

第一阶段只验证 VPP 是否适合作为 packet graph runtime 的入口和 verdict 承载体。

## 3. VPP 版本策略

第一轮使用 upstream FDio VPP 稳定 tag：

```text
v26.02
```

原因：

- GitHub tags 中 `v26.02` 是当前可见稳定 tag。
- `v26.06-rc1` 和 `v26.10-rc0` 是 RC，不作为第一轮基线。
- POC 跑通后，再用同一套脚本试 RC tag，确认是否有接口变化。

VPP 源码不直接 vendor 到本仓库。仓库只保留 POC 脚本、patch、插件源码、测试脚本和实验记录。

## 4. 推荐目录

```text
experiments/vpp-nfq-poc/
  README.md
  Dockerfile
  scripts/
    fetch-vpp.sh
    build-vpp.sh
    run-container.sh
    setup-netns.sh
    run-smoke.sh
    collect-cpu.sh
  patches/
    vpp-v26.02-nfq-poc.patch
  plugin/
    nfqueue_poc/
  results/
    .gitkeep
```

`results/` 只保存小型文本结果。大体积 build output、VPP tree、core dump、pcap 不进 git。

## 5. POC 形态

目标链路：

```text
Linux packet
  -> iptables/nftables NFQUEUE
  -> libnetfilter_queue fd
  -> VPP input node
  -> vlib_buffer_t
  -> minimal verdict node
  -> nfq_set_verdict(packet_id, NF_ACCEPT | NF_DROP)
  -> kernel continues or drops packet
```

最小节点行为：

- mode `accept-all`：所有 packet 回 `NF_ACCEPT`。
- mode `drop-all`：所有 packet 回 `NF_DROP`。
- mode `drop-ratio=50`：按 packet counter 或 hash 丢约一半包。

第一版不要求进入完整 VPP IP forwarding。可以先把 NFQUEUE packet 当成 VPP buffer + sidecar，然后在自定义 node 里直接 verdict。

## 6. 必须采集的 NFQUEUE 信息

第一阶段至少保留：

- `packet_id`
- `queue_num`
- packet family
- hook / direction，如果 libnetfilter_queue 可取到
- payload length
- copied length / original length，如果可取到

第一阶段不要求消费 UID，但需要确认是否可以从 NFQUEUE attrs 中读取并放入 sidecar：

- `NFQA_UID`
- `NFQA_GID`
- `NFQA_IFINDEX_INDEV`
- `NFQA_IFINDEX_OUTDEV`
- `NFQA_MARK`
- `NFQA_TIMESTAMP`

结论文档必须明确：哪些 attrs 在本机内核 + queue 配置下能拿到，哪些拿不到。

## 7. Docker / Linux 环境要求

容器需要能操作 netfilter 和网络命名空间。

优先尝试：

```text
--cap-add NET_ADMIN
--cap-add NET_RAW
```

如果不足，再记录需要 `--privileged` 的具体原因。

测试网络建议使用独立 namespace / veth，避免污染宿主机主网络。

## 8. 验收用例

### Case A: accept-all

步骤：

- 配置 NFQUEUE 规则。
- 启动 VPP POC。
- 从测试 namespace 发 `ping` 或 `curl`。

验收：

- 流量正常通过。
- VPP 计数显示收到 packet。
- NFQUEUE verdict 计数等于收到 packet 数。
- 没有 packet 卡在 queue 中。

### Case B: drop-all

步骤：

- 切换 POC mode 为 `drop-all`。
- 重复 `ping` 或 `curl`。

验收：

- 流量被阻断。
- VPP 计数显示收到 packet。
- NFQUEUE `DROP` verdict 计数等于收到 packet 数。

### Case C: drop-ratio=50

步骤：

- 切换 POC mode 为 `drop-ratio=50`。
- 发固定数量 ICMP 或 TCP request。

验收：

- 外部观察到接近 50% 丢包。
- VPP 内部 drop/accept 计数接近 50/50。
- 每个 packet 只回一次 verdict。

### Case D: idle CPU

步骤：

- 启动 VPP POC 后停止流量 60 秒。
- 采集 `top -H`、`pidstat -t` 或等效 CPU 统计。
- 再制造流量，之后停止流量并再次采集。

验收：

- 无流量时 VPP 线程不能长期单核 100%。
- 有流量时 CPU 随流量上涨。
- 停流后 CPU 能回落。
- VPP input node 不应被永久设成 `POLLING`。

### Case E: queue pressure

步骤：

- 用较高 packet rate 打一段时间。
- 观察 NFQUEUE queue length、VPP counters、verdict counters。

验收：

- 没有明显 packet id 泄漏。
- 没有重复 verdict。
- VPP 停止或崩溃时，失败模式必须记录清楚。

## 9. 停止条件

以下任一情况发生，本轮 POC 应停止并写结论，不继续扩展 Android/VPN：

- VPP 无法稳定从 NFQUEUE 收到 packet。
- `NF_ACCEPT` / `NF_DROP` verdict 不能可靠影响 kernel 后续处理。
- 必须使用永久 polling 才能工作，导致 idle 单核 100%。
- NFQUEUE packet id 生命周期无法安全绑定到 VPP buffer / sidecar。
- Docker 内实验依赖宿主机不可接受的全局网络改动。

## 10. 下一步任务清单

1. 创建 `experiments/vpp-nfq-poc/` 骨架。
2. 写 Dockerfile，安装 VPP build dependencies、libnetfilter_queue、iptables/nftables、测试工具。
3. 写 `fetch-vpp.sh`，clone FDio VPP 并 checkout `v26.02`。
4. 写 `build-vpp.sh`，在容器中完成最小 VPP build。
5. 写最小 NFQUEUE POC plugin 或 patch。
6. 写 `setup-netns.sh`，创建隔离测试 namespace / veth / NFQUEUE 规则。
7. 写 `run-smoke.sh`，覆盖 accept-all、drop-all、drop-ratio=50。
8. 写 `collect-cpu.sh`，采集 idle 和 active CPU 数据。
9. 运行 Case A 到 Case E。
10. 把结果沉淀到同目录 `README.md` 或新的 result doc。

## 11. 本轮不做的决策

这份实验任务不决定：

- 是否把 Snort 主线切到 VPP。
- 是否废弃当前 NFQUEUE runtime。
- 是否重写 CT A++。
- 是否采用 VPP worker-local session model。
- 是否在 Android 上使用 VPP。
- 是否使用 HEV。

这些都必须等 Linux NFQUEUE + idle CPU POC 有结果后再讨论。

## 12. 参考

- FDio VPP upstream: https://github.com/FDio/vpp
- FDio VPP tags: https://github.com/FDio/vpp/tags
- Linux netfilter queue project: https://netfilter.org/projects/libnetfilter_queue/
- 本地历史参考：`/home/js/backup/backup/Git/vpp/src/plugins/stellar_netfilter_queue_deprecated/`
