# DX 真机测试重组纲领

更新时间：2026-04-23  
状态：讨论稿 / 当前共识

本文件用于记录当前对 `Device / DX` 真机测试体系重组的阶段性共识。  
目标不是立即展开实现细节，而是先把后续拆 change 时必须遵守的分类、边界、迁移方向讲清楚。

## 1. 适用范围与边界

本文件只讨论 `Device / DX` 真机测试：

- host/WSL 侧通过 ADB 驱动 rooted Android 真机
- 真机平台 gate、功能冒烟、测试模组、perf/stress/longrun

本文件**不**涵盖：

- `Host` 单测 / `ASAN` / 覆盖率体系（见 `docs/testing/HOST_TEST_SURVEY.md`）
- 产品功能实现
- 具体到每一个脚本怎么改、何时删、何时迁移的实现步骤

## 2. 已固定的重组原则

### 2.1 active 体系只保留两类

当前 active 的真机测试只保留两类：

- `smoke`
  - 主线功能 gate
  - 覆盖必须活着的主路径
  - 跑不过就表示当前改动不能继续往后走
- `diagnostics`
  - 性能、压测、退化观测、长跑
  - 重点是发现退化或异常，不承担主功能准入语义

`archive` 只作为历史存放区，不是 active 分类的一部分。

### 2.2 active 主线一律使用 vNext

- 重组后的 active `Device / DX` 主线接口一律以 `vNext` 为准
- legacy / compat 入口只允许作为迁移期对照或历史参考存在
- 不允许把两代接口继续混在同一个 active 主入口里

### 2.3 当前不单独设立 specialized 类别

当前仓库现状下，大多数“专项功能覆盖”本质上仍属于 `smoke` 覆盖面的一部分。  
因此当前不单独设立 `specialized` 一级分类，避免为了未来可能性提前设计空结构。

### 2.4 路径只承载稳定维度

后续若做目录重组，路径只表达稳定维度：

- 运行环境：`host` / `device`
- 生命周期：`active` / `archive`

测试职责（`smoke` / `diagnostics`）应作为入口组、标签和总索引语义，不需要把所有语义都硬塞进路径层级。

### 2.5 一个入口只承担一种职责

- `smoke` 入口只承担主线 gate 语义
- `diagnostics` 入口只承担观测/比较语义
- 若当前某脚本同时承载多种职责，应视为**迁移源**，而不是未来的最终形态

### 2.6 现存 `p1/p2/ip-smoke` 只视为历史命名

- 当前仓库内的 `p1/p2/ip-smoke` 等旧命名，不再保留为未来入口名、分类名或长期兼容别名
- 后续凡是处理相关入口的迁移类 change，都必须明确：
  - 旧命名被什么新入口替换
  - 旧命名在本次 change 中是否已经移除
  - 文档 / `CTest` / VS Code Testing 展示是否已同步更新
- 不允许在新的 change 中继续新增或复用 `p1/p2/ip-smoke` 语义

### 2.7 legacy 入口的归档硬门槛

- 任何 legacy 入口，如果它覆盖的能力还**没有**对应的 `vNext` 测试版本，则**禁止归档**
- 任何 legacy 入口，即使已经出现名义上的 `vNext` 版本，只要原有覆盖责任还**没有被真正接住**，则仍然**禁止归档**
- 因此，legacy 入口在 `vNext` 覆盖补齐之前，最多只允许处于：
  - active
  - 迁移源

这里的“对应 `vNext` 测试版本”不只是“有一个新脚本”：

- 必须已经存在对应的 `vNext` 入口
- 必须已经接住 legacy 入口原先承担的测试责任

否则所谓“归档”本质上就是直接丢失覆盖。

### 2.8 纲领与具体 change 的分工边界

本文件只定义：

- active `smoke` / `diagnostics` / `archive` 的分类原则
- 主入口命名原则
- legacy 入口迁移与归档的判定法则
- 什么情况下可以视为“被 `vNext` 接住”的抽象标准

本文件**不**负责：

- 拆到每一个现存脚本或 case 的一一映射
- 决定某个脚本本次具体迁到哪个新脚本
- 决定某个脚本是否本次就删除、改名、合并
- 维护与当前代码强绑定的逐项迁移清单

凡是已经进入“具体到某个脚本 / 某个 case / 某次迁移范围”的问题，都应在后续具体实现类 change 中决定，而不是继续堆在纲领文件里。

## 3. 对当前现状的判断

### 3.1 现在的问题不是“domain 真机测试缺失”

当前仓库里，domain 相关真机覆盖已经存在，问题已经从“缺不缺”转为“怎么重组”：

- `tests/integration/run.sh`
  - 包含 `IT-12`，覆盖 `METRICS.DOMAIN.SOURCES*`
- `tests/integration/vnext-baseline.sh`
  - 已覆盖 `DOMAINRULES / DOMAINPOLICY / DOMAINLISTS`
- `tests/integration/device-smoke.sh`
  - 已有最小 `vNext` domain surface

因此当前的核心问题是：

- 角色不清
- active / migration / archive 混在一起
- `vNext` 主线与 legacy 迁移源尚未完全分轨

### 3.2 latency / perf 路径也不是空白

当前真机上的性能/latency 观测已经有两条现成路径：

- `tests/integration/perf-network-load.sh`
  - 真机真实下载流量下读取 `METRICS.PERF`
  - 已有 idle/load 对比语义
- `tests/device-modules/ip/run.sh --profile perf`
  - 受控 IP 拓扑下的 perf / latency 对比

因此当前也不是“没有 latency 路径”，而是“这条路径尚未收敛进新的 diagnostics 体系”。

## 4. 当前入口的重组归类

| 当前入口 | 当前覆盖 | 未来归类 | 当前判断 |
| --- | --- | --- | --- |
| `tests/integration/vnext-baseline.sh` | `vNext` 控制面基线；含 domain surface、metrics surface、IPRULES vNext surface | `smoke` | 这是未来 active `smoke` 的主骨架 |
| `tests/integration/device-smoke.sh` | 真机平台 gate：root、socket、netd、iptables/NFQUEUE、SELinux、lifecycle；并含最小 `vNext` domain surface | `smoke` | 保留在主线合理，不急于过度拆分 |
| `tests/device-modules/ip/run.sh --profile vnext` | IP `vNext` 最小真机功能闭环 | `smoke` | 应并入 active `smoke` 主线 |
| `tests/integration/perf-network-load.sh` | 真机下载负载下的 `METRICS.PERF` / latency 观测 | `diagnostics` | 作为 diagnostics 主入口之一是合理的 |
| `tests/device-modules/ip/run.sh --profile perf|stress|longrun` | IP 受控拓扑 perf/stress/longrun | `diagnostics` | 应留在 diagnostics，不进入主 gate |
| `tests/integration/run.sh` | legacy baseline；含 core/config/app/streams/reset，以及 domain sources 覆盖 | 迁移源 / `archive` 候选 | 内容有价值，但不应继续作为未来主入口 |
| `tests/integration/iprules.sh` | legacy `IPRULES v1` 基础验收 | 迁移源 / `archive` 候选 | 应被 `vNext` 的 IP smoke 吸收 |
| `tests/integration/iprules-device-matrix.sh` | legacy `IPRULES v1` 真机矩阵 | 迁移源 / `archive` 候选 | 继续保留参考价值，但不宜当 active 主线 |
| `tests/device-modules/ip/run.sh --profile smoke` | 当前混合 `iprules smoke + native replay poc` | 待拆 / 待收敛 | 不应直接等同未来 active `smoke` |
| `tests/integration/full-smoke.sh` | 更广的 legacy 控制协议冒烟回归 | 迁移源 / `archive` 候选 | 用于捞缺口，不继续作为主线入口 |

## 5. 当前阶段的迁移重点

在不展开实现细节的前提下，当前已明确的迁移重点如下：

### 5.1 把 active `smoke` 收敛到 `vNext`

- 未来 active `smoke` 应以 `tests/integration/vnext-baseline.sh` 为主骨架
- `tests/integration/device-smoke.sh` 继续承担平台 gate
- IP 真机最小闭环应由 `tests/device-modules/ip/run.sh --profile vnext` 纳入主线

### 5.2 把仍有价值的 domain 覆盖迁入 active `smoke`

- 从 `tests/integration/run.sh`、`tests/integration/full-smoke.sh` 中识别仍有价值的 domain 覆盖
- 迁移目标是 active `smoke`
- 迁移完成前，legacy 脚本仍可作为迁移源或回查材料存在

### 5.3 把 latency / perf 统一纳入 diagnostics

- `tests/integration/perf-network-load.sh` 继续承接真机真实流量 perf 观测
- `tests/device-modules/ip/run.sh --profile perf|stress|longrun` 继续承接受控拓扑 diagnostics
- 后续 diagnostics 只讨论“怎么收敛”，不再把它混进主功能 gate

当前阶段对 diagnostics 的要求只到“归位”为止：

- 先把现有的 perf / stress / longrun / 相关观测入口迁移到正确位置
- 不预先锁定 diagnostics 的最终主入口命名
- 不预先锁定 diagnostics 的最终内部细分层次

也就是说，当前阶段只要求 diagnostics 类测试先从 active `smoke` / legacy 混合区中分离出来；更细的 diagnostics 体系设计，留到后续具体 change 再决定。

### 5.4 archive 只是结果，不是先验分类中心

当前不会把“历史保留”抬成一个与 `smoke`、`diagnostics` 对等的 active 分类。  
某个入口只有在以下条件满足时，才进入 archive：

- 已经存在对应的 `vNext` 测试版本
- 对应的 `vNext` 测试版本已经接住原有覆盖责任
- 已经不是 active 主线
- 仍保留迁移参考价值，或者短期内还需要回查

如果以上前两条不成立，则该入口最多只能继续保留在 active 或“迁移源”状态，不允许直接归档。

这里的 archive 不是纯文档状态，而是真正的目录迁移：

- 一旦某个入口被判定为允许 archive，应进入实际的 archive 目录体系
- 不继续留在 active 工作目录中制造“仍是主工作区内容”的错觉
- 因此，archive 在本项目里同时具有：
  - 生命周期含义
  - 物理目录位置含义

## 6. 当前建议的文档与入口形态

本纲领当前只先固定方向，不锁死最终命名：

- 文档上：
  - 保留一个 `Device / DX` 总索引
  - 保留一个真机测试重组纲领
  - 其他专题文档只补专项前置、判定标准与运行记录
- 入口上：
  - active 只收敛为少数几个入口组
  - 不继续把每个底层脚本都当成用户必须记住的主入口

### 6.1 active `smoke` 主入口名

当前共识下，active `smoke` 最终只保留 **1 个总入口 + 3 个子入口**：

- `dx-smoke`
  - active `Device / DX` 主线总入口
  - 顺序执行 `platform -> control -> datapath`
  - 其通过含义是：当前真机 `vNext` 主线具备最小可继续集成的功能闭环
- `dx-smoke-platform`
  - 对应当前 `tests/integration/device-smoke.sh`
  - 负责真机平台 gate：root、socket、netd、iptables/NFQUEUE、SELinux、lifecycle 等
- `dx-smoke-control`
  - 对应当前 `tests/integration/vnext-baseline.sh`
  - 负责 `vNext` 控制面与返回面基线
- `dx-smoke-datapath`
  - 对应当前 `tests/device-modules/ip/run.sh --profile vnext`
  - 负责真实 datapath / IP `vNext` 最小功能闭环

上述名字的约束如下：

- active `smoke` 名称中不再显式携带 `vnext`
  - 原因：active 主线默认就以 `vNext` 为准，再写一遍只会造成冗余
- 不继续沿用 `p1` / `p2` / `ip-smoke`
  - 原因：这些属于历史 lane 命名，不适合作为未来对外主入口名
- 不使用 `baseline`
  - 原因：语义过宽，无法直接表达它是平台 gate、控制面基线还是 datapath 闭环
- 不把 `domain` / `ip` 直接升成 active `smoke` 一级入口名
  - 原因：那是在表达覆盖内容，不是在表达入口职责；长期会导致 active 主入口越拆越碎

这里的 `platform / control / datapath` 不是新的一级分类，仍然都属于 active `smoke` 内部的执行切片。

### 6.1.1 `dx-smoke` 的执行顺序与 gate 语义

`dx-smoke` 作为 active `smoke` 总入口，固定按以下顺序执行：

- `dx-smoke-platform`
- `dx-smoke-control`
- `dx-smoke-datapath`

该顺序不做自由重排，原因如下：

- `platform` 是运行前提；这一层不稳定，则后续控制面和 datapath 结论都不可信
- `control` 是控制面基线；若它失败，则 datapath 问题无法清楚区分是控制面问题还是流量面问题
- `datapath` 放在最后，作为最终真实效果闭环 gate

`dx-smoke` 的 gate 语义固定如下：

- `dx-smoke` 是严格 gate，不承担 diagnostics 职责
- 只有 `platform`、`control`、`datapath` 三段全部通过，`dx-smoke` 才算通过
- 任意一段失败，`dx-smoke` 整体失败
- 执行策略采用分段 fail-fast：
  - `platform` 失败，则不再继续执行 `control` / `datapath`
  - `control` 失败，则不再继续执行 `datapath`

当前阶段语义上至少区分三种总入口状态：

- `PASS`
  - 三段全部通过
- `FAIL`
  - 在已满足可运行前置的情况下，任意一段执行失败
- `BLOCKED`
  - 设备 / ADB / root / deploy 等前置不满足，导致总入口无法开始

无论后续具体实现使用 `skip`、非零退出码还是其它表示方式，`BLOCKED` 都不能被视为“通过”。

为避免段间互相污染，还应遵守一条运行约束：

- 若某段内部存在 restart / teardown / reset / 破坏性检查，应尽量放在该段尾部，避免影响后续或前置段的语义清晰度

### 6.2 迁移源总表

本表只用于记录当前迁移源的**状态与目标归属**，不展开到脚本内 case 级映射。
更细的覆盖责任拆分、迁移范围与 defer 项，统一留到后续具体 change 决定。

迁移源的可见性规则固定如下：

- 迁移源只供按需回查，不作为用户日常运行入口
- 迁移源必须在纲领 / 索引中可见，便于追踪迁移状态
- 迁移源不得进入：
  - `dx-smoke`
  - 默认 diagnostics 入口
  - 主 quick start / 主推荐命令
- 迁移源只能在以下场景下被显式点名运行：
  - 迁移核对
  - 回归对照
  - 历史问题回查

| 当前入口 | 当前状态 | 目标归属 | 迁移结论 | 备注 |
| --- | --- | --- | --- | --- |
| `tests/integration/run.sh` | `迁移源` | `dx-smoke-control` | `待补 vNext` | 仍承载部分 legacy baseline / domain 责任，当前不能归档 |
| `tests/integration/iprules.sh` | `迁移源` | `dx-smoke-datapath` | `待补 vNext` | 现有 IP 真机责任尚未被 `vNext` datapath 主线完整接住 |
| `tests/integration/iprules-device-matrix.sh` | `迁移源` | `diagnostics` / 后续专项迁移 | `待补 vNext` | 当前仍保留真机矩阵参考价值，不能直接归档 |
| `tests/integration/full-smoke.sh` | `迁移源` | `dx-smoke-control` | `迁移后再评估 archive` | 可作为 legacy 广覆盖回查入口，但不再作为未来主线入口 |
| `tests/device-modules/ip/run.sh --profile smoke` | `迁移源` | `dx-smoke-datapath` | `待收敛` | 当前混合 `iprules smoke + native replay poc`，不直接等同未来 active `smoke` |

若后续目录重组成立，当前建议方向是：

- `tests/device/smoke/`
- `tests/device/diagnostics/`
- `tests/archive/device/`

但这仍属于后续实现阶段的结构化动作；本文件当前只记录方向，不视为已落地状态。

## 7. 本文件在后续 change 中的角色

本文件是后续拆分 change 前的纲领约束。  
后续如果要启动实现类 change，应以本文件作为上层边界，至少回答清楚：

- 这次改动属于 `smoke` 还是 `diagnostics`
- 是否仍然混用了 legacy / compat 接口
- 是在收敛 active 主线，还是仅在迁移源/archive 中做整理
- 是否把本应进入 `vNext` 主线的覆盖继续留在 legacy 脚本里

若某个 change 开始处理具体 legacy 入口，则该 change 自身必须补齐：

- 本次触及哪些 legacy 入口
- 对应的 `vNext` 承接入口是什么
- 覆盖责任当前处于：
  - 未接住
  - 部分接住
  - 已接住
- 本次迁移哪些责任点，哪些责任点明确 defer
- 因此本次变更结束后，该入口处于：
  - 继续 active
  - 转为迁移源
  - 允许 archive

在这些问题没有讲清楚之前，不应直接开始大规模重排测试入口与目录。
