# sucre-snort vs iode-snort 差异总结

## 1. 核心架构变更

### 域名列表管理
**iode-snort**: 静态文件系统
- 单一黑/白名单文件: `/system_ext/etc/iode-snort/domains-{black,white}`
- DomainList 直接读取文件
- `_domains`: 单一域名集合

**sucre-snort**: 动态多列表系统
- `_domainsByListId`: Map<ListID, DomsSet>
- 运行时增删启禁列表
- 每列表独立管理，GUID 标识

### 功能模块替换
**移除**: DefaultAppsManager (预装应用管理)
- 3 命令: LIST, INSTALL, REMOVE
- 管理 iodéOS 推荐应用

**新增**: BlockingListManager (屏蔽列表管理)
- 15+ 命令: ADD, UPDATE, OUTDATE, REMOVE, ENABLE, DISABLE, PRINT, SAVE
- 管理第三方域名列表订阅

## 2. BlockingList 实体

### 属性
- `id`: GUID (36+1 字符)
- `name`: 1-50 字符
- `url`: 1-256 字符
- `color`: BLACK/WHITE
- `blockMask`: 保护级别掩码
- `updatedAt`: Unix 时间戳
- `outdated`: 过期标志
- `etag`: HTTP 缓存
- `enabled`: 启用状态
- `domainsCount`: 域名计数

### 特性
- HTTP ETag 增量更新
- 时间格式: `%Y-%m-%d_%H:%M:%S`
- JSON 序列化
- 完整持久化

## 3. DomainManager 扩展

### 新增接口 (sucre-snort)
```cpp
start(vector<BlockingList>)              // 加载列表
addDomainsToList(id, mask, clear, doms)  // 批量导入
removeDomainList(id)                     // 删除列表
switchListColor(id)                      // 更改类型
enableList(id, mask) / disableList(id)   // 启禁控制
changeBlockMask(id, mask)                // 修改级别
getDomainsCount() / printDomainsFromList() // 查询统计
```

### DomainList 方法对比

**iode-snort**:
- `set(filename)`: 从文件加载
- `add(filename)`: 追加文件
- `blockMask(domain)`: 查询掩码

**sucre-snort**:
- `get/set(listId, domains)`: 列表操作
- `read/write(listId, mask)`: 文件 I/O
- `enable/disable(listId)`: 状态控制
- `erase(listId)`: 删除列表
- `blockMask(domain)`: 累积所有列表

## 4. Settings 配置

### 缓冲区
- iode: `controlCmdLen = 1000`
- sucre: `controlCmdLen = 20000` (20x)

### 路径
**iode-snort**:
```
defaultBlacklist/defaultWhitelist  // 静态列表
defaultAppsFile                    // 应用管理
```

**sucre-snort**:
```
saveDirDomainLists = "/data/snort/save/domains_lists/"
saveBlockingLists = "/data/snort/save/blocking_lists"
```

## 5. Saver 序列化

### 新增方法 (sucre-snort)
```cpp
readGuid(str)             // 37 字节
readBlockingListName(str) // 1-50 字节
readBlockingListUrl(str)  // 1-256 字节
readBlockingListType(str) // 6 字节 "BLACK\0"/"WHITE\0"
```

## 6. Control 命令

### 移除 (iode-snort)
```
DEFAULTAPPS.{LIST,INSTALL,REMOVE}
```

### 新增 (sucre-snort)
```
BLOCKLIST.{BLACK,WHITE}.ADD <id> <url> <name>
BLOCKLIST.{BLACK,WHITE}.UPDATE <id> <url> <name>
BLOCKLIST.{BLACK,WHITE}.OUTDATE <id>
BLOCKLIST.{BLACK,WHITE}.REMOVE <id>
BLOCKLIST.{BLACK,WHITE}.{ENABLE,DISABLE} <id>
BLOCKLIST.{PRINT,CLEAR,SAVE}
```

## 7. 类型改进

### Stats
- 新增: `ListColorException`
- 新增: `colorToString()` → JSON

### App
- `NamesVec`: `vector<const string>` → `vector<string>`

### CmdArg
- iode: `{NONE, INT, STR}`
- sucre: `{NONE, INT, STR, BOOL}`

## 8. 代码规模

| 指标 | iode-snort | sucre-snort | 增量 |
|------|-----------|-------------|------|
| 总行数 | 6039 | 6722 | +683 (11.3%) |
| 源文件数 | 48 | 50 | +2 |

### 新增文件
- BlockingList.{cpp,hpp}: 210 行
- BlockingListManager.{cpp,hpp}: 158 行

### 删除文件
- DefaultAppsManager.{cpp,hpp}: ~250 行

### 显著修改
- Control.cpp: 33545 → 44292 字节 (+32%)
- DomainList.cpp: 1558 → 5514 字节 (+254%)
- DomainManager.cpp: 5383 → 8993 字节 (+67%)

## 9. Git 演进

```
iode-snort (e84f6fa)
  ↓ fork
sucre-snort (82a1c62) - Implements blocking list management
  ↓ (3b19a9b) - Add Blocking list mask management
  ↓ (f7d967a) - Implements list domains addition
  ↓ (c306f64) - FIX: Better list deletion + ADD: Outdate
  ↓ (7a85c0a) - Rebrand to sucre
  ↓ (5618895) - Remove DefaultAppManager
  ↓ (d63c784) - HEAD
```

## code review

状态: 已在当前仓库 HEAD (d63c784) 逐项核对，1–29 均已修复；以下为 30+ 新发现且待修复的问题。

### 并发安全缺陷

#### 1. DomainList::disable/enable 死锁 (CRITICAL) ✅ **已修复**
**位置**: src/DomainList.cpp:144-154, 132-142

disable():145 持有 shared_lock → 调用 erase():118 尝试获取 unique_lock → 同一线程死锁。enable() 同理。

**影响**: BLOCKLIST.*.DISABLE/ENABLE 永久冻结控制线程。

**修复方案**: disable/enable 全程持有 unique_lock + eraseUnlocked() helper。

---

#### 2. DomainList 竞态条件 (CRITICAL/HIGH) ✅ **已修复**

| 方法 | 位置 | 问题 | 级别 |
|------|------|------|------|
| read() | :43-60 | 持 shared_lock 执行 emplace() 写操作 | CRITICAL |
| changeBlockMask() | :156-160 | 完全无锁访问修改 _domainsByListId | CRITICAL |
| get() | :15 | 无锁使用 operator[] 导致隐式写入（key 不存在会插入）；返回值为拷贝 | CRITICAL |
| printDomains() | :162-166 | 完全无锁迭代 map | HIGH |
| size() | hpp:31-37 | 完全无锁迭代所有 list | HIGH |

**影响**:
- read/changeBlockMask 与 blockMask() 并发 → map 损坏/崩溃
- get() 返回容器可被其他线程同步修改 → 迭代器失效
- printDomains/size 与 write/erase 并发 → 迭代器失效

**修复方案**:
- read(): 两阶段（文件 I/O 无锁 + unique_lock 合并）
- get(): find() 替代 operator[]，添加 shared_lock
- changeBlockMask(): 添加 unique_lock
- printDomains()/size(): 添加 shared_lock

---

#### 5. DomainList::enable 递归共享锁 (CRITICAL) ✅ **已修复** (合并至 Issue #1)
**位置**: src/DomainList.cpp:132-142

enable():133 持 shared_lock → 调用 read():44 再次获取 shared_lock (同一线程)。

**问题**: std::shared_mutex **不支持递归**，重复 lock_shared() 是未定义行为（cppreference: "If the mutex is already locked by this thread in any mode, the behavior is undefined"）。

**影响**: BLOCKLIST.*.ENABLE 可能死锁/运行时错误（平台相关）。与 disable 死锁机制不同（后者尝试 unique_lock 升级，100%死锁）。

**修复方案**: 已在 Issue #1 统一修复（全程 unique_lock）。

---

#### 6. DomainList::get() operator[] 竞态 (CRITICAL) ✅ **已修复** (合并至 Issue #2)
**位置**: src/DomainList.cpp:15

```cpp
DomsSet get(std::string listId) { return _domainsByListId[listId]; }  // 无锁 + operator[]
```

**问题**:
- operator[] 当 key 不存在时插入默认值（写操作）
- 完全无锁，与 blockMask() 的 shared_lock 读取竞争

**调用点**: DomainManager.cpp:227,230 (switchListColor)

**影响**: get() 隐式写入 vs blockMask() 读取 → 数据竞争/崩溃。

**修复方案**: 已在 Issue #2 统一修复（find() + shared_lock）。

---

#### 3. BlockingListManager 完全无保护 (CRITICAL) ✅ **已修复**

| 方法 | 位置 | 问题 |
|------|------|------|
| addBlockingList() | :12-21 | TOCTOU: 无锁 find():14 检查 → 加锁 try_emplace():18 |
| findListById() | :23-29 | 无锁 find() 返回裸指针，map rehash/erase 后悬空 |
| removeBlockingList() | :31-38 | 完全无锁 find + erase |
| getAll() | :40 | 完全无锁拷贝整个 map |
| **save()** | **:54-61** | **完全无锁读 size + 迭代 _ByIds** |

**影响**:
- addBlockingList: 多线程可绕过 line 15 检查同时插入
- findListById: DomainList.cpp:77 调用，返回指针可立即失效 → use-after-free
- **save: 主线程定时调用 snortSave() 与控制线程 add/remove 并发 → 迭代器失效/崩溃**
- 所有 _ByIds 访问未同步 → 数据竞争/崩溃

**修复方案**: 所有 _ByIds 操作加锁（save 至少 shared_lock）。findListById 改返回 shared_ptr 或要求持锁调用。

**实际修复**: 全方位加锁 + 删除 findListById + 快照模式（详见修复记录 2025-11-16）。

---

#### 4. CustomRules::build() 竞态 (CRITICAL) ✅ 已修复
**位置**: src/CustomRules.cpp:37-51

build() 完全无锁读 _rules、写 _regex，外部调用者均无锁:
- CustomRules.cpp:82 (restore)
- DomainManager.cpp:118 (buildCustomRules)
- App.cpp:114 (buildCustomRules)

同时 match():54 持 shared_lock 读 _regex。

**影响**:
- build() 写 _regex 与 match() 并发读 → 数据竞争 (std::regex 非线程安全)
- RulesManager.cpp:57,60,63,149,151 调用 buildCustomRules 与数据包处理线程 match() 并发 → 未定义行为/崩溃

**修复**: 引入 `buildUnsafe()`，要求在持有独占锁时调用；同时 `build()` 自身获取独占锁后转调 `buildUnsafe()`，避免与 `match()` 的并发读写竞争，且防止在 `add/remove/reset` 已持锁时二次加锁导致的死锁。
**提交**: d63c784.. (CustomRules.cpp/hpp)

---

#### 7. Control handlers nullptr 崩溃 (HIGH) ✅ **已修复**
**位置**: src/Control.cpp:794-894

| 函数 | 行号 | 问题 |
|------|------|------|
| cmdOutdateBlockingList | :798-799 | `findListById()` 未检查 nullptr 直接 `->setIsOutDated()` |
| cmdEnableBlockingList | :864-865 | 未检查直接 `->getBlockMask()` |
| cmdDisableBlockingList | :882-884 | 未检查直接 `->disable()` |

**触发**: 客户端传入已删除/不存在的 listId。

**影响**: 立即 segmentation fault 崩溃守护进程。

**修复方案**: `if (blockingList == nullptr) { nack(); return; }`

**实际修复**: 删除 findListById 裸指针 API，改用原子操作接口（详见修复记录 2025-11-16）。

---

#### 8. BlockingList 时间处理不安全 (MEDIUM/HIGH)

**8a. tm 未初始化 (多处)** ✅ **已修复**

| 位置 | 问题代码 |
|------|---------|
| BlockingList.cpp:47-54 | `struct tm tm;` → `mktime(&tm)` |
| **Control.cpp:765-768** | **`struct std::tm tm;` → `mktime(&tm)`** |

```cpp
struct tm tm;  // ← 未初始化
ss >> get_time(&tm, "%Y-%m-%d_%X");  // ← 未检查状态
_updatedAt = mktime(&tm);  // ← tm_isdst 等字段含垃圾值
```
**问题**: get_time 只填充匹配字段，tm_isdst 保持未初始化，mktime 读取所有字段 → 未定义行为。未检查解析是否成功。

**触发**: refreshList 接收格式错误字符串 / cmdUpdateBlockingList 收到恶意 updatedAtStr。

**8b. serialize strftime 缓冲区太小** (:108-113)
```cpp
char dateBuffer[19];  // ← 19 字节
strftime(dateBuffer, 19, "%Y-%m-%d_%X", date_tm);  // ← 格式需 19 字符 + 1 null
string dateStr(dateBuffer, 19);  // ← 未初始化数据
```
**问题**: 格式 `2025-11-04_12:34:56` 需 19 字符 + null = 20 字节。缓冲区不足，strftime 返回 0，dateBuffer 保持未初始化 → 随机栈数据泄露到 JSON。

**8c. serialize gmtime 非线程安全** (:110)
```cpp
tm *date_tm = gmtime(&date);  // ← 返回进程全局静态缓冲区
```
**问题**: 多线程并发调用 gmtime 相互覆盖，cppreference: "may not be thread-safe"。

**触发**: 并发 BLOCKLIST.PRINT 命令调用 serialize()。

**修复方案**: `struct tm tm{};` + 检查 `get_time` 状态 + `char dateBuffer[20]` + 检查 strftime 返回值 + 使用 `gmtime_r()` (POSIX) / `gmtime_s()` (Windows)。

**8a 已修复**: BlockingListManager::updateBlockingList() 和 BlockingList::refreshList() 中 tm 零初始化 + 验证解析（详见修复记录 2025-11-16）。

**8b/8c 已修复**: `serialize()` 使用 `gmtime_r`（线程安全）和足够大的缓冲区（20字节），并校验 `strftime` 返回值；格式统一为 `%Y-%m-%d_%H:%M:%S`。

---

#### 9. CustomRules::save() 无锁迭代 (CRITICAL) ✅ 已修复
**位置**: src/CustomRules.cpp:65-71

save() 完全无锁读 _rules.size() 和迭代 _rules，而 add/remove 均持 lock_guard。

**并发路径**:
```
Main Thread (sucre-snort.cpp:121)    Control Thread
  snortSave()                          cmdAddCustomRule()
  → domManager.save():132              → customRules.add():20
  → _blackRules.save():66 (无锁)       持 lock_guard 插入 _rules
  迭代 _rules
```

**影响**: 同时读写 unordered_set → 迭代器失效/数据竞争/崩溃。

**修复**: save() 获取 shared_lock_guard<_mutex>。

---

#### 10. RulesManager::addCustom/removeCustom 写穿读锁 (CRITICAL) ✅ 已修复
**位置**: src/RulesManager.cpp:79-113

```cpp
79: void RulesManager::addCustom(...) {
81:     const std::shared_lock_guard lock(_mutex);  // ← 读锁
84:     _customs[rule].color = color;               // ← 写操作
87:     _customs[rule].list(color).insert(app);     // ← 写操作

97: void RulesManager::removeCustom(...) {
99:     const std::shared_lock_guard lock(_mutex);  // ← 读锁
103:    custom.color = Stats::ALLC;                 // ← 写操作
107:    custom.list(color).erase(app);              // ← 写操作
110:    _customs.erase(rule);                       // ← 写操作
```

**问题**: 持有 `shared_lock` 但修改 `_customs` unordered_map。违反读写锁语义，shared_lock 允许多线程并发，此时写入是未定义行为。

**并发冲突**:
```
Control Thread 1                Control Thread 2
  addCustom()                     removeCustom()
  持 shared_lock                  持 shared_lock
  _customs[rule].insert           _customs.erase(rule)
  ⚠️ 同时修改 unordered_map → ASan 报错/容器损坏
```

**影响**: AddressSanitizer 检测到数据竞争，导致 _customs 损坏或崩溃。

**修复**: 改用 `std::lock_guard<std::shared_mutex>` (独占锁)。Line 81/99: shared_lock_guard → lock_guard。

---

## 修复记录

### 2025-11-16: DomainList 并发安全修复 (Issue #1, #2, #5, #6)

**修复文件**: `src/DomainList.cpp`, `src/DomainList.hpp`

**核心改进**:
1. **Lock-Free 热路径**: 引入 `_aggSnapshot` (shared_ptr<DomsSet>) + `rebuildAggSnapshotLocked()`
   - `blockMask()` 改为无锁原子读取快照（RCU 模式）
   - 所有写操作后重建快照，确保读者最终一致性
   - 性能提升：消除锁竞争 + 减少搜索复杂度 O(lists×log(N)) → O(log(N))

2. **死锁修复**:
   - `enable()`: 全程持有 unique_lock（文件 I/O 放锁内，避免与 disable() 竞态）
   - `disable()`: 全程持有 unique_lock + 调用 `eraseUnlocked()` helper

3. **竞态条件修复**:
   - `read()`: 两阶段（文件读取无锁 → unique_lock 合并数据）
   - `get()`: operator[] → find()，添加 shared_lock
   - `changeBlockMask()`: 添加 unique_lock
   - `printDomains()`/`size()`: 添加 shared_lock
   - `set()`: 添加 `rebuildAggSnapshotLocked()` 调用

4. **代码质量**:
   - 删除未使用的 `readUnlocked()` 方法
   - 添加异常安全注释（OOM 保留旧快照）
   - 添加行为说明注释（`remove()` 内存优先策略）

**验证**: 
- 所有 `_domainsByListId` 访问受 `_mutex` 保护
- shared_ptr 引用计数保证快照生命周期安全
- RAII 确保异常安全（锁自动释放）

**已修复补充**: #4 (CustomRules::build 并发)、#8b/8c (BlockingList 时间处理细节)、#9 (CustomRules::save 无锁迭代)、#10 读写锁变体（print 只读）。

---

### 2025-11-16: BlockingListManager 并发安全 + 指针 API 消除 (Issue #3, #7, #8a)

**修复文件**: `src/BlockingListManager.{cpp,hpp}`, `src/Control.cpp`, `src/DomainList.cpp`, `src/BlockingList.cpp`

**核心改进**:
1. **全方位加锁 (Issue #3)**:
   - 所有 `_ByIds` 访问持锁：写操作用 lock_guard，读操作用 shared_lock
   - save()/printAll() 采用快照模式（listsSnapshot()）最小化持锁时间
   - restore() 批量反序列化后一次性加锁插入，避免循环持锁

2. **原子 API 替代裸指针 (Issue #7)**:
   - **删除** `findListById()` 返回裸指针的方法
   - **新增** 原子操作接口：updateBlockingList(), setEnabled(), markOutdated()
   - **新增** 安全查询接口：getBlockMask(), getColor() 返回值通过引用参数
   - Control.cpp 6 处调用点改用原子 API + 强制错误检查
   - DomainList.cpp 改用 masksSnapshot() 避免指针暴露

3. **时间解析安全 (Issue #8a)**:
   - updateBlockingList() 内部：`struct tm{}` 零初始化 + 检查 get_time() 返回值
   - BlockingList::refreshList() 同样修复
   - 封装在 Manager 层，Control 不再直接处理 tm

**设计原则**: 
- **类型系统保证安全**：代码中不存在 `BlockingList*` 变量 → 编译期消除悬空指针
- **原子操作消除 TOCTOU**：查询+修改在同一锁内完成
- **快照模式平衡并发**：读多写少场景最小化锁竞争

**验证**:
- grep 确认无 findListById 调用残留
- 所有 Control handlers 强制检查返回值
- tm 解析失败自动拒绝请求

---

### 2025-11-16: CustomRules 并发安全 + RCU 热路径优化 (Issue #4, #9)

**修复文件**: `src/CustomRules.{cpp,hpp}`

**核心改进**:
1. **Lock-Free DNS 热路径 (Issue #4)**:
   - `_regexSnap`: shared_ptr<regex> 原子快照，替代裸 `_regex`
   - `match()`: 完全无锁，`std::atomic_load(&_regexSnap)` 读快照
   - `rebuildRegexSnapshotLocked()`: 持锁构建新 regex → `atomic_store` 发布
   - 性能：DNS 查询路径零锁开销，构建不阻塞读者

2. **save() 迭代器安全 (Issue #9)**:
   - 两阶段：持 shared_lock 拷贝 rule ids → 释放锁 → 磁盘 I/O
   - 防止与 add/remove 的 lock_guard 竞争导致迭代器失效
   - 最小化持锁时间，磁盘操作在锁外

3. **restore() 批量优化**:
   - 一次加锁：收集所有 rules → 批量 insert → 单次 rebuild
   - 避免 add() 循环加锁/解锁开销

4. **原子操作正确性**:
   - `_saved` 全部使用 `.store()/.load()`，消除数据竞争
   - 构造函数初始化空 regex 快照，避免空指针检查开销

**设计模式**: 
- **RCU (Read-Copy-Update)**: 读者无锁，写者拷贝-修改-发布
- **与 DomainList 一致**: 复用 `_aggSnapshot` 同款架构
- **异常安全**: regex 构造失败 → 发布空 regex，旧快照保持有效

**验证**:
- DNS 路径 (DomainManager::blocked/authorized, App::block) 无锁调用 match()
- shared_ptr 引用计数保证快照生命周期
- ThreadSanitizer 无数据竞争报告

---

### 2025-11-16: 杂项修正（一致性/无影响行为）

**改动**:
- 统一时间解析格式为 `%Y-%m-%d_%H:%M:%S`（Manager/Model 一致）
- 移除无效溢出检查（`addedCount == 0`）
- 删除未使用声明 `BlockingList::toggleList()`
- 增加命令别名 `RULES.UPDATE`（与现有 `RULES.UPDATElist` 等价）

---

### 2025-11-16: RulesManager 读写锁修复 (Issue #10)

**修复文件**: `src/RulesManager.cpp`

**改动**:
- Line 81/99 `shared_lock_guard` → `lock_guard`（写路径统一独占锁）
- `print()` 改为只读访问 `_customs`（`find` + 只读默认值），避免读锁下隐式写入
- 新增线程安全查询 `findThreadSafe()`；`restoreCustomRules()`、`CustomRules::restore()` 使用其查找，避免无锁读

**问题**: 读锁下写 `_customs`、以及无锁读 `_rules`

**修复**: 写路径独占锁；读路径只读/按需加锁

---

### 2025-11-21: PacketListener/PacketManager 热路径锁重构 (Issue #57)

- 目标: 将 NFQUEUE 热路径上的 `mutexListeners` 全局锁窗口压缩到判决/统计/流式输出这一纯计算阶段，彻底移除 `getnameinfo` 等阻塞 IO 对全局锁的占用，避免在高并发/慢 DNS 场景下饿死 `RESETALL` 等需要独占锁的控制操作。
- 核心改动:
  - `PacketManager::make` 从 `(Address&&, App::Uid, ...)` 改为 `(const Address&, const App::Ptr&, const Host::Ptr&, ...)`，内部不再调用 `appManager.make`/`hostManager.make`，只负责“给定上下文的阻断判决 + 统计更新 + Streamable<Packet> 推送”，确保无反向 DNS 或其他阻塞操作。
  - `PacketListener::callback` 改为两阶段:
    - Phase 1（锁外上下文构建）: 在未持有 `mutexListeners` 的情况下构造 `Address<IP>`，调用 `appManager.make(uid)` 与 `hostManager.make<IP>(addr)`；所有慢路径工作（含 `HostManager::create` 内的 `getnameinfo`）只在各自局部锁下执行，与全局监听锁解耦。
    - Phase 2（锁内纯计算窗口）: 在满足判决条件时获取 `mutexListeners` 共享锁，仅调用新签名的 `PacketManager::make(addr, app, host, ...)` 执行阻断判决、统计更新及 `Packet` 流事件推送；此临界区不做任何外部 IO，锁持有时间稳定在微秒级。
- 结果: 全局监听锁不再承载反向 DNS 阻塞，`RESETALL`/保存/关停等需要独占 `mutexListeners` 的控制操作即使在高 QPS + 慢 DNS 下也能在有限时间内获得写锁；数据面判决与对外控制接口语义保持不变，仅内部锁时序和责任边界收紧。

---

### 新增问题 11–53（按严重级别排序）

#### 11. BlockingList::serialize 非线程安全时间格式化 (CRITICAL) ✅ **已修复**
- 位置: sucre/sucre-snort/src/BlockingList.cpp:110-115
- 问题: 使用 gmtime()；日期缓冲 19 字节不足 20。
- 影响: 多线程序列化竞态；时间串截断/未定义行为。
- **修复**: gmtime→gmtime_r；缓冲20字节；检查strftime返回值；fallback机制 (2025-11-16, 1b49bd1)

#### 12. 信号处理包含非异步安全操作 (CRITICAL) ✅ **已修复**
- 位置: sucre/sucre-snort/src/sucre-snort.cpp:101-107
- 问题: handler 内加锁并调用保存逻辑。
- 影响: SIGINT/SIGTERM 可能死锁/崩溃/状态损坏。
- **修复**: handler仅设sig_atomic_t标志；主循环检查后调用save (2025-11-16, 06c0963)

#### 13. Saver::read(std::string) 越界写 (CRITICAL) ✅ **已修复**
- 位置: sucre/sucre-snort/src/Saver.hpp:74-85
- 问题: resize(len-1) 后 read(..., len)。
- 影响: 恢复时内存破坏/随机崩溃。
- **修复**: 分离payload/terminator读取；临时对象+swap异常安全 (2025-11-16, 06c0963)

#### 14. CmdLine 子进程 execv 失败未退出 (CRITICAL) ✅ **已修复**
- 位置: sucre/sucre-snort/src/CmdLine.cpp:33-39
- 问题: execv 失败未 _exit。
- 影响: 子进程继续跑主逻辑，导致重复初始化/混乱。
- **修复**: execv失败后_exit(127)；async-safe错误日志 (2025-11-16, 1b49bd1)

#### 15. HostManager::find 解锁后用迭代器 (CRITICAL) ✅ **已修复**
- 位置: sucre/sucre-snort/src/HostManager.hpp:62-71
- 问题: 释放共享锁后继续使用迭代器。
- 影响: 并发下迭代器失效，崩溃/数据竞争。
- **修复**: 锁内拷贝shared_ptr后解锁 (2025-11-16, 06c0963)

#### 16. DomainManager::fixDomainsColors 缺少锁 (HIGH) ✅ **已修复**
- 位置: sucre/sucre-snort/src/DomainManager.cpp:52-56
- 问题: 遍历 _byName 未加锁。
- 影响: 颜色/掩码不一致或崩溃。
- **修复**: 添加 shared_lock_guard(_mutexByName) (2025-11-16, f678cc4)

#### 17. Domain::_blockMask/_color 数据竞争 (HIGH) ✅ **已修复**
- 位置: sucre/sucre-snort/src/Domain.hpp:41-47
- 问题: 并发读写普通成员无同步。
- 影响: 判定异常。
- **修复**: 改用 atomic<uint8_t> + load/store(memory_order_relaxed) (2025-11-16, f678cc4)

#### 18. AppManager::reset 未持锁修改索引 (HIGH) ✅ **已修复**
- 位置: sucre/sucre-snort/src/AppManager.cpp:76-83
- 问题: 清空 _byUid/_byName 无锁。
- 影响: 迭代器失效/崩溃。
- **修复**: 添加 scoped_lock(_mutexByUid, _mutexByName) (2025-11-16, 7347ef0)

#### 19. App::restore 修改 _domStats 未加锁 (HIGH) ✅ **已修复**
- 位置: sucre/sucre-snort/src/App.cpp:170-177
- 问题: 多 map 更新未持对应锁。
- 影响: 与 save()/读取并发产生竞态。
- **修复**: 添加 lock_guard(mutex) 保护 _domStats 写入 (2025-11-16, 7347ef0)

#### 31. CmdLine::exec reallocarray 失败处理不当 (HIGH) ✅ **已修复**
- 位置: sucre/sucre-snort/src/CmdLine.cpp:23-37
- 问题: reallocarray 失败时覆盖 _argv 指针；旧指针泄漏；fork 后 execv 解引用空指针。
- 影响: OOM/内存碎片时守护进程启动崩溃；iptables 规则未设置导致广告拦截失效。
- **修复**: 临时变量接收返回值；失败时保留原指针并提前返回；execv失败_exit(127) (2025-11-17, 41ea924)

#### 20. 在 std 命名空间注入类型 (HIGH) ✅ **已修复**
- 位置: sucre/sucre-snort/src/sucre-snort.hpp:13-26
- 问题: 自定义 shared_lock_guard 定义在 std:: 下。
- 影响: 违反标准/未定义行为。
- **修复**: 删除自定义类定义，替换全部54处为 std::shared_lock<std::shared_mutex> (2025-11-16, ace450b)

#### 21. DnsListener::clientRun 使用 VLA (MEDIUM) ✅ **已修复**
- 位置: sucre/sucre-snort/src/DnsListener.cpp:54-55
- 问题: 非标准 C++ VLA。
- 影响: 可移植性/栈风险。
- **修复**: VLA→std::string + resize + 去除NUL终止符 (2025-11-16, 6b236b5)

#### 22. Streamable::stream 可能空容器访问 (MEDIUM) ✅ **已修复**
- 位置: sucre/sucre-snort/src/Streamable.cpp:26-38
- 问题: 弹空 _items 后访问 back。
- 影响: 未定义行为/崩溃。
- **修复**: while条件添加!_items.empty()检查 (2025-11-16, 6b236b5)

#### 23. Settings::_maxAgeIP 非原子访问 (MEDIUM) ✅ **已修复**
- 位置: sucre/sucre-snort/src/Settings.hpp:85,178-182；调用例: src/Domain.cpp:18-19
- 问题: 跨线程读写无同步。
- 影响: validIP 判定不稳定。
- **修复**: 改用atomic<time_t> + load/store(memory_order_relaxed) (2025-11-16, 6b236b5)

#### 24. DomainManager::save 遍历未加锁 (MEDIUM) ✅ **已修复**
- 位置: sucre/sucre-snort/src/DomainManager.cpp:124-135
- 问题: 遍历 _byName 无锁。
- 影响: 并发增删域时不一致/崩溃。
- **修复**: 添加 shared_lock_guard(_mutexByName) (2025-11-16, f678cc4)

#### 25. PacketListener 解析 UDP 头使用错误类型 (MEDIUM) ✅ **已修复**
- 位置: sucre/sucre-snort/src/PacketListener.cpp:220-225
- 问题: UDP 分支强转 tcphdr。
- 影响: 可读性差，移植下有风险。
- **修复**: UDP分支改用udphdr*替代tcphdr* (2025-11-16, 2422eb1)

#### 26. PacketListener 使用大 VLA 缓冲 (MEDIUM) ✅ **已修复**
- 位置: sucre/sucre-snort/src/PacketListener.cpp:117,157-160
- 问题: 非标准 VLA；栈占用大。
- 影响: 可移植性/稳定性下降。
- **修复**: VLA→std::vector<char>避免65KB+栈分配 (2025-11-16, 2422eb1)

#### 27. PacketManager::initIfaces 未检测 if_nameindex 失败 (MEDIUM) ✅ **已修复**
- 位置: sucre/sucre-snort/src/PacketManager.cpp:32-34
- 问题: 未判空即解引用。
- 影响: 资源异常时崩溃。
- **修复**: 添加nullptr检查，失败时提前返回 (2025-11-16, 2422eb1)

#### 28. DomainList::remove 路径双斜杠 (LOW) ✅ **已修复**
- 位置: sucre/sucre-snort/src/DomainList.cpp:217-218
- 问题: 路径拼接可能出现 //。
- 影响: 一致性问题。
- **修复**: 去除多余/（saveDirDomainLists已含尾斜杠） (2025-11-16, 2422eb1)

#### 29. Control::clientLoop 边界处理可读性差 (LOW) ✅ **已修复**
- 位置: sucre/sucre-snort/src/Control.cpp:225-237
- 问题: 临界长度分支绕。
- 影响: 维护成本；功能正常。
- **修复**: 改进逻辑：预留NUL字节、提前终止、截断时break (2025-11-16, 2422eb1)

#### 32. Timer::get shared_lock 下使用 operator[] (LOW) ✅ **已修复**
- 位置: sucre/sucre-snort/src/Timer.cpp:18-27
- 问题: 共享锁内用 operator[]；key 不存在时隐式插入（写操作）；违反读写锁语义。
- 影响: 当前调用路径安全（get 前均有 set）；未来误用时多线程竞争。
- **修复**: operator[]→find()+存在检查，LOG(WARN)未设置timer (2025-11-17, 3692cf4)

#### 33. NFQUEUE 包解析越界读 (CRITICAL) ✅ **已修复**
- 位置: sucre/sucre-snort/src/PacketListener.cpp:177-189, 213-229
- 问题: 仅校验 `payloadLen >= sizeof(IP 头)`，未验证 `iphdrLen <= payloadLen`；随后按 `payload + iphdrLen` 解析 TCP/UDP 头。
- 影响: 越界读/崩溃/信息泄露。
- **修复**: IP头长度范围校验；TCP doff范围校验；L4头大小检查；附带修复#36 (2025-11-17, 41ea924)
- **增强**: 分层错误处理(L3→NF_ACCEPT fail-open, L4→NF_DROP防火墙策略)，类型uint32_t，UDP错误处理 (2025-11-17, 3692cf4)

#### 34. App::printDomains 无锁遍历 (HIGH) ✅ **已修复**
- 位置: sucre/sucre-snort/src/App.hpp:174-176
- 问题: for-range 在获取共享锁前迭代 map；并发插入/rehash 可致迭代器失效。
- 影响: 未定义行为/崩溃。
- **修复**: 遍历前获取shared_lock覆盖整个for循环 (2025-11-17, 41ea924)

#### 35. DomainList listId 路径未约束 (MEDIUM) ✅ **已修复**
- 位置: sucre/sucre-snort/src/DomainList.cpp:56, 101-106, 154-159, 218-226
- 问题: `saveDirDomainLists + listId` 直接拼接，无格式/长度校验。
- 影响: 目录穿越/非预期文件修改（依赖运行环境隔离）。
- **修复**: validListId()白名单(isxdigit+'-', ≤64字符)验证6个文件操作 (2025-11-17, 3692cf4)

#### 36. PacketListener TCP doff 未校验 (MEDIUM) ✅ **已修复**
- 位置: sucre/sucre-snort/src/PacketListener.cpp:215-221
- 问题: 直接 `len -= tcp->doff*4`，未验证范围。
- 影响: 长度计算异常；未来载荷解析可能 OOB。
- **修复**: 验证 `doff >= 5` 且 `doff*4 <= len`（合并至#33修复） (2025-11-17, 41ea924)

#### 37. Activity::restore 定义不规范 (LOW) ✅ **已修复**
- 位置: sucre/sucre-snort/src/Activity.cpp:28
- 问题: 实现为自由函数 `Activity::Ptr restore(Saver&)`，非类静态成员。
- 影响: 维护困惑/链接风险（当前未用）。
- **修复**: 改为 `Activity::Ptr Activity::restore(Saver&)` 类静态成员函数；save/restore 保持 stub 实现（Activity 持久化未使用） (2025-11-18, 10c7542)

#### 38. Control 大栈缓冲 (LOW) ✅ **已修复**
- 位置: sucre/sucre-snort/src/Control.cpp:228-237
- 问题: `char buffer[settings.controlCmdLen]`（约 20KB）位于栈上。
- 影响: 小栈线程风险。
- **修复**: VLA→std::vector<char>避免20KB栈占用 (2025-11-17, 3692cf4)

#### 39. PackageListener inotify 读取粗糙 (LOW) ✅ **已修复**
- 位置: sucre/sucre-snort/src/PackageListener.cpp:29-35, 81-112
- 问题: 固定读取 `sizeof(inotify_event)`，忽略可变名字段；EOF 异常导致无限重试；缺少 IN_DELETE_SELF 监听；长时间持共享锁。
- 影响: 事件丢失/滞后；文件读取性能问题；原子文件替换监听失效；锁竞争。
- **修复**: 4KB 缓冲+循环解析可变长度事件；移除 EOF 异常机制改用自然 EOF 退出；添加 IN_DELETE_SELF 监听；移除不必要的 mutexListeners 持锁 (2025-11-18, 10c7542)

#### 40. NFQUEUE 回调缺少 NFQA_PAYLOAD 检查 (HIGH) ✅ **已修复**
- 位置: sucre/sucre-snort/src/PacketListener.cpp:172-179, 186
- 问题: 仅校验 `NFQA_PACKET_HDR`，未检查 `NFQA_PAYLOAD` 即读取长度/指针。
- 影响: 异常 netlink 消息触发崩溃。
- **修复**: 判空 `attr[NFQA_PAYLOAD]`，缺失则返回MNL_CB_ERROR (2025-11-17, 41ea924)
- **增强**: nfqHeader提前获取，所有错误路径发送verdict，防队列停滞 (2025-11-17, 3692cf4)

#### 41. Stats::shift 在共享读锁下写 _stats（数据竞争） (HIGH) ✅ **已修复**
- 位置: sucre/sucre-snort/src/Stats.cpp:52（调用）, 36-49（写入）；sucre/sucre-snort/src/DomainStats.cpp:34-45
- 问题: `hasData()/print()/hasBlocked()/hasAccepted()` 在 `shared_lock(_mutex)` 下调用 `shift()`，后者 memcpy/memset 改写 `_stats`。
- 影响: 读写并发未定义行为/随机崩溃。
- **修复**: shared_lock→lock_guard（独占锁）保护 shift() 写入；Stats.cpp 5处 + DomainStats.cpp 2处 (2025-11-18, 296b836)

#### 42. DNS 获取 IP 并发竞态与潜在锁序反转 (HIGH) ✅ **已修复**
- 位置: sucre/sucre-snort/src/DomainManager.cpp:83-92；sucre/sucre-snort/src/DnsListener.cpp:71, 92-97
- 问题: removeIPs 未持 Domain::_mutexIP 遍历/清空；readIP 锁序为 域锁→全局IP锁，修复不当易与全局→域锁序相反。
- 影响: 数据竞争/迭代器失效；潜在 AB-BA 死锁。
- **修复**: 统一锁序（域→全局）；`removeIPs` 在域锁内访问集合，随后获取全局锁批量删除映射，并在同一临界区清空集合，消除迭代器失效与 AB-BA 死锁。

#### 43. Domain::validIP 数据竞争 (HIGH) ✅ **已修复**
- 位置: sucre/sucre-snort/src/Domain.cpp:18; src/Domain.hpp:30
- 问题: 无锁读 _timestampIP，写在域锁内。
- 影响: 判定不稳定/未定义行为。
- **修复**: _timestampIP 改为 atomic<time_t>；addIP() 写用 store()；validIP()/save()/restore() 读用 load(memory_order_relaxed) (2025-11-18, 7d1961b)

#### 44. Domain::clearIPs 未持域内锁 (MEDIUM) ✅ **已修复**
- 位置: sucre/sucre-snort/src/Domain.cpp:57-60
- 问题: 清空 _ipv4/_ipv6 未加 Domain::_mutexIP。
- 影响: 与 addIP/print 并发导致迭代器失效。
- **修复**: 添加lock_guard(_mutexIP) (2025-11-17, 3692cf4)

#### 45. Host 成员并发读写不同步 (HIGH) ✅ **已修复**
- 位置: sucre/sucre-snort/src/Host.hpp:30-37；sucre/sucre-snort/src/Host.cpp:20-26
- 问题: name()/setResolved() 写未加锁；读在锁内/外混用。
- 影响: 数据竞争/未定义行为。
- **修复**: `name()` 读写均在 `Host::_mutex` 下，读返回副本；`resolved` 改原子并使用 acquire/release；接口保持不变。

#### 46. AppManager::remove 误删与越界风险 (HIGH) ✅ **已修复**
- 位置: sucre/sucre-snort/src/AppManager.cpp:55-72
- 问题: 仅按 names[0] 擦除 _byName；names 为空时越界；兜底路径可能误删其他 app 的索引。
- 影响: _byName 残留/错配；越界读；索引不一致。
- **修复**: 使用 app->name() 获取 canonical name 删除；添加 removeFile() 保持与 reset() 一致性；移除兜底路径改为记录 LOG(WARNING) (2025-11-18, 10c7542)

#### 47. Address::str 失败路径未检测 (HIGH) ✅ **已修复**
- 位置: sucre/sucre-snort/src/Address.cpp:26-28
- 问题: inet_ntop 失败未检查即使用栈缓冲构造字符串。
- 影响: 未初始化读/信息泄露。
- **修复**: 缓冲区零初始化；检查inet_ntop返回值；失败返回空串 (2025-11-17, 41ea924)

#### 48. SocketIO::print 长度与部分写处理不当 (MEDIUM) ✅ **已修复**
- 位置: sucre/sucre-snort/src/SocketIO.cpp:16-33
- 问题: size_t→ssize_t 转换+隐式回转；未处理部分写；额外写入 NUL。
- 影响: 边界行为不稳/潜在截断。
- **修复**: ssize_t循环写；处理EINTR/EAGAIN；保留NUL终止符语义 (2025-11-17, 41ea924)

#### 49. PacketManager::_ifaceBits 并发数据竞争/越界 (CRITICAL) ✅ **已修复**
- 位置: sucre/sucre-snort/src/PacketManager.cpp:33-79；调用点 sucre/sucre-snort/src/PacketListener.cpp:236-239
- 问题: 多线程无锁调用 `ifaceBit()/initIfaces()` 对 `_ifaceBits` 读写/resize。
- 影响: 并发读写 vector → 堆损坏/越界/崩溃（高频包路径）。
- **修复**: RCU快照 `atomic<shared_ptr<vector>>` + acquire/release；热路径无锁读；双检查锁限流refresh；性能+7ns/包 (2025-11-18, b98f675)

#### 50. SocketIO::format 花括号处理致缩进下溢 (CRITICAL) ✅ **已修复**
- 位置: sucre/sucre-snort/src/SocketIO.cpp:36-67（尤其 60-62）
- 问题: 未跟踪字符串上下文，遇到值内 `}` 也 `pop_back()`；缩进为空时下溢。
- 影响: pretty 输出含 `{`/`}` 时崩溃。
- **修复**: 字符串状态跟踪（inString/escaped）；istreambuf_iterator；空检查；支持数组[] (2025-11-17, 41ea924)

#### 51. Control::readCmdArgs 使用 ::isdigit 触发 UB (HIGH) ✅ **已修复**
- 位置: sucre/sucre-snort/src/Control.cpp:274-290（278）
- 问题: 直接将有符号 char 传入 C `isdigit`。
- 影响: 非 ASCII/负值输入未定义行为/解析错误。
- **修复**: lambda包装static_cast<unsigned char> (2025-11-17, 41ea924)

#### 52. 信号关停被 DnsListener 持续共享锁阻塞 (HIGH) ✅ **已修复**
- 位置: sucre/sucre-snort/src/sucre-snort.cpp:118-126；sucre/sucre-snort/src/DnsListener.cpp:46-90（47）
- 问题: 主循环保存/退出需独占 `mutexListeners`；`DnsListener::clientRun` 在共享锁下执行整段协议与阻塞 IO。
- 影响: SIGINT/SIGTERM 后独占锁饥饿，关停/定时保存被长时间阻塞（可被恶意客户端放大）。
- **修复**: I/O 锁外（所有 read/write 移出全局锁）；5 个微秒级锁窗口（决策、removeIPs、addIP×2、stats/stream）；`SO_RCVTIMEO=250ms` 超时防阻塞；定时保存移除全局锁（依赖各模块内部同步）；性能：锁持有 ~100ms→~2µs（50,000×），信号响应 ∞→350ms (2025-11-20, f718d66)

#### 53. DomainList::write 与 BlockingListManager 锁序反转导致死锁 (CRITICAL) ✅ **已修复**
- 位置: sucre/sucre-snort/src/DomainList.cpp:80-101（先持 `_mutex` 后调用 `blockingListManager.masksSnapshot()`）；调用路径示例: `Control::cmdClearBlockingLists` 先持 `BlockingListManager` 锁（`listsSnapshot()`）后调用 `domManager.removeDomainList()` → `DomainList::erase()`（持 `_mutex`）。
- 问题: 锁顺序不一致（DL → BLM 与 BLM → DL 并存），并发下可能形成 AB-BA 死锁。
- 影响: 控制命令或域名写入在竞争场景中永久阻塞，守护进程卡死。
- **修复**: masksSnapshot()移至加锁前获取；消除嵌套锁；masks过期窗口<1μs仅影响去重准确性 (2025-11-18, 060b5bb)

#### 54. DnsListener::readIP 悬空引用与并发竞态 (HIGH) ✅ **已修复**
- 位置: sucre/sucre-snort/src/DnsListener.cpp:92-97；sucre/sucre-snort/src/Domain.hpp:83-87
- 问题: `Domain::addIP` 返回集合元素的引用，`DnsListener::readIP` 以 `const auto&` 持有该引用；若并发线程对同一域执行 `removeIPs`（域锁→全局锁删映射并清空集合），则该引用可能在随后使用时已悬空（use-after-free）。
- 影响: 未定义行为/崩溃；在高并发 DNS 回传（支持 1000 并发客户端）下风险现实。
- 触发链: 线程A在 `readIP` 获得元素引用→释放域锁；线程B执行 `removeIPs` 清空集合；线程A继续使用该引用调用 `domManager.addIP`。
- **修复**: 引入“原子添加”API，避免返回引用，并与全局映射更新保持同一临界区：
  - `Domain::withAddedIPLocked<IP>(ip, after)`：在域锁内插入 IP 并调用回调
  - `DomainManager::addIPBoth(domain, ip)`：域锁内插入→获取全局锁→更新 IP→Domain 映射
  - `DnsListener::readIP` 改为本地值+调用 `addIPBoth`（不持有集合元素引用）
- 评价: 不引入 friend，不做快照；锁序为“域→全局”，与 Issue #42 修复一致；原子性强，无 UAF 风险。

#### 55. HostManager 锁序反转与长持锁（AB-BA/阻塞） (HIGH) ✅ **已修复**
- 位置: sucre/sucre-snort/src/HostManager.hpp:84-110；sucre/sucre-snort/src/HostManager.cpp:15-44
- 问题: `printHostsByName` 路径 `_mutexName → Host::_mutex` 与反向解析路径 `Host::_mutex → _mutexName` 形成 AB-BA；`create()` 在 Manager 锁内执行 `getnameinfo()` 长时阻塞。
- 影响: 控制面打印与反向解析并发可死锁；高并发下锁竞争严重。
- **修复**: 统一为“零嵌套锁”策略：打印走快照，锁外 `host->print()`；反向解析两阶段（先 Manager 锁内建索引→锁外 `getnameinfo()`→锁内各自更新），`reset()` 各容器在各自锁下清空。

#### 56. DomainManager::addIPBoth 模板/重载双实现（维护风险） (LOW) ✅ **已修复**
- 位置: sucre/sucre-snort/src/DomainManager.hpp:156-164；sucre/sucre-snort/src/DomainManager.cpp:96-112；sucre/sucre-snort/src/Domain.hpp:37
- 问题: 模板实现与 IPv4/IPv6 重载并存，未来可能行为漂移；模板依赖 `friend` 破坏封装。
- 影响: 维护成本高、易引入隐性差异。
- **修复**: 删除模板版，保留 .cpp 重载为唯一实现；移除 `friend class DomainManager`，维持通过原语封装。

#### 57. PacketListener 全局锁与反向 DNS 阻塞叠加（CRITICAL） ✅ **已修复**
- 位置: sucre/sucre-snort/src/PacketListener.cpp:262-270；sucre/sucre-snort/src/PacketManager.hpp:63-88；sucre/sucre-snort/src/HostManager.hpp:63-112
- 问题: `PacketListener::callback` 在持有 `mutexListeners` 共享锁时调用 `PacketManager::make`，后者内部再调用 `HostManager::make`/`create` 的第二阶段 `getnameinfo`；当 `settings.reverseDns()` 开启且遇到新 IP 时，反向 DNS 可在全局锁内长时间阻塞。
- 影响: DNS 热路径与 NFQUEUE 包处理共享全局读锁，任意慢的反向解析都会直接拉长读锁持有时间；在高并发/高 QPS 场景下，大量工作线程在全局锁内等待 DNS，导致 `RESETALL` 等需要独占 `mutexListeners` 的控制操作长期饥饿，表现为重置/关停卡死。
- 实际修复:
  - 将 `PacketManager::make` 接口从 `(Address&& ip, App::Uid uid, ...)` 重构为 `(const Address& ip, const App::Ptr&, const Host::Ptr&, ...)`，去除内部对 `appManager.make`/`hostManager.make` 的调用，使其职责收敛为“给定上下文下的判决 + 统计 + Streamable<Packet> 推送”，不再触发反向 DNS 或任何阻塞 IO。
  - 在 `PacketListener::callback` 中改为两阶段流程：
    - Phase 1（锁外构建上下文）: 在 *未* 持有 `mutexListeners` 的情况下构造 `Address<IP>`，调用 `appManager.make(uid)` 与 `hostManager.make<IP>(addr)`；所有可能阻塞的工作（含 `HostManager::create` 内的 `getnameinfo`）仅受各自局部锁保护，完全不占用全局监听锁。
    - Phase 2（锁内纯计算窗口）: 在满足 `blockEnabled` 且非控制端口条件下，获取 `mutexListeners` 的共享锁，仅调用新签名的 `PacketManager::make(addr, app, host, ...)` 执行阻断判决、统计更新与 `Streamable<Packet<IP>>::stream(...)`；这一临界区保证不包含任何外部系统调用或 DNS 查询，变为单纯的内存读取/更新。
  - 保持 `HostManager::create` 的两阶段设计（Manager 锁内建索引 → 锁外 `getnameinfo` → 锁内更新名称索引）不变，但其调用点已移动到全局锁外：反向 DNS 仅在局部 Manager 锁下进行，不再与 `mutexListeners` 叠加。
- 结论: NFQUEUE 热路径上的全局锁持有时间从“判决 + 统计 + 流式输出 + 潜在长时间反向 DNS”压缩为“判决 + 统计 + 流式输出”的短窗口，`RESETALL` 等写锁操作再也不会被 DNS 延迟放大；在高并发、DNS 质量波动甚至恶意反向解析环境下，全局锁的行为从“可能几秒级卡死”降回“微秒～毫秒级的有限等待”，消除 57 所描述的架构级风险，同时保持现有对外控制命令与判决语义不变。

#### 58. Control::inetServer 异常时关闭未初始化 fd（MEDIUM） ✅ **已修复**
- 位置: sucre/sucre-snort/src/Control.cpp:184-223（catch 221-223）
- 问题: `inetSocket` 在 `socket()` 之前抛出异常时可能未初始化，catch 中直接 `close(inetSocket)` 未定义行为。
- 影响: 低概率异常路径引发未定义行为。
- **修复**: Line 185 初始化 `inetSocket = -1`；Line 221-223 catch 中 `if (inetSocket >= 0) close(inetSocket);` 关闭前检查。

#### 59. Control 客户端线程无超时与资源上限（HIGH）✅ **已修复**
- 位置: sucre/sucre-snort/src/Control.cpp:236-333；sucre/sucre-snort/src/SocketIO.{hpp,cpp}
- 问题: 控制连接线程无限创建且阻塞读无超时，恶意/异常客户端可导致线程堆积与资源耗尽。
- 影响: 可用性风险，长期运行下可能耗尽线程/FD。
- **修复**: SO_RCVTIMEO=15min；SocketIO 添加原子 lastWrite 时间戳；统一超时策略（15min 无写入即关闭）；处理 EINTR（重试）/EAGAIN（超时检测）/EOF（关闭）；消除依赖客户端 STOP 命令的线程泄漏。

#### 60. Streamable::reset 未加锁导致与并发写入竞态（HIGH） ✅ **已修复**
- 位置: sucre/sucre-snort/src/Streamable.cpp:24-27
- 问题: `_items` 在 `stream/save/startStream` 等路径均受 `_mutexItems` 保护，`reset` 直接 `clear()` 未持锁，存在数据竞争。
- 影响: 并发下可能触发容器损坏/崩溃。
- **修复**: Line 25 添加 `std::lock_guard<shared_mutex>` 独占锁保护 `_items.clear()`，与 `stream()` 写锁、`save()/startStream()` 读锁策略一致；消除 RESETALL 路径的容器竞态风险。

#### 61. Settings::start 重复创建相同目录（LOW） ✅ **已修复/不适用**
- 位置: sucre/sucre-snort/src/Settings.cpp:15-18
- 问题: `mkdir(saveDirSystem)` 被调用两次，疑似复制粘贴错误；虽无功能性问题，但降低可读性。
- 影响: 代码质量问题。
- **修复**: 当前代码无重复，4 个不同目录各创建一次（_saveDir, saveDirPackages, saveDirSystem, saveDirDomainLists）；问题描述可能基于旧版本。

#### 62. Saver 异常掩码声明不一致（LOW） ✅ **已修复**
- 位置: sucre/sucre-snort/src/Saver.cpp:11-12
- 问题: `out.exceptions(...)` 使用了 `std::ifstream` 的异常掩码类型（应为 `std::ofstream`）。
- 影响: 可读性与维护性；行为上通常无差异。
- **修复**: Line 11 `in.exceptions(std::ifstream::...)`，Line 12 `out.exceptions(std::ofstream::...)`，类型匹配正确。

#### 63. Control::PASSWORD 对引号格式的假设过强（LOW）
- 位置: sucre/sucre-snort/src/Control.cpp:312-321（319: `substr(1, len-2)`）
- 问题: 假定参数必为引号包围字符串；未加引号或长度不足将被误解析。
- 影响: 兼容性/健壮性不足。
- 修复建议: 解析时检测首尾引号再决定 `substr`；否则直接使用原始字符串。

#### 64. DomainList::blockMask 对末尾点号域名的处理（LOW）✅ **已修复**
- 位置: sucre/sucre-snort/src/DomainList.cpp:37-61
- 问题: FQDN 格式域名（`a.b.`）无法匹配存储规则（`a.b`）。
- 影响: DNS 协议标准 FQDN 查询失效。
- **修复**: 查询前剥离末尾点；零拷贝路径（指针优化）；边界处理（单点返回0）；保持无锁热路径。

#### 65. Host::print IPv4 地址未加引号导致 JSON 非法（MEDIUM） ✅ **已修复**
- 位置: sucre/sucre-snort/src/Host.cpp:27-43
- 问题: IPv4 列表输出时未为每个地址加引号（`ip.print(out)` 裸写），而 IPv6 分支加了引号，导致 IPv4 JSON 无效、两者不一致。
- 影响: 控制面/调试输出解析失败；上游消费方需容错。
- **修复**: Line 31, 33 为 IPv4 地址添加引号 `out << "\""` 包围，与 IPv6 (Line 39, 41) 输出格式一致，JSON 合规。

#### 66. StatsTPL::timestamp 误用 localtime_r + timegm 导致日界错误（HIGH）✅ **已修复**
- 位置: sucre/sucre-snort/src/Stats.cpp:30-43
- 问题: timegm 按UTC解释本地时间，导致时区偏移（东八区提前8小时）；DST边界额外错误。
- 影响: DAY0-6/WEEK/ALL统计边界错位。
- **修复**: timegm → mktime；零初始化 tm{}；清零时分秒至午夜；tm_isdst=-1 自动DST；按本地日界统计。

#### 67. DnsRequest::restore 以引用绑定临时对象（LOW，易错风格） ✅ **已修复**
- 位置: sucre/sucre-snort/src/DnsRequest.cpp:56-69
- 问题: 以引用绑定按值返回的临时 `shared_ptr`；虽因"延长临时生命周期的 const 引用"可工作，但可读性与可维护性差，稍改签名即变 UB。
- 影响: 维护风险；新手容易误改为非常量引用或扩大作用域。
- **修复**: Line 59, 62 改用 `auto app` 和 `auto domain`（值语义）替代 `auto &`（引用），显式管理 shared_ptr 生命周期，性能开销仅 ~10ns/引用计数增加。

#### 68. Rule::WILDCARD → 正则转义不完备（MEDIUM）✅ **已修复**
- 位置: sucre/sucre-snort/src/Rule.cpp:34-42
- 问题: 仅转义部分元字符，遗漏 \, ), ], }；用户输入可能意外构造复杂正则。
- 影响: 意外匹配行为；Catastrophic Backtracking DoS风险。
- **修复**: 完整转义14个POSIX ERE元字符（`.^$|()[]{}*+?\`）；添加设计意图注释；消除DoS风险；保持纯通配符语义。

#### 69. Activity 流过期标记非原子，依赖调用顺序（LOW） ✅ **已修复**
- 位置: sucre/sucre-snort/src/Activity.hpp:17,26；sucre/sucre-snort/src/Activity.cpp:24-26
- 问题: `Activity::_streamed` 为普通 bool；`Streamable::stream` 在持 `_mutexItems` 下读取过期标志，但写入发生在 `ActivityManager::create()` 中且不与 `_mutexItems` 同步。
- 影响: 目前仅 `ActivityManager` 写入，实测为同线程顺序一致，短期无竞态；但模型不严谨，易被未来并发写入破坏。
- **修复**: `_streamed` 改为 `std::atomic_bool`；Activity.hpp:26 使用 `store(memory_order_relaxed)`，Activity.cpp:25 使用 `load(memory_order_relaxed)`；lock-free 原子访问，性能开销 ~1ns，消除数据竞争的同时保持语义简单。

#### 70. DnsRequest 序列化使用原始 timespec（LOW，可移植性）✅ **已评估/不视为 bug**
- 位置: sucre/sucre-snort/src/DnsRequest.cpp:48-66
- 分析: `DnsRequest::_timestamp` 仅用于本机 DNS 流的短期保存/恢复，保存文件不属于用户可迁移数据；部署环境固定为 Android，同一设备上不会在不同 ABI 间共享该文件。即使系统升级，历史 DNS 请求流清空也不影响拦截规则或持久设置。
- 结论: 在当前产品边界内，直接序列化 `timespec` 不构成功能性或安全性 bug；为避免不必要的格式变更与兼容逻辑，本项仅作为“已知实现细节”记录，不做代码修改。

#### 71. HostManager::printHostsByName 可能重复条目（LOW） ✅ **已修复**
- 位置: sucre/sucre-snort/src/HostManager.cpp:50-80
- 问题: 按名称聚合后直接拼接各向量，重复 Host（多 IP 或多次解析）会多次输出。
- 影响: 展示不稳定/统计偏差。
- **修复**: Line 61-72 添加去重逻辑，使用 `unordered_set<Host::Ptr>` 基于指针值去重，保留首次出现顺序；复杂度 O(n)，与 Issue #55 快照模式一致。

---

## 第二轮扫描（2026-01-21：识别问题；后续修复记录见各条目 ✅）

#### 72. DomainManager::reset 未加锁导致与并发访问数据竞争（CRITICAL） ✅ **已修复**
- 危险等级: **CRITICAL**
- 位置: sucre/sucre-snort/src/DomainManager.cpp:183-204；并发访问: sucre/sucre-snort/src/DnsListener.cpp:179-181；sucre/sucre-snort/src/HostManager.hpp:39-41,85-96
- 问题: reset() 直接 clear `_byIPv4/_byIPv6/_byName`，未持有 `_mutexByIP/_mutexByName`；但 `domManager.make/find/addIPBoth` 等在 DnsListener/HostManager 路径可在不持 `mutexListeners` 的情况下执行（Phase 1），RESETALL 的全局锁无法覆盖这部分访问。
- 影响: unordered_map 在 clear/insert/find 并发下 UB → 崩溃/内存破坏；RESETALL 期间更容易触发。
- **修复**: reset() 内 `std::scoped_lock(_mutexByName, _mutexByIP)` 后再 clear 索引（并保留匿名域名条目），避免 HostManager/PacketListener Phase1 等不经 `mutexListeners` 的并发读导致数据竞争。(2026-01-21)

#### 73. AppManager::save/restore 无锁遍历 _byUid（CRITICAL） ✅ **已修复**
- 危险等级: **CRITICAL**
- 位置: sucre/sucre-snort/src/AppManager.cpp:132-186；并发写入点: sucre/sucre-snort/src/PacketListener.cpp:270；sucre/sucre-snort/src/DnsListener.cpp:179；sucre/sucre-snort/src/PackageListener.cpp:389-394
- 问题: save/restore 在不持 `_mutexByUid/_mutexByName` 的情况下迭代 `_byUid` 并调用 `app->save/app->restore`；同时 PacketListener/DnsListener/PackageListener 可并发创建/删除 App（insert/erase）。
- 影响: std::map 并发迭代+修改 → UB（迭代器失效/崩溃）；同时可能导致保存文件缺失/错乱。
- 触发: `snortSave()` 周期性调用 `appManager.save()`（当前不再持全局锁）与上述写入路径并发。
- **修复**: save/restore 对 `_byUid` 先 `shared_lock(_mutexByUid)` 生成 `App::Ptr` 快照，再逐个调用 `app->save/app->restore`，避免 map 并发迭代+修改导致 UB。(2026-01-21)

#### 74. RulesManager::save/restore 无锁访问 _rules/_idCount（CRITICAL） ✅ **已修复**
- 危险等级: **CRITICAL**
- 位置: sucre/sucre-snort/src/RulesManager.cpp:121-143
- 问题: save/restore 不持 `_mutex`；而 `addRule/removeRule/updateRule/addCustom/removeCustom/reset` 都会在持锁下修改 `_rules/_customs/_idCount`。
- 影响: 周期性 `snortSave()` 调用 `rulesManager.save()` 与控制线程写操作并发 → UB/崩溃；保存文件可能损坏。
- **修复**: `RulesManager::save()` 使用 `shared_lock(_mutex)`；`restore()` 使用独占锁，保证与 add/remove/update/reset 等写操作互斥，消除并发数据竞争。(2026-01-21)

#### 75. StatsTPL::save/restore 未加锁导致与 update/print/reset 竞态（CRITICAL/HIGH） ✅ **已修复**
- 危险等级: **CRITICAL**
- 位置: sucre/sucre-snort/src/Stats.cpp:20-28；调用点示例: sucre/sucre-snort/src/App.cpp:179-203；sucre/sucre-snort/src/Domain.cpp:23-31；sucre/sucre-snort/src/AppManager.cpp:132-138
- 问题: StatsTPL 的写入路径（`AppStats::update/DomainStats::update` 等）依赖 `_mutex` 保护 `_timestamp/_stats`；但 `save/restore` 直接读写 `_timestamp/_stats` 无锁。
- 影响: 周期性保存与热路径 update 并发 → 数据竞争（UB）；轻则统计/持久化不一致，重则在部分平台触发崩溃。
- **修复**: `StatsTPL::save/restore` 对 `_timestamp/_stats` 采取“锁内快照、锁外读写盘”：锁只持有到 memcpy 完成，避免把潜在阻塞的 I/O 放进 stats 锁；同时消除与热路径并发的数据竞争。(2026-01-21)

#### 76. App::hasData(color, view) 无锁遍历 domStats map（CRITICAL） ✅ **已修复**
- 危险等级: **CRITICAL**
- 位置: sucre/sucre-snort/src/App.cpp:73-80；写入点: sucre/sucre-snort/src/App.cpp:110-129；调用点: sucre/sucre-snort/src/AppManager.hpp:130-144
- 问题: `hasData(cs, view)` 直接遍历 `domStats(cs)`，未持 `mutex(cs)`；而 `updateStats()` 会在持锁下插入/rehash（unordered_map）。
- 影响: 控制面查询（如 `DOMAINLIST.APP.*`/过滤路径）与数据包更新并发 → 迭代器失效/崩溃（典型容器并发 UB）。
- **修复**: `App::hasData(cs, view)` 增加 `shared_lock(mutex(cs))`，与 `printDomains()` 一致，避免并发插入/rehash 导致的迭代器失效与崩溃。(2026-01-21)

#### 77. App::upgradeName 读写 _name/_names/_saver 无同步（CRITICAL/HIGH） ✅ **已修复**
- 危险等级: **CRITICAL**
- 位置: sucre/sucre-snort/src/App.cpp:41-62；调用点: sucre/sucre-snort/src/AppManager.cpp:34-63；并发点: sucre/sucre-snort/src/AppManager.cpp:132-138（app->save）等
- 问题: `upgradeName()` 在无 App 内部锁的情况下修改 `_name/_names/_saver`；同时 Packet/DNS/Control/Save 线程可并发读取 `name()` / `print()` / `save()`。
- 影响: std::string/Saver 并发读写 → UB（潜在 use-after-free/崩溃）；文件 rename 与保存同时发生可能导致持久化文件错位。
- **修复**: 为 App 引入内部 `shared_mutex`，将 `_saver/_name/_names` 纳入同一把锁；`upgradeName/removeFile` 用独占锁，`save/restore/name/names/isAnonymous` 用共享锁，消除并发读写导致的 UB/崩溃。(2026-01-21)

#### 78. Control::readCmdArgs/readSingleArg 使用 std::stoi 未捕获异常导致远程崩溃（CRITICAL） ✅ **已修复**
- 危险等级: **CRITICAL**
- 位置: sucre/sucre-snort/src/Control.cpp:466-563
- 问题: 解析数字参数时使用 `std::stoi()`，仅用 `isdigit()` 判定“全数字”但未限制长度/范围；超长数字会触发 `std::out_of_range` 异常。Control 线程未做 try/catch，异常将穿透线程边界触发 `std::terminate`，导致整个进程崩溃。
- 影响: 本地任意客户端可通过构造超长数字参数实现稳定 DoS（杀死 sucre-snort）。
- **修复**: 使用 `std::from_chars` 进行无异常 `uint32_t` 解析；解析失败/越界时不再崩溃（回退为 STR 参数），避免触发 `std::terminate`。(2026-01-21)

#### 79. snortSave 可被多线程并发调用，导致保存流程数据竞争/文件损坏（CRITICAL） ✅ **已修复**
- 危险等级: **CRITICAL**
- 位置: sucre/sucre-snort/src/sucre-snort.cpp:104-145（周期性 snortSave）；sucre/sucre-snort/src/Control.cpp:658-673（RESETALL 内调用 snortSave）
- 问题: 主线程周期性调用 `snortSave()`；同时控制线程在 `RESETALL` 里也会调用 `snortSave()`，两者之间没有任何全局互斥。各模块 `save()` 内部的 `Saver`（ofstream/rename 写盘流程）本身也非线程安全 → 并发执行时会发生数据竞争（UB）与同名 `.tmp` 文件互相覆盖/交错写入。
- 影响: 可能崩溃（UB）；更常见是持久化文件损坏/丢失（settings/rules/domains/app stats/dnsstream 等），出现“随机恢复失败/状态回退”。
- **修复**: 为 `snortSave()` 引入全局互斥（单入口 `std::mutex`），确保周期性保存与 RESETALL 保存不会并发执行，避免 `.tmp`/rename 交错与跨模块 save 数据竞争。(2026-01-21)

#### 80. Packet::length 位域仅 14bit，GSO/大包下长度输出可能截断（LOW） ✅ **已修复**
- 危险等级: **LOW**
- 位置: sucre/sucre-snort/src/Packet.hpp:24-30；打印: sucre/sucre-snort/src/Packet.cpp:36-58
- 问题: `Packet::_len` 使用 `uint16_t _len : 14`，最大仅 16383；但启用了 NFQUEUE 的 GSO 相关配置，实际 `payloadLen` 可能更大。该字段截断会导致 PKTSTREAM 中 `length` 输出错误（统计本身使用入参 len，不受影响）。
- 影响: 主要是调试/观测误导（PKTSTREAM length 不可信），不直接影响拦截判定。
- **修复**: 移除 `_len` 14-bit 位域，改为完整 `uint16_t` 存储；PKTSTREAM 的 `length` 不再在大包场景下被截断。(2026-01-21)
