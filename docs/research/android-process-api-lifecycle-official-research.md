# Android `Process` API、子进程与 Service 生命周期：官方资料调查

调查日期：2026-08-29
调查边界：只使用 Android Developers、AOSP、OpenJDK/JDK 官方文档或源码，以及本仓库的历史代码；没有操作设备，也没有修改生产代码或测试。

## 结论先行

1. `java.lang.Process.pid()` 不是当前 Android 公共 SDK API。Android API reference 将它标成 **Added in API level 10000**；AOSP 对 `10000` 的定义是“future API level”，也就是尚未分配正式 API level 的未来 API。`isAlive()` 与带超时的 `waitFor(long, TimeUnit)` 是 API 26，普通 `waitFor()` 是 API 1。因此，在最低 API 31 的代码中，后面三个 API 可用，但不能把 `pid()` 当成可用的 Android API。
2. Pixel 6a 上出现 `NoSuchMethodError: java.lang.Process.pid:()J` 的直接含义是：APK 的字节码已经包含对该方法的符号调用，而设备运行时加载的 `java.lang.Process` 没有这个方法。这是链接错误，不是 API 文档所说的“实现存在但不支持时抛 `UnsupportedOperationException`”。精确的 Pixel 软件 build/API level 仍需设备证据确认；硬件型号本身不能确定 API level。
3. Android 公共 API 没有一个“从 `ProcessBuilder.start()` 返回的 `Process` 取子进程 PID”的兼容 getter。AOSP 的 `UNIXProcess` 确实在内部保存 PID，但字段是 private；`android.os.Process.ProcessStartResult.pid` 和 `killProcessGroup()` 也标有 `@hide`。`android.os.Process.myPid()` 只返回调用者自己的 PID；`killProcess(int)` 只对调用者已经知道的 PID 发出 kill 请求，不能发现 PID。
4. 原来的实现之所以没有这个问题，是因为它没有调用 `Process.pid()`：它保留 Java `Process` 对象，用 API 1/26 的 `waitFor`、`isAlive` 等方法控制子进程，并在 shell 中用 `echo $$` 写 PID，再用 `exec` 把 shell 替换成 VPP。后来 Product Core 代码在 commit `772e33f` 新增了 `process.pid()`；commit `e631eea` 随后移除该依赖并改成未知 PID。这是 API/实现边界变化，不是 Android 对原有 `ProcessBuilder.start()` 行为的保证变化。
5. Service 对象重建、app 进程死亡、由 app 启动的独立 native child 是三个不同事件。Android 文档明确说系统杀进程时不保证调用 `onDestroy()`；`START_STICKY` 只保证以后尝试重建 Service 实例并再次调用 `onStartCommand()`，不保证重建旧的 Java `Process` handle，也不保证重新接管旧 child。AOSP 有时通过 app process group/cgroup 一起杀子进程，但这属于系统实现路径；AOSP 的 lmkd reaper 也明确说明并非所有进程都在 Android 管理的独立 cgroup 中。因此没有面向 app 的平台契约可以依赖“Service/app 进程死亡时由 `fork/exec` 启动的 child 必然死亡”。
6. 旧的手工构建还存在独立的 classpath 风险：JDK 17 的 `javac -source 8 -target 8 -classpath android.jar` 不等于“按 Android API 31 编译”。本地 `javac -verbose` 已观察到这种旧命令会从 `/modules/java.base`（host JDK）加载 `java.lang.Process`；而本地 Lineage API 36 `android.jar` 的 `java.lang.Process.class` 本身也含有隐藏的 `pid()` 字节码。当前 APK pipeline 已用显式 `-bootclasspath "$android_jar"` 固定 Android platform stub，并由官方 D8（`--lib "$android_jar" --min-api 31`）生成 DEX；最终兼容性仍须由目标设备证明。

## 1. Android API level 证据

Android 官方 [`java.lang.Process` API reference](https://developer.android.com/reference/java/lang/Process.html) 的方法条目给出了以下版本信息：

| 方法 | Android public API reference 的 added-in | 本调查结论 |
| --- | --- | --- |
| `waitFor()` | API 1 | 可用于所有 Android API level 的基线代码 |
| `isAlive()` | API 26 | API 31 最低版本足够 |
| `waitFor(long, TimeUnit)` | API 26 | API 31 最低版本足够 |
| `destroyForcibly()` | API 26 | API 31 最低版本足够；仍只作用于该 `Process` handle 代表的进程 |
| `pid()` | API **10000** | 不是已发布的 Android public API；不能作为设备兼容性依据 |
| `toHandle()` / `ProcessHandle` | 没有 Android public added-in level | AOSP core-library/OpenJDK 输入中存在，但被隐藏；不能作为 app API |

官方 API reference 对 `pid()` 的文字是“返回 native process ID”，并注明默认实现为 `toHandle().pid()`，不支持时抛 `UnsupportedOperationException`。注意这段文档描述的是**如果运行时存在该方法**时的实现约定；如果类定义根本没有该方法，调用点在链接阶段会得到 `NoSuchMethodError`。

官方 [API diff 26](https://developer.android.com/sdk/api_diff/26/changes/java.lang.Process) 只列出 API 26 新增的 `destroyForcibly()`、`isAlive()` 和带超时的 `waitFor()`，没有列出 `pid()`。Android API reference 当前仍把 `pid()` 标为 10000，而不是一个已发布的 26、31、35 或 36 API。

Android 构建系统对 10000 的解释见 AOSP [`android/api_levels.go`](https://android.googlesource.com/platform/build/soong/%2B/658bd0540ea85c1084857b7fb53af90941cefa60/android/api_levels.go)：注释把它称为“future API level (10000)”，并说明 `current` 是任意未来版本。因此这里不能把 10000 读作“API 10000 的稳定设备已经普遍实现”。

`ProcessHandle` 的 Android 状态也有直接的 AOSP 证据：AOSP [`ProcessHandle.annotated.java`](https://android.googlesource.com/platform/libcore/%2B/aac8cae4ff49a799b912e7bf548fb44504b6fe3c/ojluni/annotations/mmodule/java/lang/ProcessHandle.annotated.java) 在接口上标记 `@libcore.api.Hide`。AOSP 曾以 [“Temporarily hide new java.lang.Process* APIs”](https://android.googlesource.com/platform/libcore/%2B/17035ac8a22260ca2320511ef94da7a69bfd895f) 为提交主题，说明这些 OpenJDK API 在 Android 中的覆盖不足，暂不作为普通 SDK API 暴露。

## 2. `NoSuchMethodError` 为什么会出现在 Pixel 上

### 2.1 错误类型说明

Java SE 官方 [`NoSuchMethodError`](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/NoSuchMethodError.html) 文档定义为：应用尝试调用某个类的方法，而该类已经没有该方法的定义。JVM 规范 [JVMS 5.4.3.3](https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-5.html#jvms-5.4.3.3) 进一步规定，方法查找失败时方法解析抛出 `NoSuchMethodError`。

因此，如果编译产物中有如下等价的 method reference：

```text
java/lang/Process.pid:()J
```

但设备的 boot/core library 中 `java.lang.Process` 没有这个签名，执行到该调用点就会报 `NoSuchMethodError`。这与“方法在类里存在，但具体 `Process` 实现的 `toHandle()` 不支持，于是抛 `UnsupportedOperationException`”是两条不同路径。

### 2.2 本仓库和本地构建证据

仓库历史可以复现引入点：

* commit `772e33f` 的 Product Core 启动路径在 `Process process = builder.start()` 后调用 `process.pid()`，并用该值写 PID 文件、发布 running 状态。
* commit `e631eea` 删除两个 `process.pid()` 调用和 `writePid()`，改用 `ProductCoreLifecycle.UNKNOWN_PID`；当前 [RuntimeService.java](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java:839) 仍保留 `ProcessBuilder.start()`，但不再取 `pid()`。
* 当前契约测试 [s172-android-process-api-contract-test.sh](../../tests/android/s172-android-process-api-contract-test.sh:14) 以 Android `javac` bootclasspath 作为 API 边界，明确拒绝 `process.pid()`、`toHandle()` 和 `ProcessHandle`；Product Core 只保留 `Process` handle。

当前 APK 脚本 [build-debug-apk.sh](../../app/android-runtime/scripts/build-debug-apk.sh:880) 使用：

```text
javac -source 8 -target 8 -bootclasspath "$android_jar" \
  -classpath "$android_jar:$javac_support_jar" ...
```

随后使用官方 D8：

```text
d8 --lib "$android_jar" --min-api 31 ...
```

本地只读检查（JDK 17、Lineage API 36 `android.jar`）的关键输出是：

```text
warning: [options] bootstrap class path not set in conjunction with -source 8
[loading /modules/java.base/java/lang/Process.class]
```

也就是说，旧的仅 `-classpath` 手工 `javac` 会让 `java.lang.Process` 命中 host JDK 17 的 `java.base` module，而不是把 `android.jar` 当成 Java 8 boot class path。当前脚本的 `-bootclasspath` 修复了这条编译边界；其 verbose log 只作诊断证据，不作稳定的文本 gate。另一个独立风险是，`javap -classpath /home/js/android/lineage/prebuilts/sdk/36/public/android.jar java.lang.Process` 显示该 stub 的 `Process` 类含 `pid()`、`toHandle()` 等 OpenJDK 方法；`jar tf` 显示它并不提供一个对应的公开 `ProcessHandle.class`，后者又可能由 host module 补进来。这个本地 jar 行为不能推翻 Android public API reference，只说明“能从某个 stub 编译通过”不是兼容性证据。

因此目前最合理的因果链是：

```text
JDK17/module 或 android.jar stub 暴露 Process.pid
        ↓
javac 产出对 java/lang/Process.pid:()J 的调用
        ↓
Pixel 运行时的 Process 类没有该方法
        ↓
NoSuchMethodError
```

这条链解释了错误，但没有在本次调查中声称 Pixel 的确切 `ro.build.version.sdk` 或完整 APK 字节码来源；二者仍应由设备和 APK 证据补齐。

## 3. `ProcessBuilder.start()` 能否得到 child PID

### 3.1 公共 API 的边界

Android 的 [`Process` API reference](https://developer.android.com/reference/java/lang/Process.html) 说明 `ProcessBuilder.start()` 创建 native process，并返回一个 `Process` 子类实例；公开能力是 I/O、等待、退出状态和销毁。它没有为 Android 已发布 API 提供另一个兼容的 child-PID getter。`pid()` 虽出现在页面摘要中，added-in 是未来 API 10000，不能用于当前 app。

AOSP 的实现源码说明了为什么“内部当然知道 PID”不等于“app 有公开 getter”：

* AOSP [`UNIXProcess.java`](https://android.googlesource.com/platform/libcore/%2B/master/ojluni/src/main/java/java/lang/UNIXProcess.java#59) 在 private `final int pid` 中保存 PID，通过 private native `forkAndExec()` 创建进程，并由内部 reaper 线程调用 `waitForProcessExit(pid)`。
* 同一文件的公开 `waitFor()` 和 `destroy()` 只通过该 private 字段工作；字段没有 public/protected 访问器。
* AOSP OpenJDK [`Process.java`](https://android.googlesource.com/platform/libcore/%2B/837b789147d8f67538be3cfac95aea1343eaf36d/ojluni/src/main/java/java/lang/Process.java#335) 的通用 `pid()` 实现只是 `toHandle().pid()`，而 `toHandle()` 默认实现会抛 `UnsupportedOperationException`。这是 OpenJDK 源码/API 形状，不是 Android public API 的发布承诺。

### 3.2 `android.os.Process` 不是 child-PID 发现接口

官方 [`android.os.Process.myPid()`](https://developer.android.com/reference/android/os/Process.html#myPid()) 文档说它返回“this process”的 identifier；AOSP 实现 [`myPid()`](https://android.googlesource.com/platform/frameworks/base/%2B/HEAD/core/java/android/os/Process.java#860) 直接返回 `Os.getpid()`。它返回的是当前 app/调用进程，不是最近一次 `ProcessBuilder.start()` 的子进程。

官方 [`killProcess(int)`](https://developer.android.com/reference/android/os/Process.html#killProcess(int)) 文档说参数是“given PID”，并提醒 kernel 会限制可杀的范围，通常是调用者 package/application 的进程及该 app 创建的额外进程。AOSP 实现 [`killProcess`](https://android.googlesource.com/platform/frameworks/base/%2B/HEAD/core/java/android/os/Process.java#1351) 只是对传入 PID 发 `SIGKILL`；它不负责发现 PID，也不把 PID 变成稳定的跨重启身份。

AOSP 确实有内部接口，但都不能当 app 兼容 API：[`ProcessStartResult.pid` 和 `killProcessGroup()`](https://android.googlesource.com/platform/frameworks/base/%2B/HEAD/core/java/android/os/Process.java#1582) 在源码中标有 `@hide`。`ProcessStartResult` 供 framework 启动 app process 的内部路径使用，不是 `ProcessBuilder.start()` 的返回值类型。

### 3.3 可用的设计边界

在需要数值 PID 的场景，公开兼容路径只能是应用自己定义的启动协议，例如：

* wrapper/shell 在启动阶段写出自己的 PID；如果 shell 之后用 `exec` 替换成目标程序，该 PID 可继续代表目标程序。原代码就是这种思路：`echo $$ > pidFile; ...; exec <vpp>`。
* native child 自己通过受控 IPC/文件/Unix socket 报告 generation、身份和就绪状态；Java 侧仍以 `Process` 对象的 `isAlive`/`waitFor`/`destroy` 为当前代控制句柄。
* 若只需要停止和等待，不持久化 PID，直接保留 `Process` handle；若 Service 被重建，不能假设旧 handle 可以被重新取得。

不要把 `Process.toString()`、`/proc` 扫描、按可执行文件名找 PID 或 PID 文件当成没有 generation/UID/启动时间校验的安全身份。PID 会复用，而且 AOSP 的 process-group 源码本身也提示需要同时处理进程组、cgroup 与迁移竞争。

原代码的 root 路径还经过 `su 0 sh -c`，所以 shell 写出的 `$$`、`su` wrapper PID、Java `Process` 对象所代表的直接 child 不是同一个抽象层。`exec` 使 shell PID 通常变成 VPP PID，但 root wrapper 的实际进程层级仍应在目标设备上核验；这不是 `Process.pid()` 可移植性问题的反证。

## 4. Service、app process 与 native child 的生命周期

### 4.1 官方文档区分了 process 和 component

官方 [Processes and app lifecycle](https://developer.android.com/guide/components/activities/process-lifecycle) 明确说明：系统可以在任何时候为回收内存杀掉进程，并终止该进程中运行的线程；系统杀进程时 `onDestroy()` 不保证被调用。官方 [Processes and threads overview](https://developer.android.com/guide/components/processes-and-threads) 说明，进程被关掉后，里面的 app components 被销毁，需要工作时系统会再次启动进程。

官方 [Services overview](https://developer.android.com/develop/background-work/services) 对 `onStartCommand()` 返回值的描述是：

* `START_NOT_STICKY`：进程被杀后不要重建，除非有待处理 intent。
* `START_STICKY`：进程被杀后稍后重建 Service，并再次调用 `onStartCommand()`；没有待处理 intent 时传入 null。
* `START_REDELIVER_INTENT`：重建 Service 并重新投递最后一个 intent。

这些条款描述的是 Service/component 的重建策略，不是任意 native child 的托管或 adoption 协议。它们没有承诺旧 Java `Process` 对象仍然存在，也没有承诺由 Service 通过 `fork/exec` 启动的 child 会随 Service object 销毁而结束。

此外，`Process` API reference 明确写道：即使不再有 `Process` 对象的引用，created subprocess 也不会因此被杀掉，而会继续异步执行。这直接排除了“Java handle 被丢弃所以 child 自动退出”的推断。

### 4.2 Zygote/app process 不是 child 生命周期保证

AOSP [`Zygote.forkAndSpecialize()`](https://android.googlesource.com/platform/frameworks/base/%2B/master/core/java/com/android/internal/os/Zygote.java#330) 返回新 app process 的 PID；[`ActivityThread.main()`](https://android.googlesource.com/platform/frameworks/base/%2B/master/core/java/android/app/ActivityThread.java#8911) 在该 app process 中初始化并连接 ActivityManager。这解释 Android app process 的创建和管理边界。

但 `ProcessBuilder.start()` 后创建的 VPP/native sidecar 是 app process 继续执行 native fork/exec 的后代，不是另一个由 ActivityManager 作为 app component 启动的 Java Service。Zygote 管理 app process 的事实并不自动产生“任意后代随父进程死亡”的公开保证。

### 4.3 AOSP 的 process-group 路径是实现细节，而且有条件

AOSP Android 14 [`ProcessRecord.killLocked()`](https://android.googlesource.com/platform/frameworks/base/%2B/refs/heads/android14-release/services/core/java/com/android/server/am/ProcessRecord.java#1212) 在杀 app process 时先调用 `Process.killProcessQuiet(mPid)`，再调用 `killProcessGroupIfNecessaryLocked()`；后者通常调用隐藏的 `ProcessList.killProcessGroup(uid, pid)` 或 `sendSignalToProcessGroup()`。对应的 [`ProcessList`](https://android.googlesource.com/platform/frameworks/base/%2B/master/services/core/java/com/android/server/am/ProcessList.java#844) 通过 handler 异步执行 group kill。

AOSP [`libprocessgroup/processgroup.cpp`](https://android.googlesource.com/platform/system/core/%2B/master/libprocessgroup/processgroup.cpp#387) 的实现说明：

* 对正常 app，process group 与 cgroup “should completely overlap”，所以在理想的 framework 创建/管理路径中，group/cgroup kill 可以覆盖同组 child。
* 实现仍会先单独 kill 初始 PID，并处理 child fork、迁移、cgroup v1/v2、group leader 和清理超时；这表示它依赖当时的 UID/PID/group/cgroup 状态，不是 Java app 可调用的生命周期契约。
* `ProcessRecord` 对 app zygote/WebView zygote 还会根据 `mProcessGroupCreated` 决定是否跳过 group kill，说明该路径本身有条件分支。

AOSP framework 还维护 [`PhantomProcessList`](https://android.googlesource.com/platform/frameworks/base/%2B/master/services/core/java/com/android/server/am/PhantomProcessList.java#406) 来观察部分 app child，并在注释中写“parent is gone, this process should have been killed too”。这是 framework 的监控/清理推断，不是对普通 app 的 API 保证；该功能也受 feature flag、进程可见性和 UID/cgroup 识别影响。

### 4.4 LMK 明确暴露了“不是所有 child 都在可杀 cgroup”

官方 [lmkd documentation](https://source.android.com/docs/core/perf/lmkd) 说明 userspace `lmkd` 在内存压力下杀掉最不重要的进程，并使用进程优先级、memory cgroup 等机制。

AOSP lmkd 的 [`reaper.cpp`](https://android.googlesource.com/platform/system/memory/lmkd/%2B/refs/tags/android-cts-17.0_r1/reaper.cpp) 在 `kill_cgroup_or_process()` 中先尝试 cgroup kill；源码紧接着的注释是：**“Most, but not all processes are in their own cgroups managed by Android”**，并以 adbd children 为例，说明对这些进程只能 kill individual process，因为不应误杀整个 cgroup。

所以应区分以下两句话：

* “某个 Android framework 路径在某些设备/版本上可能通过 app cgroup 把同组 child 一起杀掉”——有 AOSP 实现证据。
* “Service 或 app 进程被杀时，所有由 app `fork/exec` 的 native child 都必然死亡”——没有 Android public contract，且被 lmkd/AOSP 的例外路径否定为普遍命题。

对本仓库而言，app-UID direct `ProcessBuilder` child 可能继承/进入 app 的 process group；经过 `su 0`、改变 UID、改变 process group、独立 supervisor 或 vendor 实现后则可能不同。没有本次设备上的 `/proc/<pid>/cgroup`、父子 PID 和杀进程实验，不能把 Pixel 6a 的实际结果写成平台保证。

## 5. JDK 17、`android.jar`、bootclasspath 与 desugaring

### 5.1 `-source/-target` 不等于 Android API checking

Oracle JDK 17 [`javac` tool specification](https://docs.oracle.com/en/java/javase/17/docs/specs/man/javac.html#compiling-for-earlier-releases-of-the-platform) 说明：

* `--release` 是按指定 **Java SE/JDK release** 的语言规则、class-file 目标和 API 编译。
* `-source` 只指定 Java 语言级别；`-target` 只指定生成的 class-file 目标版本。
* 使用 `-source/-target` 时，还要显式指定适当的 platform classes/boot class path；`-source 8 -target 8` 本身不会限制可调用 API。

因此 JDK 17 上的：

```text
javac -source 8 -target 8 -classpath android.jar ...
```

不能被解释为“按 Android API 31 的 `java.lang` 编译”。本地 verbose 输出已经显示 `java.lang.Process` 从 `/modules/java.base` 加载，并伴随 `bootstrap class path not set in conjunction with -source 8` 警告。`--release 8` 也只表示 Java SE 8 API，不会替代 Android `android.jar` 的 API surface；它不能单独解决 Android framework API 检查。

### 5.2 D8 与 core library desugaring 的边界

官方 [D8 command-line reference](https://developer.android.com/tools/d8) 把 `--lib android.jar` 定义为 Android SDK library classes，把 `--min-api` 定义为输出 DEX 的最低 Android API level。D8 的 `--lib` 并不把任意 host Java API 变成目标设备上的实现。

官方 [Java 8+ language/API support](https://developer.android.com/studio/write/java8-support) 特别说明：普通 Java 8 language-feature desugaring **不会**让旧 Android 版本获得额外 classes/APIs；API desugaring 只支持列出的有限集合，并通过额外 desugared library DEX 提供实现。官方 [Java 8 API desugaring table](https://developer.android.com/studio/write/java8-support-table?hl=en) 和 [Java 11 API desugaring table](https://developer.android.com/studio/write/java11-default-support-table) 列出的是 streams、部分 `java.time`、`java.util.function`、部分 collections/concurrency、部分 `java.nio` 等，没有 `java.lang.Process.pid()` 或 `java.lang.ProcessHandle`。因此不能期待开启普通 desugar 后自动补上 `Process.pid`。

本仓库脚本把 API 31 传给官方 D8（[build-debug-apk.sh](../../app/android-runtime/scripts/build-debug-apk.sh:894)），并在 javac 阶段把 Android `android.jar` 放到 bootclasspath；D8 的 `--lib`/`--min-api` 不能替代这条 source/API compile boundary，也不能把一个已经由错误 host `javac` 编出的、目标设备没有的 `java/lang/Process.pid:()J` 调用变成安全调用。这里“旧 host javac 解析导致错误字节码”的具体因果是结合本地 verbose 证据、脚本和 Android 文档做出的推断。若需要追查异常，可选用 `javap` 或 DEX 反汇编作诊断；它们不是最终的 machine gate，最终运行判断仍是目标设备上的 Start/Query/Stop。

## 6. 对验收标准的建议（研究结论，不是本次代码修改）

### S172 Product Core lifecycle

* 把 `Process` 对象的 `isAlive()`、`waitFor()`、`destroy()`/`destroyForcibly()` 作为当前 Java owner 的控制面；不要把数值 PID 作为 Product Core running 的必要字段。
* 对 Product Core 路径明确禁止 `Process.pid()`、`Process.toHandle()`、`ProcessHandle`；契约可以接受 `UNKNOWN_PID`，并以 generation、socket/session、artifact/revision 和进程 handle 的一致性作为当前代证据。
* 构建验收应在 Android `android.jar` bootclasspath 边界运行正向产品编译和负向 API 编译：`Process.pid()`、`Process.toHandle()`、`ProcessHandle` 必须在 source/API boundary 失败；成功的产品 class 再交给官方 D8（`--lib android.jar --min-api 31`）。`javap`/DEX 反汇编可在异常时作为可选诊断，但不解析 dexdump 文本，也不把最终 DEX machine gate 作为本次判定；最终以目标设备的 Start/Query/Stop 证明运行时行为。

### Service recreation / lost handle

* “Service object 被重建”与“app process 死亡后 child 一定消失/可被 adoption”应拆成独立验收项（当前历史代码已把这类问题放到后续生命周期边界）。`START_STICKY` 只能证明系统会重建 Service 调用，不证明旧 native generation 的 ownership。
* 如果产品必须跨 Service 重建收敛 stale child，应由 wrapper/sidecar 明确写入 generation、UID、启动时间/身份并提供可验证的 IPC lease；不能把 framework cgroup 偶尔一起杀 child 当成契约，也不能用裸 PID 文件作为唯一身份。
* S172 只覆盖同一存活 app process 内的可见 START/QUERY/STOP；process death、lost handle、child adoption 和 fresh recovery 应留在 S173 的独立验收，不应把 Service 自动接管未知 child 的要求塞回本次 gate。

## 7. 证据、推断与仍不确定点

### 已有直接证据

* Android API reference：`Process.pid()` 10000；`isAlive()`/timeout `waitFor` 26；普通 `waitFor` 1。
* Android API diff 26：只新增后三个 API（含 `destroyForcibly`），没有 `pid`。
* AOSP libcore：`UNIXProcess` 私有 PID；`ProcessHandle` annotation `@libcore.api.Hide`；AOSP `Process` framework 内部 PID/group API `@hide`。
* Android 官方生命周期文档：系统可以杀进程，`onDestroy()` 不保证；Service sticky 只描述 Service 重建。
* AOSP ProcessRecord/libprocessgroup/lmkd：framework 有 group/cgroup 清理路径，但 lmkd 明确存在不在 Android 管理 cgroup 中的进程例外。
* 本仓库历史：`772e33f` 引入 `process.pid()`，`e631eea` 移除；旧 VPP launcher 通过 shell `echo $$` + `exec` 写 PID。
* 对旧的仅 `-classpath` 手工命令做过本地 JDK 17 verbose 编译：`java.lang.Process` 从 `/modules/java.base` 加载，并带有 bootstrap class path 警告；当前 APK 脚本已通过 `-bootclasspath android.jar` 固定该边界。

### 本调查的推断

* `NoSuchMethodError` 的最可能来源是 host JDK/module 或隐藏 Android stub 让编译产物包含了 `Process.pid()`，而设备 runtime 的 Android public/core `Process` 没有该方法。错误类型本身证明方法定义在运行时缺失，但不能单独证明具体是 host module 还是某个 `android.jar` 版本造成。
* app-UID direct child 在某些 AOSP/设备路径上可能随 app process group 被杀；root `su`、独立 process group/cgroup 或非 Android 管理 child 的行为可能不同。

### 仍需外部/设备证据确认

* Pixel 6a 的确切 Android build、`ro.build.version.sdk`、运行时 `Process.class` 的反射方法列表，以及完整 crash stack。
* 产生该 APK 的确切 `javac`/D8 命令和 APK/Dex 中是否有 `Process.pid:()J` method reference。
* Pixel 上 VPP、shell、`su` wrapper 的实际父子 PID、UID、process group 和 `/proc/<pid>/cgroup`；以及在“Service stop / app process kill / LMK”三种情形下 child 是否还存在。
* 旧代码 shell `$$` 在目标 root path 上最终代表哪一个 exec 后进程；这应由一次有 generation/启动时间校验的设备观测确认，而不是从 Java `Process` 类型推导。

## 8. 官方来源索引

* [Android `java.lang.Process` API reference](https://developer.android.com/reference/java/lang/Process.html)
* [Android API diff 26: `java.lang.Process`](https://developer.android.com/sdk/api_diff/26/changes/java.lang.Process)
* [Android `android.os.Process` API reference](https://developer.android.com/reference/android/os/Process.html)
* [AOSP libcore `UNIXProcess.java`](https://android.googlesource.com/platform/libcore/%2B/master/ojluni/src/main/java/java/lang/UNIXProcess.java)
* [AOSP libcore `Process.java`](https://android.googlesource.com/platform/libcore/%2B/837b789147d8f67538be3cfac95aea1343eaf36d/ojluni/src/main/java/java/lang/Process.java)
* [AOSP hidden `ProcessHandle` annotation](https://android.googlesource.com/platform/libcore/%2B/aac8cae4ff49a799b912e7bf548fb44504b6fe3c/ojluni/annotations/mmodule/java/lang/ProcessHandle.annotated.java)
* [AOSP `android.os.Process`](https://android.googlesource.com/platform/frameworks/base/%2B/HEAD/core/java/android/os/Process.java)
* [AOSP `Zygote`](https://android.googlesource.com/platform/frameworks/base/%2B/master/core/java/com/android/internal/os/Zygote.java)；[AOSP `ActivityThread`](https://android.googlesource.com/platform/frameworks/base/%2B/master/core/java/android/app/ActivityThread.java)
* [Android processes and app lifecycle](https://developer.android.com/guide/components/activities/process-lifecycle)；[processes and threads](https://developer.android.com/guide/components/processes-and-threads)
* [Android Services overview](https://developer.android.com/develop/background-work/services)；[`Service` API reference](https://developer.android.com/reference/android/app/Service)
* [AOSP `ProcessRecord`](https://android.googlesource.com/platform/frameworks/base/%2B/refs/heads/android14-release/services/core/java/com/android/server/am/ProcessRecord.java)；[`ProcessList`](https://android.googlesource.com/platform/frameworks/base/%2B/master/services/core/java/com/android/server/am/ProcessList.java)；[`PhantomProcessList`](https://android.googlesource.com/platform/frameworks/base/%2B/master/services/core/java/com/android/server/am/PhantomProcessList.java)
* [AOSP `libprocessgroup/processgroup.cpp`](https://android.googlesource.com/platform/system/core/%2B/master/libprocessgroup/processgroup.cpp)
* [Android lmkd documentation](https://source.android.com/docs/core/perf/lmkd)；[AOSP lmkd reaper](https://android.googlesource.com/platform/system/memory/lmkd/%2B/refs/tags/android-cts-17.0_r1/reaper.cpp)
* [Oracle JDK 17 `javac` specification](https://docs.oracle.com/en/java/javase/17/docs/specs/man/javac.html)；[`NoSuchMethodError`](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/NoSuchMethodError.html)；[JVMS method resolution](https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-5.html#jvms-5.4.3.3)
* [Android D8 reference](https://developer.android.com/tools/d8)；[Java 8+ language/API desugaring](https://developer.android.com/studio/write/java8-support)；[Java 8 API table](https://developer.android.com/studio/write/java8-support-table?hl=en)；[Java 11 API table](https://developer.android.com/studio/write/java11-default-support-table)
