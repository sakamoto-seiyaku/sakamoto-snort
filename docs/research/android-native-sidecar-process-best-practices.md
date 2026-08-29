# Android native VPP sidecar 的进程启动与生命周期最佳实践调查

调查日期：2026-08-29
调查范围：普通、非 root 的 Android 应用；`RuntimeService` 作为前台服务，在自己的 app UID 下启动并监督一个长期运行的 native VPP sidecar。sidecar 需要在 app 私有目录使用 Unix socket，并通过 VAPI 与 Java 控制面交互。

本报告只使用 Android Developers、AOSP、NDK/bionic、OpenJDK/JDK、Linux kernel/man-pages 等一手资料；没有操作设备，也没有修改生产代码或测试。报告不重新引入仓库已经删除的 C++ daemon 或 POC 实现。

证据标记：

- **官方保证**：官方公开 API/文档明确描述的行为。
- **工程推断**：由官方行为、当前仓库代码和进程模型推导出的设计结论；不是 Android 跨版本契约。
- **设备待证**：必须在目标 Android build/APK/ABI 上实测，不能仅凭文档或 AOSP 源码断言。

## 结论先行

对于 S172（只覆盖同一个存活中的 `RuntimeService` 的 Start/Query/Stop），最小且最稳妥的方案是：

> 使用 **A：Java `ProcessBuilder` 直接启动一个不会自行 daemonize 的真实 ELF executable，保留返回的 `java.lang.Process` 作为当前 generation 的唯一控制句柄；不读取数字 PID，不写裸 PID 文件**。用 Unix socket 的带 generation/身份的 ready handshake 判断启动成功，用 `isAlive()`、socket/VAPI 状态和 `waitFor` 监督，用有界的 `destroy` → `waitFor(timeout)` → `destroyForcibly` → 再等待收口。

这是“公开 API 形状 + 工程约束”的推荐，不是 Android 对任意 native daemon 都作出的完整托管保证。Android `Process` 文档明确说 `ProcessBuilder.start()` 创建 native process 并返回可控制、可等待的 `Process`，但也警告某些 native 平台上的 daemon process 可能不适用；因此 VPP 必须保持为前台、单一、不会 double-fork/脱离父进程的 child。[官方保证：`Process` API](https://developer.android.com/reference/java/lang/Process)；[官方保证：`ProcessBuilder`](https://developer.android.com/reference/java/lang/ProcessBuilder)；“VPP 不 daemonize”是**工程推断/设备待证**。

旧的 **B：`/system/bin/sh -c 'echo $$ > pidfile; exec native'`** 不是 Android 官方推荐的 sidecar ownership 机制。Android NDK 文档只在 `wrap.sh` 调试包装器示例中展示 `exec "$@"`；没有推荐用 `echo $$`、PID 文件或这种脚本作为普通 app 的 native supervisor。`exec` 可减少一层 shell（在 Linux 上通常使目标继承 shell 的 PID），但 `echo $$` 仍只是应用自定义协议，不包含 generation、UID、可执行文件版本或 ownership 证明；`su` 参与时还会增加 wrapper/UID/process-group 层级。结论是：B 可作为 Root/`su` 边界的遗留适配器，但不应作为 Product Core app-UID 路径的 Android 最佳实践。[官方 `wrap.sh` 示例](https://developer.android.com/ndk/guides/wrap-script)；其余是**工程推断**。

**C：JNI/in-process native library** 是 Android NDK 最常见的 native 代码形状，但它不是“同一套 VPP executable 的另一种启动方式”：它会把 VPP 的线程、内存错误、信号和停机语义放进 `RuntimeService` 进程，无法复用 `Process` 的 wait/destroy 边界。如果产品明确要 fault containment、独立 VAPI Unix socket 和 child 级别的 stop/restart，C 不合适；只有在重新设计 VPP 为可重入 library lifecycle 时才应选它。这是**工程推断**。[官方 NDK ABI/库打包说明](https://developer.android.com/ndk/guides/abis)。

**D：Android component/isolated process/native service** 提供的是 component/process 边界，不是一个兼容当前 API 31–36、拥有普通 app UID 的 VPP launcher。`android:process=":runtime"` 适合让 `RuntimeService` 成为 lifecycle owner；`android:isolatedProcess="true"` 的进程没有自己的权限，不能满足 app-UID VPP 的文件、网络和 VAPI 假设；API 37 的 `nativeService` 又要求 isolated process，且只允许一小部分 NDK API，超出本仓库 API 36 目标和当前 VPP 需求。`VpnService` 只负责 VPN/TUN 接口及其授权，不替代 native sidecar supervisor。[官方 `<service>` 属性](https://developer.android.com/guide/topics/manifest/service-element)；[官方 NativeService NDK API](https://developer.android.com/ndk/reference/group/native-service)；[官方 `VpnService`](https://developer.android.com/reference/android/net/VpnService)。

## A/B/C/D 方案比较

| 方案 | Android API/平台事实 | 对本问题的生命周期与身份 | 结论 |
| --- | --- | --- | --- |
| **A. `ProcessBuilder` 直接 executable** | `start()` 是 API 1；可传 argv、环境、cwd，并返回 `Process`；`isAlive`、超时 `waitFor`、`destroyForcibly` 是 API 26。默认 stdio 是 pipes，必须重定向或消费。 | `Process` handle 在同一个 `RuntimeService` 实例内同时提供等待、退出码、停止和 child 代际绑定；Unix socket handshake 负责 VAPI ready/identity。数值 PID 不是必需信息。 | **S172 推荐**。要求真实 ELF 位于可执行的 APK native payload、child 不自行 daemonize，并做设备验证。 |
| **B. `sh -c; echo $$; exec native`** | Android 只公开了普通 shell/进程执行能力；`wrap.sh` 的 `exec` 是调试包装示例，没有 PID-file 规范。 | `$$` 是 shell 当时的 PID；文件可 stale，PID 可复用，写入时机和 shell/`su` 层级会产生身份歧义。`exec` 常使目标复用 PID，但不提供 generation/ownership。 | **不是官方最佳实践**。仅在 Root/`su` 是外部边界时保留，且 PID 不能作为唯一证据；Product Core 不采用。 |
| **C. JNI/in-process** | NDK 官方主流是 shared library + JNI；native 代码与 ART 同进程。 | 没有 child `Process`，没有独立 kill/wait；native crash、死锁或未受控线程直接影响 `RuntimeService`。可自行开 Unix socket，但 ownership/stop 变成库内协议。 | 只有在选择“VPP 就是 service 内库”这一架构时采用；不满足当前 sidecar 目标。 |
| **D. Service/isolated/native service/`VpnService`** | manifest Service 可指定私有 `:runtime` 进程；isolated service 无自身权限；`nativeService` API 37 且必须 isolated；`VpnService` 建立 VPN interface/TUN fd。 | Component 生命周期不等于任意 child adoption；isolated UID 与 app UID 不同；native service 的受限 NDK 集合不等于 VPP runtime；VPN component 也不负责启动 arbitrary executable。 | `RuntimeService`/`VpnService` 作为控制和前台边界可以保留；不要把 D 当作 A 的替代。 |

上述“推荐/不推荐”是将公开 API 与当前产品约束组合后的**工程决策**；Android 不对普通 app 的任意后代 child 提供完整 daemon manager 契约。

## 1. `ProcessBuilder` 和 `Process` 的公开 API 边界

### 1.1 A 是可用的公开启动模型，但不是任意 daemon 的保证

**官方保证：** Android `Process` 文档规定，`ProcessBuilder.start()` 和 `Runtime.exec()` 创建 native process，并返回一个 `Process` 子类；`Process` 提供向 child 写入、读取输出、等待完成、读取退出状态和销毁的操作。`ProcessBuilder` 文档也明确给出“命令 + 参数、修改环境/cwd、合并 stderr、把输出重定向到日志文件、`start()` 并保留 `Process`”的示例。[`Process`](https://developer.android.com/reference/java/lang/Process)，[`ProcessBuilder`](https://developer.android.com/reference/java/lang/ProcessBuilder)。

**官方限制：** 同一页明确警告，创建过程的方法在某些平台上可能不适合特殊 native process，包括 daemon process 或 shell script。这里的实际含义是：sidecar 不应在启动后自行 `daemon()`、double-fork、关闭/重定向其父进程的监督关系，或把 Java 返回的 process 变成一个已经退出的中间 wrapper。否则 Java handle 只代表 wrapper，不能代表真正的 VPP。把 VPP 保持为前台单进程是**工程推断**，在目标设备上仍属**设备待证**。

### 1.2 API 版本与 PID

| 方法 | Android 公开 API 资料 | 对当前仓库的影响 |
| --- | --- | --- |
| `waitFor()` | API 1 | 兼容基线；应放在后台监督线程/任务上，不能阻塞 Service 主线程。 |
| `isAlive()` | API 26 | 当前 `minSdkVersion=31` 可用；只表示这个 `Process` 对象代表的 child 是否退出。 |
| `waitFor(long, TimeUnit)` | API 26 | 可用于 Stop 的有界等待。 |
| `destroy()` | API 1；是否强制终止由实现决定 | 先发起正常/实现相关的销毁，再限时等待；不能无限等待。 |
| `destroyForcibly()` | API 26；文档仍提醒不会立即结束 | 超时后的最后手段；随后仍要 `waitFor`/`isAlive` 验证。 |
| `pid()` | 当前 Android reference 标为 **API level 10000**；API 36/37 的 diff 都没有把它列为新增 | 不能用于 `minSdk 31`/`targetSdk 36` 的兼容代码；某个 host JDK 或 `android.jar` stub 暴露该签名也不改变这一边界。 |

上述版本事实来自 [Android API diff 26 的 `Process`](https://developer.android.com/sdk/api_diff/26/changes/java.lang.Process)、[Android API diff 36](https://developer.android.com/sdk/api_diff/36/changes/changes-summary)、[Android API diff 37](https://developer.android.com/sdk/api_diff/37/changes/changes-summary) 和当前 [`Process` reference](https://developer.android.com/reference/java/lang/Process)。当前 reference 的 `pid()` 条目仍标成 API level 10000；不能把 OpenJDK 方法签名出现在某个 host JDK 或 `android.jar` stub 中当成 API 31–36 的运行时保证。

**官方保证：** Android 文档还明确说明：即使 Java 侧不再持有 `Process` 对象引用，subprocess 也不会因为引用消失而自动结束，而是继续异步执行。因此“丢掉 handle 就等于 child 已停止”是错误的。[`Process` reference](https://developer.android.com/reference/java/lang/Process)。

**工程决策：** S172 的状态模型应把 `Process` handle 作为当前 generation 的控制句柄，PID 字段如必须保留只填 `UNKNOWN_PID`/未提供；不要反射、调用 `pid()`、依赖 `ProcessHandle`，也不要用 `Process.toString()` 发现 PID。`android.os.Process.myPid()` 只返回调用它的 `RuntimeService` 进程；它不是最近一次 `ProcessBuilder.start()` 的 child PID。[`android.os.Process.myPid()`](https://developer.android.com/reference/android/os/Process.html#myPid)，[AOSP `android.os.Process`](https://android.googlesource.com/platform/frameworks/base/+/HEAD/core/java/android/os/Process.java)。

### 1.3 标准 I/O 必须显式收口

**官方保证：** 默认情况下 child 的 stdin/stdout/stderr 都通过 parent 可访问的 streams 连接；官方文档警告，如果没有及时读写，有限的 native pipe buffer 可能让 child block，甚至 deadlock。[`Process` reference](https://developer.android.com/reference/java/lang/Process)。

对 VPP 这种不以 stdin/stdout 作为控制协议的长期进程，A 的启动协议应做到：

1. 使用 argv 列表和 `ProcessBuilder.environment()`，不要为普通 app 拼接 shell 字符串；环境中只放 ABI、runtime/profile、socket/config/log 路径等必要值。
2. 启动前将 stdout/stderr 合并并重定向到 app 私有日志文件，或启动独立 reader；`ProcessBuilder.redirectErrorStream(true)` 与 `redirectOutput(...)` 都是公开 API。日志需有轮转/大小上限，这是**工程推断**，因为 API 只负责重定向，不替应用限制文件增长。[`ProcessBuilder` I/O API](https://developer.android.com/reference/java/lang/ProcessBuilder)。
3. stdin 不使用时必须明确关闭 `process.getOutputStream()`，或用 API 26 的 `redirectInput` 指向空输入；不要留下一个 child 永远等待 EOF 的隐性协议。`redirectInput` 的公开语义见 [`ProcessBuilder.redirectInput`](https://developer.android.com/reference/java/lang/ProcessBuilder)。具体选 `/dev/null` 还是 close pipe 属于**设备待证/工程实现选择**。
4. VAPI/Unix socket 是 readiness 与控制通道；stdout 只用于诊断，不能承担未消费的健康协议。

## 2. executable 的位置、W^X、ABI 和 `nativeLibraryDir`

### 2.1 不能从可写 app data 目录执行

**官方保证：** Android 10 面向 target 29+ 的行为变更明确说明：从可写 app home directory 执行文件是 W^X 违规；untrusted app 不能对 app home 中的文件直接调用 `execve()`，应只加载嵌入 APK 的 binary code。[Android 10 behavior changes: removed execute permission for app home](https://developer.android.com/about/versions/10/behavior-changes-10)。

因此无论 A 还是 B，都不应把 executable 复制到 `filesDir`、`cacheDir`、临时 profile 目录后再启动。配置、socket、日志、generation/lease 元数据可放在这些可写目录；**代码本体必须来自 APK/安装产生的 native payload**。这是**官方保证**的禁止项。

### 2.2 `nativeLibraryDir` 是受支持的 native library 位置，不是 arbitrary executable API

**官方保证：** NDK ABI 文档说明，安装 APK 时 Package Manager 扫描 `lib/<abi>/lib<name>.so`，并把匹配到的 shared library 复制到应用的 native library directory；`ApplicationInfo.nativeLibraryDir` 的定义是“where native JNI libraries are stored”。[Android ABIs](https://developer.android.com/ndk/guides/abis)，[`ApplicationInfo.nativeLibraryDir`](https://developer.android.com/reference/android/content/pm/ApplicationInfo#nativeLibraryDir)。

`android:extractNativeLibs` 为 `true` 时，安装器将 native libraries 从 APK 提取到文件系统；为 `false` 时，libraries 保持 APK 内未压缩并由 linker 直接从 APK 加载。[`<application android:extractNativeLibs>`](https://developer.android.com/guide/topics/manifest/application-element#extractNativeLibs)。这意味着需要 `execve(path)` 的 sidecar 不能依赖“从压缩/未提取的 APK 内直接执行”；必须使用目标设备真正可执行的 extracted path。

**关键边界（工程推断）：** Android public docs 讲的是 JNI/shared library 加载，并没有承诺“把一个带 `main` 的 arbitrary ELF executable 改名为 `.so` 后就支持被 `ProcessBuilder` 执行”。AOSP Package Manager 当前实现会为提取的 native library 设置可执行的文件权限（实现细节可见 [AOSP `PackageManagerService`](https://android.googlesource.com/platform/frameworks/base/+/master/services/core/java/com/android/server/pm/PackageManagerService.java)），但这仍不是 app-facing 的 arbitrary executable 契约。必须在目标设备验证：

- APK 中的文件确实是目标 ABI 的可执行 ELF（最好是 PIE `ET_DYN`/平台允许的格式），而不只是一个只能被 linker `dlopen` 的 shared object；
- `ApplicationInfo.nativeLibraryDir` 下实际路径存在、拥有执行权限、SELinux label/挂载点允许 `execve`；
- child 依赖的 `DT_NEEDED` 只使用 NDK/public API，且 `LD_LIBRARY_PATH` 指向同一 extracted native directory；
- `extractNativeLibs=true` 或等效 packaging 配置在 release/debug APK 中真的生效。

这些是**设备待证**。不能用“文件名是 `libvpp_runtime.so`”替代 ELF header、权限和实际 launch 证据。

### 2.3 NDK 默认更偏向 shared library

NDK `Android.mk` 同时定义 `BUILD_EXECUTABLE` 和 `BUILD_SHARED_LIBRARY`，但官方特别注明“Most Android apps do not include executables”；默认 app packaging/Android Studio 也主要处理 `lib/` 下的 `.so`。[NDK `Android.mk`](https://developer.android.com/ndk/guides/android_mk)。

所以“把 executable 放入 nativeLibraryDir 并直接启动”不是 Android 应用最常见的模板，而是本产品为 sidecar 选择的**有意识工程方案**。它可以建立在 Package Manager 的 native payload 行为上，但必须把真实 ELF、ABI、依赖、权限和设备 launch 纳入验收，不能把 JNI shared-library 文档解读成完整 sidecar 许可。

另外，bionic/linker 对 API 24+ native library 的依赖有 public-NDK 限制；不能因为系统镜像上某个 private `.so` 存在，就把它作为普通 app child 的稳定依赖。[AOSP/bionic “Android changes for NDK developers”](https://android.googlesource.com/platform/bionic/+/show/master/android-changes-for-ndk-developers.md)。这条规则影响 VPP 的 `DT_NEEDED`、`dlopen` 和 ABI 兼容性，是**官方保证/设备待证**的组合边界。

## 3. Foreground Service、`RuntimeService` 和 VPN 边界

### 3.1 FGS 是长期可见工作的 Android 边界

**官方保证：** Foreground service 用于用户可感知的持续工作，必须显示 status-bar notification；Android 12/API 31+ target app 从后台启动 FGS 受到限制，Android 14/API 34+ target app 还必须声明对应 foreground-service type 的权限。[FGS overview](https://developer.android.com/develop/background-work/services/fgs)，[launch restrictions](https://developer.android.com/develop/background-work/services/fgs/launch)。

`specialUse` 可覆盖没有现成类型但仍是有效用户可感知工作的场景，需要 `FOREGROUND_SERVICE_SPECIAL_USE` 和 service-level `<property>` 说明；它不是“允许任意后台 daemon”或“保证 child 存活”的权限。[FGS types: `specialUse`](https://developer.android.com/develop/background-work/services/fgs/service-types#special_use)。

当前仓库 manifest 的 `minSdkVersion=31`、`targetSdkVersion=36`、`RuntimeService` 私有 `:runtime` 进程、`specialUse`、`FOREGROUND_SERVICE_SPECIAL_USE` 和 subtype property，与这条 FGS API 边界一致（见 [`app/android-runtime/src/main/AndroidManifest.xml`](../../app/android-runtime/src/main/AndroidManifest.xml:5)）。这只证明 manifest 方向合理；通知、启动时机、实际 `startForeground`、设备策略仍应在设备验收中验证。

### 3.2 `android:process=":runtime"` 是控制面进程边界

**官方保证：** `<service android:process=":runtime">` 会在一个私有于该 app 的新进程运行 service；普通 `Service` 的进程仍是该应用组件的 Android process，并不自动变成一个由系统独立托管的 native executable。[`<service>` `android:process`](https://developer.android.com/guide/topics/manifest/service-element)。

这正适合作为产品的 lifecycle owner：Activity 重建不会改变 service 的 Java owner；Java 侧可以把 `Process` handle、VAPI session 和当前 generation 放在 `RuntimeService` 进程里。但是它不会把 arbitrary child 变成一个可以跨 Java process death 自动 adoption 的 Android component；后者需要另行设计。

### 3.3 `VpnService` 只解决 TUN/VPN 授权

`VpnService` 的官方定义是：建立虚拟网络接口，返回给 app 一个 file descriptor，由 app 处理路由到该接口的 IP packets；启动流程是 `prepare` → start service → `Builder.establish` → 处理 fd。[`VpnService`](https://developer.android.com/reference/android/net/VpnService)。

因此 `RuntimeService extends VpnService` 可以同时担当 VPN profile 的 Android component 和 FGS owner，但 `VpnService` 并没有“启动/重启 arbitrary native sidecar、取得 child PID、跨 process death 恢复 sidecar”的 API。VPP/VAPI 的 launch 和 stop 仍应由 A 的 Java supervisor 完成；VPN fd handoff 是另一条 readiness gate。这是**官方保证 + 工程推断**。

## 4. isolated process、native service 及其他 component 方案

### 4.1 `isolatedProcess` 不符合 app-UID VPP 前提

**官方保证：** `<service android:isolatedProcess="true">` 在一个与系统其余部分隔离的特殊进程中运行，并且“has no permissions of its own”；与之通信只通过 Service API 的 bind/start。[`<service android:isolatedProcess`](https://developer.android.com/guide/topics/manifest/service-element)。

本问题要求 sidecar 随 app UID 运行、访问 app 私有配置/socket，并与同 UID 的 VPP/VAPI 交互。isolated process 的 UID/权限语义与此相反，不能作为 S172 的替代。即使再把 native executable 放进 isolated service，也需要重新设计文件、权限、Binder/FD handoff 和网络能力；这是**工程推断**，不要把 isolated process 当作“比 ProcessBuilder 更官方”的 child launcher。

### 4.2 API 37 `nativeService` 不是当前路线

Android API 37 新增的 `android:nativeService=true`/`ANativeService` 让系统不初始化 ART，改为把 library 加载到 service process 并从 native entrypoint 启动；官方 NDK 文档同时强调，因为 ART 可能未加载，native service 只可使用一小组明确列出的 NDK API。[`ServiceInfo.FLAG_NATIVE_SERVICE`](https://developer.android.com/reference/android/content/pm/ServiceInfo#FLAG_NATIVE_SERVICE)，[NDK `NativeService`](https://developer.android.com/ndk/reference/group/native-service)。

官方 reference 还说明 `FLAG_NATIVE_SERVICE` 只有在 `FLAG_ISOLATED_PROCESS` 为真时才有效。[`ServiceInfo`](https://developer.android.com/reference/android/content/pm/ServiceInfo)。因此它既不是当前 `targetSdkVersion=36` 的 API 选择，也不是普通 app UID VPP 的选择；VPP 依赖的 socket、网络/VAPI、运行目录和完整 NDK/bionic 假设不能直接套用 NativeService。未来若产品改成 API 37+、isolated、受限 NDK 的 native component，应当另立架构决策，不要混入 S172。

## 5. 旧 shell `echo $$ + exec` 到底是什么

### 5.1 官方资料支持 `exec` 的局部用途，不支持 PID-file 协议

Android NDK 的 `wrap.sh` 文档为 debuggable APK 展示了：系统执行脚本并把启动命令作为参数传入，最小脚本是：

```sh
#!/system/bin/sh
exec "$@"
```

该文档的上下文是调试/profiling app startup，并未定义 sidecar pidfile、generation、identity、ownership 或 graceful stop 协议。[NDK `wrap.sh`](https://developer.android.com/ndk/guides/wrap-script)。

**官方结论：** Android 官方承认在该调试 wrapper 场景中可以用 `exec` 取代 wrapper image。

**工程结论：** `echo $$ > pidfile; exec native` 是本项目旧代码自定义的“先记录一个数，再替换 image”的协议，不是 Android native sidecar 最佳实践。

### 5.2 `$$`、`exec`、`su` 的身份问题

在 Linux shell 语义中，`$$` 表示执行 echo 时 shell 的 PID；`exec` 用目标程序替换当前 shell image，所以在没有额外 fork 的简单路径上目标通常继续使用同一个 PID。但这只能说明数值 PID 的连续性，不能说明它仍是“本次 generation 的合法 VPP”：

- shell 在写文件后、执行 native 前崩溃时，留下 stale pidfile；
- app 被杀、设备重启、卸载/重装或旧 generation 异常退出后，pidfile 可能继续存在；
- PID 是可复用的 ephemeral number，单独读取文件不能排除另一个进程已经获得同一个数字；
- 通过 `/system/bin/su 0 sh -c` 时，Java `Process` 直接拥有的是 `su` 路径返回的 process，shell、root child、目标进程还可能有不同 UID、父进程和 process group；`exec` 只能替换执行它的那一层，不能替所有 wrapper 证明身份；
- shell command 还引入 quoting、环境继承、重定向和失败分支，`ProcessBuilder` 已经有 argv/env/cwd/redirection 的公开表达。

这些是**工程推断**。本次没有设备证据证明旧 root path 在目标 Pixel/KernelSU 上的最终父子层级，因而不能说旧 pidfile 数字一定代表或一定不代表 VPP；需要专门的设备观察。

## 6. PID 是否必要，以及如何避免 PID reuse

### 6.1 S172：不需要数字 PID

在同一个存活的 `RuntimeService` 内，Java 已经持有由 `ProcessBuilder.start()` 返回的 handle。该 handle 可以：

- `isAlive()` 检查当前代表的 child；
- `waitFor(timeout)` 等待同一 child；
- `destroy`/`destroyForcibly` 请求停止同一 child；
- 读取退出码（child 已终止时）。

因此 S172 的 PID-free 状态模型应如下：

```text
Java Process handle ──控制/等待──> 当前 child generation
          │
          └── Unix socket connect + handshake ──> VAPI ready/status/identity
```

socket 文件存在本身不是 readiness，也不是进程仍活着的证明；必须 connect，并读取带 generation、协议版本、profile、artifact/revision 和 ready 状态的响应。该 handshake 是**工程协议**，不是 Android API；它比裸 PID 更贴近产品真正关心的“是不是我启动的这一代 VPP”。

### 6.2 Linux 一手资料说明 PID file 的风险和更强的 handle

Linux man-pages 对 `/proc/<pid>/stat` 的 `pid` 与 `starttime` 分别定义为 process ID 和自系统启动后的进程开始时间；这解释了为什么 `(pid, starttime)` 比裸 PID 强，但仍是读取 `/proc` 的工程协议，不是 Android app 的稳定公开 API。[`proc_pid_stat(5)`](https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html)。

Linux kernel 文档进一步说明，传统 PID 会被回收复用；打开的 `/proc/<pid>` 目录 fd 不会在 PID 复用后指向新进程。`pidfd_open(2)` 用一个 fd 稳定地指向具体 task，`pidfd_send_signal(2)` 的目的就是避免传统 `kill(pid)` 在 PID reuse 后把信号送给错误进程。[kernel `/proc` 文档](https://docs.kernel.org/next/filesystems/proc.html)，[`pidfd_open(2)`](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)，[`pidfd_send_signal(2)`](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html)。

这些 Linux 机制不能直接变成 Java Android API：`ProcessBuilder` 没有返回 pidfd 的公开方法，目标 Android kernel/bionic 是否提供所需 syscall 也必须逐设备验证。因此它们只属于 S173 的候选实现，不是 S172 要偷偷添加的兼容 fallback。

### 6.3 Unix socket handshake 可以报告什么

Linux `unix(7)` 说明 pathname AF_UNIX socket 受所在目录权限影响，并支持 `SO_PEERCRED`/`SCM_CREDENTIALS` 取得连接 peer 的 credentials；pathname socket 在不再需要时由应用 unlink。[`unix(7)`](https://man7.org/linux/man-pages/man7/unix.7.html)。

对本产品，child 在 ready 前至少应报告（或让 Java 侧通过受保护的连接验证）以下字段：

- `protocol_version`/VAPI capability；
- 本次启动的随机 `generation` 或 128-bit nonce；
- runtime profile（Root/VPN，仅在适用路径）；
- executable/artifact revision 或 digest；
- ABI/API compatibility；
- `ready=true` 以及可查询的 state；
- 可选诊断 PID/UID，不把 PID 当成授权或 ownership 的唯一依据。

Java 侧只有在 handle 尚存、child `isAlive`、socket connect 成功、handshake generation/revision 匹配且 VAPI ready 后才发布 `running`。`SO_PEERCRED` 在 Android 目标 bionic/SELinux 上是否可用、是否应纳入授权检查是**设备待证**；随机 generation + app-private directory 是 S172 的最低工程要求。

## 7. Start / Query / Stop 的最小推荐流程

以下是 S172 可执行的最小设计；超出同一 `RuntimeService` 进程存活期间的恢复不在其范围内。

### Start

1. Activity 在允许的用户可见时机请求 `RuntimeService`；service 先完成合法 FGS promotion、notification 和 profile ownership gate。不能把后台启动限制或 notification 失败吞成 native launch 失败/成功。
2. 生成新的随机 generation；准备 app-private config、socket、log 路径。不要从可写目录复制/执行 binary。
3. 从 `ApplicationInfo.nativeLibraryDir` 得到已安装的 native payload 路径；先做 artifact identity/ABI/可执行权限检查。直接执行 `.so` 文件是工程方案，必须设备验收。
4. 使用 `new ProcessBuilder(binaryPath, arg1, ...)`，不要经过 shell。设置必要的环境变量和 working directory；`redirectErrorStream(true)` + `redirectOutput(logFile)`，并立即关闭不用的 stdin。
5. 保存 `Process` 到当前 generation 的 RuntimeService owner；启动一个不会 daemonize 的 VPP child。启动异常或 child 很快退出时，按 bounded cleanup 结束，不发布 running。
6. 在固定 deadline 内轮询/连接 pathname Unix socket；只在 handshake 的 generation、artifact/revision、profile、协议和 `ready` 全部匹配后发布 running。socket 文件出现但连接失败、generation 不匹配或只返回旧状态，都是 NOT READY。

### Query

- 同一 `RuntimeService` 内先检查 current `Process` handle 是否存在、`isAlive()` 是否为真，再通过 VAPI 查询同一 generation 的 state；
- 不扫描 `/proc`、不按 executable 名称找 PID、不读取没有 identity 校验的 pidfile；
- 若 child 已退出、socket 断开或 handshake generation 不匹配，返回 bounded failure/NOT_RUNNING，进入统一 cleanup；不能用“socket 还存在”伪造 running。

### Stop

1. 优先通过已认证的 VAPI/control socket 请求 child 自己执行 graceful shutdown；等待一个明确、有限的 grace deadline。
2. 若仍存活，调用当前 `Process` 的 `destroy()`，再调用 API 26+ 的 `waitFor(timeout, unit)`。
3. 超时则调用 `destroyForcibly()`，再等待并用 `isAlive()`/退出码确认；官方文档明确说 forcible destroy 不保证立即结束。[`Process.destroy`/`destroyForcibly`](https://developer.android.com/reference/java/lang/Process)。
4. 只有确认 child 已结束或产品明确定义为 terminal cleanup failure 后，才清理 socket/config/lease 状态；清理应按 generation 归属执行，不能删除可能属于未来 generation 的 socket。

`destroy()` 是否强杀是实现相关行为，`destroyForcibly()` 也可能短暂保持 alive；因此“调用一次 destroy 就算 Stop 成功”不满足官方 API 语义。所有等待都应有 deadline，不能在 Service 主线程无限 `waitFor()`。

## 8. Service/app process death 的边界

### 8.1 官方保证只到 component/process，不到任意 child adoption

Android 生命周期文档说明，系统可以在内存紧张时杀掉 app process 和其中线程，而且 process 被杀时不保证调用 `onDestroy()`。[Processes and app lifecycle](https://developer.android.com/guide/components/activities/process-lifecycle)。`Service` 的 `START_STICKY`/`START_NOT_STICKY`/`START_REDELIVER_INTENT` 只描述 service process 被杀后是否重建、是否重新投递 intent；并不保证恢复旧 Java `Process` 对象或接管旧 native child。[`Service` API](https://developer.android.com/reference/android/app/Service)。

**官方保证：** `Process` 对象失去引用不会自动杀 child。

**工程推断：** app process 死亡后，child 是否随 app cgroup/process group 一起死亡取决于 framework、UID、group/cgroup、root wrapper 和厂商实现；不能把它当普通 app public API。AOSP 确有 app process group kill 路径，但同时有 child/cgroup 例外，且 lmkd 源码明确“Most, but not all processes are in their own cgroups managed by Android”。参考 [AOSP `ProcessRecord`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android14-release/services/core/java/com/android/server/am/ProcessRecord.java)、[AOSP `libprocessgroup`](https://android.googlesource.com/platform/system/core/+/master/libprocessgroup/processgroup.cpp)、[AOSP lmkd reaper](https://android.googlesource.com/platform/system/memory/lmkd/+/refs/tags/android-cts-17.0_r1/reaper.cpp)。

因此：

- Activity close/reopen 不应改变仍存活的 `RuntimeService` owner；这是当前产品 component 设计。
- Java Service object 被重建时，旧 `Process` handle 不会神奇恢复；不能无条件把同名 socket 当成自己的 child。
- app process 被杀时，不应把“child 通常可能被系统一起清理”写成 Android guarantee；Root/`su` 路径尤其不能这样推断。
- S172 明确限定为同一 `RuntimeService` 存活期间的 Start/Query/Stop；process death、lost handle、child adoption 和 fresh recovery 不属于本次验收。它们应由 S173 单独定义 fail-closed、清理、generation 重建和 adoption 语义，不能在 S172 中假装已经实现。

### 8.2 S173 若需跨进程恢复，另加什么

如果未来 S173 要求 `RuntimeService` 重建或 app process death 后恢复/清理旧 sidecar，至少需要单独的 durable ownership 协议：

1. 持久化 owner record：package/user UID、profile、generation/随机 nonce、artifact digest/revision、socket path、启动时间/单调时钟证据、协议版本；PID 只能是诊断字段。
2. child 启动时原子发布 generation/identity；每次 Java attach 必须通过 handshake 校验 nonce、artifact、UID/profile 和 ready state。
3. 采用 child 持有的 lease/lock/owner token，或由 native supervisor 持有可验证的 pidfd；不能只靠一个可覆盖的 pidfile。
4. 如只能用 PID，至少结合 `pid + /proc/<pid>/stat starttime + uid + executable identity + generation/token` 并在同一检查窗口验证；仍需评估 Android `/proc` 权限、PID namespace 和 bionic syscall 可用性。
5. 定义 adopt、stale、duplicate-start、stop-after-restart、旧 socket 清理和 app uninstall/upgrade 的幂等语义。
6. 对 framework process death 与 child 是否被杀分别做 device matrix；不要把 cgroup 偶然行为当 ownership 协议。

这些是 S173 的架构增量，不能为了满足 S172 把持久化 adoption、pidfd 或扫描 `/proc` 偷塞进当前改动。

## 9. 当前仓库的映射

本次只调查，不改代码；以下是对当前实现的定位：

- 当前 Product Core 启动路径 [`RuntimeService.java`](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java:817) 已经采用 A 的主要形状：从 `nativeLibraryDir` 取 VPP path，构造 argv/env，`ProcessBuilder.start()`，保留 `Process`，redirect stdout，并以 socket/VAPI readiness 连接。该路径不应重新引入 `process.pid()`。
- 当前 [`ProductCoreLifecycle.java`](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductCoreLifecycle.java:1) 的 `UNKNOWN_PID` 与 PID-free Product Core 状态模型一致；若上层旧 schema 仍有数字字段，应明确其为“未提供/诊断兼容字段”，不读取伪 PID。
- 当前 legacy/root [`launchVpp`](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java:1382) 仍有 `/system/bin/sh -c`、`echo $$`、`exec` 和 `su 0 sh -c`。它应被视为 Root profile 的历史 adapter/权限边界，不应作为普通 app-UID Product Core 的最佳实践证据；若保留，必须单独验证 UID、父子层级、process group、PID 文件身份与 cleanup。
- 当前 manifest [`AndroidManifest.xml`](../../app/android-runtime/src/main/AndroidManifest.xml:5) 明确 `android:extractNativeLibs="true"`、`:runtime`、`specialUse` 和 `BIND_VPN_SERVICE`；这些满足 FGS/component/VPN 方向，但不替代真实 ELF launch 与 device proof。
- 当前自定义构建脚本 [`build-debug-apk.sh`](../../app/android-runtime/scripts/build-debug-apk.sh:918) 把 VPP artifact 以 `libvpp_runtime.so` 放入 ABI native payload。由于 NDK 官方默认以 shared library 为主，必须在验收中确认这个文件实际上是可由 `execve` 启动的 ELF executable，而不是仅可 `dlopen` 的 library。
- 当前产品域文档已规定一个由 `RuntimeService` 监督的 VPP runtime、Root/VPN profile 互斥；本报告沿用该边界，不引用已删除 C++/POC 作为实现来源。[功能闭合契约](../../docs/decisions/ANDROID_FUNCTIONAL_CLOSURE_CONTRACT.md:23)，[Android runtime README](../../app/android-runtime/README.md:13)。

## 10. 验收与仍需验证项

### 主机/构建侧（无需设备即可先做）

- API 兼容性应在 Android `android.jar` bootclasspath 边界由 javac 负向编译证明：`Process.pid()`、`Process.toHandle()`、`ProcessHandle` 必须编译失败；成功的产品 class 再交给官方 D8（`--lib android.jar --min-api 31`）。`javap`/DEX 反汇编只作异常时的可选诊断，不解析 dexdump 文本，也不把最终 DEX machine gate 作为 S172 判定。
- 用 `file`、`readelf -h -l -d` 检查 `libvpp_runtime.so` 的 ELF type、ABI、interpreter、`DT_NEEDED` 和 public-NDK 依赖；确认它有正确 entrypoint，且不是只能被 `dlopen` 的 shared object。
- 解包 APK，确认 `lib/<abi>/libvpp_runtime.so` 的 ABI、压缩方式和 payload；检查 manifest/package metadata 中 extraction 行为与脚本预期一致。
- 编译/静态检查覆盖：`ProcessBuilder` argv（无 shell）、stdin 关闭、stdout/stderr 重定向、bounded wait、`destroyForcibly` 后再 wait、generation handshake 与 duplicate-start gate。

### 目标设备侧（本次未操作，必须由后续验证完成）

所有 Android 设备操作遵循仓库规定的 `./dev/adb` wrapper；不要直接调用 sibling checkout 或 Windows `adb.exe`。

1. 记录 `ro.build.version.sdk`、build fingerprint、ABI、app UID 和 `ApplicationInfo.nativeLibraryDir`；检查实际 native payload 路径、权限、SELinux label 和 mount `noexec` 情况。
2. 从可见 UI 启动 FGS，验证 `startForeground`、notification、`specialUse` permission/type 和后台启动边界；确认 Activity close/reopen 时 `RuntimeService` 和同一 generation 仍在。
3. 通过 A 直接启动 VPP，验证 `ProcessBuilder.start()` 成功、child 不 daemonize、同 UID、VAPI Unix socket connect、generation/artifact/ready handshake 和 query 状态。
4. Start twice/并发 Start：第二次必须拒绝或复用同一 generation，不能产生两个 VPP；socket 文件存在但 handshake 错误时不得发布 running。
5. Stop matrix：graceful VAPI stop、child 已退出、child 忽略 graceful stop、`destroy` 超时、`destroyForcibly`、stdout 高频输出；确认每个路径都 bounded 且最终状态/残留符合契约。
6. 让 child 早退/启动失败，验证 failure cleanup 不依赖数字 PID、不误删未来 generation 的 socket/config。
7. 单独对 legacy/root 路径记录 `su`、shell、native 的 UID/PID/PPID/process group/cgroup 和 pidfile 内容；验证 `echo $$ + exec` 的最终身份，仅作为 Root adapter 证据，不能反推 Product Core 结论。
8. app process death、Service recreation、LMK/系统回收属于 S173 议题；若提前实验，只记录观察结果，不把“child 一起死了”当成可依赖的 S172 public contract。

## 11. 最终推荐与决策边界

| 决策 | 状态 | 依据 |
| --- | --- | --- |
| S172 Product Core：直接 `ProcessBuilder` + 保留 `Process` + Unix socket generation/ready handshake | **推荐** | API 1/26 的公开启动、I/O、wait、destroy 语义；PID 对当前控制面没有必要。**官方保证 + 工程推断**。 |
| 生产代码读取 `Process.pid()`/`ProcessHandle` | **禁止** | 当前 min/target API 没有可依赖的 public guarantee；host stub 能编译不等于设备实现。**官方 API 资料**。 |
| 生产代码用裸 PID 文件判定/停止 Product Core | **禁止** | stale file、PID reuse、shell/`su` identity ambiguity；Linux pidfd 文档也说明传统 PID signal 有 reuse race。**工程推断 + Linux 一手资料**。 |
| 旧 `echo $$; exec` | **仅限 legacy Root adapter** | `exec` 在官方 `wrap.sh` 里有局部 wrapper 用途，但没有 pidfile/ownership recommendation。**官方局部事实 + 工程推断**。 |
| 把 VPP 改成 JNI/in-process | **不作为 S172 修复** | NDK 支持 library，但会删除 child fault/lifecycle boundary，需另立架构。**工程推断**。 |
| isolated process / API 37 NativeService | **不采用** | isolated 无普通 app 权限；NativeService API 37、必须 isolated、NDK API 受限；不适合当前 target36/app-UID VPP。**官方资料 + 工程推断**。 |
| 跨 Service/app process death adoption | **留给 S173** | 需要 durable lease/token、generation handshake、身份校验及设备 matrix；S172 不扩大范围。**工程推断**。 |

一句话：**S172 应保留并强化 A 的 handle-based supervisor，去掉 PID 依赖；B 只作为 Root 历史边界，不是 Android 官方最佳实践；C/D 是不同架构，不能用来掩盖当前 sidecar 的 launch/ownership 问题。**

## 官方来源索引

- [Android `java.lang.Process` API reference](https://developer.android.com/reference/java/lang/Process)
- [Android `java.lang.ProcessBuilder` API reference](https://developer.android.com/reference/java/lang/ProcessBuilder)
- [Android API diff 26: `java.lang.Process`](https://developer.android.com/sdk/api_diff/26/changes/java.lang.Process)
- [Android API diff 36](https://developer.android.com/sdk/api_diff/36/changes/changes-summary)
- [Android API diff 37](https://developer.android.com/sdk/api_diff/37/changes/changes-summary)
- [AOSP libcore `Process.java`](https://android.googlesource.com/platform/libcore/+/master/ojluni/src/main/java/java/lang/Process.java)
- [AOSP libcore `UNIXProcess.java`](https://android.googlesource.com/platform/libcore/+/master/ojluni/src/main/java/java/lang/UNIXProcess.java)
- [Android `android.os.Process` API](https://developer.android.com/reference/android/os/Process.html)
- [AOSP `android.os.Process`](https://android.googlesource.com/platform/frameworks/base/+/HEAD/core/java/android/os/Process.java)
- [Android processes and app lifecycle](https://developer.android.com/guide/components/activities/process-lifecycle)
- [Android `Service` API](https://developer.android.com/reference/android/app/Service)
- [`<service>` manifest element](https://developer.android.com/guide/topics/manifest/service-element)
- [Foreground services overview](https://developer.android.com/develop/background-work/services/fgs)
- [Launching a foreground service](https://developer.android.com/develop/background-work/services/fgs/launch)
- [Foreground service types](https://developer.android.com/develop/background-work/services/fgs/service-types)
- [`VpnService` API](https://developer.android.com/reference/android/net/VpnService)
- [Android 10 W^X/app-home execution behavior](https://developer.android.com/about/versions/10/behavior-changes-10)
- [Android NDK ABIs and native library extraction](https://developer.android.com/ndk/guides/abis)
- [`ApplicationInfo.nativeLibraryDir`](https://developer.android.com/reference/android/content/pm/ApplicationInfo#nativeLibraryDir)
- [`<application android:extractNativeLibs>`](https://developer.android.com/guide/topics/manifest/application-element#extractNativeLibs)
- [NDK `Android.mk` executable/shared-library modules](https://developer.android.com/ndk/guides/android_mk)
- [AOSP/bionic Android changes for NDK developers](https://android.googlesource.com/platform/bionic/+/show/master/android-changes-for-ndk-developers.md)
- [NDK `wrap.sh`](https://developer.android.com/ndk/guides/wrap-script)
- [`ServiceInfo.FLAG_NATIVE_SERVICE`](https://developer.android.com/reference/android/content/pm/ServiceInfo#FLAG_NATIVE_SERVICE)
- [NDK `NativeService`](https://developer.android.com/ndk/reference/group/native-service)
- [Linux `unix(7)`](https://man7.org/linux/man-pages/man7/unix.7.html)
- [Linux `proc_pid_stat(5)`](https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html)
- [Linux kernel `/proc` documentation](https://docs.kernel.org/next/filesystems/proc.html)
- [Linux `pidfd_open(2)`](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
- [Linux `pidfd_send_signal(2)`](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html)
- [AOSP `ProcessRecord`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android14-release/services/core/java/com/android/server/am/ProcessRecord.java)
- [AOSP `libprocessgroup`](https://android.googlesource.com/platform/system/core/+/master/libprocessgroup/processgroup.cpp)
- [AOSP lmkd reaper](https://android.googlesource.com/platform/system/memory/lmkd/+/refs/tags/android-cts-17.0_r1/reaper.cpp)
