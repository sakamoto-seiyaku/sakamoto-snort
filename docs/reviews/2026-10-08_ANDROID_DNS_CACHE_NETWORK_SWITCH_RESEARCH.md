# Android DNS 缓存与网络切换

2026-10-08。仅核对 AOSP **`android-16.0.0_r1`** 第一方源码；未运行设备或推广到 OEM／其他版本。
这是研究证据，不修改产品实现或正式决策。用户已接受产品 IP↔域名关联缓存切网 RESET、其他时候暂定 2 小时；它与 Android 的 DNS 答案缓存分别管理。

## 核对结果

**不能把“切换网络”概括成 Android 清空所有 DNS 缓存。系统原生 resolver 按网络隔离；Java 层有独立、较短的缓存及明确清理通知。**
网络销毁和 DNS 配置变更存在可定位的清理路径，但本次源码不支持“任何默认网络切换都会立即清空每层缓存”的保证。
下表的 DNS 配置更新通知针对 Java VM 缓存；原生 `resolv_set_nameservers` 的服务器更新分支修改服务器与统计，不能据此等同于执行 `flushNetworkCache`。[N4]

| 缓存／事件 | AOSP 16 r1 的明确行为 |
| --- | --- |
| 原生 DnsResolver 缓存 | `res_cache.cpp` 按 `netId` 管理 `NetConfig`；查询以 `netId` 找缓存。使用不同网络缓存，不等于擦除旧网络缓存。[N1][N3] |
| 销毁网络 | `ConnectivityService` 分别调用 `netd.networkDestroy` 与 `DnsResolver.destroyNetworkCache`；后者删除对应 `netId` 的 resolver 配置／缓存。[C1][N2] |
| 显式 resolver flush | `flushNetworkCache(netId)` 清理指定网络缓存；不是所有网络全局清空。[N2] |
| Java `InetAddress` 缓存 | 每进程静态 `AddressCache`，含正／负条目；键为 hostname＋传入 netId，TTL 为 2 秒；`clear()` 执行 `evictAll()`。[J1][J2] |
| DNS 配置更新 | `updateDnses` 若 DNS 配置相同直接返回；首次／不同配置则提交 DNS servers 并调用 `flushVmDnsCache()`，广播清理 Java VM 缓存。[C2][C3] |
| 单纯默认网络切换 | `makeDefault → makeDefaultNetwork` 设置／清除默认网络；本段没有直接调用 `flushVmDnsCache()`。因此不能用这段代码证明必定清空 Java 缓存。[C4][C5] |

## Java 清理通知闭包

```text
ConnectivityService.updateDnses
  → DnsManager.flushVmDnsCache
  → ACTION_CLEAR_DNS_CACHE 广播（UserHandle.ALL）
  → BroadcastController → AMS 的 CLEAR_DNS_CACHE_MSG
  → ProcessList.clearAllDnsCacheLOSP → IApplicationThread.clearDnsCache
  → ActivityThread → InetAddress.clearDnsCache → AddressCache.evictAll
```

广播由 AMS 转为遍历已有、拥有 `IApplicationThread` 的进程并调用清理方法；调用可能失败，不是同步清理所有任意进程的屏障。[C3][A1][A2][A4]
`ActivityThread` 还分发 libcore network configuration change；`InetAddress.clearDnsCache()` 只清 Java 地址缓存，其源码明确与原生／上游 DNS 缓存分开。[A3][J4]

## 对产品设计的含义与边界

普通 `InetAddress.getAllByName` 使用 `NETID_UNSET = 0`，因此不能仅凭 Java cache 有 netId 键，就认为默认网络切换自动换键而避开旧条目；该层短 TTL 与上述通知分别提供更新机制。[J3]
切换默认网络时旧网络可能仍存活，原生旧网络缓存无需因切换就被全部删除；实际网络销毁时才有上述对应网络删除路径。
VPN 的底层 Wi-Fi／移动网络切换也可能保持同一 VPN netId，不能把“按 netId 隔离”当成这种事件必清缓存的证明。这是从 `Vpn.setUnderlyingNetworks` 更新现有 `mNetworkAgent`、而非要求重建 VPN 网络的路径所得的推断。[V1]
产品 RESET 只丢弃产品 IP↔域名关联事实，不会替 Android 或应用重新解析。应用已有地址／自有缓存或继续使用连接时，可能没有新的 DNS 查询来重建关联；这是两套状态分开管理的设计后果。
上述 Java 通知不承诺清理浏览器自有缓存、任意原生解析器、手工 DNS 客户端或已取得的 IP／已有连接；本轮没有审计这些实现。

## 固定 tag 第一方源码

[C1]: https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/tags/android-16.0.0_r1/service/src/com/android/server/ConnectivityService.java#5770
[C2]: https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/tags/android-16.0.0_r1/service/src/com/android/server/ConnectivityService.java#10166
[C3]: https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/tags/android-16.0.0_r1/service/src/com/android/server/connectivity/DnsManager.java#419
[C4]: https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/tags/android-16.0.0_r1/service/src/com/android/server/ConnectivityService.java#11333
[C5]: https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/tags/android-16.0.0_r1/service/src/com/android/server/ConnectivityService.java#11468
[N1]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/res_cache.cpp#1489
[N2]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/ResolverController.cpp#168
[N3]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/res_cache.cpp#1247
[N4]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/res_cache.cpp#1695
[V1]: https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/services/core/java/com/android/server/connectivity/Vpn.java#2265
[J1]: https://android.googlesource.com/platform/libcore/+/refs/tags/android-16.0.0_r1/luni/src/main/java/java/net/AddressCache.java#30
[J2]: https://android.googlesource.com/platform/libcore/+/refs/tags/android-16.0.0_r1/ojluni/src/main/java/java/net/Inet6AddressImpl.java#79
[J3]: https://android.googlesource.com/platform/libcore/+/refs/tags/android-16.0.0_r1/ojluni/src/main/java/java/net/InetAddress.java#1148
[J4]: https://android.googlesource.com/platform/libcore/+/refs/tags/android-16.0.0_r1/ojluni/src/main/java/java/net/InetAddress.java#1649
[A1]: https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/services/core/java/com/android/server/am/BroadcastController.java#1361
[A2]: https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/services/core/java/com/android/server/am/ProcessList.java#3616
[A3]: https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/core/java/android/app/ActivityThread.java#1463
[A4]: https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/services/core/java/com/android/server/am/ActivityManagerService.java#1806
