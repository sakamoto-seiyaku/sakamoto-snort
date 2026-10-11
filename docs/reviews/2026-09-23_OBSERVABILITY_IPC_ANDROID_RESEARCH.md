# Android observability IPC：Perfetto 與 FMQ

2026-09-23。研究範圍：VPP-native C → Rust、minSdk 31、一般 App／無 root VPN；正常與 debug 通道可分開，但尚未選定 transport。僅查官方文件與原始碼，未建置、操作裝置或匯入程式碼。

**建議：Perfetto 保留為選配 debug tracing；FMQ 不列入一般 App 的現成 transport 短名單。** 兩者都有可取之處，但沒有直接提供本案所需的小型 C → Rust record channel。這是適配性判斷，不代表兩條通道已選型。

| 候選 | 可重用的能力 | 本案主要限制 |
| --- | --- | --- |
| Perfetto | trace schema、有限 buffer、丟失統計、UI／SQL 診斷 | tracing service/runtime、C++ 實作、內部鎖與執行緒；不是直接讀取 record 的小佇列 |
| Android FMQ | 固定容量 shared-memory ring、非阻塞 write、選配 futex 通知 | C++／AOSP 平台依賴；AIDL NDK backend 不表示 libfmq 是 App 公開 NDK library |

Perfetto 固定 **v58.2，commit `add693d8b338ba9599dbcbc3e300b1ab8c000897`**；FMQ 同時檢查 Android 12 基線 **`8dd3bc99a159970f44298bb8e3d83366aac63273`** 與查閱時 main **`2f538a2ce58e459721a81cc54f68a8296f874b0c`**。[Perfetto release](https://github.com/google/perfetto/releases/tag/v58.2)、[FMQ Android 12](https://android.googlesource.com/platform/system/libfmq/+/8dd3bc99a159970f44298bb8e3d83366aac63273/)、[FMQ main pin](https://android.googlesource.com/platform/system/libfmq/+/2f538a2ce58e459721a81cc54f68a8296f874b0c/)。

Perfetto **確有 public C ABI**：`include/perfetto/public/abi` 與 C convenience headers，可由 C 或 Rust FFI 呼叫。可是 v58.2 自己仍標示 API／ABI 未穩定；`libperfetto_c` 連入 C++ `client_api`，C producer 初始化轉呼叫 `perfetto::Tracing::Initialize`。C 介面消除呼叫端使用 C++ 的需要，沒有消除 C++ runtime／建置依賴。[C SDK 狀態](https://github.com/google/perfetto/blob/v58.2/examples/shared_lib/README.md)、[build](https://github.com/google/perfetto/blob/v58.2/src/shared_lib/BUILD.gn)、[C ABI 實作](https://github.com/google/perfetto/blob/v58.2/src/shared_lib/producer.cc)。

Android 使用途徑須區分：**in-process** 把 service 一併放進 App，不需特殊 OS 權限，適合無 root 的 App 自身診斷；它本身不連接另一個 VPP/Rust process。**system backend** 經 UNIX socket 連 `traced`；官方明確限制 producer 讀回 system trace，因此不能假定一般 App 的 Rust 可以把系統 service 當私有資料通道。自行部署 service 又增加程序與生命週期。standalone build 使用 NDK sysroot、API level 設定及 `liblog`，具有公開 NDK 建置路徑；應自行打包依賴，不能依賴裝置上的私有 Perfetto library。本研究沒有證明特定 `libperfetto_c` 成品已通過 minSdk31 ELF／裝置驗證。[模式與權限](https://github.com/google/perfetto/blob/v58.2/docs/instrumentation/tracing-sdk.md#in-process-vs-system-mode)、[NDK build](https://github.com/google/perfetto/blob/v58.2/gn/standalone/BUILD.gn)。

Perfetto 的 C data source 預設 **DROP**；另有 `STALL_AND_ABORT`、`STALL_AND_DROP`，後兩者不符合 VPP 不等待下游的要求。但 DROP 只避免等待可用 buffer：`GetNewChunk()` 仍取 `MaybeRtMutex`，不能宣稱整條 producer 路徑無鎖或 wait-free。共享 staging buffer 滿時掉資料；central buffer 可選覆寫舊資料或丟棄新資料，並有 loss statistics。其設計偏向低寫入成本，非低延遲讀取；Rust 若直接接它，還需處理 trace packet/schema 與 session。[C loss policy](https://github.com/google/perfetto/blob/v58.2/include/perfetto/public/abi/data_source_abi.h)、[預設值](https://github.com/google/perfetto/blob/v58.2/include/perfetto/public/data_source.h)、[區塊取得鎖](https://github.com/google/perfetto/blob/v58.2/src/tracing/core/shared_memory_arbiter_impl.cc#L116)、[buffer 與資料流](https://github.com/google/perfetto/blob/v58.2/docs/concepts/buffers.md)。

Perfetto 初始化建立 `TracingMuxer` 執行緒；Android task runner 用 `poll`、eventfd 喚醒，commit 可排入延遲工作。這不是零背景執行緒的 transport，也不能由「非阻塞」推導省電。若日後採用，較合理的位置是既有 debug record 的下游輸出端；不要僅因 C ABI 就把它放進 VPP 熱路徑。[muxer](https://github.com/google/perfetto/blob/v58.2/src/tracing/internal/tracing_muxer_impl.cc#L937)、[task runner](https://github.com/google/perfetto/blob/v58.2/src/base/unix_task_runner.cc)、[eventfd](https://github.com/google/perfetto/blob/v58.2/src/base/event_fd.cc)。

FMQ 從 Android 12 支援 AIDL NDK backend；Binder 傳 descriptor 完成握手後，record 本身走共享記憶體，不需要逐筆 Binder transaction。payload 必須固定 layout、不可含 pointer。同步型是單 writer／單 reader，容量不足時 `write()` 立即回傳 false、不做部分寫入；非同步型支援單 writer／多 reader，允許覆寫，慢 reader overflow 後第一次 read 失敗並跳到當前 write position。它沒有替本案定義 sequence、drop ledger 或 restart generation。[AIDL FMQ](https://source.android.com/docs/core/architecture/aidl/fmq)、[容量、拓撲及 overflow 語義](https://source.android.com/docs/core/architecture/hidl/fmq)。

FMQ 佇列本體不建立 background worker；非阻塞 `write()` 做 begin/copy/commit，普通 commit 不自動通知。選配 EventFlag 使用 atomic bit 與 `FUTEX_WAKE_BITSET`／`FUTEX_WAIT_BITSET`，已置位的通知可合併；consumer 如何睡眠、通知與握手執行緒仍需整合。VPP 必須避開 `writeBlocking()` 的同步型等待。[Android 12 queue](https://android.googlesource.com/platform/system/libfmq/+/8dd3bc99a159970f44298bb8e3d83366aac63273/include/fmq/MessageQueueBase.h)、[EventFlag](https://android.googlesource.com/platform/system/libfmq/+/8dd3bc99a159970f44298bb8e3d83366aac63273/EventFlag.cpp)。

**FMQ 的關鍵障礙是交付邊界。** Android 12 與目前 main 的 `libfmq` 都依賴 `libbase/libcutils/libutils`；AidlMessageQueue 是 C++ template。main 雖有 Rust binding，仍經 C++ erased wrapper，build 列出 libc++ 與 AIDL 平台模組。`min_sdk_version: 29` 是該平台模組的建置條件，不能證明一般 App 可連結系統 libfmq；公開 NDK API 目錄沒有 FMQ，Android 也限制 App 連結非 NDK 平台 library。因此 minSdk31／無 root VPN 不應直接採系統 libfmq。自行移植並封裝全部依賴或重作 ring 都是額外維護方案，失去「直接採用小型現成庫」的優勢。[pinned build／Rust 依賴](https://android.googlesource.com/platform/system/libfmq/+/2f538a2ce58e459721a81cc54f68a8296f874b0c/Android.bp)、[公開 NDK APIs](https://developer.android.com/ndk/guides/stable_apis)、[private library 限制](https://developer.android.com/about/versions/nougat/android-7.0-changes#ndk)。
