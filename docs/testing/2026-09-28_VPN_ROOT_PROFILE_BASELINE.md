# 普通 VPN / Root NFQUEUE CPU 與內存基線（2026-09-28）

本報告只測量、不修改產品。Pixel 6a / Android 16 上的安裝 `base.apk` SHA-256 與 S289 最終 APK 完全一致：`2370f4d8f71ec367b5ebb9d5a3e94c0647ff1c0e0ded7b700466e954c516fdee`；APK 文件大小 **6,183,045 B（5.90 MiB）**。普通 UI 點 Start 啟動 VPN generation 1782，Root UI 點 Start 啟動正式冷進程 generation 1784，兩者均為 `running`、`protectionRunning=true`。Root 前先核驗應用 KernelSU 授權；該授權只用於 Root 模式及採樣，不是普通 VPN 的產品依賴。

## 方法與負載

兩模式按 **VPN → Root** 順序，在同一設備、同一 APK、同一原有規則文件（全程 SHA-256 `f9e8c4ffef5a6a20b81e4092cc83a7c56b8359605b1a78f35b94fbc284438f0b`）下測量。Chrome 對主機 `192.168.4.5:40562` 的同源 HTTP 頁面執行固定調度：POST 請求體及回應體各 1,024 B，5 Hz × 40 s 與 20 Hz × 40 s，各模式各一輪。只有一個頁面／流量源；20 Hz 實際峰值並發 VPN 3、Root 2。瀏覽器用普通系統網絡，服務器逐請求記錄實際交付；Android 狀態顯示 VPN Flow Stack 或 Root NFQUEUE 正在保護，Root 的 `/proc/net/netfilter/nfnetlink_queue` 有產品隊列。負載期間不做 VPP 健康／Flow 查詢，以免診斷混入熱窗口；因此本輪不聲稱逐個 HTTP 請求均有獨立 VPP FlowEntry 對照，普通 Chrome VPN 的逐流通路證據仍見 [S289 驗收](2026-09-28_S289_VPN_NORMAL_START.md)。

| 模式 | 5 Hz：實際請求、回應 | 20 Hz：實際請求、回應 | Chrome 成功/失敗 |
| --- | ---: | ---: | ---: |
| VPN | 200 / 200，39.75 s | 800 / 800，39.95 s | 200/0；800/0 |
| Root NFQUEUE | 200 / 200，39.80 s | 800 / 800，39.95 s | 200/0；800/0 |

四輪請求體與回應體實收大小分別為 204,800 B 或 819,200 B。兩模式 USB 供電、屏幕 `Awake`，測量期間手動亮度 60；原自動亮度模式與其餘設置在收尾恢復。電池溫度在 VPN 5 Hz 32.2→32.3°C、20 Hz 32.4→32.4°C；Root 5 Hz 32.7→32.8°C、20 Hz 32.7→32.8°C。Root 較晚且約熱 0.3–0.5°C，不能把單輪模式差當成普遍功耗或吞吐結論。歷史 SQLite 是累積資料，未清除；每段保留前後雜湊，不能假定 Root 與 VPN 有相同歷史內容。切換時短暫啟動的 Root generation 1783 僅為預備探針，已停止並 force-stop；正式 Root 使用新 UI、`:runtime` 和 VPP 進程 generation 1784。

## 真實 CPU 採樣與熱點

設備 `/system/bin/simpleperf record -g` 按 VPP、`:runtime`、UI PID 取 50 s 調用棧，NDK 29 的 `report_html.py` 生成可展開的[火焰圖索引](../../build-output/vpn-profile-20260928/index.html)。5 Hz 用 `cpu-clock:u`/99 Hz；20 Hz 用 `cpu-clock`/99 Hz 包括內核。每輪 **0 樣本丟失**。後一檔是更清晰的有界觀察，不是極限壓測；兩事件類型不同，不跨檔直接比較樣本數。

| 50 s 採樣窗口 | VPN VPP | Root VPP | VPN `:runtime` | Root `:runtime` | UI |
| --- | ---: | ---: | ---: | ---: | ---: |
| 5 Hz，用戶態 | 41 樣本，約 0.414 s 權重 | 34，約 0.343 s | 27，約 0.273 s | 9，約 0.091 s | VPN 76 / Root 75 |
| 20 Hz，用戶態+內核 | **242**，約 **2.444 s** 權重，147 內核 | **88**，約 **0.889 s**，58 內核 | **55**，約 **0.556 s**，27 內核 | **19**，約 **0.192 s**，12 內核 | 兩模式均 0 |

20 Hz 的 50 s 窗口中，VPN VPP 樣本分布於 `vpp_wk_1` 138、`vpp_wk_0` 103；Root 為 `vpp_wk_0` 86、另一 worker 1。VPN `:runtime` 55 樣本分在 `sakamoto-vpn-ui` 30、`flow-observatio` 25；Root 19 個全在觀察線程。這與 VPN UID broker 和雙向用戶空間轉發的額外工作一致，但單個目的端與單輪結果不足以給出普遍倍率或根因。VPP 內核葉節點常見調度／鎖、`epoll_wait`、iptables/BPF 路徑；Root 有 netlink/iptables 路徑。前台 Debug Control 的 15 s 空閒用戶態樣本 VPN 156、Root 160，幾乎全在 UI；VPP 分別只有 1、0，`:runtime` 0、1。20 Hz Chrome 前台時 UI 樣本為 0，故不把診斷 Activity 的前台輪詢算作服務熱點。

本 APK 所帶產品 ELF 已剝離本地函數符號。已用**同一最終構建** stage 的 build-id／native SHA-256 建立 [符號對照](../../build-output/vpn-profile-20260928/symbol-cache-manifest.json)；沒有用重建 ELF 冒充樣本構建。20 Hz 的 VPP 調用棧均非空，但葉節點仍有 VPN **61/242**、Root **25/88** 個 `unknown`：VPN 其中 45 個在 `libproduct_core_plugin.so`、15 個在 `libvlib.so`；Root 22 個在插件、3 個在 `libvlib.so`。Rust native 庫也有 VPN **8/55**、Root **5/19** 個未知葉。內核大多可顯示函數名，但上述未解產品幀使逐函數排名不可信；火焰圖保留原始未知幀，沒有把計數替代為調用棧。最可讀的排名只能到線程、DSO 和已知系統函數層。`perf.data`、逐進程樣本統計、全部 HTML 圖見索引。

`/proc` 前後 CPU tick 另存 [5 Hz](../../build-output/vpn-profile-20260928/vpn/5hz-cpu.json)與[20 Hz](../../build-output/vpn-profile-20260928/vpn/20hz-cpu.json)原始摘要（Root 對應同名目錄）。快照有多個 `dumpsys meminfo`/`smaps` 讀取，且 20 Hz 前後快照間隔 VPN 127.8 s、Root 79.6 s，**不能**將這些 tick 差直接除以 40 s 或拿兩模式高檔 tick 做嚴格比較；上表採用同長 50 s 的 simpleperf 權重。這也不是每包延遲測試，不能由樣本推導 HTTP 或 packet tail latency。

## 內存：進程與映射歸因

下表是 `smaps_rollup` 實際駐留 PSS/RSS，單位 KiB；20 Hz 前後各在流量窗口外採樣。Android `dumpsys meminfo` 的 **TOTAL PSS 包含 SwapPss**，不可直接與只看駐留的 `smaps_rollup Pss` 混比；完整輸出與逐映射[匯總 JSON](../../build-output/vpn-profile-20260928/memory-summary.json)保留。

| 模式、進程 | 冷啟動空閒 PSS/RSS | 20 Hz 前 PSS/RSS | 20 Hz 後 PSS/RSS |
| --- | ---: | ---: | ---: |
| VPN VPP | 121,037 / 124,264 | 121,048 / 124,280 | 121,020 / 124,304 |
| Root VPP | 120,700 / 124,044 | 120,733 / 124,092 | 120,719 / 124,092 |
| VPN `:runtime` | 50,284 / 159,012 | 30,863 / 134,028 | 29,218 / 132,440 |
| Root `:runtime` | 32,179 / 135,476 | 26,535 / 129,916 | 26,586 / 129,984 |
| VPN UI | 43,901 / 170,864 | 16,188 / 145,608 | 16,168 / 145,520 |
| Root UI | 58,395 / 185,352 | 17,265 / 147,244 | 17,251 / 147,248 |

VPP PSS 約 121,000 KiB（**118 MiB**）在兩模式及兩次流量前後都穩定。20 Hz 前 VPN VPP 中約 76,700 KiB 是匿名映射、32,768 KiB 是 `/memfd:buffers-numa-0` VPP 緩衝池、9,450 KiB 是 APK 內產品 native 庫；Root 對應 76,572、32,768、9,236 KiB。匿名映射含分配器與 VPP 基礎設施，不能都視為當前活躍 Flow。VPP `VmSize` 約 27.5 GiB，Android Java 進程約 16.2 GiB，是虛擬地址範圍，不是實體占用。

`:runtime` 是 Java/ART + JNI/Rust + 觀察消費者的獨立 Android 進程，不是獨立 Rust RSS。20 Hz 前 VPN 的 Scudo resident PSS 12,218 KiB、Root 8,126 KiB；JIT 3,740/3,636 KiB，Dalvik/ART 映射 7,343/6,961 KiB，應用 native 庫 3,164/3,046 KiB。同期 `dumpsys meminfo` Native Heap **Alloc 僅 10,216/10,041 KiB**、Java/Dalvik Heap Alloc **2,152/2,144 KiB**；約 4.1 MiB Scudo PSS 差不能直接歸給活躍 Rust 物件、HEV 或泄漏。VPN 冷啟動 `:runtime` PSS 50,284 KiB 中有約 19,646 KiB 暫駐 `.apk` 映射，主要為系統 APK；到 Chrome 前台／20 Hz 前降至 380 KiB。冷啟動時單是 `/system/framework/framework.jar` 就有 RSS 26,972 KiB、PSS 556 KiB，顯示共享頁如何放大 RSS。到 20 Hz 前，`:runtime` 系統映射 RSS 約 69,936 KiB、PSS 僅 1,681 KiB；`dumpsys` 的 Code RSS 79,668 KiB、Code PSS 3,100 KiB，同一共享頁計入多進程 RSS。這解釋為何 T30 曾見約 189 MiB Java/Rust 進程峰值 RSS，但不能讀成 189 MiB Rust 堆或泄漏。本輪沒有觀察到 40 s 負載後的 VPP 或 `:runtime` PSS 持續增長，也沒有低擾動分配棧足以把 Scudo 頁逐組件歸因；因此沒有啟用更具擾動的 heapprofd。

## 可證偽的後續判斷與收尾

1. **VPN 轉發開銷**：若額外 VPP CPU 主要在 TUN/HEV 路徑，匹配構建的未剝離符號與同一流量重跑應把 VPN 的新增樣本落到該路徑；本輪線程/DSO/內核分布與此相容，但未知插件幀阻止逐函數確認。
2. **UID broker 工作**：若 `:runtime` 額外 CPU 由 VPN 的 UID broker 造成，同負載 Root 中該線程樣本應消失；本輪 30→0 符合預測，仍需更大樣本確認穩定比例。
3. **冷啟動 RSS 瞬態**：若較高冷啟動 RSS 來自可回收共享 APK／代碼映射，切到 Chrome 後 `.apk` PSS 應下降而 Native Heap Alloc 不等量上升；本輪 19,646→380 KiB 與約 10 MiB Native Alloc 支持此解釋。
4. **診斷 UI 擾動**：若空閒 CPU 在前台 Debug Control 的輪詢／繪製，Chrome 前台後 UI 樣本應消失；本輪兩模式 20 Hz 均為 0。Activity 的 `onPause` 已取消輪詢 callback，本輪無後台輪詢缺陷證據。

本次短時採樣未發現足以確認的異常或泄漏；不構成長期無泄漏證明。建議下次做逐函數性能定位時保留**與出貨 APK build-id 完全匹配**的 unstripped ELF，並在固定溫度、重複輪次下採樣；這是證據質量建議，不是本輪改動。

原始證據集中在 [`build-output/vpn-profile-20260928/`](../../build-output/vpn-profile-20260928/index.html)：每輪 `http-load*.jsonl`、`*.perf.data`、`*.perf.summary.json`、前後 `status/stat/threads/smaps/smaps_rollup/maps/meminfo`、電池與規則雜湊。最後 UI Stop Root generation 1784 並 force-stop 應用；[收尾證據](../../build-output/vpn-profile-20260928/closure/)顯示 `state=stopped`、無 VPP/`:runtime` 進程、無 NFQUEUE、無 Sakamoto mangle 規則，原規則 SHA 不變。主機 HTTP peer 已停止，設備臨時 perf 文件已移除；原自動亮度模式恢復，系統因自動亮度把保存值 44 自行調整為 40。歷史原資料保留，只記錄其正常累積雜湊變化。入口 34 個原有脏文件的逐文件雜湊保存在 `/tmp/sakamoto-vpn-profile-entry-dirty.json`；本任務未修改產品代碼或這些文件。
