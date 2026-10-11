# 普通 VPN / Root NFQUEUE 匹配符號 CPU 採樣

**有可讀熱路徑，沒有單一產品函數的明確 self CPU 尖峰。** 這次為 final-q 相同產品源碼另建 profiling APK，保留 Release 優化並加入調試符號，對普通 UI VPN 和 Root NFQUEUE 各跑一次相同負載。四張可展開的[真實 simpleperf 火焰圖](../../build-output/vpn-symbol-profile-20260928/index.html)及原始 `perf.data` 已保存；沒有修改產品行為、規則或代碼，也未做優化。

## 構建與符號身份

舊 final-q 雖稱 debug APK，native 插件實際用 CMake `Release`、Rust `cargo --release`，發布前再 `llvm-strip --strip-unneeded`；所以舊採樣的產品插件與 Rust 葉節點有大量未知函數。一次性 profiling 構建仍用相同 pinned VPP stage 與 **逐文件完全相同的 1,331 個 Product source SHA**（源集合 SHA-256 `6b0302a255ace9c8a264aba5f9f2d60a49606de604ef133980821138ddc10fb9`），九個 VPP 基礎 ELF 與 final-q 位元組相同。僅在編譯期給 C 加 `-g`、Cargo release 加 `debug=2`，並在 strip 前留存 ELF；實際 27 個產品 C 編譯命令均含 **`-g -O3 -DNDEBUG`**，沒有 `-O0`，Cargo 記錄為 `release [optimized + debuginfo]`，debug assertions／overflow 設置未變。一次性腳本已刪，差異留在 [構建腳本證據](../../build-output/vpn-symbol-profile-20260928/profile-build-script.diff)。

新 APK 6,174,853 B，SHA-256 `45912610714e32221fa3c924d0b81968f66028ef4820ab6e3ca9a2f194c2afd1`，以與 final-q 相同 versionCode 更新安裝，設備 `base.apk` hash 已核對。產品插件的 pre-strip／APK ELF GNU build-id 均為 `2097cd49b90b5cd163c2920e0f203f5b87e05bdd`。現有 Rust/JNI 鏈接器未寫 GNU build-id；因此逐一核對 pre-strip 與 stage 的**所有可加載節名稱、虛擬地址、大小及內容 SHA-256**（插件 27、Rust 24、JNI 19 節，全部相等），再核對 APK 內三庫與 stage 完整文件 SHA 相等，見 [ELF 身份證據](../../build-output/vpn-symbol-profile-20260928/elf-identity.json)。新符號只解讀**新 APK 的新 `perf.data`**，未套用到舊 final-q 樣本。

## 同條件負載與採樣

Pixel 6a / Android 16，同一 Chrome、同一本機 LAN HTTP 端點及原規則 hash `f9e8c4ffef5a6a20b81e4092cc83a7c56b8359605b1a78f35b94fbc284438f0b`。Chrome 每 50 ms POST 1,024 B，服務端回應 1,024 B，共 800 次／約 40 s；VPN generation 1785 和 Root generation 1786 各 **800/800 成功**，實收請求及回應各 819,200 B。Root 在 VPN Stop、force-stop 後冷進程啟動，KernelSU grant 已核驗。USB 供電、屏幕保持醒著、手動亮度 60；VPN 前後 32.3→32.5°C，Root 32.7→32.7°C。歷史 SQLite 持續正常累積，未清空；這是單設備、單次、低速功能轉發窗口，不能推最大吞吐、長期功耗或 per-packet latency。

每模式對 VPP、獨立 `:runtime` 和 UI 進程作 **50 s `simpleperf record -e cpu-clock -f 199 -g`**，含用戶態與內核，兩次均 0 丟樣。下表的秒數是樣本 `period` 權重之和，表示本次 on-CPU 採樣估計；分母是各模式同長 50 s 窗口。服務占比只在 VPP + `:runtime` 兩進程內計，UI 作環境成本另列。

| 模式 | VPP | `:runtime` | UI（不計服務） | 服務內 VPP / `:runtime` |
| --- | ---: | ---: | ---: | ---: |
| VPN | 529 樣本，2.658 s | 123，0.618 s | 159，0.799 s | 81% / 19% |
| Root | 324 樣本，1.628 s | 48，0.241 s | 209，1.050 s | 87% / 13% |

VPN VPP 線程 `vpp_wk_1`/`vpp_wk_0` 分別約 1.518/1.126 s；Root 的 `vpp_wk_0`/`vpp_wk_1` 約 1.020/0.593 s。VPN `:runtime` 的 UID broker 線程約 0.322 s（64/123 樣本）、觀察消費者約 0.296 s（59/123）；Root 觀察消費者約 0.221 s（44/48），其餘主要是 ART Profile Saver。UID broker 是 VPN 非阻塞應用身份查詢的預期功能工作，Root 沒有相應線程。UI 樣本含前台 Debug Control 與切往 Chrome 的成本，不歸入服務 CPU。這個新 199 Hz 構建與舊 99 Hz final-q 的**樣本個數不可直接相比**；兩輪設備順序和溫度也限制對模式成本倍率的解讀。

## 函數熱點如何讀

下列 **self** 是指令直接落在函數的樣本；**inclusive** 是函數出現在樣本調用棧的次數，以**該進程本輪全部樣本**為分母。調用者與被調用者會重疊，inclusive 數不可相加，也不等於函數自身 CPU 耗時。

| 進程 | 主要 self 命中 | 主要 inclusive 路徑 |
| --- | --- | --- |
| VPN VPP（529） | 內核 `_raw_spin_unlock_irq` 40；`libvlib` 未知葉聚合 38；`vlib_frame_queue_dequeue_fn` 25。產品插件最高的 `product_flow_entry_observe_impl`、`product_packet_origin_completion_node_fn` 各 5。 | `product_packet_origin_completion_node_fn` 95（18%）；`product_vpn_tun_complete_from_graph` 89（17%）；HEV executor 69、TCP session task 67。 |
| Root VPP（324） | 內核 `finish_task_switch` 18；`vlib_frame_queue_dequeue_fn` 17；`libvlib` 未知葉聚合 17；產品插件最高 `product_root_nfqueue_read_ready` 5。 | `product_packet_origin_completion_node_fn` 84（26%）；`product_root_nfqueue_complete_from_graph` 82（25%）；`product_nfqueue_send_verdict` 79（24%）。 |
| VPN `:runtime`（123） | Java `VpnUidBroker.run` 9（7.3%）、內核 `_raw_spin_unlock_irqrestore` 6；Rust `ObservationStore::consume` 3（2.4%），其他產品 Rust 葉各至多 1。 | `ObservationStore::flush` 45（37% `:runtime`；45/59 觀察線程）；`sqlite3_step` 33，屬嵌套的記錄持久化路徑。 |
| Root `:runtime`（48） | 產品 Rust 函數各至多 1。 | `ObservationStore::flush` 36（75% `:runtime`；36/44 觀察線程）；`sqlite3_step` 20，同屬觀察持久化路徑。整個 `:runtime` 在 50 s 僅約 0.241 s 採樣 CPU 權重。 |

這些是可讀的功能路徑熱點：VPN 的 TUN 完成與 HEV/TCP 工作、Root 的 NFQUEUE verdict、兩模式共享的 Flow/Policy 與 SQLite 觀察持久化。單個產品插件函數最高 self 只有 5 個樣本，尚無可直接修復的狹窄熱函數證據。`_raw_spin_unlock*`、`finish_task_switch`、`epoll` 只是 **on-CPU 指令位置**，不能由此認定 off-CPU 等待、鎖競爭或產品缺陷；`libvlib` 的 `unknown` 是多個未命名地址的聚合，**不是一個函數**。

新符號使 VPP 未知**葉**降為 VPN 41/529（7.8%）、Root 19/324（5.9%）；產品插件與 Rust 未知葉均為 0。殘留葉主要來自沿用的、已 strip 的 `libvlib.so`（VPN 38、Root 17）。但 VPP 調用棧中**任意祖先仍有未知幀**的樣本 VPN 453/529、Root 315/324；因此不能宣稱整條棧完整解析。若需追到 VPP 核心內部函數，後續須保留與**相應 VPP stage**精確匹配的未剝離 ELF，再做重複輪次；本輪沒有因此擴大重建或提出優化改動。

本次新構建的 VPP PSS 前後 VPN 120,888→120,894 KiB、Root 120,689→120,692 KiB，`:runtime` VPN 29,853→30,753 KiB、Root 29,376→30,089 KiB；短窗口不能判斷長期泄漏。APK 大小、RSS/PSS/虛擬映射與冷啟動瞬態的完整解釋仍見[原 final-q 基線報告](2026-09-28_VPN_ROOT_PROFILE_BASELINE.md)，不能把此 APK 的文件大小或 Java 進程 RSS 當成 Rust 堆。

原始採樣、前後 meminfo/smaps、實際 HTTP 交付日誌、[symbol cache 身份](../../build-output/vpn-symbol-profile-20260928/symbol-cache-manifest.json)和 [build identity](../../build-output/vpn-symbol-profile-20260928/build-identity.json) 均在新證據目錄，舊 final-q 證據未覆寫。收尾後已停止 Root、force-stop 應用、刪除設備臨時 perf，並用 `install -r` **恢復原 final-q APK**（設備 SHA-256 再次為 `2370f4d8f71ec367b5ebb9d5a3e94c0647ff1c0e0ded7b700466e954c516fdee`）。[收尾讀回](../../build-output/vpn-symbol-profile-20260928/closure.json)顯示停止、無 VPP/`:runtime` 進程、無 NFQUEUE/產品 hooks，規則 hash 保持，停機後 SQLite hash 於重新安裝前後一致。自動亮度模式與 USB 保持喚醒設置已恢復；自動亮度即時值由 44 自行調至 43。
