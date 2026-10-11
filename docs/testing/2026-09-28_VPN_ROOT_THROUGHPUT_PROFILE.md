# VPN / Root NFQUEUE 的有界 TCP、UDP 吞吐與 VPP 採樣

**取得了 VPN TCP 端到端實收數據，以及 VPN、Root 兩模式可信的 10 Mbps UDP 交付與 VPP 採樣；沒有取得可信的 Root TCP 全路徑吞吐。** Root TCP 兩輪的主機收量遠高於 VPP Flow 計數，且隊列 176 在 TCP 輪後消失；因此 557、333 Mbps 只保留作異常證據，不作 VPN/Root 吞吐比。三張有效 [VPP 火焰圖及原始資料索引](../../build-output/vpn-throughput-profile-20260928/index.html)已保存；Root TCP 重測圖在索引中明示為失效輪次。沒有修改產品程式、規則或做優化。

## 負載與可比範圍

Pixel 6a / Android 16、USB 供電，先普通 UI VPN（generation 1787），後 Root NFQUEUE（1788；為核隊列只冷重啟一次至 1789）。兩模式使用同一帶匹配符號的 APK，SHA-256 `45912610714e32221fa3c924d0b81968f66028ef4820ab6e3ca9a2f194c2afd1`；產品源碼及 ELF 身份見[上一輪符號報告](2026-09-28_VPN_ROOT_SYMBOL_PROFILE.md)。原規則 SHA-256 始終為 `f9e8c4ffef5a6a20b81e4092cc83a7c56b8359605b1a78f35b94fbc284438f0b`。

手機沒有 `iperf`/`iperf3`，故使用一次性 C sender 與 LAN Python receiver，**不是 iperf 成績**。同一主機 `192.168.4.5`，TCP `40562` 單連線連續送 16 KiB 塊 25 秒；UDP `40563` 以 1,200 B datagram 固定提供約 10 Mbps、25 秒。開始前暖機、核對 Product typed `current_flows` 的 UID、端點與計數；正式 sender gate 後才計數。TCP 以主機實收位元組及首末實收時刻計 Mbps，核對 sender 位元組與 EOF；UDP 以序號核對實收、丟失、重複及結束標記。10 Mbps 是**指定速率的一檔**，不是 UDP 最大吞吐。receiver 與 sender 本身也可能限制 TCP，不能把此次 TCP 數值稱為產品極限。

VPN 的 sender 是 `./dev/adb shell` UID 2000，typed Flow 暖機匹配；Root 原產品 OUTPUT NFQUEUE hook 僅選 UID 12632，故 Root sender 以現有可調試產品包的 `run-as` UID 12632 運行，沒有改 hook。這是模式選擇所需的**不同發送 UID**，限制了嚴格同 App 比較。Root 的一次性 helper 在正式輪前只將 gate 最長等待由 60 秒延至 120 秒，主送流迴圈和 25 秒參數不變。送流不計入所採 VPP/`:runtime` 進程。

| 模式 / 負載 | 主機實收 | 主機實收速率 | 交付與路徑證據 |
| --- | ---: | ---: | --- |
| VPN TCP | 643,334,144 B | **205.8 Mbps** | sender 位元組相等、EOF、0 send error；暖機 typed Flow UID 2000，雙向包 `[4,2]`。沒有保存正式後逐位元組 VPP Flow 核對，故只主張端到端實收與採樣窗內 VPP 活躍。 |
| VPN UDP | 26,041/26,041 包，31,249,200 B | 10.026 Mbps | 0 loss、0 duplicate、0 invalid；暖機 typed Flow UID 2000，VPP 入向包 1。未作正式後逐位元組 VPP 核對。 |
| Root UDP，重啟後 | 26,041/26,041 包，31,249,200 B | 10.024 Mbps | 0 loss、0 duplicate、0 invalid。正式後 typed Flow `[26,045,0]` 包／`[31,983,260,0]` B，正好是 26,041 主包 + 1 暖機 + 3 結束標記，每包含 28 B IPv4/UDP 開銷；OUTPUT NFQUEUE 同增 26,045 包／31,983,260 B，隊列 176 序號 0→26,045、drop 0。 |

[TCP/UDP sender、receiver 和 Flow 分頁原件](../../build-output/vpn-throughput-profile-20260928/index.html)可複核這些數字。TCP 的 `TCP_INFO.total_retrans` 在 VPN 只反映 App→HEV 腿，Root 則是另一種連線範圍，沒有拿它們當同口徑 underlay 重傳比較。

## 真實 CPU 火焰圖

設備 `simpleperf record -e cpu-clock -f 199 -g --clockid monotonic` 記錄 VPP、`:runtime` 和 UI PID，每輪設定 28 秒，均 **0 lost samples**。sender 也用 `CLOCK_MONOTONIC`；依實際 `start_monotonic_ns` 與 `main_end_monotonic_ns` 只分析正式負載內樣本。可見 CPU 樣本延伸至正式開始後約 20.8 秒（VPN TCP）、22.1 秒（VPN UDP）、23.7 秒（Root UDP）；記錄設定的 28 秒不代表可聲稱完整 25 秒 CPU 覆蓋。VPN TCP 圖取前 **20 秒**；UDP 兩圖一致取前 **22 秒**，兩種 25 秒負載的吞吐仍按完整交付計。下表秒數是樣本 `period` 權重之和，表示這個**裁剪窗內**估計 on-CPU 時間，並非整輪耗時、電量或每包延遲。

| 負載與 CPU 窗 | VPP | `:runtime` | VPP 主線程 |
| --- | ---: | ---: | --- |
| [VPN TCP 前20秒](../../build-output/vpn-throughput-profile-20260928/vpn/vpp-tcp25-first20-flamegraph.html) | 3,938 樣本／19.789 s | 569／2.859 s | `vpp_wk_0` 3,936/3,938 |
| [VPN UDP 前22秒](../../build-output/vpn-throughput-profile-20260928/vpn/vpp-udp25-matched22-flamegraph.html) | 1,994／10.020 s | 94／0.472 s | `vpp_wk_0` 1,991/1,994 |
| [Root UDP 前22秒](../../build-output/vpn-throughput-profile-20260928/root/vpp-udp25-matched22-flamegraph.html) | 2,096／10.533 s | 120／0.603 s | `vpp_wk_0` 2,093/2,096 |

下列 **self** 是 CPU 指令直接落在函數的樣本；**inclusive** 是函數出現在調用棧的樣本，以該輪 VPP 樣本數為分母。inclusive 的調用者與被調用者重疊，**不可相加**。

| VPP 輪次 | 顯著 self 命中 | 產品／HEV inclusive 路徑 |
| --- | --- | --- |
| VPN TCP（3,938） | `getenv` 277（7.0%）；內核 `ipt_do_table` 182；linker TLS resolver 158；產品 `product_l4_policy_match_cached` 154（3.9%）。 | `product_packet_origin_completion_node_fn` 1,143（29.0%）；`product_vpn_tun_complete_from_graph` 1,096（27.8%）；`product_packet_policy_node_fn` 758（19.2%）；HEV TCP direct-send 662。 |
| VPN UDP（1,994） | 內核 `queue_work_on` 138；`_raw_write_unlock_irq` 74；`do_epoll_wait` 62。最高產品 self `product_l4_policy_match_cached` 23（1.2%）。 | HEV executor 673（33.8%）、HEV UDP direct-send 545（27.3%）、`product_vpn_flow_stack_input_node_fn` 317（15.9%）。 |
| Root UDP（2,096） | 內核 `queue_work_on` 243；`_raw_spin_unlock_irqrestore` 137；`finish_task_switch` 127。產品 `product_l4_policy_match_cached` 38（1.8%）、`product_root_nfqueue_read_ready` 34（1.6%）。 | `product_packet_origin_completion_node_fn` 951（45.4%）、`product_root_nfqueue_complete_from_graph` 944（45.0%）、`product_nfqueue_send_verdict` 930（44.4%）。 |

VPN TCP 的 277 個 `getenv` self 樣本，其現有符號棧直接調用者全是 `product_vpn_tun_product_mode`；[該函數](../../src/product/vpp/product_vpn_tun_adapter.c)確實讀取兩個環境變數。這是明確可定位的採樣熱點，但樣本不能推每包調用次數或保證任何改動的收益，本次也沒有做改動。UDP 兩模式在同長窗口的 VPP period 權重分別 10.020 與 10.533 s，負載與功能路徑不同，不把差額解讀成單包成本倍率。內核鎖與 `epoll` 的 **on-CPU** 幀不證明 off-CPU 等待或鎖競爭。VPP 未知葉 VPN TCP 73/3,938、VPN UDP 72/1,994、Root UDP 70/2,096，主要仍來自原有 stripped `libvlib.so`；任意棧幀未知數更高，不能稱整條棧完整解析。

## Root TCP 失效輪次

Root generation 1788 的 TCP 主機實收 1,738,260,480 B／557.0 Mbps，但隨後仍可讀的同 tuple VPP Flow 僅計 `[21,695,688,67,712]` B，隊列 176 缺席，服務 health 當時仍是 `ok`。冷重啟後四隊列 176–179 齊全，Root UDP 如上全量核對；**僅一次** Root TCP 重測的主機實收 1,043,584,504 B／333.3 Mbps，VPP Flow 卻只有 `[167,473,760,1,583,864]` B，結束後隊列 176 再次缺席，health 仍 `ok`。[重測診斷火焰圖](../../build-output/vpn-throughput-profile-20260928/root/vpp-tcp25-invalid-flamegraph.html)及兩次原始 `perf.data` 都保留，但這些 Mbps **不屬於已驗證的 NFQUEUE/VPP 吞吐**，不參與主比較。

Root mangle OUTPUT 的 NFQUEUE 規則在重測期增加 19,463 包／1,044,975,540 B；因規則含 `--queue-bypass`，**規則命中計數不能證明每個包實際進入隊列**。缺失隊列與 VPP Flow 位元組差距是可重複的測量有效性警訊；本輪沒有確認具體根因，也沒有修改隊列、hook 或產品。Root TCP 的高 Mbps 和少量 VPP 樣本不可拿來宣稱 NFQUEUE 性能或 GSO 加速倍率。原始[缺隊列讀回](../../build-output/vpn-throughput-profile-20260928/root/queue-incident/nfnetlink_queue.txt)、[規則](../../build-output/vpn-throughput-profile-20260928/root/queue-incident/mangle-save.txt)、[health](../../build-output/vpn-throughput-profile-20260928/root/queue-incident/health.properties)與重測[前](../../build-output/vpn-throughput-profile-20260928/root/tcp25-retest-before/nfqueues.txt)／[後](../../build-output/vpn-throughput-profile-20260928/root/tcp25-retest-after/nfqueues.txt)隊列快照保留供後續獨立診斷。

各有效輪的 VPP PSS 前後是 VPN TCP 120,854→120,862 KiB、VPN UDP 120,873→120,901 KiB、Root UDP 120,740→120,764 KiB；電池溫度依次 32.1→32.2、32.3→32.3、32.7→32.7°C。短時快照不足以推長期記憶體趨勢。

收尾後已停止服務、刪除本次設備 helper／gate／perf、恢復原 final-q APK（設備 SHA-256 `2370f4d8f71ec367b5ebb9d5a3e94c0647ff1c0e0ded7b700466e954c516fdee`）。[收尾讀回](../../build-output/vpn-throughput-profile-20260928/closure.json)顯示無 VPP、`:runtime`、NFQUEUE 或產品 mangle hooks；規則 hash 未變，停機歷史 SQLite hash 在恢復 APK 前後相同。自動亮度模式和保持喚醒設定已恢復，亮度即時值由自動感測調至 36。證據檔 SHA 見[清單](../../build-output/vpn-throughput-profile-20260928/evidence-manifest.json)。
