# VPP handoff 與 worker 排程實踐審查

2026-10-11；產品基線 `54f2566f26cbbd2ae2cdfd3a1796e4e0f19041e6`，VPP pin `9258530f3804a152578ce11cc7c8a1e9eab88ed0`。本次只讀現行 C 產品、決策與官方來源，沒有執行產品測試、裝置操作或效能量測。`build-output/pinned-vpp-clean` 是乾淨官方 checkout；以下 upstream 行號取自該 commit 的 `git show`，產品改動另對照現行 core／Android patch，沒有把歷史實驗 artifact 當現況。

主要結論：worker、native frame queue、receiver frame 合併與通知都已實作；欠缺的是把既有 packet burst 帶到實際 producer publication 的批次用法。前三優先面如下，均是機制假設，沒有速度預測。

| 優先 | 狀態 | 可獨立評估的改善面 |
| --- | --- | --- |
| P1 | underused／批次调用 missing | Primary、completion、fragment 的 retained publication 按既定 target 聚合 |
| P2 | underused | Adapter burst 以 native 多向量 frame 進入 graph，保持 callback 非遞迴 |
| P3 | constrained／underused | Completion backlog 的批次 retry，連同 packet credits、ring slots、dispatch budget 一起設計 |

## 1. P1：跨 worker 發布確實是一包一個 queue element

產品 primary 在 [`product_packet_graph.c:1213`](../../../src/product/vpp/product_packet_graph.c) 以 `n_packets=1` 呼叫 retained enqueue；completion 同樣在 1865–1866，fragment steer／final 共用 [`product_packet_fragment_graph.inc:275–291`](../../../src/product/vpp/product_packet_fragment_graph.inc)。這不是只有函式名稱呈現 scalar：pin 的 enqueue 在 [buffer_funcs.c:303–321](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vlib/buffer_funcs.c#L303) 每次為每個 target 取得一個 ring element，壓縮同 target indexes，設定 `n_vectors` 後發布 `valid`；跨呼叫不保留未滿 producer element。官方 [handoffdemo:99–102](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/examples/handoffdemo/node.c#L99) 則一次提交整個 frame。

現行 [core patch:78–102](../../../src/product/vpp/patches/core/0001-vlib-nonblocking-retained-enqueue.patch) 已接受 index／target arrays 並逐 `VLIB_FRAME_SIZE` chunk 處理；欠缺的是產品批次呼叫，不必新增另一種 packet queue。可在同一 node dispatch 內以固定 scratch arrays 聚合已決定的 target，結束前發布；不等待後續流量湊滿。每包仍獨立 reserve credit、攜帶 immutable obligation；只對 failed indexes 回滾 credit／保留結算，已成功發布的 buffer 不得再讀寫。Fragment 仍保留 steer 與 final 兩階段，各自依既有 owner 發布，不能混成第二次 corrective distribution。

## 2. P2：入口 burst 在進 graph 時被拆成獨立 frame

Root read callback 有 64 次 receive budget（[`root adapter:1027`](../../../src/product/vpp/product_root_nfqueue_adapter.c)），TUN callback 也有 64 次（[`TUN adapter:317`](../../../src/product/vpp/product_vpn_tun_adapter.c)），但共同 submit 每包呼叫 `vlib_get_frame_to_node`、寫 `n_vectors=1`、再 put（[`graph:4089–4093`](../../../src/product/vpp/product_packet_graph.c)）。pin [main.c:99–104、133–152](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vlib/main.c#L99) 是配置 frame／追加 pending-frame，這裡沒有 native next-frame 的累積行為。故只改 primary handoff 的 array 介面，仍可能一直收到單包 admit dispatch。

可把同一次 read-ready 的已接納 indexes 放入一個 native frame，逐包設定 facts／obligation，逐包處理 pre-admission failure，再提交成功子集。這同時保留 origin-lane ownership、非阻塞 budget 和 graph acceptance 邊界。HEV output callback 也使用同一 submit 入口；若延伸批次，必須保持 ADR-0007 的 copy 完成後 native graph scheduling，不能遞迴執行 parser／policy，不能異步保留 pbuf 借用指標或未提交的裸 buffer index。

## 3. P3：Completion retry 可批次化，但容量單位不能混用

Primary 的 32 credits 是 packet 數（[`graph:47、986–1004`](../../../src/product/vpp/product_packet_graph.c)），receiver 在 policy node 1617–1622 歸還；不是從 primary reserve 一直持有到 NFQUEUE verdict。Primary／completion FQM 分別配置 64／128 slots（4680–4683）。pin [buffer_funcs.c:269–286](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vlib/buffer_funcs.c#L269) 留一個空 slot，故可佔用量是 63／127 elements，每 element 最多 256 indexes。不能將 64 解讀成 64 packets，也不能將 32 改成 32 frames；packing 本身不提高 packet credit 上限。

Completion 已有每 producer-thread 的 512-index bounded backlog，其 static assertions 覆蓋現行 admitted carrier population（1832–1848）。Retry 每次最多掃 64 包，仍一包一個 publication，第一次普通 queue rejection 就停，剩餘工作以 native SCHED node 在 1 ms deadline 重試（1904–1945）。可把 retry 中同 origin 的可送 indexes 成批發布，仍把每個 failed carrier 留在原 holder，保留同 origin 順序與 fault-held carrier 的處理。需要一起核對 burst credit exhaustion、部分成功、backlog high-watermark、oldest pending 與 stop drain；增加 ring depth 無法解除 32 packet credits，增加 credits 又會改變活 buffer／completion debt 上界。pin 每個 FQM 的 dequeue threshold 是 512 vectors（[threads.c:387](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vlib/threads.c#L387)），不是全 worker 的總服務 budget；批次改動也須維持 owner 上其他 timer／I/O 的 bounded progress。

## 4. used：receiver 已合併 frame，local scalar enqueue 也能累積

pin [buffer_funcs.c:471–541](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vlib/buffer_funcs.c#L471) 將多個 queue elements 合併成最多 256-vector graph frame，達 threshold 或缺少有效 head 才結束；所以 scalar publication 不代表 downstream node 必定每次執行一包。產品 local admit／completion 用 `vlib_buffer_enqueue_to_single_next(...,1)`（graph 1392、2149）；pin [buffer_funcs.c:199–207](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vlib/buffer_funcs.c#L199) 取得既有 next-frame 空間並追加 indexes，亦不能直接判成單包 physical publication。

應分別看 producer calls、published elements／vectors、receiver dispatch vectors、local next-frame vectors。Receiver 合併已利用 VPP；P1 改善的是 producer ring reservation／publication 次數，P2 改善的是入口 native frame，兩者不是重建 receiver dispatcher。[FD.io 官方 VLIB 說明](https://docs.fd.io/vpp/23.02/developer/corearchitecture/vlib.html#handing-off-buffers-between-threads) 也明確把 frame queue capacity 定義為 frames，並說明每 worker 的目標 node queue；此一般說明不替代本次 pin 的具體實作。

## 5. used／underused：通知已合併 syscall，publication 仍逐包參與 latch

Android [0019 patch:17–45、65–70、125–130](../../../src/product/vpp/android/patches/0019-vpp-worker-notification-latch.patch) 已在 work publication 後通知，以 seq-cst pending exchange 合併 eventfd write，consumer 在 drain／ack 後檢查 pending frames、scheduled pending 與 remote queue indication；node interrupt／barrier 亦使用同一路徑。這與 pin [threads.h:498–506](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vlib/threads.h#L498) 的 sleep-flag hint 不同，不能說產品欠缺通知。

即使沒有每包 syscall，每次 physical publication 仍執行 latch exchange。P1 可以減少相同 target 的 publication 次數；不能直接跳過某些 publication 的 ordered exchange、改回依賴 sleep flag，或等下一包喚醒未滿 batch。Completion 的 dependency-blocked retry 已用 deadline；VPN stack 也已有 owner-specific fd／timer subscriptions 和 bounded step（[`flow stack:80–83、337–374`](../../../src/product/vpp/product_vpn_flow_stack.c)），不存在所有 worker 都只靠全局 polling 推進的缺口。

## 6. constrained：固定 owner 與 I/O funnel 是容量邊界

產品 worker layout 現為編譯期 W2（graph 44–45）；Root fd 明確註冊到 lane 所屬 worker（root adapter 1412），TUN capture／completion 歸 worker 0（TUN adapter 226、403），VPN mutable stack 保持 owner-local。CPU placement 已由 [ordered-worker patch:7–9、96–129](../../../src/product/vpp/patches/core/0006-vlib-ordered-worker-cpus.patch) 提供啟動時順序、online／allowed／distinct 檢查。這些是已使用的並行與 affinity 機制。

TUN I/O 對 owner 0 的聚合、flow hash 的 owner 負載偏斜，限制可用並行度；同一重 flow 的 stateful 處理也必然由唯一 owner 序列化。P1–P3 應先保持此 topology 與逐 owner／origin 的容量帳本，觀察 lane／owner 的 vectors、credit rejects、queue occupancy 與 pending age。ADR-0006／0007 和 [per-worker ownership](../../decisions/PER_WORKER_FLOW_OWNERSHIP.md) 禁止共享 NFQUEUE TX、全局 mutable transport authority、live migration／overload spill；批次化不是改 owner mapping 或搬移存量 flow 的授權。
