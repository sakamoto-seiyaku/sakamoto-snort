# A2 cell verdict prototype — THROWAWAY

问题：manifest-driven verifier 能否把 `PASS`、`FAIL`、`INVALID`、
`INCONCLUSIVE` 与 aggregate `A2_INCOMPLETE` 分开，而不把空 logcat 或缺
instrumentation 混成一个笼统的 `INSUFFICIENT`？

运行（仓库根目录）：

```sh
python3 experiments/vpp-nfq-poc/prototypes/a2_cell_verdict/tui.py
```

这是内存中的逻辑原型，不读写证据、不访问设备、无依赖、没有持久化，也不
代表生产 verifier。每个动作后 TUI 全屏重绘所有 cell 状态；`--demo` 是最小
非交互 smoke：

```sh
python3 experiments/vpp-nfq-poc/prototypes/a2_cell_verdict/tui.py --demo
```

快捷键 `1`–`7` 选择 cell；`h/f/m/i/z/o` 分别快速产生 PASS、行为 FAIL、
provenance INVALID、instrumentation INVALID、deadline INCONCLUSIVE、以及
“空 logcat 但 durable 证据完整”的 PASS。`j/v/e/b/d/c/x` 可逐项加入 join、
instrumentation、decisive/falsifier、deadline、cleanup 证据；`r/R/q` 重置
当前/全部或退出。

结论：模型能分开这些状态；`LOGCAT_EMPTY` 是非 durable 诊断事件，不会使
已有 durable PASS 变成 INVALID。缺失 required instrumentation/provenance
在 deadline 收口为 INVALID；有效但没有 decisive event 才是 INCONCLUSIVE；
required cells 未全 PASS 时 aggregate 为 `A2_INCOMPLETE`。
