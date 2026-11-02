# 编译缓存与空间

## 编译

- 使用 Android／Host Product builders；共享缓存为 `build-output/product-build-cache/`，Host 测试复用 `build-output/host-tests`。不逐任务／轮次新建 `CARGO_TARGET_DIR`、CMake `-B` 或 SDK/NDK 副本。
- 缓存按 checkout、平台／ABI／API、工具链、VPP 身份及编译环境隔离；不以完整业务源码身份或发布路径分键。源文件、生成头和选项变化交由 Ninja／Cargo 跟踪，缓存命中不跳过现有输入与产物校验。
- 只构建受影响目标；不例行 `cargo clean`、`--clean-first` 或删除缓存。冷构建仅用于明确的失效诊断／隔离测试，限定目录并说明原因。
- 保持 HEV 编译输入、生成 VAPI 路径及未变文件时间戳稳定；复用现有 APK 字节码、VPP 生成与配置缓存。
- 同缓存写入串行；Android stage 原子发布，strip 仅作用于发布副本。相同发布文件由 `output_storage.py` 共享只读副本，更新用新文件原子替换，不链接可变编译输出。
- 自定义缓存仅可位于本 checkout 的 `build-output` 下，遵守 `build-cache.py` 的归属与路径校验。

## 复验

仅构建／缓存机制、缓存身份变化或复用异常时，验证受影响平台：相同输入、不同发布目录，第二次零 Rust 编译、零 Ninja 构建动作，编译文件时间戳及原生产物内容不变。同一机制与身份的有效证明直接复用，不逐票／逐轮重做。

复用检查入口：`tests/host/product_build_cache_test.py`、`tests/android/check_build_cache.py`、`tests/android/check_apk_build_cache.py`；所需 VPP/NDK 输入按当前 builder 提供，只运行受影响项。

## 保留与清理

- 每任务一个输出根；复用已有产物和采集，不重复保存完整 stdout、累计日志或整仓快照。源码优先用提交与必要差异回溯。
- 验收、诊断及恢复未完成前保留必要原件；完成后默认仅留命令、源码／工具链身份、结论、关键测量与失败原因，以及 Git 未覆盖的必要源码。
- 当前交付及依赖、有效编译缓存及依赖、协调锁、一份有效原始数据恢复基线保留。额外原件须有未闭合问题、明确复核或用户要求。
- 默认清理本任务已结束的临时二进制、符号副本、抓包、测试数据库、全量导出与重复备份；不以“证据”为由永久累积。精简文本摘要不承诺历史原始数据的离线重验。
- 使用 `clean-build-output.py`，先预览，再对同一范围加 `--apply`；同根目录中的当前交付及恢复基线须显式 `--keep PATH`。跨任务清理须有相应授权，禁止整删 `build-output`。

```sh
rtk proxy python3 tools/product/clean-build-output.py --root build-output/TASK --finished --keep build-output/TASK/DELIVERABLE --keep build-output/TASK/BASELINE
```

仅在产生／清理输出时测量相关目录的实际分配空间；异常增长先定位。权限受限时保留已完成结果，报告具体路径及处理命令，不追加全盘扫描、重复构建或审计材料。

依据：[Cargo 缓存](https://doc.rust-lang.org/cargo/reference/build-cache.html)、[CMake 构建](https://cmake.org/cmake/help/latest/manual/cmake.1.html#build-a-project)、[GitHub 缓存与产物](https://docs.github.com/en/actions/concepts/workflows-and-actions/dependency-caching#artifacts-versus-dependency-caching)。任务结束后的保留范围为本仓库约定。
