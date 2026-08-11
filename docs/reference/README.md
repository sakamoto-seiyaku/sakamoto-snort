# Reference Docs

This directory contains background and lineage material.

Reference docs are not default agent context. They can help compare `sucre-snort` with prior codebases or recover old risk categories, but old line numbers, bug lists, and implementation notes are not current facts unless confirmed against the active code and docs.

## Focused References

- [Android VPP POC 技术复盘](ANDROID_VPP_POC_TECHNICAL_RETROSPECTIVE.md)：按实验顺序整理 Android VPP 的构建、root/NFQUEUE、VPN/TUN/HEV、体积裁剪和 idle CPU 优化过程。
- [Protocol Identification VPP Reference Inventory](PROTOCOL_IDENTIFICATION_VPP_REFERENCE_INVENTORY.md)：盘点 `/home/js/backup/backup/Git/vpp` 中的 `stellar_lpi`、libprotoident、decoder/enforcer 和 PCAP 语料，作为 SAKAMOTO-61/S63 的参考输入。
- `tools/protocol_identification/vpp_stellar_lpi_wrapper_inventory.sh`：机器可读地清点 modified VPP `stellar_lpi` wrapper 的 C boundary、调用顺序、source/build/license 形状；不复制源码、不决定 provider source strategy。
- [Protocol Identification VPP LPI Corpus Manifest](PROTOCOL_IDENTIFICATION_VPP_LPI_CORPUS_MANIFEST.md)：记录 modified VPP `stellar_lpi` PCAP corpus 的 group/count/expected JSON 形态，以及 expected `APP_NAME` 对当前 Sakamoto provider alias catalog 的覆盖；不复制样本或 expected JSON，不替代 license/privacy review。
- [Protocol Identification libprotoident Reference Audit](PROTOCOL_IDENTIFICATION_LIBPROTOIDENT_REFERENCE_AUDIT.md)：记录 backup VPP vendored `libprotoident` 的 license/build/API/Android 风险事实；不作为法律结论或 vendoring 决策。
- [Protocol Identification libprotoident NDK Probe](PROTOCOL_IDENTIFICATION_LIBPROTOIDENT_NDK_PROBE.md)：提供只读 Android/NDK build probe，验证 backup VPP vendored `libprotoident` 当前能否在本地 NDK toolchain 下编译。
- [Protocol Identification stellar_lpi Wrapper Inventory](PROTOCOL_IDENTIFICATION_STELLAR_LPI_WRAPPER_INVENTORY.md)：记录 modified VPP `stellar_lpi_core` wrapper 的 C API、source/build shape、VPP-tree dependency 和 fork-local mapping 风险；不复制源码或决定 provider source strategy。
- `tools/protocol_identification/stellar_lpi_wrapper_android_build_probe.sh`：只读 Android/NDK compile-link probe，验证 modified VPP `stellar_lpi_core.c + stellar_lpi_extend.c` 能否和 backup vendored `libprotoident` 一起编译链接；只写 `build-output`，不复制源码、不启用 runtime provider。
