# Reference Docs

This directory contains background and lineage material.

Reference docs are not default agent context. They can help compare `sucre-snort` with prior codebases or recover old risk categories, but old line numbers, bug lists, and implementation notes are not current facts unless confirmed against the active code and docs.

## Focused References

- [Android VPP POC 技术复盘](ANDROID_VPP_POC_TECHNICAL_RETROSPECTIVE.md)：按实验顺序整理 Android VPP 的构建、root/NFQUEUE、VPN/TUN/HEV、体积裁剪和 idle CPU 优化过程。
- [Protocol Identification VPP Reference Inventory](PROTOCOL_IDENTIFICATION_VPP_REFERENCE_INVENTORY.md)：盘点 `/home/js/backup/backup/Git/vpp` 中的 `stellar_lpi`、libprotoident、decoder/enforcer 和 PCAP 语料，作为 SAKAMOTO-61/S63 的参考输入。
- [Protocol Identification VPP LPI Corpus Manifest](PROTOCOL_IDENTIFICATION_VPP_LPI_CORPUS_MANIFEST.md)：记录 modified VPP `stellar_lpi` PCAP corpus 的 group/count/expected JSON 形态；不复制样本，不替代 license/privacy review。
