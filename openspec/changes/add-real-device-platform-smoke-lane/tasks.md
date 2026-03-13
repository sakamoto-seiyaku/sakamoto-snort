## 1. OpenSpec docs (this change)
- [x] 1.1 完成 `proposal.md` / `tasks.md` / `design.md` 与 capability spec delta（`specs/real-device-platform-smoke-testing/spec.md`）
- [x] 1.2 `openspec validate add-real-device-platform-smoke-lane --strict` 通过

## 2. Phase 2 implementation
- [x] 2.1 提供 rooted 真机平台 smoke 入口与 group / case 过滤
- [x] 2.2 覆盖 socket、`netd` 前置、`iptables` / `ip6tables` / `NFQUEUE`、SELinux / AVC 检查
- [x] 2.3 覆盖 shutdown / redeploy / restart lifecycle smoke
- [x] 2.4 更新 `README` / roadmap，并保留 `dev/` 兼容 wrapper
- [x] 2.5 在当前 rooted 真机上完成验证
