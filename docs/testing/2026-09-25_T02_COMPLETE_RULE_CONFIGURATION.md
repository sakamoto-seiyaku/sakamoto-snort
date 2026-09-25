# T02: complete direct configuration, versions and failure behavior

Date: 2026-09-25. Scope: [SAKAMOTO-253](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/ecec1e20-41de-478a-a12d-69fcbdc18c9b).
Result: **PASS for T02's representative acceptance**. This is the bounded direct
L4 source slice of [ADR-0009](../adr/0009-unified-rules-and-vpp-owned-configuration.md),
not the later expression/group engine or a public VPN release. The
[interface contract](../interfaces/T02_RULE_CONFIGURATION.md) records ownership,
identity operations, errors, capacity and the cross-language request/reply layout.

## Source and artifacts

Both final builds use Product source closure
`186a21007dc469cc72f608d08f03e6c50b02456cad9445b9bf66bf1690221020`.
The frozen manifests record base commit `1913d1e772ad5875a9f9e4bb6fc67e3a0b7bdc1e`
and the exact dirty source bytes; the implementation commit does not alter those
bytes. API identity is `product_core.api/1.0.0@eb8f9cae`.

Evidence root: `build-output/t02-20260925/`. The raw artifacts are local acceptance
inputs, not replaced by this document. Start at `acceptance-index.json`.

| Evidence | Result and scope |
| --- | --- |
| `linux-build-c/build.json`, sibling `product-vpp-host-t02-c/` | Official fixed Host VPP/plugin/Rust build, source snapshot and artifact hashes |
| `pixel-build-f/build.json` | Matching ARM64/APK build; APK SHA-256 `6586cc3f9a15df5d3bd13cd74997eb300cfa9eae66cfbc2f953b0aee6c9b0267` |
| `linux-c/`, `linux-c-verified.json` | Independent PASS; 12 actual dual-stack UDP packets, NFQUEUE, generations 25301 and 25302 |
| `pixel-e/`, `pixel-e-verified.json` | Independent PASS; 10 Root dual-stack UDP packets plus 2 controlled VPN UDP packets; four complete runtime lifetimes |
| `host-tests-final.xml` | Applicable complete Host CTest suite: 41/41 PASS, including C rule management, Rust session, Java and production VAPI/plugin checks |
| `linux-c-negative-witnesses.json`, `pixel-e-negative-witnesses.json` | Five falsified winner/source/action/verdict/endpoint witnesses rejected for each platform |
| `review-results.md` | Independent Standards and Spec reviews and confirmed corrections |

## Acceptance mapping

The first column retains the original T02 acceptance text.

| Requirement | Implementation and evidence |
| --- | --- |
| 完整提交支持当前 C L4 主线的 IPv4/IPv6、TCP/UDP、CIDR、端口范围、方向及可用平台条件；固定一版后编译，不混入下一次编辑。 | REPLACE_ALL transports one bounded array through Java/JNI → Rust session → generated VAPI → VPP main-thread copy. VPP validates, saves and compiles that copy using the existing C L4 compiler. Host tests exercise IPv4 UDP, IPv6 TCP, CIDR/ranges, input/output, priority/order and network/interface availability; VAPI tests preserve full multi-rule fields. Both runtime collectors exercise two related dual-stack rules in one submission. |
| 高 48 位非零随机逻辑身份碰撞检查，低 16 位修订递增、不回绕；同完整 ID 不同内容拒绝，修订耗尽明确报告。 | `product_rule_config_test.c` injects zero and repeated random identities before successful creation, checks unchanged versions, edit progression, explicit-ID content conflict, duplicate logical identities, 65535 exhaustion and deleted-ID conflict after reopening. The source retains only logical identity high-water marks, not old conditions. |
| 保存失败不编译；保存成功后编译失败保留新配置、旧快照和可定位错误；查询分别报告保存与生效身份。 | Host partial-write failure, directory-sync uncertainty and publication rejection preserve active state. Linux `save-failure-*` retains the preceding file and DROP snapshot. Linux/Pixel `compile-failure-*` retain all 129 saved rules and their identities while the preceding two-rule DROP snapshot continues executing. Replies carry saved/active revisions, saved entries, active versions, error index and compiler status. |
| 验证多规则关联提交、重复提交、文件失败和编译超限，不截断规则、不回退已保存编辑以伪造成功。 | Two related rules update atomically in every successful runtime phase. Host exact resolved duplicate submissions preserve configuration and rule IDs; retry after durability uncertainty also preserves the saved revision. The source accepts up to 256 entries; the existing compiler's 128-rule limit rejects the complete 129-rule source after saving. Correction removes surplus entries through the same API, rather than restoring a hidden prior file. |
| 正常重启读取同一源文件恢复规则；相关旧 Java/Rust 写入口统一到 VPP 权威来源，不能维护第二份可编辑持久模型。 | Linux generation 25302 and Pixel generation 1485 restore the same saved two-rule source and full IDs. T01's retired authoring/store paths remain retired; the single-rule compatibility operation is only an adapter to this same source and refuses to overwrite a multi-rule source. Java properties files are diagnostic API-result projections, not editable rule inputs. |
| 本票完成的是源配置/直接规则行为，不引入未确认的草稿、固定 checkpoint 档案或 UI 工作流。 | The only UI addition is a transient complete-request field and submit/query controls in the existing diagnostic Activity. The only authoritative source remains VPP's file. No draft store, old-condition archive, group semantics or new user workflow was added. |
| VPP 写入的持久配置不属于停止时删除的 generation/profile 运行资源；正常停止、重启及 Root/VPN 切换后，配置内容、身份和读写权限仍正确。覆盖 Root 写入→VPN 读取/更新→Root 读取的实际往返，不新增第二份按模式分离的配置。 | Pixel generations 1484 (Root), 1485 (Root restart), 1486 (VPN), 1487 (Root return) use the same `files/rule-configuration/rules.conf`. `root-final`, `root-stopped`, `root-restored`, `root-restart-stopped`, `vpn-read` files are byte-identical. After actual VPN updates, `vpn-final`, `vpn-stopped`, `root-return-read`, `root-return-stopped` are byte-identical. Every captured source owner/mode is app UID/GID 12632 and mode 600; `/proc` records distinguish root and app runtime identities. No permission repair or alternate per-mode file was used. |
| 完成本票代表性验证并保留证据；未执行项明确说明与最近承接位置，不把 host PASS 当作设备 PASS。 | Host, Linux and Pixel results are separately retained and independently scoped below. All required T02 representative verification ran; broader combinations and later capabilities remain explicitly outside these claims. |

## Actual packet and lifecycle observations

Linux uses an isolated user/network namespace and actual VPP/NFQUEUE adapters.
For each of IPv4 and IPv6, the endpoint observed ALLOW, DROP, unchanged DROP after
save failure, unchanged DROP after saved compilation failure, ALLOW after correction,
and ALLOW after restart. The save failure temporarily made the source directory
unavailable, then restored that same directory; it did not modify rule bytes.

Pixel Root observed both IP families through the app's actual UDP diagnostic
probe. Saved revision 25 contains 129 rules and ALLOW edits; active revision 24
continues dropping both packets. Correction publishes revision 26 without
rewriting the first two rules' already-saved versions. Root restart preserves
revision 26. VPN reads those exact bytes, saves revision 27 with DROP and then
revision 28 with ALLOW, and produces timeout/no endpoint arrival versus actual
LAN echo through TUN → owner-local HEV → protected socket. Root then restores
revision 28 and its full rule IDs from the same file.

The verifier joins captured packet bytes/nonces and UID to generation/token,
protected-snapshot rule version and revision, actual NFQUEUE verdict or VPN
completion, and exactly-once buffer settlement. Endpoint receipt is independent
of the policy evidence. XML and screenshots establish the submitted complete
request and click/result display; they are not substitutes for packet evidence.
Both VPN owners report zero remaining sessions, inputs, pbufs and packet debt,
closed sockets, and retired timer/broker descriptors. All four Pixel processes
are absent after stopping; no Product NFQUEUE/hook residue remains.

Final Pixel state is stopped, Root profile, generation 1487, `mayBeActive=false`
and `protectionRunning=false`. The app-owned saved configuration intentionally
remains revision 28 with two VPN-targeted ALLOW rules. The collector cleaned its
owned endpoints and restored the previous stay-awake setting.

## Errors, retained failures and review

Pre-rename save errors leave the preceding source. If rename succeeds but
syncing its directory fails, the API reports `DURABILITY_UNCERTAIN` (9), the actual
new saved identity and the old active identity, without compiling. It does not
claim the new bytes will survive power loss. Injected Host tests cover creation,
replacement, reopened identity and a successful identical-content retry.

Retained attempts are not counted as final PASS:

- `pixel-build-a/` failed because the default temporary VPP stage path was absent;
  subsequent builds use the existing verified `s220-20260913/android-stage-b`.
- `linux-a/` completed update/failure packets but reused a nonempty generation
  runtime directory at restart. The collector now uses separate runtime directories
  and one configuration directory; `linux-b/` and final `linux-c/` complete restart.
- `pixel-a/` found the complete-rule action missing from RuntimeService's allowed
  action list. `pixel-b/` found diagnostic prefill placed in the wrong lifecycle
  branch, causing an explicit empty submission. Both integration defects were fixed.
- `pixel-c/` passed eight dual-stack update/failure packets, then found the inherited
  Java startup validator still limited to one rule. It now accepts the existing
  C compiler's bounded multi-rule capacity; final runs restore correctly.
- `pixel-d/` completed all functional phases, but its collector read the Root stop
  archive for VPN. The corrected `pixel-e/` uses the proper VPN archive and passes
  independent generation and owner-cleanup verification.
- The initial sanitizer invocation encountered LeakSanitizer's ptrace limitation;
  the focused ASan/UBSan run passed with leak detection disabled. This is not a
  leak-check claim and is supplementary to the final ordinary Host suite.

The code-review skill ran separate Standards and Spec reviewers against the T02
working diff from the fixed base, excluding pre-existing design-doc changes.
Standards found no hard violation and one layout-number maintainability concern;
named constants and the documented layout closed it. Spec found incorrect saved
revision reporting after initial post-rename sync failure; a failing regression
preceded the correction, and the reviewer confirmed closure. A subsequent exact
retry regression and fix also received review closure. No finding remains open.

## Rechecking and scope limits

```sh
rtk proxy python3 tests/evidence/verify_t02_rules.py build-output/t02-20260925/linux-c
rtk proxy python3 tests/evidence/verify_t02_rules.py build-output/t02-20260925/pixel-e
```

Fresh collection uses `tests/device/t02-linux-rule.py` with a matching official
Host build in an isolated netns, and `tests/device/t02-pixel-rules.py` with a matching
APK. All phone operations go through `dev/adb` and run serially.

This campaign proves representative dual-stack UDP runtime behavior and a VPN
IPv4 path; it does not claim every TCP/UDP/CIDR/platform combination on both
adapters. TCP, direction, CIDR, interface/network availability and identity/failure
boundaries have focused Host coverage. Broader combined Root/VPN qualification is
[SAKAMOTO-281](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/faaa95d4-dfb4-4a8e-9605-9fa22c207c64).
Startup of an invalid source still needs the management-only Android repair
lifecycle owned by [SAKAMOTO-254](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/d7c2eaa5-324a-4c45-8e8b-2315c1eae77c).
No public VPN launch, performance/power result, physical cellular coverage or
24-hour TCP expiry result is implied.
