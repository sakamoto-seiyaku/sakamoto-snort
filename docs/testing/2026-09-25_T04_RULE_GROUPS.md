# T04: reusable rule groups and enforce/observe application bindings

Date: 2026-09-25. Scope: [SAKAMOTO-255](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/aef8382b-aaf4-432a-a2b2-bbcb76f99d63).
Result: **PASS for T04 representative acceptance**.
The [interface contract](../interfaces/T04_RULE_GROUPS.md) defines input/output,
source identity, error tags, bounds and ownership under ADR-0009. VPP remains
the sole source writer and compiler; workers consume the protected snapshot.

## Source and evidence

Evidence root: `build-output/t04-20260925/`; start at `acceptance-index.json`.
The matching final Linux build f and Android build h have Product source closure
`7dd25ee427580f3bc896e631532a266d315074f67b08c57cbb011ec534836311`.
The frozen source manifests record base commit
`18dec87262b8dec9e7bcb61792265328ce2b1bee`, exact source bytes and dirty diff.
API identity is `product_core.api/1.0.0@b2bbc6a8`.

The accepted compilation limits are implementation parameters, not measured
performance guarantees: 256 source rules, 64 groups, 512 edges, 128 bindings,
depth 8, 4096 visited references per binding, and the existing 128 total effective
rule/application entries. Groups do not add precedence or default actions.

## Original acceptance mapping

| Original requirement | Implementation and evidence |
| --- | --- |
| 支持规则、组、子组及应用绑定的完整提交和查询；检查缺失引用、循环、深度/展开上限及来源可追溯性。 | Same complete VAPI → VPP source operation and query, with Rust/Java/JNI adapters. V3 stores the complete graph; V1/V2 remain readable. Host validates missing references, bound/unbound cycles, depth 8 acceptance/9 rejection, and 4096-reference acceptance/4097 rejection. Linux and Android request/source/query triples retain all group edges, binding IDs, application UIDs and full rule versions. |
| 每应用独立展开，同源同有效模式多路径去重，同源 enforce/observe 冲突拒绝；不同规则 ID 即使内容相同也不静默合并。 | Host checks exact same content under distinct identities and two candidates. The 4032 repeated-leaf-path case emits one effective candidate. Linux uses two real kernel UIDs sharing nested groups, with group/direct duplicate references; each packet sees four candidates rather than duplicated paths. Conflicting modes reject before saving, retain source bytes and continue the old snapshot. |
| 完整顺序是 priority、显式 order、稳定逻辑身份；不因组/直接引用的遍历顺序增权，组不自行选赢家或拥有 default action。 | Linux hand-decided competitors distinguish priority, order and identity, then reorder all group/binding traversal and retain the winner. A subsequent priority promotion makes ordinary ALLOW win. Independent test-only set expansion and ordered evaluation compare packet facts to full source, actual winner, mode, declared/actual actions and candidate count. |
| 有效 observe 模式保留声明动作与赢家而实际 ALLOW；最低优先级普通 DROP 可表达缺省拒绝。 | Matcher returns mode plus declared/actual actions. Graph completion and drop counters use actual action. Linux and Android compare declared DROP with real successful observe echoes and zero drop-count growth. Host `ordinary_group_fallback` checks specific ALLOW followed by a lowest-priority ordinary UDP DROP and an empty unbound application view. This is the current L4 field scope, not future expression/protocol coverage. |
| 通过多应用共享组、重复引用、冲突模式、高低优先级规则竞争案例，核对实际赢家、动作及规则计数。 | Linux-d: 10 real NFQUEUE IPv4 UDP packets across two VPP lifetimes and two actual UIDs. Each packet increments logical hits once; actual drop counts grow only for enforced DROP. Query reports eight effective entries, four for each app. Android checks two effective entries despite three paths to its higher-priority DROP. |
| 与 T05 的交叉能力由后落地的一方补组合回归。 | T05/SAKAMOTO-256 remains Backlog in the live readback. Its implementation must combine ordinary network disabling with the shared-group/observe view delivered here, preserving winner and actual action. This is explicitly its later-landing integration responsibility, not a new dependency edge or work deferred solely to T29. |
| 完成本票代表性验证并保留证据；未执行项明确说明与最近承接位置，不把 host PASS 当作设备 PASS。 | Host, Linux and Android are independently indexed below. Saved source, source/artifact identity, API generation, runtime process, observed packet bytes, winner trace, native completion, endpoint outcome, query counters and resource cleanup are joined by the verifier. UI XML/screenshots prove operations and source-query display only. |

## Verification and limits

- `host-tests-final.xml`: complete applicable CTest suite, 41/41 PASS. Focused C
  TDD covers save/reload, graph validation/deduplication/mode conflicts, exact
  resource boundaries, effective-view compile overflow retaining saved edits and
  old runtime, same-content identities, fallback and old single-rule compatibility.
  Java request/reply and native VAPI/plugin fixtures cover the expanded contract;
  Rust layout and lifecycle checks remain included.
- `linux-build-f/build.json`, `linux-d/`, `linux-d-verified.json`: final Linux
  product source/artifact closure and independently verified ten real packets.
  Both native stops settle all buffers, obligations and pending frames; both
  processes are absent and NFQUEUE hooks are removed.
- `pixel-build-h/build.json`, `pixel-c/`, `pixel-c-verified.json`: matching
  installed APK SHA-256 `fa89026cb451b47cd83f809e112d3d196eef5a4028e19fe25d37d0fbcd192038`;
  two real Root packets and two real controlled VPN packets. Each profile
  submits enforce then observe through the visible Android Product API, queries
  full group/binding source, and proves the same declared DROP and winner with
  different actual packet delivery. Native teardown closes both VPN owners'
  sessions/sockets and packet resources; Root/VPN processes are absent.
- `linux-d-negative-witnesses.json`, `pixel-c-negative-witnesses.json`: seven
  falsified process, winner, logical-count, mode, endpoint, source-binding and
  runtime-generation witnesses rejected on each platform.
- `review-results.md`: independent Standards/Spec review and repair closure.

Final Pixel generation 1508 is stopped in VPN profile with no error,
`mayBeActive=false` and `protectionRunning=false`. Saved revision 63 contains
one app-owned mode-0600 source with two reusable IPv4 UDP rules, two groups,
four edges and two observe bindings. The higher-priority rule declares DROP;
its actual action is ALLOW. The lower-priority rule declares ALLOW. These are
controlled VPN probe rules, not a public protection claim. The test endpoints
were cleaned and the prior stay-awake setting restored; the OS lockdown setting
was only read and remains unset.

Linux ran with ordinary host tools in an existing Debian container, isolated
network namespace and actual UIDs 12001/12002. The existing image has a historical
POC name, but no image-owned POC source or binary was used: VPP, plugin, Rust
control and API are exclusively the separately built Product artifacts. The
repository was mounted read-only except the ticket evidence and two designated
runtime directories. Container NET_ADMIN applies only to its isolated namespace;
there is no host-network capture. The single-UID unprivileged namespace route
could not satisfy the two-app requirement because newuidmap is absent.

This ticket does not qualify public VPN launch, performance/power, cellular,
all protocol/condition combinations, 24-hour TCP expiry, or later expression,
placement/cache and normal-observation implementation. T05 owns its stated
network-disable integration; broader combined qualification remains T29.

## Review and retained attempts

Both code-review axes ran independently. Standards found a reply loop bounded
by a network-order count and repeated literal capacity guards; both were fixed.
Spec found missing exact-same-content and exact expansion-boundary tests; those
were added and passed. A final compatibility regression exposed the legacy
single-rule request and V1/V2 loader accepting the new reusable-only UID sentinel;
their previous rejection was restored and both final platform builds/runs repeated after that fix.

Earlier Linux-a/Linux-b/Linux-c and Pixel-a/Pixel-b campaigns passed their then-current source,
but are superseded by the final source identity above. Pixel build attempts a/b
stopped before compilation because their specified stage paths were absent; the
existing verified Android stage b was then used. First Host suite failures were
an outdated fake generated-plugin message shape and sandbox-denied Unix sockets;
the fixture was updated and the suite passed with local socket permission. No
failed attempt is counted as current acceptance.

```sh
rtk proxy python3 tests/evidence/verify_t04_groups.py build-output/t04-20260925/linux-d
rtk proxy python3 tests/evidence/verify_t04_groups.py build-output/t04-20260925/pixel-c
```
