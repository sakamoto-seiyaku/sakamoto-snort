# T01: one online L4 rule to real packets

Date: 2026-09-25. Scope: [SAKAMOTO-252](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/9d312f86-c52d-4278-ae7d-3c116506d001).
Result: **PASS for T01's bounded slice**, not the complete unified engine or a
public VPN release. The [minimal contract](../interfaces/T01_RULE_CONFIGURATION.md)
records source ownership, request/reply types, versions and the next-ticket boundary.

## Source and evidence identity

All final Linux and Android artifacts use Product source closure
`cc12c729ed7907b83837fb626d496aad967479acc7ad8ca7c01676da409a46b0`.
Builds record base commit `e9356b1111c80ade013dc66052ba4cb28da91860`, the complete
dirty Product source snapshot and actual binary hashes; the implementation commit
does not change those source bytes. API identity is `product_core.api/1.0.0@af6675d4`.
The dirty build manifest records removed `crates/product-core/src/policy.rs` as
`null`; after commit Git omits that path. Rechecking compares the existing source
paths and bytes while preserving that absence, rather than treating the removed
file's bookkeeping entry as a source change.

Evidence root: `build-output/t01-20260925/`. These local raw artifacts are required
to reproduce the independent checks; this document is not a substitute for them.

| Evidence | Result and scope |
| --- | --- |
| `linux-build-e/build.json`, `product-vpp-host-t01-e` (sibling of this root) | Official pinned Host VPP/plugin/Rust build, source and library closure |
| `pixel-build-e/build.json` | Matching ARM64 native/APK build; APK SHA-256 `4ed13fbb69a8d633f6e3eaaf2356097e41aacf6357dacf029525f0127619a89a` |
| `linux-e/`, `linux-e-verified.json` | Independent PASS; real VPP/NFQUEUE in a disposable Linux user/net namespace, generation 25201 |
| `pixel-root-f/`, `pixel-root-f-verified.json` | Independent PASS; Pixel 6a, actual app UID 12632, Root generation 1474, UIAutomator clicks and screenshots |
| `pixel-vpn-smoke/`, `pixel-vpn-smoke-verified.json` | Controlled VPN generation 1475, three actual UDP echoes via TUN/HEV/socket broker and LAN endpoint; both owners cleaned; `protectionRunning=false` |
| `host-tests-final.xml` | Current complete Host CTest suite: 41/41 PASS, including Rust session and Android contract checks |
| `linux-negative-witnesses.json`, `pixel-negative-witnesses.json` | Five falsified winner/source/verdict/endpoint/cleanup witnesses rejected per platform |

## Acceptance mapping

| Original T01 requirement | Evidence / implementation |
| --- | --- |
| First retain Linux and Android minimal baselines | `baseline-linux-build-b/`, `baseline-linux-root/`, `baseline-pixel-build/`, `baseline-pixel-root/`; recorded before product edits. Pixel Root smoke completed. Linux real-packet phase completed; its later injected S221 self-check failed at step 15, retained as a pre-existing baseline failure, not counted as T01 PASS. |
| Real product entrypoint; VPP sole source writer; save, compile, protected publish | Product Core host CLI and Activity → RuntimeService → JNI → Rust serialized session → generated VAPI → VPP main-thread source module → existing immutable snapshot publication. Final source files and saved/active API replies are retained for each phase. Rust source-store/replay implementation removed; legacy VAPI/CLI mutations reject. |
| Minimal IPv4 UDP exact conditions and ordinary ALLOW/DROP | Both Root runs use `127.0.0.1:32000 → 127.0.0.2:40608`, full UID, UDP, device OUTPUT. Same target yields echo / no endpoint arrival / echo for allow / drop / recover. |
| Single 64-bit rule-version identity and queryable saved/active/winner/result | Linux versions `12497249153677000705..707`, configurations 2/3/4. Pixel versions `6668719245693812743..745`, configurations 10/11/12. Queries agree with each packet-bound winner, source file and actual verdict. Linux also exercises values above signed 64-bit maximum; Java ABI test covers that representation. |
| Full-write failure or compile rejection cannot falsely succeed or publish half state | `product_rule_config_test.c`: real partial-write failure using `RLIMIT_FSIZE`, intact preceding file, no new publication; saved unsupported protocol preserves new source and old active rule; callback publication failure preserves active identity; correction succeeds. VAPI tests retain unknown outcome for missing/error replies and fence the session. Detailed real-runtime fault matrix remains T02. |
| Diagnostic Activity submits and queries through real API; no second source | `pixel-root-f/*-before.xml`, `*-query-before.xml`, `*-result.png`, `*-apply.properties`, `*-query.properties`. Buttons use the online API; retired app/Gate/L4 authoring actions reject. The properties file is an API result projection, not editable rule configuration. |
| Empty set compiles normally, not corrupt-source fallback | Fresh Linux source revision 1 is empty and active before capture; explicit Pixel Clear is saved and active. Host tests reject malformed existing bytes without publication. Startup does not synthesize an empty Rust policy. |
| Scope stays minimal | Zero/one directly bound exact IPv4 UDP rule, source persistence and status, existing L4/graph and diagnostic controls. No groups, imports, general expressions, complete editor or extra packet engine. |
| Representative verification retained; unexecuted scope explicit | Linux and Android Root real packets plus controlled VPN smoke, artifact/source/runtime/config identity, packet payloads, native verdict and buffer settlement, UI evidence and teardown. Limits below remain explicit. |

The Root verifier independently joins captured IPv4/UDP bytes and nonce, complete
UID, generation/token, snapshot revision, 64-bit winner, native NFQUEUE verdict
and exactly-once buffer free. Endpoint receipt is separate from policy evidence.
Linux additionally rebinds all four NFQUEUE numbers after stop. Pixel records empty
queue/hook residue, process absence and app-owned source mode `600`.

## Failures retained and corrected

- The initial Linux build attempt used a directory name rejected by the existing
  artifact guard; `baseline-linux-build/` retains the error. No product source
  change was needed.
- `linux-a/` exposed a collector assertion using L4-internal verdict numbers for
  the public query enum; corrected to public ALLOW=1/DROP=2, then re-run.
- `pixel-root-c/` exposed Java's retired TCP-only startup validator rejecting a
  correctly restored UDP snapshot. RuntimeService now validates VPP publication
  identity and consistency. The subsequent final run restores the same saved file.
- `pixel-root-d/` retained the UIAutomator idle failure. Repeated unchanged spinner
  selection and view updates are now avoided; final XML captures complete normally.
- `pixel-root-e/` completed all three UI/packet phases but failed on the collector's
  spaced Android `stat` format. Its cleanup ran; the corrected `pixel-root-f/` is
  the accepted complete run.
- The old S237 verifier assumes every callback uses the single thread 1. Its
  retained failure is `pixel-vpn-smoke/legacy-single-owner-verifier.txt`; it rejects
  the valid idle owner-1/thread-2 cleanup. T01's scoped reader checks each owner
  against its own thread, all three real echoes and both clean lifetimes. This
  does not weaken or claim the older full S237 matrix.

## Review and test maintenance

The `code-review` skill ran independent Standards and Spec reviews against the
T01 working diff from the fixed base above, excluding the user's pre-existing
uncommitted design documents. Spec reported no confirmed issues; Standards found
no hard violation and one maintainability concern about positional Java arrays.
That concern was fixed with a named-field `Rule` value and one boundary codec;
the reviewer confirmed closure. No review finding remains open.

Four active source-pattern contracts asserting the superseded Rust store,
draft/bundle persistence and old mutation-fence lifecycle (S188, Android S192,
Host/Android S194) were retired from CTest. Their historical files were retained.
The new C behavior tests, typed Java checks and extended production VAPI callback
tests cover the replacement seam. The applicable protected-snapshot, L4, graph,
flow, lifecycle, artifact and platform tests remain active. The final full suite
was run with local UDS permission; the initial sandbox-denied UDS run is not a pass.

## Rechecking retained evidence

```sh
rtk proxy python3 tests/evidence/verify_t01_rule.py build-output/t01-20260925/linux-e
rtk proxy python3 tests/evidence/verify_t01_rule.py build-output/t01-20260925/pixel-root-f
rtk proxy python3 tests/evidence/verify_t01_vpn_smoke.py --build build-output/t01-20260925/pixel-build-e/build.json build-output/t01-20260925/pixel-vpn-smoke
```

Fresh packet collection uses `tests/device/t01-linux-rule.py` in a disposable
`unshare --user --map-root-user --net` environment, and `tests/device/t01-pixel-rule.py`
with a new matching build witness. Pixel operations are serial and use `dev/adb`.

## Limits and continuation

T02/SAKAMOTO-253 owns complete direct multi-rule configuration, dual-stack/ranges,
the full identity/save/compile failure matrix and explicit Root↔VPN persistence
round trips. T03/SAKAMOTO-254 owns the Android management-only startup repair
lifecycle. An invalid startup source currently prevents capture; T01 does not
claim the T03 user repair experience. The controlled VPN smoke is not a policy
parity matrix, performance gate, public VPN launch or release decision. No deferred
24-hour expiry, physical cellular handover or broad device coverage is claimed.
