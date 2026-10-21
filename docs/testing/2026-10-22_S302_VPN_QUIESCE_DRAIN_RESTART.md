# SAKAMOTO-302: VPN quiesce, drain and generation restart

2026-10-22. This record covers [SAKAMOTO-302](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/b4cb978e-112a-4fae-bdc1-71dcaff40a90) under [ADR-0012](../adr/0012-configurable-flow-owners-and-dedicated-vpn-tun-io.md). It is Product functional evidence, not a release or performance result.

## Stop contract

The VPN control stop runs under the VPP worker barrier. It withdraws TUN read readiness first, including when a fatal read or exhausted capture token has already set `draining`. While captured originals remain, graph admission for their already admitted work, owner-local HEV turns, native return admission, completion transport and TUN completion writes remain active. Once every original has completed, stop quiesces HEV and graph, releases validation holds, waits for return credits/stamps, native buffers, completion frames and obligations to settle, then closes the I/O lane. The Android control client retains its bounded eight-second retry deadline; a failed drain is reported as a failed adapter close. HEV input copying/lwIP input runs synchronously before an original completion; active transport sessions are closed during HEV quiesce, so this contract does not wait for a remote response that has not arrived within bounded drain.

The deterministic `product tun original-hold`, `pre-stop-draining` and `write-short`/`write-eagain` controls are available only in debug validation mode. They do not change ordinary Product VPN capture or completion semantics. A real zero-length TUN syscall fault returned `EINVAL` on this Pixel; the short and EAGAIN stop cases therefore inject the immediate syscall **result**, while `sakamoto-product-vpn-tun-write-test` separately exercises actual short and EAGAIN writes on nonblocking Host fds. No physical TUN short write or EAGAIN is claimed.

## Exact artifacts and Pixel observations

The final APK is `build-output/s302-apk-e/sakamoto-runtime-debug.apk`, SHA-256 `6e298d4b6b2caad123c7062ce2dc9d2ce74c11fb0a9f416c161a79c79fd30b96`. Its Android Product plugin is `build-output/android-product-stage-s302-e/lib/arm64-v8a/libproduct_core_plugin.so`, SHA-256 `a6634cd5c18a6278026604aa40cf81fecfb409cb4f19c49f56435ba47d6b7635`. The matching Host plugin in `build-output/product-vpp-host-s302-e/` has SHA-256 `bc033371f392ef8a04f00cf4d1ba79b23b3cadf6e5693d1e7e96580862007bf9`; `build-output/s302-host-identity-e.json` binds its artifact bytes and source closure. Earlier artifact `s302-apk-d/` and its runs remain raw pre-review evidence.

Each final run matched installed APK and all installed native libraries to the APK, used the real Pixel TUN with the dedicated I/O worker, and stopped the VPP process. Raw results and native logs are in:

| Run | Generation / owners | Stop-time observation |
| --- | --- | --- |
| `build-output/s302-review-prestop-draining/` | 2320 / N=3 | Injected fatal `draining=1` before stop while read fd was still subscribed; stop removed its epoll subscription before graph quiesce and closed with zero debt. |
| `build-output/s302-review-stale-return-n1/` | 2321 / N=1 | After the N change, a real HEV return was deliberately supplied with generation 2320; Product rejected it before allocating a return token or credit, then stopped with zero debt. |
| `build-output/s302-final-e-n3-short/` | 2322 / N=3 | One live return buffer and obligation at read cutoff; one injected short result (`54/55` bytes) after cutoff; zero final debt. |
| `build-output/s302-final-e-n1-eagain/` | 2323 / N=1 | One live return at cutoff; one injected EAGAIN result (`errno=11`) after cutoff; zero final debt. |
| `build-output/s302-final-e-n3-success/` | 2324 / N=3 | One live return at cutoff; one actual successful 55-byte TUN write after cutoff; zero final debt. |
| `build-output/s302-final-e-congestion/` | 2325 / N=3 | Two-slot completion queue, 136 real captured originals, 128 bounded deferrals, 128 pending obligations at read cutoff; all 128 completed after cutoff and final debt was zero. |

`tests/evidence/verify_s302_quiesce.py` passed against the six final raw runs and final APK (`build-output/s302-verifier-e.log`). It independently matched each traced captured or return `(generation, token, buffer)` to exactly one completion and native free, each return token to one credit release, checked no capture after read cutoff, and checked quiesce/close ordering. It also checked the fatal-draining read-pause order and the attempted stale generation rejection. The repeated N=3→1→3→1→3 sequence used distinct runtime generations with a stopped process and zero outstanding debt between starts. All scoped packet-domain events carried the run's generation; the supplied old-generation return created no token, credit, return copy or TUN write.

The first two Pixel attempts remain raw **HOLD** evidence: `s302-pixel-n1-held-a/` had no reply because the Pixel was on `CU_7WFb_5G` (`192.168.1.0/24`) while the Host endpoint was on `192.168.4.0/24`; `s302-pixel-n1-held-device-b/` used the Pixel's own Wi-Fi address and bypassed TUN. The qualifying runs used saved `Openwrt_5G` (`192.168.4.151`) and a separately controlled Host UDP echo endpoint at `192.168.4.5`, then restored the original network. Earlier congestion timing attempts `s302-pixel-congestion-stop-h/i/j/` are retained as diagnostics; deterministic original hold made the final overlap reproducible.

## Regressions, cache and restoration

Host VPN Product topology/startup N=1/2/3/4 passed against the final artifact in `/tmp/s302-e-topology/`, including the dedicated I/O role and repeated owner CPU placement. Real Host Root NFQUEUE N=1 and N=3 regressions passed in `build-output/s302-root-n1-e/` and `build-output/s302-root-n3-e/`. Android runtime contract tests passed in `build-output/s302-android-contract-e.log`.

Full Host CTest completed 62/67 against the final worktree in `build-output/s302-host-ctest-e.log`. Failures #28/#31/#51 are older source-token contracts; #64 is sandbox Unix-socket denial and passed 1/1 with socket access in `s302-host-socket-escalated.log`. #44 is a stale S192 Host fixture contract calling the removed `product packet-graph configure` command; the exact S301 baseline artifact fails identically in `s302-s192-policy-baseline.log`, while the earlier S302 artifact failure is in `s302-s192-policy-runtime.log`. The relevant real Product Root/VPN runtime checks above passed.

`build-output/s302-cache-reuse-e.json` records zero compile actions on unchanged second Host and Android native builds, 650 Host and 652 Android compiled object hashes/timestamps unchanged, and byte-identical final plugins. The final device audit in `build-output/s302-final-e-device-audit/` confirms runtime stopped, no VPP or test endpoint process, restored APK SHA-256 `cc329acc906ba6ce8dd6e626c2849de1e9f335a96e2548a7ea3ab2becf9a1110`, and original `CU_7WFb_5G` Wi-Fi/route.
