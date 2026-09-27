# SAKAMOTO-289 ordinary VPN start and rules acceptance

The ordinary UI VPN profile previously stopped with
`vpn_flow_stack_not_ready`. It now starts the Product VPP-native TUN and
owner-local HEV Flow Stack, reports readiness only after native handoff,
and applies the same current VPP rules and observation query as Root. The
Android UID broker is asynchronous; its accepted live-UDP reuse limit is
recorded in the [decision](../decisions/VPN_ASYNC_UID_AND_RETURN_LINEAGE.md).

Final source-bound Android build:

- `build-output/s289-20260928/pixel-build-q/build.json`: source SHA-256
  `6b0302a255ace9c8a264aba5f9f2d60a49606de604ef133980821138ddc10fb9`;
  debug APK SHA-256
  `2370f4d8f71ec367b5ebb9d5a3e94c0647ff1c0e0ded7b700466e954c516fdee`.
- On the physical Pixel, installed with `./dev/adb install -r`, generation
  1780 started ordinary VPN with `state=running`, `protectionRunning=true`,
  `adapter=vpn-flow-stack`, no error; query showed selected underlay,
  `dnsRestartRequired=false`, active VPP graph, and no temporary rule.
- The installed `base.apk` on the Pixel was rehashed as the same final APK
  SHA-256 (`build-output/s289-20260928/installed-q-apk-hash.txt`). A fresh
  physical UI tap of **Start** then started generation 1781 with the same
  running/protection status; the final DNS and TCP/HTTPS checks below use
  that exact installed binary.

Packet and rule evidence:

| Generation | Scenario | Result |
| --- | --- | --- |
| 1779, build-p | Cold App A UDP on port 45802 | Host echoed one; live FlowEntry UID 12630, ORIG/REPLY packets `[1,1]`, incarnation 3. This closes the earlier `[1,0]` regression. Saved query: `build-output/s289-20260928/cold2-p-1779.json`. |
| 1779, build-p | A DROP, then B allowed on reused port 45811 | A's first cold packet reached host and its next was dropped; B sent 16, host saw 15. The brief first B loss is within the accepted UID window; subsequent B traffic was delivered. |
| 1779, build-p | B DROP, then A allowed on reused port 45812 | B's first cold packet reached host; A sent 16, host saw 13, then sustained delivery. |
| 1779, build-p | **A allowed, then B DROP** on reused port 45813 | A completed six sends and host received six. Only the first of B's 16 sends reached host; B's later 15 were blocked. Rule revision 909 targeted UID 12631; query recorded 18 logical hits and 18 actual drops. The first B allow is the accepted live-UDP UID ambiguity. Saved rule/query: `build-output/s289-20260928/critical-rule-p-1779.properties`, `critical-p-1779.json`. |
| 1780, final build-q | Same App A UDP tuple port 45841 after 36.19 seconds idle | Both ordinary app sends reached the host echo peer, one before and one after the 30-second FlowEntry boundary. `build-output/s289-20260928/a-all-1780.jsonl` records the same VPN handle and source port; `peer-final.jsonl` records both distinct payloads at the host. |
| 1781, final build-q | Startup-bound DNS and ordinary TCP/HTTPS | `final-q-dns-tun.txt` captured A and AAAA queries for unique `s289-q-1781.192-168-4-5.sslip.io` on TUN and both matching replies (4/4 packets, zero kernel drops); App A resolved `192.168.4.5`. Chrome rendered the IANA HTTPS page (`final-q-iana-1781.xml`); VPP live flow query `final-q-iana-flows-1781.json` recorded Chrome UID 10180, TCP/443, ORIG/REPLY packets `[560,1006]`. The final APK also rendered Example Domain (`final-q-chrome-1781.xml`). |

The build-p rule tests precede only the final Product UDP idle-lifetime and
dashboard wording correction. Build-q's normal idle test exercises that final
code. Host HEV tests cover both timer-before-next-input rollover and forced
old-session/new-incarnation ordering: one trigger rejection, cleanup, and
successful next input. The latter is an explicit bounded transport limit,
not a zero-loss claim.

Earlier physical Pixel runs on the same implementation path also checked
consent cancellation and regrant, stop/restart, underlay offline/recovery
status, Product debug-CLI guards, and Root HTTPS/NFQUEUE smoke. Those runs are under
`build-output/s289-20260927/`; the final source changed the return-lineage
seam and UDP idle guard afterward, so they are supporting lifecycle evidence
rather than a final binary identity claim.

Host verification on final source: Android runtime contract PASS; Product
platform-boundary 7/7; plugin-init contract PASS; FlowEntry, TCP, and
return-credit/stamp tests 3/3; HEV test suite 36/36. The 128-slot stamp test
checks full-width incarnation, capacity, stale generation/token, held oldest
slot, and duplicate release.

After the final UI Stop, VPN generation 1781 was `stopped`,
`protectionRunning=false`, `mayBeActive=false`; no active RuntimeService or
VPP process remained. The cached runtime process was then force-stopped and
was absent. The original device
`rules.conf` SHA-256 remained
`f9e8c4ffef5a6a20b81e4092cc83a7c56b8359605b1a78f35b94fbc284438f0b`;
temporary backup was removed. Compared with the pre-task retained SQLite
**sample** (820 rows), all 819 historical non-cumulative rows remained
byte-identical and no sampled key was missing; the cumulative overall row
changed as new traffic was recorded. This comparison is a retained sample,
not a claim that every older database row was independently rehashed. All 34
pre-existing unrelated dirty files retained their entry hashes.

Manual debug APK: `build-output/s289-20260928/pixel-build-q/apk/sakamoto-runtime-debug.apk`.
Install as an update, open Sakamoto Debug Control, select VPN, tap Start, grant
Android VPN consent if prompted, then Query health and flows. A normal running
query should show `vpn-flow-stack`, selected underlay, and native VPP/flow
status. If `dnsRestartRequired` appears after changing networks, Stop and
Start VPN to refresh Android's startup-bound DNS servers. Stop from the same
screen when finished.
